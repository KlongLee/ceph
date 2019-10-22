// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#include "ElectionLogic.h"

#include "include/ceph_assert.h"
#include "common/dout.h"

#define dout_subsys ceph_subsys_mon
#undef dout_prefix
#define dout_prefix _prefix(_dout, epoch, elector)
static ostream& _prefix(std::ostream *_dout, epoch_t epoch, ElectionOwner* elector) {
  return *_dout << "paxos." << elector->get_my_rank()
		<< ").electionLogic(" <<  epoch << ") ";
}
void ElectionLogic::init()
{
  epoch = elector->read_persisted_epoch();
  if (!epoch) {
    ldout(cct, 1) << "init, first boot, initializing epoch at 1 " << dendl;
    epoch = 1;
  } else if (epoch % 2) {
    ldout(cct, 1) << "init, last seen epoch " << epoch
	    << ", mid-election, bumping" << dendl;
    ++epoch;
    elector->persist_epoch(epoch);
  } else {
    ldout(cct, 1) << "init, last seen epoch " << epoch << dendl;
  }
}

void ElectionLogic::bump_epoch(epoch_t e)
{
  ldout(cct, 10) << __func__ << epoch << " to " << e << dendl;
  ceph_assert(epoch <= e);
  epoch = e;
  peer_tracker->increase_epoch(e);
  elector->persist_epoch(epoch);
  // clear up some state
  electing_me = false;
  acked_me.clear();
  elector->notify_bump_epoch();
}

void ElectionLogic::declare_standalone_victory()
{
  assert(elector->paxos_size() == 1 && elector->get_my_rank() == 0);
  init();
  bump_epoch(epoch+1);
}

void ElectionLogic::start()
{
  if (!participating) {
    ldout(cct, 0) << "not starting new election -- not participating" << dendl;
    return;
  }
  ldout(cct, 5) << "start -- can i be leader?" << dendl;

  acked_me.clear();
  init();
  
  // start by trying to elect me
  if (epoch % 2 == 0) {
    bump_epoch(epoch+1);  // odd == election cycle
  } else {
    elector->validate_store();
  }
  electing_me = true;
  acked_me.insert(elector->get_my_rank());
  leader_acked = -1;

  elector->propose_to_peers(epoch);
  elector->_start();
}

void ElectionLogic::defer(int who)
{
  if (strategy == CLASSIC) {
      ldout(cct, 5) << "defer to " << who << dendl;
      ceph_assert(who < elector->get_my_rank());
  } else {
    ldout(cct, 5) << "defer to " << who << ", disallowed_leaders=" << elector->get_disallowed_leaders() << dendl;
    ceph_assert(!elector->get_disallowed_leaders().count(who));
  }

  if (electing_me) {
    // drop out
    acked_me.clear();
    electing_me = false;
  }

  // ack them
  leader_acked = who;
  elector->_defer_to(who);
}

void ElectionLogic::end_election_period()
{
  ldout(cct, 5) << "election period ended" << dendl;
  
  // did i win?
  if (electing_me &&
      acked_me.size() > (elector->paxos_size() / 2)) {
    // i win
    declare_victory();
  } else {
    // whoever i deferred to didn't declare victory quickly enough.
    if (elector->ever_participated())
      start();
    else
      elector->reset_election();
  }
}


void ElectionLogic::declare_victory()
{
  ldout(cct, 5) << "I win! acked_me=" << acked_me << dendl;
  last_election_winner = elector->get_my_rank();
  leader_acked = -1;
  electing_me = false;

  set<int> new_quorum;
  new_quorum.swap(acked_me);
  
  ceph_assert(epoch % 2 == 1);  // election
  bump_epoch(epoch+1);     // is over!

  elector->message_victory(new_quorum);
}

bool ElectionLogic::propose_classic_prefix(int from, epoch_t mepoch)
{
  if (mepoch > epoch) {
    bump_epoch(mepoch);
  } else if (mepoch < epoch) {
    // got an "old" propose,
    if (epoch % 2 == 0 &&    // in a non-election cycle
	!elector->is_current_member(from)) {  // from someone outside the quorum
      // a mon just started up, call a new election so they can rejoin!
      ldout(cct, 5) << " got propose from old epoch, "
	      << from << " must have just started" << dendl;
      // we may be active; make sure we reset things in the monitor appropriately.
      elector->trigger_new_election();
    } else {
      ldout(cct, 5) << " ignoring old propose" << dendl;
    }
    return true;
  }
  return false;
}

void ElectionLogic::receive_propose(int from, epoch_t mepoch)
{
  switch (strategy) {
  case CLASSIC:
    propose_classic_handler(from, mepoch);
    break;
  case DISALLOW:
    propose_disallow_handler(from, mepoch);
    break;
  case CONNECTIVITY:
    propose_connectivity_handler(from, mepoch);
    break;
  default:
    ceph_assert(0 == "how did election strategy become an invalid value?");
  }
}

void ElectionLogic::propose_disallow_handler(int from, epoch_t mepoch)
{
  if (propose_classic_prefix(from, mepoch)) {
    return;
  }
  const set<int>& disallowed_leaders = elector->get_disallowed_leaders();
  int my_rank = elector->get_my_rank();
  bool me_disallowed = disallowed_leaders.count(my_rank);
  bool from_disallowed = disallowed_leaders.count(from);
  bool my_win = !me_disallowed && // we are allowed to lead
    (my_rank < from || from_disallowed); // we are a better choice than them
  bool their_win = !from_disallowed && // they are allowed to lead
    (my_rank > from || me_disallowed) && // they are a better choice than us
    (leader_acked < 0 || leader_acked >= from); // they are a better choice than our previously-acked choice
    
  
  if (my_win) {
    // i would win over them.
    if (leader_acked >= 0) {        // we already acked someone
      ceph_assert(leader_acked < from || from_disallowed);  // and they still win, of course
      ldout(cct, 5) << "no, we already acked " << leader_acked << dendl;
    } else {
      // wait, i should win!
      if (!electing_me) {
	elector->trigger_new_election();
      }
    }
  } else {
    // they would win over me
    if (their_win) {
      defer(from);
    } else {
      // ignore them!
      ldout(cct, 5) << "no, we already acked " << leader_acked << dendl;
    }
  }
}

void ElectionLogic::propose_classic_handler(int from, epoch_t mepoch)
{
  if (propose_classic_prefix(from, mepoch)) {
    return;
  }
  if (elector->get_my_rank() < from) {
    // i would win over them.
    if (leader_acked >= 0) {        // we already acked someone
      ceph_assert(leader_acked < from);  // and they still win, of course
      ldout(cct, 5) << "no, we already acked " << leader_acked << dendl;
    } else {
      // wait, i should win!
      if (!electing_me) {
	elector->trigger_new_election();
      }
    }
  } else {
    // they would win over me
    if (leader_acked < 0 || // haven't acked anyone yet, or
	leader_acked > from ||   // they would win over who you did ack, or
	leader_acked == from) {  // this is the guy we're already deferring to
      defer(from);
    } else {
      // ignore them!
      ldout(cct, 5) << "no, we already acked " << leader_acked << dendl;
    }
  }
}

double ElectionLogic::connectivity_election_score(int rank)
{
  if (elector->get_disallowed_leaders().count(rank)) {
    return 0;
  }
  double score;
  int liveness;
  peer_tracker->get_total_connection_score(rank, &score, &liveness);
  return score;
}

void ElectionLogic::propose_connectivity_handler(int from, epoch_t mepoch)
{
  if (mepoch > epoch) {
    bump_epoch(mepoch);
  } else if (mepoch < epoch) {
    // got an "old" propose,
    if (epoch % 2 == 0 &&    // in a non-election cycle
	!elector->is_current_member(from)) {  // from someone outside the quorum
      // a mon just started up, call a new election so they can rejoin!
      ldout(cct, 5) << " got propose from old epoch, "
	      << from << " must have just started" << dendl;
      // we may be active; make sure we reset things in the monitor appropriately.
      elector->trigger_new_election();
    } else {
      ldout(cct, 5) << " ignoring old propose" << dendl;
    }
    return;
  }

  int my_rank = elector->get_my_rank();
  double my_score = connectivity_election_score(my_rank);
  double from_score = connectivity_election_score(from);
  double leader_score = 0;
  if (leader_acked >= 0) {
    leader_score = connectivity_election_score(leader_acked);
  }

  ldout(cct, 10) << "propose from rank=" << from << ",score=" << from_score
		 << "; my score=" << my_score
		 << "; currently acked " << leader_acked
		 << ",score=" << leader_score << dendl;

  bool my_win = (my_score > 0) && // My score is non-zero; I am allowed to lead
    ((my_rank < from && my_score >= from_score) || // We have same scores and I have lower rank, or
     (my_score > from_score)); // my score is higher
  
  bool their_win = (from_score > 0) && // Their score is non-zero; they're allowed to lead, AND
    ((from < my_rank && from_score >= my_score) || // Either they have lower rank and same score, or
     (from_score > my_score)) && // their score is higher, AND
    ((from <= leader_acked && from_score >= leader_score) || // same conditions compared to leader, or IS leader
     (from_score > leader_score));

  if (my_win) {
    // i would win over them.
    if (leader_acked >= 0) {        // we already acked someone
      ceph_assert(leader_score >= from_score);  // and they still win, of course
      ldout(cct, 5) << "no, we already acked " << leader_acked << dendl;
    } else {
      // wait, i should win!
      if (!electing_me) {
	elector->trigger_new_election();
      }
    }
  } else {
    // they would win over me
    if (their_win) {
      defer(from);
    } else {
      // ignore them!
      ldout(cct, 5) << "no, we already acked " << leader_acked << " with score >=" << from_score << dendl;
    }
  }
}

void ElectionLogic::receive_ack(int from, epoch_t from_epoch)
{
  ceph_assert(from_epoch % 2 == 1); // sender in an election epoch
  if (from_epoch > epoch) {
    ldout(cct, 5) << "woah, that's a newer epoch, i must have rebooted.  bumping and re-starting!" << dendl;
    bump_epoch(from_epoch);
    start();
    return;
  }
  // is that _everyone_?
  if (electing_me) {
    acked_me.insert(from);
    if (acked_me.size() == elector->paxos_size()) {
      // if yes, shortcut to election finish
      declare_victory();
    }
  } else {
    // ignore, i'm deferring already.
    ceph_assert(leader_acked >= 0);
  }
}

bool ElectionLogic::victory_makes_sense(int from)
{
  bool makes_sense = false;
  switch (strategy) {
  case CLASSIC:
    makes_sense = (from < elector->get_my_rank());
    break;
  case DISALLOW:
    makes_sense = (from < elector->get_my_rank()) ||
      elector->get_disallowed_leaders().count(elector->get_my_rank());
    break;
  case CONNECTIVITY:
    double my_score, leader_score;
    my_score = connectivity_election_score(elector->get_my_rank());
    leader_score = connectivity_election_score(from);
    ldout(cct, 5) << "victory from " << from << " makes sense? lscore:"
		  << leader_score
		  << "; my score:" << my_score << dendl;

    // TODO: this probably isn't safe because we may be behind on score states?
    makes_sense = (leader_score >= my_score);
    break;
  default:
    ceph_assert(0 == "how did you get a nonsense election strategy assigned?");
  }
  return makes_sense;
}

bool ElectionLogic::receive_victory_claim(int from, epoch_t from_epoch)
{
  ceph_assert(victory_makes_sense(from));

  last_election_winner = from;
  leader_acked = -1;

  // i should have seen this election if i'm getting the victory.
  if (from_epoch != epoch + 1) { 
    ldout(cct, 5) << "woah, that's a funny epoch, i must have rebooted.  bumping and re-starting!" << dendl;
    bump_epoch(from_epoch);
    start();
    return false;
  }

  bump_epoch(from_epoch);

  // they win
  return true;
}
