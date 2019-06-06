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

#include "Elector.h"
#include "Monitor.h"

#include "common/Timer.h"
#include "MonitorDBStore.h"
#include "messages/MMonElection.h"

#include "common/config.h"
#include "include/ceph_assert.h"

#define dout_subsys ceph_subsys_mon
#undef dout_prefix
#define dout_prefix _prefix(_dout, mon, logic.epoch)
static ostream& _prefix(std::ostream *_dout, Monitor *mon, epoch_t epoch) {
  return *_dout << "mon." << mon->name << "@" << mon->rank
		<< "(" << mon->get_state_name()
		<< ").elector(" << epoch << ") ";
}

void ElectionLogic::persist_epoch(epoch_t e)
{
  auto t(std::make_shared<MonitorDBStore::Transaction>());
  t->put(Monitor::MONITOR_NAME, "election_epoch", e);
  mon->store->apply_transaction(t);
}

void ElectionLogic::validate_store()
{
  auto t(std::make_shared<MonitorDBStore::Transaction>());
  t->put(Monitor::MONITOR_NAME, "election_writeable_test", rand());
  int r = mon->store->apply_transaction(t);
  ceph_assert(r >= 0);
}

void Elector::init()
{
  logic.epoch = mon->store->get(Monitor::MONITOR_NAME, "election_epoch");
  if (!logic.epoch) {
    dout(1) << "init, first boot, initializing epoch at 1 " << dendl;
    logic.epoch = 1;
  } else if (logic.epoch % 2) {
    dout(1) << "init, last seen epoch " << logic.epoch
	    << ", mid-election, bumping" << dendl;
    ++logic.epoch;
    auto t(std::make_shared<MonitorDBStore::Transaction>());
    t->put(Monitor::MONITOR_NAME, "election_epoch", logic.epoch);
    mon->store->apply_transaction(t);
  } else {
    dout(1) << "init, last seen epoch " << logic.epoch << dendl;
  }
}

void Elector::shutdown()
{
  cancel_timer();
}

void Elector::bump_epoch(epoch_t e) 
{
  dout(10) << "bump_epoch " << logic.epoch << " to " << e << dendl;
  ceph_assert(logic.epoch <= e);
  logic.epoch = e;
  auto t(std::make_shared<MonitorDBStore::Transaction>());
  t->put(Monitor::MONITOR_NAME, "election_epoch", logic.epoch);
  mon->store->apply_transaction(t);

  mon->join_election();

  // clear up some state
  logic.electing_me = false;
  logic.acked_me.clear();
  peer_info.clear();
}


void Elector::start()
{
  if (!participating) {
    dout(0) << "not starting new election -- not participating" << dendl;
    return;
  }
  dout(5) << "start -- can i be leader?" << dendl;

  logic.acked_me.clear();
  peer_info.clear();
  init();
  
  // start by trying to elect me
  if (logic.epoch % 2 == 0) {
    bump_epoch(logic.epoch+1);  // odd == election cycle
  } else {
    // do a trivial db write just to ensure it is writeable.
    auto t(std::make_shared<MonitorDBStore::Transaction>());
    t->put(Monitor::MONITOR_NAME, "election_writeable_test", rand());
    int r = mon->store->apply_transaction(t);
    ceph_assert(r >= 0);
  }
  logic.electing_me = true;
  logic.acked_me.insert(mon->rank);
  peer_info[mon->rank].cluster_features = CEPH_FEATURES_ALL;
  peer_info[mon->rank].mon_release = ceph_release();
  peer_info[mon->rank].mon_features = ceph::features::mon::get_supported();
  mon->collect_metadata(&peer_info[mon->rank].metadata);
  logic.leader_acked = -1;

  // bcast to everyone else
  for (unsigned i=0; i<mon->monmap->size(); ++i) {
    if ((int)i == mon->rank) continue;
    MMonElection *m =
      new MMonElection(MMonElection::OP_PROPOSE, logic.epoch, mon->monmap);
    m->mon_features = ceph::features::mon::get_supported();
    m->mon_release = ceph_release();
    mon->send_mon_message(m, i);
  }
  
  reset_timer();
}

void Elector::defer(int who)
{
  dout(5) << "defer to " << who << dendl;

  if (logic.electing_me) {
    // drop out
    logic.acked_me.clear();
    peer_info.clear();
    logic.electing_me = false;
  }

  // ack them
  logic.leader_acked = who;
  MMonElection *m = new MMonElection(MMonElection::OP_ACK, logic.epoch, mon->monmap);
  m->mon_features = ceph::features::mon::get_supported();
  m->mon_release = ceph_release();
  mon->collect_metadata(&m->metadata);

  mon->send_mon_message(m, who);
  
  // set a timer
  reset_timer(1.0);  // give the leader some extra time to declare victory
}


void Elector::reset_timer(double plus)
{
  // set the timer
  cancel_timer();
  /**
   * This class is used as the callback when the expire_event timer fires up.
   *
   * If the expire_event is fired, then it means that we had an election going,
   * either started by us or by some other participant, but it took too long,
   * thus expiring.
   *
   * When the election expires, we will check if we were the ones who won, and
   * if so we will declare victory. If that is not the case, then we assume
   * that the one we defered to didn't declare victory quickly enough (in fact,
   * as far as we know, we may even be dead); so, just propose ourselves as the
   * Leader.
   */
  expire_event = mon->timer.add_event_after(
    g_conf()->mon_election_timeout + plus,
    new C_MonContext(mon, [this](int) {
	expire();
      }));
}


void Elector::cancel_timer()
{
  if (expire_event) {
    mon->timer.cancel_event(expire_event);
    expire_event = 0;
  }
}

void Elector::expire()
{
  dout(5) << "election timer expired" << dendl;
  
  // did i win?
  if (logic.electing_me &&
      logic.acked_me.size() > (unsigned)(mon->monmap->size() / 2)) {
    // i win
    victory();
  } else {
    // whoever i deferred to didn't declare victory quickly enough.
    if (mon->has_ever_joined)
      start();
    else
      mon->bootstrap();
  }
}


void Elector::victory()
{
  logic.leader_acked = -1;
  logic.electing_me = false;

  uint64_t cluster_features = CEPH_FEATURES_ALL;
  mon_feature_t mon_features = ceph::features::mon::get_supported();
  set<int> quorum;
  map<int,Metadata> metadata;
  int min_mon_release = -1;
  for (auto id : logic.acked_me) {
    quorum.insert(id);
    auto i = peer_info.find(id);
    ceph_assert(i != peer_info.end());
    auto& info = i->second;
    cluster_features &= info.cluster_features;
    mon_features &= info.mon_features;
    metadata[id] = info.metadata;
    if (min_mon_release < 0 ||
	info.mon_release < min_mon_release) {
      min_mon_release = info.mon_release;
    }
  }

  cancel_timer();
  
  ceph_assert(logic.epoch % 2 == 1);  // election
  bump_epoch(logic.epoch+1);     // is over!

  // tell everyone!
  for (set<int>::iterator p = quorum.begin();
       p != quorum.end();
       ++p) {
    if (*p == mon->rank) continue;
    MMonElection *m = new MMonElection(MMonElection::OP_VICTORY, logic.epoch,
				       mon->monmap);
    m->quorum = quorum;
    m->quorum_features = cluster_features;
    m->mon_features = mon_features;
    m->sharing_bl = mon->get_local_commands_bl(mon_features);
    m->mon_release = min_mon_release;
    mon->send_mon_message(m, *p);
  }

  // tell monitor
  mon->win_election(logic.epoch, quorum,
                    cluster_features, mon_features, min_mon_release,
		    metadata);
}


void Elector::handle_propose(MonOpRequestRef op)
{
  op->mark_event("elector:handle_propose");
  MMonElection *m = static_cast<MMonElection*>(op->get_req());
  dout(5) << "handle_propose from " << m->get_source() << dendl;
  int from = m->get_source().num();

  ceph_assert(m->epoch % 2 == 1); // election
  uint64_t required_features = mon->get_required_features();
  mon_feature_t required_mon_features = mon->get_required_mon_features();

  dout(10) << __func__ << " required features " << required_features
           << " " << required_mon_features
           << ", peer features " << m->get_connection()->get_features()
           << " " << m->mon_features
           << dendl;

  if ((required_features ^ m->get_connection()->get_features()) &
      required_features) {
    dout(5) << " ignoring propose from mon" << from
	    << " without required features" << dendl;
    nak_old_peer(op);
    return;
  } else if (mon->monmap->min_mon_release > m->mon_release) {
    dout(5) << " ignoring propose from mon" << from
	    << " release " << (int)m->mon_release
	    << " < min_mon_release " << (int)mon->monmap->min_mon_release
	    << dendl;
    nak_old_peer(op);
    return;
  } else if (!m->mon_features.contains_all(required_mon_features)) {
    // all the features in 'required_mon_features' not in 'm->mon_features'
    mon_feature_t missing = required_mon_features.diff(m->mon_features);
    dout(5) << " ignoring propose from mon." << from
            << " without required mon_features " << missing
            << dendl;
    nak_old_peer(op);
  } else if (m->epoch > logic.epoch) {
    bump_epoch(m->epoch);
  } else if (m->epoch < logic.epoch) {
    // got an "old" propose,
    if (logic.epoch % 2 == 0 &&    // in a non-election cycle
	mon->quorum.count(from) == 0) {  // from someone outside the quorum
      // a mon just started up, call a new election so they can rejoin!
      dout(5) << " got propose from old epoch, quorum is " << mon->quorum 
	      << ", " << m->get_source() << " must have just started" << dendl;
      // we may be active; make sure we reset things in the monitor appropriately.
      mon->start_election();
    } else {
      dout(5) << " ignoring old propose" << dendl;
    }
    return;
  }

  if (mon->rank < from) {
    // i would win over them.
    if (logic.leader_acked >= 0) {        // we already acked someone
      ceph_assert(logic.leader_acked < from);  // and they still win, of course
      dout(5) << "no, we already acked " << logic.leader_acked << dendl;
    } else {
      // wait, i should win!
      if (!logic.electing_me) {
	mon->start_election();
      }
    }
  } else {
    // they would win over me
    if (logic.leader_acked < 0 ||      // haven't acked anyone yet, or
	logic.leader_acked > from ||   // they would win over who you did ack, or
	logic.leader_acked == from) {  // this is the guy we're already deferring to
      defer(from);
    } else {
      // ignore them!
      dout(5) << "no, we already acked " << logic.leader_acked << dendl;
    }
  }
}

void Elector::handle_ack(MonOpRequestRef op)
{
  op->mark_event("elector:handle_ack");
  MMonElection *m = static_cast<MMonElection*>(op->get_req());
  dout(5) << "handle_ack from " << m->get_source() << dendl;
  int from = m->get_source().num();

  ceph_assert(m->epoch % 2 == 1); // election
  if (m->epoch > logic.epoch) {
    dout(5) << "woah, that's a newer epoch, i must have rebooted.  bumping and re-starting!" << dendl;
    bump_epoch(m->epoch);
    start();
    return;
  }
  ceph_assert(m->epoch == logic.epoch);
  uint64_t required_features = mon->get_required_features();
  if ((required_features ^ m->get_connection()->get_features()) &
      required_features) {
    dout(5) << " ignoring ack from mon" << from
	    << " without required features" << dendl;
    return;
  }

  mon_feature_t required_mon_features = mon->get_required_mon_features();
  if (!m->mon_features.contains_all(required_mon_features)) {
    mon_feature_t missing = required_mon_features.diff(m->mon_features);
    dout(5) << " ignoring ack from mon." << from
            << " without required mon_features " << missing
            << dendl;
    return;
  }

  if (logic.electing_me) {
    // thanks
    peer_info[from].cluster_features = m->get_connection()->get_features();
    peer_info[from].mon_features = m->mon_features;
    peer_info[from].mon_release = m->mon_release;
    peer_info[from].metadata = m->metadata;
    dout(5) << " so far i have {";
    for (auto q = logic.acked_me.begin();
         q != logic.acked_me.end();
         ++q) {
      auto p = peer_info.find(*q);
      ceph_assert(p != peer_info.end());
      if (q != logic.acked_me.begin())
        *_dout << ",";
      *_dout << " mon." << p->first << ":"
             << " features " << p->second.cluster_features
             << " " << p->second.mon_features;
    }
    *_dout << " }" << dendl;

    // is that _everyone_?
    if (logic.acked_me.size() == mon->monmap->size()) {
      // if yes, shortcut to election finish
      victory();
    }
  } else {
    // ignore, i'm deferring already.
    ceph_assert(logic.leader_acked >= 0);
  }
}


void Elector::handle_victory(MonOpRequestRef op)
{
  op->mark_event("elector:handle_victory");
  MMonElection *m = static_cast<MMonElection*>(op->get_req());
  dout(5) << "handle_victory from " << m->get_source()
          << " quorum_features " << m->quorum_features
          << " " << m->mon_features
          << dendl;
  int from = m->get_source().num();

  ceph_assert(from < mon->rank);
  ceph_assert(m->epoch % 2 == 0);  

  logic.leader_acked = -1;

  // i should have seen this election if i'm getting the victory.
  if (m->epoch != logic.epoch + 1) { 
    dout(5) << "woah, that's a funny epoch, i must have rebooted.  bumping and re-starting!" << dendl;
    bump_epoch(m->epoch);
    start();
    return;
  }

  bump_epoch(m->epoch);

  // they win
  mon->lose_election(logic.epoch, m->quorum, from,
                     m->quorum_features, m->mon_features, m->mon_release);

  // cancel my timer
  cancel_timer();

  // stash leader's commands
  ceph_assert(m->sharing_bl.length());
  vector<MonCommand> new_cmds;
  auto bi = m->sharing_bl.cbegin();
  MonCommand::decode_vector(new_cmds, bi);
  mon->set_leader_commands(new_cmds);
}

void Elector::nak_old_peer(MonOpRequestRef op)
{
  op->mark_event("elector:nak_old_peer");
  MMonElection *m = static_cast<MMonElection*>(op->get_req());
  uint64_t supported_features = m->get_connection()->get_features();
  uint64_t required_features = mon->get_required_features();
  mon_feature_t required_mon_features = mon->get_required_mon_features();
  dout(10) << "sending nak to peer " << m->get_source()
	   << " supports " << supported_features << " " << m->mon_features
	   << ", required " << required_features << " " << required_mon_features
	   << ", release " << (int)m->mon_release
	   << " vs required " << (int)mon->monmap->min_mon_release
	   << dendl;
  MMonElection *reply = new MMonElection(MMonElection::OP_NAK, m->epoch,
                                         mon->monmap);
  reply->quorum_features = required_features;
  reply->mon_features = required_mon_features;
  reply->mon_release = mon->monmap->min_mon_release;
  mon->features.encode(reply->sharing_bl);
  m->get_connection()->send_message(reply);
}

void Elector::handle_nak(MonOpRequestRef op)
{
  op->mark_event("elector:handle_nak");
  MMonElection *m = static_cast<MMonElection*>(op->get_req());
  dout(1) << "handle_nak from " << m->get_source()
	  << " quorum_features " << m->quorum_features
          << " " << m->mon_features
	  << " min_mon_release " << (int)m->mon_release
          << dendl;

  if (m->mon_release > ceph_release()) {
    derr << "Shutting down because I am release " << (int)ceph_release()
	 << " < min_mon_release " << (int)m->mon_release << dendl;
  } else {
    CompatSet other;
    auto bi = m->sharing_bl.cbegin();
    other.decode(bi);
    CompatSet diff = Monitor::get_supported_features().unsupported(other);

    mon_feature_t mon_supported = ceph::features::mon::get_supported();
    // all features in 'm->mon_features' not in 'mon_supported'
    mon_feature_t mon_diff = m->mon_features.diff(mon_supported);

    derr << "Shutting down because I lack required monitor features: { "
	 << diff << " } " << mon_diff << dendl;
  }
  exit(0);
  // the end!
}

void Elector::dispatch(MonOpRequestRef op)
{
  op->mark_event("elector:dispatch");
  ceph_assert(op->is_type_election());

  switch (op->get_req()->get_type()) {
    
  case MSG_MON_ELECTION:
    {
      if (!participating) {
        return;
      }
      if (op->get_req()->get_source().num() >= mon->monmap->size()) {
	dout(5) << " ignoring bogus election message with bad mon rank " 
		<< op->get_req()->get_source() << dendl;
	return;
      }

      MMonElection *em = static_cast<MMonElection*>(op->get_req());

      // assume an old message encoding would have matched
      if (em->fsid != mon->monmap->fsid) {
	dout(0) << " ignoring election msg fsid " 
		<< em->fsid << " != " << mon->monmap->fsid << dendl;
	return;
      }

      if (!mon->monmap->contains(em->get_source_addr())) {
	dout(1) << "discarding election message: " << em->get_source_addr()
		<< " not in my monmap " << *mon->monmap << dendl;
	return;
      }

      MonMap peermap;
      peermap.decode(em->monmap_bl);
      if (peermap.epoch > mon->monmap->epoch) {
	dout(0) << em->get_source_inst() << " has newer monmap epoch " << peermap.epoch
		<< " > my epoch " << mon->monmap->epoch 
		<< ", taking it"
		<< dendl;
	mon->monmap->decode(em->monmap_bl);
        auto t(std::make_shared<MonitorDBStore::Transaction>());
        t->put("monmap", mon->monmap->epoch, em->monmap_bl);
        t->put("monmap", "last_committed", mon->monmap->epoch);
        mon->store->apply_transaction(t);
	//mon->monmon()->paxos->stash_latest(mon->monmap->epoch, em->monmap_bl);
	cancel_timer();
	mon->bootstrap();
	return;
      }
      if (peermap.epoch < mon->monmap->epoch) {
	dout(0) << em->get_source_inst() << " has older monmap epoch " << peermap.epoch
		<< " < my epoch " << mon->monmap->epoch 
		<< dendl;
      } 

      switch (em->op) {
      case MMonElection::OP_PROPOSE:
	handle_propose(op);
	return;
      }

      if (em->epoch < logic.epoch) {
	dout(5) << "old epoch, dropping" << dendl;
	break;
      }

      switch (em->op) {
      case MMonElection::OP_ACK:
	handle_ack(op);
	return;
      case MMonElection::OP_VICTORY:
	handle_victory(op);
	return;
      case MMonElection::OP_NAK:
	handle_nak(op);
	return;
      default:
	ceph_abort();
      }
    }
    break;
    
  default: 
    ceph_abort();
  }
}

void Elector::start_participating()
{
  if (!participating) {
    participating = true;
  }
}
