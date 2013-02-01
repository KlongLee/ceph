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

#include "common/config.h"
#include "osdc/Journaler.h"
#include "events/ESubtreeMap.h"
#include "events/ESession.h"
#include "events/ESessions.h"

#include "events/EMetaBlob.h"
#include "events/EResetJournal.h"

#include "events/EUpdate.h"
#include "events/ESlaveUpdate.h"
#include "events/EOpen.h"
#include "events/ECommitted.h"

#include "events/EExport.h"
#include "events/EImportStart.h"
#include "events/EImportFinish.h"
#include "events/EFragment.h"

#include "events/ETableClient.h"
#include "events/ETableServer.h"


#include "LogSegment.h"

#include "MDS.h"
#include "MDLog.h"
#include "MDCache.h"
#include "Server.h"
#include "Migrator.h"
#include "Mutation.h"

#include "InoTable.h"
#include "MDSTableClient.h"
#include "MDSTableServer.h"

#include "Locker.h"

#define dout_subsys ceph_subsys_mds
#undef DOUT_COND
#define DOUT_COND(cct, l) (l<=cct->_conf->debug_mds || l <= cct->_conf->debug_mds_log \
			      || l <= cct->_conf->debug_mds_log_expire)
#undef dout_prefix
#define dout_prefix *_dout << "mds." << mds->get_nodeid() << ".journal "


// -----------------------
// LogSegment

void LogSegment::try_to_expire(MDS *mds, C_GatherBuilder &gather_bld)
{
  set<CDir*> commit;

  dout(6) << "LogSegment(" << offset << ").try_to_expire" << dendl;

  // commit dirs
  for (elist<CDir*>::iterator p = new_dirfrags.begin(); !p.end(); ++p) {
    dout(20) << " new_dirfrag " << **p << dendl;
    assert((*p)->is_auth());
    commit.insert(*p);
  }
  for (elist<CDir*>::iterator p = dirty_dirfrags.begin(); !p.end(); ++p) {
    dout(20) << " dirty_dirfrag " << **p << dendl;
    assert((*p)->is_auth());
    commit.insert(*p);
  }
  for (elist<CDentry*>::iterator p = dirty_dentries.begin(); !p.end(); ++p) {
    dout(20) << " dirty_dentry " << **p << dendl;
    assert((*p)->is_auth());
    commit.insert((*p)->get_dir());
  }
  for (elist<CInode*>::iterator p = dirty_inodes.begin(); !p.end(); ++p) {
    dout(20) << " dirty_inode " << **p << dendl;
    assert((*p)->is_auth());
    if ((*p)->is_base()) {
      (*p)->store(gather_bld.new_sub());
    } else
      commit.insert((*p)->get_parent_dn()->get_dir());
  }

  if (!commit.empty()) {
    for (set<CDir*>::iterator p = commit.begin();
	 p != commit.end();
	 ++p) {
      CDir *dir = *p;
      assert(dir->is_auth());
      if (dir->can_auth_pin()) {
	dout(15) << "try_to_expire committing " << *dir << dendl;
	dir->commit(0, gather_bld.new_sub());
      } else {
	dout(15) << "try_to_expire waiting for unfreeze on " << *dir << dendl;
	dir->add_waiter(CDir::WAIT_UNFREEZE, gather_bld.new_sub());
      }
    }
  }

  // master ops with possibly uncommitted slaves
  for (set<metareqid_t>::iterator p = uncommitted_masters.begin();
       p != uncommitted_masters.end();
       p++) {
    dout(10) << "try_to_expire waiting for slaves to ack commit on " << *p << dendl;
    mds->mdcache->wait_for_uncommitted_master(*p, gather_bld.new_sub());
  }

  // nudge scatterlocks
  for (elist<CInode*>::iterator p = dirty_dirfrag_dir.begin(); !p.end(); ++p) {
    CInode *in = *p;
    dout(10) << "try_to_expire waiting for dirlock flush on " << *in << dendl;
    mds->locker->scatter_nudge(&in->filelock, gather_bld.new_sub());
  }
  for (elist<CInode*>::iterator p = dirty_dirfrag_dirfragtree.begin(); !p.end(); ++p) {
    CInode *in = *p;
    dout(10) << "try_to_expire waiting for dirfragtreelock flush on " << *in << dendl;
    mds->locker->scatter_nudge(&in->dirfragtreelock, gather_bld.new_sub());
  }
  for (elist<CInode*>::iterator p = dirty_dirfrag_nest.begin(); !p.end(); ++p) {
    CInode *in = *p;
    dout(10) << "try_to_expire waiting for nest flush on " << *in << dendl;
    mds->locker->scatter_nudge(&in->nestlock, gather_bld.new_sub());
  }

  // open files
  if (!open_files.empty()) {
    assert(!mds->mdlog->is_capped()); // hmm FIXME
    EOpen *le = 0;
    LogSegment *ls = mds->mdlog->get_current_segment();
    assert(ls != this);
    elist<CInode*>::iterator p = open_files.begin(member_offset(CInode, item_open_file));
    while (!p.end()) {
      CInode *in = *p;
      assert(in->last == CEPH_NOSNAP);
      ++p;
      if (in->is_auth() && in->is_any_caps()) {
	if (in->is_any_caps_wanted()) {
	  dout(20) << "try_to_expire requeueing open file " << *in << dendl;
	  if (!le) {
	    le = new EOpen(mds->mdlog);
	    mds->mdlog->start_entry(le);
	  }
	  le->add_clean_inode(in);
	  ls->open_files.push_back(&in->item_open_file);
	} else {
	  // drop inodes that aren't wanted
	  dout(20) << "try_to_expire not requeueing and delisting unwanted file " << *in << dendl;
	  in->item_open_file.remove_myself();
	}
      } else {
	/*
	 * we can get a capless inode here if we replay an open file, the client fails to
	 * reconnect it, but does REPLAY an open request (that adds it to the logseg).  AFAICS
	 * it's ok for the client to replay an open on a file it doesn't have in it's cache
	 * anymore.
	 *
	 * this makes the mds less sensitive to strict open_file consistency, although it does
	 * make it easier to miss subtle problems.
	 */
	dout(20) << "try_to_expire not requeueing and delisting capless file " << *in << dendl;
	in->item_open_file.remove_myself();
      }
    }
    if (le) {
      mds->mdlog->submit_entry(le, gather_bld.new_sub());
      dout(10) << "try_to_expire waiting for open files to rejournal" << dendl;
    }
  }

  // parent pointers on renamed dirs
  for (elist<CInode*>::iterator p = renamed_files.begin(); !p.end(); ++p) {
    CInode *in = *p;
    dout(10) << "try_to_expire waiting for dir parent pointer update on " << *in << dendl;
    assert(in->state_test(CInode::STATE_DIRTYPARENT));
    in->store_parent(gather_bld.new_sub());
  }

  // slave updates
  for (elist<MDSlaveUpdate*>::iterator p = slave_updates.begin(member_offset(MDSlaveUpdate,
									     item));
       !p.end(); ++p) {
    MDSlaveUpdate *su = *p;
    dout(10) << "try_to_expire waiting on slave update " << su << dendl;
    assert(su->waiter == 0);
    su->waiter = gather_bld.new_sub();
  }

  // idalloc
  if (inotablev > mds->inotable->get_committed_version()) {
    dout(10) << "try_to_expire saving inotable table, need " << inotablev
	      << ", committed is " << mds->inotable->get_committed_version()
	      << " (" << mds->inotable->get_committing_version() << ")"
	      << dendl;
    mds->inotable->save(gather_bld.new_sub(), inotablev);
  }

  // sessionmap
  if (sessionmapv > mds->sessionmap.committed) {
    dout(10) << "try_to_expire saving sessionmap, need " << sessionmapv 
	      << ", committed is " << mds->sessionmap.committed
	      << " (" << mds->sessionmap.committing << ")"
	      << dendl;
    mds->sessionmap.save(gather_bld.new_sub(), sessionmapv);
  }

  // pending commit atids
  for (map<int, hash_set<version_t> >::iterator p = pending_commit_tids.begin();
       p != pending_commit_tids.end();
       ++p) {
    MDSTableClient *client = mds->get_table_client(p->first);
    for (hash_set<version_t>::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      dout(10) << "try_to_expire " << get_mdstable_name(p->first) << " transaction " << *q 
	       << " pending commit (not yet acked), waiting" << dendl;
      assert(!client->has_committed(*q));
      client->wait_for_ack(*q, gather_bld.new_sub());
    }
  }
  
  // table servers
  for (map<int, version_t>::iterator p = tablev.begin();
       p != tablev.end();
       p++) {
    MDSTableServer *server = mds->get_table_server(p->first);
    if (p->second > server->get_committed_version()) {
      dout(10) << "try_to_expire waiting for " << get_mdstable_name(p->first) 
	       << " to save, need " << p->second << dendl;
      server->save(gather_bld.new_sub());
    }
  }

  // truncating
  for (set<CInode*>::iterator p = truncating_inodes.begin();
       p != truncating_inodes.end();
       p++) {
    dout(10) << "try_to_expire waiting for truncate of " << **p << dendl;
    (*p)->add_waiter(CInode::WAIT_TRUNC, gather_bld.new_sub());
  }
  
  // FIXME client requests...?
  // audit handling of anchor transactions?

  if (gather_bld.has_subs()) {
    dout(6) << "LogSegment(" << offset << ").try_to_expire waiting" << dendl;
    mds->mdlog->flush();
  } else {
    dout(6) << "LogSegment(" << offset << ").try_to_expire success" << dendl;
  }
}


#undef DOUT_COND
#define DOUT_COND(cct, l) (l<=cct->_conf->debug_mds || l <= cct->_conf->debug_mds_log)


// -----------------------
// EMetaBlob

EMetaBlob::EMetaBlob(MDLog *mdlog) : opened_ino(0), renamed_dirino(0),
				     inotablev(0), sessionmapv(0),
				     allocated_ino(0),
				     last_subtree_map(mdlog ? mdlog->get_last_segment_offset() : 0),
				     my_offset(mdlog ? mdlog->get_write_pos() : 0) //, _segment(0)
{ }

void EMetaBlob::add_dir_context(CDir *dir, int mode)
{
  MDS *mds = dir->cache->mds;

  list<CDentry*> parents;

  // it may be okay not to include the maybe items, if
  //  - we journaled the maybe child inode in this segment
  //  - that subtree turns out to be unambiguously auth
  list<CDentry*> maybe;
  bool maybenot = false;

  while (true) {
    // already have this dir?  (we must always add in order)
    if (lump_map.count(dir->dirfrag())) {
      dout(20) << "EMetaBlob::add_dir_context(" << dir << ") have lump " << dir->dirfrag() << dendl;
      break;
    }
      
    // stop at root/stray
    CInode *diri = dir->get_inode();
    CDentry *parent = diri->get_projected_parent_dn();

    if (!parent)
      break;

    if (mode == TO_AUTH_SUBTREE_ROOT) {
      // subtree root?
      if (dir->is_subtree_root()) {
	if (dir->is_auth() && !dir->is_ambiguous_auth()) {
	  // it's an auth subtree, we don't need maybe (if any), and we're done.
	  dout(20) << "EMetaBlob::add_dir_context(" << dir << ") reached unambig auth subtree, don't need " << maybe
		   << " at " << *dir << dendl;
	  maybe.clear();
	  break;
	} else {
	  dout(20) << "EMetaBlob::add_dir_context(" << dir << ") reached ambig or !auth subtree, need " << maybe
		   << " at " << *dir << dendl;
	  // we need the maybe list after all!
	  parents.splice(parents.begin(), maybe);
	  maybenot = false;
	}
      }
      
      // was the inode journaled in this blob?
      if (my_offset && diri->last_journaled == my_offset) {
	dout(20) << "EMetaBlob::add_dir_context(" << dir << ") already have diri this blob " << *diri << dendl;
	break;
      }

      // have we journaled this inode since the last subtree map?
      if (!maybenot && last_subtree_map && diri->last_journaled >= last_subtree_map) {
	dout(20) << "EMetaBlob::add_dir_context(" << dir << ") already have diri in this segment (" 
		 << diri->last_journaled << " >= " << last_subtree_map << "), setting maybenot flag "
		 << *diri << dendl;
	maybenot = true;
      }
    }

    if (maybenot) {
      dout(25) << "EMetaBlob::add_dir_context(" << dir << ")      maybe " << *parent << dendl;
      maybe.push_front(parent);
    } else {
      dout(25) << "EMetaBlob::add_dir_context(" << dir << ") definitely " << *parent << dendl;
      parents.push_front(parent);
    }
    
    dir = parent->get_dir();
  }
  
  parents.splice(parents.begin(), maybe);

  dout(20) << "EMetaBlob::add_dir_context final: " << parents << dendl;
  for (list<CDentry*>::iterator p = parents.begin(); p != parents.end(); p++) {
    assert((*p)->get_projected_linkage()->is_primary());
    add_dentry(*p, false);
  }
}

void EMetaBlob::update_segment(LogSegment *ls)
{
  // atids?
  //for (list<version_t>::iterator p = atids.begin(); p != atids.end(); ++p)
  //  ls->pending_commit_atids[*p] = ls;
  // -> handled directly by AnchorClient

  // dirty inode mtimes
  // -> handled directly by Server.cc, replay()

  // alloc table update?
  if (inotablev)
    ls->inotablev = inotablev;
  if (sessionmapv)
    ls->sessionmapv = sessionmapv;

  // truncated inodes
  // -> handled directly by Server.cc

  // client requests
  //  note the newest request per client
  //if (!client_reqs.empty())
    //    ls->last_client_tid[client_reqs.rbegin()->client] = client_reqs.rbegin()->tid);
}

// EMetaBlob::fullbit

void EMetaBlob::fullbit::encode(bufferlist& bl) const {
  ENCODE_START(4, 4, bl);
  if (!_enc.length()) {
    fullbit copy(dn, dnfirst, dnlast, dnv, inode, dirfragtree, xattrs, symlink,
		 snapbl, dirty, dir_layout, &old_inodes);
    bl.append(copy._enc);
  } else {
    bl.append(_enc);
  }
  ENCODE_FINISH(bl);
}

void EMetaBlob::fullbit::decode(bufferlist::iterator &bl) {
  DECODE_START_LEGACY_COMPAT_LEN(4, 4, 4, bl);
  ::decode(dn, bl);
  ::decode(dnfirst, bl);
  ::decode(dnlast, bl);
  ::decode(dnv, bl);
  ::decode(inode, bl);
  ::decode(xattrs, bl);
  if (inode.is_symlink())
    ::decode(symlink, bl);
  if (inode.is_dir()) {
    ::decode(dirfragtree, bl);
    ::decode(snapbl, bl);
    if (struct_v >= 2) {
      bool dir_layout_exists;
      ::decode(dir_layout_exists, bl);
      if (dir_layout_exists) {
	dir_layout = new file_layout_policy_t;
	::decode(*dir_layout, bl);
      }
    }
  }
  ::decode(dirty, bl);
  if (struct_v >= 3) {
    bool old_inodes_present;
    ::decode(old_inodes_present, bl);
    if (old_inodes_present) {
      ::decode(old_inodes, bl);
    }
  }
  DECODE_FINISH(bl);
}

void EMetaBlob::fullbit::dump(Formatter *f) const
{
  if (_enc.length() && !dn.length()) {
    /* if our bufferlist has data but our name is empty, we
     * haven't initialized ourselves; do so in order to print members!
     * We use const_cast here because the whole point is we aren't
     * fully set up and this isn't changing who we "are", just our
     * representation.
     */
    EMetaBlob::fullbit *me = const_cast<EMetaBlob::fullbit*>(this);
    bufferlist encoded;
    encode(encoded);
    bufferlist::iterator p = encoded.begin();
    me->decode(p);
  }
  f->dump_string("dentry", dn);
  f->dump_stream("snapid.first") << dnfirst;
  f->dump_stream("snapid.last") << dnlast;
  f->dump_int("dentry version", dnv);
  f->open_object_section("inode");
  inode.dump(f);
  f->close_section(); // inode
  f->open_array_section("xattrs");
  for (map<string, bufferptr>::const_iterator iter = xattrs.begin();
      iter != xattrs.end(); ++iter) {
    f->dump_string(iter->first.c_str(), iter->second.c_str());
  }
  f->close_section(); // xattrs
  if (inode.is_symlink()) {
    f->dump_string("symlink", symlink);
  }
  if (inode.is_dir()) {
    f->dump_stream("frag tree") << dirfragtree;
    f->dump_string("has_snapbl", snapbl.length() ? "true" : "false");
    if (dir_layout) {
      f->open_object_section("file layout policy");
      dir_layout->dump(f);
      f->close_section(); // file layout policy
    }
  }
  f->dump_string("dirty", dirty ? "true" : "false");
  if (old_inodes.size()) {
    f->open_array_section("old inodes");
    for (old_inodes_t::const_iterator iter = old_inodes.begin();
	iter != old_inodes.end(); ++iter) {
      f->open_object_section("inode");
      f->dump_int("snapid", iter->first);
      iter->second.dump(f);
      f->close_section(); // inode
    }
    f->close_section(); // old inodes
  }
}

void EMetaBlob::fullbit::generate_test_instances(list<EMetaBlob::fullbit*>& ls)
{
  inode_t inode;
  fragtree_t fragtree;
  map<string,bufferptr> empty_xattrs;
  bufferlist empty_snapbl;
  fullbit *sample = new fullbit("/testdn", 0, 0, 0,
                                inode, fragtree, empty_xattrs, "", empty_snapbl,
                                false, NULL, NULL);
  ls.push_back(sample);
}

void EMetaBlob::fullbit::update_inode(MDS *mds, CInode *in)
{
  in->inode = inode;
  in->xattrs = xattrs;
  if (in->inode.is_dir()) {
    if (!(in->dirfragtree == dirfragtree)) {
      dout(10) << "EMetaBlob::fullbit::update_inode dft " << in->dirfragtree << " -> "
	       << dirfragtree << " on " << *in << dendl;
      in->dirfragtree = dirfragtree;
      in->force_dirfrags();
    }

    delete in->default_layout;
    in->default_layout = dir_layout;
    dir_layout = NULL;
    /*
     * we can do this before linking hte inode bc the split_at would
     * be a no-op.. we have no children (namely open snaprealms) to
     * divy up 
     */
    in->decode_snap_blob(snapbl);  
  } else if (in->inode.is_symlink()) {
    in->symlink = symlink;
  }
  in->old_inodes = old_inodes;
}

// EMetaBlob::remotebit

void EMetaBlob::remotebit::encode(bufferlist& bl) const
{
  ENCODE_START(2, 2, bl);
  if (!_enc.length()) {
    remotebit copy(dn, dnfirst, dnlast, dnv, ino, d_type, dirty);
    bl.append(copy._enc);
  } else {
    bl.append(_enc);
  }
  ENCODE_FINISH(bl);
}

void EMetaBlob::remotebit::decode(bufferlist::iterator &bl)
{
  DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, bl);
  ::decode(dn, bl);
  ::decode(dnfirst, bl);
  ::decode(dnlast, bl);
  ::decode(dnv, bl);
  ::decode(ino, bl);
  ::decode(d_type, bl);
  ::decode(dirty, bl);
  DECODE_FINISH(bl);
}

void EMetaBlob::remotebit::dump(Formatter *f) const
{
  if (_enc.length() && !dn.length()) {
    /* if our bufferlist has data but our name is empty, we
     * haven't initialized ourselves; do so in order to print members!
     * We use const_cast here because the whole point is we aren't
     * fully set up and this isn't changing who we "are", just our
     * representation.
     */
    EMetaBlob::remotebit *me = const_cast<EMetaBlob::remotebit*>(this);
    bufferlist encoded;
    encode(encoded);
    bufferlist::iterator p = encoded.begin();
    me->decode(p);
  }
  f->dump_string("dentry", dn);
  f->dump_int("snapid.first", dnfirst);
  f->dump_int("snapid.last", dnlast);
  f->dump_int("dentry version", dnv);
  f->dump_int("inodeno", ino);
  uint32_t type = DTTOIF(d_type) & S_IFMT; // convert to type entries
  string type_string;
  switch(type) {
  case S_IFREG:
    type_string = "file"; break;
  case S_IFLNK:
    type_string = "symlink"; break;
  case S_IFDIR:
    type_string = "directory"; break;
  default:
    assert (0 == "unknown d_type!");
  }
  f->dump_string("d_type", type_string);
  f->dump_string("dirty", dirty ? "true" : "false");
}

void EMetaBlob::remotebit::
generate_test_instances(list<EMetaBlob::remotebit*>& ls)
{
  remotebit *remote = new remotebit("/test/dn", 0, 10, 15, 1, IFTODT(S_IFREG), false);
  ls.push_back(remote);
}

// EMetaBlob::nullbit

void EMetaBlob::nullbit::encode(bufferlist& bl) const
{
  ENCODE_START(2, 2, bl);
  if (!_enc.length()) {
    nullbit copy(dn, dnfirst, dnlast, dnv, dirty);
    bl.append(copy._enc);
  } else {
    bl.append(_enc);
  }
  ENCODE_FINISH(bl);
}

void EMetaBlob::nullbit::decode(bufferlist::iterator &bl)
{
  DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, bl);
  ::decode(dn, bl);
  ::decode(dnfirst, bl);
  ::decode(dnlast, bl);
  ::decode(dnv, bl);
  ::decode(dirty, bl);
  DECODE_FINISH(bl);
}

void EMetaBlob::nullbit::dump(Formatter *f) const
{
  if (_enc.length() && !dn.length()) {
    /* if our bufferlist has data but our name is empty, we
     * haven't initialized ourselves; do so in order to print members!
     * We use const_cast here because the whole point is we aren't
     * fully set up and this isn't changing who we "are", just our
     * representation.
     */
    EMetaBlob::nullbit *me = const_cast<EMetaBlob::nullbit*>(this);
    bufferlist encoded;
    encode(encoded);
    bufferlist::iterator p = encoded.begin();
    me->decode(p);
  }
  f->dump_string("dentry", dn);
  f->dump_int("snapid.first", dnfirst);
  f->dump_int("snapid.last", dnlast);
  f->dump_int("dentry version", dnv);
  f->dump_string("dirty", dirty ? "true" : "false");
}

void EMetaBlob::nullbit::generate_test_instances(list<nullbit*>& ls)
{
  nullbit *sample = new nullbit("/test/dentry", 0, 10, 15, false);
  nullbit *sample2 = new nullbit("/test/dirty", 10, 20, 25, true);
  ls.push_back(sample);
  ls.push_back(sample2);
}

/**
 *
 */

void EMetaBlob::replay(MDS *mds, LogSegment *logseg, MDSlaveUpdate *slaveup)
{
  dout(10) << "EMetaBlob.replay " << lump_map.size() << " dirlumps by " << client_name << dendl;

  assert(logseg);

  for (list<std::tr1::shared_ptr<fullbit> >::iterator p = roots.begin(); p != roots.end(); p++) {
    CInode *in = mds->mdcache->get_inode((*p)->inode.ino);
    bool isnew = in ? false:true;
    if (!in)
      in = new CInode(mds->mdcache, true);
    (*p)->update_inode(mds, in);
    if (isnew)
      mds->mdcache->add_inode(in);
    if ((*p)->dirty) in->_mark_dirty(logseg);
    dout(10) << "EMetaBlob.replay " << (isnew ? " added root ":" updated root ") << *in << dendl;    
  }

  CInode *renamed_diri = 0;
  CDir *olddir = 0;
  if (renamed_dirino) {
    renamed_diri = mds->mdcache->get_inode(renamed_dirino);
    if (renamed_diri)
      dout(10) << "EMetaBlob.replay renamed inode is " << *renamed_diri << dendl;
    else
      dout(10) << "EMetaBlob.replay don't have renamed ino " << renamed_dirino << dendl;

    int nnull = 0;
    for (list<dirfrag_t>::iterator lp = lump_order.begin(); lp != lump_order.end(); ++lp) {
      dirlump &lump = lump_map[*lp];
      if (lump.nnull) {
	dout(10) << "EMetaBlob.replay found null dentry in dir " << *lp << dendl;
	nnull += lump.nnull;
      }
    }
    assert(nnull <= 1);
  }

  // keep track of any inodes we unlink and don't relink elsewhere
  map<CInode*, CDir*> unlinked;
  set<CInode*> linked;

  // walk through my dirs (in order!)
  for (list<dirfrag_t>::iterator lp = lump_order.begin();
       lp != lump_order.end();
       ++lp) {
    dout(10) << "EMetaBlob.replay dir " << *lp << dendl;
    dirlump &lump = lump_map[*lp];

    // the dir 
    CDir *dir = mds->mdcache->get_force_dirfrag(*lp);
    if (!dir) {
      // hmm.  do i have the inode?
      CInode *diri = mds->mdcache->get_inode((*lp).ino);
      if (!diri) {
	if (MDS_INO_IS_BASE(lp->ino)) {
	  diri = mds->mdcache->create_system_inode(lp->ino, S_IFDIR|0755);
	  dout(10) << "EMetaBlob.replay created base " << *diri << dendl;
	} else {
	  dout(0) << "EMetaBlob.replay missing dir ino  " << (*lp).ino << dendl;
	  assert(0);
	}
      }

      // create the dirfrag
      dir = diri->get_or_open_dirfrag(mds->mdcache, (*lp).frag);

      if (MDS_INO_IS_BASE(lp->ino))
	mds->mdcache->adjust_subtree_auth(dir, CDIR_AUTH_UNKNOWN);

      dout(10) << "EMetaBlob.replay added dir " << *dir << dendl;  
    }
    dir->set_version( lump.fnode.version );
    dir->fnode = lump.fnode;

    if (lump.is_dirty()) {
      dir->_mark_dirty(logseg);
      dir->get_inode()->filelock.mark_dirty();
      dir->get_inode()->nestlock.mark_dirty();

      if (!(dir->fnode.rstat == dir->fnode.accounted_rstat)) {
	dout(10) << "EMetaBlob.replay      dirty nestinfo on " << *dir << dendl;
	mds->locker->mark_updated_scatterlock(&dir->inode->nestlock);
	logseg->dirty_dirfrag_nest.push_back(&dir->inode->item_dirty_dirfrag_nest);
      } else {
	dout(10) << "EMetaBlob.replay      clean nestinfo on " << *dir << dendl;
      }
      if (!(dir->fnode.fragstat == dir->fnode.accounted_fragstat)) {
	dout(10) << "EMetaBlob.replay      dirty fragstat on " << *dir << dendl;
	mds->locker->mark_updated_scatterlock(&dir->inode->filelock);
	logseg->dirty_dirfrag_dir.push_back(&dir->inode->item_dirty_dirfrag_dir);
      } else {
	dout(10) << "EMetaBlob.replay      clean fragstat on " << *dir << dendl;
      }
    }
    if (lump.is_new())
      dir->mark_new(logseg);
    if (lump.is_complete())
      dir->mark_complete();
    else if (lump.is_importing())
      dir->state_clear(CDir::STATE_COMPLETE);
    
    dout(10) << "EMetaBlob.replay updated dir " << *dir << dendl;  

    // decode bits
    lump._decode_bits();

    // full dentry+inode pairs
    for (list<std::tr1::shared_ptr<fullbit> >::iterator pp = lump.get_dfull().begin();
	 pp != lump.get_dfull().end();
	 pp++) {
      std::tr1::shared_ptr<fullbit> p = *pp;
      CDentry *dn = dir->lookup_exact_snap(p->dn, p->dnlast);
      if (!dn) {
	dn = dir->add_null_dentry(p->dn, p->dnfirst, p->dnlast);
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay added " << *dn << dendl;
      } else {
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay for [" << p->dnfirst << "," << p->dnlast << "] had " << *dn << dendl;
	dn->first = p->dnfirst;
	assert(dn->last == p->dnlast);
      }

      CInode *in = mds->mdcache->get_inode(p->inode.ino, p->dnlast);
      if (!in) {
	in = new CInode(mds->mdcache, true, p->dnfirst, p->dnlast);
	p->update_inode(mds, in);
	mds->mdcache->add_inode(in);
	if (!dn->get_linkage()->is_null()) {
	  if (dn->get_linkage()->is_primary()) {
	    unlinked[dn->get_linkage()->get_inode()] = dir;
	    stringstream ss;
	    ss << "EMetaBlob.replay FIXME had dentry linked to wrong inode " << *dn
	       << " " << *dn->get_linkage()->get_inode() << " should be " << p->inode.ino;
	    dout(0) << ss.str() << dendl;
	    mds->clog.warn(ss);
	  }
	  dir->unlink_inode(dn);
	}
	if (unlinked.count(in))
	  linked.insert(in);
	dir->link_primary_inode(dn, in);
	if (p->dirty) in->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay added " << *in << dendl;
      } else {
	if (dn->get_linkage()->get_inode() != in && in->get_parent_dn()) {
	  dout(10) << "EMetaBlob.replay unlinking " << *in << dendl;
	  unlinked[in] = in->get_parent_dir();
	  in->get_parent_dir()->unlink_inode(in->get_parent_dn());
	}
	if (in->get_parent_dn() && in->inode.anchored != p->inode.anchored)
	  in->get_parent_dn()->adjust_nested_anchors( (int)p->inode.anchored - (int)in->inode.anchored );
	p->update_inode(mds, in);
	if (p->dirty) in->_mark_dirty(logseg);
	if (dn->get_linkage()->get_inode() != in) {
	  if (!dn->get_linkage()->is_null()) { // note: might be remote.  as with stray reintegration.
	    if (dn->get_linkage()->is_primary()) {
	      unlinked[dn->get_linkage()->get_inode()] = dir;
	      stringstream ss;
	      ss << "EMetaBlob.replay FIXME had dentry linked to wrong inode " << *dn
		 << " " << *dn->get_linkage()->get_inode() << " should be " << p->inode.ino;
	      dout(0) << ss.str() << dendl;
	      mds->clog.warn(ss);
	    }
	    dir->unlink_inode(dn);
	  }
	  if (unlinked.count(in))
	    linked.insert(in);
	  dir->link_primary_inode(dn, in);
	  dout(10) << "EMetaBlob.replay linked " << *in << dendl;
	} else {
	  dout(10) << "EMetaBlob.replay for [" << p->dnfirst << "," << p->dnlast << "] had " << *in << dendl;
	}
	assert(in->first == p->dnfirst ||
	       (in->is_multiversion() && in->first > p->dnfirst));
      }
    }

    // remote dentries
    for (list<remotebit>::iterator p = lump.get_dremote().begin();
	 p != lump.get_dremote().end();
	 p++) {
      CDentry *dn = dir->lookup_exact_snap(p->dn, p->dnlast);
      if (!dn) {
	dn = dir->add_remote_dentry(p->dn, p->ino, p->d_type, p->dnfirst, p->dnlast);
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay added " << *dn << dendl;
      } else {
	if (!dn->get_linkage()->is_null()) {
	  dout(10) << "EMetaBlob.replay unlinking " << *dn << dendl;
	  if (dn->get_linkage()->is_primary()) {
	    unlinked[dn->get_linkage()->get_inode()] = dir;
	    stringstream ss;
	    ss << "EMetaBlob.replay FIXME had dentry linked to wrong inode " << *dn
	       << " " << *dn->get_linkage()->get_inode() << " should be remote " << p->ino;
	    dout(0) << ss.str() << dendl;
	  }
	  dir->unlink_inode(dn);
	}
	dir->link_remote_inode(dn, p->ino, p->d_type);
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay for [" << p->dnfirst << "," << p->dnlast << "] had " << *dn << dendl;
	dn->first = p->dnfirst;
	assert(dn->last == p->dnlast);
      }
    }

    // null dentries
    for (list<nullbit>::iterator p = lump.get_dnull().begin();
	 p != lump.get_dnull().end();
	 p++) {
      CDentry *dn = dir->lookup_exact_snap(p->dn, p->dnlast);
      if (!dn) {
	dn = dir->add_null_dentry(p->dn, p->dnfirst, p->dnlast);
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay added " << *dn << dendl;
      } else {
	dn->first = p->dnfirst;
	if (!dn->get_linkage()->is_null()) {
	  dout(10) << "EMetaBlob.replay unlinking " << *dn << dendl;
	  if (dn->get_linkage()->is_primary())
	    unlinked[dn->get_linkage()->get_inode()] = dir;
	  dir->unlink_inode(dn);
	}
	dn->set_version(p->dnv);
	if (p->dirty) dn->_mark_dirty(logseg);
	dout(10) << "EMetaBlob.replay had " << *dn << dendl;
	assert(dn->last == p->dnlast);
      }
      olddir = dir;
    }
  }

  if (renamed_dirino) {
    if (renamed_diri) {
      assert(unlinked.count(renamed_diri));
      assert(linked.count(renamed_diri));
      olddir = unlinked[renamed_diri];
    } else {
      // we imported a diri we haven't seen before
      renamed_diri = mds->mdcache->get_inode(renamed_dirino);
      assert(renamed_diri);  // it was in the metablob
    }

    if (olddir) {
      if (olddir->authority() != CDIR_AUTH_UNDEF &&
	  renamed_diri->authority() == CDIR_AUTH_UNDEF) {
	list<frag_t> leaves;
	renamed_diri->dirfragtree.get_leaves(leaves);
	for (list<frag_t>::iterator p = leaves.begin(); p != leaves.end(); ++p)
	  renamed_diri->get_or_open_dirfrag(mds->mdcache, *p);
      }

      mds->mdcache->adjust_subtree_after_rename(renamed_diri, olddir, false);
      
      // see if we can discard the subtree we renamed out of
      CDir *root = mds->mdcache->get_subtree_root(olddir);
      if (root->get_dir_auth() == CDIR_AUTH_UNDEF) {
	if (slaveup) // preserve the old dir until slave commit
	  slaveup->rename_olddir = olddir;
	else
	  mds->mdcache->try_trim_non_auth_subtree(root);
      }
    }

    // if we are the srci importer, we'll also have some dirfrags we have to open up...
    if (renamed_diri->authority() != CDIR_AUTH_UNDEF) {
      for (list<frag_t>::iterator p = renamed_dir_frags.begin(); p != renamed_dir_frags.end(); ++p) {
	CDir *dir = renamed_diri->get_dirfrag(*p);
	if (dir) {
	  // we already had the inode before, and we already adjusted this subtree accordingly.
	  dout(10) << " already had+adjusted rename import bound " << *dir << dendl;
	  assert(olddir); 
	  continue;
	}
	dir = renamed_diri->get_or_open_dirfrag(mds->mdcache, *p);
	dout(10) << " creating new rename import bound " << *dir << dendl;
	mds->mdcache->adjust_subtree_auth(dir, CDIR_AUTH_UNDEF, false);
      }
    }

    // rename may overwrite an empty directory and move it into stray dir.
    unlinked.erase(renamed_diri);
    for (map<CInode*, CDir*>::iterator p = unlinked.begin(); p != unlinked.end(); ++p) {
      if (!linked.count(p->first))
	continue;
      assert(p->first->is_dir());
      mds->mdcache->adjust_subtree_after_rename(p->first, p->second, false);
    }
  }

  if (!unlinked.empty()) {
    for (set<CInode*>::iterator p = linked.begin(); p != linked.end(); p++)
      unlinked.erase(*p);
    dout(10) << " unlinked set contains " << unlinked << dendl;
    for (map<CInode*, CDir*>::iterator p = unlinked.begin(); p != unlinked.end(); ++p) {
      if (slaveup) // preserve unlinked inodes until slave commit
	slaveup->unlinked.insert(p->first);
      else
	mds->mdcache->remove_inode_recursive(p->first);
    }
  }

  // table client transactions
  for (list<pair<__u8,version_t> >::iterator p = table_tids.begin();
       p != table_tids.end();
       ++p) {
    dout(10) << "EMetaBlob.replay noting " << get_mdstable_name(p->first)
	     << " transaction " << p->second << dendl;
    MDSTableClient *client = mds->get_table_client(p->first);
    client->got_journaled_agree(p->second, logseg);
  }

  // opened ino?
  if (opened_ino) {
    CInode *in = mds->mdcache->get_inode(opened_ino);
    assert(in);
    dout(10) << "EMetaBlob.replay noting opened inode " << *in << dendl;
    logseg->open_files.push_back(&in->item_open_file);
  }

  // allocated_inos
  if (inotablev) {
    if (mds->inotable->get_version() >= inotablev) {
      dout(10) << "EMetaBlob.replay inotable tablev " << inotablev
	       << " <= table " << mds->inotable->get_version() << dendl;
    } else {
      dout(10) << "EMetaBlob.replay inotable v " << inotablev
	       << " - 1 == table " << mds->inotable->get_version()
	       << " allocated+used " << allocated_ino
	       << " prealloc " << preallocated_inos
	       << dendl;
      if (allocated_ino)
	mds->inotable->replay_alloc_id(allocated_ino);
      if (preallocated_inos.size())
	mds->inotable->replay_alloc_ids(preallocated_inos);

      // [repair bad inotable updates]
      if (inotablev > mds->inotable->get_version()) {
	mds->clog.error() << "journal replay inotablev mismatch "
	    << mds->inotable->get_version() << " -> " << inotablev << "\n";
	mds->inotable->force_replay_version(inotablev);
      }

      assert(inotablev == mds->inotable->get_version());
    }
  }
  if (sessionmapv) {
    if (mds->sessionmap.version >= sessionmapv) {
      dout(10) << "EMetaBlob.replay sessionmap v " << sessionmapv
	       << " <= table " << mds->sessionmap.version << dendl;
    } else {
      dout(10) << "EMetaBlob.replay sessionmap v" << sessionmapv
	       << " -(1|2) == table " << mds->sessionmap.version
	       << " prealloc " << preallocated_inos
	       << " used " << used_preallocated_ino
	       << dendl;
      Session *session = mds->sessionmap.get_session(client_name);
      assert(session);
      dout(20) << " (session prealloc " << session->info.prealloc_inos << ")" << dendl;
      if (used_preallocated_ino) {
	if (session->info.prealloc_inos.empty()) {
	  // HRM: badness in the journal
	  mds->clog.warn() << " replayed op " << client_reqs << " on session for " << client_name
			   << " with empty prealloc_inos\n";
	} else {
	  inodeno_t next = session->next_ino();
	  inodeno_t i = session->take_ino(used_preallocated_ino);
	  if (next != i)
	    mds->clog.warn() << " replayed op " << client_reqs << " used ino " << i
			     << " but session next is " << next << "\n";
	  assert(i == used_preallocated_ino);
	  session->info.used_inos.clear();
	}
	mds->sessionmap.projected = ++mds->sessionmap.version;
      }
      if (preallocated_inos.size()) {
	session->info.prealloc_inos.insert(preallocated_inos);
	mds->sessionmap.projected = ++mds->sessionmap.version;
      }
      assert(sessionmapv == mds->sessionmap.version);
    }
  }

  // truncating inodes
  for (list<inodeno_t>::iterator p = truncate_start.begin();
       p != truncate_start.end();
       p++) {
    CInode *in = mds->mdcache->get_inode(*p);
    assert(in);
    mds->mdcache->add_recovered_truncate(in, logseg);
  }
  for (map<inodeno_t,uint64_t>::iterator p = truncate_finish.begin();
       p != truncate_finish.end();
       p++) {
    LogSegment *ls = mds->mdlog->get_segment(p->second);
    if (ls) {
      CInode *in = mds->mdcache->get_inode(p->first);
      assert(in);
      mds->mdcache->remove_recovered_truncate(in, ls);
    }
  }

  // destroyed inodes
  for (vector<inodeno_t>::iterator p = destroyed_inodes.begin();
       p != destroyed_inodes.end();
       p++) {
    CInode *in = mds->mdcache->get_inode(*p);
    if (in) {
      dout(10) << "EMetaBlob.replay destroyed " << *p << ", dropping " << *in << dendl;
      mds->mdcache->remove_inode(in);
    } else {
      dout(10) << "EMetaBlob.replay destroyed " << *p << ", not in cache" << dendl;
    }
  }

  // client requests
  for (list<pair<metareqid_t, uint64_t> >::iterator p = client_reqs.begin();
       p != client_reqs.end();
       ++p)
    if (p->first.name.is_client()) {
      dout(10) << "EMetaBlob.replay request " << p->first << " " << p->second << dendl;
      if (mds->sessionmap.have_session(p->first.name))
	mds->sessionmap.add_completed_request(p->first, p->second);
    }


  // update segment
  update_segment(logseg);
}

// -----------------------
// ESession

void ESession::update_segment()
{
  _segment->sessionmapv = cmapv;
  if (inos.size() && inotablev)
    _segment->inotablev = inotablev;
}

void ESession::replay(MDS *mds)
{
  if (mds->sessionmap.version >= cmapv) {
    dout(10) << "ESession.replay sessionmap " << mds->sessionmap.version 
	     << " >= " << cmapv << ", noop" << dendl;
  } else {
    dout(10) << "ESession.replay sessionmap " << mds->sessionmap.version
	     << " < " << cmapv << " " << (open ? "open":"close") << " " << client_inst << dendl;
    mds->sessionmap.projected = ++mds->sessionmap.version;
    assert(mds->sessionmap.version == cmapv);
    Session *session;
    if (open) {
      session = mds->sessionmap.get_or_add_session(client_inst);
      mds->sessionmap.set_state(session, Session::STATE_OPEN);
      dout(10) << " opened session " << session->info.inst << dendl;
    } else {
      session = mds->sessionmap.get_session(client_inst.name);
      if (session) { // there always should be a session, but there's a bug
	if (session->connection == NULL) {
	  dout(10) << " removed session " << session->info.inst << dendl;
	  mds->sessionmap.remove_session(session);
	} else {
	  session->clear();    // the client has reconnected; keep the Session, but reset
	  dout(10) << " reset session " << session->info.inst << " (they reconnected)" << dendl;
	}
      } else {
	mds->clog.error() << "replayed stray Session close event for " << client_inst
			  << " from time " << stamp << ", ignoring";
      }
    }
  }
  
  if (inos.size() && inotablev) {
    if (mds->inotable->get_version() >= inotablev) {
      dout(10) << "ESession.replay inotable " << mds->inotable->get_version()
	       << " >= " << inotablev << ", noop" << dendl;
    } else {
      dout(10) << "ESession.replay inotable " << mds->inotable->get_version()
	       << " < " << inotablev << " " << (open ? "add":"remove") << dendl;
      assert(!open);  // for now
      mds->inotable->replay_release_ids(inos);
      assert(mds->inotable->get_version() == inotablev);
    }
  }

  update_segment();
}

void ESessions::update_segment()
{
  _segment->sessionmapv = cmapv;
}

void ESessions::replay(MDS *mds)
{
  if (mds->sessionmap.version >= cmapv) {
    dout(10) << "ESessions.replay sessionmap " << mds->sessionmap.version
	     << " >= " << cmapv << ", noop" << dendl;
  } else {
    dout(10) << "ESessions.replay sessionmap " << mds->sessionmap.version
	     << " < " << cmapv << dendl;
    mds->sessionmap.open_sessions(client_map);
    assert(mds->sessionmap.version == cmapv);
    mds->sessionmap.projected = mds->sessionmap.version;
  }
  update_segment();
}




void ETableServer::update_segment()
{
  _segment->tablev[table] = version;
}

void ETableServer::replay(MDS *mds)
{
  MDSTableServer *server = mds->get_table_server(table);
  if (server->get_version() >= version) {
    dout(10) << "ETableServer.replay " << get_mdstable_name(table)
	     << " " << get_mdstableserver_opname(op)
	     << " event " << version
	     << " <= table " << server->get_version() << dendl;
    return;
  }
  
  dout(10) << " ETableServer.replay " << get_mdstable_name(table)
	   << " " << get_mdstableserver_opname(op)
	   << " event " << version << " - 1 == table " << server->get_version() << dendl;
  assert(version-1 == server->get_version());

  switch (op) {
  case TABLESERVER_OP_PREPARE:
    server->_prepare(mutation, reqid, bymds);
    server->_note_prepare(bymds, reqid);
    break;
  case TABLESERVER_OP_COMMIT:
    server->_commit(tid);
    server->_note_commit(tid);
    break;
  case TABLESERVER_OP_ROLLBACK:
    server->_rollback(tid);
    server->_note_rollback(tid);
    break;
  case TABLESERVER_OP_SERVER_UPDATE:
    server->_server_update(mutation);
    break;
  default:
    assert(0);
  }
  
  assert(version == server->get_version());
  update_segment();
}


void ETableClient::replay(MDS *mds)
{
  dout(10) << " ETableClient.replay " << get_mdstable_name(table)
	   << " op " << get_mdstableserver_opname(op)
	   << " tid " << tid << dendl;
    
  MDSTableClient *client = mds->get_table_client(table);
  assert(op == TABLESERVER_OP_ACK);
  client->got_journaled_ack(tid);
}


// -----------------------
// ESnap
/*
void ESnap::update_segment()
{
  _segment->tablev[TABLE_SNAP] = version;
}

void ESnap::replay(MDS *mds)
{
  if (mds->snaptable->get_version() >= version) {
    dout(10) << "ESnap.replay event " << version
	     << " <= table " << mds->snaptable->get_version() << dendl;
    return;
  } 
  
  dout(10) << " ESnap.replay event " << version
	   << " - 1 == table " << mds->snaptable->get_version() << dendl;
  assert(version-1 == mds->snaptable->get_version());

  if (create) {
    version_t v;
    snapid_t s = mds->snaptable->create(snap.dirino, snap.name, snap.stamp, &v);
    assert(s == snap.snapid);
  } else {
    mds->snaptable->remove(snap.snapid);
  }

  assert(version == mds->snaptable->get_version());
}
*/



// -----------------------
// EUpdate

void EUpdate::update_segment()
{
  metablob.update_segment(_segment);

  if (had_slaves)
    _segment->uncommitted_masters.insert(reqid);
}

void EUpdate::replay(MDS *mds)
{
  metablob.replay(mds, _segment);
  
  if (had_slaves) {
    dout(10) << "EUpdate.replay " << reqid << " had slaves, expecting a matching ECommitted" << dendl;
    _segment->uncommitted_masters.insert(reqid);
    set<int> slaves;
    mds->mdcache->add_uncommitted_master(reqid, _segment, slaves);
  }
  
  if (client_map.length()) {
    if (mds->sessionmap.version >= cmapv) {
      dout(10) << "EUpdate.replay sessionmap v " << cmapv
	       << " <= table " << mds->sessionmap.version << dendl;
    } else {
      dout(10) << "EUpdate.replay sessionmap " << mds->sessionmap.version
	       << " < " << cmapv << dendl;
      // open client sessions?
      map<client_t,entity_inst_t> cm;
      map<client_t, uint64_t> seqm;
      bufferlist::iterator blp = client_map.begin();
      ::decode(cm, blp);
      mds->server->prepare_force_open_sessions(cm, seqm);
      mds->server->finish_force_open_sessions(cm, seqm);

      assert(mds->sessionmap.version = cmapv);
      mds->sessionmap.projected = mds->sessionmap.version;
    }
  }
}


// ------------------------
// EOpen

void EOpen::update_segment()
{
  // ??
}

void EOpen::replay(MDS *mds)
{
  dout(10) << "EOpen.replay " << dendl;
  metablob.replay(mds, _segment);

  // note which segments inodes belong to, so we don't have to start rejournaling them
  for (vector<inodeno_t>::iterator p = inos.begin();
       p != inos.end();
       p++) {
    CInode *in = mds->mdcache->get_inode(*p);
    if (!in) {
      dout(0) << "EOpen.replay ino " << *p << " not in metablob" << dendl;
      assert(in);
    }
    _segment->open_files.push_back(&in->item_open_file);
  }
}


// -----------------------
// ECommitted

void ECommitted::replay(MDS *mds)
{
  if (mds->mdcache->uncommitted_masters.count(reqid)) {
    dout(10) << "ECommitted.replay " << reqid << dendl;
    mds->mdcache->uncommitted_masters[reqid].ls->uncommitted_masters.erase(reqid);
    mds->mdcache->uncommitted_masters.erase(reqid);
  } else {
    dout(10) << "ECommitted.replay " << reqid << " -- didn't see original op" << dendl;
  }
}

void ECommitted::encode(bufferlist& bl) const
{
  ENCODE_START(3, 3, bl);
  ::encode(stamp, bl);
  ::encode(reqid, bl);
  ENCODE_FINISH(bl);
} 

void ECommitted::decode(bufferlist::iterator& bl)
{
  DECODE_START_LEGACY_COMPAT_LEN(3, 3, 3, bl);
  if (struct_v >= 2)
    ::decode(stamp, bl);
  ::decode(reqid, bl);
  DECODE_FINISH(bl);
}

void ECommitted::dump(Formatter *f) const {
  f->dump_stream("stamp") << stamp;
  f->dump_stream("reqid") << reqid;
}

void ECommitted::generate_test_instances(list<ECommitted*>& ls)
{
  ls.push_back(new ECommitted);
  ls.push_back(new ECommitted);
  ls.back()->stamp = utime_t(1, 2);
  ls.back()->reqid = metareqid_t(entity_name_t::CLIENT(123), 456);
}

// -----------------------
// ESlaveUpdate

void ESlaveUpdate::replay(MDS *mds)
{
  MDSlaveUpdate *su;
  switch (op) {
  case ESlaveUpdate::OP_PREPARE:
    dout(10) << "ESlaveUpdate.replay prepare " << reqid << " for mds." << master 
	     << ": applying commit, saving rollback info" << dendl;
    su = new MDSlaveUpdate(origop, rollback, _segment->slave_updates);
    commit.replay(mds, _segment, su);
    mds->mdcache->add_uncommitted_slave_update(reqid, master, su);
    break;

  case ESlaveUpdate::OP_COMMIT:
    su = mds->mdcache->get_uncommitted_slave_update(reqid, master);
    if (su) {
      dout(10) << "ESlaveUpdate.replay commit " << reqid << " for mds." << master << dendl;
      mds->mdcache->finish_uncommitted_slave_update(reqid, master);
    } else {
      dout(10) << "ESlaveUpdate.replay commit " << reqid << " for mds." << master 
	       << ": ignoring, no previously saved prepare" << dendl;
    }
    break;

  case ESlaveUpdate::OP_ROLLBACK:
    dout(10) << "ESlaveUpdate.replay abort " << reqid << " for mds." << master
	     << ": applying rollback commit blob" << dendl;
    su = mds->mdcache->get_uncommitted_slave_update(reqid, master);
    if (su)
      mds->mdcache->finish_uncommitted_slave_update(reqid, master);
    commit.replay(mds, _segment);
    break;

  default:
    assert(0);
  }
}


// -----------------------
// ESubtreeMap

void ESubtreeMap::replay(MDS *mds) 
{
  if (expire_pos && expire_pos > mds->mdlog->journaler->get_expire_pos())
    mds->mdlog->journaler->set_expire_pos(expire_pos);

  // suck up the subtree map?
  if (mds->mdcache->is_subtrees()) {
    dout(10) << "ESubtreeMap.replay -- i already have import map; verifying" << dendl;
    int errors = 0;

    for (map<dirfrag_t, vector<dirfrag_t> >::iterator p = subtrees.begin();
	 p != subtrees.end();
	 ++p) {
      CDir *dir = mds->mdcache->get_dirfrag(p->first);
      if (!dir) {
	mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			  << " subtree root " << p->first << " not in cache";
	++errors;
	continue;
      }
      
      if (!mds->mdcache->is_subtree(dir)) {
	mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			  << " subtree root " << p->first << " not a subtree in cache";
	++errors;
	continue;
      }
      if (dir->get_dir_auth().first != mds->whoami) {
	mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			  << " subtree root " << p->first
			  << " is not mine in cache (it's " << dir->get_dir_auth() << ")";
	++errors;
	continue;
      }

      set<CDir*> bounds;
      mds->mdcache->get_subtree_bounds(dir, bounds);
      for (vector<dirfrag_t>::iterator q = p->second.begin(); q != p->second.end(); ++q) {
	CDir *b = mds->mdcache->get_dirfrag(*q);
	if (!b) {
	  mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			    << " subtree " << p->first << " bound " << *q << " not in cache";
	++errors;
	  continue;
	}
	if (bounds.count(b) == 0) {
	  mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			    << " subtree " << p->first << " bound " << *q << " not a bound in cache";
	++errors;
	  continue;
	}
	bounds.erase(b);
      }
      for (set<CDir*>::iterator q = bounds.begin(); q != bounds.end(); ++q) {
	mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			  << " subtree " << p->first << " has extra bound in cache " << (*q)->dirfrag();
	++errors;
      }
      
      if (ambiguous_subtrees.count(p->first)) {
	if (!mds->mdcache->have_ambiguous_import(p->first)) {
	  mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			    << " subtree " << p->first << " is ambiguous but is not in our cache";
	  ++errors;
	}
      } else {
	if (mds->mdcache->have_ambiguous_import(p->first)) {
	  mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			    << " subtree " << p->first << " is not ambiguous but is in our cache";
	  ++errors;
	}
      }
    }
    
    list<CDir*> subs;
    mds->mdcache->list_subtrees(subs);
    for (list<CDir*>::iterator p = subs.begin(); p != subs.end(); ++p) {
      CDir *dir = *p;
      if (dir->get_dir_auth().first != mds->whoami)
	continue;
      if (subtrees.count(dir->dirfrag()) == 0) {
	mds->clog.error() << " replayed ESubtreeMap at " << get_start_off()
			  << " does not include cache subtree " << dir->dirfrag();
	++errors;
      }
    }

    if (errors) {
      dout(0) << "journal subtrees: " << subtrees << dendl;
      dout(0) << "journal ambig_subtrees: " << ambiguous_subtrees << dendl;
      mds->mdcache->show_subtrees();
      assert(!g_conf->mds_debug_subtrees || errors == 0);
    }
    return;
  }

  dout(10) << "ESubtreeMap.replay -- reconstructing (auth) subtree spanning tree" << dendl;
  
  // first, stick the spanning tree in my cache
  //metablob.print(*_dout);
  metablob.replay(mds, _segment);
  
  // restore import/export maps
  for (map<dirfrag_t, vector<dirfrag_t> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *dir = mds->mdcache->get_dirfrag(p->first);
    assert(dir);
    if (ambiguous_subtrees.count(p->first)) {
      // ambiguous!
      mds->mdcache->add_ambiguous_import(p->first, p->second);
      mds->mdcache->adjust_bounded_subtree_auth(dir, p->second,
						pair<int,int>(mds->get_nodeid(), mds->get_nodeid()));
    } else {
      // not ambiguous
      mds->mdcache->adjust_bounded_subtree_auth(dir, p->second, mds->get_nodeid());
    }
  }
  
  mds->mdcache->show_subtrees();
}



// -----------------------
// EFragment

void EFragment::replay(MDS *mds)
{
  dout(10) << "EFragment.replay " << op_name(op) << " " << ino << " " << basefrag << " by " << bits << dendl;

  list<CDir*> resultfrags;
  list<Context*> waiters;
  pair<dirfrag_t,int> desc(dirfrag_t(ino,basefrag), bits);

  // in may be NULL if it wasn't in our cache yet.  if it's a prepare
  // it will be once we replay the metablob , but first we need to
  // refragment anything we already have in the cache.
  CInode *in = mds->mdcache->get_inode(ino);

  switch (op) {
  case OP_PREPARE:
    mds->mdcache->uncommitted_fragments.insert(desc);
    // fall-thru
  case OP_ONESHOT:
    if (in)
      mds->mdcache->adjust_dir_fragments(in, basefrag, bits, resultfrags, waiters, true);
    break;

  case OP_COMMIT:
    mds->mdcache->uncommitted_fragments.erase(desc);
    break;

  case OP_ROLLBACK:
    if (mds->mdcache->uncommitted_fragments.count(desc)) {
      mds->mdcache->uncommitted_fragments.erase(desc);
      assert(in);
      mds->mdcache->adjust_dir_fragments(in, basefrag, -bits, resultfrags, waiters, true);
    } else {
      dout(10) << " no record of prepare for " << desc << dendl;
    }
    break;
  }
  metablob.replay(mds, _segment);
  if (in && g_conf->mds_debug_frag)
    in->verify_dirfrags();
}

void EFragment::encode(bufferlist &bl) const {
  ENCODE_START(4, 4, bl);
  ::encode(stamp, bl);
  ::encode(op, bl);
  ::encode(ino, bl);
  ::encode(basefrag, bl);
  ::encode(bits, bl);
  ::encode(metablob, bl);
  ENCODE_FINISH(bl);
}

void EFragment::decode(bufferlist::iterator &bl) {
  DECODE_START_LEGACY_COMPAT_LEN(4, 4, 4, bl);
  if (struct_v >= 2)
    ::decode(stamp, bl);
  if (struct_v >= 3)
    ::decode(op, bl);
  else
    op = OP_ONESHOT;
  ::decode(ino, bl);
  ::decode(basefrag, bl);
  ::decode(bits, bl);
  ::decode(metablob, bl);
  DECODE_FINISH(bl);
}

void EFragment::dump(Formatter *f) const
{
  /*f->open_object_section("Metablob");
  metablob.dump(f); // sadly we don't have this; dunno if we'll get it
  f->close_section();*/
  f->dump_string("op", op_name(op));
  f->dump_stream("ino") << ino;
  f->dump_stream("base frag") << basefrag;
  f->dump_int("bits", bits);
}

void EFragment::generate_test_instances(list<EFragment*>& ls)
{
  ls.push_back(new EFragment);
  ls.push_back(new EFragment);
  ls.back()->op = OP_PREPARE;
  ls.back()->ino = 1;
  ls.back()->bits = 5;
}





// =========================================================================

// -----------------------
// EExport

void EExport::replay(MDS *mds)
{
  dout(10) << "EExport.replay " << base << dendl;
  metablob.replay(mds, _segment);
  
  CDir *dir = mds->mdcache->get_dirfrag(base);
  assert(dir);
  
  set<CDir*> realbounds;
  for (set<dirfrag_t>::iterator p = bounds.begin();
       p != bounds.end();
       ++p) {
    CDir *bd = mds->mdcache->get_dirfrag(*p);
    assert(bd);
    realbounds.insert(bd);
  }

  // adjust auth away
  mds->mdcache->adjust_bounded_subtree_auth(dir, realbounds, CDIR_AUTH_UNDEF);

  mds->mdcache->try_trim_non_auth_subtree(dir);
}

void EExport::encode(bufferlist& bl) const
{
  ENCODE_START(3, 3, bl);
  ::encode(stamp, bl);
  ::encode(metablob, bl);
  ::encode(base, bl);
  ::encode(bounds, bl);
  ENCODE_FINISH(bl);
}

void EExport::decode(bufferlist::iterator &bl)
{
  DECODE_START_LEGACY_COMPAT_LEN(3, 3, 3, bl);
  if (struct_v >= 2)
    ::decode(stamp, bl);
  ::decode(metablob, bl);
  ::decode(base, bl);
  ::decode(bounds, bl);
  DECODE_FINISH(bl);
}

void EExport::dump(Formatter *f) const
{
  f->dump_float("stamp", (double)stamp);
  /*f->open_object_section("Metablob");
  metablob.dump(f); // sadly we don't have this; dunno if we'll get it
  f->close_section();*/
  f->dump_stream("base dirfrag") << base;
  f->open_array_section("bounds dirfrags");
  for (set<dirfrag_t>::const_iterator i = bounds.begin();
      i != bounds.end(); ++i) {
    f->dump_stream("dirfrag") << *i;
  }
  f->close_section(); // bounds dirfrags
}

void EExport::generate_test_instances(list<EExport*>& ls)
{
  EExport *sample = new EExport();
  ls.push_back(sample);
}


// -----------------------
// EImportStart

void EImportStart::update_segment()
{
  _segment->sessionmapv = cmapv;
}

void EImportStart::replay(MDS *mds)
{
  dout(10) << "EImportStart.replay " << base << " bounds " << bounds << dendl;
  //metablob.print(*_dout);
  metablob.replay(mds, _segment);

  // put in ambiguous import list
  mds->mdcache->add_ambiguous_import(base, bounds);

  // set auth partially to us so we don't trim it
  CDir *dir = mds->mdcache->get_dirfrag(base);
  assert(dir);
  mds->mdcache->adjust_bounded_subtree_auth(dir, bounds, pair<int,int>(mds->get_nodeid(), mds->get_nodeid()));

  // open client sessions?
  if (mds->sessionmap.version >= cmapv) {
    dout(10) << "EImportStart.replay sessionmap " << mds->sessionmap.version 
	     << " >= " << cmapv << ", noop" << dendl;
  } else {
    dout(10) << "EImportStart.replay sessionmap " << mds->sessionmap.version 
	     << " < " << cmapv << dendl;
    map<client_t,entity_inst_t> cm;
    bufferlist::iterator blp = client_map.begin();
    ::decode(cm, blp);
    mds->sessionmap.open_sessions(cm);
    assert(mds->sessionmap.version == cmapv);
    mds->sessionmap.projected = mds->sessionmap.version;
  }
  update_segment();
}

void EImportStart::encode(bufferlist &bl) const {
  ENCODE_START(3, 3, bl);
  ::encode(stamp, bl);
  ::encode(base, bl);
  ::encode(metablob, bl);
  ::encode(bounds, bl);
  ::encode(cmapv, bl);
  ::encode(client_map, bl);
  ENCODE_FINISH(bl);
}

void EImportStart::decode(bufferlist::iterator &bl) {
  DECODE_START_LEGACY_COMPAT_LEN(3, 3, 3, bl);
  if (struct_v >= 2)
    ::decode(stamp, bl);
  ::decode(base, bl);
  ::decode(metablob, bl);
  ::decode(bounds, bl);
  ::decode(cmapv, bl);
  ::decode(client_map, bl);
  DECODE_FINISH(bl);
}

void EImportStart::dump(Formatter *f) const
{
  f->dump_stream("base dirfrag") << base;
  f->open_array_section("boundary dirfrags");
  for (vector<dirfrag_t>::const_iterator iter = bounds.begin();
      iter != bounds.end(); ++iter) {
    f->dump_stream("frag") << *iter;
  }
  f->close_section();
}

void EImportStart::generate_test_instances(list<EImportStart*>& ls)
{
  ls.push_back(new EImportStart);
}

// -----------------------
// EImportFinish

void EImportFinish::replay(MDS *mds)
{
  if (mds->mdcache->have_ambiguous_import(base)) {
    dout(10) << "EImportFinish.replay " << base << " success=" << success << dendl;
    if (success) {
      mds->mdcache->finish_ambiguous_import(base);
    } else {
      CDir *dir = mds->mdcache->get_dirfrag(base);
      assert(dir);
      vector<dirfrag_t> bounds;
      mds->mdcache->get_ambiguous_import_bounds(base, bounds);
      mds->mdcache->adjust_bounded_subtree_auth(dir, bounds, CDIR_AUTH_UNDEF);
      mds->mdcache->cancel_ambiguous_import(dir);
      mds->mdcache->try_trim_non_auth_subtree(dir);
   }
  } else {
    dout(10) << "EImportFinish.replay " << base << " success=" << success
	     << " on subtree not marked as ambiguous" 
	     << dendl;
    assert(0 == "this shouldn't happen unless this is an old journal");
  }
}

void EImportFinish::encode(bufferlist& bl) const
{
  ENCODE_START(3, 3, bl);
  ::encode(stamp, bl);
  ::encode(base, bl);
  ::encode(success, bl);
  ENCODE_FINISH(bl);
}

void EImportFinish::decode(bufferlist::iterator &bl)
{
  DECODE_START_LEGACY_COMPAT_LEN(3, 3, 3, bl);
  if (struct_v >= 2)
    ::decode(stamp, bl);
  ::decode(base, bl);
  ::decode(success, bl);
  DECODE_FINISH(bl);
}

void EImportFinish::dump(Formatter *f) const
{
  f->dump_stream("base dirfrag") << base;
  f->dump_string("success", success ? "true" : "false");
}
void EImportFinish::generate_test_instances(list<EImportFinish*>& ls)
{
  ls.push_back(new EImportFinish);
  ls.push_back(new EImportFinish);
  ls.back()->success = true;
}


// ------------------------
// EResetJournal

void EResetJournal::replay(MDS *mds)
{
  dout(1) << "EResetJournal" << dendl;

  mds->sessionmap.wipe();
  mds->inotable->replay_reset();

  if (mds->mdsmap->get_root() == mds->whoami) {
    CDir *rootdir = mds->mdcache->get_root()->get_or_open_dirfrag(mds->mdcache, frag_t());
    mds->mdcache->adjust_subtree_auth(rootdir, mds->whoami);   
  }

  CDir *mydir = mds->mdcache->get_myin()->get_or_open_dirfrag(mds->mdcache, frag_t());
  mds->mdcache->adjust_subtree_auth(mydir, mds->whoami);   

  mds->mdcache->show_subtrees();
}

