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

#include <errno.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <map>

#include "MDCache.h"
#include "MDS.h"
#include "Server.h"
#include "Locker.h"
#include "MDLog.h"
#include "MDBalancer.h"
#include "Migrator.h"

#include "AnchorClient.h"
#include "SnapClient.h"

#include "MDSMap.h"

#include "CInode.h"
#include "CDir.h"

#include "Mutation.h"

#include "include/ceph_fs.h"
#include "include/filepath.h"

#include "msg/Message.h"
#include "msg/Messenger.h"

#include "common/errno.h"
#include "common/safe_io.h"
#include "common/perf_counters.h"
#include "common/MemoryModel.h"
#include "osdc/Journaler.h"
#include "osdc/Filer.h"

#include "events/ESubtreeMap.h"
#include "events/EUpdate.h"
#include "events/ESlaveUpdate.h"
#include "events/EImportFinish.h"
#include "events/EFragment.h"
#include "events/ECommitted.h"

#include "messages/MGenericMessage.h"

#include "messages/MMDSResolve.h"
#include "messages/MMDSResolveAck.h"
#include "messages/MMDSCacheRejoin.h"

#include "messages/MDiscover.h"
#include "messages/MDiscoverReply.h"

//#include "messages/MInodeUpdate.h"
#include "messages/MDirUpdate.h"
#include "messages/MCacheExpire.h"

#include "messages/MInodeFileCaps.h"

#include "messages/MLock.h"
#include "messages/MDentryLink.h"
#include "messages/MDentryUnlink.h"

#include "messages/MMDSFindIno.h"
#include "messages/MMDSFindInoReply.h"

#include "messages/MMDSOpenIno.h"
#include "messages/MMDSOpenInoReply.h"

#include "messages/MClientRequest.h"
#include "messages/MClientCaps.h"
#include "messages/MClientSnap.h"

#include "messages/MMDSSlaveRequest.h"

#include "messages/MMDSFragmentNotify.h"


#include "InoTable.h"

#include "common/Timer.h"

using namespace std;

extern struct ceph_file_layout g_default_file_layout;

#include "common/config.h"
#include "include/assert.h"

#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix _prefix(_dout, mds)
static ostream& _prefix(std::ostream *_dout, MDS *mds) {
  return *_dout << "mds." << mds->get_nodeid() << ".cache ";
}

long g_num_ino = 0;
long g_num_dir = 0;
long g_num_dn = 0;
long g_num_cap = 0;

long g_num_inoa = 0;
long g_num_dira = 0;
long g_num_dna = 0;
long g_num_capa = 0;

long g_num_inos = 0;
long g_num_dirs = 0;
long g_num_dns = 0;
long g_num_caps = 0;

set<int> SimpleLock::empty_gather_set;


MDCache::MDCache(MDS *m) :
  delayed_eval_stray(member_offset(CDentry, item_stray))
{
  mds = m;
  migrator = new Migrator(mds, this);
  root = NULL;
  myin = NULL;

  stray_index = 0;
  for (int i = 0; i < NUM_STRAY; ++i) {
    strays[i] = NULL;
  }

  num_inodes_with_caps = 0;
  num_caps = 0;

  max_dir_commit_size = g_conf->mds_dir_max_commit_size ?
                        (g_conf->mds_dir_max_commit_size << 20) :
                        (0.9 *(g_conf->osd_max_write_size << 20));

  discover_last_tid = 0;
  open_ino_last_tid = 0;
  find_ino_peer_last_tid = 0;

  last_cap_id = 0;

  client_lease_durations[0] = 5.0;
  client_lease_durations[1] = 30.0;
  client_lease_durations[2] = 300.0;

  resolves_pending = false;
  rejoins_pending = false;
  cap_imports_num_opening = 0;

  opening_root = open = false;
  lru.lru_set_max(g_conf->mds_cache_size);
  lru.lru_set_midpoint(g_conf->mds_cache_mid);

  decayrate.set_halflife(g_conf->mds_decay_halflife);

  memset(&default_log_layout, 0, sizeof(default_log_layout));

  did_shutdown_log_cap = false;
}

MDCache::~MDCache() 
{
  delete migrator;
  //delete renamer;
}



void MDCache::log_stat()
{
  mds->logger->set(l_mds_imax, g_conf->mds_cache_size);
  mds->logger->set(l_mds_i, lru.lru_get_size());
  mds->logger->set(l_mds_ipin, lru.lru_get_num_pinned());
  mds->logger->set(l_mds_itop, lru.lru_get_top());
  mds->logger->set(l_mds_ibot, lru.lru_get_bot());
  mds->logger->set(l_mds_iptail, lru.lru_get_pintail());
  mds->logger->set(l_mds_icap, num_inodes_with_caps);
  mds->logger->set(l_mds_cap, num_caps);
}


// 

bool MDCache::shutdown()
{
  if (lru.lru_get_size() > 0) {
    dout(7) << "WARNING: mdcache shutdown with non-empty cache" << dendl;
    //show_cache();
    show_subtrees();
    //dump();
  }
  return true;
}


// ====================================================================
// some inode functions

void MDCache::add_inode(CInode *in) 
{
  // add to lru, inode map
  assert(inode_map.count(in->vino()) == 0);  // should be no dup inos!
  inode_map[ in->vino() ] = in;

  if (in->ino() < MDS_INO_SYSTEM_BASE) {
    if (in->ino() == MDS_INO_ROOT)
      root = in;
    else if (in->ino() == MDS_INO_MDSDIR(mds->get_nodeid()))
      myin = in;
    else if (in->is_stray()) {
      if (MDS_INO_STRAY_OWNER(in->ino()) == mds->get_nodeid()) {
	strays[MDS_INO_STRAY_INDEX(in->ino())] = in;
      }
    }
    if (in->is_base())
      base_inodes.insert(in);
  }
}

void MDCache::remove_inode(CInode *o) 
{ 
  dout(14) << "remove_inode " << *o << dendl;

  if (o->get_parent_dn()) {
    // FIXME: multiple parents?
    CDentry *dn = o->get_parent_dn();
    assert(!dn->is_dirty());
    dn->dir->unlink_inode(dn);   // leave dentry ... FIXME?
  }

  if (o->is_dirty())
    o->mark_clean();
  if (o->is_dirty_parent())
    o->clear_dirty_parent();

  o->filelock.remove_dirty();
  o->nestlock.remove_dirty();
  o->dirfragtreelock.remove_dirty();

  o->item_open_file.remove_myself();

  // remove from inode map
  inode_map.erase(o->vino());    

  if (o->ino() < MDS_INO_SYSTEM_BASE) {
    if (o == root) root = 0;
    if (o == myin) myin = 0;
    if (o->is_stray()) {
      if (MDS_INO_STRAY_OWNER(o->ino()) == mds->get_nodeid()) {
	strays[MDS_INO_STRAY_INDEX(o->ino())] = 0;
      }
    }
    if (o->is_base())
      base_inodes.erase(o);
    }

  // delete it
  assert(o->get_num_ref() == 0);
  delete o; 
}



void MDCache::init_layouts()
{
  default_file_layout = g_default_file_layout;
  default_file_layout.fl_pg_pool = mds->mdsmap->get_first_data_pool();

  default_log_layout = g_default_file_layout;
  default_log_layout.fl_pg_pool = mds->mdsmap->get_metadata_pool();
  if (g_conf->mds_log_segment_size > 0) {
    default_log_layout.fl_object_size = g_conf->mds_log_segment_size;
    default_log_layout.fl_stripe_unit = g_conf->mds_log_segment_size;
  }
}

CInode *MDCache::create_system_inode(inodeno_t ino, int mode)
{
  dout(0) << "creating system inode with ino:" << ino << dendl;
  CInode *in = new CInode(this);
  in->inode.ino = ino;
  in->inode.version = 1;
  in->inode.mode = 0500 | mode;
  in->inode.size = 0;
  in->inode.ctime = 
    in->inode.mtime = ceph_clock_now(g_ceph_context);
  in->inode.nlink = 1;
  in->inode.truncate_size = -1ull;

  memset(&in->inode.dir_layout, 0, sizeof(in->inode.dir_layout));
  if (in->inode.is_dir()) {
    memset(&in->inode.layout, 0, sizeof(in->inode.layout));
    in->inode.dir_layout.dl_dir_hash = g_conf->mds_default_dir_hash;
    ++in->inode.rstat.rsubdirs;
  } else {
    in->inode.layout = default_file_layout;
    ++in->inode.rstat.rfiles;
  }
  in->inode.accounted_rstat = in->inode.rstat;

  if (in->is_base()) {
    if (in->is_root())
      in->inode_auth = pair<int,int>(mds->whoami, CDIR_AUTH_UNKNOWN);
    else
      in->inode_auth = pair<int,int>(in->ino() - MDS_INO_MDSDIR_OFFSET, CDIR_AUTH_UNKNOWN);
    in->open_snaprealm();  // empty snaprealm
    in->snaprealm->srnode.seq = 1;
  }
  
  add_inode(in);
  return in;
}

CInode *MDCache::create_root_inode()
{
  CInode *i = create_system_inode(MDS_INO_ROOT, S_IFDIR|0755);
  i->inode.layout = default_file_layout;
  i->inode.layout.fl_pg_pool = mds->mdsmap->get_first_data_pool();
  return i;
}

void MDCache::create_empty_hierarchy(C_Gather *gather)
{
  // create root dir
  CInode *root = create_root_inode();

  // force empty root dir
  CDir *rootdir = root->get_or_open_dirfrag(this, frag_t());
  adjust_subtree_auth(rootdir, mds->whoami);   
  rootdir->dir_rep = CDir::REP_ALL;   //NONE;

  // create ceph dir
  CInode *ceph = create_system_inode(MDS_INO_CEPH, S_IFDIR);
  CDentry *dn = rootdir->add_primary_dentry(".ceph", ceph);
  dn->_mark_dirty(mds->mdlog->get_current_segment());

  CDir *cephdir = ceph->get_or_open_dirfrag(this, frag_t());
  cephdir->dir_rep = CDir::REP_ALL;   //NONE;

  ceph->inode.dirstat = cephdir->fnode.fragstat;

  rootdir->fnode.fragstat.nsubdirs = 1;
  rootdir->fnode.rstat = ceph->inode.rstat;
  rootdir->fnode.accounted_fragstat = rootdir->fnode.fragstat;
  rootdir->fnode.accounted_rstat = rootdir->fnode.rstat;

  root->inode.dirstat = rootdir->fnode.fragstat;
  root->inode.rstat = rootdir->fnode.rstat;
  root->inode.accounted_rstat = root->inode.rstat;

  cephdir->mark_complete();
  cephdir->mark_dirty(cephdir->pre_dirty(), mds->mdlog->get_current_segment());
  cephdir->commit(0, gather->new_sub());

  rootdir->mark_complete();
  rootdir->mark_dirty(rootdir->pre_dirty(), mds->mdlog->get_current_segment());
  rootdir->commit(0, gather->new_sub());

  root->store(gather->new_sub());
}

void MDCache::create_mydir_hierarchy(C_Gather *gather)
{
  // create mds dir
  char myname[10];
  snprintf(myname, sizeof(myname), "mds%d", mds->whoami);
  CInode *my = create_system_inode(MDS_INO_MDSDIR(mds->whoami), S_IFDIR);
  //cephdir->add_remote_dentry(myname, MDS_INO_MDSDIR(mds->whoami), S_IFDIR);

  CDir *mydir = my->get_or_open_dirfrag(this, frag_t());
  adjust_subtree_auth(mydir, mds->whoami);   

  // stray dir
  for (int i = 0; i < NUM_STRAY; ++i) {
    CInode *stray = create_system_inode(MDS_INO_STRAY(mds->whoami, i), S_IFDIR);
    CDir *straydir = stray->get_or_open_dirfrag(this, frag_t());
    stringstream name;
    name << "stray" << i;
    CDentry *sdn = mydir->add_primary_dentry(name.str(), stray);
    sdn->_mark_dirty(mds->mdlog->get_current_segment());

    stray->inode.dirstat = straydir->fnode.fragstat;

    mydir->fnode.rstat.add(stray->inode.rstat);
    mydir->fnode.fragstat.nsubdirs++;
    // save them
    straydir->mark_complete();
    straydir->mark_dirty(straydir->pre_dirty(), mds->mdlog->get_current_segment());
    straydir->commit(0, gather->new_sub());
  }

  CInode *journal = create_system_inode(MDS_INO_LOG_OFFSET + mds->whoami, S_IFREG);
  string name = "journal";
  CDentry *jdn = mydir->add_primary_dentry(name, journal);
  jdn->_mark_dirty(mds->mdlog->get_current_segment());

  mydir->fnode.fragstat.nfiles++;
  mydir->fnode.rstat.rfiles++;
  mydir->fnode.accounted_fragstat = mydir->fnode.fragstat;
  mydir->fnode.accounted_rstat = mydir->fnode.rstat;

  myin->inode.dirstat = mydir->fnode.fragstat;
  myin->inode.rstat = mydir->fnode.rstat;
  myin->inode.accounted_rstat = myin->inode.rstat;


  mydir->mark_complete();
  mydir->mark_dirty(mydir->pre_dirty(), mds->mdlog->get_current_segment());
  mydir->commit(0, gather->new_sub());

  myin->store(gather->new_sub());
}

struct C_MDC_CreateSystemFile : public Context {
  MDCache *cache;
  Mutation *mut;
  CDentry *dn;
  version_t dpv;
  Context *fin;
  C_MDC_CreateSystemFile(MDCache *c, Mutation *mu, CDentry *d, version_t v, Context *f) :
    cache(c), mut(mu), dn(d), dpv(v), fin(f) {}
  void finish(int r) {
    cache->_create_system_file_finish(mut, dn, dpv, fin);
  }
};

void MDCache::_create_system_file(CDir *dir, const char *name, CInode *in, Context *fin)
{
  dout(10) << "_create_system_file " << name << " in " << *dir << dendl;
  CDentry *dn = dir->add_null_dentry(name);

  dn->push_projected_linkage(in);
  version_t dpv = dn->pre_dirty();
  
  CDir *mdir = 0;
  if (in->inode.is_dir()) {
    in->inode.rstat.rsubdirs = 1;

    mdir = in->get_or_open_dirfrag(this, frag_t());
    mdir->mark_complete();
    mdir->pre_dirty();
  } else
    in->inode.rstat.rfiles = 1;
  in->inode.version = dn->pre_dirty();
  
  SnapRealm *realm = dir->get_inode()->find_snaprealm();
  dn->first = in->first = realm->get_newest_seq() + 1;

  Mutation *mut = new Mutation;

  // force some locks.  hacky.
  mds->locker->wrlock_force(&dir->inode->filelock, mut);
  mds->locker->wrlock_force(&dir->inode->nestlock, mut);

  mut->ls = mds->mdlog->get_current_segment();
  EUpdate *le = new EUpdate(mds->mdlog, "create system file");
  mds->mdlog->start_entry(le);

  if (!in->is_mdsdir()) {
    predirty_journal_parents(mut, &le->metablob, in, dir, PREDIRTY_PRIMARY|PREDIRTY_DIR, 1);
    le->metablob.add_primary_dentry(dn, in, true);
  } else {
    predirty_journal_parents(mut, &le->metablob, in, dir, PREDIRTY_DIR, 1);
    journal_dirty_inode(mut, &le->metablob, in);
    dn->push_projected_linkage(in->ino(), in->d_type());
    le->metablob.add_remote_dentry(dn, true, in->ino(), in->d_type());
    le->metablob.add_root(true, in);
  }
  if (mdir)
    le->metablob.add_new_dir(mdir); // dirty AND complete AND new

  mds->mdlog->submit_entry(le);
  mds->mdlog->wait_for_safe(new C_MDC_CreateSystemFile(this, mut, dn, dpv, fin));
  mds->mdlog->flush();
}

void MDCache::_create_system_file_finish(Mutation *mut, CDentry *dn, version_t dpv, Context *fin)
{
  dout(10) << "_create_system_file_finish " << *dn << dendl;
  
  dn->pop_projected_linkage();
  dn->mark_dirty(dpv, mut->ls);

  CInode *in = dn->get_linkage()->get_inode();
  in->inode.version--;
  in->mark_dirty(in->inode.version + 1, mut->ls);

  if (in->inode.is_dir()) {
    CDir *dir = in->get_dirfrag(frag_t());
    assert(dir);
    dir->mark_dirty(1, mut->ls);
    dir->mark_new(mut->ls);
  }

  mut->apply();
  mds->locker->drop_locks(mut);
  mut->cleanup();
  delete mut;

  fin->complete(0);

  //if (dir && MDS_INO_IS_MDSDIR(in->ino()))
  //migrator->export_dir(dir, (int)in->ino() - MDS_INO_MDSDIR_OFFSET);
}



struct C_MDS_RetryOpenRoot : public Context {
  MDCache *cache;
  C_MDS_RetryOpenRoot(MDCache *c) : cache(c) {}
  void finish(int r) {
    if (r < 0)
      cache->mds->suicide();
    else
      cache->open_root();
  }
};

void MDCache::open_root_inode(Context *c)
{
  if (mds->whoami == mds->mdsmap->get_root()) {
    CInode *in;
    in = create_system_inode(MDS_INO_ROOT, S_IFDIR|0755);  // initially inaccurate!
    in->fetch(c);
  } else {
    discover_base_ino(MDS_INO_ROOT, c, mds->mdsmap->get_root());
  }
}

void MDCache::open_mydir_inode(Context *c)
{
  CInode *in = create_system_inode(MDS_INO_MDSDIR(mds->whoami), S_IFDIR|0755);  // initially inaccurate!
  in->fetch(c);
}

void MDCache::open_root()
{
  dout(10) << "open_root" << dendl;

  if (!root) {
    open_root_inode(new C_MDS_RetryOpenRoot(this));
    return;
  }
  if (mds->whoami == mds->mdsmap->get_root()) {
    assert(root->is_auth());  
    CDir *rootdir = root->get_or_open_dirfrag(this, frag_t());
    assert(rootdir);
    if (!rootdir->is_subtree_root())
      adjust_subtree_auth(rootdir, mds->whoami);   
    if (!rootdir->is_complete()) {
      rootdir->fetch(new C_MDS_RetryOpenRoot(this));
      return;
    }
  } else {
    assert(!root->is_auth());
    CDir *rootdir = root->get_dirfrag(frag_t());
    if (!rootdir) {
      discover_dir_frag(root, frag_t(), new C_MDS_RetryOpenRoot(this));
      return;
    }    
  }

  if (!myin) {
    CInode *in = create_system_inode(MDS_INO_MDSDIR(mds->whoami), S_IFDIR|0755);  // initially inaccurate!
    in->fetch(new C_MDS_RetryOpenRoot(this));
    return;
  }
  CDir *mydir = myin->get_or_open_dirfrag(this, frag_t());
  assert(mydir);
  adjust_subtree_auth(mydir, mds->whoami);

  populate_mydir();
}

void MDCache::populate_mydir()
{
  assert(myin);
  CDir *mydir = myin->get_or_open_dirfrag(this, frag_t());
  assert(mydir);

  dout(10) << "populate_mydir " << *mydir << dendl;

  if (!mydir->is_complete()) {
    mydir->fetch(new C_MDS_RetryOpenRoot(this));
    return;
  }    

  // open or create stray
  for (int i = 0; i < NUM_STRAY; ++i) {
    stringstream name;
    name << "stray" << i;
    CDentry *straydn = mydir->lookup(name.str());

    // allow for older fs's with stray instead of stray0
    if (straydn == NULL && i == 0)
      straydn = mydir->lookup("stray");

    if (!straydn || !straydn->get_linkage()->get_inode()) {
      _create_system_file(mydir, name.str().c_str(), create_system_inode(MDS_INO_STRAY(mds->whoami, i), S_IFDIR),
			  new C_MDS_RetryOpenRoot(this));
      return;
    }
    assert(straydn);
    assert(strays[i]);
    // we make multiple passes through this method; make sure we only pin each stray once.
    if (!strays[i]->state_test(CInode::STATE_STRAYPINNED)) {
      strays[i]->get(CInode::PIN_STRAY);
      strays[i]->state_set(CInode::STATE_STRAYPINNED);
      strays[i]->get_stickydirs();
    }
    dout(20) << " stray num " << i << " is " << *strays[i] << dendl;

    // open all frags
    list<frag_t> ls;
    strays[i]->dirfragtree.get_leaves(ls);
    for (list<frag_t>::iterator p = ls.begin(); p != ls.end(); ++p) {
      frag_t fg = *p;
      CDir *dir = strays[i]->get_dirfrag(fg);
      if (!dir)
	dir = strays[i]->get_or_open_dirfrag(this, fg);
      if (!dir->is_complete()) {
	dir->fetch(new C_MDS_RetryOpenRoot(this));
	return;
      }
    }
  }

  // open or create journal file
  string jname("journal");
  CDentry *jdn = mydir->lookup(jname);
  if (!jdn || !jdn->get_linkage()->get_inode()) {
    _create_system_file(mydir, jname.c_str(), create_system_inode(MDS_INO_LOG_OFFSET + mds->whoami, S_IFREG),
			new C_MDS_RetryOpenRoot(this));
    return;
  }

  // okay!
  dout(10) << "populate_mydir done" << dendl;
  assert(!open);    
  open = true;
  mds->queue_waiters(waiting_for_open);
}

void MDCache::open_foreign_mdsdir(inodeno_t ino, Context *fin)
{
  discover_base_ino(ino, fin, ino & (MAX_MDS-1));
}

CDentry *MDCache::get_or_create_stray_dentry(CInode *in)
{
  string straydname;
  in->name_stray_dentry(straydname);

  CInode *strayi = get_stray();
  assert(strayi);
  frag_t fg = strayi->pick_dirfrag(straydname);
  CDir *straydir = strayi->get_dirfrag(fg);
  assert(straydir);
  CDentry *straydn = straydir->lookup(straydname);
  if (!straydn) {
    straydn = straydir->add_null_dentry(straydname);
    straydn->mark_new();
  } else 
    assert(straydn->get_projected_linkage()->is_null());

  straydn->state_set(CDentry::STATE_STRAY);
  return straydn;
}



MDSCacheObject *MDCache::get_object(MDSCacheObjectInfo &info) 
{
  // inode?
  if (info.ino) 
    return get_inode(info.ino, info.snapid);

  // dir or dentry.
  CDir *dir = get_dirfrag(info.dirfrag);
  if (!dir) return 0;
    
  if (info.dname.length()) 
    return dir->lookup(info.dname, info.snapid);
  else
    return dir;
}




// ====================================================================
// subtree management

void MDCache::list_subtrees(list<CDir*>& ls)
{
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p)
    ls.push_back(p->first);
}

/*
 * adjust the dir_auth of a subtree.
 * merge with parent and/or child subtrees, if is it appropriate.
 * merge can ONLY happen if both parent and child have unambiguous auth.
 */
void MDCache::adjust_subtree_auth(CDir *dir, pair<int,int> auth, bool do_eval)
{
  dout(7) << "adjust_subtree_auth " << dir->get_dir_auth() << " -> " << auth
	  << " on " << *dir << dendl;

  if (mds->is_any_replay() || mds->is_resolve())
    do_eval = false;

  show_subtrees();

  CDir *root;
  if (dir->inode->is_base()) {
    root = dir;  // bootstrap hack.
    if (subtrees.count(root) == 0) {
      subtrees[root].clear();
      root->get(CDir::PIN_SUBTREE);
    }
  } else {
    root = get_subtree_root(dir);  // subtree root
  }
  assert(root);
  assert(subtrees.count(root));
  dout(7) << " current root is " << *root << dendl;

  if (root == dir) {
    // i am already a subtree.
    dir->set_dir_auth(auth);
  } else {
    // i am a new subtree.
    dout(10) << "  new subtree at " << *dir << dendl;
    assert(subtrees.count(dir) == 0);
    subtrees[dir].clear();      // create empty subtree bounds list for me.
    dir->get(CDir::PIN_SUBTREE);

    // set dir_auth
    dir->set_dir_auth(auth);
    
    // move items nested beneath me, under me.
    set<CDir*>::iterator p = subtrees[root].begin();
    while (p != subtrees[root].end()) {
      set<CDir*>::iterator next = p;
      ++next;
      if (get_subtree_root((*p)->get_parent_dir()) == dir) {
	// move under me
	dout(10) << "  claiming child bound " << **p << dendl;
	subtrees[dir].insert(*p); 
	subtrees[root].erase(p);
      }
      p = next;
    }
    
    // i am a bound of the parent subtree.
    subtrees[root].insert(dir); 

    // i am now the subtree root.
    root = dir;

    // adjust recursive pop counters
    if (dir->is_auth()) {
      utime_t now = ceph_clock_now(g_ceph_context);
      CDir *p = dir->get_parent_dir();
      while (p) {
	p->pop_auth_subtree.sub(now, decayrate, dir->pop_auth_subtree);
	if (p->is_subtree_root()) break;
	p = p->inode->get_parent_dir();
      }
    }

    if (do_eval)
      eval_subtree_root(dir->get_inode());
  }

  show_subtrees();
}


void MDCache::try_subtree_merge(CDir *dir)
{
  dout(7) << "try_subtree_merge " << *dir << dendl;
  assert(subtrees.count(dir));
  set<CDir*> oldbounds = subtrees[dir];

  // try merge at my root
  try_subtree_merge_at(dir);

  // try merge at my old bounds
  for (set<CDir*>::iterator p = oldbounds.begin();
       p != oldbounds.end();
       ++p) 
    try_subtree_merge_at(*p);
}

class C_MDC_SubtreeMergeWB : public Context {
  MDCache *mdcache;
  CInode *in;
  Mutation *mut;
public:
  C_MDC_SubtreeMergeWB(MDCache *mdc, CInode *i, Mutation *m) : mdcache(mdc), in(i), mut(m) {}
  void finish(int r) { 
    mdcache->subtree_merge_writebehind_finish(in, mut);
  }
};

void MDCache::try_subtree_merge_at(CDir *dir, bool do_eval)
{
  dout(10) << "try_subtree_merge_at " << *dir << dendl;
  assert(subtrees.count(dir));

  if (mds->is_any_replay() || mds->is_resolve())
    do_eval = false;

  // merge with parent?
  CDir *parent = dir;  
  if (!dir->inode->is_base())
    parent = get_subtree_root(dir->get_parent_dir());
  
  if (parent != dir &&                              // we have a parent,
      parent->dir_auth == dir->dir_auth &&          // auth matches,
      dir->dir_auth.second == CDIR_AUTH_UNKNOWN &&  // auth is unambiguous,
      !dir->state_test(CDir::STATE_EXPORTBOUND)) {  // not an exportbound,
    // merge with parent.
    dout(10) << "  subtree merge at " << *dir << dendl;
    dir->set_dir_auth(CDIR_AUTH_DEFAULT);
    
    // move our bounds under the parent
    for (set<CDir*>::iterator p = subtrees[dir].begin();
	 p != subtrees[dir].end();
	 ++p) 
      subtrees[parent].insert(*p);
    
    // we are no longer a subtree or bound
    dir->put(CDir::PIN_SUBTREE);
    subtrees.erase(dir);
    subtrees[parent].erase(dir);

    // adjust popularity?
    if (dir->is_auth()) {
      utime_t now = ceph_clock_now(g_ceph_context);
      CDir *p = dir->get_parent_dir();
      while (p) {
	p->pop_auth_subtree.add(now, decayrate, dir->pop_auth_subtree);
	if (p->is_subtree_root()) break;
	p = p->inode->get_parent_dir();
      }
    }

    if (do_eval)
      eval_subtree_root(dir->get_inode());

    // journal inode? 
    //  (this is a large hammer to ensure that dirfragtree updates will
    //   hit the disk before the relevant dirfrags ever close)
    if (dir->inode->is_auth() &&
	dir->inode->can_auth_pin() &&
	(mds->is_clientreplay() || mds->is_active() || mds->is_stopping())) {
      CInode *in = dir->inode;
      dout(10) << "try_subtree_merge_at journaling merged bound " << *in << dendl;
      
      in->auth_pin(this);

      // journal write-behind.
      inode_t *pi = in->project_inode();
      pi->version = in->pre_dirty();
      
      Mutation *mut = new Mutation;
      mut->ls = mds->mdlog->get_current_segment();
      EUpdate *le = new EUpdate(mds->mdlog, "subtree merge writebehind");
      mds->mdlog->start_entry(le);

      le->metablob.add_dir_context(in->get_parent_dn()->get_dir());
      journal_dirty_inode(mut, &le->metablob, in);
      
      mds->mdlog->submit_entry(le);
      mds->mdlog->wait_for_safe(new C_MDC_SubtreeMergeWB(this, in, mut));
      mds->mdlog->flush();
    }
  } 

  show_subtrees(15);
}

void MDCache::subtree_merge_writebehind_finish(CInode *in, Mutation *mut)
{
  dout(10) << "subtree_merge_writebehind_finish on " << in << dendl;
  in->pop_and_dirty_projected_inode(mut->ls);

  mut->apply();
  mds->locker->drop_locks(mut);
  mut->cleanup();
  delete mut;

  in->auth_unpin(this);
}

void MDCache::eval_subtree_root(CInode *diri)
{
  // evaluate subtree inode filelock?
  //  (we should scatter the filelock on subtree bounds)
  if (diri->is_auth())
    mds->locker->try_eval(diri, CEPH_LOCK_IFILE | CEPH_LOCK_INEST);
}


void MDCache::adjust_bounded_subtree_auth(CDir *dir, set<CDir*>& bounds, pair<int,int> auth)
{
  dout(7) << "adjust_bounded_subtree_auth " << dir->get_dir_auth() << " -> " << auth
	  << " on " << *dir
	  << " bounds " << bounds
	  << dendl;

  show_subtrees();

  CDir *root;
  if (dir->ino() == MDS_INO_ROOT) {
    root = dir;  // bootstrap hack.
    if (subtrees.count(root) == 0) {
      subtrees[root].clear();
      root->get(CDir::PIN_SUBTREE);
    }
  } else {
    root = get_subtree_root(dir);  // subtree root
  }
  assert(root);
  assert(subtrees.count(root));
  dout(7) << " current root is " << *root << dendl;

  pair<int,int> oldauth = dir->authority();

  if (root == dir) {
    // i am already a subtree.
    dir->set_dir_auth(auth);
  } else {
    // i am a new subtree.
    dout(10) << "  new subtree at " << *dir << dendl;
    assert(subtrees.count(dir) == 0);
    subtrees[dir].clear();      // create empty subtree bounds list for me.
    dir->get(CDir::PIN_SUBTREE);
    
    // set dir_auth
    dir->set_dir_auth(auth);
    
    // move items nested beneath me, under me.
    set<CDir*>::iterator p = subtrees[root].begin();
    while (p != subtrees[root].end()) {
      set<CDir*>::iterator next = p;
      ++next;
      if (get_subtree_root((*p)->get_parent_dir()) == dir) {
	// move under me
	dout(10) << "  claiming child bound " << **p << dendl;
	subtrees[dir].insert(*p); 
	subtrees[root].erase(p);
      }
      p = next;
    }
    
    // i am a bound of the parent subtree.
    subtrees[root].insert(dir); 

    // i am now the subtree root.
    root = dir;
  }

  // verify/adjust bounds.
  // - these may be new, or
  // - beneath existing ambiguous bounds (which will be collapsed),
  // - but NOT beneath unambiguous bounds.
  for (set<CDir*>::iterator p = bounds.begin();
       p != bounds.end();
       ++p) {
    CDir *bound = *p;
    
    // new bound?
    if (subtrees[dir].count(bound) == 0) {
      if (get_subtree_root(bound) == dir) {
	dout(10) << "  new bound " << *bound << ", adjusting auth back to old " << oldauth << dendl;
	adjust_subtree_auth(bound, oldauth);       // otherwise, adjust at bound.
      }
      else {
	dout(10) << "  want bound " << *bound << dendl;
	CDir *t = get_subtree_root(bound->get_parent_dir());
	if (subtrees[t].count(bound) == 0) {
	  assert(t != dir);
	  dout(10) << "  new bound " << *bound << dendl;
	  adjust_subtree_auth(bound, t->authority());
	}
	// make sure it's nested beneath ambiguous subtree(s)
	while (1) {
	  while (subtrees[dir].count(t) == 0)
	    t = get_subtree_root(t->get_parent_dir());
	  dout(10) << "  swallowing intervening subtree at " << *t << dendl;
	  adjust_subtree_auth(t, auth);
	  try_subtree_merge_at(t);
	  t = get_subtree_root(bound->get_parent_dir());
	  if (t == dir) break;
	}
      }
    }
    else {
      dout(10) << "  already have bound " << *bound << dendl;
    }
  }
  // merge stray bounds?
  while (!subtrees[dir].empty()) {
    set<CDir*> copy = subtrees[dir];
    for (set<CDir*>::iterator p = copy.begin(); p != copy.end(); ++p) {
      if (bounds.count(*p) == 0) {
	CDir *stray = *p;
	dout(10) << "  swallowing extra subtree at " << *stray << dendl;
	adjust_subtree_auth(stray, auth);
	try_subtree_merge_at(stray);
      }
    }
    // swallowing subtree may add new subtree bounds
    if (copy == subtrees[dir])
      break;
  }

  // bound should now match.
  verify_subtree_bounds(dir, bounds);

  show_subtrees();
}


/*
 * return a set of CDir*'s that correspond to the given bound set.  Only adjust
 * fragmentation as necessary to get an equivalent bounding set.  That is, only
 * split if one of our frags spans the provided bounding set.  Never merge.
 */
void MDCache::get_force_dirfrag_bound_set(vector<dirfrag_t>& dfs, set<CDir*>& bounds)
{
  dout(10) << "get_force_dirfrag_bound_set " << dfs << dendl;

  // sort by ino
  map<inodeno_t, fragset_t> byino;
  for (vector<dirfrag_t>::iterator p = dfs.begin(); p != dfs.end(); ++p)
    byino[p->ino].insert(p->frag);
  dout(10) << " by ino: " << byino << dendl;

  for (map<inodeno_t,fragset_t>::iterator p = byino.begin(); p != byino.end(); ++p) {
    CInode *diri = get_inode(p->first);
    if (!diri)
      continue;
    dout(10) << " checking fragset " << p->second.get() << " on " << *diri << dendl;
    for (set<frag_t>::iterator q = p->second.begin(); q != p->second.end(); ++q) {
      frag_t fg = *q;
      list<CDir*> u;
      diri->get_dirfrags_under(fg, u);
      dout(10) << "  frag " << fg << " contains " << u << dendl;
      if (!u.empty())
	bounds.insert(u.begin(), u.end());
      frag_t t = fg;
      while (t != frag_t()) {
	t = t.parent();
	CDir *dir = diri->get_dirfrag(t);
	if (dir) {
	  // ugh, we found a containing parent
	  dout(10) << "  ugh, splitting parent frag " << t << " " << *dir << dendl;
	  force_dir_fragment(diri, fg);
	  break;
	}
      }
    }
  }
}


void MDCache::adjust_bounded_subtree_auth(CDir *dir, vector<dirfrag_t>& bound_dfs, pair<int,int> auth)
{
  dout(7) << "adjust_bounded_subtree_auth " << dir->get_dir_auth() << " -> " << auth
	  << " on " << *dir 
	  << " bound_dfs " << bound_dfs
	  << dendl;
  
  // make bounds list
  set<CDir*> bounds;
  for (vector<dirfrag_t>::iterator p = bound_dfs.begin();
       p != bound_dfs.end();
       ++p) {
    CDir *bd = get_dirfrag(*p);
    if (bd) 
      bounds.insert(bd);
  }
  
  adjust_bounded_subtree_auth(dir, bounds, auth);
}

void MDCache::map_dirfrag_set(list<dirfrag_t>& dfs, set<CDir*>& result)
{
  dout(10) << "map_dirfrag_set " << dfs << dendl;

  // group by inode
  map<inodeno_t, fragset_t> ino_fragset;
  for (list<dirfrag_t>::iterator p = dfs.begin(); p != dfs.end(); ++p)
    ino_fragset[p->ino].insert(p->frag);

  // get frags
  for (map<inodeno_t, fragset_t>::iterator p = ino_fragset.begin();
       p != ino_fragset.end();
       ++p) {
    CInode *in = get_inode(p->first);
    if (!in)
      continue;

    list<frag_t> fglist;
    for (set<frag_t>::iterator q = p->second.begin(); q != p->second.end(); ++q)
      in->dirfragtree.get_leaves_under(*q, fglist);

    dout(15) << "map_dirfrag_set " << p->second << " -> " << fglist
	     << " on " << *in << dendl;

    for (list<frag_t>::iterator q = fglist.begin(); q != fglist.end(); ++q) {
      CDir *dir = in->get_dirfrag(*q);
      if (dir)
	result.insert(dir);
    }
  }
}



CDir *MDCache::get_subtree_root(CDir *dir)
{
  // find the underlying dir that delegates (or is about to delegate) auth
  while (true) {
    if (dir->is_subtree_root()) 
      return dir;
    dir = dir->get_inode()->get_parent_dir();
    if (!dir) 
      return 0;             // none
  }
}

CDir *MDCache::get_projected_subtree_root(CDir *dir)
{
  // find the underlying dir that delegates (or is about to delegate) auth
  while (true) {
    if (dir->is_subtree_root()) 
      return dir;
    dir = dir->get_inode()->get_projected_parent_dir();
    if (!dir) 
      return 0;             // none
  }
}

void MDCache::remove_subtree(CDir *dir)
{
  dout(10) << "remove_subtree " << *dir << dendl;
  assert(subtrees.count(dir));
  assert(subtrees[dir].empty());
  subtrees.erase(dir);
  dir->put(CDir::PIN_SUBTREE);
  if (dir->get_parent_dir()) {
    CDir *p = get_subtree_root(dir->get_parent_dir());
    assert(subtrees[p].count(dir));
    subtrees[p].erase(dir);
  }
}

void MDCache::get_subtree_bounds(CDir *dir, set<CDir*>& bounds)
{
  assert(subtrees.count(dir));
  bounds = subtrees[dir];
}

void MDCache::get_wouldbe_subtree_bounds(CDir *dir, set<CDir*>& bounds)
{
  if (subtrees.count(dir)) {
    // just copy them, dir is a subtree.
    get_subtree_bounds(dir, bounds);
  } else {
    // find them
    CDir *root = get_subtree_root(dir);
    for (set<CDir*>::iterator p = subtrees[root].begin();
	 p != subtrees[root].end();
	 ++p) {
      CDir *t = *p;
      while (t != root) {
	t = t->get_parent_dir();
	assert(t);
	if (t == dir) {
	  bounds.insert(*p);
	  continue;
	}
      }
    }
  }
}

void MDCache::verify_subtree_bounds(CDir *dir, const set<CDir*>& bounds)
{
  // for debugging only.
  assert(subtrees.count(dir));
  if (bounds != subtrees[dir]) {
    dout(0) << "verify_subtree_bounds failed" << dendl;
    set<CDir*> b = bounds;
    for (set<CDir*>::iterator p = subtrees[dir].begin();
	 p != subtrees[dir].end();
	 ++p) {
      if (bounds.count(*p)) {
	b.erase(*p);
	continue;
      }
      dout(0) << "  missing bound " << **p << dendl;
    }
    for (set<CDir*>::iterator p = b.begin();
	 p != b.end();
	 ++p) 
      dout(0) << "    extra bound " << **p << dendl;
  }
  assert(bounds == subtrees[dir]);
}

void MDCache::verify_subtree_bounds(CDir *dir, const list<dirfrag_t>& bounds)
{
  // for debugging only.
  assert(subtrees.count(dir));

  // make sure that any bounds i do have are properly noted as such.
  int failed = 0;
  for (list<dirfrag_t>::const_iterator p = bounds.begin();
       p != bounds.end();
       ++p) {
    CDir *bd = get_dirfrag(*p);
    if (!bd) continue;
    if (subtrees[dir].count(bd) == 0) {
      dout(0) << "verify_subtree_bounds failed: extra bound " << *bd << dendl;
      failed++;
    }
  }
  assert(failed == 0);
}

void MDCache::project_subtree_rename(CInode *diri, CDir *olddir, CDir *newdir)
{
  dout(10) << "project_subtree_rename " << *diri << " from " << *olddir
	   << " to " << *newdir << dendl;
  projected_subtree_renames[diri].push_back(pair<CDir*,CDir*>(olddir, newdir));
}

void MDCache::adjust_subtree_after_rename(CInode *diri, CDir *olddir,
                                          bool pop, bool imported)
{
  dout(10) << "adjust_subtree_after_rename " << *diri << " from " << *olddir << dendl;

  //show_subtrees();

  CDir *newdir = diri->get_parent_dir();

  if (pop) {
    map<CInode*,list<pair<CDir*,CDir*> > >::iterator p = projected_subtree_renames.find(diri);
    assert(p != projected_subtree_renames.end());
    assert(!p->second.empty());
    assert(p->second.front().first == olddir);
    assert(p->second.front().second == newdir);
    p->second.pop_front();
    if (p->second.empty())
      projected_subtree_renames.erase(p);
  }

  // adjust subtree
  list<CDir*> dfls;
  diri->get_dirfrags(dfls);
  for (list<CDir*>::iterator p = dfls.begin(); p != dfls.end(); ++p) {
    CDir *dir = *p;

    dout(10) << "dirfrag " << *dir << dendl;
    CDir *oldparent = get_subtree_root(olddir);
    dout(10) << " old parent " << *oldparent << dendl;
    CDir *newparent = get_subtree_root(newdir);
    dout(10) << " new parent " << *newparent << dendl;

    if (oldparent == newparent) {
      dout(10) << "parent unchanged for " << *dir << " at " << *oldparent << dendl;
      continue;
    }

    if (dir->is_subtree_root()) {
      // children are fine.  change parent.
      dout(10) << "moving " << *dir << " from " << *oldparent << " to " << *newparent << dendl;
      assert(subtrees[oldparent].count(dir));
      subtrees[oldparent].erase(dir);
      assert(subtrees.count(newparent));
      subtrees[newparent].insert(dir);
      try_subtree_merge_at(dir, !imported);
    } else {
      // mid-subtree.

      // see if any old bounds move to the new parent.
      list<CDir*> tomove;
      for (set<CDir*>::iterator p = subtrees[oldparent].begin();
	   p != subtrees[oldparent].end();
	   ++p) {
	CDir *bound = *p;
	CDir *broot = get_subtree_root(bound->get_parent_dir());
	if (broot != oldparent) {
	  assert(broot == newparent);
	  tomove.push_back(bound);
	}
      }
      for (list<CDir*>::iterator p = tomove.begin(); p != tomove.end(); ++p) {
	CDir *bound = *p;
	dout(10) << "moving bound " << *bound << " from " << *oldparent << " to " << *newparent << dendl;
	subtrees[oldparent].erase(bound);
	subtrees[newparent].insert(bound);
      }	   

      // did auth change?
      if (oldparent->authority() != newparent->authority()) {
	adjust_subtree_auth(dir, oldparent->authority(), !imported);  // caller is responsible for *diri.
	try_subtree_merge_at(dir, !imported);
      }
    }
  }

  show_subtrees();
}


void MDCache::get_fullauth_subtrees(set<CDir*>& s)
{
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *root = p->first;
    if (root->is_full_dir_auth())
      s.insert(root);
  }
}
void MDCache::get_auth_subtrees(set<CDir*>& s)
{
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *root = p->first;
    if (root->is_auth())
      s.insert(root);
  }
}


// count.

int MDCache::num_subtrees()
{
  return subtrees.size();
}

int MDCache::num_subtrees_fullauth()
{
  int n = 0;
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *root = p->first;
    if (root->is_full_dir_auth())
      n++;
  }
  return n;
}

int MDCache::num_subtrees_fullnonauth()
{
  int n = 0;
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *root = p->first;
    if (root->is_full_dir_nonauth())
      n++;
  }
  return n;
}



// ===================================
// journal and snap/cow helpers


/*
 * find first inode in cache that follows given snapid.  otherwise, return current.
 */
CInode *MDCache::pick_inode_snap(CInode *in, snapid_t follows)
{
  dout(10) << "pick_inode_snap follows " << follows << " on " << *in << dendl;
  assert(in->last == CEPH_NOSNAP);

  SnapRealm *realm = in->find_snaprealm();
  const set<snapid_t>& snaps = realm->get_snaps();
  dout(10) << " realm " << *realm << " " << *realm->inode << dendl;
  dout(10) << " snaps " << snaps << dendl;

  if (snaps.empty())
    return in;

  for (set<snapid_t>::const_iterator p = snaps.upper_bound(follows);  // first item > follows
       p != snaps.end();
       ++p) {
    CInode *t = get_inode(in->ino(), *p);
    if (t) {
      in = t;
      dout(10) << "pick_inode_snap snap " << *p << " found " << *in << dendl;
      break;
    }
  }
  return in;
}


/*
 * note: i'm currently cheating wrt dirty and inode.version on cow
 * items.  instead of doing a full dir predirty, i just take the
 * original item's version, and set the dirty flag (via
 * mutation::add_cow_{inode,dentry}() and mutation::apply().  that
 * means a special case in the dir commit clean sweep assertions.
 * bah.
 */
CInode *MDCache::cow_inode(CInode *in, snapid_t last)
{
  assert(last >= in->first);

  CInode *oldin = new CInode(this, true, in->first, last);
  oldin->inode = *in->get_previous_projected_inode();
  oldin->symlink = in->symlink;
  oldin->xattrs = *in->get_previous_projected_xattrs();

  oldin->inode.trim_client_ranges(last);

  in->first = last+1;

  dout(10) << "cow_inode " << *in << " to " << *oldin << dendl;
  add_inode(oldin);
  
  SnapRealm *realm = in->find_snaprealm();
  const set<snapid_t>& snaps = realm->get_snaps();

  // clone caps?
  for (map<client_t,Capability*>::iterator p = in->client_caps.begin();
      p != in->client_caps.end();
      ++p) {
    client_t client = p->first;
    Capability *cap = p->second;
    int issued = cap->issued();
    if ((issued & CEPH_CAP_ANY_WR) &&
	cap->client_follows < last) {
      // note in oldin
      for (int i = 0; i < num_cinode_locks; i++) {
	if (issued & cinode_lock_info[i].wr_caps) {
	  int lockid = cinode_lock_info[i].lock;
	  SimpleLock *lock = oldin->get_lock(lockid);
	  assert(lock);
	  oldin->client_snap_caps[lockid].insert(client);
	  oldin->auth_pin(lock);
	  lock->set_state(LOCK_SNAP_SYNC);  // gathering
	  lock->get_wrlock(true);
	  dout(10) << " client." << client << " cap " << ccap_string(issued & cinode_lock_info[i].wr_caps)
		   << " wrlock lock " << *lock << " on " << *oldin << dendl;
	}
      }
      cap->client_follows = last;
      
      // we need snapflushes for any intervening snaps
      dout(10) << "  snaps " << snaps << dendl;
      for (set<snapid_t>::const_iterator q = snaps.lower_bound(oldin->first);
	   q != snaps.end() && *q <= last;
	   ++q) {
	in->add_need_snapflush(oldin, *q, client);
      }
    } else {
      dout(10) << " ignoring client." << client << " cap follows " << cap->client_follows << dendl;
    }
  }

  return oldin;
}

void MDCache::journal_cow_dentry(Mutation *mut, EMetaBlob *metablob, CDentry *dn, snapid_t follows,
				 CInode **pcow_inode, CDentry::linkage_t *dnl)
{
  if (!dn) {
    dout(10) << "journal_cow_dentry got null CDentry, returning" << dendl;
    return;
  }
  dout(10) << "journal_cow_dentry follows " << follows << " on " << *dn << dendl;
  assert(dn->is_auth());

  // nothing to cow on a null dentry, fix caller
  if (!dnl)
    dnl = dn->get_projected_linkage();
  assert(!dnl->is_null());

  if (dnl->is_primary() && dnl->get_inode()->is_multiversion()) {
    // multiversion inode.
    CInode *in = dnl->get_inode();

    if (follows == CEPH_NOSNAP)
      follows = in->find_snaprealm()->get_newest_seq();

    if (in->get_projected_parent_dn() != dn &&
	follows+1 > dn->first) {
      snapid_t oldfirst = dn->first;
      dn->first = follows+1;
      CDentry *olddn = dn->dir->add_remote_dentry(dn->name, in->ino(),  in->d_type(),
						  oldfirst, follows);
      olddn->pre_dirty();
      dout(10) << " olddn " << *olddn << dendl;
      metablob->add_remote_dentry(olddn, true);
      mut->add_cow_dentry(olddn);

      // FIXME: adjust link count here?  hmm.
    }

    // already cloned?
    if (follows < in->first) {
      dout(10) << "journal_cow_dentry follows " << follows << " < first on " << *in << dendl;
      return;
    }

    in->cow_old_inode(follows, false);

  } else {
    if (follows == CEPH_NOSNAP)
      follows = dn->dir->inode->find_snaprealm()->get_newest_seq();
    
    // already cloned?
    if (follows < dn->first) {
      dout(10) << "journal_cow_dentry follows " << follows << " < first on " << *dn << dendl;
      return;
    }
       
    // update dn.first before adding old dentry to cdir's map
    snapid_t oldfirst = dn->first;
    dn->first = follows+1;
    
    dout(10) << "    dn " << *dn << dendl;
    if (dnl->is_primary()) {
      assert(oldfirst == dnl->get_inode()->first);
      CInode *oldin = cow_inode(dnl->get_inode(), follows);
      mut->add_cow_inode(oldin);
      if (pcow_inode)
	*pcow_inode = oldin;
      CDentry *olddn = dn->dir->add_primary_dentry(dn->name, oldin, oldfirst, follows);
      oldin->inode.version = olddn->pre_dirty();
      dout(10) << " olddn " << *olddn << dendl;
      metablob->add_primary_dentry(olddn, 0, true);
      mut->add_cow_dentry(olddn);
    } else {
      assert(dnl->is_remote());
      CDentry *olddn = dn->dir->add_remote_dentry(dn->name, dnl->get_remote_ino(), dnl->get_remote_d_type(),
						  oldfirst, follows);
      olddn->pre_dirty();
      dout(10) << " olddn " << *olddn << dendl;
      metablob->add_remote_dentry(olddn, true);
      mut->add_cow_dentry(olddn);
    }
  }
}


void MDCache::journal_cow_inode(Mutation *mut, EMetaBlob *metablob, CInode *in, snapid_t follows,
				CInode **pcow_inode)
{
  dout(10) << "journal_cow_inode follows " << follows << " on " << *in << dendl;
  CDentry *dn = in->get_projected_parent_dn();
  journal_cow_dentry(mut, metablob, dn, follows, pcow_inode);
}

void MDCache::journal_dirty_inode(Mutation *mut, EMetaBlob *metablob, CInode *in, snapid_t follows)
{
  if (in->is_base()) {
    metablob->add_root(true, in, in->get_projected_inode());
  } else {
    if (follows == CEPH_NOSNAP && in->last != CEPH_NOSNAP)
      follows = in->first - 1;
    CDentry *dn = in->get_projected_parent_dn();
    if (!dn->get_projected_linkage()->is_null())  // no need to cow a null dentry
      journal_cow_dentry(mut, metablob, dn, follows);
    if (in->get_projected_inode()->is_backtrace_updated()) {
      bool dirty_pool = in->get_projected_inode()->layout.fl_pg_pool !=
			in->get_previous_projected_inode()->layout.fl_pg_pool;
      metablob->add_primary_dentry(dn, in, true, true, dirty_pool);
    } else {
      metablob->add_primary_dentry(dn, in, true);
    }
  }
}



// nested ---------------------------------------------------------------

void MDCache::project_rstat_inode_to_frag(CInode *cur, CDir *parent, snapid_t first, int linkunlink)
{
  CDentry *parentdn = cur->get_projected_parent_dn();
  inode_t *curi = cur->get_projected_inode();

  if (cur->first > first)
    first = cur->first;

  dout(10) << "projected_rstat_inode_to_frag first " << first << " linkunlink " << linkunlink
	   << " " << *cur << dendl;
  dout(20) << "    frag head is [" << parent->first << ",head] " << dendl;
  dout(20) << " inode update is [" << first << "," << cur->last << "]" << dendl;

  /*
   * FIXME.  this incompletely propagates rstats to _old_ parents
   * (i.e. shortly after a directory rename).  but we need full
   * blown hard link backpointers to make this work properly...
   */
  snapid_t floor = parentdn->first;
  dout(20) << " floor of " << floor << " from parent dn " << *parentdn << dendl;

  if (cur->last >= floor)
    _project_rstat_inode_to_frag(*curi, MAX(first, floor), cur->last, parent, linkunlink);
      
  for (set<snapid_t>::iterator p = cur->dirty_old_rstats.begin();
       p != cur->dirty_old_rstats.end();
       ++p) {
    old_inode_t& old = cur->old_inodes[*p];
    if (*p >= floor)
      _project_rstat_inode_to_frag(old.inode, MAX(old.first, floor), *p, parent);
  }
  cur->dirty_old_rstats.clear();
}


void MDCache::_project_rstat_inode_to_frag(inode_t& inode, snapid_t ofirst, snapid_t last,
					  CDir *parent, int linkunlink)
{
  dout(10) << "_project_rstat_inode_to_frag [" << ofirst << "," << last << "]" << dendl;
  dout(20) << "  inode           rstat " << inode.rstat << dendl;
  dout(20) << "  inode accounted_rstat " << inode.accounted_rstat << dendl;
  nest_info_t delta;
  if (linkunlink == 0) {
    delta.add(inode.rstat);
    delta.sub(inode.accounted_rstat);
  } else if (linkunlink < 0) {
    delta.sub(inode.accounted_rstat);
  } else {
    delta.add(inode.rstat);
  }
  dout(20) << "                  delta " << delta << dendl;

  inode.accounted_rstat = inode.rstat;

  while (last >= ofirst) {
    /*
     * pick fnode version to update.  at each iteration, we want to
     * pick a segment ending in 'last' to update.  split as necessary
     * to make that work.  then, adjust first up so that we only
     * update one segment at a time.  then loop to cover the whole
     * [ofirst,last] interval.
     */    
    nest_info_t *prstat;
    snapid_t first;
    fnode_t *pf = parent->get_projected_fnode();
    if (last == CEPH_NOSNAP) {
      first = MAX(ofirst, parent->first);
      prstat = &pf->rstat;
      dout(20) << " projecting to head [" << first << "," << last << "] " << *prstat << dendl;

      if (first > parent->first &&
	  !(pf->rstat == pf->accounted_rstat)) {
	dout(10) << "  target snapped and not fully accounted, cow to dirty_old_rstat ["
		 << parent->first << "," << (first-1) << "] "
		 << " " << *prstat << "/" << pf->accounted_rstat
		 << dendl;
	parent->dirty_old_rstat[first-1].first = parent->first;
	parent->dirty_old_rstat[first-1].rstat = pf->rstat;
	parent->dirty_old_rstat[first-1].accounted_rstat = pf->accounted_rstat;
      }
      parent->first = first;
    } else if (last >= parent->first) {
      first = parent->first;
      parent->dirty_old_rstat[last].first = first;
      parent->dirty_old_rstat[last].rstat = pf->rstat;
      parent->dirty_old_rstat[last].accounted_rstat = pf->accounted_rstat;
      prstat = &parent->dirty_old_rstat[last].rstat;
      dout(10) << " projecting to newly split dirty_old_fnode [" << first << "," << last << "] "
	       << " " << *prstat << "/" << pf->accounted_rstat << dendl;
    } else {
      // be careful, dirty_old_rstat is a _sparse_ map.
      // sorry, this is ugly.
      first = ofirst;

      // find any intersection with last
      map<snapid_t,old_rstat_t>::iterator p = parent->dirty_old_rstat.lower_bound(last);
      if (p == parent->dirty_old_rstat.end()) {
	dout(20) << "  no dirty_old_rstat with last >= last " << last << dendl;
	if (!parent->dirty_old_rstat.empty() && parent->dirty_old_rstat.rbegin()->first >= first) {
	  dout(20) << "  last dirty_old_rstat ends at " << parent->dirty_old_rstat.rbegin()->first << dendl;
	  first = parent->dirty_old_rstat.rbegin()->first+1;
	}
      } else {
	// *p last is >= last
	if (p->second.first <= last) {
	  // *p intersects [first,last]
	  if (p->second.first < first) {
	    dout(10) << " splitting off left bit [" << p->second.first << "," << first-1 << "]" << dendl;
	    parent->dirty_old_rstat[first-1] = p->second;
	    p->second.first = first;
	  }
	  if (p->second.first > first)
	    first = p->second.first;
	  if (last < p->first) {
	    dout(10) << " splitting off right bit [" << last+1 << "," << p->first << "]" << dendl;
	    parent->dirty_old_rstat[last] = p->second;
	    p->second.first = last+1;
	  }
	} else {
	  // *p is to the _right_ of [first,last]
	  p = parent->dirty_old_rstat.lower_bound(first);
	  // new *p last is >= first
	  if (p->second.first <= last &&  // new *p isn't also to the right, and
	      p->first >= first) {        // it intersects our first bit,
	    dout(10) << " staying to the right of [" << p->second.first << "," << p->first << "]..." << dendl;
	    first = p->first+1;
	  }
	  dout(10) << " projecting to new dirty_old_rstat [" << first << "," << last << "]" << dendl;
	}
      }
      dout(20) << " projecting to dirty_old_rstat [" << first << "," << last << "]" << dendl;
      parent->dirty_old_rstat[last].first = first;
      prstat = &parent->dirty_old_rstat[last].rstat;
    }
    
    // apply
    dout(20) << "  project to [" << first << "," << last << "] " << *prstat << dendl;
    assert(last >= first);
    prstat->add(delta);
    inode.accounted_rstat = inode.rstat;
    dout(20) << "      result [" << first << "," << last << "] " << *prstat << " " << *parent << dendl;

    last = first-1;
  }
}

void MDCache::project_rstat_frag_to_inode(nest_info_t& rstat, nest_info_t& accounted_rstat,
					  snapid_t ofirst, snapid_t last, 
					  CInode *pin, bool cow_head)
{
  dout(10) << "project_rstat_frag_to_inode [" << ofirst << "," << last << "]" << dendl;
  dout(20) << "  frag           rstat " << rstat << dendl;
  dout(20) << "  frag accounted_rstat " << accounted_rstat << dendl;
  nest_info_t delta = rstat;
  delta.sub(accounted_rstat);
  dout(20) << "                 delta " << delta << dendl;

  while (last >= ofirst) {
    inode_t *pi;
    snapid_t first;
    if (last == pin->last) {
      pi = pin->get_projected_inode();
      first = MAX(ofirst, pin->first);
      if (first > pin->first) {
	old_inode_t& old = pin->cow_old_inode(first-1, cow_head);
	dout(20) << "   cloned old_inode rstat is " << old.inode.rstat << dendl;
      }
    } else {
      if (last >= pin->first) {
	first = pin->first;
	pin->cow_old_inode(last, cow_head);
      } else {
	// our life is easier here because old_inodes is not sparse
	// (although it may not begin at snapid 1)
	map<snapid_t,old_inode_t>::iterator p = pin->old_inodes.lower_bound(last);
	if (p == pin->old_inodes.end()) {
	  dout(10) << " no old_inode <= " << last << ", done." << dendl;
	  break;
	}
	first = p->second.first;
	if (first > last) {
	  dout(10) << " oldest old_inode is [" << first << "," << p->first << "], done." << dendl;
	  assert(p == pin->old_inodes.begin());
	  break;
	}
	if (p->first > last) {
	  dout(10) << " splitting right old_inode [" << first << "," << p->first << "] to ["
		   << (last+1) << "," << p->first << "]" << dendl;
	  pin->old_inodes[last] = p->second;
	  p->second.first = last+1;
	  pin->dirty_old_rstats.insert(p->first);
	}
      }
      if (first < ofirst) {
	dout(10) << " splitting left old_inode [" << first << "," << last << "] to ["
		 << first << "," << ofirst-1 << "]" << dendl;
	pin->old_inodes[ofirst-1] = pin->old_inodes[last];
	pin->dirty_old_rstats.insert(ofirst-1);
	pin->old_inodes[last].first = first = ofirst;
      }
      pi = &pin->old_inodes[last].inode;
      pin->dirty_old_rstats.insert(last);
    }
    dout(20) << " projecting to [" << first << "," << last << "] " << pi->rstat << dendl;
    pi->rstat.add(delta);
    dout(20) << "        result [" << first << "," << last << "] " << pi->rstat << dendl;

    if (pi->rstat.rbytes < 0)
      assert(!"negative rstat rbytes" == g_conf->mds_verify_scatter);

    last = first-1;
  }
}


/*
 * NOTE: we _have_ to delay the scatter if we are called during a
 * rejoin, because we can't twiddle locks between when the
 * rejoin_(weak|strong) is received and when we send the rejoin_ack.
 * normally, this isn't a problem: a recover mds doesn't twiddle locks
 * (no requests), and a survivor acks immediately.  _except_ that
 * during rejoin_(weak|strong) processing, we may complete a lock
 * gather, and do a scatter_writebehind.. and we _can't_ twiddle the
 * scatterlock state in that case or the lock states will get out of
 * sync between the auth and replica.
 *
 * the simple solution is to never do the scatter here.  instead, put
 * the scatterlock on a list if it isn't already wrlockable.  this is
 * probably the best plan anyway, since we avoid too many
 * scatters/locks under normal usage.
 */
/*
 * some notes on dirlock/nestlock scatterlock semantics:
 *
 * the fragstat (dirlock) will never be updated without
 * dirlock+nestlock wrlock held by the caller.
 *
 * the rstat (nestlock) _may_ get updated without a wrlock when nested
 * data is pushed up the tree.  this could be changed with some
 * restructuring here, but in its current form we ensure that the
 * fragstat+rstat _always_ reflect an accurrate summation over the dir
 * frag, which is nice.  and, we only need to track frags that need to
 * be nudged (and not inodes with pending rstat changes that need to
 * be pushed into the frag).  a consequence of this is that the
 * accounted_rstat on scatterlock sync may not match our current
 * rstat.  this is normal and expected.
 */
void MDCache::predirty_journal_parents(Mutation *mut, EMetaBlob *blob,
				       CInode *in, CDir *parent,
				       int flags, int linkunlink,
				       snapid_t cfollows)
{
  bool primary_dn = flags & PREDIRTY_PRIMARY;
  bool do_parent_mtime = flags & PREDIRTY_DIR;
  bool shallow = flags & PREDIRTY_SHALLOW;

  assert(mds->mdlog->entry_is_open());

  // declare now?
  if (mut->now == utime_t())
    mut->now = ceph_clock_now(g_ceph_context);

  if (in->is_base())
    return;

  dout(10) << "predirty_journal_parents"
	   << (do_parent_mtime ? " do_parent_mtime":"")
	   << " linkunlink=" <<  linkunlink
	   << (primary_dn ? " primary_dn":" remote_dn")
	   << (shallow ? " SHALLOW":"")
	   << " follows " << cfollows
	   << " " << *in << dendl;

  if (!parent) {
    assert(primary_dn);
    parent = in->get_projected_parent_dn()->get_dir();
  }

  if (flags == 0 && linkunlink == 0) {
    dout(10) << " no flags/linkunlink, just adding dir context to blob(s)" << dendl;
    blob->add_dir_context(parent);
    return;
  }

  // build list of inodes to wrlock, dirty, and update
  list<CInode*> lsi;
  CInode *cur = in;
  CDentry *parentdn = NULL;
  bool first = true;
  while (parent) {
    //assert(cur->is_auth() || !primary_dn);  // this breaks the rename auth twiddle hack
    assert(parent->is_auth());
    
    // opportunistically adjust parent dirfrag
    CInode *pin = parent->get_inode();

    // inode -> dirfrag
    mut->auth_pin(parent);
    mut->add_projected_fnode(parent);

    fnode_t *pf = parent->project_fnode();
    pf->version = parent->pre_dirty();

    if (do_parent_mtime || linkunlink) {
      assert(mut->wrlocks.count(&pin->filelock) ||
	     mut->is_slave());   // we are slave.  master will have wrlocked the dir.
      assert(cfollows == CEPH_NOSNAP);
      
      // update stale fragstat?
      parent->resync_accounted_fragstat();

      if (do_parent_mtime) {
	pf->fragstat.mtime = mut->now;
	if (mut->now > pf->rstat.rctime) {
	  dout(10) << "predirty_journal_parents updating mtime on " << *parent << dendl;
	  pf->rstat.rctime = mut->now;
	} else {
	  dout(10) << "predirty_journal_parents updating mtime UNDERWATER on " << *parent << dendl;
	}
      }
      if (linkunlink) {
	dout(10) << "predirty_journal_parents updating size on " << *parent << dendl;
	if (in->is_dir()) {
	  pf->fragstat.nsubdirs += linkunlink;
	  //pf->rstat.rsubdirs += linkunlink;
	} else {
 	  pf->fragstat.nfiles += linkunlink;
 	  //pf->rstat.rfiles += linkunlink;
	}
      }
    }

    
    // rstat
    if (!primary_dn) {
      // don't update parent this pass
    } else if (!linkunlink && !(parent->inode->nestlock.can_wrlock(-1) &&
			        parent->inode->versionlock.can_wrlock())) {
      dout(20) << " unwritable parent nestlock " << parent->inode->nestlock
	       << ", marking dirty rstat on " << *cur << dendl;
      cur->mark_dirty_rstat();
   } else {
      // if we don't hold a wrlock reference on this nestlock, take one,
      // because we are about to write into the dirfrag fnode and that needs
      // to commit before the lock can cycle.
     if (linkunlink) {
       assert(parent->inode->nestlock.get_num_wrlocks() || mut->is_slave());
     }

      if (mut->wrlocks.count(&parent->inode->nestlock) == 0) {
	dout(10) << " taking wrlock on " << parent->inode->nestlock << " on " << *parent->inode << dendl;
	mds->locker->wrlock_force(&parent->inode->nestlock, mut);
      }

      // now we can project the inode rstat diff the dirfrag
      SnapRealm *prealm = parent->inode->find_snaprealm();
      
      snapid_t follows = cfollows;
      if (follows == CEPH_NOSNAP)
	follows = prealm->get_newest_seq();
      
      snapid_t first = follows+1;

      // first, if the frag is stale, bring it back in sync.
      parent->resync_accounted_rstat();

      // now push inode rstats into frag
      project_rstat_inode_to_frag(cur, parent, first, linkunlink);
      cur->clear_dirty_rstat();
    }

    bool stop = false;
    if (!pin->is_auth() || pin->is_ambiguous_auth()) {
      dout(10) << "predirty_journal_parents !auth or ambig on " << *pin << dendl;
      stop = true;
    }

    // delay propagating until later?
    if (!stop && !first &&
	g_conf->mds_dirstat_min_interval > 0) {
      if (pin->last_dirstat_prop.sec() > 0) {
	double since_last_prop = mut->now - pin->last_dirstat_prop;
	if (since_last_prop < g_conf->mds_dirstat_min_interval) {
	  dout(10) << "predirty_journal_parents last prop " << since_last_prop
		   << " < " << g_conf->mds_dirstat_min_interval
		   << ", stopping" << dendl;
	  stop = true;
	} else {
	  dout(10) << "predirty_journal_parents last prop " << since_last_prop << " ago, continuing" << dendl;
	}
      } else {
	dout(10) << "predirty_journal_parents last prop never, stopping" << dendl;
	stop = true;
      }
    }

    if (!stop &&
	mut->wrlocks.count(&pin->nestlock) == 0 &&
	(!pin->can_auth_pin() ||
	 !pin->versionlock.can_wrlock() ||                   // make sure we can take versionlock, too
	 //true
	 !mds->locker->wrlock_start(&pin->nestlock, static_cast<MDRequest*>(mut), true) // can cast only because i'm passing nowait=true
	 )) {  // ** do not initiate.. see above comment **
      dout(10) << "predirty_journal_parents can't wrlock one of " << pin->versionlock << " or " << pin->nestlock
	       << " on " << *pin << dendl;
      stop = true;
    }
    if (stop) {
      dout(10) << "predirty_journal_parents stop.  marking nestlock on " << *pin << dendl;
      mds->locker->mark_updated_scatterlock(&pin->nestlock);
      mut->ls->dirty_dirfrag_nest.push_back(&pin->item_dirty_dirfrag_nest);
      mut->add_updated_lock(&pin->nestlock);
      if (do_parent_mtime || linkunlink) {
	mds->locker->mark_updated_scatterlock(&pin->filelock);
	mut->ls->dirty_dirfrag_dir.push_back(&pin->item_dirty_dirfrag_dir);
	mut->add_updated_lock(&pin->filelock);
      }
      break;
    }
    if (!mut->wrlocks.count(&pin->versionlock))
      mds->locker->local_wrlock_grab(&pin->versionlock, mut);

    assert(mut->wrlocks.count(&pin->nestlock) ||
	   mut->is_slave());
    
    pin->last_dirstat_prop = mut->now;

    // dirfrag -> diri
    mut->auth_pin(pin);
    mut->add_projected_inode(pin);
    lsi.push_front(pin);

    pin->pre_cow_old_inode();  // avoid cow mayhem!

    inode_t *pi = pin->project_inode();
    pi->version = pin->pre_dirty();

    // dirstat
    if (do_parent_mtime || linkunlink) {
      dout(20) << "predirty_journal_parents add_delta " << pf->fragstat << dendl;
      dout(20) << "predirty_journal_parents         - " << pf->accounted_fragstat << dendl;
      bool touched_mtime = false;
      pi->dirstat.add_delta(pf->fragstat, pf->accounted_fragstat, touched_mtime);
      pf->accounted_fragstat = pf->fragstat;
      if (touched_mtime)
	pi->mtime = pi->ctime = pi->dirstat.mtime;
      dout(20) << "predirty_journal_parents     gives " << pi->dirstat << " on " << *pin << dendl;

      if (pi->dirstat.size() < 0)
	assert(!"negative dirstat size" == g_conf->mds_verify_scatter);
      if (parent->get_frag() == frag_t()) { // i.e., we are the only frag
	if (pi->dirstat.size() != pf->fragstat.size()) {
	  mds->clog.error() << "unmatched fragstat size on single dirfrag "
	     << parent->dirfrag() << ", inode has " << pi->dirstat
	     << ", dirfrag has " << pf->fragstat << "\n";
	  
	  // trust the dirfrag for now
	  pi->dirstat = pf->fragstat;

	  assert(!"unmatched fragstat size" == g_conf->mds_verify_scatter);
	}
      }
    }

    /* 
     * the rule here is to follow the _oldest_ parent with dirty rstat
     * data.  if we don't propagate all data, we add ourselves to the
     * nudge list.  that way all rstat data will (eventually) get
     * pushed up the tree.
     *
     * actually, no.  for now, silently drop rstats for old parents.  we need 
     * hard link backpointers to do the above properly.
     */

    // stop?
    if (pin->is_base())
      break;
    parentdn = pin->get_projected_parent_dn();
    assert(parentdn);

    // rstat
    if (primary_dn) {

      dout(10) << "predirty_journal_parents frag->inode on " << *parent << dendl;

      // first, if the frag is stale, bring it back in sync.
      parent->resync_accounted_rstat();

      for (map<snapid_t,old_rstat_t>::iterator p = parent->dirty_old_rstat.begin();
	   p != parent->dirty_old_rstat.end();
	   ++p)
	project_rstat_frag_to_inode(p->second.rstat, p->second.accounted_rstat, p->second.first, p->first, pin, true);//false);
      parent->dirty_old_rstat.clear();
      project_rstat_frag_to_inode(pf->rstat, pf->accounted_rstat, parent->first, CEPH_NOSNAP, pin, true);//false);

      pf->accounted_rstat = pf->rstat;

      if (parent->get_frag() == frag_t()) { // i.e., we are the only frag
	if (pi->rstat.rbytes != pf->rstat.rbytes) { 
	  mds->clog.error() << "unmatched rstat rbytes on single dirfrag "
	      << parent->dirfrag() << ", inode has " << pi->rstat
	      << ", dirfrag has " << pf->rstat << "\n";
	  
	  // trust the dirfrag for now
	  pi->rstat = pf->rstat;

	  assert(!"unmatched rstat rbytes" == g_conf->mds_verify_scatter);
	}
      }
    }

    parent->check_rstats();
    // next parent!
    cur = pin;
    parent = parentdn->get_dir();
    linkunlink = 0;
    do_parent_mtime = false;
    primary_dn = true;
    first = false;
  }

  // now, stick it in the blob
  assert(parent);
  assert(parent->is_auth());
  blob->add_dir_context(parent);
  blob->add_dir(parent, true);
  for (list<CInode*>::iterator p = lsi.begin();
       p != lsi.end();
       ++p) {
    CInode *cur = *p;
    journal_dirty_inode(mut, blob, cur);
  }
 
}





// ===================================
// slave requests


/*
 * some handlers for master requests with slaves.  we need to make 
 * sure slaves journal commits before we forget we mastered them and
 * remove them from the uncommitted_masters map (used during recovery
 * to commit|abort slaves).
 */
struct C_MDC_CommittedMaster : public Context {
  MDCache *cache;
  metareqid_t reqid;
  C_MDC_CommittedMaster(MDCache *s, metareqid_t r) : cache(s), reqid(r) {}
  void finish(int r) {
    cache->_logged_master_commit(reqid);
  }
};

void MDCache::log_master_commit(metareqid_t reqid)
{
  dout(10) << "log_master_commit " << reqid << dendl;
  uncommitted_masters[reqid].committing = true;
  mds->mdlog->start_submit_entry(new ECommitted(reqid), 
				 new C_MDC_CommittedMaster(this, reqid));
}

void MDCache::_logged_master_commit(metareqid_t reqid)
{
  dout(10) << "_logged_master_commit " << reqid << dendl;
  assert(uncommitted_masters.count(reqid));
  uncommitted_masters[reqid].ls->uncommitted_masters.erase(reqid);
  mds->queue_waiters(uncommitted_masters[reqid].waiters);
  uncommitted_masters.erase(reqid);
}

// while active...

void MDCache::committed_master_slave(metareqid_t r, int from)
{
  dout(10) << "committed_master_slave mds." << from << " on " << r << dendl;
  assert(uncommitted_masters.count(r));
  uncommitted_masters[r].slaves.erase(from);
  if (!uncommitted_masters[r].recovering && uncommitted_masters[r].slaves.empty())
    log_master_commit(r);
}

void MDCache::logged_master_update(metareqid_t reqid)
{
  dout(10) << "logged_master_update " << reqid << dendl;
  assert(uncommitted_masters.count(reqid));
  uncommitted_masters[reqid].safe = true;
  if (pending_masters.count(reqid)) {
    pending_masters.erase(reqid);
    if (pending_masters.empty())
      process_delayed_resolve();
  }
}

/*
 * Master may crash after receiving all slaves' commit acks, but before journalling
 * the final commit. Slaves may crash after journalling the slave commit, but before
 * sending commit ack to the master. Commit masters with no uncommitted slave when
 * resolve finishes.
 */
void MDCache::finish_committed_masters()
{
  for (map<metareqid_t, umaster>::iterator p = uncommitted_masters.begin();
       p != uncommitted_masters.end();
       ++p) {
    p->second.recovering = false;
    if (!p->second.committing && p->second.slaves.empty()) {
      dout(10) << "finish_committed_masters " << p->first << dendl;
      log_master_commit(p->first);
    }
  }
}

/*
 * at end of resolve... we must journal a commit|abort for all slave
 * updates, before moving on.
 * 
 * this is so that the master can safely journal ECommitted on ops it
 * masters when it reaches up:active (all other recovering nodes must
 * complete resolve before that happens).
 */
struct C_MDC_SlaveCommit : public Context {
  MDCache *cache;
  int from;
  metareqid_t reqid;
  C_MDC_SlaveCommit(MDCache *c, int f, metareqid_t r) : cache(c), from(f), reqid(r) {}
  void finish(int r) {
    cache->_logged_slave_commit(from, reqid);
  }
};

void MDCache::_logged_slave_commit(int from, metareqid_t reqid)
{
  dout(10) << "_logged_slave_commit from mds." << from << " " << reqid << dendl;
  
  // send a message
  MMDSSlaveRequest *req = new MMDSSlaveRequest(reqid, 0, MMDSSlaveRequest::OP_COMMITTED);
  mds->send_message_mds(req, from);
}






// ====================================================================
// import map, recovery

void MDCache::_move_subtree_map_bound(dirfrag_t df, dirfrag_t oldparent, dirfrag_t newparent,
				      map<dirfrag_t,vector<dirfrag_t> >& subtrees)
{
  if (subtrees.count(oldparent)) {
      vector<dirfrag_t>& v = subtrees[oldparent];
      dout(10) << " removing " << df << " from " << oldparent << " bounds " << v << dendl;
      for (vector<dirfrag_t>::iterator it = v.begin(); it != v.end(); ++it)
	if (*it == df) {
	  v.erase(it);
	  break;
	}
    }
  if (subtrees.count(newparent)) {
    vector<dirfrag_t>& v = subtrees[newparent];
    dout(10) << " adding " << df << " to " << newparent << " bounds " << v << dendl;
    v.push_back(df);
  }
}

ESubtreeMap *MDCache::create_subtree_map() 
{
  dout(10) << "create_subtree_map " << num_subtrees() << " subtrees, " 
	   << num_subtrees_fullauth() << " fullauth"
	   << dendl;

  show_subtrees();

  ESubtreeMap *le = new ESubtreeMap();
  mds->mdlog->start_entry(le);
  
  CDir *mydir = 0;
  if (myin) {
    mydir = myin->get_dirfrag(frag_t());
  }

  // include all auth subtrees, and their bounds.
  // and a spanning tree to tie it to the root.
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *dir = p->first;

    // journal subtree as "ours" if we are
    //   me, -2
    //   me, me
    //   me, !me (may be importing and ambiguous!)

    // so not
    //   !me, *
    if (dir->get_dir_auth().first != mds->whoami)
      continue;

    if (migrator->is_ambiguous_import(dir->dirfrag()) ||
	my_ambiguous_imports.count(dir->dirfrag())) {
      dout(15) << " ambig subtree " << *dir << dendl;
      le->ambiguous_subtrees.insert(dir->dirfrag());
    } else {
      dout(15) << " subtree " << *dir << dendl;
    }

    le->subtrees[dir->dirfrag()].clear();
    le->metablob.add_dir_context(dir, EMetaBlob::TO_ROOT);
    le->metablob.add_dir(dir, false);

    if (mydir == dir)
      mydir = NULL;

    // bounds
    for (set<CDir*>::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      CDir *bound = *q;
      dout(15) << " subtree bound " << *bound << dendl;
      le->subtrees[dir->dirfrag()].push_back(bound->dirfrag());
      le->metablob.add_dir_context(bound, EMetaBlob::TO_ROOT);
      le->metablob.add_dir(bound, false);
    }
  }

  // apply projected renames
  for (map<CInode*,list<pair<CDir*,CDir*> > >::iterator p = projected_subtree_renames.begin();
       p != projected_subtree_renames.end();
       ++p) {
    for (list<pair<CDir*,CDir*> >::iterator q = p->second.begin(); q != p->second.end(); ++q) {
      CInode *diri = p->first;
      CDir *olddir = q->first;
      CDir *newdir = q->second;
      dout(10) << " adjusting for projected rename of " << *diri << " to " << *newdir << dendl;

      list<CDir*> dfls;
      diri->get_dirfrags(dfls);
      for (list<CDir*>::iterator p = dfls.begin(); p != dfls.end(); ++p) {
	CDir *dir = *p;
	dout(10) << "dirfrag " << dir->dirfrag() << " " << *dir << dendl;
	CDir *oldparent = get_projected_subtree_root(olddir);
	dout(10) << " old parent " << oldparent->dirfrag() << " " << *oldparent << dendl;
	CDir *newparent = get_projected_subtree_root(newdir);
	dout(10) << " new parent " << newparent->dirfrag() << " " << *newparent << dendl;

	if (oldparent == newparent) {
	  dout(10) << "parent unchanged for " << dir->dirfrag() << " at "
		   << oldparent->dirfrag() << dendl;
	  continue;
	}

	bool journal_dir = false;
	if (dir->is_subtree_root()) {
	  if (le->subtrees.count(newparent->dirfrag()) &&
	      oldparent->get_dir_auth() != newparent->get_dir_auth())
	    journal_dir = true;
	  // children are fine.  change parent.
	  _move_subtree_map_bound(dir->dirfrag(), oldparent->dirfrag(), newparent->dirfrag(),
				  le->subtrees);
	} else {
	  // mid-subtree.

	  if (oldparent->get_dir_auth() != newparent->get_dir_auth()) {
	    dout(10) << " creating subtree for " << dir->dirfrag() << dendl;
	    // if oldparent is auth, subtree is mine; include it.
	    if (le->subtrees.count(oldparent->dirfrag())) {
	      le->subtrees[dir->dirfrag()].clear();
	      journal_dir = true;
	    }
	    // if newparent is auth, subtree is a new bound
	    if (le->subtrees.count(newparent->dirfrag())) {
	      le->subtrees[newparent->dirfrag()].push_back(dir->dirfrag());  // newparent is auth; new bound
	      journal_dir = true;
	    }
	    newparent = dir;
	  }
	  
	  // see if any old bounds move to the new parent.
	  for (set<CDir*>::iterator p = subtrees[oldparent].begin();
	       p != subtrees[oldparent].end();
	       ++p) {
	    CDir *bound = *p;
	    if (dir->contains(bound->get_parent_dir()))
	      _move_subtree_map_bound(bound->dirfrag(), oldparent->dirfrag(), newparent->dirfrag(),
				      le->subtrees);
	  }
	}
	if (journal_dir) {
	  le->metablob.add_dir_context(dir, EMetaBlob::TO_ROOT);
	  le->metablob.add_dir(dir, false);
	}
      }
    }
  }

  // simplify the journaled map.  our in memory map may have more
  // subtrees than needed due to migrations that are just getting
  // started or just completing.  but on replay, the "live" map will
  // be simple and we can do a straight comparison.
  for (map<dirfrag_t, vector<dirfrag_t> >::iterator p = le->subtrees.begin(); p != le->subtrees.end(); ++p) {
    if (le->ambiguous_subtrees.count(p->first))
      continue;
    unsigned i = 0;
    while (i < p->second.size()) {
      dirfrag_t b = p->second[i];
      if (le->subtrees.count(b) &&
	  le->ambiguous_subtrees.count(b) == 0) {
	vector<dirfrag_t>& bb = le->subtrees[b];
	dout(10) << "simplify: " << p->first << " swallowing " << b << " with bounds " << bb << dendl;
	for (vector<dirfrag_t>::iterator r = bb.begin(); r != bb.end(); ++r)
	  p->second.push_back(*r);
	le->subtrees.erase(b);
	p->second.erase(p->second.begin() + i);
      } else {
	++i;
      }
    }
  }
  dout(15) << " subtrees " << le->subtrees << dendl;
  dout(15) << " ambiguous_subtrees " << le->ambiguous_subtrees << dendl;

  if (mydir) {
    // include my dir
    le->metablob.add_dir_context(mydir, EMetaBlob::TO_ROOT);
    le->metablob.add_dir(mydir, false);
  }

  //le->metablob.print(cout);
  le->expire_pos = mds->mdlog->journaler->get_expire_pos();
  return le;
}


void MDCache::resolve_start()
{
  dout(10) << "resolve_start" << dendl;

  if (mds->mdsmap->get_root() != mds->whoami) {
    // if we don't have the root dir, adjust it to UNKNOWN.  during
    // resolve we want mds0 to explicit claim the portion of it that
    // it owns, so that anything beyond its bounds get left as
    // unknown.
    CDir *rootdir = root->get_dirfrag(frag_t());
    if (rootdir)
      adjust_subtree_auth(rootdir, CDIR_AUTH_UNKNOWN);
  }
  resolve_gather = recovery_set;
}

void MDCache::send_resolves()
{
  send_slave_resolves();
  if (!resolve_ack_gather.empty()) {
    dout(10) << "send_resolves still waiting for resolve ack from ("
	     << resolve_ack_gather << ")" << dendl;
    return;
  }
  if (!need_resolve_rollback.empty()) {
    dout(10) << "send_resolves still waiting for rollback to commit on ("
	     << need_resolve_rollback << ")" << dendl;
    return;
  }
  send_subtree_resolves();
}

void MDCache::send_slave_resolves()
{
  dout(10) << "send_slave_resolves" << dendl;

  map<int, MMDSResolve*> resolves;

  if (mds->is_resolve()) {
    for (map<int, map<metareqid_t, MDSlaveUpdate*> >::iterator p = uncommitted_slave_updates.begin();
	 p != uncommitted_slave_updates.end();
	 ++p) {
      resolves[p->first] = new MMDSResolve;
      for (map<metareqid_t, MDSlaveUpdate*>::iterator q = p->second.begin();
	   q != p->second.end();
	   ++q) {
	dout(10) << " including uncommitted " << q->first << dendl;
	resolves[p->first]->add_slave_request(q->first);
      }
    }
  } else {
    set<int> resolve_set;
    mds->mdsmap->get_mds_set(resolve_set, MDSMap::STATE_RESOLVE);
    for (hash_map<metareqid_t, MDRequest*>::iterator p = active_requests.begin();
	 p != active_requests.end();
	 ++p) {
      if (!p->second->is_slave() || !p->second->slave_did_prepare())
	continue;
      int master = p->second->slave_to_mds;
      if (resolve_set.count(master) || is_ambiguous_slave_update(p->first, master)) {
	dout(10) << " including uncommitted " << *p->second << dendl;
	if (!resolves.count(master))
	  resolves[master] = new MMDSResolve;
	resolves[master]->add_slave_request(p->first);
      }
    }
  }

  for (map<int, MMDSResolve*>::iterator p = resolves.begin();
       p != resolves.end();
       ++p) {
    dout(10) << "sending slave resolve to mds." << p->first << dendl;
    mds->send_message_mds(p->second, p->first);
    resolve_ack_gather.insert(p->first);
  }
}

void MDCache::send_subtree_resolves()
{
  dout(10) << "send_subtree_resolves" << dendl;

  if (migrator->is_exporting() || migrator->is_importing()) {
    dout(7) << "send_subtree_resolves waiting, imports/exports still in progress" << dendl;
    migrator->show_importing();
    migrator->show_exporting();
    resolves_pending = true;
    return;  // not now
  }

  map<int, MMDSResolve*> resolves;
  for (set<int>::iterator p = recovery_set.begin();
       p != recovery_set.end();
       ++p) {
    if (*p == mds->whoami)
      continue;
    if (mds->is_resolve() || mds->mdsmap->is_resolve(*p))
      resolves[*p] = new MMDSResolve;
  }

  // known
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *dir = p->first;

    // only our subtrees
    if (dir->authority().first != mds->get_nodeid()) 
      continue;

    if (mds->is_resolve() && my_ambiguous_imports.count(dir->dirfrag()))
      continue;  // we'll add it below
    
    if (migrator->is_ambiguous_import(dir->dirfrag())) {
      // ambiguous (mid-import)
      set<CDir*> bounds;
      get_subtree_bounds(dir, bounds);
      vector<dirfrag_t> dfls;
      for (set<CDir*>::iterator q = bounds.begin(); q != bounds.end(); ++q)
	dfls.push_back((*q)->dirfrag());
      for (map<int, MMDSResolve*>::iterator q = resolves.begin();
	   q != resolves.end();
	   ++q)
	resolves[q->first]->add_ambiguous_import(dir->dirfrag(), dfls);
      dout(10) << " ambig " << dir->dirfrag() << " " << dfls << dendl;
    } else {
      // not ambiguous.
      for (map<int, MMDSResolve*>::iterator q = resolves.begin();
	   q != resolves.end();
	   ++q)
	resolves[q->first]->add_subtree(dir->dirfrag());
      // bounds too
      vector<dirfrag_t> dfls;
      for (set<CDir*>::iterator q = subtrees[dir].begin();
	   q != subtrees[dir].end();
	   ++q) {
	CDir *bound = *q;
	dfls.push_back(bound->dirfrag());
	for (map<int, MMDSResolve*>::iterator r = resolves.begin();
	     r != resolves.end();
	     ++r)
	  resolves[r->first]->add_subtree_bound(dir->dirfrag(), bound->dirfrag());
      }
      dout(10) << " claim " << dir->dirfrag() << " " << dfls << dendl;
    }
  }

  // ambiguous
  for (map<dirfrag_t, vector<dirfrag_t> >::iterator p = my_ambiguous_imports.begin();
       p != my_ambiguous_imports.end();
       ++p) {
    for (map<int, MMDSResolve*>::iterator q = resolves.begin();
	 q != resolves.end();
	 ++q)
      resolves[q->first]->add_ambiguous_import(p->first, p->second);
    dout(10) << " ambig " << p->first << " " << p->second << dendl;
  }

  // send
  for (map<int, MMDSResolve*>::iterator p = resolves.begin();
       p != resolves.end();
       ++p) {
    dout(10) << "sending subtee resolve to mds." << p->first << dendl;
    mds->send_message_mds(p->second, p->first);
  }
  resolves_pending = false;
}

void MDCache::handle_mds_failure(int who)
{
  dout(7) << "handle_mds_failure mds." << who << dendl;
  
  // make note of recovery set
  mds->mdsmap->get_recovery_mds_set(recovery_set);
  recovery_set.erase(mds->get_nodeid());
  dout(1) << "handle_mds_failure mds." << who << " : recovery peers are " << recovery_set << dendl;

  resolve_gather.insert(who);
  discard_delayed_resolve(who);
  ambiguous_slave_updates.erase(who);

  rejoin_gather.insert(who);
  rejoin_sent.erase(who);        // i need to send another
  rejoin_ack_gather.erase(who);  // i'll need/get another.

  dout(10) << " resolve_gather " << resolve_gather << dendl;
  dout(10) << " resolve_ack_gather " << resolve_ack_gather << dendl;
  dout(10) << " rejoin_sent " << rejoin_sent << dendl;
  dout(10) << " rejoin_gather " << rejoin_gather << dendl;
  dout(10) << " rejoin_ack_gather " << rejoin_ack_gather << dendl;

 
  // tell the migrator too.
  migrator->handle_mds_failure_or_stop(who);

  // clean up any requests slave to/from this node
  list<MDRequest*> finish;
  for (hash_map<metareqid_t, MDRequest*>::iterator p = active_requests.begin();
       p != active_requests.end();
       ++p) {
    // slave to the failed node?
    if (p->second->slave_to_mds == who) {
      if (p->second->slave_did_prepare()) {
	dout(10) << " slave request " << *p->second << " uncommitted, will resolve shortly" << dendl;
	if (!p->second->more()->waiting_on_slave.empty()) {
	  assert(p->second->more()->srcdn_auth_mds == mds->get_nodeid());
	  // will rollback, no need to wait
	  if (p->second->slave_request) {
	    p->second->slave_request->put();
	    p->second->slave_request = 0;
	  }
	  p->second->more()->waiting_on_slave.clear();
	}
      } else {
	dout(10) << " slave request " << *p->second << " has no prepare, finishing up" << dendl;
	if (p->second->slave_request)
	  p->second->aborted = true;
	else
	  finish.push_back(p->second);
      }
    }

    if (p->second->is_slave() && p->second->slave_did_prepare()) {
      if (p->second->more()->waiting_on_slave.count(who)) {
	assert(p->second->more()->srcdn_auth_mds == mds->get_nodeid());
	dout(10) << " slave request " << *p->second << " no longer need rename notity ack from mds."
		 << who << dendl;
	p->second->more()->waiting_on_slave.erase(who);
	if (p->second->more()->waiting_on_slave.empty())
	  mds->queue_waiter(new C_MDS_RetryRequest(this, p->second));
      }

      if (p->second->more()->srcdn_auth_mds == who &&
	  mds->mdsmap->is_clientreplay_or_active_or_stopping(p->second->slave_to_mds)) {
	// rename srcdn's auth mds failed, resolve even I'm a survivor.
	dout(10) << " slave request " << *p->second << " uncommitted, will resolve shortly" << dendl;
	add_ambiguous_slave_update(p->first, p->second->slave_to_mds);
      }
    }
    
    // failed node is slave?
    if (p->second->is_master() && !p->second->committing) {
      if (p->second->more()->srcdn_auth_mds == who) {
	dout(10) << " master request " << *p->second << " waiting for rename srcdn's auth mds."
		 << who << " to recover" << dendl;
	assert(p->second->more()->witnessed.count(who) == 0);
	if (p->second->more()->is_ambiguous_auth)
	  p->second->clear_ambiguous_auth();
	// rename srcdn's auth mds failed, all witnesses will rollback
	p->second->more()->witnessed.clear();
	pending_masters.erase(p->first);
      }

      if (p->second->more()->witnessed.count(who)) {
	int srcdn_auth = p->second->more()->srcdn_auth_mds;
	if (srcdn_auth >= 0 && p->second->more()->waiting_on_slave.count(srcdn_auth)) {
	  dout(10) << " master request " << *p->second << " waiting for rename srcdn's auth mds."
		   << p->second->more()->srcdn_auth_mds << " to reply" << dendl;
	  // waiting for the slave (rename srcdn's auth mds), delay sending resolve ack
	  // until either the request is committing or the slave also fails.
	  assert(p->second->more()->waiting_on_slave.size() == 1);
	  pending_masters.insert(p->first);
	} else {
	  dout(10) << " master request " << *p->second << " no longer witnessed by slave mds."
		   << who << " to recover" << dendl;
	  if (srcdn_auth >= 0)
	    assert(p->second->more()->witnessed.count(srcdn_auth) == 0);

	  // discard this peer's prepare (if any)
	  p->second->more()->witnessed.erase(who);
	}
      }
      
      if (p->second->more()->waiting_on_slave.count(who)) {
	dout(10) << " master request " << *p->second << " waiting for slave mds." << who
		 << " to recover" << dendl;
	// retry request when peer recovers
	p->second->more()->waiting_on_slave.erase(who);
	if (p->second->more()->waiting_on_slave.empty())
	  mds->wait_for_active_peer(who, new C_MDS_RetryRequest(this, p->second));
      }

      if (p->second->locking && p->second->locking_target_mds == who)
	p->second->finish_locking(p->second->locking);
    }
  }

  for (map<metareqid_t, umaster>::iterator p = uncommitted_masters.begin();
       p != uncommitted_masters.end();
       ++p) {
    // The failed MDS may have already committed the slave update
    if (p->second.slaves.count(who)) {
      p->second.recovering = true;
      p->second.slaves.erase(who);
    }
  }

  while (!finish.empty()) {
    dout(10) << "cleaning up slave request " << *finish.front() << dendl;
    request_finish(finish.front());
    finish.pop_front();
  }

  kick_find_ino_peers(who);
  kick_open_ino_peers(who);

  show_subtrees();  
}

/*
 * handle_mds_recovery - called on another node's transition 
 * from resolve -> active.
 */
void MDCache::handle_mds_recovery(int who)
{
  dout(7) << "handle_mds_recovery mds." << who << dendl;

  list<Context*> waiters;

  // wake up any waiters in their subtrees
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *dir = p->first;

    if (dir->authority().first != who ||
	dir->authority().second == mds->whoami)
      continue;
    assert(!dir->is_auth());
   
    // wake any waiters
    list<CDir*> q;
    q.push_back(dir);

    while (!q.empty()) {
      CDir *d = q.front();
      q.pop_front();
      d->take_waiting(CDir::WAIT_ANY_MASK, waiters);

      // inode waiters too
      for (CDir::map_t::iterator p = d->items.begin();
	   p != d->items.end();
	   ++p) {
	CDentry *dn = p->second;
	CDentry::linkage_t *dnl = dn->get_linkage();
	if (dnl->is_primary()) {
	  dnl->get_inode()->take_waiting(CInode::WAIT_ANY_MASK, waiters);
	  
	  // recurse?
	  list<CDir*> ls;
	  dnl->get_inode()->get_dirfrags(ls);
	  for (list<CDir*>::iterator p = ls.begin();
	       p != ls.end();
	       ++p) {
	    CDir *subdir = *p;
	    if (!subdir->is_subtree_root())
	      q.push_back(subdir);
	  }
	}
      }
    }
  }

  kick_discovers(who);
  kick_open_ino_peers(who);
  kick_find_ino_peers(who);

  // queue them up.
  mds->queue_waiters(waiters);
}

void MDCache::set_recovery_set(set<int>& s) 
{
  dout(7) << "set_recovery_set " << s << dendl;
  recovery_set = s;
}


/*
 * during resolve state, we share resolves to determine who
 * is authoritative for which trees.  we expect to get an resolve
 * from _everyone_ in the recovery_set (the mds cluster at the time of
 * the first failure).
 *
 * This functions puts the passed message before returning
 */
void MDCache::handle_resolve(MMDSResolve *m)
{
  dout(7) << "handle_resolve from " << m->get_source() << dendl;
  int from = m->get_source().num();

  if (mds->get_state() < MDSMap::STATE_RESOLVE) {
    if (mds->get_want_state() == CEPH_MDS_STATE_RESOLVE) {
      mds->wait_for_resolve(new C_MDS_RetryMessage(mds, m));
      return;
    }
    // wait until we reach the resolve stage!
    m->put();
    return;
  }

  discard_delayed_resolve(from);

  // ambiguous slave requests?
  if (!m->slave_requests.empty()) {
    for (vector<metareqid_t>::iterator p = m->slave_requests.begin();
	 p != m->slave_requests.end();
	 ++p) {
      if (uncommitted_masters.count(*p) && !uncommitted_masters[*p].safe)
	pending_masters.insert(*p);
    }

    if (!pending_masters.empty()) {
      dout(10) << " still have pending updates, delay processing slave resolve" << dendl;
      delayed_resolve[from] = m;
      return;
    }

    MMDSResolveAck *ack = new MMDSResolveAck;
    for (vector<metareqid_t>::iterator p = m->slave_requests.begin();
	 p != m->slave_requests.end();
	 ++p) {
      if (uncommitted_masters.count(*p)) {  //mds->sessionmap.have_completed_request(*p)) {
	// COMMIT
	dout(10) << " ambiguous slave request " << *p << " will COMMIT" << dendl;
	ack->add_commit(*p);
	uncommitted_masters[*p].slaves.insert(from);   // wait for slave OP_COMMITTED before we log ECommitted
      } else {
	// ABORT
	dout(10) << " ambiguous slave request " << *p << " will ABORT" << dendl;
	ack->add_abort(*p);      
      }
    }
    mds->send_message(ack, m->get_connection());
    m->put();
    return;
  }

  if (!resolve_ack_gather.empty() || !need_resolve_rollback.empty()) {
    dout(10) << "delay processing subtree resolve" << dendl;
    delayed_resolve[from] = m;
    return;
  }

  // am i a surviving ambiguous importer?
  if (mds->is_clientreplay() || mds->is_active() || mds->is_stopping()) {
    // check for any import success/failure (from this node)
    map<dirfrag_t, vector<dirfrag_t> >::iterator p = my_ambiguous_imports.begin();
    while (p != my_ambiguous_imports.end()) {
      map<dirfrag_t, vector<dirfrag_t> >::iterator next = p;
      ++next;
      CDir *dir = get_dirfrag(p->first);
      assert(dir);
      dout(10) << "checking ambiguous import " << *dir << dendl;
      if (migrator->is_importing(dir->dirfrag()) &&
	  migrator->get_import_peer(dir->dirfrag()) == from) {
	assert(migrator->get_import_state(dir->dirfrag()) == Migrator::IMPORT_ACKING);
	
	// check if sender claims the subtree
	bool claimed_by_sender = false;
	for (map<dirfrag_t, vector<dirfrag_t> >::iterator q = m->subtrees.begin();
	     q != m->subtrees.end();
	     ++q) {
	  // an ambiguous import won't race with a refragmentation; it's appropriate to force here.
	  CDir *base = get_force_dirfrag(q->first);
	  if (!base || !base->contains(dir)) 
	    continue;  // base not dir or an ancestor of dir, clearly doesn't claim dir.

	  bool inside = true;
	  set<CDir*> bounds;
	  get_force_dirfrag_bound_set(q->second, bounds);
	  for (set<CDir*>::iterator p = bounds.begin(); p != bounds.end(); ++p) {
	    CDir *bound = *p;
	    if (bound->contains(dir)) {
	      inside = false;  // nope, bound is dir or parent of dir, not inside.
	      break;
	    }
	  }
	  if (inside)
	    claimed_by_sender = true;
	}

	if (claimed_by_sender) {
	  dout(7) << "ambiguous import failed on " << *dir << dendl;
	  migrator->import_reverse(dir);
	} else {
	  dout(7) << "ambiguous import succeeded on " << *dir << dendl;
	  migrator->import_finish(dir, true);
	}
	my_ambiguous_imports.erase(p);  // no longer ambiguous.
      }
      p = next;
    }
  }    

  // update my dir_auth values
  //   need to do this on recoverying nodes _and_ bystanders (to resolve ambiguous
  //   migrations between other nodes)
  for (map<dirfrag_t, vector<dirfrag_t> >::iterator pi = m->subtrees.begin();
       pi != m->subtrees.end();
       ++pi) {
    dout(10) << "peer claims " << pi->first << " bounds " << pi->second << dendl;
    CDir *dir = get_force_dirfrag(pi->first);
    if (!dir)
      continue;

    set<CDir*> bounds;
    get_force_dirfrag_bound_set(pi->second, bounds);

    adjust_bounded_subtree_auth(dir, bounds, from);
    try_subtree_merge(dir);
  }

  show_subtrees();

  // note ambiguous imports too
  for (map<dirfrag_t, vector<dirfrag_t> >::iterator pi = m->ambiguous_imports.begin();
       pi != m->ambiguous_imports.end();
       ++pi) {
    dout(10) << "noting ambiguous import on " << pi->first << " bounds " << pi->second << dendl;
    other_ambiguous_imports[from][pi->first].swap( pi->second );
  }
  
  // did i get them all?
  resolve_gather.erase(from);
  
  maybe_resolve_finish();

  m->put();
}

void MDCache::process_delayed_resolve()
{
  dout(10) << "process_delayed_resolve" << dendl;
  map<int, MMDSResolve*> tmp;
  tmp.swap(delayed_resolve);
  for (map<int, MMDSResolve*>::iterator p = tmp.begin(); p != tmp.end(); ++p)
    handle_resolve(p->second);
}

void MDCache::discard_delayed_resolve(int who)
{
  if (delayed_resolve.count(who)) {
      delayed_resolve[who]->put();
      delayed_resolve.erase(who);
  }
}

void MDCache::maybe_resolve_finish()
{
  assert(resolve_ack_gather.empty());
  assert(need_resolve_rollback.empty());

  if (!resolve_gather.empty()) {
    dout(10) << "maybe_resolve_finish still waiting for resolves ("
	     << resolve_gather << ")" << dendl;
    return;
  }

  dout(10) << "maybe_resolve_finish got all resolves+resolve_acks, done." << dendl;
  disambiguate_imports();
  finish_committed_masters();
  if (mds->is_resolve()) {
    trim_unlinked_inodes();
    recalc_auth_bits();
    mds->resolve_done();
  } else {
    maybe_send_pending_rejoins();
  }
}

/* This functions puts the passed message before returning */
void MDCache::handle_resolve_ack(MMDSResolveAck *ack)
{
  dout(10) << "handle_resolve_ack " << *ack << " from " << ack->get_source() << dendl;
  int from = ack->get_source().num();

  if (!resolve_ack_gather.count(from) ||
      mds->mdsmap->get_state(from) < MDSMap::STATE_RESOLVE) {
    ack->put();
    return;
  }

  if (ambiguous_slave_updates.count(from)) {
    assert(mds->mdsmap->is_clientreplay_or_active_or_stopping(from));
    assert(mds->is_clientreplay() || mds->is_active() || mds->is_stopping());
  }

  for (vector<metareqid_t>::iterator p = ack->commit.begin();
       p != ack->commit.end();
       ++p) {
    dout(10) << " commit on slave " << *p << dendl;
    
    if (ambiguous_slave_updates.count(from)) {
      remove_ambiguous_slave_update(*p, from);
      continue;
    }

    if (mds->is_resolve()) {
      // replay
      MDSlaveUpdate *su = get_uncommitted_slave_update(*p, from);
      assert(su);

      // log commit
      mds->mdlog->start_submit_entry(new ESlaveUpdate(mds->mdlog, "unknown", *p, from,
						      ESlaveUpdate::OP_COMMIT, su->origop));
      mds->mdlog->wait_for_safe(new C_MDC_SlaveCommit(this, from, *p));
      mds->mdlog->flush();

      finish_uncommitted_slave_update(*p, from);
    } else {
      MDRequest *mdr = request_get(*p);
      assert(mdr->slave_request == 0);  // shouldn't be doing anything!
      request_finish(mdr);
    }
  }

  for (vector<metareqid_t>::iterator p = ack->abort.begin();
       p != ack->abort.end();
       ++p) {
    dout(10) << " abort on slave " << *p << dendl;

    if (mds->is_resolve()) {
      MDSlaveUpdate *su = get_uncommitted_slave_update(*p, from);
      assert(su);

      // perform rollback (and journal a rollback entry)
      // note: this will hold up the resolve a bit, until the rollback entries journal.
      switch (su->origop) {
      case ESlaveUpdate::LINK:
	mds->server->do_link_rollback(su->rollback, from, 0);
	break;
      case ESlaveUpdate::RENAME:
	mds->server->do_rename_rollback(su->rollback, from, 0);
	break;
      case ESlaveUpdate::RMDIR:
	mds->server->do_rmdir_rollback(su->rollback, from, 0);
	break;
      default:
	assert(0);
      }
    } else {
      MDRequest *mdr = request_get(*p);
      if (mdr->more()->slave_commit) {
	Context *fin = mdr->more()->slave_commit;
	mdr->more()->slave_commit = 0;
	fin->complete(-1);
      } else {
	if (mdr->slave_request) 
	  mdr->aborted = true;
	else
	  request_finish(mdr);
      }
    }
  }

  if (!ambiguous_slave_updates.count(from))
    resolve_ack_gather.erase(from);
  if (resolve_ack_gather.empty() && need_resolve_rollback.empty()) {
    send_subtree_resolves();
    process_delayed_resolve();
  }

  ack->put();
}

void MDCache::add_uncommitted_slave_update(metareqid_t reqid, int master, MDSlaveUpdate *su)
{
  assert(uncommitted_slave_updates[master].count(reqid) == 0);
  uncommitted_slave_updates[master][reqid] = su;
  for(set<CDir*>::iterator p = su->olddirs.begin(); p != su->olddirs.end(); ++p)
    uncommitted_slave_rename_olddir[*p]++;
  for(set<CInode*>::iterator p = su->unlinked.begin(); p != su->unlinked.end(); ++p)
    uncommitted_slave_unlink[*p]++;
}

void MDCache::finish_uncommitted_slave_update(metareqid_t reqid, int master)
{
  assert(uncommitted_slave_updates[master].count(reqid));
  MDSlaveUpdate* su = uncommitted_slave_updates[master][reqid];

  uncommitted_slave_updates[master].erase(reqid);
  if (uncommitted_slave_updates[master].empty())
    uncommitted_slave_updates.erase(master);
  // discard the non-auth subtree we renamed out of
  for(set<CDir*>::iterator p = su->olddirs.begin(); p != su->olddirs.end(); ++p) {
    CDir *dir = *p;
    uncommitted_slave_rename_olddir[dir]--;
    if (uncommitted_slave_rename_olddir[dir] == 0) {
      uncommitted_slave_rename_olddir.erase(dir);
      CDir *root = get_subtree_root(dir);
      if (root->get_dir_auth() == CDIR_AUTH_UNDEF)
	try_trim_non_auth_subtree(root);
    }
  }
  // removed the inodes that were unlinked by slave update
  for(set<CInode*>::iterator p = su->unlinked.begin(); p != su->unlinked.end(); ++p) {
    CInode *in = *p;
    uncommitted_slave_unlink[in]--;
    if (uncommitted_slave_unlink[in] == 0) {
      uncommitted_slave_unlink.erase(in);
      if (!in->get_projected_parent_dn())
	mds->mdcache->remove_inode_recursive(in);
    }
  }
  delete su;
}

MDSlaveUpdate* MDCache::get_uncommitted_slave_update(metareqid_t reqid, int master)
{

  MDSlaveUpdate* su = NULL;
  if (uncommitted_slave_updates.count(master) &&
      uncommitted_slave_updates[master].count(reqid)) {
    su = uncommitted_slave_updates[master][reqid];
    assert(su);
  }
  return su;
}

void MDCache::finish_rollback(metareqid_t reqid) {
  assert(need_resolve_rollback.count(reqid));
  if (mds->is_resolve())
    finish_uncommitted_slave_update(reqid, need_resolve_rollback[reqid]);
  need_resolve_rollback.erase(reqid);
  if (resolve_ack_gather.empty() && need_resolve_rollback.empty()) {
    send_subtree_resolves();
    process_delayed_resolve();
  }
}

void MDCache::disambiguate_imports()
{
  dout(10) << "disambiguate_imports" << dendl;

  // other nodes' ambiguous imports
  for (map<int, map<dirfrag_t, vector<dirfrag_t> > >::iterator p = other_ambiguous_imports.begin();
       p != other_ambiguous_imports.end();
       ++p) {
    int who = p->first;
    dout(10) << "ambiguous imports for mds." << who << dendl;

    for (map<dirfrag_t, vector<dirfrag_t> >::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      dout(10) << " ambiguous import " << q->first << " bounds " << q->second << dendl;
      // an ambiguous import will not race with a refragmentation; it's appropriate to force here.
      CDir *dir = get_force_dirfrag(q->first);
      if (!dir) continue;
      
      if (dir->is_ambiguous_auth() ||	// works for me_ambig or if i am a surviving bystander
	  dir->authority() == CDIR_AUTH_UNDEF) { // resolving
	dout(10) << "  mds." << who << " did import " << *dir << dendl;
	adjust_bounded_subtree_auth(dir, q->second, who);
	try_subtree_merge(dir);
      } else {
	dout(10) << "  mds." << who << " did not import " << *dir << dendl;
      }
    }
  }
  other_ambiguous_imports.clear();

  // my ambiguous imports
  pair<int,int> me_ambig(mds->whoami, mds->whoami);
  while (!my_ambiguous_imports.empty()) {
    map<dirfrag_t, vector<dirfrag_t> >::iterator q = my_ambiguous_imports.begin();

    CDir *dir = get_dirfrag(q->first);
    if (!dir) continue;
    
    if (dir->authority() != me_ambig) {
      dout(10) << "ambiguous import auth known, must not be me " << *dir << dendl;
      cancel_ambiguous_import(dir);

      // subtree may have been swallowed by another node claiming dir
      // as their own.
      CDir *root = get_subtree_root(dir);
      if (root != dir)
	dout(10) << "  subtree root is " << *root << dendl;
      assert(root->dir_auth.first != mds->whoami);  // no us!
      try_trim_non_auth_subtree(root);

      mds->mdlog->start_submit_entry(new EImportFinish(dir, false));
    } else {
      dout(10) << "ambiguous import auth unclaimed, must be me " << *dir << dendl;
      finish_ambiguous_import(q->first);
      mds->mdlog->start_submit_entry(new EImportFinish(dir, true));
    }
  }
  assert(my_ambiguous_imports.empty());
  mds->mdlog->flush();

  if (mds->is_resolve()) {
    // verify all my subtrees are unambiguous!
    for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
	 p != subtrees.end();
	 ++p) {
      CDir *dir = p->first;
      if (dir->is_ambiguous_dir_auth()) {
	dout(0) << "disambiguate_imports uh oh, dir_auth is still ambiguous for " << *dir << dendl;
	show_subtrees();
      }
      assert(!dir->is_ambiguous_dir_auth());
    }
  }

  show_subtrees();
}


void MDCache::add_ambiguous_import(dirfrag_t base, const vector<dirfrag_t>& bounds) 
{
  assert(my_ambiguous_imports.count(base) == 0);
  my_ambiguous_imports[base] = bounds;
}


void MDCache::add_ambiguous_import(CDir *base, const set<CDir*>& bounds)
{
  // make a list
  vector<dirfrag_t> binos;
  for (set<CDir*>::iterator p = bounds.begin();
       p != bounds.end();
       ++p) 
    binos.push_back((*p)->dirfrag());
  
  // note: this can get called twice if the exporter fails during recovery
  if (my_ambiguous_imports.count(base->dirfrag()))
    my_ambiguous_imports.erase(base->dirfrag());

  add_ambiguous_import(base->dirfrag(), binos);
}

void MDCache::cancel_ambiguous_import(CDir *dir)
{
  dirfrag_t df = dir->dirfrag();
  assert(my_ambiguous_imports.count(df));
  dout(10) << "cancel_ambiguous_import " << df
	   << " bounds " << my_ambiguous_imports[df]
	   << " " << *dir
	   << dendl;
  my_ambiguous_imports.erase(df);
}

void MDCache::finish_ambiguous_import(dirfrag_t df)
{
  assert(my_ambiguous_imports.count(df));
  vector<dirfrag_t> bounds;
  bounds.swap(my_ambiguous_imports[df]);
  my_ambiguous_imports.erase(df);
  
  dout(10) << "finish_ambiguous_import " << df
	   << " bounds " << bounds
	   << dendl;
  CDir *dir = get_dirfrag(df);
  assert(dir);
  
  // adjust dir_auth, import maps
  adjust_bounded_subtree_auth(dir, bounds, mds->get_nodeid());
  try_subtree_merge(dir);
}

void MDCache::remove_inode_recursive(CInode *in)
{
  dout(10) << "remove_inode_recursive " << *in << dendl;
  list<CDir*> ls;
  in->get_dirfrags(ls);
  list<CDir*>::iterator p = ls.begin();
  while (p != ls.end()) {
    CDir *subdir = *p++;

    dout(10) << " removing dirfrag " << subdir << dendl;
    CDir::map_t::iterator q = subdir->items.begin();
    while (q != subdir->items.end()) {
      CDentry *dn = q->second;
      ++q;
      CDentry::linkage_t *dnl = dn->get_linkage();
      if (dnl->is_primary()) {
	CInode *tin = dnl->get_inode();
	subdir->unlink_inode(dn);
	remove_inode_recursive(tin);
      }
      subdir->remove_dentry(dn);
    }
    
    if (subdir->is_subtree_root()) 
      remove_subtree(subdir);
    in->close_dirfrag(subdir->dirfrag().frag);
  }
  remove_inode(in);
}

void MDCache::trim_unlinked_inodes()
{
  dout(7) << "trim_unlinked_inodes" << dendl;
  list<CInode*> q;
  for (hash_map<vinodeno_t,CInode*>::iterator p = inode_map.begin();
       p != inode_map.end();
       ++p) {
    CInode *in = p->second;
    if (in->get_parent_dn() == NULL && !in->is_base()) {
      dout(7) << " will trim from " << *in << dendl;
      q.push_back(in);
    }
  }
  for (list<CInode*>::iterator p = q.begin(); p != q.end(); ++p)
    remove_inode_recursive(*p);
}

/** recalc_auth_bits()
 * once subtree auth is disambiguated, we need to adjust all the 
 * auth and dirty bits in our cache before moving on.
 */
void MDCache::recalc_auth_bits()
{
  dout(7) << "recalc_auth_bits" << dendl;

  if (root) {
    root->inode_auth.first = mds->mdsmap->get_root();
    if (mds->whoami != root->inode_auth.first) {
      root->state_clear(CInode::STATE_AUTH);
      root->state_set(CInode::STATE_REJOINING);
    }
  }

  set<CInode*> subtree_inodes;
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    if (p->first->dir_auth.first == mds->get_nodeid())
      subtree_inodes.insert(p->first->inode);
  }

  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {

    CInode *inode = p->first->get_inode();
    if (inode->is_mdsdir() && inode->ino() != MDS_INO_MDSDIR(mds->get_nodeid())) {
      inode->state_clear(CInode::STATE_AUTH);
      inode->state_set(CInode::STATE_REJOINING);
    }

    list<CDir*> dfq;  // dirfrag queue
    dfq.push_back(p->first);

    bool auth = p->first->authority().first == mds->get_nodeid();
    dout(10) << " subtree auth=" << auth << " for " << *p->first << dendl;

    while (!dfq.empty()) {
      CDir *dir = dfq.front();
      dfq.pop_front();

      // dir
      if (auth) 
	dir->state_set(CDir::STATE_AUTH);
      else {
	dir->state_set(CDir::STATE_REJOINING);
	dir->state_clear(CDir::STATE_AUTH);
	dir->state_clear(CDir::STATE_COMPLETE);
	if (dir->is_dirty()) 
	  dir->mark_clean();
      }

      // dentries in this dir
      for (CDir::map_t::iterator q = dir->items.begin();
	   q != dir->items.end();
	   ++q) {
	// dn
	CDentry *dn = q->second;
	CDentry::linkage_t *dnl = dn->get_linkage();
	if (auth)
	  dn->state_set(CDentry::STATE_AUTH);
	else {
	  dn->state_set(CDentry::STATE_REJOINING);
	  dn->state_clear(CDentry::STATE_AUTH);
	  if (dn->is_dirty()) 
	    dn->mark_clean();
	}

	if (dnl->is_primary()) {
	  // inode
	  if (auth) 
	    dnl->get_inode()->state_set(CInode::STATE_AUTH);
	  else {
	    dnl->get_inode()->state_set(CInode::STATE_REJOINING);
	    dnl->get_inode()->state_clear(CInode::STATE_AUTH);
	    if (dnl->get_inode()->is_dirty())
	      dnl->get_inode()->mark_clean();
	    if (dnl->get_inode()->is_dirty_parent())
	      dnl->get_inode()->clear_dirty_parent();
	    // avoid touching scatterlocks for our subtree roots!
	    if (subtree_inodes.count(dnl->get_inode()) == 0)
	      dnl->get_inode()->clear_scatter_dirty();
	  }

	  // recurse?
	  if (dnl->get_inode()->is_dir()) 
	    dnl->get_inode()->get_nested_dirfrags(dfq);
	}
      }
    }
  }
  
  show_subtrees();
  show_cache();
}



// ===========================================================================
// REJOIN

/*
 * notes on scatterlock recovery:
 *
 * - recovering inode replica sends scatterlock data for any subtree
 *   roots (the only ones that are possibly dirty).
 *
 * - surviving auth incorporates any provided scatterlock data.  any
 *   pending gathers are then finished, as with the other lock types.
 *
 * that takes care of surviving auth + (recovering replica)*.
 *
 * - surviving replica sends strong_inode, which includes current
 *   scatterlock state, AND any dirty scatterlock data.  this
 *   provides the recovering auth with everything it might need.
 * 
 * - recovering auth must pick initial scatterlock state based on
 *   (weak|strong) rejoins.
 *   - always assimilate scatterlock data (it can't hurt)
 *   - any surviving replica in SCATTER state -> SCATTER.  otherwise, SYNC.
 *   - include base inode in ack for all inodes that saw scatterlock content
 *
 * also, for scatter gather,
 *
 * - auth increments {frag,r}stat.version on completion of any gather.
 *
 * - auth incorporates changes in a gather _only_ if the version
 *   matches.
 *
 * - replica discards changes any time the scatterlock syncs, and
 *   after recovery.
 */

void MDCache::rejoin_start()
{
  dout(10) << "rejoin_start" << dendl;

  rejoin_gather = recovery_set;
  // need finish opening cap inodes before sending cache rejoins
  rejoin_gather.insert(mds->get_nodeid());
  process_imported_caps();
}

/*
 * rejoin phase!
 *
 * this initiates rejoin.  it shoudl be called before we get any
 * rejoin or rejoin_ack messages (or else mdsmap distribution is broken).
 *
 * we start out by sending rejoins to everyone in the recovery set.
 *
 * if we are rejoin, send for all regions in our cache.
 * if we are active|stopping, send only to nodes that are are rejoining.
 */
void MDCache::rejoin_send_rejoins()
{
  dout(10) << "rejoin_send_rejoins with recovery_set " << recovery_set << dendl;

  if (rejoin_gather.count(mds->get_nodeid())) {
    dout(7) << "rejoin_send_rejoins still processing imported caps, delaying" << dendl;
    rejoins_pending = true;
    return;
  }
  if (!resolve_gather.empty()) {
    dout(7) << "rejoin_send_rejoins still waiting for resolves ("
	    << resolve_gather << ")" << dendl;
    rejoins_pending = true;
    return;
  }

  map<int, MMDSCacheRejoin*> rejoins;


  // if i am rejoining, send a rejoin to everyone.
  // otherwise, just send to others who are rejoining.
  for (set<int>::iterator p = recovery_set.begin();
       p != recovery_set.end();
       ++p) {
    if (*p == mds->get_nodeid())  continue;  // nothing to myself!
    if (rejoin_sent.count(*p)) continue;     // already sent a rejoin to this node!
    if (mds->is_rejoin())
      rejoins[*p] = new MMDSCacheRejoin(MMDSCacheRejoin::OP_WEAK);
    else if (mds->mdsmap->is_rejoin(*p))
      rejoins[*p] = new MMDSCacheRejoin(MMDSCacheRejoin::OP_STRONG);
  }

  if (mds->is_rejoin()) {
    for (map<inodeno_t,map<client_t,ceph_mds_cap_reconnect> >::iterator p = cap_exports.begin();
         p != cap_exports.end();
	 ++p) {
      assert(cap_export_targets.count(p->first));
      rejoins[cap_export_targets[p->first]]->cap_exports[p->first] = p->second;
    }
  }
  
  assert(!migrator->is_importing());
  assert(!migrator->is_exporting());
  
  // check all subtrees
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    CDir *dir = p->first;
    assert(dir->is_subtree_root());
    if (dir->is_ambiguous_dir_auth()) {
      // exporter is recovering, importer is survivor.
      assert(rejoins.count(dir->authority().first));
      assert(!rejoins.count(dir->authority().second));
      continue;
    }

    // my subtree?
    if (dir->is_auth())
      continue;  // skip my own regions!

    int auth = dir->get_dir_auth().first;
    assert(auth >= 0);
    if (rejoins.count(auth) == 0)
      continue;   // don't care about this node's subtrees

    rejoin_walk(dir, rejoins[auth]);
  }
  
  // rejoin root inodes, too
  for (map<int, MMDSCacheRejoin*>::iterator p = rejoins.begin();
       p != rejoins.end();
       ++p) {
    if (mds->is_rejoin()) {
      // weak
      if (p->first == 0 && root) {
	p->second->add_weak_inode(root->vino());
	if (root->is_dirty_scattered()) {
	  dout(10) << " sending scatterlock state on root " << *root << dendl;
	  p->second->add_scatterlock_state(root);
	}
      }
      if (CInode *in = get_inode(MDS_INO_MDSDIR(p->first))) { 
	if (in)
	  p->second->add_weak_inode(in->vino());
      }
    } else {
      // strong
      if (p->first == 0 && root) {
	p->second->add_strong_inode(root->vino(),
				    root->get_replica_nonce(),
				    root->get_caps_wanted(),
				    root->filelock.get_state(),
				    root->nestlock.get_state(),
				    root->dirfragtreelock.get_state());
	root->state_set(CInode::STATE_REJOINING);
	if (root->is_dirty_scattered()) {
	  dout(10) << " sending scatterlock state on root " << *root << dendl;
	  p->second->add_scatterlock_state(root);
	}
      }

      if (CInode *in = get_inode(MDS_INO_MDSDIR(p->first))) {
	p->second->add_strong_inode(in->vino(),
				    in->get_replica_nonce(),
				    in->get_caps_wanted(),
				    in->filelock.get_state(),
				    in->nestlock.get_state(),
				    in->dirfragtreelock.get_state());
	in->state_set(CInode::STATE_REJOINING);
      }
    }
  }  

  if (!mds->is_rejoin()) {
    // i am survivor.  send strong rejoin.
    // note request remote_auth_pins, xlocks
    for (hash_map<metareqid_t, MDRequest*>::iterator p = active_requests.begin();
	 p != active_requests.end();
	 ++p) {
      if ( p->second->is_slave())
	continue;
      // auth pins
      for (set<MDSCacheObject*>::iterator q = p->second->remote_auth_pins.begin();
	   q != p->second->remote_auth_pins.end();
	   ++q) {
	if (!(*q)->is_auth()) {
	  int who = (*q)->authority().first;
	  if (rejoins.count(who) == 0) continue;
	  MMDSCacheRejoin *rejoin = rejoins[who];
	  
	  dout(15) << " " << *p->second << " authpin on " << **q << dendl;
	  MDSCacheObjectInfo i;
	  (*q)->set_object_info(i);
	  if (i.ino)
	    rejoin->add_inode_authpin(vinodeno_t(i.ino, i.snapid), p->second->reqid, p->second->attempt);
	  else
	    rejoin->add_dentry_authpin(i.dirfrag, i.dname, i.snapid, p->second->reqid, p->second->attempt);

	  if (p->second->has_more() && p->second->more()->is_remote_frozen_authpin &&
	      p->second->more()->rename_inode == (*q))
	    rejoin->add_inode_frozen_authpin(vinodeno_t(i.ino, i.snapid),
					     p->second->reqid, p->second->attempt);
	}
      }
      // xlocks
      for (set<SimpleLock*>::iterator q = p->second->xlocks.begin();
	   q != p->second->xlocks.end();
	   ++q) {
	if (!(*q)->get_parent()->is_auth()) {
	  int who = (*q)->get_parent()->authority().first;
	  if (rejoins.count(who) == 0) continue;
	  MMDSCacheRejoin *rejoin = rejoins[who];
	  
	  dout(15) << " " << *p->second << " xlock on " << **q << " " << *(*q)->get_parent() << dendl;
	  MDSCacheObjectInfo i;
	  (*q)->get_parent()->set_object_info(i);
	  if (i.ino)
	    rejoin->add_inode_xlock(vinodeno_t(i.ino, i.snapid), (*q)->get_type(),
				    p->second->reqid, p->second->attempt);
	  else
	    rejoin->add_dentry_xlock(i.dirfrag, i.dname, i.snapid,
				     p->second->reqid, p->second->attempt);
	}
      }
      // remote wrlocks
      for (map<SimpleLock*, int>::iterator q = p->second->remote_wrlocks.begin();
	   q != p->second->remote_wrlocks.end();
	   ++q) {
	int who = q->second;
	if (rejoins.count(who) == 0) continue;
	MMDSCacheRejoin *rejoin = rejoins[who];

	dout(15) << " " << *p->second << " wrlock on " << q->second
		 << " " << q->first->get_parent() << dendl;
	MDSCacheObjectInfo i;
	q->first->get_parent()->set_object_info(i);
	assert(i.ino);
	rejoin->add_inode_wrlock(vinodeno_t(i.ino, i.snapid), q->first->get_type(),
				 p->second->reqid, p->second->attempt);
      }
    }
  }

  // send the messages
  for (map<int,MMDSCacheRejoin*>::iterator p = rejoins.begin();
       p != rejoins.end();
       ++p) {
    assert(rejoin_sent.count(p->first) == 0);
    assert(rejoin_ack_gather.count(p->first) == 0);
    rejoin_sent.insert(p->first);
    rejoin_ack_gather.insert(p->first);
    mds->send_message_mds(p->second, p->first);
  }
  rejoin_ack_gather.insert(mds->whoami);   // we need to complete rejoin_gather_finish, too
  rejoins_pending = false;

  // nothing?
  if (mds->is_rejoin() && rejoins.empty()) {
    dout(10) << "nothing to rejoin" << dendl;
    rejoin_gather_finish();
  }
}


/** 
 * rejoin_walk - build rejoin declarations for a subtree
 * 
 * @param dir subtree root
 * @param rejoin rejoin message
 *
 * from a rejoining node:
 *  weak dirfrag
 *  weak dentries (w/ connectivity)
 *
 * from a surviving node:
 *  strong dirfrag
 *  strong dentries (no connectivity!)
 *  strong inodes
 */
void MDCache::rejoin_walk(CDir *dir, MMDSCacheRejoin *rejoin)
{
  dout(10) << "rejoin_walk " << *dir << dendl;

  list<CDir*> nested;  // finish this dir, then do nested items
  
  if (mds->is_rejoin()) {
    // WEAK
    rejoin->add_weak_dirfrag(dir->dirfrag());
    for (CDir::map_t::iterator p = dir->items.begin();
	 p != dir->items.end();
	 ++p) {
      CDentry *dn = p->second;
      CDentry::linkage_t *dnl = dn->get_linkage();
      dout(15) << " add_weak_primary_dentry " << *dn << dendl;
      assert(dnl->is_primary());
      CInode *in = dnl->get_inode();
      assert(dnl->get_inode()->is_dir());
      rejoin->add_weak_primary_dentry(dir->ino(), dn->name.c_str(), dn->first, dn->last, in->ino());
      in->get_nested_dirfrags(nested);
      if (in->is_dirty_scattered()) {
	dout(10) << " sending scatterlock state on " << *in << dendl;
	rejoin->add_scatterlock_state(in);
      }
    }
  } else {
    // STRONG
    dout(15) << " add_strong_dirfrag " << *dir << dendl;
    rejoin->add_strong_dirfrag(dir->dirfrag(), dir->get_replica_nonce(), dir->get_dir_rep());
    dir->state_set(CDir::STATE_REJOINING);
    dir->mseq = 0;

    for (CDir::map_t::iterator p = dir->items.begin();
	 p != dir->items.end();
	 ++p) {
      CDentry *dn = p->second;
      CDentry::linkage_t *dnl = dn->get_linkage();
      dout(15) << " add_strong_dentry " << *dn << dendl;
      rejoin->add_strong_dentry(dir->dirfrag(), dn->name, dn->first, dn->last,
				dnl->is_primary() ? dnl->get_inode()->ino():inodeno_t(0),
				dnl->is_remote() ? dnl->get_remote_ino():inodeno_t(0),
				dnl->is_remote() ? dnl->get_remote_d_type():0, 
				dn->get_replica_nonce(),
				dn->lock.get_state());
      dn->state_set(CDentry::STATE_REJOINING);
      if (dnl->is_primary()) {
	CInode *in = dnl->get_inode();
	dout(15) << " add_strong_inode " << *in << dendl;
	rejoin->add_strong_inode(in->vino(),
				 in->get_replica_nonce(),
				 in->get_caps_wanted(),
				 in->filelock.get_state(),
				 in->nestlock.get_state(),
				 in->dirfragtreelock.get_state());
	in->state_set(CInode::STATE_REJOINING);
	in->get_nested_dirfrags(nested);
	if (in->is_dirty_scattered()) {
	  dout(10) << " sending scatterlock state on " << *in << dendl;
	  rejoin->add_scatterlock_state(in);
	}
      }
    }
  }

  // recurse into nested dirs
  for (list<CDir*>::iterator p = nested.begin(); 
       p != nested.end();
       ++p)
    rejoin_walk(*p, rejoin);
}


/*
 * i got a rejoin.
 *  - reply with the lockstate
 *
 * if i am active|stopping, 
 *  - remove source from replica list for everything not referenced here.
 * This function puts the passed message before returning.
 */
void MDCache::handle_cache_rejoin(MMDSCacheRejoin *m)
{
  dout(7) << "handle_cache_rejoin " << *m << " from " << m->get_source() 
	  << " (" << m->get_payload().length() << " bytes)"
	  << dendl;

  switch (m->op) {
  case MMDSCacheRejoin::OP_WEAK:
    handle_cache_rejoin_weak(m);
    break;
  case MMDSCacheRejoin::OP_STRONG:
    handle_cache_rejoin_strong(m);
    break;

  case MMDSCacheRejoin::OP_ACK:
    handle_cache_rejoin_ack(m);
    break;
  case MMDSCacheRejoin::OP_MISSING:
    handle_cache_rejoin_missing(m);
    break;

  case MMDSCacheRejoin::OP_FULL:
    handle_cache_rejoin_full(m);
    break;

  default: 
    assert(0);
  }
  m->put();
}


/*
 * handle_cache_rejoin_weak
 *
 * the sender 
 *  - is recovering from their journal.
 *  - may have incorrect (out of date) inode contents
 *  - will include weak dirfrag if sender is dirfrag auth and parent inode auth is recipient
 *
 * if the sender didn't trim_non_auth(), they
 *  - may have incorrect (out of date) dentry/inode linkage
 *  - may have deleted/purged inodes
 * and i may have to go to disk to get accurate inode contents.  yuck.
 * This functions DOES NOT put the passed message before returning
 */
void MDCache::handle_cache_rejoin_weak(MMDSCacheRejoin *weak)
{
  int from = weak->get_source().num();

  // possible response(s)
  MMDSCacheRejoin *ack = 0;      // if survivor
  set<vinodeno_t> acked_inodes;  // if survivor
  set<SimpleLock *> gather_locks;  // if survivor
  bool survivor = false;  // am i a survivor?

  if (mds->is_clientreplay() || mds->is_active() || mds->is_stopping()) {
    survivor = true;
    dout(10) << "i am a surivivor, and will ack immediately" << dendl;
    ack = new MMDSCacheRejoin(MMDSCacheRejoin::OP_ACK);

    // check cap exports
    for (map<inodeno_t,map<client_t,ceph_mds_cap_reconnect> >::iterator p = weak->cap_exports.begin();
	 p != weak->cap_exports.end();
	 ++p) {
      CInode *in = get_inode(p->first);
      assert(!in || in->is_auth());
      for (map<client_t,ceph_mds_cap_reconnect>::iterator q = p->second.begin();
	   q != p->second.end();
	   ++q) {
	dout(10) << " claiming cap import " << p->first << " client." << q->first << " on " << *in << dendl;
	rejoin_import_cap(in, q->first, q->second, from);
      }
      mds->locker->eval(in, CEPH_CAP_LOCKS, true);
    }
  } else {
    assert(mds->is_rejoin());

    // check cap exports.
    for (map<inodeno_t,map<client_t,ceph_mds_cap_reconnect> >::iterator p = weak->cap_exports.begin();
	 p != weak->cap_exports.end();
	 ++p) {
      CInode *in = get_inode(p->first);
      assert(in && in->is_auth());
      // note
      for (map<client_t,ceph_mds_cap_reconnect>::iterator q = p->second.begin();
	   q != p->second.end();
	   ++q) {
	dout(10) << " claiming cap import " << p->first << " client." << q->first << dendl;
	cap_imports[p->first][q->first][from] = q->second;
      }
    }
  }

  // assimilate any potentially dirty scatterlock state
  for (map<inodeno_t,MMDSCacheRejoin::lock_bls>::iterator p = weak->inode_scatterlocks.begin();
       p != weak->inode_scatterlocks.end();
       ++p) {
    CInode *in = get_inode(p->first);
    assert(in);
    if (survivor) {
      in->start_scatter_gather(&in->filelock, from);
      in->start_scatter_gather(&in->nestlock, from);
    } else {
      rejoin_potential_updated_scatterlocks.insert(in);
    }
    in->decode_lock_state(CEPH_LOCK_IFILE, p->second.file);
    in->decode_lock_state(CEPH_LOCK_INEST, p->second.nest);
    in->decode_lock_state(CEPH_LOCK_IDFT, p->second.dft);
  }

  // recovering peer may send incorrect dirfrags here.  we need to
  // infer which dirfrag they meant.  the ack will include a
  // strong_dirfrag that will set them straight on the fragmentation.
  
  // walk weak map
  set<CDir*> dirs_to_share;
  for (set<dirfrag_t>::iterator p = weak->weak_dirfrags.begin();
       p != weak->weak_dirfrags.end();
       ++p) {
    CInode *diri = get_inode(p->ino);
    if (!diri)
      dout(0) << " missing dir ino " << p->ino << dendl;
    assert(diri);
    
    frag_t fg = diri->dirfragtree[p->frag.value()];
    CDir *dir = diri->get_dirfrag(fg);
    if (!dir)
      dout(0) << " missing dir for " << p->frag << " (which maps to " << fg << ") on " << *diri << dendl;
    assert(dir);
    if (dirs_to_share.count(dir)) {
      dout(10) << " already have " << p->frag << " -> " << fg << " " << *dir << dendl;
    } else {
      dirs_to_share.insert(dir);
      int nonce = dir->add_replica(from);
      dout(10) << " have " << p->frag << " -> " << fg << " " << *dir << dendl;
      if (ack)
	ack->add_strong_dirfrag(dir->dirfrag(), nonce, dir->dir_rep);
    }
  }

  for (map<inodeno_t,map<string_snap_t,MMDSCacheRejoin::dn_weak> >::iterator p = weak->weak.begin();
       p != weak->weak.end();
       ++p) {
    CInode *diri = get_inode(p->first);
    if (!diri)
      dout(0) << " missing dir ino " << p->first << dendl;
    assert(diri);

    // weak dentries
    CDir *dir = 0;
    for (map<string_snap_t,MMDSCacheRejoin::dn_weak>::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      // locate proper dirfrag.
      //  optimize for common case (one dirfrag) to avoid dirs_to_share set check
      frag_t fg = diri->pick_dirfrag(q->first.name);
      if (!dir || dir->get_frag() != fg) {
	dir = diri->get_dirfrag(fg);
	if (!dir)
	  dout(0) << " missing dir frag " << fg << " on " << *diri << dendl;
	assert(dir);
	assert(dirs_to_share.count(dir));
      }

      // and dentry
      CDentry *dn = dir->lookup(q->first.name, q->first.snapid);
      assert(dn);
      CDentry::linkage_t *dnl = dn->get_linkage();
      assert(dnl->is_primary());
      
      if (survivor && dn->is_replica(from)) 
	dentry_remove_replica(dn, from, gather_locks);
      int dnonce = dn->add_replica(from);
      dout(10) << " have " << *dn << dendl;
      if (ack) 
	ack->add_strong_dentry(dir->dirfrag(), dn->name, dn->first, dn->last,
			       dnl->get_inode()->ino(), inodeno_t(0), 0, 
			       dnonce, dn->lock.get_replica_state());

      // inode
      CInode *in = dnl->get_inode();
      assert(in);

      if (survivor && in->is_replica(from)) 
	inode_remove_replica(in, from, gather_locks);
      int inonce = in->add_replica(from);
      dout(10) << " have " << *in << dendl;

      // scatter the dirlock, just in case?
      if (!survivor && in->is_dir() && in->has_subtree_root_dirfrag())
	in->filelock.set_state(LOCK_MIX);

      if (ack) {
	acked_inodes.insert(in->vino());
	ack->add_inode_base(in);
	ack->add_inode_locks(in, inonce);
      }
    }
  }
  
  // weak base inodes?  (root, stray, etc.)
  for (set<vinodeno_t>::iterator p = weak->weak_inodes.begin();
       p != weak->weak_inodes.end();
       ++p) {
    CInode *in = get_inode(*p);
    assert(in);   // hmm fixme wrt stray?
    if (survivor && in->is_replica(from)) 
      inode_remove_replica(in, from, gather_locks);
    int inonce = in->add_replica(from);
    dout(10) << " have base " << *in << dendl;
    
    if (ack) {
      acked_inodes.insert(in->vino());
      ack->add_inode_base(in);
      ack->add_inode_locks(in, inonce);
    }
  }

  assert(rejoin_gather.count(from));
  rejoin_gather.erase(from);
  if (survivor) {
    // survivor.  do everything now.
    for (map<inodeno_t,MMDSCacheRejoin::lock_bls>::iterator p = weak->inode_scatterlocks.begin();
	 p != weak->inode_scatterlocks.end();
	 ++p) {
      CInode *in = get_inode(p->first);
      assert(in);
      dout(10) << " including base inode (due to potential scatterlock update) " << *in << dendl;
      acked_inodes.insert(in->vino());
      ack->add_inode_base(in);
    }

    rejoin_scour_survivor_replicas(from, ack, gather_locks, acked_inodes);
    mds->send_message(ack, weak->get_connection());

    for (set<SimpleLock*>::iterator p = gather_locks.begin(); p != gather_locks.end(); ++p)
      mds->locker->eval_gather(*p);
  } else {
    // done?
    if (rejoin_gather.empty()) {
      rejoin_gather_finish();
    } else {
      dout(7) << "still need rejoin from (" << rejoin_gather << ")" << dendl;
    }
  }
}

class C_MDC_RejoinGatherFinish : public Context {
  MDCache *cache;
public:
  C_MDC_RejoinGatherFinish(MDCache *c) : cache(c) {}
  void finish(int r) {
    cache->rejoin_gather_finish();
  }
};

#if 0
/**
 * parallel_fetch -- make a pass at fetching a bunch of paths in parallel
 *
 * @param pathmap map of inodeno to full pathnames.  we remove items
 *            from this map as we discover we have them.
 *
 *	      returns true if there is work to do, false otherwise.
 */

bool MDCache::parallel_fetch(map<inodeno_t,filepath>& pathmap, set<inodeno_t>& missing)
{
  dout(10) << "parallel_fetch on " << pathmap.size() << " paths" << dendl;

  C_GatherBuilder gather_bld(g_ceph_context, new C_MDC_RejoinGatherFinish(this));

  // scan list
  set<CDir*> fetch_queue;
  map<inodeno_t,filepath>::iterator p = pathmap.begin();
  while (p != pathmap.end()) {
    // do we have the target already?
    CInode *cur = get_inode(p->first);
    if (cur) {
      dout(15) << " have " << *cur << dendl;
      pathmap.erase(p++);
      continue;
    }

    // traverse
    dout(17) << " missing " << p->first << " at " << p->second << dendl;
    if (parallel_fetch_traverse_dir(p->first, p->second, fetch_queue,
				    missing, gather_bld))
      pathmap.erase(p++);
    else
      ++p;
  }

  if (pathmap.empty() && (!gather_bld.has_subs())) {
    dout(10) << "parallel_fetch done" << dendl;
    assert(fetch_queue.empty());
    return false;
  }

  // do a parallel fetch
  for (set<CDir*>::iterator p = fetch_queue.begin();
       p != fetch_queue.end();
       ++p) {
    dout(10) << "parallel_fetch fetching " << **p << dendl;
    (*p)->fetch(gather_bld.new_sub());
  }
  
  if (gather_bld.get()) {
    gather_bld.activate();
    return true;
  }
  return false;
}

// true if we're done with this path
bool MDCache::parallel_fetch_traverse_dir(inodeno_t ino, filepath& path,
					  set<CDir*>& fetch_queue, set<inodeno_t>& missing,
					  C_GatherBuilder &gather_bld)
{
  CInode *cur = get_inode(path.get_ino());
  if (!cur) {
    dout(5) << " missing " << path << " base ino " << path.get_ino() << dendl;
    missing.insert(ino);
    return true;
  }

  for (unsigned i=0; i<path.depth(); i++) {
    dout(20) << " path " << path << " seg " << i << "/" << path.depth() << ": " << path[i]
	     << " under " << *cur << dendl;
    if (!cur->is_dir()) {
      dout(5) << " bad path " << path << " ENOTDIR at " << path[i] << dendl;
      missing.insert(ino);
      return true;
    }
      
    frag_t fg = cur->pick_dirfrag(path[i]);
    CDir *dir = cur->get_or_open_dirfrag(this, fg);
    CDentry *dn = dir->lookup(path[i]);
    CDentry::linkage_t *dnl = dn ? dn->get_linkage() : NULL;

    if (!dnl || dnl->is_null()) {
      if (!dir->is_auth()) {
	dout(10) << " not dirfrag auth " << *dir << dendl;
	return true;
      }
      if (dnl || dir->is_complete()) {
	// probably because the client created it and held a cap but it never committed
	// to the journal, and the op hasn't replayed yet.
	dout(5) << " dne (not created yet?) " << ino << " at " << path << dendl;
	missing.insert(ino);
	return true;
      }
      // fetch dir
      fetch_queue.insert(dir);
      return false;
    }

    cur = dnl->get_inode();
    if (!cur) {
      assert(dnl->is_remote());
      cur = get_inode(dnl->get_remote_ino());
      if (cur) {
	dn->link_remote(dnl, cur);
      } else {
	// open remote ino
	open_remote_ino(dnl->get_remote_ino(), gather_bld.new_sub());
	return false;
      }
    }
  }

  dout(5) << " ino not found " << ino << " at " << path << dendl;
  missing.insert(ino);
  return true;
}
#endif

/*
 * rejoin_scour_survivor_replica - remove source from replica list on unmentioned objects
 *
 * all validated replicas are acked with a strong nonce, etc.  if that isn't in the
 * ack, the replica dne, and we can remove it from our replica maps.
 */
void MDCache::rejoin_scour_survivor_replicas(int from, MMDSCacheRejoin *ack,
					     set<SimpleLock *>& gather_locks,
					     set<vinodeno_t>& acked_inodes)
{
  dout(10) << "rejoin_scour_survivor_replicas from mds." << from << dendl;

  // FIXME: what about root and stray inodes.
  
  for (hash_map<vinodeno_t,CInode*>::iterator p = inode_map.begin();
       p != inode_map.end();
       ++p) {
    CInode *in = p->second;
    
    // inode?
    if (in->is_auth() &&
	in->is_replica(from) &&
	acked_inodes.count(p->second->vino()) == 0) {
      inode_remove_replica(in, from, gather_locks);
      dout(10) << " rem " << *in << dendl;
    }

    if (!in->is_dir()) continue;
    
    list<CDir*> dfs;
    in->get_dirfrags(dfs);
    for (list<CDir*>::iterator p = dfs.begin();
	 p != dfs.end();
	 ++p) {
      CDir *dir = *p;
      
      if (dir->is_auth() &&
	  dir->is_replica(from) &&
	  ack->strong_dirfrags.count(dir->dirfrag()) == 0) {
	dir->remove_replica(from);
	dout(10) << " rem " << *dir << dendl;
      } 
      
      // dentries
      for (CDir::map_t::iterator p = dir->items.begin();
	   p != dir->items.end();
	   ++p) {
	CDentry *dn = p->second;
	
	if (dn->is_replica(from) &&
	    (ack->strong_dentries.count(dir->dirfrag()) == 0 ||
	     ack->strong_dentries[dir->dirfrag()].count(string_snap_t(dn->name, dn->last)) == 0)) {
	  dentry_remove_replica(dn, from, gather_locks);
	  dout(10) << " rem " << *dn << dendl;
	}
      }
    }
  }
}


CInode *MDCache::rejoin_invent_inode(inodeno_t ino, snapid_t last)
{
  CInode *in = new CInode(this, true, 1, last);
  in->inode.ino = ino;
  in->state_set(CInode::STATE_REJOINUNDEF);
  add_inode(in);
  rejoin_undef_inodes.insert(in);
  dout(10) << " invented " << *in << dendl;
  return in;
}

CDir *MDCache::rejoin_invent_dirfrag(dirfrag_t df)
{
  CInode *in = get_inode(df.ino);
  if (!in)
    in = rejoin_invent_inode(df.ino, CEPH_NOSNAP);
  if (!in->is_dir()) {
    assert(in->state_test(CInode::STATE_REJOINUNDEF));
    in->inode.mode = S_IFDIR;
  }
  CDir *dir = in->get_or_open_dirfrag(this, df.frag);
  dir->state_set(CDir::STATE_REJOINUNDEF);
  rejoin_undef_dirfrags.insert(dir);
  dout(10) << " invented " << *dir << dendl;
  return dir;
}

/* This functions DOES NOT put the passed message before returning */
void MDCache::handle_cache_rejoin_strong(MMDSCacheRejoin *strong)
{
  int from = strong->get_source().num();

  // only a recovering node will get a strong rejoin.
  assert(mds->is_rejoin());

  // assimilate any potentially dirty scatterlock state
  for (map<inodeno_t,MMDSCacheRejoin::lock_bls>::iterator p = strong->inode_scatterlocks.begin();
       p != strong->inode_scatterlocks.end();
       ++p) {
    CInode *in = get_inode(p->first);
    assert(in);
    in->decode_lock_state(CEPH_LOCK_IFILE, p->second.file);
    in->decode_lock_state(CEPH_LOCK_INEST, p->second.nest);
    in->decode_lock_state(CEPH_LOCK_IDFT, p->second.dft);
    rejoin_potential_updated_scatterlocks.insert(in);
  }

  rejoin_unlinked_inodes[from].clear();

  // surviving peer may send incorrect dirfrag here (maybe they didn't
  // get the fragment notify, or maybe we rolled back?).  we need to
  // infer the right frag and get them with the program.  somehow.
  // we don't normally send ACK.. so we'll need to bundle this with
  // MISSING or something.

  // strong dirfrags/dentries.
  //  also process auth_pins, xlocks.
  for (map<dirfrag_t, MMDSCacheRejoin::dirfrag_strong>::iterator p = strong->strong_dirfrags.begin();
       p != strong->strong_dirfrags.end();
       ++p) {
    CInode *diri = get_inode(p->first.ino);
    if (!diri)
      diri = rejoin_invent_inode(p->first.ino, CEPH_NOSNAP);
    CDir *dir = diri->get_dirfrag(p->first.frag);
    bool refragged = false;
    if (dir) {
      dout(10) << " have " << *dir << dendl;
    } else {
      if (diri->state_test(CInode::STATE_REJOINUNDEF))
	dir = rejoin_invent_dirfrag(dirfrag_t(diri->ino(), frag_t()));
      else if (diri->dirfragtree.is_leaf(p->first.frag))
	dir = rejoin_invent_dirfrag(p->first);
    }
    if (dir) {
      dir->add_replica(from, p->second.nonce);
      dir->dir_rep = p->second.dir_rep;
    } else {
      dout(10) << " frag " << p->first << " doesn't match dirfragtree " << *diri << dendl;
      list<frag_t> ls;
      diri->dirfragtree.get_leaves_under(p->first.frag, ls);
      if (ls.empty())
	ls.push_back(diri->dirfragtree[p->first.frag.value()]);
      dout(10) << " maps to frag(s) " << ls << dendl;
      for (list<frag_t>::iterator q = ls.begin(); q != ls.end(); ++q) {
	CDir *dir = diri->get_dirfrag(*q);
	if (!dir)
	  dir = rejoin_invent_dirfrag(p->first);
	else
	  dout(10) << " have(approx) " << *dir << dendl;
	dir->add_replica(from, p->second.nonce);
	dir->dir_rep = p->second.dir_rep;
      }
      refragged = true;
    }
    
    map<string_snap_t,MMDSCacheRejoin::dn_strong>& dmap = strong->strong_dentries[p->first];
    for (map<string_snap_t,MMDSCacheRejoin::dn_strong>::iterator q = dmap.begin();
	 q != dmap.end();
	 ++q) {
      CDentry *dn;
      if (!refragged)
	dn = dir->lookup(q->first.name, q->first.snapid);
      else {
	frag_t fg = diri->pick_dirfrag(q->first.name);
	dir = diri->get_dirfrag(fg);
	assert(dir);
	dn = dir->lookup(q->first.name, q->first.snapid);
      }
      if (!dn) {
	if (q->second.is_remote()) {
	  dn = dir->add_remote_dentry(q->first.name, q->second.remote_ino, q->second.remote_d_type,
				      q->second.first, q->first.snapid);
	} else if (q->second.is_null()) {
	  dn = dir->add_null_dentry(q->first.name, q->second.first, q->first.snapid);
	} else {
	  CInode *in = get_inode(q->second.ino, q->first.snapid);
	  if (!in) in = rejoin_invent_inode(q->second.ino, q->first.snapid);
	  dn = dir->add_primary_dentry(q->first.name, in, q->second.first, q->first.snapid);
	}
	dout(10) << " invented " << *dn << dendl;
      }
      CDentry::linkage_t *dnl = dn->get_linkage();

      // dn auth_pin?
      if (strong->authpinned_dentries.count(p->first) &&
	  strong->authpinned_dentries[p->first].count(q->first)) {
	for (list<MMDSCacheRejoin::slave_reqid>::iterator r = strong->authpinned_dentries[p->first][q->first].begin();
	     r != strong->authpinned_dentries[p->first][q->first].end();
	     ++r) {
	  dout(10) << " dn authpin by " << *r << " on " << *dn << dendl;

	  // get/create slave mdrequest
	  MDRequest *mdr;
	  if (have_request(r->reqid))
	    mdr = request_get(r->reqid);
	  else
	    mdr = request_start_slave(r->reqid, r->attempt, from);
	  mdr->auth_pin(dn);
	}
      }

      // dn xlock?
      if (strong->xlocked_dentries.count(p->first) &&
	  strong->xlocked_dentries[p->first].count(q->first)) {
	MMDSCacheRejoin::slave_reqid r = strong->xlocked_dentries[p->first][q->first];
	dout(10) << " dn xlock by " << r << " on " << *dn << dendl;
	MDRequest *mdr = request_get(r.reqid);  // should have this from auth_pin above.
	assert(mdr->is_auth_pinned(dn));
	if (!mdr->xlocks.count(&dn->versionlock)) {
	  assert(dn->versionlock.can_xlock_local());
	  dn->versionlock.get_xlock(mdr, mdr->get_client());
	  mdr->xlocks.insert(&dn->versionlock);
	  mdr->locks.insert(&dn->versionlock);
	}
	if (dn->lock.is_stable())
	  dn->auth_pin(&dn->lock);
	dn->lock.set_state(LOCK_XLOCK);
	dn->lock.get_xlock(mdr, mdr->get_client());
	mdr->xlocks.insert(&dn->lock);
	mdr->locks.insert(&dn->lock);
      }

      dn->add_replica(from, q->second.nonce);
      dout(10) << " have " << *dn << dendl;

      if (dnl->is_primary()) {
	if (q->second.is_primary()) {
	  if (vinodeno_t(q->second.ino, q->first.snapid) != dnl->get_inode()->vino()) {
	    // the survivor missed MDentryUnlink+MDentryLink messages ?
	    assert(strong->strong_inodes.count(dnl->get_inode()->vino()) == 0);
	    CInode *in = get_inode(q->second.ino, q->first.snapid);
	    assert(in);
	    assert(in->get_parent_dn());
	    rejoin_unlinked_inodes[from].insert(in);
	    dout(7) << " sender has primary dentry but wrong inode" << dendl;
	  }
	} else {
	  // the survivor missed MDentryLink message ?
	  assert(strong->strong_inodes.count(dnl->get_inode()->vino()) == 0);
	  dout(7) << " sender doesn't have primay dentry" << dendl;
	}
      } else {
	if (q->second.is_primary()) {
	  // the survivor missed MDentryUnlink message ?
	  CInode *in = get_inode(q->second.ino, q->first.snapid);
	  assert(in);
	  assert(in->get_parent_dn());
	  rejoin_unlinked_inodes[from].insert(in);
	  dout(7) << " sender has primary dentry but we don't" << dendl;
	}
      }
    }
  }

  for (map<vinodeno_t, MMDSCacheRejoin::inode_strong>::iterator p = strong->strong_inodes.begin();
       p != strong->strong_inodes.end();
       ++p) {
    CInode *in = get_inode(p->first);
    assert(in);
    in->add_replica(from, p->second.nonce);
    dout(10) << " have " << *in << dendl;

    MMDSCacheRejoin::inode_strong &is = p->second;

    // caps_wanted
    if (is.caps_wanted) {
      in->mds_caps_wanted[from] = is.caps_wanted;
      dout(15) << " inode caps_wanted " << ccap_string(is.caps_wanted)
	       << " on " << *in << dendl;
    }

    // scatterlocks?
    //  infer state from replica state:
    //   * go to MIX if they might have wrlocks
    //   * go to LOCK if they are LOCK (just bc identify_files_to_recover might start twiddling filelock)
    in->filelock.infer_state_from_strong_rejoin(is.filelock, true);  // maybe also go to LOCK
    in->nestlock.infer_state_from_strong_rejoin(is.nestlock, false);
    in->dirfragtreelock.infer_state_from_strong_rejoin(is.dftlock, false);

    // auth pin?
    if (strong->authpinned_inodes.count(in->vino())) {
      for (list<MMDSCacheRejoin::slave_reqid>::iterator r = strong->authpinned_inodes[in->vino()].begin();
	   r != strong->authpinned_inodes[in->vino()].end();
	   ++r) {
	dout(10) << " inode authpin by " << *r << " on " << *in << dendl;

	// get/create slave mdrequest
	MDRequest *mdr;
	if (have_request(r->reqid))
	  mdr = request_get(r->reqid);
	else
	  mdr = request_start_slave(r->reqid, r->attempt, from);
	if (strong->frozen_authpin_inodes.count(in->vino())) {
	  assert(!in->get_num_auth_pins());
	  mdr->freeze_auth_pin(in);
	} else {
	  assert(!in->is_frozen_auth_pin());
	}
	mdr->auth_pin(in);
      }
    }
    // xlock(s)?
    if (strong->xlocked_inodes.count(in->vino())) {
      for (map<int,MMDSCacheRejoin::slave_reqid>::iterator q = strong->xlocked_inodes[in->vino()].begin();
	   q != strong->xlocked_inodes[in->vino()].end();
	   ++q) {
	SimpleLock *lock = in->get_lock(q->first);
	dout(10) << " inode xlock by " << q->second << " on " << *lock << " on " << *in << dendl;
	MDRequest *mdr = request_get(q->second.reqid);  // should have this from auth_pin above.
	assert(mdr->is_auth_pinned(in));
	if (!mdr->xlocks.count(&in->versionlock)) {
	  assert(in->versionlock.can_xlock_local());
	  in->versionlock.get_xlock(mdr, mdr->get_client());
	  mdr->xlocks.insert(&in->versionlock);
	  mdr->locks.insert(&in->versionlock);
	}
	if (lock->is_stable())
	  in->auth_pin(lock);
	lock->set_state(LOCK_XLOCK);
	if (lock == &in->filelock)
	  in->loner_cap = -1;
	lock->get_xlock(mdr, mdr->get_client());
	mdr->xlocks.insert(lock);
	mdr->locks.insert(lock);
      }
    }
  }
  // wrlock(s)?
  for (map<vinodeno_t, map<int, list<MMDSCacheRejoin::slave_reqid> > >::iterator p = strong->wrlocked_inodes.begin();
       p != strong->wrlocked_inodes.end();
       ++p) {
    CInode *in = get_inode(p->first);
    for (map<int, list<MMDSCacheRejoin::slave_reqid> >::iterator q = p->second.begin();
	 q != p->second.end();
	++q) {
      SimpleLock *lock = in->get_lock(q->first);
      for (list<MMDSCacheRejoin::slave_reqid>::iterator r = q->second.begin();
	  r != q->second.end();
	  ++r) {
	dout(10) << " inode wrlock by " << *r << " on " << *lock << " on " << *in << dendl;
	MDRequest *mdr = request_get(r->reqid);  // should have this from auth_pin above.
	if (in->is_auth())
	  assert(mdr->is_auth_pinned(in));
	lock->set_state(LOCK_MIX);
	if (lock == &in->filelock)
	  in->loner_cap = -1;
	lock->get_wrlock(true);
	mdr->wrlocks.insert(lock);
	mdr->locks.insert(lock);
      }
    }
  }

  // done?
  assert(rejoin_gather.count(from));
  rejoin_gather.erase(from);
  if (rejoin_gather.empty()) {
    rejoin_gather_finish();
  } else {
    dout(7) << "still need rejoin from (" << rejoin_gather << ")" << dendl;
  }
}

/* This functions DOES NOT put the passed message before returning */
void MDCache::handle_cache_rejoin_ack(MMDSCacheRejoin *ack)
{
  dout(7) << "handle_cache_rejoin_ack from " << ack->get_source() << dendl;
  int from = ack->get_source().num();

  // for sending cache expire message
  set<CInode*> isolated_inodes;

  // dirs
  for (map<dirfrag_t, MMDSCacheRejoin::dirfrag_strong>::iterator p = ack->strong_dirfrags.begin();
       p != ack->strong_dirfrags.end();
       ++p) {
    // we may have had incorrect dir fragmentation; refragment based
    // on what they auth tells us.
    CDir *dir = get_force_dirfrag(p->first);
    if (!dir) {
      CInode *diri = get_inode(p->first.ino);
      if (!diri) {
	// barebones inode; the full inode loop below will clean up.
	diri = new CInode(this, false);
	diri->inode.ino = p->first.ino;
	diri->inode.mode = S_IFDIR;
	add_inode(diri);
	if (MDS_INO_MDSDIR(from) == p->first.ino) {
	  diri->inode_auth = pair<int,int>(from, CDIR_AUTH_UNKNOWN);
	  dout(10) << " add inode " << *diri << dendl;
	} else {
	  diri->inode_auth = CDIR_AUTH_DEFAULT;
	  isolated_inodes.insert(diri);
	  dout(10) << " unconnected dirfrag " << p->first << dendl;
	}
      }
      // barebones dirfrag; the full dirfrag loop below will clean up.
      dir = diri->add_dirfrag(new CDir(diri, p->first.frag, this, false));
      if (dir->authority() != CDIR_AUTH_UNDEF &&
	  dir->authority().first != from)
	adjust_subtree_auth(dir, from);
      dout(10) << " add dirfrag " << *dir << dendl;
    }

    dir->set_replica_nonce(p->second.nonce);
    dir->state_clear(CDir::STATE_REJOINING);
    dout(10) << " got " << *dir << dendl;

    // dentries
    map<string_snap_t,MMDSCacheRejoin::dn_strong>& dmap = ack->strong_dentries[p->first];
    for (map<string_snap_t,MMDSCacheRejoin::dn_strong>::iterator q = dmap.begin();
	 q != dmap.end();
	 ++q) {
      CDentry *dn = dir->lookup(q->first.name, q->first.snapid);
      if(!dn)
	dn = dir->add_null_dentry(q->first.name, q->second.first, q->first.snapid);

      CDentry::linkage_t *dnl = dn->get_linkage();

      assert(dn->last == q->first.snapid);
      if (dn->first != q->second.first) {
	dout(10) << " adjust dn.first " << dn->first << " -> " << q->second.first << " on " << *dn << dendl;
	dn->first = q->second.first;
      }

      // may have bad linkage if we missed dentry link/unlink messages
      if (dnl->is_primary()) {
	CInode *in = dnl->get_inode();
	if (!q->second.is_primary() ||
	    vinodeno_t(q->second.ino, q->first.snapid) != in->vino()) {
	  dout(10) << " had bad linkage for " << *dn << ", unlinking " << *in << dendl;
	  dir->unlink_inode(dn);
	}
      } else if (dnl->is_remote()) {
	if (!q->second.is_remote() ||
	    q->second.remote_ino != dnl->get_remote_ino() ||
	    q->second.remote_d_type != dnl->get_remote_d_type()) {
	  dout(10) << " had bad linkage for " << *dn <<  dendl;
	  dir->unlink_inode(dn);
	}
      } else {
	if (!q->second.is_null())
	  dout(10) << " had bad linkage for " << *dn <<  dendl;
      }

      // hmm, did we have the proper linkage here?
      if (dnl->is_null() && !q->second.is_null()) {
	if (q->second.is_remote()) {
	  dn->dir->link_remote_inode(dn, q->second.remote_ino, q->second.remote_d_type);
	} else {
	  CInode *in = get_inode(q->second.ino, q->first.snapid);
	  if (!in) {
	    // barebones inode; assume it's dir, the full inode loop below will clean up.
	    in = new CInode(this, false, q->second.first, q->first.snapid);
	    in->inode.ino = q->second.ino;
	    in->inode.mode = S_IFDIR;
	    add_inode(in);
	    dout(10) << " add inode " << *in << dendl;
	  } else if (in->get_parent_dn()) {
	    dout(10) << " had bad linkage for " << *(in->get_parent_dn())
		     << ", unlinking " << *in << dendl;
	    in->get_parent_dir()->unlink_inode(in->get_parent_dn());
	  }
	  dn->dir->link_primary_inode(dn, in);
	  isolated_inodes.erase(in);
	}
      }

      dn->set_replica_nonce(q->second.nonce);
      dn->lock.set_state_rejoin(q->second.lock, rejoin_waiters);
      dn->state_clear(CDentry::STATE_REJOINING);
      dout(10) << " got " << *dn << dendl;
    }
  }

  // full dirfrags
  for (map<dirfrag_t, bufferlist>::iterator p = ack->dirfrag_bases.begin();
       p != ack->dirfrag_bases.end();
       ++p) {
    CDir *dir = get_dirfrag(p->first);
    assert(dir);
    bufferlist::iterator q = p->second.begin();
    dir->_decode_base(q);
    dout(10) << " got dir replica " << *dir << dendl;
  }

  // full inodes
  bufferlist::iterator p = ack->inode_base.begin();
  while (!p.end()) {
    inodeno_t ino;
    snapid_t last;
    bufferlist basebl;
    ::decode(ino, p);
    ::decode(last, p);
    ::decode(basebl, p);
    CInode *in = get_inode(ino, last);
    assert(in);
    bufferlist::iterator q = basebl.begin();
    in->_decode_base(q);
    // auth will send a full inode for any inode it got scatterlock state for.
    in->clear_scatter_dirty();
    dout(10) << " got inode base " << *in << dendl;
  }

  // inodes
  p = ack->inode_locks.begin();
  //dout(10) << "inode_locks len " << ack->inode_locks.length() << " is " << ack->inode_locks << dendl;
  while (!p.end()) {
    inodeno_t ino;
    snapid_t last;
    __u32 nonce;
    bufferlist lockbl;
    ::decode(ino, p);
    ::decode(last, p);
    ::decode(nonce, p);
    ::decode(lockbl, p);
    
    CInode *in = get_inode(ino, last);
    assert(in);
    in->set_replica_nonce(nonce);
    bufferlist::iterator q = lockbl.begin();
    in->_decode_locks_rejoin(q, rejoin_waiters);
    in->state_clear(CInode::STATE_REJOINING);
    dout(10) << " got inode locks " << *in << dendl;
  }

  // FIXME: This can happen if entire subtree, together with the inode subtree root
  // belongs to, were trimmed between sending cache rejoin and receiving rejoin ack.
  assert(isolated_inodes.empty());

  // done?
  assert(rejoin_ack_gather.count(from));
  rejoin_ack_gather.erase(from);
  if (mds->is_rejoin()) {
    if (rejoin_gather.empty() &&     // make sure we've gotten our FULL inodes, too.
	rejoin_ack_gather.empty()) {
      // finally, kickstart past snap parent opens
      open_snap_parents();
    } else {
      dout(7) << "still need rejoin from (" << rejoin_gather << ")"
	      << ", rejoin_ack from (" << rejoin_ack_gather << ")" << dendl;
    }
  } else {
    // survivor.
    mds->queue_waiters(rejoin_waiters);
  }
}



/* This functions DOES NOT put the passed message before returning */
void MDCache::handle_cache_rejoin_missing(MMDSCacheRejoin *missing)
{
  dout(7) << "handle_cache_rejoin_missing from " << missing->get_source() << dendl;

  MMDSCacheRejoin *full = new MMDSCacheRejoin(MMDSCacheRejoin::OP_FULL);

  // dirs
  for (map<dirfrag_t, MMDSCacheRejoin::dirfrag_strong>::iterator p = missing->strong_dirfrags.begin();
       p != missing->strong_dirfrags.end();
       ++p) {
    // we may have had incorrect dir fragmentation; refragment based
    // on what they auth tells us.
    CDir *dir = get_force_dirfrag(p->first);
    assert(dir);

    dir->set_replica_nonce(p->second.nonce);
    dir->state_clear(CDir::STATE_REJOINING);
    dout(10) << " adjusted frag on " << *dir << dendl;
  }

  // inodes
  for (set<vinodeno_t>::iterator p = missing->weak_inodes.begin();
       p != missing->weak_inodes.end();
       ++p) {
    CInode *in = get_inode(*p);
    if (!in) {
      dout(10) << " don't have inode " << *p << dendl;
      continue; // we must have trimmed it after the originalo rejoin
    }
    
    dout(10) << " sending " << *in << dendl;
    full->add_inode_base(in);
  }

  mds->send_message(full, missing->get_connection());
}

/* This function DOES NOT put the passed message before returning */
void MDCache::handle_cache_rejoin_full(MMDSCacheRejoin *full)
{
  dout(7) << "handle_cache_rejoin_full from " << full->get_source() << dendl;
  int from = full->get_source().num();
  
  // integrate full inodes
  bufferlist::iterator p = full->inode_base.begin();
  while (!p.end()) {
    inodeno_t ino;
    snapid_t last;
    bufferlist basebl;
    ::decode(ino, p);
    ::decode(last, p);
    ::decode(basebl, p);

    CInode *in = get_inode(ino);
    assert(in);
    bufferlist::iterator pp = basebl.begin();
    in->_decode_base(pp);

    set<CInode*>::iterator q = rejoin_undef_inodes.find(in);
    if (q != rejoin_undef_inodes.end()) {
      CInode *in = *q;
      in->state_clear(CInode::STATE_REJOINUNDEF);
      dout(10) << " got full " << *in << dendl;
      rejoin_undef_inodes.erase(q);
    } else {
      dout(10) << " had full " << *in << dendl;
    }
  }

  // done?
  assert(rejoin_gather.count(from));
  rejoin_gather.erase(from);
  if (rejoin_gather.empty()) {
    rejoin_gather_finish();
  } else {
    dout(7) << "still need rejoin from (" << rejoin_gather << ")" << dendl;
  }
}



/**
 * rejoin_trim_undef_inodes() -- remove REJOINUNDEF flagged inodes
 *
 * FIXME: wait, can this actually happen?  a survivor should generate cache trim
 * messages that clean these guys up...
 */
void MDCache::rejoin_trim_undef_inodes()
{
  dout(10) << "rejoin_trim_undef_inodes" << dendl;

  while (!rejoin_undef_inodes.empty()) {
    set<CInode*>::iterator p = rejoin_undef_inodes.begin();
    CInode *in = *p;
    rejoin_undef_inodes.erase(p);

    in->clear_replica_map();
    
    // close out dirfrags
    if (in->is_dir()) {
      list<CDir*> dfls;
      in->get_dirfrags(dfls);
      for (list<CDir*>::iterator p = dfls.begin();
	   p != dfls.end();
	   ++p) {
	CDir *dir = *p;
	dir->clear_replica_map();

	for (CDir::map_t::iterator p = dir->items.begin();
	     p != dir->items.end();
	     ++p) {
	  CDentry *dn = p->second;
	  dn->clear_replica_map();

	  dout(10) << " trimming " << *dn << dendl;
	  dir->remove_dentry(dn);
	}

	dout(10) << " trimming " << *dir << dendl;
	in->close_dirfrag(dir->dirfrag().frag);
      }
    }
    
    CDentry *dn = in->get_parent_dn();
    if (dn) {
      dn->clear_replica_map();
      dout(10) << " trimming " << *dn << dendl;
      dn->dir->remove_dentry(dn);
    } else {
      dout(10) << " trimming " << *in << dendl;
      remove_inode(in);
    }
  }

  assert(rejoin_undef_inodes.empty());
}

void MDCache::rejoin_gather_finish() 
{
  dout(10) << "rejoin_gather_finish" << dendl;
  assert(mds->is_rejoin());

  if (open_undef_inodes_dirfrags())
    return;

  if (process_imported_caps())
    return;

  choose_lock_states_and_reconnect_caps();

  identify_files_to_recover(rejoin_recover_q, rejoin_check_q);
  rejoin_send_acks();
  
  // signal completion of fetches, rejoin_gather_finish, etc.
  assert(rejoin_ack_gather.count(mds->whoami));
  rejoin_ack_gather.erase(mds->whoami);

  // did we already get our acks too?
  // this happens when the rejoin_gather has to wait on a MISSING/FULL exchange.
  if (rejoin_ack_gather.empty()) {
    // finally, kickstart past snap parent opens
    open_snap_parents();
  }
}

class C_MDC_RejoinOpenInoFinish: public Context {
  MDCache *cache;
  inodeno_t ino;
public:
  C_MDC_RejoinOpenInoFinish(MDCache *c, inodeno_t i) : cache(c), ino(i) {}
  void finish(int r) {
    cache->rejoin_open_ino_finish(ino, r);
  }
};

void MDCache::rejoin_open_ino_finish(inodeno_t ino, int ret)
{
  dout(10) << "open_caps_inode_finish ino " << ino << " ret " << ret << dendl;

  if (ret < 0) {
    cap_imports_missing.insert(ino);
  } else if (ret == mds->get_nodeid()) {
    assert(get_inode(ino));
  } else {
    map<inodeno_t,map<client_t,map<int,ceph_mds_cap_reconnect> > >::iterator p;
    p = cap_imports.find(ino);
    assert(p != cap_imports.end());
    for (map<client_t,map<int,ceph_mds_cap_reconnect> >::iterator q = p->second.begin();
	q != p->second.end();
	++q) {
      assert(q->second.count(-1));
      assert(q->second.size() == 1);
      rejoin_export_caps(p->first, q->first, q->second[-1], ret);
    }
    cap_imports.erase(p);
  }

  assert(cap_imports_num_opening > 0);
  cap_imports_num_opening--;

  if (cap_imports_num_opening == 0) {
    if (rejoin_gather.count(mds->get_nodeid()))
      process_imported_caps();
    else
      rejoin_gather_finish();
  }
}

bool MDCache::process_imported_caps()
{
  dout(10) << "process_imported_caps" << dendl;

  map<inodeno_t,map<client_t, map<int,ceph_mds_cap_reconnect> > >::iterator p;
  for (p = cap_imports.begin(); p != cap_imports.end(); ++p) {
    CInode *in = get_inode(p->first);
    if (in) {
      assert(in->is_auth());
      cap_imports_missing.erase(p->first);
      continue;
    }
    if (cap_imports_missing.count(p->first) > 0)
      continue;

    cap_imports_num_opening++;
    dout(10) << "  opening missing ino " << p->first << dendl;
    open_ino(p->first, (int64_t)-1, new C_MDC_RejoinOpenInoFinish(this, p->first), false);
  }

  if (cap_imports_num_opening > 0)
    return true;

  // called by rejoin_gather_finish() ?
  if (rejoin_gather.count(mds->get_nodeid()) == 0) {
    // process cap imports
    //  ino -> client -> frommds -> capex
    p = cap_imports.begin();
    while (p != cap_imports.end()) {
      CInode *in = get_inode(p->first);
      if (!in) {
	dout(10) << " still missing ino " << p->first
	         << ", will try again after replayed client requests" << dendl;
	++p;
	continue;
      }
      assert(in->is_auth());
      for (map<client_t,map<int,ceph_mds_cap_reconnect> >::iterator q = p->second.begin();
	  q != p->second.end();
	  ++q)
	for (map<int,ceph_mds_cap_reconnect>::iterator r = q->second.begin();
	    r != q->second.end();
	    ++r) {
	  dout(20) << " add_reconnected_cap " << in->ino() << " client." << q->first << dendl;
	  add_reconnected_cap(in, q->first, inodeno_t(r->second.snaprealm));
	  rejoin_import_cap(in, q->first, r->second, r->first);
	}
      cap_imports.erase(p++);  // remove and move on
    }
  } else {
    for (map<inodeno_t,map<client_t,ceph_mds_cap_reconnect> >::iterator q = cap_exports.begin();
	 q != cap_exports.end();
	 ++q) {
      for (map<client_t,ceph_mds_cap_reconnect>::iterator r = q->second.begin();
	   r != q->second.end();
	   ++r) {
	dout(10) << " exporting caps for client." << r->first << " ino " << q->first << dendl;
	Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(r->first.v));
	assert(session);
	// mark client caps stale.
	MClientCaps *m = new MClientCaps(CEPH_CAP_OP_EXPORT, q->first, 0, 0, 0);
	mds->send_message_client_counted(m, session);
      }
    }

    trim_non_auth();

    rejoin_gather.erase(mds->get_nodeid());
    maybe_send_pending_rejoins();

    if (rejoin_gather.empty() && rejoin_ack_gather.count(mds->get_nodeid()))
      rejoin_gather_finish();
  }
  return false;
}

void MDCache::check_realm_past_parents(SnapRealm *realm)
{
  // are this realm's parents fully open?
  if (realm->have_past_parents_open()) {
    dout(10) << " have past snap parents for realm " << *realm 
	     << " on " << *realm->inode << dendl;
  } else {
    if (!missing_snap_parents.count(realm->inode)) {
      dout(10) << " MISSING past snap parents for realm " << *realm
	       << " on " << *realm->inode << dendl;
      realm->inode->get(CInode::PIN_OPENINGSNAPPARENTS);
      missing_snap_parents[realm->inode].size();   // just to get it into the map!
    } else {
      dout(10) << " (already) MISSING past snap parents for realm " << *realm 
	       << " on " << *realm->inode << dendl;
    }
  }
}

/*
 * choose lock states based on reconnected caps
 */
void MDCache::choose_lock_states_and_reconnect_caps()
{
  dout(10) << "choose_lock_states_and_reconnect_caps" << dendl;

  map<client_t,MClientSnap*> splits;

  for (hash_map<vinodeno_t,CInode*>::iterator i = inode_map.begin();
       i != inode_map.end();
       ++i) {
    CInode *in = i->second;
 
    if (in->is_auth() && !in->is_base() && in->inode.is_dirty_rstat())
      in->mark_dirty_rstat();

    in->choose_lock_states();
    dout(15) << " chose lock states on " << *in << dendl;

    SnapRealm *realm = in->find_snaprealm();

    check_realm_past_parents(realm);

    map<CInode*,map<client_t,inodeno_t> >::iterator p = reconnected_caps.find(in);
    if (p != reconnected_caps.end()) {

      // also, make sure client's cap is in the correct snaprealm.
      for (map<client_t,inodeno_t>::iterator q = p->second.begin();
	   q != p->second.end();
	   ++q) {
	if (q->second == realm->inode->ino()) {
	  dout(15) << "  client." << q->first << " has correct realm " << q->second << dendl;
	} else {
	  dout(15) << "  client." << q->first << " has wrong realm " << q->second
		   << " != " << realm->inode->ino() << dendl;
	  if (realm->have_past_parents_open()) {
	    // ok, include in a split message _now_.
	    prepare_realm_split(realm, q->first, in->ino(), splits);
	  } else {
	    // send the split later.
	    missing_snap_parents[realm->inode][q->first].insert(in->ino());
	  }
	}
      }
    }
  }    
  reconnected_caps.clear();

  send_snaps(splits);
}

void MDCache::prepare_realm_split(SnapRealm *realm, client_t client, inodeno_t ino,
				  map<client_t,MClientSnap*>& splits)
{
  MClientSnap *snap;
  if (splits.count(client) == 0) {
    splits[client] = snap = new MClientSnap(CEPH_SNAP_OP_SPLIT);
    snap->head.split = realm->inode->ino();
    realm->build_snap_trace(snap->bl);

    for (set<SnapRealm*>::iterator p = realm->open_children.begin();
	 p != realm->open_children.end();
	 ++p)
      snap->split_realms.push_back((*p)->inode->ino());
    
  } else 
    snap = splits[client]; 
  snap->split_inos.push_back(ino);	
}

void MDCache::send_snaps(map<client_t,MClientSnap*>& splits)
{
  dout(10) << "send_snaps" << dendl;
  
  for (map<client_t,MClientSnap*>::iterator p = splits.begin();
       p != splits.end();
       ++p) {
    Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(p->first.v));
    if (session) {
      dout(10) << " client." << p->first
	       << " split " << p->second->head.split
	       << " inos " << p->second->split_inos
	       << dendl;
      mds->send_message_client_counted(p->second, session);
    } else {
      dout(10) << " no session for client." << p->first << dendl;
      p->second->put();
    }
  }
  splits.clear();
}


/*
 * remove any items from logsegment open_file lists that don't have
 * any caps
 */
void MDCache::clean_open_file_lists()
{
  dout(10) << "clean_open_file_lists" << dendl;
  
  for (map<uint64_t,LogSegment*>::iterator p = mds->mdlog->segments.begin();
       p != mds->mdlog->segments.end();
       ++p) {
    LogSegment *ls = p->second;
    
    elist<CInode*>::iterator q = ls->open_files.begin(member_offset(CInode, item_open_file));
    while (!q.end()) {
      CInode *in = *q;
      ++q;
      if (!in->is_any_caps_wanted()) {
	dout(10) << " unlisting unwanted/capless inode " << *in << dendl;
	in->item_open_file.remove_myself();
      }
    }
  }
}



void MDCache::rejoin_import_cap(CInode *in, client_t client, ceph_mds_cap_reconnect& icr, int frommds)
{
  dout(10) << "rejoin_import_cap for client." << client << " from mds." << frommds
	   << " on " << *in << dendl;
  Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(client.v));
  assert(session);

  Capability *cap = in->reconnect_cap(client, icr, session);

  if (frommds >= 0) {
    cap->rejoin_import();
    do_cap_import(session, in, cap);
  }
}

void MDCache::export_remaining_imported_caps()
{
  dout(10) << "export_remaining_imported_caps" << dendl;

  stringstream warn_str;

  for (map<inodeno_t,map<client_t,map<int,ceph_mds_cap_reconnect> > >::iterator p = cap_imports.begin();
       p != cap_imports.end();
       ++p) {
    warn_str << " ino " << p->first << "\n";
    for (map<client_t,map<int,ceph_mds_cap_reconnect> >::iterator q = p->second.begin();
	q != p->second.end();
	++q) {
      Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(q->first.v));
      if (session) {
	// mark client caps stale.
	MClientCaps *stale = new MClientCaps(CEPH_CAP_OP_EXPORT, p->first, 0, 0, 0);
	mds->send_message_client_counted(stale, q->first);
      }
    }
  }

  cap_imports.clear();

  if (warn_str.peek() != EOF) {
    mds->clog.warn() << "failed to reconnect caps for missing inodes:" << "\n";
    mds->clog.warn(warn_str);
  }
}

void MDCache::try_reconnect_cap(CInode *in, Session *session)
{
  client_t client = session->info.get_client();
  ceph_mds_cap_reconnect *rc = get_replay_cap_reconnect(in->ino(), client);
  if (rc) {
    in->reconnect_cap(client, *rc, session);
    dout(10) << "try_reconnect_cap client." << client
	     << " reconnect wanted " << ccap_string(rc->wanted)
	     << " issue " << ccap_string(rc->issued)
	     << " on " << *in << dendl;
    remove_replay_cap_reconnect(in->ino(), client);

    if (in->is_replicated()) {
      mds->locker->try_eval(in, CEPH_CAP_LOCKS);
    } else {
      in->choose_lock_states();
      dout(15) << " chose lock states on " << *in << dendl;
    }
  }
}



// -------
// cap imports and delayed snap parent opens

void MDCache::do_cap_import(Session *session, CInode *in, Capability *cap)
{
  client_t client = session->info.inst.name.num();
  SnapRealm *realm = in->find_snaprealm();
  if (realm->have_past_parents_open()) {
    dout(10) << "do_cap_import " << session->info.inst.name << " mseq " << cap->get_mseq() << " on " << *in << dendl;
    if (cap->get_last_seq() == 0)
      cap->issue_norevoke(cap->issued()); // reconnected cap
    cap->set_last_issue();
    MClientCaps *reap = new MClientCaps(CEPH_CAP_OP_IMPORT,
					in->ino(),
					realm->inode->ino(),
					cap->get_cap_id(), cap->get_last_seq(),
					cap->pending(), cap->wanted(), 0,
					cap->get_mseq());
    in->encode_cap_message(reap, cap);
    realm->build_snap_trace(reap->snapbl);
    mds->send_message_client_counted(reap, session);
  } else {
    dout(10) << "do_cap_import missing past snap parents, delaying " << session->info.inst.name << " mseq "
	     << cap->get_mseq() << " on " << *in << dendl;
    in->auth_pin(this);
    cap->inc_suppress();
    delayed_imported_caps[client].insert(in);
    missing_snap_parents[in].size();
  }
}

void MDCache::do_delayed_cap_imports()
{
  dout(10) << "do_delayed_cap_imports" << dendl;

  map<client_t,set<CInode*> > d;
  d.swap(delayed_imported_caps);

  for (map<client_t,set<CInode*> >::iterator p = d.begin();
       p != d.end();
       ++p) {
    for (set<CInode*>::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      CInode *in = *q;
      Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(p->first.v));
      if (session) {
	Capability *cap = in->get_client_cap(p->first);
	if (cap) {
	  do_cap_import(session, in, cap);  // note: this may fail and requeue!
	  cap->dec_suppress();
	}
      }
      in->auth_unpin(this);

      if (in->is_head())
	mds->locker->issue_caps(in);
    }
  }    
}

struct C_MDC_OpenSnapParents : public Context {
  MDCache *mdcache;
  C_MDC_OpenSnapParents(MDCache *c) : mdcache(c) {}
  void finish(int r) {
    mdcache->open_snap_parents();
  }
};

void MDCache::open_snap_parents()
{
  dout(10) << "open_snap_parents" << dendl;
  
  map<client_t,MClientSnap*> splits;
  C_GatherBuilder gather(g_ceph_context);

  map<CInode*,map<client_t,set<inodeno_t> > >::iterator p = missing_snap_parents.begin();
  while (p != missing_snap_parents.end()) {
    CInode *in = p->first;
    assert(in->snaprealm);
    if (in->snaprealm->open_parents(gather.new_sub())) {
      dout(10) << " past parents now open on " << *in << dendl;
      
      // include in a (now safe) snap split?
      for (map<client_t,set<inodeno_t> >::iterator q = p->second.begin();
	   q != p->second.end();
	   ++q)
	for (set<inodeno_t>::iterator r = q->second.begin();
	     r != q->second.end();
	     ++r) 
	  prepare_realm_split(in->snaprealm, q->first, *r, splits);

      missing_snap_parents.erase(p++);

      in->put(CInode::PIN_OPENINGSNAPPARENTS);

      // finish off client snaprealm reconnects?
      map<inodeno_t,map<client_t,snapid_t> >::iterator q = reconnected_snaprealms.find(in->ino());
      if (q != reconnected_snaprealms.end()) {
	for (map<client_t,snapid_t>::iterator r = q->second.begin();
	     r != q->second.end();
	     ++r)
	  finish_snaprealm_reconnect(r->first, in->snaprealm, r->second);
      	reconnected_snaprealms.erase(q);
      }
    } else {
      dout(10) << " opening past parents on " << *in << dendl;
      ++p;
    }
  }

  send_snaps(splits);

  if (gather.has_subs()) {
    dout(10) << "open_snap_parents - waiting for "
	     << gather.num_subs_remaining() << dendl;
    gather.set_finisher(new C_MDC_OpenSnapParents(this));
    gather.activate();
  } else {
    if (!reconnected_snaprealms.empty()) {
      stringstream warn_str;
      for (map<inodeno_t,map<client_t,snapid_t> >::iterator p = reconnected_snaprealms.begin();
	   p != reconnected_snaprealms.end();
	   ++p) {
	warn_str << " unconnected snaprealm " << p->first << "\n";
	for (map<client_t,snapid_t>::iterator q = p->second.begin();
	     q != p->second.end();
	     ++q)
	  warn_str << "  client." << q->first << " snapid " << q->second << "\n";
      }
      mds->clog.warn() << "open_snap_parents has:" << "\n";
      mds->clog.warn(warn_str);
    }
    assert(rejoin_waiters.empty());
    assert(missing_snap_parents.empty());
    dout(10) << "open_snap_parents - all open" << dendl;
    do_delayed_cap_imports();

    start_files_to_recover(rejoin_recover_q, rejoin_check_q);
    mds->rejoin_done();
  }
}

bool MDCache::open_undef_inodes_dirfrags()
{
  dout(10) << "open_undef_inodes_dirfrags "
	   << rejoin_undef_inodes.size() << " inodes "
	   << rejoin_undef_dirfrags.size() << " dirfrags" << dendl;

  set<CDir*> fetch_queue = rejoin_undef_dirfrags;

  for (set<CInode*>::iterator p = rejoin_undef_inodes.begin();
       p != rejoin_undef_inodes.end();
       ++p) {
    CInode *in = *p;
    assert(!in->is_base());
    fetch_queue.insert(in->get_parent_dir());
  }

  if (fetch_queue.empty())
    return false;

  C_GatherBuilder gather(g_ceph_context, new C_MDC_RejoinGatherFinish(this));
  for (set<CDir*>::iterator p = fetch_queue.begin();
       p != fetch_queue.end();
       ++p) {
    CDir *dir = *p;
    CInode *diri = dir->get_inode();
    if (diri->state_test(CInode::STATE_REJOINUNDEF))
      continue;
    if (dir->state_test(CDir::STATE_REJOINUNDEF) && dir->get_frag() == frag_t()) {
      rejoin_undef_dirfrags.erase(dir);
      dir->state_clear(CDir::STATE_REJOINUNDEF);
      diri->force_dirfrags();
      list<CDir*> ls;
      diri->get_dirfrags(ls);
      for (list<CDir*>::iterator q = ls.begin(); q != ls.end(); ++q) {
	rejoin_undef_dirfrags.insert(*q);
	(*q)->state_set(CDir::STATE_REJOINUNDEF);
	(*q)->fetch(gather.new_sub());
      }
      continue;
    }
    dir->fetch(gather.new_sub());
  }
  assert(gather.has_subs());
  gather.activate();
  return true;
}

void MDCache::finish_snaprealm_reconnect(client_t client, SnapRealm *realm, snapid_t seq)
{
  if (seq < realm->get_newest_seq()) {
    dout(10) << "finish_snaprealm_reconnect client." << client << " has old seq " << seq << " < " 
	     << realm->get_newest_seq()
    	     << " on " << *realm << dendl;
    // send an update
    Session *session = mds->sessionmap.get_session(entity_name_t::CLIENT(client.v));
    if (session) {
      MClientSnap *snap = new MClientSnap(CEPH_SNAP_OP_UPDATE);
      realm->build_snap_trace(snap->bl);
      mds->send_message_client_counted(snap, session);
    } else {
      dout(10) << " ...or not, no session for this client!" << dendl;
    }
  } else {
    dout(10) << "finish_snaprealm_reconnect client." << client << " up to date"
	     << " on " << *realm << dendl;
  }
}



void MDCache::rejoin_send_acks()
{
  dout(7) << "rejoin_send_acks" << dendl;

  // replicate stray
  for (map<int, set<CInode*> >::iterator p = rejoin_unlinked_inodes.begin();
       p != rejoin_unlinked_inodes.end();
       ++p) {
    for (set<CInode*>::iterator q = p->second.begin();
	 q != p->second.end();
	 ++q) {
      CInode *in = *q;
      dout(7) << " unlinked inode " << *in << dendl;
      // inode expired
      if (!in->is_replica(p->first))
	continue;
      while (1) {
	CDentry *dn = in->get_parent_dn();
	if (dn->is_replica(p->first))
	  break;
	dn->add_replica(p->first);
	CDir *dir = dn->get_dir();
	if (dir->is_replica(p->first))
	  break;
	dir->add_replica(p->first);
	in = dir->get_inode();
	if (in->is_replica(p->first))
	  break;
	if (in->is_base())
	  break;
      }
    }
  }
  rejoin_unlinked_inodes.clear();
  
  // send acks to everyone in the recovery set
  map<int,MMDSCacheRejoin*> ack;
  for (set<int>::iterator p = recovery_set.begin();
       p != recovery_set.end();
       ++p) 
    ack[*p] = new MMDSCacheRejoin(MMDSCacheRejoin::OP_ACK);
  
  // walk subtrees
  for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin(); 
       p != subtrees.end();
       ++p) {
    CDir *dir = p->first;
    if (!dir->is_auth())
      continue;
    dout(10) << "subtree " << *dir << dendl;
    
    // auth items in this subtree
    list<CDir*> dq;
    dq.push_back(dir);

    while (!dq.empty()) {
      CDir *dir = dq.front();
      dq.pop_front();
      
      // dir
      for (map<int,int>::iterator r = dir->replicas_begin();
	   r != dir->replicas_end();
	   ++r) {
	ack[r->first]->add_strong_dirfrag(dir->dirfrag(), ++r->second, dir->dir_rep);
	ack[r->first]->add_dirfrag_base(dir);
      }
	   
      for (CDir::map_t::iterator q = dir->items.begin();
	   q != dir->items.end();
	   ++q) {
	CDentry *dn = q->second;
	CDentry::linkage_t *dnl = dn->get_linkage();

	// inode
	CInode *in = NULL;
	if (dnl->is_primary())
	  in = dnl->get_inode();

	// dentry
	for (map<int,int>::iterator r = dn->replicas_begin();
	     r != dn->replicas_end();
	     ++r) {
	  ack[r->first]->add_strong_dentry(dir->dirfrag(), dn->name, dn->first, dn->last,
					   dnl->is_primary() ? dnl->get_inode()->ino():inodeno_t(0),
					   dnl->is_remote() ? dnl->get_remote_ino():inodeno_t(0),
					   dnl->is_remote() ? dnl->get_remote_d_type():0,
					   ++r->second,
					   dn->lock.get_replica_state());
	  // peer missed MDentrylink message ?
	  if (in && !in->is_replica(r->first))
	    in->add_replica(r->first);
	}
	
	if (!in)
	  continue;

	for (map<int,int>::iterator r = in->replicas_begin();
	     r != in->replicas_end();
	     ++r) {
	  ack[r->first]->add_inode_base(in);
	  ack[r->first]->add_inode_locks(in, ++r->second);
	}
	
	// subdirs in this subtree?
	in->get_nested_dirfrags(dq);
      }
    }
  }

  // base inodes too
  if (root && root->is_auth()) 
    for (map<int,int>::iterator r = root->replicas_begin();
	 r != root->replicas_end();
	 ++r) {
      ack[r->first]->add_inode_base(root);
      ack[r->first]->add_inode_locks(root, ++r->second);
    }
  if (myin)
    for (map<int,int>::iterator r = myin->replicas_begin();
	 r != myin->replicas_end();
	 ++r) {
      ack[r->first]->add_inode_base(myin);
      ack[r->first]->add_inode_locks(myin, ++r->second);
    }

  // include inode base for any inodes whose scatterlocks may have updated
  for (set<CInode*>::iterator p = rejoin_potential_updated_scatterlocks.begin();
       p != rejoin_potential_updated_scatterlocks.end();
       ++p) {
    CInode *in = *p;
    for (map<int,int>::iterator r = in->replicas_begin();
	 r != in->replicas_end();
	 ++r)
      ack[r->first]->add_inode_base(in);
  }

  // send acks
  for (map<int,MMDSCacheRejoin*>::iterator p = ack.begin();
       p != ack.end();
       ++p) 
    mds->send_message_mds(p->second, p->first);
  
}


void MDCache::reissue_all_caps()
{
  dout(10) << "reissue_all_caps" << dendl;

  for (hash_map<vinodeno_t,CInode*>::iterator p = inode_map.begin();
       p != inode_map.end();
       ++p) {
    CInode *in = p->second;
    if (in->is_head() && in->is_any_caps()) {
      if (!mds->locker->eval(in, CEPH_CAP_LOCKS))
	mds->locker->issue_caps(in);
    }
  }
}


// ===============================================================================

struct C_MDC_QueuedCow : public Context {
  MDCache *mdcache;
  CInode *in;
  Mutation *mut;
  C_MDC_QueuedCow(MDCache *mdc, CInode *i, Mutation *m) : mdcache(mdc), in(i), mut(m) {}
  void finish(int r) {
    mdcache->_queued_file_recover_cow(in, mut);
  }
};

void MDCache::queue_file_recover(CInode *in)
{
  dout(10) << "queue_file_recover " << *in << dendl;
  assert(in->is_auth());

  // cow?
  SnapRealm *realm = in->find_snaprealm();
  set<snapid_t> s = realm->get_snaps();
  while (!s.empty() && *s.begin() < in->first)
    s.erase(s.begin());
  while (!s.empty() && *s.rbegin() > in->last)
    s.erase(*s.rbegin());
  dout(10) << " snaps in [" << in->first << "," << in->last << "] are " << s << dendl;
  if (s.size() > 1) {
    inode_t *pi = in->project_inode();
    pi->version = in->pre_dirty();

    Mutation *mut = new Mutation;
    mut->ls = mds->mdlog->get_current_segment();
    EUpdate *le = new EUpdate(mds->mdlog, "queue_file_recover cow");
    mds->mdlog->start_entry(le);
    predirty_journal_parents(mut, &le->metablob, in, 0, PREDIRTY_PRIMARY);

    s.erase(*s.begin());
    while (!s.empty()) {
      snapid_t snapid = *s.begin();
      CInode *cow_inode = 0;
      journal_cow_inode(mut, &le->metablob, in, snapid-1, &cow_inode);
      assert(cow_inode);
      _queue_file_recover(cow_inode);
      s.erase(*s.begin());
    }
    
    in->parent->first = in->first;
    le->metablob.add_primary_dentry(in->parent, in, true);
    mds->mdlog->submit_entry(le, new C_MDC_QueuedCow(this, in, mut));
    mds->mdlog->flush();
  }

  _queue_file_recover(in);
}

void MDCache::_queued_file_recover_cow(CInode *in, Mutation *mut)
{
  in->pop_and_dirty_projected_inode(mut->ls);
  mut->apply();
  mds->locker->drop_locks(mut);
  mut->cleanup();
  delete mut;
}

void MDCache::_queue_file_recover(CInode *in)
{
  dout(15) << "_queue_file_recover " << *in << dendl;
  assert(in->is_auth());
  in->state_clear(CInode::STATE_NEEDSRECOVER);
  if (!in->state_test(CInode::STATE_RECOVERING)) {
    in->state_set(CInode::STATE_RECOVERING);
    in->auth_pin(this);
  }
  file_recover_queue.insert(in);
}

void MDCache::unqueue_file_recover(CInode *in)
{
  dout(15) << "unqueue_file_recover " << *in << dendl;
  in->state_clear(CInode::STATE_RECOVERING);
  in->auth_unpin(this);
  file_recover_queue.erase(in);
}

/*
 * called after recovery to recover file sizes for previously opened (for write)
 * files.  that is, those where max_size > size.
 */
void MDCache::identify_files_to_recover(vector<CInode*>& recover_q, vector<CInode*>& check_q)
{
  dout(10) << "identify_files_to_recover" << dendl;
  for (hash_map<vinodeno_t,CInode*>::iterator p = inode_map.begin();
       p != inode_map.end();
       ++p) {
    CInode *in = p->second;
    if (!in->is_auth())
      continue;
    
    bool recover = false;
    for (map<client_t,client_writeable_range_t>::iterator p = in->inode.client_ranges.begin();
	 p != in->inode.client_ranges.end();
	 ++p) {
      Capability *cap = in->get_client_cap(p->first);
      if (!cap) {
	dout(10) << " client." << p->first << " has range " << p->second << " but no cap on " << *in << dendl;
	recover = true;
	break;
      }
    }

    if (recover) {
      in->auth_pin(&in->filelock);
      in->filelock.set_state(LOCK_PRE_SCAN);
      recover_q.push_back(in);
      
      // make sure past parents are open/get opened
      SnapRealm *realm = in->find_snaprealm();
      check_realm_past_parents(realm);
    } else {
      check_q.push_back(in);
    }
  }
}

void MDCache::start_files_to_recover(vector<CInode*>& recover_q, vector<CInode*>& check_q)
{
  for (vector<CInode*>::iterator p = check_q.begin(); p != check_q.end(); ++p) {
    CInode *in = *p;
    mds->locker->check_inode_max_size(in);
  }
  for (vector<CInode*>::iterator p = recover_q.begin(); p != recover_q.end(); ++p) {
    CInode *in = *p;
    mds->locker->file_recover(&in->filelock);
  }
}

struct C_MDC_Recover : public Context {
  MDCache *mdc;
  CInode *in;
  uint64_t size;
  utime_t mtime;
  C_MDC_Recover(MDCache *m, CInode *i) : mdc(m), in(i), size(0) {}
  void finish(int r) {
    mdc->_recovered(in, r, size, mtime);
  }
};

void MDCache::do_file_recover()
{
  dout(10) << "do_file_recover " << file_recover_queue.size() << " queued, "
	   << file_recovering.size() << " recovering" << dendl;

  while (file_recovering.size() < 5 &&
	 !file_recover_queue.empty()) {
    CInode *in = *file_recover_queue.begin();
    file_recover_queue.erase(in);

    inode_t *pi = in->get_projected_inode();

    // blech
    if (pi->client_ranges.size() && !pi->get_max_size()) {
      mds->clog.warn() << "bad client_range " << pi->client_ranges
	  << " on ino " << pi->ino << "\n";
    }

    if (pi->client_ranges.size() && pi->get_max_size()) {
      dout(10) << "do_file_recover starting " << in->inode.size << " " << pi->client_ranges
	       << " " << *in << dendl;
      file_recovering.insert(in);
      
      C_MDC_Recover *fin = new C_MDC_Recover(this, in);
      mds->filer->probe(in->inode.ino, &in->inode.layout, in->last,
			pi->get_max_size(), &fin->size, &fin->mtime, false,
			0, fin);    
    } else {
      dout(10) << "do_file_recover skipping " << in->inode.size
	       << " " << *in << dendl;
      in->state_clear(CInode::STATE_RECOVERING);
      in->auth_unpin(this);
      if (in->filelock.is_stable()) {
	bool need_issue = false;
	mds->locker->eval(&in->filelock, &need_issue);
	if (in->is_head() && need_issue)
	  mds->locker->issue_caps(in);
      } else
	mds->locker->eval_gather(&in->filelock);
    }
  }
}

void MDCache::_recovered(CInode *in, int r, uint64_t size, utime_t mtime)
{
  dout(10) << "_recovered r=" << r << " size=" << in->inode.size << " mtime=" << in->inode.mtime
	   << " for " << *in << dendl;

  if (r != 0) {
    dout(0) << "recovery error! " << r << dendl;
    if (r == -EBLACKLISTED) {
      mds->suicide();
      return;
    }
    assert(0 == "unexpected error from osd during recovery");
  }

  file_recovering.erase(in);
  in->state_clear(CInode::STATE_RECOVERING);

  if (!in->get_parent_dn() && !in->get_projected_parent_dn()) {
    dout(10) << " inode has no parents, killing it off" << dendl;
    in->auth_unpin(this);
    remove_inode(in);
  } else {
    // journal
    mds->locker->check_inode_max_size(in, true, true, size, false, 0, mtime);
    in->auth_unpin(this);
  }

  do_file_recover();
}

void MDCache::purge_prealloc_ino(inodeno_t ino, Context *fin)
{
  object_t oid = CInode::get_object_name(ino, frag_t(), "");
  object_locator_t oloc(mds->mdsmap->get_metadata_pool());

  dout(10) << "purge_prealloc_ino " << ino << " oid " << oid << dendl;
  SnapContext snapc;
  mds->objecter->remove(oid, oloc, snapc, ceph_clock_now(g_ceph_context), 0, 0, fin);
}  




// ===============================================================================



// ----------------------------
// truncate

void MDCache::truncate_inode(CInode *in, LogSegment *ls)
{
  inode_t *pi = in->get_projected_inode();
  dout(10) << "truncate_inode "
	   << pi->truncate_from << " -> " << pi->truncate_size
	   << " on " << *in
	   << dendl;

  ls->truncating_inodes.insert(in);
  in->get(CInode::PIN_TRUNCATING);

  _truncate_inode(in, ls);
}

struct C_MDC_TruncateFinish : public Context {
  MDCache *mdc;
  CInode *in;
  LogSegment *ls;
  C_MDC_TruncateFinish(MDCache *c, CInode *i, LogSegment *l) :
    mdc(c), in(i), ls(l) {}
  void finish(int r) {
    assert(r != -EINVAL);
    mdc->truncate_inode_finish(in, ls);
  }
};

void MDCache::_truncate_inode(CInode *in, LogSegment *ls)
{
  inode_t *pi = &in->inode;
  dout(10) << "_truncate_inode "
	   << pi->truncate_from << " -> " << pi->truncate_size
	   << " on " << *in << dendl;

  assert(pi->is_truncating());
  assert(pi->truncate_size < (1ULL << 63));
  assert(pi->truncate_from < (1ULL << 63));
  assert(pi->truncate_size < pi->truncate_from);

  in->auth_pin(this);

  SnapRealm *realm = in->find_snaprealm();
  SnapContext nullsnap;
  const SnapContext *snapc;
  if (realm) {
    dout(10) << " realm " << *realm << dendl;
    snapc = &realm->get_snap_context();
  } else {
    dout(10) << " NO realm, using null context" << dendl;
    snapc = &nullsnap;
    assert(in->last == CEPH_NOSNAP);
  }
  dout(10) << "_truncate_inode  snapc " << snapc << " on " << *in << dendl;
  mds->filer->truncate(in->inode.ino, &in->inode.layout, *snapc,
		       pi->truncate_size, pi->truncate_from-pi->truncate_size, pi->truncate_seq, utime_t(), 0,
		       0, new C_MDC_TruncateFinish(this, in, ls));
}

struct C_MDC_TruncateLogged : public Context {
  MDCache *mdc;
  CInode *in;
  Mutation *mut;
  C_MDC_TruncateLogged(MDCache *m, CInode *i, Mutation *mu) : mdc(m), in(i), mut(mu) {}
  void finish(int r) {
    mdc->truncate_inode_logged(in, mut);
  }
};

void MDCache::truncate_inode_finish(CInode *in, LogSegment *ls)
{
  dout(10) << "truncate_inode_finish " << *in << dendl;
  
  set<CInode*>::iterator p = ls->truncating_inodes.find(in);
  assert(p != ls->truncating_inodes.end());
  ls->truncating_inodes.erase(p);

  // update
  inode_t *pi = in->project_inode();
  pi->version = in->pre_dirty();
  pi->truncate_from = 0;
  pi->truncate_pending--;

  Mutation *mut = new Mutation;
  mut->ls = mds->mdlog->get_current_segment();
  mut->add_projected_inode(in);

  EUpdate *le = new EUpdate(mds->mdlog, "truncate finish");
  mds->mdlog->start_entry(le);
  CDentry *dn = in->get_projected_parent_dn();
  le->metablob.add_dir_context(dn->get_dir());
  le->metablob.add_primary_dentry(dn, in, true);
  le->metablob.add_truncate_finish(in->ino(), ls->offset);

  journal_dirty_inode(mut, &le->metablob, in);
  mds->mdlog->submit_entry(le, new C_MDC_TruncateLogged(this, in, mut));

  // flush immediately if there are readers/writers waiting
  if (in->get_caps_wanted() & (CEPH_CAP_FILE_RD|CEPH_CAP_FILE_WR))
    mds->mdlog->flush();
}

void MDCache::truncate_inode_logged(CInode *in, Mutation *mut)
{
  dout(10) << "truncate_inode_logged " << *in << dendl;
  mut->apply();
  mds->locker->drop_locks(mut);
  mut->cleanup();
  delete mut;

  in->put(CInode::PIN_TRUNCATING);
  in->auth_unpin(this);

  list<Context*> waiters;
  in->take_waiting(CInode::WAIT_TRUNC, waiters);
  mds->queue_waiters(waiters);
}


void MDCache::add_recovered_truncate(CInode *in, LogSegment *ls)
{
  dout(20) << "add_recovered_truncate " << *in << " in " << ls << " offset " << ls->offset << dendl;
  ls->truncating_inodes.insert(in);
  in->get(CInode::PIN_TRUNCATING);
}

void MDCache::remove_recovered_truncate(CInode *in, LogSegment *ls)
{
  dout(20) << "remove_recovered_truncate " << *in << " in " << ls << " offset " << ls->offset << dendl;
  // if we have the logseg the truncate started in, it must be in our list.
  set<CInode*>::iterator p = ls->truncating_inodes.find(in);
  assert(p != ls->truncating_inodes.end());
  ls->truncating_inodes.erase(p);
  in->put(CInode::PIN_TRUNCATING);
}

void MDCache::start_recovered_truncates()
{
  dout(10) << "start_recovered_truncates" << dendl;
  for (map<uint64_t,LogSegment*>::iterator p = mds->mdlog->segments.begin();
       p != mds->mdlog->segments.end();
       ++p) {
    LogSegment *ls = p->second;
    for (set<CInode*>::iterator q = ls->truncating_inodes.begin();
	 q != ls->truncating_inodes.end();
	 ++q)
      _truncate_inode(*q, ls);
  }
}






// ================================================================================
// cache trimming


/*
 * note: only called while MDS is active or stopping... NOT during recovery.
 * however, we may expire a replica whose authority is recovering.
 * 
 */
bool MDCache::trim(int max) 
{
  // trim LRU
  if (max < 0) {
    max = g_conf->mds_cache_size;
    if (!max) return false;
  }
  dout(7) << "trim max=" << max << "  cur=" << lru.lru_get_size() << dendl;

  // process delayed eval_stray()
  for (elist<CDentry*>::iterator p = delayed_eval_stray.begin(); !p.end(); ) {
    CDentry *dn = *p;
    ++p;
    dn->item_stray.remove_myself();
    eval_stray(dn);
  }

  map<int, MCacheExpire*> expiremap;
  bool is_standby_replay = mds->is_standby_replay();
  int unexpirable = 0;
  list<CDentry*> unexpirables;
  // trim dentries from the LRU
  while (lru.lru_get_size() + unexpirable > (unsigned)max) {
    CDentry *dn = static_cast<CDentry*>(lru.lru_expire());
    if (!dn) break;
    if ((is_standby_replay && dn->get_linkage() &&
        dn->get_linkage()->inode->item_open_file.is_on_list()) ||
	trim_dentry(dn, expiremap)) {
      unexpirables.push_back(dn);
      ++unexpirable;
    }
  }
  for(list<CDentry*>::iterator i = unexpirables.begin();
      i != unexpirables.end();
      ++i)
    lru.lru_insert_mid(*i);

  // trim non-auth, non-bound subtrees
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();) {
    CDir *dir = p->first;
    ++p;
    if (!dir->is_auth() && !dir->get_inode()->is_auth()) {
      if (dir->get_num_ref() == 1)  // subtree pin
	trim_dirfrag(dir, 0, expiremap);
    }
  }

  // trim root?
  if (max == 0 && root) {
    list<CDir*> ls;
    root->get_dirfrags(ls);
    for (list<CDir*>::iterator p = ls.begin(); p != ls.end(); ++p) {
      CDir *dir = *p;
      if (dir->get_num_ref() == 1)  // subtree pin
	trim_dirfrag(dir, 0, expiremap);
    }
    if (root->get_num_ref() == 0)
      trim_inode(0, root, 0, expiremap);
  }

  // send any expire messages
  send_expire_messages(expiremap);

  return true;
}

void MDCache::send_expire_messages(map<int, MCacheExpire*>& expiremap)
{
  // send expires
  for (map<int, MCacheExpire*>::iterator it = expiremap.begin();
       it != expiremap.end();
       ++it) {
    if (mds->mdsmap->get_state(it->first) < MDSMap::STATE_REJOIN ||
	(mds->mdsmap->get_state(it->first) == MDSMap::STATE_REJOIN &&
	 rejoin_sent.count(it->first) == 0)) {
      it->second->put();
      continue;
    }
    dout(7) << "sending cache_expire to " << it->first << dendl;
    mds->send_message_mds(it->second, it->first);
  }
}


bool MDCache::trim_dentry(CDentry *dn, map<int, MCacheExpire*>& expiremap)
{
  dout(12) << "trim_dentry " << *dn << dendl;
  
  CDentry::linkage_t *dnl = dn->get_linkage();

  CDir *dir = dn->get_dir();
  assert(dir);
  
  CDir *con = get_subtree_root(dir);
  if (con)
    dout(12) << " in container " << *con << dendl;
  else {
    dout(12) << " no container; under a not-yet-linked dir" << dendl;
    assert(dn->is_auth());
  }

  // notify dentry authority?
  if (!dn->is_auth()) {
    pair<int,int> auth = dn->authority();
    
    for (int p=0; p<2; p++) {
      int a = auth.first;
      if (p) a = auth.second;
      if (a < 0 || (p == 1 && auth.second == auth.first)) break;
      if (mds->get_nodeid() == auth.second &&
	  con->is_importing()) break;                // don't send any expire while importing.
      if (a == mds->get_nodeid()) continue;          // on export, ignore myself.
      
      dout(12) << "  sending expire to mds." << a << " on " << *dn << dendl;
      assert(a != mds->get_nodeid());
      if (expiremap.count(a) == 0) 
	expiremap[a] = new MCacheExpire(mds->get_nodeid());
      expiremap[a]->add_dentry(con->dirfrag(), dir->dirfrag(), dn->name, dn->last, dn->get_replica_nonce());
    }
  }

  // adjust the dir state
  // NOTE: we can safely remove a clean, null dentry without effecting
  //       directory completeness.
  // (check this _before_ we unlink the inode, below!)
  bool clear_complete = false;
  if (!(dnl->is_null() && dn->is_clean())) 
    clear_complete = true;
  
  // unlink the dentry
  if (dnl->is_remote()) {
    // just unlink.
    dir->unlink_inode(dn);
  } 
  else if (dnl->is_primary()) {
    // expire the inode, too.
    CInode *in = dnl->get_inode();
    assert(in);
    trim_inode(dn, in, con, expiremap);
    // purging stray instead of trimming ?
    if (dn->get_num_ref() > 0)
      return true;
  } 
  else {
    assert(dnl->is_null());
  }
    
  // remove dentry
  if (dir->is_auth())
    dir->add_to_bloom(dn);
  dir->remove_dentry(dn);

  if (clear_complete)
    dir->state_clear(CDir::STATE_COMPLETE);
  
  // reexport?
  if (dir->get_num_head_items() == 0 && dir->is_subtree_root())
    migrator->export_empty_import(dir);
  
  if (mds->logger) mds->logger->inc(l_mds_iex);
  return false;
}


void MDCache::trim_dirfrag(CDir *dir, CDir *con, map<int, MCacheExpire*>& expiremap)
{
  dout(15) << "trim_dirfrag " << *dir << dendl;

  if (dir->is_subtree_root()) {
    assert(!dir->is_auth() ||
	   (!dir->is_replicated() && dir->inode->is_base()));
    remove_subtree(dir);	// remove from subtree map
  }
  assert(dir->get_num_ref() == 0);

  CInode *in = dir->get_inode();

  if (!dir->is_auth()) {
    pair<int,int> auth = dir->authority();
    
    // was this an auth delegation?  (if so, slightly modified container)
    dirfrag_t condf;
    if (dir->is_subtree_root()) {
      dout(12) << " subtree root, container is " << *dir << dendl;
      con = dir;
      condf = dir->dirfrag();
    } else {
      condf = con->dirfrag();
    }
      
    for (int p=0; p<2; p++) {
      int a = auth.first;
      if (p) a = auth.second;
      if (a < 0 || (p == 1 && auth.second == auth.first)) break;
      if (mds->get_nodeid() == auth.second &&
	  con->is_importing()) break;                // don't send any expire while importing.
      if (a == mds->get_nodeid()) continue;          // on export, ignore myself.

      dout(12) << "  sending expire to mds." << a << " on   " << *dir << dendl;
      assert(a != mds->get_nodeid());
      if (expiremap.count(a) == 0) 
	expiremap[a] = new MCacheExpire(mds->get_nodeid());
      expiremap[a]->add_dir(condf, dir->dirfrag(), dir->replica_nonce);
    }
  }
  
  in->close_dirfrag(dir->dirfrag().frag);
}

void MDCache::trim_inode(CDentry *dn, CInode *in, CDir *con, map<int, MCacheExpire*>& expiremap)
{
  dout(15) << "trim_inode " << *in << dendl;
  assert(in->get_num_ref() == 0);
    
  // DIR
  list<CDir*> dfls;
  in->get_dirfrags(dfls);
  for (list<CDir*>::iterator p = dfls.begin();
       p != dfls.end();
       ++p) 
    trim_dirfrag(*p, con ? con:*p, expiremap);  // if no container (e.g. root dirfrag), use *p
  
  // INODE
  if (in->is_auth()) {
    // eval stray after closing dirfrags
    if (dn) {
      maybe_eval_stray(in);
      if (dn->get_num_ref() > 0)
	return;
    }
  } else {
    pair<int,int> auth = in->authority();
    
    dirfrag_t df;
    if (con)
      df = con->dirfrag();
    else
      df = dirfrag_t(0,frag_t());   // must be a root or stray inode.

    for (int p=0; p<2; p++) {
      int a = auth.first;
      if (p) a = auth.second;
      if (a < 0 || (p == 1 && auth.second == auth.first)) break;
      if (con && mds->get_nodeid() == auth.second &&
	  con->is_importing()) break;                // don't send any expire while importing.
      if (a == mds->get_nodeid()) continue;          // on export, ignore myself.

      dout(12) << "  sending expire to mds." << a << " on " << *in << dendl;
      assert(a != mds->get_nodeid());
      if (expiremap.count(a) == 0) 
	expiremap[a] = new MCacheExpire(mds->get_nodeid());
      expiremap[a]->add_inode(df, in->vino(), in->get_replica_nonce());
    }
  }

  /*
  if (in->is_auth()) {
    if (in->hack_accessed)
      mds->logger->inc("outt");
    else {
      mds->logger->inc("outut");
      mds->logger->fset("oututl", ceph_clock_now(g_ceph_context) - in->hack_load_stamp);
    }
  }
  */
    
  // unlink
  if (dn)
    dn->get_dir()->unlink_inode(dn);
  remove_inode(in);
}


/**
 * trim_non_auth - remove any non-auth items from our cache
 *
 * this reduces the amount of non-auth metadata in our cache, reducing the 
 * load incurred by the rejoin phase.
 *
 * the only non-auth items that remain are those that are needed to 
 * attach our own subtrees to the root.  
 *
 * when we are done, all dentries will be in the top bit of the lru.
 *
 * why we have to do this:
 *  we may not have accurate linkage for non-auth items.  which means we will 
 *  know which subtree it falls into, and can not be sure to declare it to the
 *  correct authority.  
 */
void MDCache::trim_non_auth()
{
  dout(7) << "trim_non_auth" << dendl;
  
  // temporarily pin all subtree roots
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) 
    p->first->get(CDir::PIN_SUBTREETEMP);

  // note first auth item we see.  
  // when we see it the second time, stop.
  CDentry *first_auth = 0;
  
  // trim non-auth items from the lru
  while (lru.lru_get_size() > 0) {
    CDentry *dn = static_cast<CDentry*>(lru.lru_expire());
    if (!dn) break;
    CDentry::linkage_t *dnl = dn->get_linkage();

    if (dn->is_auth()) {
      // add back into lru (at the top)
      lru.lru_insert_top(dn);

      if (dn->get_dir()->get_inode()->is_stray()) {
	dn->state_set(CDentry::STATE_STRAY);
	if (dnl->is_primary() && dnl->get_inode()->inode.nlink == 0)
	  dnl->get_inode()->state_set(CInode::STATE_ORPHAN);
      }

      if (!first_auth) {
	first_auth = dn;
      } else {
	if (first_auth == dn) 
	  break;
      }
    } else {
      // non-auth.  expire.
      CDir *dir = dn->get_dir();
      assert(dir);

      // unlink the dentry
      dout(10) << " removing " << *dn << dendl;
      if (dnl->is_remote()) {
	dir->unlink_inode(dn);
      } 
      else if (dnl->is_primary()) {
	CInode *in = dnl->get_inode();
	dout(10) << " removing " << *in << dendl;
	list<CDir*> ls;
	in->get_dirfrags(ls);
	for (list<CDir*>::iterator p = ls.begin(); p != ls.end(); ++p) {
	  CDir *subdir = *p;
	  assert(!subdir->is_subtree_root());
	  in->close_dirfrag(subdir->dirfrag().frag);
	}
	dir->unlink_inode(dn);
	remove_inode(in);
      } 
      else {
	assert(dnl->is_null());
      }

      assert(!dir->has_bloom());
      dir->remove_dentry(dn);
      // adjust the dir state
      dir->state_clear(CDir::STATE_COMPLETE);  // dir incomplete!
    }
  }

  // move everything in the pintail to the top bit of the lru.
  lru.lru_touch_entire_pintail();

  // unpin all subtrees
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) 
    p->first->put(CDir::PIN_SUBTREETEMP);

  if (lru.lru_get_size() == 0) {
    // root, stray, etc.?
    hash_map<vinodeno_t,CInode*>::iterator p = inode_map.begin();
    while (p != inode_map.end()) {
      hash_map<vinodeno_t,CInode*>::iterator next = p;
      ++next;
      CInode *in = p->second;
      if (!in->is_auth()) {
	list<CDir*> ls;
	in->get_dirfrags(ls);
	for (list<CDir*>::iterator p = ls.begin();
	     p != ls.end();
	     ++p) {
	  dout(10) << " removing " << **p << dendl;
	  assert((*p)->get_num_ref() == 1);  // SUBTREE
	  remove_subtree((*p));
	  in->close_dirfrag((*p)->dirfrag().frag);
	}
	dout(10) << " removing " << *in << dendl;
	assert(!in->get_parent_dn());
	assert(in->get_num_ref() == 0);
	remove_inode(in);
      }
      p = next;
    }
  }

  show_subtrees();
}

/**
 * Recursively trim the subtree rooted at directory to remove all
 * CInodes/CDentrys/CDirs that aren't links to remote MDSes, or ancestors
 * of those links. This is used to clear invalid data out of the cache.
 * Note that it doesn't clear the passed-in directory, since that's not
 * always safe.
 */
bool MDCache::trim_non_auth_subtree(CDir *dir)
{
  dout(10) << "trim_non_auth_subtree(" << dir << ") " << *dir << dendl;

  if (uncommitted_slave_rename_olddir.count(dir) || // preserve the dir for rollback
      my_ambiguous_imports.count(dir->dirfrag()))
    return true;

  bool keep_dir = false;
  CDir::map_t::iterator j = dir->begin();
  CDir::map_t::iterator i = j;
  while (j != dir->end()) {
    i = j++;
    CDentry *dn = i->second;
    dout(10) << "trim_non_auth_subtree(" << dir << ") Checking dentry " << dn << dendl;
    CDentry::linkage_t *dnl = dn->get_linkage();
    if (dnl->is_primary()) { // check for subdirectories, etc
      CInode *in = dnl->get_inode();
      bool keep_inode = false;
      if (in->is_dir()) {
        list<CDir*> subdirs;
        in->get_dirfrags(subdirs);
        for (list<CDir*>::iterator subdir = subdirs.begin();
            subdir != subdirs.end();
            ++subdir) {
          if (uncommitted_slave_rename_olddir.count(*subdir) || // preserve the dir for rollback
	      my_ambiguous_imports.count((*subdir)->dirfrag()) ||
	      (*subdir)->is_subtree_root()) {
            keep_inode = true;
            dout(10) << "trim_non_auth_subtree(" << dir << ") subdir " << *subdir << "is kept!" << dendl;
          }
          else {
            if (trim_non_auth_subtree(*subdir))
              keep_inode = true;
            else {
              in->close_dirfrag((*subdir)->get_frag());
              dir->state_clear(CDir::STATE_COMPLETE);  // now incomplete!
            }
          }
        }

      }
      if (!keep_inode) { // remove it!
        dout(20) << "trim_non_auth_subtree(" << dir << ") removing inode " << in << " with dentry" << dn << dendl;
        dir->unlink_inode(dn);
        remove_inode(in);
	assert(!dir->has_bloom());
        dir->remove_dentry(dn);
      } else {
        dout(20) << "trim_non_auth_subtree(" << dir << ") keeping inode " << in << " with dentry " << dn <<dendl;
        keep_dir = true;
      }
    } else { // just remove it
      dout(20) << "trim_non_auth_subtree(" << dir << ") removing dentry " << dn << dendl;
      if (dnl->is_remote())
        dir->unlink_inode(dn);
      dir->remove_dentry(dn);
    }
  }
  /**
   * We've now checked all our children and deleted those that need it.
   * Now return to caller, and tell them if *we're* a keeper.
   */
  return keep_dir;
}

/*
 * during replay, when we determine a subtree is no longer ours, we
 * try to trim it from our cache.  because subtrees must be connected
 * to the root, the fact that we can trim this tree may mean that our
 * children or parents can also be trimmed.
 */
void MDCache::try_trim_non_auth_subtree(CDir *dir)
{
  dout(10) << "try_trim_nonauth_subtree " << *dir << dendl;

  // can we now trim child subtrees?
  set<CDir*> bounds;
  get_subtree_bounds(dir, bounds);
  for (set<CDir*>::iterator p = bounds.begin(); p != bounds.end(); ++p) {
    CDir *bd = *p;
    if (bd->get_dir_auth().first != mds->whoami &&  // we are not auth
	bd->get_num_any() == 0) {                   // and empty
      CInode *bi = bd->get_inode();
      dout(10) << " closing empty non-auth child subtree " << *bd << dendl;
      remove_subtree(bd);
      bd->mark_clean();
      bi->close_dirfrag(bd->get_frag());
    }
  }

  if (trim_non_auth_subtree(dir)) {
    // keep
    try_subtree_merge(dir);
  } else {
    // can we trim this subtree (and possibly our ancestors) too?
    while (true) {
      CInode *diri = dir->get_inode();
      if (diri->is_base())
	break;

      CDir *psub = get_subtree_root(diri->get_parent_dir());
      dout(10) << " parent subtree is " << *psub << dendl;
      if (psub->get_dir_auth().first == mds->whoami)
	break;  // we are auth, keep.

      dout(10) << " closing empty non-auth subtree " << *dir << dendl;
      remove_subtree(dir);
      dir->mark_clean();
      diri->close_dirfrag(dir->get_frag());

      dout(10) << " parent subtree also non-auth: " << *psub << dendl;
      if (trim_non_auth_subtree(psub))
	break;
      dir = psub;
    }
  }

  show_subtrees();
}


/* This function DOES put the passed message before returning */
void MDCache::handle_cache_expire(MCacheExpire *m)
{
  int from = m->get_from();
  
  dout(7) << "cache_expire from mds." << from << dendl;

  if (mds->get_state() < MDSMap::STATE_REJOIN) {
    m->put();
    return;
  }

  set<SimpleLock *> gather_locks;
  // loop over realms
  for (map<dirfrag_t,MCacheExpire::realm>::iterator p = m->realms.begin();
       p != m->realms.end();
       ++p) {
    // check container?
    if (p->first.ino > 0) {
      CInode *expired_inode = get_inode(p->first.ino);
      assert(expired_inode);  // we had better have this.
      CDir *parent_dir = expired_inode->get_approx_dirfrag(p->first.frag);
      assert(parent_dir);

      int export_state = -1;
      if (parent_dir->is_auth() && parent_dir->is_exporting()) {
	export_state = migrator->get_export_state(parent_dir);
	assert(export_state >= 0);
      }

      if (!parent_dir->is_auth() ||
	  (export_state != -1 &&
	   ((export_state == Migrator::EXPORT_WARNING &&
	     migrator->export_has_warned(parent_dir,from)) ||
	    export_state == Migrator::EXPORT_EXPORTING ||
	    export_state == Migrator::EXPORT_LOGGINGFINISH ||
	    (export_state == Migrator::EXPORT_NOTIFYING &&
	     !migrator->export_has_notified(parent_dir,from))))) {

	// not auth.
	dout(7) << "delaying nonauth|warned expires for " << *parent_dir << dendl;
	assert(parent_dir->is_frozen_tree_root());
	
	// make a message container
	if (delayed_expire[parent_dir].count(from) == 0)
	  delayed_expire[parent_dir][from] = new MCacheExpire(from);
	
	// merge these expires into it
	delayed_expire[parent_dir][from]->add_realm(p->first, p->second);
	continue;
      }
      assert(export_state <= Migrator::EXPORT_PREPPING ||
             (export_state == Migrator::EXPORT_WARNING &&
              !migrator->export_has_warned(parent_dir, from)));

      dout(7) << "expires for " << *parent_dir << dendl;
    } else {
      dout(7) << "containerless expires (root, stray inodes)" << dendl;
    }

    // INODES
    for (map<vinodeno_t,int>::iterator it = p->second.inodes.begin();
	 it != p->second.inodes.end();
	 ++it) {
      CInode *in = get_inode(it->first);
      int nonce = it->second;
      
      if (!in) {
	dout(0) << " inode expire on " << it->first << " from " << from 
		<< ", don't have it" << dendl;
	assert(in);
      }        
      assert(in->is_auth());
      
      // check nonce
      if (nonce == in->get_replica_nonce(from)) {
	// remove from our cached_by
	dout(7) << " inode expire on " << *in << " from mds." << from 
		<< " cached_by was " << in->get_replicas() << dendl;
	inode_remove_replica(in, from, gather_locks);
      } 
      else {
	// this is an old nonce, ignore expire.
	dout(7) << " inode expire on " << *in << " from mds." << from
		<< " with old nonce " << nonce
		<< " (current " << in->get_replica_nonce(from) << "), dropping" 
		<< dendl;
      }
    }
    
    // DIRS
    for (map<dirfrag_t,int>::iterator it = p->second.dirs.begin();
	 it != p->second.dirs.end();
	 ++it) {
      CDir *dir = get_dirfrag(it->first);
      int nonce = it->second;
      
      if (!dir) {
	dout(0) << " dir expire on " << it->first << " from " << from 
		<< ", don't have it" << dendl;
	assert(dir);
      }  
      assert(dir->is_auth());
      
      // check nonce
      if (nonce == dir->get_replica_nonce(from)) {
	// remove from our cached_by
	dout(7) << " dir expire on " << *dir << " from mds." << from
		<< " replicas was " << dir->replica_map << dendl;
	dir->remove_replica(from);
      } 
      else {
	// this is an old nonce, ignore expire.
	dout(7) << " dir expire on " << *dir << " from mds." << from 
		<< " with old nonce " << nonce << " (current " << dir->get_replica_nonce(from)
		<< "), dropping" << dendl;
      }
    }
    
    // DENTRIES
    for (map<dirfrag_t, map<pair<string,snapid_t>,int> >::iterator pd = p->second.dentries.begin();
	 pd != p->second.dentries.end();
	 ++pd) {
      dout(10) << " dn expires in dir " << pd->first << dendl;
      CInode *diri = get_inode(pd->first.ino);
      assert(diri);
      CDir *dir = diri->get_dirfrag(pd->first.frag);
      
      if (!dir) {
	dout(0) << " dn expires on " << pd->first << " from " << from
		<< ", must have refragmented" << dendl;
      } else {
	assert(dir->is_auth());
      }
      
      for (map<pair<string,snapid_t>,int>::iterator p = pd->second.begin();
	   p != pd->second.end();
	   ++p) {
	int nonce = p->second;
	CDentry *dn;
	
	if (dir) {
	  dn = dir->lookup(p->first.first, p->first.second);
	} else {
	  // which dirfrag for this dentry?
	  CDir *dir = diri->get_dirfrag(diri->pick_dirfrag(p->first.first));
	  assert(dir); 
	  assert(dir->is_auth());
	  dn = dir->lookup(p->first.first, p->first.second);
	}

	if (!dn) 
	  dout(0) << "  missing dentry for " << p->first.first << " snap " << p->first.second << " in " << *dir << dendl;
	assert(dn);
	
	if (nonce == dn->get_replica_nonce(from)) {
	  dout(7) << "  dentry_expire on " << *dn << " from mds." << from << dendl;
	  dentry_remove_replica(dn, from, gather_locks);
	} 
	else {
	  dout(7) << "  dentry_expire on " << *dn << " from mds." << from
		  << " with old nonce " << nonce << " (current " << dn->get_replica_nonce(from)
		  << "), dropping" << dendl;
	}
      }
    }
  }

  for (set<SimpleLock*>::iterator p = gather_locks.begin(); p != gather_locks.end(); ++p)
    mds->locker->eval_gather(*p);

  // done
  m->put();
}

void MDCache::process_delayed_expire(CDir *dir)
{
  dout(7) << "process_delayed_expire on " << *dir << dendl;
  for (map<int,MCacheExpire*>::iterator p = delayed_expire[dir].begin();
       p != delayed_expire[dir].end();
       ++p) 
    handle_cache_expire(p->second);
  delayed_expire.erase(dir);  
}

void MDCache::discard_delayed_expire(CDir *dir)
{
  dout(7) << "discard_delayed_expire on " << *dir << dendl;
  for (map<int,MCacheExpire*>::iterator p = delayed_expire[dir].begin();
       p != delayed_expire[dir].end();
       ++p) 
    p->second->put();
  delayed_expire.erase(dir);  
}

void MDCache::inode_remove_replica(CInode *in, int from, set<SimpleLock *>& gather_locks)
{
  in->remove_replica(from);
  in->mds_caps_wanted.erase(from);
  
  // note: this code calls _eval more often than it needs to!
  // fix lock
  if (in->authlock.remove_replica(from)) gather_locks.insert(&in->authlock);
  if (in->linklock.remove_replica(from)) gather_locks.insert(&in->linklock);
  if (in->dirfragtreelock.remove_replica(from)) gather_locks.insert(&in->dirfragtreelock);
  if (in->filelock.remove_replica(from)) gather_locks.insert(&in->filelock);
  if (in->snaplock.remove_replica(from)) gather_locks.insert(&in->snaplock);
  if (in->xattrlock.remove_replica(from)) gather_locks.insert(&in->xattrlock);

  if (in->nestlock.remove_replica(from)) gather_locks.insert(&in->nestlock);
  if (in->flocklock.remove_replica(from)) gather_locks.insert(&in->flocklock);
  if (in->policylock.remove_replica(from)) gather_locks.insert(&in->policylock);
}

void MDCache::dentry_remove_replica(CDentry *dn, int from, set<SimpleLock *>& gather_locks)
{
  dn->remove_replica(from);

  // fix lock
  if (dn->lock.remove_replica(from))
    gather_locks.insert(&dn->lock);
}

void MDCache::trim_client_leases()
{
  utime_t now = ceph_clock_now(g_ceph_context);
  
  dout(10) << "trim_client_leases" << dendl;

  for (int pool=0; pool<client_lease_pools; pool++) {
    int before = client_leases[pool].size();
    if (client_leases[pool].empty()) 
      continue;

    while (!client_leases[pool].empty()) {
      ClientLease *r = client_leases[pool].front();
      if (r->ttl > now) break;
      CDentry *dn = static_cast<CDentry*>(r->parent);
      dout(10) << " expiring client." << r->client << " lease of " << *dn << dendl;
      dn->remove_client_lease(r, mds->locker);
    }
    int after = client_leases[pool].size();
    dout(10) << "trim_client_leases pool " << pool << " trimmed "
	     << (before-after) << " leases, " << after << " left" << dendl;
  }
}


void MDCache::check_memory_usage()
{
  static MemoryModel mm(g_ceph_context);
  static MemoryModel::snap last;
  mm.sample(&last);
  static MemoryModel::snap baseline = last;

  // check client caps
  int num_inodes = inode_map.size();
  float caps_per_inode = (float)num_caps / (float)num_inodes;
  //float cap_rate = (float)num_inodes_with_caps / (float)inode_map.size();

  dout(2) << "check_memory_usage"
	   << " total " << last.get_total()
	   << ", rss " << last.get_rss()
	   << ", heap " << last.get_heap()
	   << ", malloc " << last.malloc << " mmap " << last.mmap
	   << ", baseline " << baseline.get_heap()
	   << ", buffers " << (buffer::get_total_alloc() >> 10)
	   << ", max " << g_conf->mds_mem_max
	   << ", " << num_inodes_with_caps << " / " << inode_map.size() << " inodes have caps"
	   << ", " << num_caps << " caps, " << caps_per_inode << " caps per inode"
	   << dendl;

  mds->mlogger->set(l_mdm_rss, last.get_rss());
  mds->mlogger->set(l_mdm_heap, last.get_heap());
  mds->mlogger->set(l_mdm_malloc, last.malloc);

  /*int size = last.get_total();
  if (size > g_conf->mds_mem_max * .9) {
    float ratio = (float)g_conf->mds_mem_max * .9 / (float)size;
    if (ratio < 1.0)
      mds->server->recall_client_state(ratio);
  } else 
    */
  if (num_inodes_with_caps > g_conf->mds_cache_size) {
    float ratio = (float)g_conf->mds_cache_size * .9 / (float)num_inodes_with_caps;
    if (ratio < 1.0)
      mds->server->recall_client_state(ratio);
  }

}



// =========================================================================================
// shutdown

class C_MDC_ShutdownCheck : public Context {
  MDCache *mdc;
public:
  C_MDC_ShutdownCheck(MDCache *m) : mdc(m) {}
  void finish(int) {
    mdc->shutdown_check();
  }
};

void MDCache::shutdown_check()
{
  dout(0) << "shutdown_check at " << ceph_clock_now(g_ceph_context) << dendl;

  // cache
  char old_val[32] = { 0 };
  char *o = old_val;
  g_conf->get_val("debug_mds", &o, sizeof(old_val));
  g_conf->set_val("debug_mds", "10");
  g_conf->apply_changes(NULL);
  show_cache();
  g_conf->set_val("debug_mds", old_val);
  g_conf->apply_changes(NULL);
  mds->timer.add_event_after(g_conf->mds_shutdown_check, new C_MDC_ShutdownCheck(this));

  // this
  dout(0) << "lru size now " << lru.lru_get_size() << dendl;
  dout(0) << "log len " << mds->mdlog->get_num_events() << dendl;


  if (mds->objecter->is_active()) {
    dout(0) << "objecter still active" << dendl;
    mds->objecter->dump_active();
  }
}


void MDCache::shutdown_start()
{
  dout(2) << "shutdown_start" << dendl;

  if (g_conf->mds_shutdown_check)
    mds->timer.add_event_after(g_conf->mds_shutdown_check, new C_MDC_ShutdownCheck(this));

  //  g_conf->debug_mds = 10;
}



bool MDCache::shutdown_pass()
{
  dout(7) << "shutdown_pass" << dendl;

  if (mds->is_stopped()) {
    dout(7) << " already shut down" << dendl;
    show_cache();
    show_subtrees();
    return true;
  }

  // close out any sessions (and open files!) before we try to trim the log, etc.
  if (!mds->server->terminating_sessions &&
      mds->sessionmap.have_unclosed_sessions()) {
    mds->server->terminate_sessions();
    return false;
  }


  // flush what we can from the log
  mds->mdlog->trim(0);

  if (mds->mdlog->get_num_segments() > 1) {
    dout(7) << "still >1 segments, waiting for log to trim" << dendl;
    return false;
  }

  // empty stray dir
  if (!shutdown_export_strays()) {
    dout(7) << "waiting for strays to migrate" << dendl;
    return false;
  }
  
  // drop our reference to our stray dir inode
  for (int i = 0; i < NUM_STRAY; ++i) {
    if (strays[i] &&
	strays[i]->state_test(CInode::STATE_STRAYPINNED)) {
      strays[i]->state_clear(CInode::STATE_STRAYPINNED);
      strays[i]->put(CInode::PIN_STRAY);
      strays[i]->put_stickydirs();
    }
  }

  // trim cache
  trim(0);
  dout(5) << "lru size now " << lru.lru_get_size() << dendl;

  // SUBTREES
  if (!subtrees.empty() &&
      mds->get_nodeid() != 0 && 
      !migrator->is_exporting() //&&
      //!migrator->is_importing()
      ) {
    dout(7) << "looking for subtrees to export to mds0" << dendl;
    list<CDir*> ls;
    for (map<CDir*, set<CDir*> >::iterator it = subtrees.begin();
         it != subtrees.end();
         ++it) {
      CDir *dir = it->first;
      if (dir->get_inode()->is_mdsdir())
	continue;
      if (dir->is_frozen() || dir->is_freezing())
	continue;
      if (!dir->is_full_dir_auth())
	continue;
      ls.push_back(dir);
    }
    int max = 5; // throttle shutdown exports.. hack!
    for (list<CDir*>::iterator p = ls.begin(); p != ls.end(); ++p) {
      CDir *dir = *p;
      int dest = dir->get_inode()->authority().first;
      if (dest > 0 && !mds->mdsmap->is_active(dest))
	dest = 0;
      dout(7) << "sending " << *dir << " back to mds." << dest << dendl;
      migrator->export_dir(dir, dest);
      if (--max == 0)
	break;
    }
  }

  if (!shutdown_export_caps()) {
    dout(7) << "waiting for residual caps to export" << dendl;
    return false;
  }

  // make mydir subtree go away
  if (myin) {
    CDir *mydir = myin->get_dirfrag(frag_t());
    if (mydir && mydir->is_subtree_root()) {
      adjust_subtree_auth(mydir, CDIR_AUTH_UNKNOWN);
      remove_subtree(mydir);
    }
  }
  
  // subtrees map not empty yet?
  if (!subtrees.empty()) {
    dout(7) << "still have " << num_subtrees() << " subtrees" << dendl;
    show_subtrees();
    migrator->show_importing();
    migrator->show_exporting();
    if (!migrator->is_importing() && !migrator->is_exporting())
      show_cache();
    return false;
  }
  assert(subtrees.empty());
  assert(!migrator->is_exporting());
  assert(!migrator->is_importing());

  // (only do this once!)
  if (!mds->mdlog->is_capped()) {
    dout(7) << "capping the log" << dendl;
    mds->mdlog->cap();
    mds->mdlog->trim();
  }
  
  if (!mds->mdlog->empty()) {
    dout(7) << "waiting for log to flush.. " << mds->mdlog->get_num_events() 
	    << " in " << mds->mdlog->get_num_segments() << " segments" << dendl;
    return false;
  }
  
  if (!did_shutdown_log_cap) {
    // flush journal header
    dout(7) << "writing header for (now-empty) journal" << dendl;
    assert(mds->mdlog->empty());
    mds->mdlog->write_head(0);  
    // NOTE: filer active checker below will block us until this completes.
    did_shutdown_log_cap = true;
    return false;
  }

  // filer active?
  if (mds->objecter->is_active()) {
    dout(7) << "objecter still active" << dendl;
    mds->objecter->dump_active();
    return false;
  }

  // trim what we can from the cache
  if (lru.lru_get_size() > 0) {
    dout(7) << "there's still stuff in the cache: " << lru.lru_get_size() << dendl;
    show_cache();
    //dump();
    return false;
  } 
  
  // done!
  dout(2) << "shutdown done." << dendl;
  return true;
}

bool MDCache::shutdown_export_strays()
{
  if (mds->get_nodeid() == 0) return true;
  
  dout(10) << "shutdown_export_strays" << dendl;

  bool done = true;
  static set<inodeno_t> exported_strays;

  list<CDir*> dfs;
  for (int i = 0; i < NUM_STRAY; ++i) {
    if (!strays[i]) {
      continue;
    }
    strays[i]->get_dirfrags(dfs);
  }
  
  while (!dfs.empty()) {
    CDir *dir = dfs.front();
    dfs.pop_front();

    if (!dir->is_complete()) {
      dir->fetch(0);
      done = false;
    }
    
    for (CDir::map_t::iterator p = dir->items.begin();
	 p != dir->items.end();
	 ++p) {
      CDentry *dn = p->second;
      CDentry::linkage_t *dnl = dn->get_linkage();
      if (dnl->is_null()) continue;
      done = false;
      
      // FIXME: we'll deadlock if a rename fails.
      if (exported_strays.count(dnl->get_inode()->ino()) == 0) {
	exported_strays.insert(dnl->get_inode()->ino());
	migrate_stray(dn, 0);  // send to root!
      } else {
	dout(10) << "already exporting " << *dn << dendl;
      }
    }
  }

  return done;
}

bool MDCache::shutdown_export_caps()
{
  // export caps?
  //  note: this runs more often than it should.
  static bool exported_caps = false;
  static set<CDir*> exported_caps_in;
  if (!exported_caps) {
    dout(7) << "searching for caps to export" << dendl;
    exported_caps = true;

    list<CDir*> dirq;
    for (map<CDir*,set<CDir*> >::iterator p = subtrees.begin();
	 p != subtrees.end();
	 ++p) {
      if (exported_caps_in.count(p->first)) continue;
      if (p->first->is_auth() ||
	  p->first->is_ambiguous_auth())
	exported_caps = false; // we'll have to try again
      else {
	dirq.push_back(p->first);
	exported_caps_in.insert(p->first);
      }
    }
    while (!dirq.empty()) {
      CDir *dir = dirq.front();
      dirq.pop_front();
      for (CDir::map_t::iterator p = dir->items.begin();
	   p != dir->items.end();
	   ++p) {
	CDentry *dn = p->second;
	CDentry::linkage_t *dnl = dn->get_linkage();
	if (!dnl->is_primary()) continue;
	CInode *in = dnl->get_inode();
	if (in->is_dir())
	  in->get_nested_dirfrags(dirq);
	if (in->is_any_caps() && !in->state_test(CInode::STATE_EXPORTINGCAPS))
	  migrator->export_caps(in);
      }
    }
  }

  return true;
}





// ========= messaging ==============

/* This function DOES put the passed message before returning */
void MDCache::dispatch(Message *m)
{
  switch (m->get_type()) {

    // RESOLVE
  case MSG_MDS_RESOLVE:
    handle_resolve(static_cast<MMDSResolve*>(m));
    break;
  case MSG_MDS_RESOLVEACK:
    handle_resolve_ack(static_cast<MMDSResolveAck*>(m));
    break;

    // REJOIN
  case MSG_MDS_CACHEREJOIN:
    handle_cache_rejoin(static_cast<MMDSCacheRejoin*>(m));
    break;

  case MSG_MDS_DISCOVER:
    handle_discover(static_cast<MDiscover*>(m));
    break;
  case MSG_MDS_DISCOVERREPLY:
    handle_discover_reply(static_cast<MDiscoverReply*>(m));
    break;

  case MSG_MDS_DIRUPDATE:
    handle_dir_update(static_cast<MDirUpdate*>(m));
    break;

  case MSG_MDS_CACHEEXPIRE:
    handle_cache_expire(static_cast<MCacheExpire*>(m));
    break;

  case MSG_MDS_DENTRYLINK:
    handle_dentry_link(static_cast<MDentryLink*>(m));
    break;
  case MSG_MDS_DENTRYUNLINK:
    handle_dentry_unlink(static_cast<MDentryUnlink*>(m));
    break;

  case MSG_MDS_FRAGMENTNOTIFY:
    handle_fragment_notify(static_cast<MMDSFragmentNotify*>(m));
    break;

  case MSG_MDS_FINDINO:
    handle_find_ino(static_cast<MMDSFindIno *>(m));
    break;
  case MSG_MDS_FINDINOREPLY:
    handle_find_ino_reply(static_cast<MMDSFindInoReply *>(m));
    break;

  case MSG_MDS_OPENINO:
    handle_open_ino(static_cast<MMDSOpenIno *>(m));
    break;
  case MSG_MDS_OPENINOREPLY:
    handle_open_ino_reply(static_cast<MMDSOpenInoReply *>(m));
    break;
    
  default:
    dout(7) << "cache unknown message " << m->get_type() << dendl;
    assert(0);
    m->put();
    break;
  }
}

Context *MDCache::_get_waiter(MDRequest *mdr, Message *req, Context *fin)
{
  if (mdr) {
    dout(20) << "_get_waiter retryrequest" << dendl;
    return new C_MDS_RetryRequest(this, mdr);
  } else if (req) {
    dout(20) << "_get_waiter retrymessage" << dendl;
    return new C_MDS_RetryMessage(mds, req);
  } else {
    return fin;
  }
}

int MDCache::path_traverse(MDRequest *mdr, Message *req, Context *fin,     // who
			   const filepath& path,                   // what
                           vector<CDentry*> *pdnvec,         // result
			   CInode **pin,
                           int onfail)
{
  bool discover = (onfail == MDS_TRAVERSE_DISCOVER);
  bool null_okay = (onfail == MDS_TRAVERSE_DISCOVERXLOCK);
  bool forward = (onfail == MDS_TRAVERSE_FORWARD);

  assert(mdr || req || fin);
  assert(!forward || mdr || req);  // forward requires a request

  snapid_t snapid = CEPH_NOSNAP;
  if (mdr)
    mdr->snapid = snapid;

  client_t client = (mdr && mdr->reqid.name.is_client()) ? mdr->reqid.name.num() : -1;

  if (mds->logger) mds->logger->inc(l_mds_t);

  dout(7) << "traverse: opening base ino " << path.get_ino() << " snap " << snapid << dendl;
  CInode *cur = get_inode(path.get_ino());
  if (cur == NULL) {
    if (MDS_INO_IS_MDSDIR(path.get_ino())) 
      open_foreign_mdsdir(path.get_ino(), _get_waiter(mdr, req, fin));
    else {
      //assert(0);  // hrm.. broken
      return -ESTALE;
    }
    return 1;
  }
  if (cur->state_test(CInode::STATE_PURGING))
    return -ESTALE;

  // start trace
  if (pdnvec)
    pdnvec->clear();
  if (pin)
    *pin = cur;

  unsigned depth = 0;
  while (depth < path.depth()) {
    dout(12) << "traverse: path seg depth " << depth << " '" << path[depth]
	     << "' snapid " << snapid << dendl;
    
    if (!cur->is_dir()) {
      dout(7) << "traverse: " << *cur << " not a dir " << dendl;
      return -ENOTDIR;
    }

    // walk into snapdir?
    if (path[depth].length() == 0) {
      dout(10) << "traverse: snapdir" << dendl;
      if (!mdr)
	return -EINVAL;
      snapid = CEPH_SNAPDIR;
      mdr->snapid = snapid;
      depth++;
      continue;
    }
    // walk thru snapdir?
    if (snapid == CEPH_SNAPDIR) {
      if (!mdr)
	return -EINVAL;
      SnapRealm *realm = cur->find_snaprealm();
      snapid = realm->resolve_snapname(path[depth], cur->ino());
      dout(10) << "traverse: snap " << path[depth] << " -> " << snapid << dendl;
      if (!snapid)
	return -ENOENT;
      mdr->snapid = snapid;
      depth++;
      continue;
    }

    // open dir
    frag_t fg = cur->pick_dirfrag(path[depth]);
    CDir *curdir = cur->get_dirfrag(fg);
    if (!curdir) {
      if (cur->is_auth()) {
        // parent dir frozen_dir?
        if (cur->is_frozen()) {
          dout(7) << "traverse: " << *cur << " is frozen, waiting" << dendl;
          cur->add_waiter(CDir::WAIT_UNFREEZE, _get_waiter(mdr, req, fin));
          return 1;
        }
        curdir = cur->get_or_open_dirfrag(this, fg);
      } else {
        // discover?
	dout(10) << "traverse: need dirfrag " << fg << ", doing discover from " << *cur << dendl;
	discover_path(cur, snapid, path.postfixpath(depth), _get_waiter(mdr, req, fin),
		      null_okay);
	if (mds->logger) mds->logger->inc(l_mds_tdis);
        return 1;
      }
    }
    assert(curdir);

#ifdef MDS_VERIFY_FRAGSTAT
    if (curdir->is_complete())
      curdir->verify_fragstat();
#endif

    // frozen?
    /*
    if (curdir->is_frozen()) {
    // doh!
      // FIXME: traverse is allowed?
      dout(7) << "traverse: " << *curdir << " is frozen, waiting" << dendl;
      curdir->add_waiter(CDir::WAIT_UNFREEZE, _get_waiter(mdr, req, fin));
      if (onfinish) delete onfinish;
      return 1;
    }
    */

    // must read directory hard data (permissions, x bit) to traverse
#if 0    
    if (!noperm && 
	!mds->locker->rdlock_try(&cur->authlock, client, 0)) {
      dout(7) << "traverse: waiting on authlock rdlock on " << *cur << dendl;
      cur->authlock.add_waiter(SimpleLock::WAIT_RD, _get_waiter(mdr, req, fin));
      return 1;
    }
#endif
    

    // make sure snaprealm parents are open...
    if (cur->snaprealm && !cur->snaprealm->open && mdr &&
	!cur->snaprealm->open_parents(_get_waiter(mdr, req, fin))) {
      return 1;
    }


    // dentry
    CDentry *dn = curdir->lookup(path[depth], snapid);
    CDentry::linkage_t *dnl = dn ? dn->get_projected_linkage() : 0;

    // null and last_bit and xlocked by me?
    if (dnl && dnl->is_null() && null_okay) {
      dout(10) << "traverse: hit null dentry at tail of traverse, succeeding" << dendl;
      if (pdnvec)
	pdnvec->push_back(dn);
      if (pin)
	*pin = 0;
      break; // done!
    }

    if (dnl &&
	dn->lock.is_xlocked() &&
	dn->lock.get_xlock_by() != mdr &&
	!dn->lock.can_read(client) &&
	(dnl->is_null() || forward)) {
      dout(10) << "traverse: xlocked dentry at " << *dn << dendl;
      dn->lock.add_waiter(SimpleLock::WAIT_RD, _get_waiter(mdr, req, fin));
      if (mds->logger) mds->logger->inc(l_mds_tlock);
      mds->mdlog->flush();
      return 1;
    }
    
    // can we conclude ENOENT?
    if (dnl && dnl->is_null()) {
      if (dn->lock.can_read(client) ||
	  (dn->lock.is_xlocked() && dn->lock.get_xlock_by() == mdr)) {
        dout(10) << "traverse: miss on null+readable dentry " << path[depth] << " " << *dn << dendl;
        return -ENOENT;
      } else {
        dout(10) << "miss on dentry " << *dn << ", can't read due to lock" << dendl;
        dn->lock.add_waiter(SimpleLock::WAIT_RD, _get_waiter(mdr, req, fin));
        return 1;
      }
    }

    if (dnl && !dnl->is_null()) {
      CInode *in = dnl->get_inode();
      
      // do we have inode?
      if (!in) {
        assert(dnl->is_remote());
        // do i have it?
        in = get_inode(dnl->get_remote_ino());
        if (in) {
	  dout(7) << "linking in remote in " << *in << dendl;
	  dn->link_remote(dnl, in);
	} else {
          dout(7) << "remote link to " << dnl->get_remote_ino() << ", which i don't have" << dendl;
	  assert(mdr);  // we shouldn't hit non-primary dentries doing a non-mdr traversal!
          open_remote_dentry(dn, true, _get_waiter(mdr, req, fin),
			     (null_okay && depth == path.depth() - 1));
	  if (mds->logger) mds->logger->inc(l_mds_trino);
          return 1;
        }        
      }

      // forwarder wants replicas?
#if 0
      if (mdr && mdr->client_request && 
	  mdr->client_request->get_mds_wants_replica_in_dirino()) {
	dout(30) << "traverse: REP is here, " 
		 << mdr->client_request->get_mds_wants_replica_in_dirino() 
		 << " vs " << curdir->dirfrag() << dendl;
	
	if (mdr->client_request->get_mds_wants_replica_in_dirino() == curdir->ino() &&
	    curdir->is_auth() && 
	    curdir->is_rep() &&
	    curdir->is_replica(req->get_source().num()) &&
	    dn->is_auth()
	    ) {
	  assert(req->get_source().is_mds());
	  int from = req->get_source().num();
	  
	  if (dn->is_replica(from)) {
	    dout(15) << "traverse: REP would replicate to mds." << from << ", but already cached_by " 
		     << req->get_source() << " dn " << *dn << dendl; 
	  } else {
	    dout(10) << "traverse: REP replicating to " << req->get_source() << " dn " << *dn << dendl;
	    MDiscoverReply *reply = new MDiscoverReply(curdir->dirfrag());
	    reply->mark_unsolicited();
	    reply->starts_with = MDiscoverReply::DENTRY;
	    replicate_dentry(dn, from, reply->trace);
	    if (dnl->is_primary())
	      replicate_inode(in, from, reply->trace);
	    if (req->get_source() != req->get_orig_source())
	      mds->send_message_mds(reply, req->get_source().num());
	    else mds->send_message(reply->req->get_connnection());
	  }
	}
      }
#endif
      
      // add to trace, continue.
      cur = in;
      touch_inode(cur);
      if (pdnvec)
	pdnvec->push_back(dn);
      if (pin)
	*pin = cur;
      depth++;
      continue;
    }
    

    // MISS.  dentry doesn't exist.
    dout(12) << "traverse: miss on dentry " << path[depth] << " in " << *curdir << dendl;

    if (curdir->is_auth()) {
      // dentry is mine.
      if (curdir->is_complete() || (curdir->has_bloom() &&
          !curdir->is_in_bloom(path[depth]))){
        // file not found
	if (pdnvec) {
	  // instantiate a null dn?
	  if (depth < path.depth()-1){
	    dout(20) << " didn't traverse full path; not returning pdnvec" << dendl;
	    dn = NULL;
	  } else if (dn) {
	    assert(0); // should have fallen out in ->is_null() check above
	  } else if (curdir->is_frozen()) {
	    dout(20) << " not adding null to frozen dir " << dendl;
	  } else if (snapid < CEPH_MAXSNAP) {
	    dout(20) << " not adding null for snapid " << snapid << dendl;
	  } else {
	    // create a null dentry
	    dn = curdir->add_null_dentry(path[depth]);
	    dout(20) << " added null " << *dn << dendl;
	  }
	  if (dn)
	    pdnvec->push_back(dn);
	  else
	    pdnvec->clear();   // do not confuse likes of rdlock_path_pin_ref();
	}
        return -ENOENT;
      } else {
	// directory isn't complete; reload
        dout(7) << "traverse: incomplete dir contents for " << *cur << ", fetching" << dendl;
        touch_inode(cur);
        curdir->fetch(_get_waiter(mdr, req, fin), path[depth]);
	if (mds->logger) mds->logger->inc(l_mds_tdirf);
        return 1;
      }
    } else {
      // dirfrag/dentry is not mine.
      pair<int,int> dauth = curdir->authority();

      if (forward &&
	  snapid && mdr && mdr->client_request &&
	  (int)depth < mdr->client_request->get_num_fwd()) {
	dout(7) << "traverse: snap " << snapid << " and depth " << depth
		<< " < fwd " << mdr->client_request->get_num_fwd()
		<< ", discovering instead of forwarding" << dendl;
	discover = true;
      }

      if ((discover || null_okay)) {
	dout(7) << "traverse: discover from " << path[depth] << " from " << *curdir << dendl;
	discover_path(curdir, snapid, path.postfixpath(depth), _get_waiter(mdr, req, fin),
		      null_okay);
	if (mds->logger) mds->logger->inc(l_mds_tdis);
        return 1;
      } 
      if (forward) {
        // forward
        dout(7) << "traverse: not auth for " << path << " in " << *curdir << dendl;
	
	if (curdir->is_ambiguous_auth()) {
	  // wait
	  dout(7) << "traverse: waiting for single auth in " << *curdir << dendl;
	  curdir->add_waiter(CDir::WAIT_SINGLEAUTH, _get_waiter(mdr, req, fin));
	  return 1;
	} 

	dout(7) << "traverse: forwarding, not auth for " << *curdir << dendl;
	
#if 0
	// request replication?
	if (mdr && mdr->client_request && curdir->is_rep()) {
	  dout(15) << "traverse: REP fw to mds." << dauth << ", requesting rep under "
		   << *curdir << " req " << *(MClientRequest*)req << dendl;
	  mdr->client_request->set_mds_wants_replica_in_dirino(curdir->ino());
	  req->clear_payload();  // reencode!
	}
#endif
	
	if (mdr) 
	  request_forward(mdr, dauth.first);
	else
	  mds->forward_message_mds(req, dauth.first);
	
	if (mds->logger) mds->logger->inc(l_mds_tfw);
	assert(fin == NULL);
	return 2;
      }    
    }
    
    assert(0);  // i shouldn't get here
  }
  
  // success.
  if (mds->logger) mds->logger->inc(l_mds_thit);
  dout(10) << "path_traverse finish on snapid " << snapid << dendl;
  if (mdr) 
    assert(mdr->snapid == snapid);
  return 0;
}

#if 0
/**
 * Find out if the MDS is auth for a given path.
 *
 * Returns true if:
 * 1) The full path DNE and we are auth for the deepest existing piece
 * 2) We are auth for the inode linked to by the last dentry.
 */
bool MDCache::path_is_mine(filepath& path)
{
  dout(15) << "path_is_mine " << path.get_ino() << " " << path << dendl;
  
  CInode *cur = get_inode(path.get_ino());
  if (!cur)
    return false;  // who knows!

  for (unsigned i=0; i<path.depth(); i++) {
    dout(15) << "path_is_mine seg " << i << ": " << path[i] << " under " << *cur << dendl;
    frag_t fg = cur->pick_dirfrag(path[i]);
    CDir *dir = cur->get_dirfrag(fg);
    if (!dir)
      return cur->is_auth();
    CDentry *dn = dir->lookup(path[i]);
    CDentry::linkage_t *dnl = dn->get_linkage();
    if (!dn || dnl->is_null())
      return dir->is_auth();
    if (!dnl->is_primary())
      return false;
    cur = dnl->get_inode();
  }

  return cur->is_auth();
}
#endif

CInode *MDCache::cache_traverse(const filepath& fp)
{
  dout(10) << "cache_traverse " << fp << dendl;

  CInode *in;
  if (fp.get_ino())
    in = get_inode(fp.get_ino());
  else
    in = root;
  if (!in)
    return NULL;

  for (unsigned i = 0; i < fp.depth(); i++) {
    const string& dname = fp[i];
    frag_t fg = in->pick_dirfrag(dname);
    dout(20) << " " << i << " " << dname << " frag " << fg << " from " << *in << dendl;
    CDir *curdir = in->get_dirfrag(fg);
    if (!curdir)
      return NULL;
    CDentry *dn = curdir->lookup(dname, CEPH_NOSNAP);
    if (!dn)
      return NULL;
    in = dn->get_linkage()->get_inode();
    if (!in)
      return NULL;
  }
  dout(10) << " got " << *in << dendl;
  return in;
}


/**
 * open_remote_dir -- open up a remote dirfrag
 *
 * @param diri base inode
 * @param approxfg approximate fragment.
 * @param fin completion callback
 */
void MDCache::open_remote_dirfrag(CInode *diri, frag_t approxfg, Context *fin) 
{
  dout(10) << "open_remote_dir on " << *diri << dendl;
  
  assert(diri->is_dir());
  assert(!diri->is_auth());
  assert(diri->get_dirfrag(approxfg) == 0);

  int auth = diri->authority().first;

  if (mds->mdsmap->get_state(auth) >= MDSMap::STATE_REJOIN) {
    discover_dir_frag(diri, approxfg, fin);
  } else {
    // mds is down or recovering.  forge a replica!
    forge_replica_dir(diri, approxfg, auth);
    if (fin)
      mds->queue_waiter(fin);
  }
}


/** 
 * get_dentry_inode - get or open inode
 *
 * @param dn the dentry
 * @param mdr current request
 *
 * will return inode for primary, or link up/open up remote link's inode as necessary.
 * If it's not available right now, puts mdr on wait list and returns null.
 */
CInode *MDCache::get_dentry_inode(CDentry *dn, MDRequest *mdr, bool projected)
{
  CDentry::linkage_t *dnl;
  if (projected)
    dnl = dn->get_projected_linkage();
  else
    dnl = dn->get_linkage();

  assert(!dnl->is_null());
  
  if (dnl->is_primary())
    return dnl->inode;

  assert(dnl->is_remote());
  CInode *in = get_inode(dnl->get_remote_ino());
  if (in) {
    dout(7) << "get_dentry_inode linking in remote in " << *in << dendl;
    dn->link_remote(dnl, in);
    return in;
  } else {
    dout(10) << "get_dentry_inode on remote dn, opening inode for " << *dn << dendl;
    open_remote_ino(dnl->remote_ino, new C_MDS_RetryRequest(this, mdr));
    return 0;
  }
}

class C_MDC_RetryOpenRemoteIno : public Context {
  MDCache *mdcache;
  inodeno_t ino;
  bool want_xlocked;
  Context *onfinish;
public:
  C_MDC_RetryOpenRemoteIno(MDCache *mdc, inodeno_t i, Context *c, bool wx) :
    mdcache(mdc), ino(i), want_xlocked(wx), onfinish(c) {}
  void finish(int r) {
    if (mdcache->get_inode(ino)) {
      onfinish->complete(0);
    } else
      mdcache->open_remote_ino(ino, onfinish, want_xlocked);
  }
};


class C_MDC_OpenRemoteIno : public Context {
  MDCache *mdcache;
  inodeno_t ino;
  inodeno_t hadino;
  version_t hadv;
  bool want_xlocked;
  Context *onfinish;
public:
  vector<Anchor> anchortrace;

  C_MDC_OpenRemoteIno(MDCache *mdc, inodeno_t i, bool wx, inodeno_t hi, version_t hv, Context *c) :
    mdcache(mdc), ino(i), hadino(hi), hadv(hv), want_xlocked(wx), onfinish(c) {}
  C_MDC_OpenRemoteIno(MDCache *mdc, inodeno_t i, bool wx, vector<Anchor>& at, Context *c) :
    mdcache(mdc), ino(i), hadino(0), hadv(0), want_xlocked(wx), onfinish(c), anchortrace(at) {}

  void finish(int r) {
    assert(r == 0);
    if (r == 0)
      mdcache->open_remote_ino_2(ino, anchortrace, want_xlocked, hadino, hadv, onfinish);
    else {
      onfinish->complete(r);
    }
  }
};

void MDCache::open_remote_ino(inodeno_t ino, Context *onfinish, bool want_xlocked,
			      inodeno_t hadino, version_t hadv)
{
  dout(7) << "open_remote_ino on " << ino << (want_xlocked ? " want_xlocked":"") << dendl;
  
  C_MDC_OpenRemoteIno *c = new C_MDC_OpenRemoteIno(this, ino, want_xlocked,
						   hadino, hadv, onfinish);
  mds->anchorclient->lookup(ino, c->anchortrace, c);
}

void MDCache::open_remote_ino_2(inodeno_t ino, vector<Anchor>& anchortrace, bool want_xlocked,
				inodeno_t hadino, version_t hadv, Context *onfinish)
{
  dout(7) << "open_remote_ino_2 on " << ino
	  << ", trace depth is " << anchortrace.size() << dendl;
  
  // find deepest cached inode in prefix
  unsigned i = anchortrace.size();  // i := array index + 1
  CInode *in = 0;
  while (1) {
    // inode?
    dout(10) << " " << i << ": " << anchortrace[i-1] << dendl;
    in = get_inode(anchortrace[i-1].ino);
    if (in)
      break;
    i--;
    if (!i) {
      in = get_inode(anchortrace[i].dirino);
      if (!in) {
	dout(0) << "open_remote_ino_2 don't have dir inode " << anchortrace[i].dirino << dendl;
	if (MDS_INO_IS_MDSDIR(anchortrace[i].dirino)) {
	  open_foreign_mdsdir(anchortrace[i].dirino, onfinish);
	  return;
	}
	assert(in);  // hrm!
      }
      break;
    }
  }
  dout(10) << "deepest cached inode at " << i << " is " << *in << dendl;

  if (in->ino() == ino) {
    // success
    dout(10) << "open_remote_ino_2 have " << *in << dendl;
    onfinish->complete(0);
    return;
  } 

  // open dirfrag beneath *in
  frag_t frag = in->dirfragtree[anchortrace[i].dn_hash];

  if (!in->dirfragtree.contains(frag)) {
    dout(10) << "frag " << frag << " not valid, requerying anchortable" << dendl;
    open_remote_ino(ino, onfinish, want_xlocked);
    return;
  }

  CDir *dir = in->get_dirfrag(frag);

  if (!dir && !in->is_auth()) {
    dout(10) << "opening remote dirfrag " << frag << " under " << *in << dendl;
    /* we re-query the anchortable just to avoid a fragtree update race */
    open_remote_dirfrag(in, frag,
			new C_MDC_RetryOpenRemoteIno(this, ino, onfinish, want_xlocked));
    return;
  }

  if (!dir && in->is_auth()) {
    if (in->is_frozen_dir()) {
      dout(7) << "traverse: " << *in << " is frozen_dir, waiting" << dendl;
      in->parent->dir->add_waiter(CDir::WAIT_UNFREEZE,
				  new C_MDC_RetryOpenRemoteIno(this, ino, onfinish, want_xlocked));
      return;
    }
    dir = in->get_or_open_dirfrag(this, frag);
  }
  assert(dir);

  if (dir->is_auth()) {
    if (dir->is_complete()) {
      // make sure we didn't get to the same version anchor 2x in a row
      if (hadv && hadino == anchortrace[i].ino && hadv == anchortrace[i].updated) {
	dout(10) << "expected ino " << anchortrace[i].ino
		 << " in complete dir " << *dir
		 << ", got same anchor " << anchortrace[i] << " 2x in a row" << dendl;
	onfinish->complete(-ENOENT);
      } else {
	// hrm.  requery anchor table.
	dout(10) << "expected ino " << anchortrace[i].ino
		 << " in complete dir " << *dir
		 << ", requerying anchortable"
		 << dendl;
	open_remote_ino(ino, onfinish, want_xlocked,
		        anchortrace[i].ino, anchortrace[i].updated);
      }
    } else {
      dout(10) << "need ino " << anchortrace[i].ino
	       << ", fetching incomplete dir " << *dir
	       << dendl;
      dir->fetch(new C_MDC_OpenRemoteIno(this, ino, want_xlocked, anchortrace, onfinish));
    }
  } else {
    // hmm, discover.
    dout(10) << "have remote dirfrag " << *dir << ", discovering " 
	     << anchortrace[i].ino << dendl;
    discover_ino(dir, anchortrace[i].ino,
	         new C_MDC_RetryOpenRemoteIno(this, ino, onfinish, want_xlocked),
		 (want_xlocked && i == anchortrace.size() - 1));
  }
}


struct C_MDC_OpenRemoteDentry : public Context {
  MDCache *mdc;
  CDentry *dn;
  inodeno_t ino;
  Context *onfinish;
  bool want_xlocked;
  int mode;
  C_MDC_OpenRemoteDentry(MDCache *m, CDentry *d, inodeno_t i, Context *f,
			 bool wx, int md) :
    mdc(m), dn(d), ino(i), onfinish(f), want_xlocked(wx), mode(md) {}
  void finish(int r) {
    mdc->_open_remote_dentry_finish(dn, ino, onfinish, want_xlocked, mode, r);
  }
};

void MDCache::open_remote_dentry(CDentry *dn, bool projected, Context *fin, bool want_xlocked)
{
  dout(10) << "open_remote_dentry " << *dn << dendl;
  CDentry::linkage_t *dnl = projected ? dn->get_projected_linkage() : dn->get_linkage();
  inodeno_t ino = dnl->get_remote_ino();
  int mode = g_conf->mds_open_remote_link_mode;
  Context *fin2 =  new C_MDC_OpenRemoteDentry(this, dn, ino, fin, want_xlocked, mode);
  if (mode == 0)
    open_remote_ino(ino, fin2, want_xlocked); // anchor
  else
    open_ino(ino, -1, fin2, true, want_xlocked); // backtrace
}

void MDCache::_open_remote_dentry_finish(CDentry *dn, inodeno_t ino, Context *fin,
					 bool want_xlocked, int mode, int r)
{
  if (r < 0) {
    if (mode == 0) {
      dout(0) << "open_remote_dentry_finish bad remote dentry " << *dn << dendl;
      dn->state_set(CDentry::STATE_BADREMOTEINO);
    } else {
      dout(7) << "open_remote_dentry_finish failed to open ino " << ino
	      << " for " << *dn << ", retry using anchortable" << dendl;
      assert(mode == 1);
      Context *fin2 =  new C_MDC_OpenRemoteDentry(this, dn, ino, fin, want_xlocked, 0);
      open_remote_ino(ino, fin2, want_xlocked);
      return;
    }
  }
  fin->complete(r < 0 ? r : 0);
}


void MDCache::make_trace(vector<CDentry*>& trace, CInode *in)
{
  // empty trace if we're a base inode
  if (in->is_base())
    return;

  CInode *parent = in->get_parent_inode();
  assert(parent);
  make_trace(trace, parent);

  CDentry *dn = in->get_parent_dn();
  dout(15) << "make_trace adding " << *dn << dendl;
  trace.push_back(dn);
}


// -------------------------------------------------------------------------------
// Open inode by inode number

class C_MDC_OpenInoBacktraceFetched : public Context {
  MDCache *cache;
  inodeno_t ino;
  public:
  bufferlist bl;
  C_MDC_OpenInoBacktraceFetched(MDCache *c, inodeno_t i) :
    cache(c), ino(i) {}
  void finish(int r) {
    cache->_open_ino_backtrace_fetched(ino, bl, r);
  }
};

struct C_MDC_OpenInoTraverseDir : public Context {
  MDCache *cache;
  inodeno_t ino;
  public:
  C_MDC_OpenInoTraverseDir(MDCache *c, inodeno_t i) : cache(c), ino(i) {}
  void finish(int r) {
    assert(cache->opening_inodes.count(ino));
    cache->_open_ino_traverse_dir(ino, cache->opening_inodes[ino], r);
  }
};

struct C_MDC_OpenInoParentOpened : public Context {
  MDCache *cache;
  inodeno_t ino;
  public:
  C_MDC_OpenInoParentOpened(MDCache *c, inodeno_t i) : cache(c), ino(i) {}
  void finish(int r) {
    cache->_open_ino_parent_opened(ino, r);
  }
};

void MDCache::_open_ino_backtrace_fetched(inodeno_t ino, bufferlist& bl, int err)
{
  dout(10) << "_open_ino_backtrace_fetched ino " << ino << " errno " << err << dendl;

  assert(opening_inodes.count(ino));
  open_ino_info_t& info = opening_inodes[ino];

  CInode *in = get_inode(ino);
  if (in) {
    dout(10) << " found cached " << *in << dendl;
    open_ino_finish(ino, info, in->authority().first);
    return;
  }

  inode_backtrace_t backtrace;
  if (err == 0) {
    ::decode(backtrace, bl);
    if (backtrace.pool != info.pool && backtrace.pool != -1) {
      dout(10) << " old object in pool " << info.pool
	       << ", retrying pool " << backtrace.pool << dendl;
      info.pool = backtrace.pool;
      C_MDC_OpenInoBacktraceFetched *fin = new C_MDC_OpenInoBacktraceFetched(this, ino);
      fetch_backtrace(ino, info.pool, fin->bl, fin);
      return;
    }
  } else if (err == -ENOENT) {
    int64_t meta_pool = mds->mdsmap->get_metadata_pool();
    if (info.pool != meta_pool) {
      dout(10) << " no object in pool " << info.pool
	       << ", retrying pool " << meta_pool << dendl;
      info.pool = meta_pool;
      C_MDC_OpenInoBacktraceFetched *fin = new C_MDC_OpenInoBacktraceFetched(this, ino);
      fetch_backtrace(ino, info.pool, fin->bl, fin);
      return;
    }
  }

  if (err == 0) {
    if (backtrace.ancestors.empty()) {
      dout(10) << " got empty backtrace " << dendl;
      err = -EIO;
    } else if (!info.ancestors.empty()) {
      if (info.ancestors[0] == backtrace.ancestors[0]) {
	dout(10) << " got same parents " << info.ancestors[0] << " 2 times" << dendl;
	err = -EINVAL;
      }
    }
  }
  if (err) {
    dout(10) << " failed to open ino " << ino << dendl;
    open_ino_finish(ino, info, err);
    return;
  }

  dout(10) << " got backtrace " << backtrace << dendl;
  info.ancestors = backtrace.ancestors;

  _open_ino_traverse_dir(ino, info, 0);
}

void MDCache::_open_ino_parent_opened(inodeno_t ino, int ret)
{
  dout(10) << "_open_ino_parent_opened ino " << ino << " ret " << ret << dendl;

  assert(opening_inodes.count(ino));
  open_ino_info_t& info = opening_inodes[ino];

  CInode *in = get_inode(ino);
  if (in) {
    dout(10) << " found cached " << *in << dendl;
    open_ino_finish(ino, info, in->authority().first);
    return;
  }

  if (ret == mds->get_nodeid()) {
    _open_ino_traverse_dir(ino, info, 0);
  } else {
    if (ret >= 0) {
      info.check_peers = true;
      info.auth_hint = ret;
      info.checked.erase(ret);
    }
    do_open_ino(ino, info, ret);
  }
}

Context* MDCache::_open_ino_get_waiter(inodeno_t ino, MMDSOpenIno *m)
{
  if (m)
    return new C_MDS_RetryMessage(mds, m);
  else
    return new C_MDC_OpenInoTraverseDir(this, ino);
}

void MDCache::_open_ino_traverse_dir(inodeno_t ino, open_ino_info_t& info, int ret)
{
  dout(10) << "_open_ino_trvserse_dir ino " << ino << " ret " << ret << dendl;

  CInode *in = get_inode(ino);
  if (in) {
    dout(10) << " found cached " << *in << dendl;
    open_ino_finish(ino, info, in->authority().first);
    return;
  }

  if (ret) {
    do_open_ino(ino, info, ret);
    return;
  }

  int hint = info.auth_hint;
  ret = open_ino_traverse_dir(ino, NULL, info.ancestors,
			      info.discover, info.want_xlocked, &hint);
  if (ret > 0)
    return;
  if (hint != mds->get_nodeid())
    info.auth_hint = hint;
  do_open_ino(ino, info, ret);
}

void MDCache::_open_ino_fetch_dir(inodeno_t ino, MMDSOpenIno *m, CDir *dir)
{
  if (dir->state_test(CDir::STATE_REJOINUNDEF) && dir->get_frag() == frag_t()) {
    rejoin_undef_dirfrags.erase(dir);
    dir->state_clear(CDir::STATE_REJOINUNDEF);

    CInode *diri = dir->get_inode();
    diri->force_dirfrags();
    list<CDir*> ls;
    diri->get_dirfrags(ls);

    C_GatherBuilder gather(g_ceph_context, _open_ino_get_waiter(ino, m));
    for (list<CDir*>::iterator p = ls.begin(); p != ls.end(); ++p) {
      rejoin_undef_dirfrags.insert(*p);
      (*p)->state_set(CDir::STATE_REJOINUNDEF);
      (*p)->fetch(gather.new_sub());
    }
    assert(gather.has_subs());
    gather.activate();
  } else
    dir->fetch(_open_ino_get_waiter(ino, m));
}

int MDCache::open_ino_traverse_dir(inodeno_t ino, MMDSOpenIno *m,
				   vector<inode_backpointer_t>& ancestors,
				   bool discover, bool want_xlocked, int *hint)
{
  dout(10) << "open_ino_traverse_dir ino " << ino << " " << ancestors << dendl;
  int err = 0;
  for (unsigned i = 0; i < ancestors.size(); i++) {
    CInode *diri = get_inode(ancestors[i].dirino);

    if (!diri) {
      if (discover && MDS_INO_IS_MDSDIR(ancestors[i].dirino)) {
	open_foreign_mdsdir(ancestors[i].dirino, _open_ino_get_waiter(ino, m));
	return 1;
      }
      continue;
    }

    if (diri->state_test(CInode::STATE_REJOINUNDEF)) {
      CDir *dir = diri->get_parent_dir();
      while (dir->state_test(CDir::STATE_REJOINUNDEF) &&
	     dir->get_inode()->state_test(CInode::STATE_REJOINUNDEF))
	dir = dir->get_inode()->get_parent_dir();
      _open_ino_fetch_dir(ino, m, dir);
      return 1;
    }

    if (!diri->is_dir()) {
      dout(10) << " " << *diri << " is not dir" << dendl;
      if (i == 0)
	err = -ENOTDIR;
      break;
    }

    string &name = ancestors[i].dname;
    frag_t fg = diri->pick_dirfrag(name);
    CDir *dir = diri->get_dirfrag(fg);
    if (!dir) {
      if (diri->is_auth()) {
	if (diri->is_frozen()) {
	  dout(10) << " " << *diri << " is frozen, waiting " << dendl;
	  diri->add_waiter(CDir::WAIT_UNFREEZE, _open_ino_get_waiter(ino, m));
	  return 1;
	}
	dir = diri->get_or_open_dirfrag(this, fg);
      } else if (discover) {
	open_remote_dirfrag(diri, fg, _open_ino_get_waiter(ino, m));
	return 1;
      }
    }
    if (dir) {
      inodeno_t next_ino = i > 0 ? ancestors[i - 1].dirino : ino;
      if (dir->is_auth()) {
	CDentry *dn = dir->lookup(name);
	CDentry::linkage_t *dnl = dn ? dn->get_linkage() : NULL;

	if (dnl && dnl->is_primary() &&
	    dnl->get_inode()->state_test(CInode::STATE_REJOINUNDEF)) {
	  dout(10) << " fetching undef " << *dnl->get_inode() << dendl;
	  _open_ino_fetch_dir(ino, m, dir);
	  return 1;
	}

	if (!dnl && !dir->is_complete() &&
	    (!dir->has_bloom() || dir->is_in_bloom(name))) {
	  dout(10) << " fetching incomplete " << *dir << dendl;
	  _open_ino_fetch_dir(ino, m, dir);
	  return 1;
	}

	dout(10) << " no ino " << next_ino << " in " << *dir << dendl;
	if (i == 0)
	  err = -ENOENT;
      } else if (discover) {
	discover_ino(dir, next_ino, _open_ino_get_waiter(ino, m),
		     (i == 0 && want_xlocked));
	return 1;
      }
    }
    if (hint && i == 0)
      *hint = dir ? dir->authority().first : diri->authority().first;
    break;
  }
  return err;
}

void MDCache::open_ino_finish(inodeno_t ino, open_ino_info_t& info, int ret)
{
  dout(10) << "open_ino_finish ino " << ino << " ret " << ret << dendl;

  finish_contexts(g_ceph_context, info.waiters, ret);
  opening_inodes.erase(ino);
}

void MDCache::do_open_ino(inodeno_t ino, open_ino_info_t& info, int err)
{
  if (err < 0) {
    info.checked.clear();
    info.checked.insert(mds->get_nodeid());
    info.checking = -1;
    info.check_peers = true;
    info.fetch_backtrace = true;
    if (info.discover) {
      info.discover = false;
      info.ancestors.clear();
    }
  }

  if (info.check_peers) {
    info.check_peers = false;
    info.checking = -1;
    do_open_ino_peer(ino, info);
  } else if (info.fetch_backtrace) {
    info.check_peers = true;
    info.fetch_backtrace = false;
    info.checking = mds->get_nodeid();
    info.checked.clear();
    info.checked.insert(mds->get_nodeid());
    C_MDC_OpenInoBacktraceFetched *fin = new C_MDC_OpenInoBacktraceFetched(this, ino);
    fetch_backtrace(ino, info.pool, fin->bl, fin);
  } else {
    assert(!info.ancestors.empty());
    info.checking = mds->get_nodeid();
    open_ino(info.ancestors[0].dirino, mds->mdsmap->get_metadata_pool(),
	     new C_MDC_OpenInoParentOpened(this, ino), info.want_replica);
  }
}

void MDCache::do_open_ino_peer(inodeno_t ino, open_ino_info_t& info)
{
  set<int> all, active;
  mds->mdsmap->get_mds_set(all);
  mds->mdsmap->get_clientreplay_or_active_or_stopping_mds_set(active);
  if (mds->get_state() == MDSMap::STATE_REJOIN)
    mds->mdsmap->get_mds_set(active, MDSMap::STATE_REJOIN);

  dout(10) << "do_open_ino_peer " << ino << " active " << active
	   << " all " << all << " checked " << info.checked << dendl;

  int peer = -1;
  if (info.auth_hint >= 0) {
    if (active.count(info.auth_hint)) {
      peer = info.auth_hint;
      info.auth_hint = -1;
    }
  } else {
    for (set<int>::iterator p = active.begin(); p != active.end(); ++p)
      if (*p != mds->get_nodeid() && info.checked.count(*p) == 0) {
	peer = *p;
	break;
      }
  }
  if (peer < 0) {
    if (all.size() > active.size() && all != info.checked) {
      dout(10) << " waiting for more peers to be active" << dendl;
    } else {
      dout(10) << " all MDS peers have been checked " << dendl;
      do_open_ino(ino, info, 0);
    }
  } else {
    info.checking = peer;
    mds->send_message_mds(new MMDSOpenIno(info.tid, ino, info.ancestors), peer);
  }
}

void MDCache::handle_open_ino(MMDSOpenIno *m)
{
  dout(10) << "handle_open_ino " << *m << dendl;

  inodeno_t ino = m->ino;
  MMDSOpenInoReply *reply;
  CInode *in = get_inode(ino);
  if (in) {
    dout(10) << " have " << *in << dendl;
    reply = new MMDSOpenInoReply(m->get_tid(), ino, 0);
    if (in->is_auth()) {
      touch_inode(in);
      while (1) {
	CDentry *pdn = in->get_parent_dn();
	if (!pdn)
	  break;
	CInode *diri = pdn->get_dir()->get_inode();
	reply->ancestors.push_back(inode_backpointer_t(diri->ino(), pdn->name,
						       in->inode.version));
	in = diri;
      }
    } else {
      reply->hint = in->authority().first;
    }
  } else {
    int hint = -1;
    int ret = open_ino_traverse_dir(ino, m, m->ancestors, false, false, &hint);
    if (ret > 0)
      return;
    reply = new MMDSOpenInoReply(m->get_tid(), ino, hint, ret);
  }
  mds->messenger->send_message(reply, m->get_connection());
  m->put();
}

void MDCache::handle_open_ino_reply(MMDSOpenInoReply *m)
{
  dout(10) << "handle_open_ino_reply " << *m << dendl;

  inodeno_t ino = m->ino;
  int from = m->get_source().num();
  if (opening_inodes.count(ino)) {
    open_ino_info_t& info = opening_inodes[ino];

    if (info.checking == from)
	info.checking = -1;
    info.checked.insert(from);

    CInode *in = get_inode(ino);
    if (in) {
      dout(10) << " found cached " << *in << dendl;
      open_ino_finish(ino, info, in->authority().first);
    } else if (!m->ancestors.empty()) {
      dout(10) << " found ino " << ino << " on mds." << from << dendl;
      if (!info.want_replica) {
	open_ino_finish(ino, info, from);
	return;
      }

      info.ancestors = m->ancestors;
      info.auth_hint = from;
      info.checking = mds->get_nodeid();
      info.discover = true;
      _open_ino_traverse_dir(ino, info, 0);
    } else if (m->error) {
      dout(10) << " error " << m->error << " from mds." << from << dendl;
      do_open_ino(ino, info, m->error);
    } else {
      if (m->hint >= 0 && m->hint != mds->get_nodeid()) {
	info.auth_hint = m->hint;
	info.checked.erase(m->hint);
      }
      do_open_ino_peer(ino, info);
    }
  }
  m->put();
}

void MDCache::kick_open_ino_peers(int who)
{
  dout(10) << "kick_open_ino_peers mds." << who << dendl;

  for (map<inodeno_t, open_ino_info_t>::iterator p = opening_inodes.begin();
       p != opening_inodes.end();
       ++p) {
    open_ino_info_t& info = p->second;
    if (info.checking == who) {
      dout(10) << "  kicking ino " << p->first << " who was checking mds." << who << dendl;
      info.checking = -1;
      do_open_ino_peer(p->first, info);
    } else if (info.checking == -1) {
      dout(10) << "  kicking ino " << p->first << " who was waiting" << dendl;
      do_open_ino_peer(p->first, info);
    }
  }
}

void MDCache::open_ino(inodeno_t ino, int64_t pool, Context* fin,
		       bool want_replica, bool want_xlocked)
{
  dout(10) << "open_ino " << ino << " pool " << pool << " want_replica "
	   << want_replica << dendl;

  if (opening_inodes.count(ino)) {
    open_ino_info_t& info = opening_inodes[ino];
    if (want_replica) {
      info.want_replica = true;
      if (want_xlocked)
	info.want_xlocked = true;
    }
    info.waiters.push_back(fin);
  } else {
    open_ino_info_t& info = opening_inodes[ino];
    info.checked.insert(mds->get_nodeid());
    info.want_replica = want_replica;
    info.want_xlocked = want_xlocked;
    info.tid = ++open_ino_last_tid;
    info.pool = pool >= 0 ? pool : mds->mdsmap->get_first_data_pool();
    info.waiters.push_back(fin);
    do_open_ino(ino, info, 0);
  }
}

/* ---------------------------- */

/*
 * search for a given inode on MDS peers.  optionally start with the given node.


 TODO 
  - recover from mds node failure, recovery
  - traverse path

 */
void MDCache::find_ino_peers(inodeno_t ino, Context *c, int hint)
{
  dout(5) << "find_ino_peers " << ino << " hint " << hint << dendl;
  assert(!have_inode(ino));
  
  tid_t tid = ++find_ino_peer_last_tid;
  find_ino_peer_info_t& fip = find_ino_peer[tid];
  fip.ino = ino;
  fip.tid = tid;
  fip.fin = c;
  fip.hint = hint;
  fip.checked.insert(mds->whoami);
  _do_find_ino_peer(fip);
}

void MDCache::_do_find_ino_peer(find_ino_peer_info_t& fip)
{
  set<int> all, active;
  mds->mdsmap->get_mds_set(all);
  mds->mdsmap->get_active_mds_set(active);
  mds->mdsmap->get_mds_set(active, MDSMap::STATE_STOPPING);

  dout(10) << "_do_find_ino_peer " << fip.tid << " " << fip.ino
	   << " active " << active << " all " << all
	   << " checked " << fip.checked
	   << dendl;
    
  int m = -1;
  if (fip.hint >= 0) {
    m = fip.hint;
    fip.hint = -1;
  } else {
    for (set<int>::iterator p = active.begin(); p != active.end(); ++p)
      if (*p != mds->whoami &&
	  fip.checked.count(*p) == 0) {
	m = *p;
	break;
      }
  }
  if (m < 0) {
    if (all.size() > active.size()) {
      dout(10) << "_do_find_ino_peer waiting for more peers to be active" << dendl;
    } else {
      dout(10) << "_do_find_ino_peer failed on " << fip.ino << dendl;
      fip.fin->complete(-ESTALE);
      find_ino_peer.erase(fip.tid);
    }
  } else {
    fip.checking = m;
    mds->send_message_mds(new MMDSFindIno(fip.tid, fip.ino), m);
  }
}

void MDCache::handle_find_ino(MMDSFindIno *m)
{
  dout(10) << "handle_find_ino " << *m << dendl;
  MMDSFindInoReply *r = new MMDSFindInoReply(m->tid);
  CInode *in = get_inode(m->ino);
  if (in) {
    in->make_path(r->path);
    dout(10) << " have " << r->path << " " << *in << dendl;
  }
  mds->messenger->send_message(r, m->get_connection());
  m->put();
}


void MDCache::handle_find_ino_reply(MMDSFindInoReply *m)
{
  map<tid_t, find_ino_peer_info_t>::iterator p = find_ino_peer.find(m->tid);
  if (p != find_ino_peer.end()) {
    dout(10) << "handle_find_ino_reply " << *m << dendl;
    find_ino_peer_info_t& fip = p->second;

    // success?
    if (get_inode(fip.ino)) {
      dout(10) << "handle_find_ino_reply successfully found " << fip.ino << dendl;
      mds->queue_waiter(fip.fin);
      find_ino_peer.erase(p);
      m->put();
      return;
    }

    int from = m->get_source().num();
    if (fip.checking == from)
      fip.checking = -1;
    fip.checked.insert(from);

    if (!m->path.empty()) {
      // we got a path!
      vector<CDentry*> trace;
      int r = path_traverse(NULL, m, NULL, m->path, &trace, NULL, MDS_TRAVERSE_DISCOVER);
      if (r > 0)
	return; 
      dout(0) << "handle_find_ino_reply failed with " << r << " on " << m->path 
	      << ", retrying" << dendl;
      fip.checked.clear();
      _do_find_ino_peer(fip);
    } else {
      // nope, continue.
      _do_find_ino_peer(fip);
    }      
  } else {
    dout(10) << "handle_find_ino_reply tid " << m->tid << " dne" << dendl;
  }  
  m->put();
}

void MDCache::kick_find_ino_peers(int who)
{
  // find_ino_peers requests we should move on from
  for (map<tid_t,find_ino_peer_info_t>::iterator p = find_ino_peer.begin();
       p != find_ino_peer.end();
       ++p) {
    find_ino_peer_info_t& fip = p->second;
    if (fip.checking == who) {
      dout(10) << "kicking find_ino_peer " << fip.tid << " who was checking mds." << who << dendl;
      fip.checking = -1;
      _do_find_ino_peer(fip);
    } else if (fip.checking == -1) {
      dout(10) << "kicking find_ino_peer " << fip.tid << " who was waiting" << dendl;
      _do_find_ino_peer(fip);
    }
  }
}

/* ---------------------------- */

struct C_MDS_FindInoDir : public Context {
  MDCache *mdcache;
  inodeno_t ino;
  Context *fin;
  bufferlist bl;
  C_MDS_FindInoDir(MDCache *m, inodeno_t i, Context *f) : mdcache(m), ino(i), fin(f) {}
  void finish(int r) {
    mdcache->_find_ino_dir(ino, fin, bl, r);
  }
};

void MDCache::find_ino_dir(inodeno_t ino, Context *fin)
{
  dout(10) << "find_ino_dir " << ino << dendl;
  assert(!have_inode(ino));

  // get the backtrace from the dir
  object_t oid = CInode::get_object_name(ino, frag_t(), "");
  object_locator_t oloc(mds->mdsmap->get_metadata_pool());
  
  C_MDS_FindInoDir *c = new C_MDS_FindInoDir(this, ino, fin);
  mds->objecter->getxattr(oid, oloc, "path", CEPH_NOSNAP, &c->bl, 0, c);
}

void MDCache::_find_ino_dir(inodeno_t ino, Context *fin, bufferlist& bl, int r)
{
  dout(10) << "_find_ino_dir " << ino << " got " << r << " " << bl.length() << " bytes" << dendl;
  if (r < 0) {
    fin->complete(r);
    return;
  }

  string s(bl.c_str(), bl.length());
  filepath path(s.c_str());
  vector<CDentry*> trace;

  dout(10) << "_find_ino_dir traversing to path " << path << dendl;

  C_MDS_FindInoDir *c = new C_MDS_FindInoDir(this, ino, fin);
  c->bl = bl;
  r = path_traverse(NULL, NULL, c, path, &trace, NULL, MDS_TRAVERSE_DISCOVER);
  if (r > 0)
    return;
  delete c;  // path_traverse doesn't clean it up for us for r <= 0
  
  fin->complete(r);
}


/* ---------------------------- */

int MDCache::get_num_client_requests()
{
  int count = 0;
  for (hash_map<metareqid_t, MDRequest*>::iterator p = active_requests.begin();
      p != active_requests.end();
      ++p) {
    if (p->second->reqid.name.is_client() && !p->second->is_slave())
      count++;
  }
  return count;
}

/* This function takes over the reference to the passed Message */
MDRequest *MDCache::request_start(MClientRequest *req)
{
  // did we win a forward race against a slave?
  if (active_requests.count(req->get_reqid())) {
    MDRequest *mdr = active_requests[req->get_reqid()];
    if (mdr->is_slave()) {
      dout(10) << "request_start already had " << *mdr << ", forward new msg" << dendl;
      mds->forward_message_mds(req, mdr->slave_to_mds);
    } else {
      dout(10) << "request_start already processing " << *mdr << ", dropping new msg" << dendl;
      req->put();
    }
    return 0;
  }

  // register new client request
  MDRequest *mdr = new MDRequest(req->get_reqid(), req->get_num_fwd(), req);
  active_requests[req->get_reqid()] = mdr;
  dout(7) << "request_start " << *mdr << dendl;
  return mdr;
}

MDRequest *MDCache::request_start_slave(metareqid_t ri, __u32 attempt, int by)
{
  MDRequest *mdr = new MDRequest(ri, attempt, by);
  assert(active_requests.count(mdr->reqid) == 0);
  active_requests[mdr->reqid] = mdr;
  dout(7) << "request_start_slave " << *mdr << " by mds." << by << dendl;
  return mdr;
}

MDRequest *MDCache::request_start_internal(int op)
{
  MDRequest *mdr = new MDRequest;
  mdr->reqid.name = entity_name_t::MDS(mds->get_nodeid());
  mdr->reqid.tid = mds->issue_tid();
  mdr->internal_op = op;

  assert(active_requests.count(mdr->reqid) == 0);
  active_requests[mdr->reqid] = mdr;
  dout(7) << "request_start_internal " << *mdr << " op " << op << dendl;
  return mdr;
}


MDRequest *MDCache::request_get(metareqid_t rid)
{
  assert(active_requests.count(rid));
  dout(7) << "request_get " << rid << " " << *active_requests[rid] << dendl;
  return active_requests[rid];
}

void MDCache::request_finish(MDRequest *mdr)
{
  dout(7) << "request_finish " << *mdr << dendl;

  // slave finisher?
  if (mdr->more()->slave_commit) {
    Context *fin = mdr->more()->slave_commit;
    mdr->more()->slave_commit = 0;
    fin->complete(0);   // this must re-call request_finish.
    return; 
  }

  request_cleanup(mdr);
}


void MDCache::request_forward(MDRequest *mdr, int who, int port)
{
  if (mdr->client_request->get_source().is_client()) {
    dout(7) << "request_forward " << *mdr << " to mds." << who << " req "
            << *mdr->client_request << dendl;
    mds->forward_message_mds(mdr->client_request, who);
    mdr->client_request = 0;
    if (mds->logger) mds->logger->inc(l_mds_fw);
  } else {
    dout(7) << "request_forward drop " << *mdr << " req " << *mdr->client_request
            << " was from mds" << dendl;
  }
  request_cleanup(mdr);
}


void MDCache::dispatch_request(MDRequest *mdr)
{
  if (mdr->killed) {
    dout(10) << "request " << *mdr << " was killed" << dendl;
    return;
  }
  if (mdr->client_request) {
    mds->server->dispatch_client_request(mdr);
  } else if (mdr->slave_request) {
    mds->server->dispatch_slave_request(mdr);
  } else {
    switch (mdr->internal_op) {
    case CEPH_MDS_OP_FRAGMENTDIR:
      dispatch_fragment_dir(mdr);
      break;
    default:
      assert(0);
    }
  }
}


void MDCache::request_drop_foreign_locks(MDRequest *mdr)
{
  // clean up slaves
  //  (will implicitly drop remote dn pins)
  for (set<int>::iterator p = mdr->more()->slaves.begin();
       p != mdr->more()->slaves.end();
       ++p) {
    MMDSSlaveRequest *r = new MMDSSlaveRequest(mdr->reqid, mdr->attempt,
					       MMDSSlaveRequest::OP_FINISH);
    mds->send_message_mds(r, *p);
  }

  /* strip foreign xlocks out of lock lists, since the OP_FINISH drops them
   * implicitly. Note that we don't call the finishers -- there shouldn't
   * be any on a remote lock and the request finish wakes up all
   * the waiters anyway! */
  set<SimpleLock*>::iterator p = mdr->xlocks.begin();
  while (p != mdr->xlocks.end()) {
    if ((*p)->get_parent()->is_auth()) 
      ++p;
    else {
      dout(10) << "request_drop_foreign_locks forgetting lock " << **p
	       << " on " << *(*p)->get_parent() << dendl;
      (*p)->put_xlock();
      mdr->locks.erase(*p);
      mdr->xlocks.erase(p++);
    }
  }

  map<SimpleLock*, int>::iterator q = mdr->remote_wrlocks.begin();
  while (q != mdr->remote_wrlocks.end()) {
    dout(10) << "request_drop_foreign_locks forgetting remote_wrlock " << *q->first
	     << " on mds." << q->second
	     << " on " << *(q->first)->get_parent() << dendl;
    mdr->locks.erase(q->first);
    mdr->remote_wrlocks.erase(q++);
  }

  mdr->more()->slaves.clear(); /* we no longer have requests out to them, and
                                * leaving them in can cause double-notifies as
                                * this function can get called more than once */
}

void MDCache::request_drop_non_rdlocks(MDRequest *mdr)
{
  request_drop_foreign_locks(mdr);
  mds->locker->drop_non_rdlocks(mdr);
}

void MDCache::request_drop_locks(MDRequest *mdr)
{
  request_drop_foreign_locks(mdr);
  mds->locker->drop_locks(mdr);
}

void MDCache::request_cleanup(MDRequest *mdr)
{
  dout(15) << "request_cleanup " << *mdr << dendl;

  if (mdr->has_more() && mdr->more()->is_ambiguous_auth)
    mdr->clear_ambiguous_auth();

  request_drop_locks(mdr);

  // drop (local) auth pins
  mdr->drop_local_auth_pins();

  // drop stickydirs
  for (set<CInode*>::iterator p = mdr->stickydirs.begin();
       p != mdr->stickydirs.end();
       ++p) 
    (*p)->put_stickydirs();

  mds->locker->kick_cap_releases(mdr);

  // drop cache pins
  mdr->drop_pins();

  // remove from session
  mdr->item_session_request.remove_myself();

  bool was_replay = mdr->client_request && mdr->client_request->is_replay();

  // remove from map
  active_requests.erase(mdr->reqid);
  mdr->put();

  // fail-safe!
  if (was_replay && active_requests.empty()) {
    dout(10) << " fail-safe queueing next replay op" << dendl;
    mds->queue_one_replay();
  }

  if (mds->logger)
    log_stat();
}

void MDCache::request_kill(MDRequest *mdr)
{
  mdr->killed = true;
  if (!mdr->committing) {
    dout(10) << "request_kill " << *mdr << dendl;
    request_cleanup(mdr);
  } else {
    dout(10) << "request_kill " << *mdr << " -- already committing, no-op" << dendl;
  }
}


// --------------------------------------------------------------------
// ANCHORS

class C_MDC_AnchorPrepared : public Context {
  MDCache *cache;
  CInode *in;
  bool add;
public:
  version_t atid;
  C_MDC_AnchorPrepared(MDCache *c, CInode *i, bool a) : cache(c), in(i), add(a), atid(0) {}
  void finish(int r) {
    cache->_anchor_prepared(in, atid, add);
  }
};

void MDCache::anchor_create_prep_locks(MDRequest *mdr, CInode *in,
				       set<SimpleLock*>& rdlocks, set<SimpleLock*>& xlocks)
{
  dout(10) << "anchor_create_prep_locks " << *in << dendl;

  if (in->is_anchored()) {
    // caller may have already xlocked it.. if so, that will suffice!
    if (xlocks.count(&in->linklock) == 0)
      rdlocks.insert(&in->linklock);
  } else {
    xlocks.insert(&in->linklock);

    // path components too!
    CDentry *dn = in->get_projected_parent_dn();
    while (dn) {
      rdlocks.insert(&dn->lock);
      dn = dn->get_dir()->get_inode()->get_parent_dn();
    }
  }
}

void MDCache::anchor_create(MDRequest *mdr, CInode *in, Context *onfinish)
{
  assert(in->is_auth());
  dout(10) << "anchor_create " << *in << dendl;

  // auth pin
  if (!in->can_auth_pin() &&
      !mdr->is_auth_pinned(in)) {
    dout(7) << "anchor_create not authpinnable, waiting on " << *in << dendl;
    in->add_waiter(CInode::WAIT_UNFREEZE, onfinish);
    return;
  }

  // wait
  in->add_waiter(CInode::WAIT_ANCHORED, onfinish);

  // already anchoring?
  if (in->state_test(CInode::STATE_ANCHORING)) {
    dout(7) << "anchor_create already anchoring " << *in << dendl;
    return;
  }

  dout(7) << "anchor_create " << *in << dendl;

  // auth: do it
  in->state_set(CInode::STATE_ANCHORING);
  in->get(CInode::PIN_ANCHORING);
  in->auth_pin(this);
  
  // make trace
  vector<Anchor> trace;
  in->make_anchor_trace(trace);
  if (trace.empty()) {
    assert(MDS_INO_IS_BASE(in->ino()));
    trace.push_back(Anchor(in->ino(), in->ino(), 0, 0, 0));
  }
  
  // do it
  C_MDC_AnchorPrepared *fin = new C_MDC_AnchorPrepared(this, in, true);
  mds->anchorclient->prepare_create(in->ino(), trace, &fin->atid, fin);
}

void MDCache::anchor_destroy(CInode *in, Context *onfinish)
{
  assert(in->is_auth());

  // auth pin
  if (!in->can_auth_pin()/* &&
			    !mdr->is_auth_pinned(in)*/) {
    dout(7) << "anchor_destroy not authpinnable, waiting on " << *in << dendl;
    in->add_waiter(CInode::WAIT_UNFREEZE, onfinish);
    return;
  }

  dout(7) << "anchor_destroy " << *in << dendl;

  // wait
  if (onfinish)
    in->add_waiter(CInode::WAIT_UNANCHORED, onfinish);

  // already anchoring?
  if (in->state_test(CInode::STATE_UNANCHORING)) {
    dout(7) << "anchor_destroy already unanchoring " << *in << dendl;
    return;
  }

  // auth: do it
  in->state_set(CInode::STATE_UNANCHORING);
  in->get(CInode::PIN_UNANCHORING);
  in->auth_pin(this);
  
  // do it
  C_MDC_AnchorPrepared *fin = new C_MDC_AnchorPrepared(this, in, false);
  mds->anchorclient->prepare_destroy(in->ino(), &fin->atid, fin);
}

class C_MDC_AnchorLogged : public Context {
  MDCache *cache;
  CInode *in;
  version_t atid;
  Mutation *mut;
public:
  C_MDC_AnchorLogged(MDCache *c, CInode *i, version_t t, Mutation *m) : 
    cache(c), in(i), atid(t), mut(m) {}
  void finish(int r) {
    cache->_anchor_logged(in, atid, mut);
  }
};

void MDCache::_anchor_prepared(CInode *in, version_t atid, bool add)
{
  dout(10) << "_anchor_prepared " << *in << " atid " << atid 
	   << " " << (add ? "create":"destroy") << dendl;
  assert(in->inode.anchored == !add);

  // update the logged inode copy
  inode_t *pi = in->project_inode();
  if (add) {
    pi->anchored = true;
    pi->rstat.ranchors++;
  } else {
    pi->anchored = false;
    pi->rstat.ranchors--;
  }
  pi->version = in->pre_dirty();

  Mutation *mut = new Mutation;
  mut->ls = mds->mdlog->get_current_segment();
  EUpdate *le = new EUpdate(mds->mdlog, add ? "anchor_create":"anchor_destroy");
  mds->mdlog->start_entry(le);
  predirty_journal_parents(mut, &le->metablob, in, 0, PREDIRTY_PRIMARY);
  journal_dirty_inode(mut, &le->metablob, in);
  le->metablob.add_table_transaction(TABLE_ANCHOR, atid);
  mds->mdlog->submit_entry(le, new C_MDC_AnchorLogged(this, in, atid, mut));
  mds->mdlog->flush();
}


void MDCache::_anchor_logged(CInode *in, version_t atid, Mutation *mut)
{
  dout(10) << "_anchor_logged on " << *in << dendl;

  // unpin
  if (in->state_test(CInode::STATE_ANCHORING)) {
    in->state_clear(CInode::STATE_ANCHORING);
    in->put(CInode::PIN_ANCHORING);
    if (in->parent)
      in->parent->adjust_nested_anchors(1);
  } else if (in->state_test(CInode::STATE_UNANCHORING)) {
    in->state_clear(CInode::STATE_UNANCHORING);
    in->put(CInode::PIN_UNANCHORING);
    if (in->parent)
      in->parent->adjust_nested_anchors(-1);
  }
  in->auth_unpin(this);
  
  // apply update to cache
  in->pop_and_dirty_projected_inode(mut->ls);
  mut->apply();
  
  // tell the anchortable we've committed
  mds->anchorclient->commit(atid, mut->ls);

  // drop locks and finish
  mds->locker->drop_locks(mut);
  mut->cleanup();
  delete mut;

  // trigger waiters
  in->finish_waiting(CInode::WAIT_ANCHORED|CInode::WAIT_UNANCHORED, 0);
}


// -------------------------------------------------------------------------------
// SNAPREALMS

struct C_MDC_snaprealm_create_finish : public Context {
  MDCache *cache;
  MDRequest *mdr;
  Mutation *mut;
  CInode *in;
  C_MDC_snaprealm_create_finish(MDCache *c, MDRequest *m, Mutation *mu, CInode *i) : 
    cache(c), mdr(m), mut(mu), in(i) {}
  void finish(int r) {
    cache->_snaprealm_create_finish(mdr, mut, in);
  }
};

void MDCache::snaprealm_create(MDRequest *mdr, CInode *in)
{
  dout(10) << "snaprealm_create " << *in << dendl;
  assert(!in->snaprealm);

  if (!in->inode.anchored) {
    mds->mdcache->anchor_create(mdr, in, new C_MDS_RetryRequest(mds->mdcache, mdr));
    return;
  }

  // allocate an id..
  if (!mdr->more()->stid) {
    mds->snapclient->prepare_create_realm(in->ino(), &mdr->more()->stid, &mdr->more()->snapidbl,
					  new C_MDS_RetryRequest(this, mdr));
    return;
  }

  Mutation *mut = new Mutation;
  mut->ls = mds->mdlog->get_current_segment();
  EUpdate *le = new EUpdate(mds->mdlog, "snaprealm_create");
  mds->mdlog->start_entry(le);

  le->metablob.add_table_transaction(TABLE_SNAP, mdr->more()->stid);

  inode_t *pi = in->project_inode();
  pi->version = in->pre_dirty();
  pi->rstat.rsnaprealms++;

  bufferlist::iterator p = mdr->more()->snapidbl.begin();
  snapid_t seq;
  ::decode(seq, p);

  sr_t *newsnap = in->project_snaprealm(seq);
  newsnap->seq = seq;
  newsnap->last_created = seq;
  
  predirty_journal_parents(mut, &le->metablob, in, 0, PREDIRTY_PRIMARY);
  journal_cow_inode(mut, &le->metablob, in);
  le->metablob.add_primary_dentry(in->get_projected_parent_dn(), in, true);

  mds->mdlog->submit_entry(le, new C_MDC_snaprealm_create_finish(this, mdr, mut, in));
  mds->mdlog->flush();
}


void MDCache::do_realm_invalidate_and_update_notify(CInode *in, int snapop, bool nosend)
{
  dout(10) << "do_realm_invalidate_and_update_notify " << *in->snaprealm << " " << *in << dendl;

  vector<inodeno_t> split_inos;
  vector<inodeno_t> split_realms;

  if (snapop == CEPH_SNAP_OP_SPLIT) {
    // notify clients of update|split
    for (elist<CInode*>::iterator p = in->snaprealm->inodes_with_caps.begin(member_offset(CInode, item_caps));
	 !p.end(); ++p)
      split_inos.push_back((*p)->ino());
    
    for (set<SnapRealm*>::iterator p = in->snaprealm->open_children.begin();
	 p != in->snaprealm->open_children.end();
	 ++p)
      split_realms.push_back((*p)->inode->ino());
  }

  bufferlist snapbl;
  in->snaprealm->build_snap_trace(snapbl);

  map<client_t, MClientSnap*> updates;
  list<SnapRealm*> q;
  q.push_back(in->snaprealm);
  while (!q.empty()) {
    SnapRealm *realm = q.front();
    q.pop_front();

    dout(10) << " realm " << *realm << " on " << *realm->inode << dendl;
    realm->invalidate_cached_snaps();

    for (map<client_t, xlist<Capability*>* >::iterator p = realm->client_caps.begin();
	 p != realm->client_caps.end();
	 ++p) {
      assert(!p->second->empty());
      if (!nosend && updates.count(p->first) == 0) {
	MClientSnap *update = new MClientSnap(snapop);
	update->head.split = in->ino();
	update->split_inos = split_inos;
	update->split_realms = split_realms;
	update->bl = snapbl;
	updates[p->first] = update;
      }
    }

    // notify for active children, too.
    dout(10) << " " << realm << " open_children are " << realm->open_children << dendl;
    for (set<SnapRealm*>::iterator p = realm->open_children.begin();
	 p != realm->open_children.end();
	 ++p)
      q.push_back(*p);
  }

  if (!nosend)
    send_snaps(updates);
}

void MDCache::_snaprealm_create_finish(MDRequest *mdr, Mutation *mut, CInode *in)
{
  dout(10) << "_snaprealm_create_finish " << *in << dendl;

  // apply
  in->pop_and_dirty_projected_inode(mut->ls);
  mut->apply();
  mds->locker->drop_locks(mut);
  mut->cleanup();

  // tell table we've committed
  mds->snapclient->commit(mdr->more()->stid, mut->ls);

  delete mut;

  // create
  bufferlist::iterator p = mdr->more()->snapidbl.begin();
  snapid_t seq;
  ::decode(seq, p);

  in->open_snaprealm();
  in->snaprealm->open = true;
  in->snaprealm->srnode.seq = seq;
  in->snaprealm->srnode.created = seq;
  in->snaprealm->srnode.current_parent_since = seq;

  do_realm_invalidate_and_update_notify(in, CEPH_SNAP_OP_SPLIT);

  /*
  static int count = 5;
  if (--count == 0)
    assert(0);  // hack test test **********
  */

  // done.
  mdr->more()->stid = 0;  // caller will likely need to reuse this
  dispatch_request(mdr);
}


// -------------------------------------------------------------------------------
// STRAYS

void MDCache::scan_stray_dir()
{
  dout(10) << "scan_stray_dir" << dendl;
  
  list<CDir*> ls;
  for (int i = 0; i < NUM_STRAY; ++i) {
    if (strays[i]) {
      strays[i]->get_dirfrags(ls);
    }
  }

  for (list<CDir*>::iterator p = ls.begin(); p != ls.end(); ++p) {
    CDir *dir = *p;
    for (CDir::map_t::iterator q = dir->items.begin(); q != dir->items.end(); ++q) {
      CDentry *dn = q->second;
      CDentry::linkage_t *dnl = dn->get_projected_linkage();
      if (dnl->is_primary())
	maybe_eval_stray(dnl->get_inode());
    }
  }
}

struct C_MDC_EvalStray : public Context {
  MDCache *mdcache;
  CDentry *dn;
  C_MDC_EvalStray(MDCache *c, CDentry *d) : mdcache(c), dn(d) {}
  void finish(int r) {
    mdcache->eval_stray(dn);
  }
};

void MDCache::eval_stray(CDentry *dn, bool delay)
{
  dout(10) << "eval_stray " << *dn << dendl;
  CDentry::linkage_t *dnl = dn->get_projected_linkage();
  dout(10) << " inode is " << *dnl->get_inode() << dendl;
  assert(dnl->is_primary());
  CInode *in = dnl->get_inode();
  assert(in);

  assert(dn->get_dir()->get_inode()->is_stray());

  if (!dn->is_auth()) {
    // has to be mine
    // move to bottom of lru so that we trim quickly!
    touch_dentry_bottom(dn);
    return;
  }

  // purge?
  if (in->inode.nlink == 0) {
    if (in->is_dir()) {
      // past snaprealm parents imply snapped dentry remote links.
      // only important for directories.  normal file data snaps are handled
      // by the object store.
      if (in->snaprealm && in->snaprealm->has_past_parents()) {
	if (!in->snaprealm->have_past_parents_open() &&
	    !in->snaprealm->open_parents(new C_MDC_EvalStray(this, dn)))
	  return;
	in->snaprealm->prune_past_parents();
	if (in->snaprealm->has_past_parents()) {
	  dout(20) << "  has past parents " << in->snaprealm->srnode.past_parents << dendl;
	  return;  // not until some snaps are deleted.
	}
      }
    }
    if (dn->is_replicated()) {
      dout(20) << " replicated" << dendl;
      return;
    }
    if (dn->is_any_leases() || in->is_any_caps()) {
      dout(20) << " caps | leases" << dendl;
      return;  // wait
    }
    if (!in->dirfrags.empty()) {
      dout(20) << " open dirfrags" << dendl;
      return;  // wait for dirs to close/trim
    }
    if (dn->state_test(CDentry::STATE_PURGING)) {
      dout(20) << " already purging" << dendl;
      return;  // already purging
    }
    if (in->state_test(CInode::STATE_NEEDSRECOVER) ||
	in->state_test(CInode::STATE_RECOVERING)) {
      dout(20) << " pending recovery" << dendl;
      return;  // don't mess with file size probing
    }
    if (in->get_num_ref() > (int)in->is_dirty() + (int)in->is_dirty_parent()) {
      dout(20) << " too many inode refs" << dendl;
      return;
    }
    if (dn->get_num_ref() > (int)dn->is_dirty() + !!in->get_num_ref()) {
      dout(20) << " too many dn refs" << dendl;
      return;
    }
    if (delay) {
      if (!dn->item_stray.is_on_list())
	delayed_eval_stray.push_back(&dn->item_stray);
    } else
      purge_stray(dn);
  }
  else if (in->inode.nlink >= 1) {
    // trivial reintegrate?
    if (!in->remote_parents.empty()) {
      CDentry *rlink = *in->remote_parents.begin();
      
      // don't do anything if the remote parent is projected, or we may
      // break user-visible semantics!
      // NOTE: we repeat this check in _rename(), since our submission path is racey.
      if (!rlink->is_projected()) {
	if (rlink->is_auth() && rlink->dir->can_auth_pin())
	  reintegrate_stray(dn, rlink);
	
	if (!rlink->is_auth() && dn->is_auth())
	  migrate_stray(dn, rlink->authority().first);
      }
    }
  } else {
    // wait for next use.
  }
}

void MDCache::eval_remote(CDentry *dn)
{
  dout(10) << "eval_remote " << *dn << dendl;
  CDentry::linkage_t *dnl = dn->get_projected_linkage();
  assert(dnl->is_remote());
  CInode *in = dnl->get_inode();
  if (!in) return;

  // refers to stray?
  if (in->get_parent_dn()->get_dir()->get_inode()->is_stray()) {
    if (in->is_auth())
      eval_stray(in->get_parent_dn());
    else
      migrate_stray(in->get_parent_dn(), mds->get_nodeid());
  }
}

void MDCache::fetch_backtrace(inodeno_t ino, int64_t pool, bufferlist& bl, Context *fin)
{
  object_t oid = CInode::get_object_name(ino, frag_t(), "");
  mds->objecter->getxattr(oid, object_locator_t(pool), "parent", CEPH_NOSNAP, &bl, 0, fin);
}

class C_MDC_PurgeStrayPurged : public Context {
  MDCache *cache;
  CDentry *dn;
public:
  C_MDC_PurgeStrayPurged(MDCache *c, CDentry *d) : 
    cache(c), dn(d) { }
  void finish(int r) {
    cache->_purge_stray_purged(dn, r);
  }
};

void MDCache::purge_stray(CDentry *dn)
{
  CDentry::linkage_t *dnl = dn->get_projected_linkage();
  CInode *in = dnl->get_inode();
  dout(10) << "purge_stray " << *dn << " " << *in << dendl;
  assert(!dn->is_replicated());

  // anchored?
  if (in->inode.anchored) {
    anchor_destroy(in, new C_MDC_EvalStray(this, dn));
    return;
  }

  dn->state_set(CDentry::STATE_PURGING);
  dn->get(CDentry::PIN_PURGING);
  in->state_set(CInode::STATE_PURGING);

  if (dn->item_stray.is_on_list())
    dn->item_stray.remove_myself();

  if (in->is_dirty_parent())
    in->clear_dirty_parent();

  // CHEAT.  there's no real need to journal our intent to purge, since
  // that is implicit in the dentry's presence and non-use in the stray
  // dir.  on recovery, we'll need to re-eval all strays anyway.
  
  SnapContext nullsnapc;
  C_GatherBuilder gather(g_ceph_context, new C_MDC_PurgeStrayPurged(this, dn));

  if (in->is_dir()) {
    object_locator_t oloc(mds->mdsmap->get_metadata_pool());
    list<frag_t> ls;
    if (!in->dirfragtree.is_leaf(frag_t()))
      in->dirfragtree.get_leaves(ls);
    ls.push_back(frag_t());
    for (list<frag_t>::iterator p = ls.begin();
         p != ls.end();
         ++p) {
      object_t oid = CInode::get_object_name(in->inode.ino, *p, "");
      dout(10) << "purge_stray remove dirfrag " << oid << dendl;
      mds->objecter->remove(oid, oloc, nullsnapc, ceph_clock_now(g_ceph_context),
                            0, NULL, gather.new_sub());
    }
    assert(gather.has_subs());
    gather.activate();
    return;
  }

  const SnapContext *snapc;
  SnapRealm *realm = in->find_snaprealm();
  if (realm) {
    dout(10) << " realm " << *realm << dendl;
    snapc = &realm->get_snap_context();
  } else {
    dout(10) << " NO realm, using null context" << dendl;
    snapc = &nullsnapc;
    assert(in->last == CEPH_NOSNAP);
  }

  if (in->is_file()) {
    uint64_t period = (uint64_t)in->inode.layout.fl_object_size *
		      (uint64_t)in->inode.layout.fl_stripe_count;
    uint64_t cur_max_size = in->inode.get_max_size();
    uint64_t to = MAX(in->inode.size, cur_max_size);
    if (to && period) {
      uint64_t num = (to + period - 1) / period;
      dout(10) << "purge_stray 0~" << to << " objects 0~" << num
	       << " snapc " << snapc << " on " << *in << dendl;
      mds->filer->purge_range(in->inode.ino, &in->inode.layout, *snapc,
			      0, num, ceph_clock_now(g_ceph_context), 0,
			      gather.new_sub());
    }
  }

  inode_t *pi = in->get_projected_inode();
  object_t oid = CInode::get_object_name(pi->ino, frag_t(), "");
  // remove the backtrace object if it was not purged
  if (!gather.has_subs()) {
    object_locator_t oloc(pi->layout.fl_pg_pool);
    dout(10) << "purge_stray remove backtrace object " << oid
	     << " pool " << oloc.pool << " snapc " << snapc << dendl;
    mds->objecter->remove(oid, oloc, *snapc, ceph_clock_now(g_ceph_context), 0,
			  NULL, gather.new_sub());
  }
  // remove old backtrace objects
  for (vector<int64_t>::iterator p = pi->old_pools.begin();
       p != pi->old_pools.end();
       ++p) {
    object_locator_t oloc(*p);
    dout(10) << "purge_stray remove backtrace object " << oid
	     << " old pool " << *p << " snapc " << snapc << dendl;
    mds->objecter->remove(oid, oloc, *snapc, ceph_clock_now(g_ceph_context), 0,
			  NULL, gather.new_sub());
  }
  assert(gather.has_subs());
  gather.activate();
}

class C_MDC_PurgeStrayLogged : public Context {
  MDCache *cache;
  CDentry *dn;
  version_t pdv;
  LogSegment *ls;
public:
  C_MDC_PurgeStrayLogged(MDCache *c, CDentry *d, version_t v, LogSegment *s) : 
    cache(c), dn(d), pdv(v), ls(s) { }
  void finish(int r) {
    cache->_purge_stray_logged(dn, pdv, ls);
  }
};
class C_MDC_PurgeStrayLoggedTruncate : public Context {
  MDCache *cache;
  CDentry *dn;
  LogSegment *ls;
public:
  C_MDC_PurgeStrayLoggedTruncate(MDCache *c, CDentry *d, LogSegment *s) : 
    cache(c), dn(d), ls(s) { }
  void finish(int r) {
    cache->_purge_stray_logged_truncate(dn, ls);
  }
};

void MDCache::_purge_stray_purged(CDentry *dn, int r)
{
  assert (r == 0 || r == -ENOENT);
  CInode *in = dn->get_projected_linkage()->get_inode();
  dout(10) << "_purge_stray_purged " << *dn << " " << *in << dendl;

  if (in->get_num_ref() == (int)in->is_dirty() &&
      dn->get_num_ref() == (int)dn->is_dirty() + !!in->get_num_ref() + 1/*PIN_PURGING*/) {
    // kill dentry.
    version_t pdv = dn->pre_dirty();
    dn->push_projected_linkage(); // NULL

    EUpdate *le = new EUpdate(mds->mdlog, "purge_stray");
    mds->mdlog->start_entry(le);

    // update dirfrag fragstat, rstat
    CDir *dir = dn->get_dir();
    fnode_t *pf = dir->project_fnode();
    pf->version = dir->pre_dirty();
    if (in->is_dir())
      pf->fragstat.nsubdirs--;
    else
      pf->fragstat.nfiles--;
    pf->rstat.sub(in->inode.accounted_rstat);

    le->metablob.add_dir_context(dn->dir);
    EMetaBlob::dirlump& dl = le->metablob.add_dir(dn->dir, true);
    le->metablob.add_null_dentry(dl, dn, true);
    le->metablob.add_destroyed_inode(in->ino());

    mds->mdlog->submit_entry(le, new C_MDC_PurgeStrayLogged(this, dn, pdv, mds->mdlog->get_current_segment()));
  } else {
    // new refs.. just truncate to 0
    EUpdate *le = new EUpdate(mds->mdlog, "purge_stray truncate");
    mds->mdlog->start_entry(le);
    
    inode_t *pi = in->project_inode();
    pi->size = 0;
    pi->client_ranges.clear();
    pi->truncate_size = 0;
    pi->truncate_from = 0;
    pi->version = in->pre_dirty();

    le->metablob.add_dir_context(dn->dir);
    le->metablob.add_primary_dentry(dn, in, true);

    mds->mdlog->submit_entry(le, new C_MDC_PurgeStrayLoggedTruncate(this, dn, mds->mdlog->get_current_segment()));
  }
}

void MDCache::_purge_stray_logged(CDentry *dn, version_t pdv, LogSegment *ls)
{
  CInode *in = dn->get_linkage()->get_inode();
  dout(10) << "_purge_stray_logged " << *dn << " " << *in << dendl;

  assert(!in->state_test(CInode::STATE_RECOVERING));

  // unlink
  assert(dn->get_projected_linkage()->is_null());
  dn->dir->unlink_inode(dn);
  dn->pop_projected_linkage();
  dn->mark_dirty(pdv, ls);

  dn->dir->pop_and_dirty_projected_fnode(ls);

  in->state_clear(CInode::STATE_ORPHAN);
  dn->state_clear(CDentry::STATE_PURGING);
  dn->put(CDentry::PIN_PURGING);

  // drop inode
  if (in->is_dirty())
    in->mark_clean();

  remove_inode(in);

  // drop dentry?
  if (dn->is_new()) {
    dout(20) << " dn is new, removing" << dendl;
    dn->mark_clean();
    dn->dir->remove_dentry(dn);
  } else
    touch_dentry_bottom(dn);  // drop dn as quickly as possible.
}

void MDCache::_purge_stray_logged_truncate(CDentry *dn, LogSegment *ls)
{
  CInode *in = dn->get_projected_linkage()->get_inode();
  dout(10) << "_purge_stray_logged_truncate " << *dn << " " << *in << dendl;

  dn->state_clear(CDentry::STATE_PURGING);
  dn->put(CDentry::PIN_PURGING);

  in->pop_and_dirty_projected_inode(ls);

  eval_stray(dn);
}



void MDCache::reintegrate_stray(CDentry *straydn, CDentry *rdn)
{
  dout(10) << "reintegrate_stray " << *straydn << " into " << *rdn << dendl;
  
  // rename it to another mds.
  filepath src;
  straydn->make_path(src);
  filepath dst;
  rdn->make_path(dst);

  MClientRequest *req = new MClientRequest(CEPH_MDS_OP_RENAME);
  req->set_filepath(dst);
  req->set_filepath2(src);
  req->set_tid(mds->issue_tid());

  mds->send_message_mds(req, rdn->authority().first);
}
 

void MDCache::migrate_stray(CDentry *dn, int to)
{
  CInode *in = dn->get_linkage()->get_inode();
  assert(in);
  CInode *diri = dn->dir->get_inode();
  assert(diri->is_stray());
  dout(10) << "migrate_stray from mds." << MDS_INO_STRAY_OWNER(diri->inode.ino)
	   << " to mds." << to
	   << " " << *dn << " " << *in << dendl;

  // rename it to another mds.
  filepath src;
  dn->make_path(src);

  string dname;
  in->name_stray_dentry(dname);
  filepath dst(dname, MDS_INO_STRAY(to, 0));

  MClientRequest *req = new MClientRequest(CEPH_MDS_OP_RENAME);
  req->set_filepath(dst);
  req->set_filepath2(src);
  req->set_tid(mds->issue_tid());

  mds->send_message_mds(req, to);
}




// ========================================================================================
// DISCOVER
/*

  - for all discovers (except base_inos, e.g. root, stray), waiters are attached
  to the parent metadata object in the cache (pinning it).

  - all discovers are tracked by tid, so that we can ignore potentially dup replies.

*/

void MDCache::_send_discover(discover_info_t& d)
{
  MDiscover *dis = new MDiscover(d.ino, d.frag, d.snap,
				 d.want_path, d.want_ino, d.want_base_dir, d.want_xlocked);
  dis->set_tid(d.tid);
  mds->send_message_mds(dis, d.mds);
}

void MDCache::discover_base_ino(inodeno_t want_ino,
				Context *onfinish,
				int from) 
{
  dout(7) << "discover_base_ino " << want_ino << " from mds." << from << dendl;
  if (waiting_for_base_ino[from].count(want_ino) == 0) {
    discover_info_t& d = _create_discover(from);
    d.ino = want_ino;
    _send_discover(d);
  }
  waiting_for_base_ino[from][want_ino].push_back(onfinish);
}


void MDCache::discover_dir_frag(CInode *base,
				frag_t approx_fg,
				Context *onfinish,
				int from)
{
  if (from < 0)
    from = base->authority().first;

  dirfrag_t df(base->ino(), approx_fg);
  dout(7) << "discover_dir_frag " << df
	  << " from mds." << from << dendl;

  if (!base->is_waiter_for(CInode::WAIT_DIR) || !onfinish) {  // FIXME: this is kind of weak!
    discover_info_t& d = _create_discover(from);
    d.ino = base->ino();
    d.frag = approx_fg;
    d.want_base_dir = true;
    _send_discover(d);
  }

  if (onfinish) 
    base->add_waiter(CInode::WAIT_DIR, onfinish);
}

struct C_MDC_RetryDiscoverPath : public Context {
  MDCache *mdc;
  CInode *base;
  snapid_t snapid;
  filepath path;
  int from;
  C_MDC_RetryDiscoverPath(MDCache *c, CInode *b, snapid_t s, filepath &p, int f) :
    mdc(c), base(b), snapid(s), path(p), from(f)  {}
  void finish(int r) {
    mdc->discover_path(base, snapid, path, 0, from);
  }
};

void MDCache::discover_path(CInode *base,
			    snapid_t snap,
			    filepath want_path,
			    Context *onfinish,
			    bool want_xlocked,
			    int from)
{
  if (from < 0)
    from = base->authority().first;

  dout(7) << "discover_path " << base->ino() << " " << want_path << " snap " << snap << " from mds." << from
	  << (want_xlocked ? " want_xlocked":"")
	  << dendl;

  if (base->is_ambiguous_auth()) {
    dout(10) << " waiting for single auth on " << *base << dendl;
    if (!onfinish)
      onfinish = new C_MDC_RetryDiscoverPath(this, base, snap, want_path, from);
    base->add_waiter(CInode::WAIT_SINGLEAUTH, onfinish);
    return;
  } 

  if ((want_xlocked && want_path.depth() == 1) ||
      !base->is_waiter_for(CInode::WAIT_DIR) || !onfinish) { // FIXME: weak!
    discover_info_t& d = _create_discover(from);
    d.ino = base->ino();
    d.snap = snap;
    d.want_path = want_path;
    d.want_base_dir = true;
    d.want_xlocked = want_xlocked;
    _send_discover(d);
  }

  // register + wait
  if (onfinish)
    base->add_waiter(CInode::WAIT_DIR, onfinish);
}

struct C_MDC_RetryDiscoverPath2 : public Context {
  MDCache *mdc;
  CDir *base;
  snapid_t snapid;
  filepath path;
  C_MDC_RetryDiscoverPath2(MDCache *c, CDir *b, snapid_t s, filepath &p) :
    mdc(c), base(b), snapid(s), path(p) {}
  void finish(int r) {
    mdc->discover_path(base, snapid, path, 0);
  }
};

void MDCache::discover_path(CDir *base,
			    snapid_t snap,
			    filepath want_path,
			    Context *onfinish,
			    bool want_xlocked)
{
  int from = base->authority().first;

  dout(7) << "discover_path " << base->dirfrag() << " " << want_path << " snap " << snap << " from mds." << from
	  << (want_xlocked ? " want_xlocked":"")
	  << dendl;

  if (base->is_ambiguous_auth()) {
    dout(7) << " waiting for single auth on " << *base << dendl;
    if (!onfinish)
      onfinish = new C_MDC_RetryDiscoverPath2(this, base, snap, want_path);
    base->add_waiter(CDir::WAIT_SINGLEAUTH, onfinish);
    return;
  }

  if ((want_xlocked && want_path.depth() == 1) ||
      !base->is_waiting_for_dentry(want_path[0].c_str(), snap) || !onfinish) {
    discover_info_t& d = _create_discover(from);
    d.ino = base->ino();
    d.frag = base->get_frag();
    d.snap = snap;
    d.want_path = want_path;
    d.want_base_dir = false;
    d.want_xlocked = want_xlocked;
    _send_discover(d);
  }

  // register + wait
  if (onfinish)
    base->add_dentry_waiter(want_path[0], snap, onfinish);
}

struct C_MDC_RetryDiscoverIno : public Context {
  MDCache *mdc;
  CDir *base;
  inodeno_t want_ino;
  C_MDC_RetryDiscoverIno(MDCache *c, CDir *b, inodeno_t i) :
    mdc(c), base(b), want_ino(i) {}
  void finish(int r) {
    mdc->discover_ino(base, want_ino, 0);
  }
};

void MDCache::discover_ino(CDir *base,
			   inodeno_t want_ino,
			   Context *onfinish,
			   bool want_xlocked)
{
  int from = base->authority().first;

  dout(7) << "discover_ino " << base->dirfrag() << " " << want_ino << " from mds." << from
	  << (want_xlocked ? " want_xlocked":"")
	  << dendl;
  
  if (base->is_ambiguous_auth()) {
    dout(10) << " waiting for single auth on " << *base << dendl;
    if (!onfinish)
      onfinish = new C_MDC_RetryDiscoverIno(this, base, want_ino);
    base->add_waiter(CDir::WAIT_SINGLEAUTH, onfinish);
    return;
  } 

  if (want_xlocked || !base->is_waiting_for_ino(want_ino) || !onfinish) {
    discover_info_t& d = _create_discover(from);
    d.ino = base->ino();
    d.frag = base->get_frag();
    d.want_ino = want_ino;
    d.want_base_dir = false;
    d.want_xlocked = want_xlocked;
    _send_discover(d);
  }

  // register + wait
  if (onfinish)
    base->add_ino_waiter(want_ino, onfinish);
}



void MDCache::kick_discovers(int who)
{
  for (map<tid_t,discover_info_t>::iterator p = discovers.begin();
       p != discovers.end();
       ++p)
    _send_discover(p->second);
}


/* This function DOES put the passed message before returning */
void MDCache::handle_discover(MDiscover *dis) 
{
  int whoami = mds->get_nodeid();
  int from = dis->get_source_inst().name._num;

  assert(from != whoami);

  if (mds->get_state() <= MDSMap::STATE_REJOIN) {
    int from = dis->get_source().num();
    // proceed if requester is in the REJOIN stage, the request is from parallel_fetch().
    // delay processing request from survivor because we may not yet choose lock states.
    if (mds->get_state() < MDSMap::STATE_REJOIN ||
	!mds->mdsmap->is_rejoin(from)) {
      dout(0) << "discover_reply not yet active(|still rejoining), delaying" << dendl;
      mds->wait_for_active(new C_MDS_RetryMessage(mds, dis));
      return;
    }
  }


  CInode *cur = 0;
  MDiscoverReply *reply = new MDiscoverReply(dis);

  snapid_t snapid = dis->get_snapid();

  // get started.
  if (MDS_INO_IS_BASE(dis->get_base_ino()) &&
      !dis->wants_base_dir() && dis->get_want().depth() == 0) {
    // wants root
    dout(7) << "handle_discover from mds." << from
	    << " wants base + " << dis->get_want().get_path()
	    << " snap " << snapid
	    << dendl;

    cur = get_inode(dis->get_base_ino());

    // add root
    reply->starts_with = MDiscoverReply::INODE;
    replicate_inode(cur, from, reply->trace);
    dout(10) << "added base " << *cur << dendl;
  }
  else {
    // there's a base inode
    cur = get_inode(dis->get_base_ino(), snapid);
    if (!cur && snapid != CEPH_NOSNAP) {
      cur = get_inode(dis->get_base_ino());
      if (cur && !cur->is_multiversion())
	cur = NULL;  // nope!
    }
    
    if (!cur) {
      dout(7) << "handle_discover mds." << from 
	      << " don't have base ino " << dis->get_base_ino() << "." << snapid
	      << dendl;
      if (!dis->wants_base_dir() && dis->get_want().depth() > 0)
	reply->set_error_dentry(dis->get_dentry(0));
      reply->set_flag_error_dir();
    } else if (dis->wants_base_dir()) {
      dout(7) << "handle_discover mds." << from 
	      << " wants basedir+" << dis->get_want().get_path() 
	      << " has " << *cur 
	      << dendl;
    } else {
      dout(7) << "handle_discover mds." << from 
	      << " wants " << dis->get_want().get_path()
	      << " has " << *cur
	      << dendl;
    }
  }

  assert(reply);
  
  // add content
  // do some fidgeting to include a dir if they asked for the base dir, or just root.
  for (unsigned i = 0; 
       cur && (i < dis->get_want().depth() || dis->get_want().depth() == 0); 
       i++) {

    // -- figure out the dir

    // is *cur even a dir at all?
    if (!cur->is_dir()) {
      dout(7) << *cur << " not a dir" << dendl;
      reply->set_flag_error_dir();
      break;
    }

    // pick frag
    frag_t fg;
    if (dis->get_want().depth()) {
      // dentry specifies
      fg = cur->pick_dirfrag(dis->get_dentry(i));
    } else {
      // requester explicity specified the frag
      fg = dis->get_base_dir_frag();
      assert(dis->wants_base_dir() || dis->get_want_ino() || MDS_INO_IS_BASE(dis->get_base_ino()));
    }
    CDir *curdir = cur->get_dirfrag(fg);

    if ((!curdir && !cur->is_auth()) ||
	(curdir && !curdir->is_auth())) {

	/* before:
	 * ONLY set flag if empty!!
	 * otherwise requester will wake up waiter(s) _and_ continue with discover,
	 * resulting in duplicate discovers in flight,
	 * which can wreak havoc when discovering rename srcdn (which may move)
	 */

      if (reply->is_empty()) {
	// only hint if empty.
	//  someday this could be better, but right now the waiter logic isn't smart enough.
	
	// hint
	if (curdir) {
	  dout(7) << " not dirfrag auth, setting dir_auth_hint for " << *curdir << dendl;
	  reply->set_dir_auth_hint(curdir->authority().first);
	} else {
	  dout(7) << " dirfrag not open, not inode auth, setting dir_auth_hint for " 
		  << *cur << dendl;
	  reply->set_dir_auth_hint(cur->authority().first);
	}
	
	// note error dentry, if any
	//  NOTE: important, as it allows requester to issue an equivalent discover
	//        to whomever we hint at.
	if (dis->get_want().depth() > i)
	  reply->set_error_dentry(dis->get_dentry(i));
      }

      break;
    }

    // open dir?
    if (!curdir) 
      curdir = cur->get_or_open_dirfrag(this, fg);
    assert(curdir);
    assert(curdir->is_auth());
    
    // is dir frozen?
    if (curdir->is_frozen()) {
      if (reply->is_empty()) {
	dout(7) << *curdir << " is frozen, empty reply, waiting" << dendl;
	curdir->add_waiter(CDir::WAIT_UNFREEZE, new C_MDS_RetryMessage(mds, dis));
	reply->put();
	return;
      } else {
	dout(7) << *curdir << " is frozen, non-empty reply, stopping" << dendl;
	break;
      }
    }
    
    // add dir
    if (reply->is_empty() && !dis->wants_base_dir()) {
      dout(7) << "handle_discover not adding unwanted base dir " << *curdir << dendl;
      // make sure the base frag is correct, though, in there was a refragment since the
      // original request was sent.
      reply->set_base_dir_frag(curdir->get_frag());
    } else {
      assert(!curdir->is_ambiguous_auth()); // would be frozen.
      if (!reply->trace.length())
	reply->starts_with = MDiscoverReply::DIR;
      replicate_dir(curdir, from, reply->trace);
      dout(7) << "handle_discover added dir " << *curdir << dendl;
    }

    // lookup
    CDentry *dn = 0;
    if (dis->get_want_ino()) {
      // lookup by ino
      CInode *in = get_inode(dis->get_want_ino(), snapid);
      if (in && in->is_auth() && in->get_parent_dn()->get_dir() == curdir) {
	dn = in->get_parent_dn();
	if (dn->state_test(CDentry::STATE_PURGING)) {
	  // set error flag in reply
	  dout(7) << "dentry " << *dn << " is purging, flagging error ino" << dendl;
	  reply->set_flag_error_ino();
	  break;
	}
      }
    } else if (dis->get_want().depth() > 0) {
      // lookup dentry
      dn = curdir->lookup(dis->get_dentry(i), snapid);
    } else 
      break; // done!
          
    // incomplete dir?
    if (!dn) {
      if (!curdir->is_complete()) {
	// readdir
	dout(7) << "incomplete dir contents for " << *curdir << ", fetching" << dendl;
	if (reply->is_empty()) {
	  // fetch and wait
	  curdir->fetch(new C_MDS_RetryMessage(mds, dis));
	  reply->put();
	  return;
	} else {
	  // initiate fetch, but send what we have so far
	  curdir->fetch(0);
	  break;
	}
      }
      
      // don't have wanted ino in this dir?
      if (dis->get_want_ino()) {
	// set error flag in reply
	dout(7) << "no ino " << dis->get_want_ino() << " in this dir, flagging error in "
		<< *curdir << dendl;
	reply->set_flag_error_ino();
	break;
      }
      
      // is this a new mds dir?
      /*
      if (curdir->ino() == MDS_INO_CEPH) {
	char t[10];
	snprintf(t, sizeof(t), "mds%d", from);
	if (t == dis->get_dentry(i)) {
	  // yes.
	  _create_mdsdir_dentry(curdir, from, t, new C_MDS_RetryMessage(mds, dis));
	  //_create_system_file(curdir, t, create_system_inode(MDS_INO_MDSDIR(from), S_IFDIR),
	  //new C_MDS_RetryMessage(mds, dis));
	  reply->put();
	  return;
	}
      }	
      */
      
      // send null dentry
      dout(7) << "dentry " << dis->get_dentry(i) << " dne, returning null in "
	      << *curdir << dendl;
      dn = curdir->add_null_dentry(dis->get_dentry(i));
    }
    assert(dn);

    CDentry::linkage_t *dnl = dn->get_linkage();

    // xlocked dentry?
    //  ...always block on non-tail items (they are unrelated)
    //  ...allow xlocked tail disocvery _only_ if explicitly requested
    bool tailitem = (dis->get_want().depth() == 0) || (i == dis->get_want().depth() - 1);
    if (dn->lock.is_xlocked()) {
      // is this the last (tail) item in the discover traversal?
      if (tailitem && dis->wants_xlocked()) {
	dout(7) << "handle_discover allowing discovery of xlocked tail " << *dn << dendl;
      } else if (reply->is_empty()) {
	dout(7) << "handle_discover blocking on xlocked " << *dn << dendl;
	dn->lock.add_waiter(SimpleLock::WAIT_RD, new C_MDS_RetryMessage(mds, dis));
	reply->put();
	return;
      } else {
	dout(7) << "handle_discover non-empty reply, xlocked tail " << *dn << dendl;
	break;
      }
    }

    // frozen inode?
    if (dnl->is_primary() && dnl->get_inode()->is_frozen()) {
      if (tailitem && dis->wants_xlocked()) {
	dout(7) << "handle_discover allowing discovery of frozen tail " << *dnl->get_inode() << dendl;
      } else if (reply->is_empty()) {
	dout(7) << *dnl->get_inode() << " is frozen, empty reply, waiting" << dendl;
	dnl->get_inode()->add_waiter(CDir::WAIT_UNFREEZE, new C_MDS_RetryMessage(mds, dis));
	reply->put();
	return;
      } else {
	dout(7) << *dnl->get_inode() << " is frozen, non-empty reply, stopping" << dendl;
	break;
      }
    }

    // add dentry
    if (!reply->trace.length())
      reply->starts_with = MDiscoverReply::DENTRY;
    replicate_dentry(dn, from, reply->trace);
    dout(7) << "handle_discover added dentry " << *dn << dendl;
    
    if (!dnl->is_primary()) break;  // stop on null or remote link.
    
    // add inode
    CInode *next = dnl->get_inode();
    assert(next->is_auth());
    
    replicate_inode(next, from, reply->trace);
    dout(7) << "handle_discover added inode " << *next << dendl;
    
    // descend, keep going.
    cur = next;
    continue;
  }

  // how did we do?
  assert(!reply->is_empty());
  dout(7) << "handle_discover sending result back to asker mds." << from << dendl;
  mds->send_message(reply, dis->get_connection());

  dis->put();
}

/* This function DOES put the passed message before returning */
void MDCache::handle_discover_reply(MDiscoverReply *m) 
{
  /*
  if (mds->get_state() < MDSMap::STATE_ACTIVE) {
    dout(0) << "discover_reply NOT ACTIVE YET" << dendl;
    m->put();
    return;
  }
  */
  dout(7) << "discover_reply " << *m << dendl;
  if (m->is_flag_error_dir()) 
    dout(7) << " flag error, dir" << dendl;
  if (m->is_flag_error_dn()) 
    dout(7) << " flag error, dentry = " << m->get_error_dentry() << dendl;
  if (m->is_flag_error_ino()) 
    dout(7) << " flag error, ino = " << m->get_wanted_ino() << dendl;

  list<Context*> finished, error;
  int from = m->get_source().num();

  // starting point
  CInode *cur = get_inode(m->get_base_ino());
  bufferlist::iterator p = m->trace.begin();

  int next = m->starts_with;

  // decrement discover counters
  if (m->get_tid()) {
    map<tid_t,discover_info_t>::iterator p = discovers.find(m->get_tid());
    if (p != discovers.end()) {
      dout(10) << " found tid " << m->get_tid() << dendl;
      discovers.erase(p);
    } else {
      dout(10) << " tid " << m->get_tid() << " not found, must be dup reply" << dendl;
    }
  }

  // discover ino error
  if (p.end() && m->is_flag_error_ino()) {
    assert(cur);
    assert(cur->is_dir());
    CDir *dir = cur->get_dirfrag(m->get_base_dir_frag());
    if (dir) {
      dout(7) << " flag_error on ino " << m->get_wanted_ino()
	      << ", triggering ino" << dendl;
      dir->take_ino_waiting(m->get_wanted_ino(), error);
    } else
      assert(0);
  }

  // discover may start with an inode
  if (!p.end() && next == MDiscoverReply::INODE) {
    cur = add_replica_inode(p, NULL, finished);
    dout(7) << "discover_reply got base inode " << *cur << dendl;
    assert(cur->is_base());
    
    next = MDiscoverReply::DIR;
    
    // take waiters?
    if (cur->is_base() &&
	waiting_for_base_ino[from].count(cur->ino())) {
      finished.swap(waiting_for_base_ino[from][cur->ino()]);
      waiting_for_base_ino[from].erase(cur->ino());
    }
  }
  assert(cur);
  
  // loop over discover results.
  // indexes follow each ([[dir] dentry] inode) 
  // can start, end with any type.
  while (!p.end()) {
    // dir
    frag_t fg;
    CDir *curdir = 0;
    if (next == MDiscoverReply::DIR)
      curdir = add_replica_dir(p, cur, m->get_source().num(), finished);
    else {
      // note: this can only happen our first way around this loop.
      if (p.end() && m->is_flag_error_dn()) {
	fg = cur->pick_dirfrag(m->get_error_dentry());
	curdir = cur->get_dirfrag(fg);
      } else
	curdir = cur->get_dirfrag(m->get_base_dir_frag());
    }

    if (p.end())
      break;
    
    // dentry
    CDentry *dn = add_replica_dentry(p, curdir, finished);
    
    if (p.end())
      break;

    // inode
    cur = add_replica_inode(p, dn, finished);

    next = MDiscoverReply::DIR;
  }

  // dir error?
  // or dir_auth hint?
  if (m->is_flag_error_dir() && !cur->is_dir()) {
    // not a dir.
    cur->take_waiting(CInode::WAIT_DIR, error);
  } else if (m->is_flag_error_dir() || m->get_dir_auth_hint() != CDIR_AUTH_UNKNOWN) {
    int who = m->get_dir_auth_hint();
    if (who == mds->get_nodeid()) who = -1;
    if (who >= 0)
      dout(7) << " dir_auth_hint is " << m->get_dir_auth_hint() << dendl;

    // try again?
    if (m->get_error_dentry().length()) {
      // wanted a dentry
      frag_t fg = cur->pick_dirfrag(m->get_error_dentry());
      CDir *dir = cur->get_dirfrag(fg);
      filepath relpath(m->get_error_dentry(), 0);

      if (cur->is_waiter_for(CInode::WAIT_DIR)) {
	if (cur->is_auth() || dir)
	  cur->take_waiting(CInode::WAIT_DIR, finished);
	else
	  discover_path(cur, m->get_wanted_snapid(), relpath, 0, m->get_wanted_xlocked(), who);
      } else
	  dout(7) << " doing nothing, nobody is waiting for dir" << dendl;

      if (dir) {
	// don't actaully need the hint, now
	if (dir->is_waiting_for_dentry(m->get_error_dentry().c_str(), m->get_wanted_snapid())) {
	  if (dir->is_auth() || dir->lookup(m->get_error_dentry()))
	    dir->take_dentry_waiting(m->get_error_dentry(), m->get_wanted_snapid(),
				     m->get_wanted_snapid(), finished);
	  else
	    discover_path(dir, m->get_wanted_snapid(), relpath, 0, m->get_wanted_xlocked());
	} else
	  dout(7) << " doing nothing, have dir but nobody is waiting on dentry "
		  << m->get_error_dentry() << dendl;
      }
    } else {
      // wanted dir or ino
      frag_t fg = m->get_base_dir_frag();
      CDir *dir = cur->get_dirfrag(fg);

      if (cur->is_waiter_for(CInode::WAIT_DIR)) {
	if (cur->is_auth() || dir)
	  cur->take_waiting(CInode::WAIT_DIR, finished);
	else
	  discover_dir_frag(cur, fg, 0, who);
      } else
	dout(7) << " doing nothing, nobody is waiting for dir" << dendl;

      if (dir && m->get_wanted_ino() && dir->is_waiting_for_ino(m->get_wanted_ino())) {
	if (dir->is_auth() || get_inode(m->get_wanted_ino()))
	  dir->take_ino_waiting(m->get_wanted_ino(), finished);
	else
	  discover_ino(dir, m->get_wanted_ino(), 0, m->get_wanted_xlocked());
      } else
	dout(7) << " doing nothing, nobody is waiting for ino" << dendl;
    }
  }

  // waiters
  finish_contexts(g_ceph_context, error, -ENOENT);  // finish errors directly
  mds->queue_waiters(finished);

  // done
  m->put();
}



// ----------------------------
// REPLICAS

CDir *MDCache::add_replica_dir(bufferlist::iterator& p, CInode *diri, int from,
			       list<Context*>& finished)
{
  dirfrag_t df;
  ::decode(df, p);

  assert(diri->ino() == df.ino);

  // add it (_replica_)
  CDir *dir = diri->get_dirfrag(df.frag);

  if (dir) {
    // had replica. update w/ new nonce.
    dir->decode_replica(p);
    dout(7) << "add_replica_dir had " << *dir << " nonce " << dir->replica_nonce << dendl;
  } else {
    // force frag to leaf in the diri tree
    if (!diri->dirfragtree.is_leaf(df.frag)) {
      dout(7) << "add_replica_dir forcing frag " << df.frag << " to leaf in the fragtree "
	      << diri->dirfragtree << dendl;
      diri->dirfragtree.force_to_leaf(g_ceph_context, df.frag);
    }

    // add replica.
    dir = diri->add_dirfrag( new CDir(diri, df.frag, this, false) );
    dir->decode_replica(p);

    // is this a dir_auth delegation boundary?
    if (from != diri->authority().first ||
	diri->is_ambiguous_auth() ||
	diri->is_base())
      adjust_subtree_auth(dir, from);
    
    dout(7) << "add_replica_dir added " << *dir << " nonce " << dir->replica_nonce << dendl;
    
    // get waiters
    diri->take_waiting(CInode::WAIT_DIR, finished);
  }

  return dir;
}

CDir *MDCache::forge_replica_dir(CInode *diri, frag_t fg, int from)
{
  assert(mds->mdsmap->get_state(from) < MDSMap::STATE_REJOIN);
  
  // forge a replica.
  CDir *dir = diri->add_dirfrag( new CDir(diri, fg, this, false) );
  
  // i'm assuming this is a subtree root. 
  adjust_subtree_auth(dir, from);

  dout(7) << "forge_replica_dir added " << *dir << " while mds." << from << " is down" << dendl;

  return dir;
}

CDentry *MDCache::add_replica_dentry(bufferlist::iterator& p, CDir *dir, list<Context*>& finished)
{
  string name;
  snapid_t last;
  ::decode(name, p);
  ::decode(last, p);

  CDentry *dn = dir->lookup(name, last);
  
  // have it?
  if (dn) {
    dn->decode_replica(p, false);
    dout(7) << "add_replica_dentry had " << *dn << dendl;
  } else {
    dn = dir->add_null_dentry(name, 1 /* this will get updated below */, last);
    dn->decode_replica(p, true);
    dout(7) << "add_replica_dentry added " << *dn << dendl;
  }

  dir->take_dentry_waiting(name, dn->first, dn->last, finished);

  return dn;
}

CInode *MDCache::add_replica_inode(bufferlist::iterator& p, CDentry *dn, list<Context*>& finished)
{
  inodeno_t ino;
  snapid_t last;
  ::decode(ino, p);
  ::decode(last, p);
  CInode *in = get_inode(ino, last);
  if (!in) {
    in = new CInode(this, false, 1, last);
    in->decode_replica(p, true);
    add_inode(in);
    if (in->ino() == MDS_INO_ROOT)
      in->inode_auth.first = 0;
    else if (in->is_mdsdir())
      in->inode_auth.first = in->ino() - MDS_INO_MDSDIR_OFFSET;
    dout(10) << "add_replica_inode added " << *in << dendl;
    if (dn) {
      assert(dn->get_linkage()->is_null());
      dn->dir->link_primary_inode(dn, in);
    }
  } else {
    in->decode_replica(p, false);
    dout(10) << "add_replica_inode had " << *in << dendl;
  }

  if (dn) {
    if (!dn->get_linkage()->is_primary() || dn->get_linkage()->get_inode() != in)
      dout(10) << "add_replica_inode different linkage in dentry " << *dn << dendl;
    
    dn->get_dir()->take_ino_waiting(in->ino(), finished);
  }
  
  return in;
}

 
void MDCache::replicate_stray(CDentry *straydn, int who, bufferlist& bl)
{
  replicate_inode(get_myin(), who, bl);
  replicate_dir(straydn->get_dir()->inode->get_parent_dn()->get_dir(), who, bl);
  replicate_dentry(straydn->get_dir()->inode->get_parent_dn(), who, bl);
  replicate_inode(straydn->get_dir()->inode, who, bl);
  replicate_dir(straydn->get_dir(), who, bl);
  replicate_dentry(straydn, who, bl);
}
   
CDentry *MDCache::add_replica_stray(bufferlist &bl, int from)
{
  list<Context*> finished;
  bufferlist::iterator p = bl.begin();

  CInode *mdsin = add_replica_inode(p, NULL, finished);
  CDir *mdsdir = add_replica_dir(p, mdsin, from, finished);
  CDentry *straydirdn = add_replica_dentry(p, mdsdir, finished);
  CInode *strayin = add_replica_inode(p, straydirdn, finished);
  CDir *straydir = add_replica_dir(p, strayin, from, finished);
  CDentry *straydn = add_replica_dentry(p, straydir, finished);
  if (!finished.empty())
    mds->queue_waiters(finished);

  return straydn;
}


int MDCache::send_dir_updates(CDir *dir, bool bcast)
{
  // this is an FYI, re: replication

  set<int> who;
  if (bcast) {
    mds->get_mds_map()->get_active_mds_set(who);
  } else {
    for (map<int,int>::iterator p = dir->replicas_begin();
	 p != dir->replicas_end();
	 ++p)
      who.insert(p->first);
  }
  
  dout(7) << "sending dir_update on " << *dir << " bcast " << bcast << " to " << who << dendl;

  filepath path;
  dir->inode->make_path(path);

  int whoami = mds->get_nodeid();
  for (set<int>::iterator it = who.begin();
       it != who.end();
       ++it) {
    if (*it == whoami) continue;
    //if (*it == except) continue;
    dout(7) << "sending dir_update on " << *dir << " to " << *it << dendl;

    mds->send_message_mds(new MDirUpdate(mds->get_nodeid(),
					 dir->dirfrag(),
					 dir->dir_rep,
					 dir->dir_rep_by,
					 path,
					 bcast),
			  *it);
  }

  return 0;
}

/* This function DOES put the passed message before returning */
void MDCache::handle_dir_update(MDirUpdate *m)
{
  CDir *dir = get_dirfrag(m->get_dirfrag());
  if (!dir) {
    dout(5) << "dir_update on " << m->get_dirfrag() << ", don't have it" << dendl;

    // discover it?
    if (m->should_discover()) {
      // only try once! 
      // this is key to avoid a fragtree update race, among other things.
      m->tried_discover();        
      vector<CDentry*> trace;
      CInode *in;
      filepath path = m->get_path();
      dout(5) << "trying discover on dir_update for " << path << dendl;
      int r = path_traverse(NULL, m, NULL, path, &trace, &in, MDS_TRAVERSE_DISCOVER);
      if (r > 0)
        return;
      assert(r == 0);
      open_remote_dirfrag(in, m->get_dirfrag().frag, 
			  new C_MDS_RetryMessage(mds, m));
      return;
    }

    m->put();
    return;
  }

  // update
  dout(5) << "dir_update on " << *dir << dendl;
  dir->dir_rep = m->get_dir_rep();
  dir->dir_rep_by = m->get_dir_rep_by();
  
  // done
  m->put();
}





// LINK

void MDCache::send_dentry_link(CDentry *dn)
{
  dout(7) << "send_dentry_link " << *dn << dendl;

  CDir *subtree = get_subtree_root(dn->get_dir());
  for (map<int,int>::iterator p = dn->replicas_begin(); 
       p != dn->replicas_end(); 
       ++p) {
    if (mds->mdsmap->get_state(p->first) < MDSMap::STATE_REJOIN ||
	(mds->mdsmap->get_state(p->first) == MDSMap::STATE_REJOIN &&
	 rejoin_gather.count(p->first)))
      continue;
    CDentry::linkage_t *dnl = dn->get_linkage();
    MDentryLink *m = new MDentryLink(subtree->dirfrag(), dn->get_dir()->dirfrag(),
				     dn->name, dnl->is_primary());
    if (dnl->is_primary()) {
      dout(10) << "  primary " << *dnl->get_inode() << dendl;
      replicate_inode(dnl->get_inode(), p->first, m->bl);
    } else if (dnl->is_remote()) {
      inodeno_t ino = dnl->get_remote_ino();
      __u8 d_type = dnl->get_remote_d_type();
      dout(10) << "  remote " << ino << " " << d_type << dendl;
      ::encode(ino, m->bl);
      ::encode(d_type, m->bl);
    } else
      assert(0);   // aie, bad caller!
    mds->send_message_mds(m, p->first);
  }
}

/* This function DOES put the passed message before returning */
void MDCache::handle_dentry_link(MDentryLink *m)
{

  CDentry *dn = NULL;
  CDir *dir = get_dirfrag(m->get_dirfrag());
  if (!dir) {
    dout(7) << "handle_dentry_link don't have dirfrag " << m->get_dirfrag() << dendl;
  } else {
    dn = dir->lookup(m->get_dn());
    if (!dn) {
      dout(7) << "handle_dentry_link don't have dentry " << *dir << " dn " << m->get_dn() << dendl;
    } else {
      dout(7) << "handle_dentry_link on " << *dn << dendl;
      CDentry::linkage_t *dnl = dn->get_linkage();

      assert(!dn->is_auth());
      assert(dnl->is_null());
    }
  }

  bufferlist::iterator p = m->bl.begin();
  list<Context*> finished;
  if (dn) {
    if (m->get_is_primary()) {
      // primary link.
      add_replica_inode(p, dn, finished);
    } else {
      // remote link, easy enough.
      inodeno_t ino;
      __u8 d_type;
      ::decode(ino, p);
      ::decode(d_type, p);
      dir->link_remote_inode(dn, ino, d_type);
    }
  } else if (m->get_is_primary()) {
    CInode *in = add_replica_inode(p, NULL, finished);
    assert(in->get_num_ref() == 0);
    assert(in->get_parent_dn() == NULL);
    map<int, MCacheExpire*> expiremap;
    int from = m->get_source().num();
    expiremap[from] = new MCacheExpire(mds->get_nodeid());
    expiremap[from]->add_inode(m->get_subtree(), in->vino(), in->get_replica_nonce());
    send_expire_messages(expiremap);
    remove_inode(in);
  }

  if (!finished.empty())
    mds->queue_waiters(finished);

  m->put();
  return;
}


// UNLINK

void MDCache::send_dentry_unlink(CDentry *dn, CDentry *straydn, MDRequest *mdr)
{
  dout(10) << "send_dentry_unlink " << *dn << dendl;
  // share unlink news with replicas
  for (map<int,int>::iterator it = dn->replicas_begin();
       it != dn->replicas_end();
       ++it) {
    // don't tell (rmdir) witnesses; they already know
    if (mdr && mdr->more()->witnessed.count(it->first))
      continue;

    if (mds->mdsmap->get_state(it->first) < MDSMap::STATE_REJOIN ||
	(mds->mdsmap->get_state(it->first) == MDSMap::STATE_REJOIN &&
	 rejoin_gather.count(it->first)))
      continue;

    MDentryUnlink *unlink = new MDentryUnlink(dn->get_dir()->dirfrag(), dn->name);
    if (straydn)
      replicate_stray(straydn, it->first, unlink->straybl);
    mds->send_message_mds(unlink, it->first);
  }
}

/* This function DOES put the passed message before returning */
void MDCache::handle_dentry_unlink(MDentryUnlink *m)
{
  // straydn
  CDentry *straydn = NULL;
  if (m->straybl.length())
    straydn = add_replica_stray(m->straybl, m->get_source().num());

  CDir *dir = get_dirfrag(m->get_dirfrag());
  if (!dir) {
    dout(7) << "handle_dentry_unlink don't have dirfrag " << m->get_dirfrag() << dendl;
  } else {
    CDentry *dn = dir->lookup(m->get_dn());
    if (!dn) {
      dout(7) << "handle_dentry_unlink don't have dentry " << *dir << " dn " << m->get_dn() << dendl;
    } else {
      dout(7) << "handle_dentry_unlink on " << *dn << dendl;
      CDentry::linkage_t *dnl = dn->get_linkage();

      // open inode?
      if (dnl->is_primary()) {
	CInode *in = dnl->get_inode();
	dn->dir->unlink_inode(dn);
	assert(straydn);
	straydn->dir->link_primary_inode(straydn, in);

	// in->first is lazily updated on replica; drag it forward so
	// that we always keep it in sync with the dnq
	assert(straydn->first >= in->first);
	in->first = straydn->first;

	// update subtree map?
	if (in->is_dir()) 
	  adjust_subtree_after_rename(in, dir, false);

	// send caps to auth (if we're not already)
	if (in->is_any_caps() &&
	    !in->state_test(CInode::STATE_EXPORTINGCAPS))
	  migrator->export_caps(in);
	
	touch_dentry_bottom(straydn); // move stray to end of lru
	straydn = NULL;
      } else {
	assert(!straydn);
	assert(dnl->is_remote());
	dn->dir->unlink_inode(dn);
      }
      assert(dnl->is_null());
      
      // move to bottom of lru
      touch_dentry_bottom(dn);
    }
  }

  // race with trim_dentry()
  if (straydn) {
    assert(straydn->get_num_ref() == 0);
    assert(straydn->get_linkage()->is_null());
    map<int, MCacheExpire*> expiremap;
    trim_dentry(straydn, expiremap);
    send_expire_messages(expiremap);
  }

  m->put();
  return;
}






// ===================================================================



// ===================================================================
// FRAGMENT


/** 
 * adjust_dir_fragments -- adjust fragmentation for a directory
 *
 * @param diri directory inode
 * @param basefrag base fragment
 * @param bits bit adjustment.  positive for split, negative for merge.
 */
void MDCache::adjust_dir_fragments(CInode *diri, frag_t basefrag, int bits,
				   list<CDir*>& resultfrags, 
				   list<Context*>& waiters,
				   bool replay)
{
  dout(10) << "adjust_dir_fragments " << basefrag << " " << bits 
	   << " on " << *diri << dendl;

  list<CDir*> srcfrags;
  diri->get_dirfrags_under(basefrag, srcfrags);

  adjust_dir_fragments(diri, srcfrags, basefrag, bits, resultfrags, waiters, replay);
}

CDir *MDCache::force_dir_fragment(CInode *diri, frag_t fg)
{
  CDir *dir = diri->get_dirfrag(fg);
  if (dir)
    return dir;

  dout(10) << "force_dir_fragment " << fg << " on " << *diri << dendl;

  list<CDir*> src, result;
  list<Context*> waiters;

  // split a parent?
  frag_t parent = diri->dirfragtree.get_branch_or_leaf(fg);
  while (1) {
    CDir *pdir = diri->get_dirfrag(parent);
    if (pdir) {
      int split = fg.bits() - parent.bits();
      dout(10) << " splitting parent by " << split << " " << *pdir << dendl;
      src.push_back(pdir);
      adjust_dir_fragments(diri, src, parent, split, result, waiters, true);
      dir = diri->get_dirfrag(fg);
      if (dir)
        dout(10) << "force_dir_fragment result " << *dir << dendl;
      return dir;
    }
    if (parent == frag_t())
      break;
    frag_t last = parent;
    parent = parent.parent();
    dout(10) << " " << last << " parent is " << parent << dendl;
  }

  // hoover up things under fg?
  diri->get_dirfrags_under(fg, src);
  if (src.empty()) {
    dout(10) << "force_dir_fragment no frags under " << fg << dendl;
    return NULL;
  }
  dout(10) << " will combine frags under " << fg << ": " << src << dendl;
  adjust_dir_fragments(diri, src, fg, 0, result, waiters, true);
  dir = result.front();
  dout(10) << "force_dir_fragment result " << *dir << dendl;
  return dir;
}

void MDCache::adjust_dir_fragments(CInode *diri,
				   list<CDir*>& srcfrags,
				   frag_t basefrag, int bits,
				   list<CDir*>& resultfrags, 
				   list<Context*>& waiters,
				   bool replay)
{
  dout(10) << "adjust_dir_fragments " << basefrag << " bits " << bits
	   << " srcfrags " << srcfrags
	   << " on " << *diri << dendl;

  // adjust fragtree
  // yuck.  we may have discovered the inode while it was being fragmented.
  if (!diri->dirfragtree.is_leaf(basefrag))
    diri->dirfragtree.force_to_leaf(g_ceph_context, basefrag);

  if (bits > 0)
    diri->dirfragtree.split(basefrag, bits);
  dout(10) << " new fragtree is " << diri->dirfragtree << dendl;

  if (srcfrags.empty())
    return;

  // split
  CDir *parent_dir = diri->get_parent_dir();
  CDir *parent_subtree = 0;
  if (parent_dir)
    parent_subtree = get_subtree_root(parent_dir);

  if (bits > 0) {
    // SPLIT
    assert(srcfrags.size() == 1);
    CDir *dir = srcfrags.front();

    dir->split(bits, resultfrags, waiters, replay);

    // did i change the subtree map?
    if (dir->is_subtree_root()) {
      // new frags are now separate subtrees
      for (list<CDir*>::iterator p = resultfrags.begin();
	   p != resultfrags.end();
	   ++p)
	subtrees[*p].clear();   // new frag is now its own subtree
      
      // was i a bound?
      if (parent_subtree) {
	assert(subtrees[parent_subtree].count(dir));
	subtrees[parent_subtree].erase(dir);
	for (list<CDir*>::iterator p = resultfrags.begin();
	     p != resultfrags.end();
	     ++p)
	  subtrees[parent_subtree].insert(*p);
      }
      
      // adjust my bounds.
      set<CDir*> bounds;
      bounds.swap(subtrees[dir]);
      subtrees.erase(dir);
      for (set<CDir*>::iterator p = bounds.begin();
	   p != bounds.end();
	   ++p) {
	CDir *frag = get_subtree_root((*p)->get_parent_dir());
	subtrees[frag].insert(*p);
      }

      show_subtrees(10);

      // dir has no PIN_SUBTREE; CDir::purge_stolen() drops it.
      dir->dir_auth = CDIR_AUTH_DEFAULT;
    }
    
    diri->close_dirfrag(dir->get_frag());
    
  } else {
    // MERGE

    // are my constituent bits subtrees?  if so, i will be too.
    // (it's all or none, actually.)
    bool was_subtree = false;
    set<CDir*> new_bounds;
    for (list<CDir*>::iterator p = srcfrags.begin(); p != srcfrags.end(); ++p) {
      CDir *dir = *p;
      if (dir->is_subtree_root()) {
	dout(10) << " taking srcfrag subtree bounds from " << *dir << dendl;
	was_subtree = true;
	map<CDir*, set<CDir*> >::iterator q = subtrees.find(dir);
	set<CDir*>::iterator r = q->second.begin();
	while (r != subtrees[dir].end()) {
	  new_bounds.insert(*r);
	  subtrees[dir].erase(r++);
	}
	subtrees.erase(q);
	
	// remove myself as my parent's bound
	if (parent_subtree)
	  subtrees[parent_subtree].erase(dir);
      }
    }
    
    // merge
    CDir *f = new CDir(diri, basefrag, this, srcfrags.front()->is_auth());
    f->merge(srcfrags, waiters, replay);
    diri->add_dirfrag(f);

    if (was_subtree) {
      subtrees[f].swap(new_bounds);
      if (parent_subtree)
	subtrees[parent_subtree].insert(f);
      
      show_subtrees(10);
    }

    resultfrags.push_back(f);
  }
}


class C_MDC_FragmentFrozen : public Context {
  MDCache *mdcache;
  list<CDir*> dirs;
  frag_t basefrag;
  int by;
public:
  C_MDC_FragmentFrozen(MDCache *m, list<CDir*> d, frag_t bf, int b) : mdcache(m), dirs(d), basefrag(bf), by(b) {}
  virtual void finish(int r) {
    mdcache->fragment_frozen(dirs, basefrag, by);
  }
};

bool MDCache::can_fragment(CInode *diri, list<CDir*>& dirs)
{
  if (mds->mdsmap->is_degraded()) {
    dout(7) << "can_fragment: cluster degraded, no fragmenting for now" << dendl;
    return false;
  }
  if (diri->get_parent_dir() &&
      diri->get_parent_dir()->get_inode()->is_stray()) {
    dout(7) << "can_fragment: i won't merge|split anything in stray" << dendl;
    return false;
  }
  if (diri->is_mdsdir() || diri->ino() == MDS_INO_CEPH) {
    dout(7) << "can_fragment: i won't fragment the mdsdir or .ceph" << dendl;
    return false;
  }

  for (list<CDir*>::iterator p = dirs.begin(); p != dirs.end(); ++p) {
    CDir *dir = *p;
    if (dir->state_test(CDir::STATE_FRAGMENTING)) {
      dout(7) << "can_fragment: already fragmenting " << *dir << dendl;
      return false;
    }
    if (!dir->is_auth()) {
      dout(7) << "can_fragment: not auth on " << *dir << dendl;
      return false;
    }
    if (dir->is_frozen() ||
	dir->is_freezing()) {
      dout(7) << "can_fragment: can't merge, freezing|frozen.  wait for other exports to finish first." << dendl;
      return false;
    }
  }

  return true;
}

void MDCache::split_dir(CDir *dir, int bits)
{
  dout(7) << "split_dir " << *dir << " bits " << bits << dendl;
  assert(dir->is_auth());
  CInode *diri = dir->inode;

  list<CDir*> dirs;
  dirs.push_back(dir);

  if (!can_fragment(diri, dirs))
    return;

  C_GatherBuilder gather(g_ceph_context, 
	  new C_MDC_FragmentFrozen(this, dirs, dir->get_frag(), bits));
  fragment_freeze_dirs(dirs, gather);
  gather.activate();

  // initial mark+complete pass
  fragment_mark_and_complete(dirs);
}

void MDCache::merge_dir(CInode *diri, frag_t frag)
{
  dout(7) << "merge_dir to " << frag << " on " << *diri << dendl;

  list<CDir*> dirs;
  if (!diri->get_dirfrags_under(frag, dirs)) {
    dout(7) << "don't have all frags under " << frag << " for " << *diri << dendl;
    return;
  }

  if (diri->dirfragtree.is_leaf(frag)) {
    dout(10) << " " << frag << " already a leaf for " << *diri << dendl;
    return;
  }

  if (!can_fragment(diri, dirs))
    return;

  CDir *first = dirs.front();
  int bits = first->get_frag().bits() - frag.bits();
  dout(10) << " we are merginb by " << bits << " bits" << dendl;

  C_GatherBuilder gather(g_ceph_context,
	  new C_MDC_FragmentFrozen(this, dirs, frag, bits));
  fragment_freeze_dirs(dirs, gather);
  gather.activate();

  // initial mark+complete pass
  fragment_mark_and_complete(dirs);
}

void MDCache::fragment_freeze_dirs(list<CDir*>& dirs, C_GatherBuilder &gather)
{
  for (list<CDir*>::iterator p = dirs.begin(); p != dirs.end(); ++p) {
    CDir *dir = *p;
    dir->auth_pin(dir);  // until we mark and complete them
    dir->state_set(CDir::STATE_FRAGMENTING);
    dir->freeze_dir();
    assert(dir->is_freezing_dir());
    dir->add_waiter(CDir::WAIT_FROZEN, gather.new_sub());
  }
}

class C_MDC_FragmentMarking : public Context {
  MDCache *mdcache;
  list<CDir*> dirs;
public:
  C_MDC_FragmentMarking(MDCache *m, list<CDir*>& d) : mdcache(m), dirs(d) {}
  virtual void finish(int r) {
    mdcache->fragment_mark_and_complete(dirs);
  }
};

void MDCache::fragment_mark_and_complete(list<CDir*>& dirs)
{
  CInode *diri = dirs.front()->get_inode();
  dout(10) << "fragment_mark_and_complete " << dirs << " on " << *diri << dendl;

  C_GatherBuilder gather(g_ceph_context);
  
  for (list<CDir*>::iterator p = dirs.begin();
       p != dirs.end();
       ++p) {
    CDir *dir = *p;

    if (!dir->is_complete()) {
      dout(15) << " fetching incomplete " << *dir << dendl;
      dir->fetch(gather.new_sub(),
		 true);  // ignore authpinnability
    } 
    else if (!dir->state_test(CDir::STATE_DNPINNEDFRAG)) {
      dout(15) << " marking " << *dir << dendl;
      for (CDir::map_t::iterator p = dir->items.begin();
	   p != dir->items.end();
	   ++p) {
	CDentry *dn = p->second;
	dn->get(CDentry::PIN_FRAGMENTING);
	assert(!dn->state_test(CDentry::STATE_FRAGMENTING));
	dn->state_set(CDentry::STATE_FRAGMENTING);
      }
      dir->state_set(CDir::STATE_DNPINNEDFRAG);
      dir->auth_unpin(dir);
    }
    else {
      dout(15) << " already marked " << *dir << dendl;
    }
  }
  if (gather.has_subs()) {
    gather.set_finisher(new C_MDC_FragmentMarking(this, dirs));
    gather.activate();
  }

  // flush log so that request auth_pins are retired
  mds->mdlog->flush();
}

void MDCache::fragment_unmark_unfreeze_dirs(list<CDir*>& dirs)
{
  dout(10) << "fragment_unmark_unfreeze_dirs " << dirs << dendl;
  for (list<CDir*>::iterator p = dirs.begin(); p != dirs.end(); ++p) {
    CDir *dir = *p;
    dout(10) << " frag " << *dir << dendl;

    assert(dir->state_test(CDir::STATE_DNPINNEDFRAG));
    dir->state_clear(CDir::STATE_DNPINNEDFRAG);

    assert(dir->state_test(CDir::STATE_FRAGMENTING));
    dir->state_clear(CDir::STATE_FRAGMENTING);

    for (CDir::map_t::iterator p = dir->items.begin();
	 p != dir->items.end();
	 ++p) {
      CDentry *dn = p->second;
      assert(dn->state_test(CDentry::STATE_FRAGMENTING));
      dn->state_clear(CDentry::STATE_FRAGMENTING);
      dn->put(CDentry::PIN_FRAGMENTING);
    }

    dir->unfreeze_dir();
  }
}

class C_MDC_FragmentLoggedAndStored : public Context {
  MDCache *mdcache;
  MDRequest *mdr;
public:
  C_MDC_FragmentLoggedAndStored(MDCache *m, MDRequest *r) : mdcache(m), mdr(r) {}
  virtual void finish(int r) {
    mdcache->fragment_logged_and_stored(mdr);
  }
};

class C_MDC_FragmentCommit : public Context {
  MDCache *mdcache;
  dirfrag_t basedirfrag;
  list<CDir*> resultfrags;
public:
  C_MDC_FragmentCommit(MDCache *m, inodeno_t ino, frag_t f, list<CDir*>& l) :
    mdcache(m), basedirfrag(ino, f) {
    resultfrags.swap(l);
  }
  virtual void finish(int r) {
    mdcache->_fragment_committed(basedirfrag, resultfrags);
  }
};

void MDCache::fragment_frozen(list<CDir*>& dirs, frag_t basefrag, int bits)
{
  dout(10) << "fragment_frozen " << dirs << " " << basefrag << " by " << bits
	   << " on " << dirs.front()->get_inode() << dendl;

  if (bits > 0)
    assert(dirs.size() == 1);
  else if (bits < 0)
    assert(dirs.size() > 1);
  else
    assert(0);

  MDRequest *mdr = request_start_internal(CEPH_MDS_OP_FRAGMENTDIR);
  fragment_info_t &info = fragment_requests[mdr->reqid];
  info.basefrag = basefrag;
  info.bits = bits;
  info.dirs = dirs;

  dispatch_fragment_dir(mdr);
}

void MDCache::dispatch_fragment_dir(MDRequest *mdr)
{
  assert(fragment_requests.count(mdr->reqid));
  fragment_info_t &info = fragment_requests[mdr->reqid];
  CInode *diri = info.dirs.front()->get_inode();

  dout(10) << "dispatch_fragment_dir " << info.resultfrags << " "
	   << info.basefrag << " bits " << info.bits << " on " << *diri << dendl;

  // avoid freeze dir deadlock
  if (!mdr->is_auth_pinned(diri)) {
    if (!diri->can_auth_pin()) {
      dout(10) << " can't auth_pin " << *diri << ", requeuing dir "
	       << info.dirs.front()->dirfrag() << dendl;
      if (info.bits > 0)
	mds->balancer->queue_split(info.dirs.front());
      else
	mds->balancer->queue_merge(info.dirs.front());
      fragment_unmark_unfreeze_dirs(info.dirs);
      fragment_requests.erase(mdr->reqid);
      request_finish(mdr);
      return;
    }
    mdr->auth_pin(diri);
  }

  set<SimpleLock*> rdlocks, wrlocks, xlocks;
  wrlocks.insert(&diri->dirfragtreelock);
  // prevent a racing gather on any other scatterlocks too
  wrlocks.insert(&diri->nestlock);
  wrlocks.insert(&diri->filelock);
  if (!mds->locker->acquire_locks(mdr, rdlocks, wrlocks, xlocks))
    return;

  mdr->ls = mds->mdlog->get_current_segment();
  EFragment *le = new EFragment(mds->mdlog, EFragment::OP_PREPARE, diri->ino(),
			        info.basefrag, info.bits);
  mds->mdlog->start_entry(le);

  list<frag_t> old_frags;
  for (list<CDir*>::iterator p = info.dirs.begin(); p != info.dirs.end(); ++p)
    old_frags.push_back((*p)->get_frag());

  // refragment
  list<Context*> waiters;
  adjust_dir_fragments(diri, info.dirs, info.basefrag, info.bits,
		       info.resultfrags, waiters, false);
  if (g_conf->mds_debug_frag)
    diri->verify_dirfrags();
  mds->queue_waiters(waiters);

  le->metablob.add_dir_context(*info.resultfrags.begin());

  // dft lock
  mds->locker->mark_updated_scatterlock(&diri->dirfragtreelock);
  mdr->ls->dirty_dirfrag_dirfragtree.push_back(&diri->item_dirty_dirfrag_dirfragtree);
  mdr->add_updated_lock(&diri->dirfragtreelock);

  /*
  // filelock
  mds->locker->mark_updated_scatterlock(&diri->filelock);
  mut->ls->dirty_dirfrag_dir.push_back(&diri->item_dirty_dirfrag_dir);
  mut->add_updated_lock(&diri->filelock);

  // dirlock
  mds->locker->mark_updated_scatterlock(&diri->nestlock);
  mut->ls->dirty_dirfrag_nest.push_back(&diri->item_dirty_dirfrag_nest);
  mut->add_updated_lock(&diri->nestlock);
  */

  // freeze, journal, and store resulting frags
  C_GatherBuilder gather(g_ceph_context, new C_MDC_FragmentLoggedAndStored(this, mdr));

  for (list<CDir*>::iterator p = info.resultfrags.begin();
       p != info.resultfrags.end();
       ++p) {
    CDir *dir = *p;
    dout(10) << " result frag " << *dir << dendl;
    le->metablob.add_dir(dir, false);

    // freeze and store them too
    dir->auth_pin(this);
    dir->state_set(CDir::STATE_FRAGMENTING);
    dir->commit(0, gather.new_sub(), true);  // ignore authpinnability
  }

  add_uncommitted_fragment(dirfrag_t(diri->ino(), info.basefrag), info.bits, old_frags);
  mds->mdlog->submit_entry(le, gather.new_sub());
  mds->mdlog->flush();
  gather.activate();
}

void MDCache::fragment_logged_and_stored(MDRequest *mdr)
{
  assert(fragment_requests.count(mdr->reqid));
  fragment_info_t &info = fragment_requests[mdr->reqid];
  CInode *diri = info.resultfrags.front()->get_inode();

  dout(10) << "fragment_logged_and_stored " << info.resultfrags << " " << info.basefrag
	   << " bits " << info.bits << " on " << *diri << dendl;

  // tell peers
  CDir *first = *info.resultfrags.begin();
  for (map<int,int>::iterator p = first->replica_map.begin();
       p != first->replica_map.end();
       ++p) {
    if (mds->mdsmap->get_state(p->first) <= MDSMap::STATE_REJOIN)
      continue;
    MMDSFragmentNotify *notify = new MMDSFragmentNotify(diri->ino(), info.basefrag, info.bits);

    /*
    // freshly replicate new dirs to peers
    for (list<CDir*>::iterator q = resultfrags.begin(); q != resultfrags.end(); q++)
      replicate_dir(*q, p->first, notify->basebl);
    */

    mds->send_message_mds(notify, p->first);
  } 
  
  mdr->apply();  // mark scatterlock
  mds->locker->drop_locks(mdr);

  // unfreeze resulting frags
  for (list<CDir*>::iterator p = info.resultfrags.begin();
       p != info.resultfrags.end();
       ++p) {
    CDir *dir = *p;
    dout(10) << " result frag " << *dir << dendl;

    for (CDir::map_t::iterator p = dir->items.begin();
	 p != dir->items.end();
	 ++p) { 
      CDentry *dn = p->second;
      assert(dn->state_test(CDentry::STATE_FRAGMENTING));
      dn->state_clear(CDentry::STATE_FRAGMENTING);
      dn->put(CDentry::PIN_FRAGMENTING);
    }

    // unfreeze
    dir->unfreeze_dir();
  }

  // journal commit
  EFragment *le = new EFragment(mds->mdlog, EFragment::OP_COMMIT,
				diri->ino(), info.basefrag, info.bits);
  mds->mdlog->start_submit_entry(le, new C_MDC_FragmentCommit(this, diri->ino(), info.basefrag,
							      info.resultfrags));

  fragment_requests.erase(mdr->reqid);
  request_finish(mdr);
}

void MDCache::_fragment_committed(dirfrag_t basedirfrag, list<CDir*>& resultfrags)
{
  dout(10) << "fragment_committed " << basedirfrag << dendl;
  assert(uncommitted_fragments.count(basedirfrag));
  ufragment &uf = uncommitted_fragments[basedirfrag];

  // remove old frags
  C_GatherBuilder gather(g_ceph_context, new C_MDC_FragmentFinish(this, basedirfrag, resultfrags));

  SnapContext nullsnapc;
  object_locator_t oloc(mds->mdsmap->get_metadata_pool());
  for (list<frag_t>::iterator p = uf.old_frags.begin();
       p != uf.old_frags.end();
       ++p) {
    object_t oid = CInode::get_object_name(basedirfrag.ino, *p, "");
    ObjectOperation op;
    if (*p == frag_t()) {
      // backtrace object
      dout(10) << " truncate orphan dirfrag " << oid << dendl;
      op.truncate(0);
    } else {
      dout(10) << " removing orphan dirfrag " << oid << dendl;
      op.remove();
    }
    mds->objecter->mutate(oid, oloc, op, nullsnapc, ceph_clock_now(g_ceph_context),
			  0, NULL, gather.new_sub());
  }

  assert(gather.has_subs());
  gather.activate();
}

void MDCache::_fragment_finish(dirfrag_t basedirfrag, list<CDir*>& resultfrags)
{
  dout(10) << "fragment_finish " << basedirfrag << dendl;
  assert(uncommitted_fragments.count(basedirfrag));

  // unmark & auth_unpin
  for (list<CDir*>::iterator p = resultfrags.begin(); p != resultfrags.end(); ++p) {
    (*p)->state_clear(CDir::STATE_FRAGMENTING);
    (*p)->auth_unpin(this);
  }

  finish_uncommitted_fragment(basedirfrag);
}

/* This function DOES put the passed message before returning */
void MDCache::handle_fragment_notify(MMDSFragmentNotify *notify)
{
  dout(10) << "handle_fragment_notify " << *notify << " from " << notify->get_source() << dendl;

  if (mds->get_state() < MDSMap::STATE_REJOIN) {
    notify->put();
    return;
  }

  CInode *diri = get_inode(notify->get_ino());
  if (diri) {
    frag_t base = notify->get_basefrag();
    int bits = notify->get_bits();

    if ((bits < 0 && diri->dirfragtree.is_leaf(base)) ||
	(bits > 0 && !diri->dirfragtree.is_leaf(base))) {
      dout(10) << " dft " << diri->dirfragtree << " state doesn't match " << base << " by " << bits
	       << ", must have found out during resolve/rejoin?  ignoring. " << *diri << dendl;
      notify->put();
      return;
    }

    // refragment
    list<Context*> waiters;
    list<CDir*> resultfrags;
    adjust_dir_fragments(diri, base, bits, 
			 resultfrags, waiters, false);
    if (g_conf->mds_debug_frag)
      diri->verify_dirfrags();
    
    /*
    // add new replica dirs values
    bufferlist::iterator p = notify->basebl.begin();
    while (!p.end()) {
      add_replica_dir(p, diri, notify->get_source().num(), waiters);
    */

    mds->queue_waiters(waiters);
  }

  notify->put();
}

void MDCache::add_uncommitted_fragment(dirfrag_t basedirfrag, int bits, list<frag_t>& old_frags)
{
  dout(10) << "add_uncommitted_fragment: base dirfrag " << basedirfrag << " bits " << bits << dendl;
  assert(!uncommitted_fragments.count(basedirfrag));
  ufragment& uf = uncommitted_fragments[basedirfrag];
  uf.old_frags = old_frags;
  uf.bits = bits;
}

void MDCache::finish_uncommitted_fragment(dirfrag_t basedirfrag)
{
  dout(10) << "finish_uncommitted_fragments: base dirfrag " << basedirfrag << dendl;
  if (uncommitted_fragments.count(basedirfrag)) {
    uncommitted_fragments.erase(basedirfrag);
  }
}

void MDCache::rollback_uncommitted_fragments()
{
  dout(10) << "rollback_uncommitted_fragments: " << uncommitted_fragments.size() << " pending" << dendl;
  for (map<dirfrag_t, ufragment>::iterator p = uncommitted_fragments.begin();
       p != uncommitted_fragments.end();
       ++p) {
    ufragment &uf = p->second;
    CInode *diri = get_inode(p->first.ino);
    assert(diri);
    dout(10) << " rolling back " << p->first << " refragment by " << uf.bits << " bits" << dendl;
    list<CDir*> resultfrags;
    list<Context*> waiters;
    adjust_dir_fragments(diri, p->first.frag, -uf.bits, resultfrags, waiters, true);
    if (g_conf->mds_debug_frag)
      diri->verify_dirfrags();

    EFragment *le = new EFragment(mds->mdlog, EFragment::OP_ROLLBACK, diri->ino(), p->first.frag, uf.bits);
    mds->mdlog->start_submit_entry(le);
  }
  uncommitted_fragments.clear();
}



// ==============================================================
// debug crap

void MDCache::show_subtrees(int dbl)
{
  //dout(10) << "show_subtrees" << dendl;

  if (!g_conf->subsys.should_gather(ceph_subsys_mds, dbl))
    return;  // i won't print anything.

  if (subtrees.empty()) {
    dout(dbl) << "show_subtrees - no subtrees" << dendl;
    return;
  }

  // root frags
  list<CDir*> basefrags;
  for (set<CInode*>::iterator p = base_inodes.begin();
       p != base_inodes.end();
       ++p) 
    (*p)->get_dirfrags(basefrags);
  //dout(15) << "show_subtrees, base dirfrags " << basefrags << dendl;
  dout(15) << "show_subtrees" << dendl;

  // queue stuff
  list<pair<CDir*,int> > q;
  string indent;
  set<CDir*> seen;

  // calc max depth
  for (list<CDir*>::iterator p = basefrags.begin(); p != basefrags.end(); ++p) 
    q.push_back(pair<CDir*,int>(*p, 0));

  set<CDir*> subtrees_seen;

  int depth = 0;
  while (!q.empty()) {
    CDir *dir = q.front().first;
    int d = q.front().second;
    q.pop_front();

    if (subtrees.count(dir) == 0) continue;

    subtrees_seen.insert(dir);

    if (d > depth) depth = d;

    // sanity check
    //dout(25) << "saw depth " << d << " " << *dir << dendl;
    if (seen.count(dir)) dout(0) << "aah, already seen " << *dir << dendl;
    assert(seen.count(dir) == 0);
    seen.insert(dir);

    // nested items?
    if (!subtrees[dir].empty()) {
      for (set<CDir*>::iterator p = subtrees[dir].begin();
	   p != subtrees[dir].end();
	   ++p) {
	//dout(25) << " saw sub " << **p << dendl;
	q.push_front(pair<CDir*,int>(*p, d+1));
      }
    }
  }


  // print tree
  for (list<CDir*>::iterator p = basefrags.begin(); p != basefrags.end(); ++p) 
    q.push_back(pair<CDir*,int>(*p, 0));

  while (!q.empty()) {
    CDir *dir = q.front().first;
    int d = q.front().second;
    q.pop_front();

    if (subtrees.count(dir) == 0) continue;

    // adjust indenter
    while ((unsigned)d < indent.size()) 
      indent.resize(d);
    
    // pad
    string pad = "______________________________________";
    pad.resize(depth*2+1-indent.size());
    if (!subtrees[dir].empty()) 
      pad[0] = '.'; // parent


    string auth;
    if (dir->is_auth())
      auth = "auth ";
    else
      auth = " rep ";

    char s[10];
    if (dir->get_dir_auth().second == CDIR_AUTH_UNKNOWN)
      snprintf(s, sizeof(s), "%2d   ", dir->get_dir_auth().first);
    else
      snprintf(s, sizeof(s), "%2d,%2d", dir->get_dir_auth().first, dir->get_dir_auth().second);
    
    // print
    dout(dbl) << indent << "|_" << pad << s << " " << auth << *dir << dendl;

    if (dir->ino() == MDS_INO_ROOT)
      assert(dir->inode == root);
    if (dir->ino() == MDS_INO_MDSDIR(mds->get_nodeid()))
      assert(dir->inode == myin);
    if (dir->inode->is_stray() && (MDS_INO_STRAY_OWNER(dir->ino()) == mds->get_nodeid()))
      assert(strays[MDS_INO_STRAY_INDEX(dir->ino())] == dir->inode);

    // nested items?
    if (!subtrees[dir].empty()) {
      // more at my level?
      if (!q.empty() && q.front().second == d)
	indent += "| ";
      else
	indent += "  ";

      for (set<CDir*>::iterator p = subtrees[dir].begin();
	   p != subtrees[dir].end();
	   ++p) 
	q.push_front(pair<CDir*,int>(*p, d+2));
    }
  }

  // verify there isn't stray crap in subtree map
  int lost = 0;
  for (map<CDir*, set<CDir*> >::iterator p = subtrees.begin();
       p != subtrees.end();
       ++p) {
    if (subtrees_seen.count(p->first)) continue;
    dout(10) << "*** stray/lost entry in subtree map: " << *p->first << dendl;
    lost++;
  }
  assert(lost == 0);
}


void MDCache::show_cache()
{
  dout(7) << "show_cache" << dendl;
  
  for (hash_map<vinodeno_t,CInode*>::iterator it = inode_map.begin();
       it != inode_map.end();
       ++it) {
    // unlinked?
    if (!it->second->parent)
      dout(7) << " unlinked " << *it->second << dendl;
    
    // dirfrags?
    list<CDir*> dfs;
    it->second->get_dirfrags(dfs);
    for (list<CDir*>::iterator p = dfs.begin(); p != dfs.end(); ++p) {
      CDir *dir = *p;
      dout(7) << "  dirfrag " << *dir << dendl;
	    
      for (CDir::map_t::iterator p = dir->items.begin();
	   p != dir->items.end();
	   ++p) {
	CDentry *dn = p->second;
	dout(7) << "   dentry " << *dn << dendl;
	CDentry::linkage_t *dnl = dn->get_linkage();
	if (dnl->is_primary() && dnl->get_inode()) 
	  dout(7) << "    inode " << *dnl->get_inode() << dendl;
      }
    }
  }
}


void MDCache::dump_cache(const char *fn)
{
  int r;
  char deffn[200];
  if (!fn) {
    snprintf(deffn, sizeof(deffn), "cachedump.%d.mds%d", (int)mds->mdsmap->get_epoch(), mds->get_nodeid());
    fn = deffn;
  }

  dout(1) << "dump_cache to " << fn << dendl;

  int fd = ::open(fn, O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (fd < 0) {
    derr << "failed to open " << fn << ": " << cpp_strerror(errno) << dendl;
    return;
  }
  
  for (hash_map<vinodeno_t,CInode*>::iterator it = inode_map.begin();
       it != inode_map.end();
       ++it) {
    CInode *in = it->second;
    ostringstream ss;
    ss << *in << std::endl;
    std::string s = ss.str();
    r = safe_write(fd, s.c_str(), s.length());
    if (r < 0)
      return;

    list<CDir*> dfs;
    in->get_dirfrags(dfs);
    for (list<CDir*>::iterator p = dfs.begin(); p != dfs.end(); ++p) {
      CDir *dir = *p;
      ostringstream tt;
      tt << " " << *dir << std::endl;
      string t = tt.str();
      r = safe_write(fd, t.c_str(), t.length());
      if (r < 0)
	goto out;
      
      for (CDir::map_t::iterator q = dir->items.begin();
	   q != dir->items.end();
	   ++q) {
	CDentry *dn = q->second;
	ostringstream uu;
	uu << "  " << *dn << std::endl;
	string u = uu.str();
	r = safe_write(fd, u.c_str(), u.length());
	if (r < 0)
	  goto out;
      }
      dir->check_rstats();
    }
  }

 out:
  ::close(fd);
}



C_MDS_RetryRequest::C_MDS_RetryRequest(MDCache *c, MDRequest *r)
  : cache(c), mdr(r)
{
  mdr->get();
}

void C_MDS_RetryRequest::finish(int r)
{
  mdr->retry++;
  cache->dispatch_request(mdr);
  mdr->put();
}
