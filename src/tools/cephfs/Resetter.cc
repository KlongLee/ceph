// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2010 Greg Farnum <gregf@hq.newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#include "common/errno.h"
#include "osdc/Journaler.h"
#include "mds/JournalPointer.h"

#include "mds/mdstypes.h"
#include "mds/MDCache.h"
#include "mon/MonClient.h"
#include "mds/events/EResetJournal.h"

#include "Resetter.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_mds

int Resetter::init(mds_role_t role_, const std::string &type, bool hard)
{
  role = role_;
  int r = MDSUtility::init();
  if (r < 0) {
    return r;
  }

  auto fs = fsmap->get_filesystem(role.fscid);
  assert(nullptr != fs);

  is_mdlog = false;
  if (type == "mdlog") {
    JournalPointer jp(role.rank, fs->mds_map.get_metadata_pool());
    int rt = 0;
    if (hard) {
      jp.front = role.rank + MDS_INO_LOG_OFFSET;
      jp.back = 0;
      rt = jp.save(objecter);
      if (rt != 0) {
        derr << "Error writing journal pointer:  " << cpp_strerror(rt) << dendl;
        return rt;
      }
      ino = jp.front; // only need to reset ino for mdlog
    } else {
      rt = jp.load(objecter);
      if (rt != 0) {
        std::cerr << "Error loading journal: " << cpp_strerror(rt) <<
        ", pass --force to forcibly reset this journal" << std::endl;
        return rt;
      } else {
        ino = jp.front;
      }
    }
    is_mdlog = true;
  } else if (type == "purge_queue") {
    ino = MDS_INO_PURGE_QUEUE + role.rank;
  } else {
    ceph_abort(); // should not get here
  }
  return 0; 
}

int Resetter::reset()
{
  Mutex mylock("Resetter::reset::lock");
  Cond cond;
  bool done;
  int r;

  auto fs =  fsmap->get_filesystem(role.fscid);
  assert(fs != nullptr);

  Journaler journaler("resetter", ino,
      fs->mds_map.get_metadata_pool(),
      CEPH_FS_ONDISK_MAGIC,
      objecter, 0, 0, &finisher);

  lock.Lock();
  journaler.recover(new C_SafeCond(&mylock, &cond, &done, &r));
  lock.Unlock();

  mylock.Lock();
  while (!done)
    cond.Wait(mylock);
  mylock.Unlock();

  if (r != 0) {
    if (r == -ENOENT) {
      cerr << "journal does not exist on-disk. Did you set a bad rank?"
	   << std::endl;
      std::cerr << "Error loading journal: " << cpp_strerror(r) <<
        ", pass --force to forcibly reset this journal" << std::endl;
      return r;
    } else {
      cerr << "got error " << r << "from Journaler, failing" << std::endl;
      return r;
    }
  }

  lock.Lock();
  uint64_t old_start = journaler.get_read_pos();
  uint64_t old_end = journaler.get_write_pos();
  uint64_t old_len = old_end - old_start;
  cout << "old journal was " << old_start << "~" << old_len << std::endl;

  uint64_t new_start = round_up_to(old_end+1, journaler.get_layout_period());
  cout << "new journal start will be " << new_start
       << " (" << (new_start - old_end) << " bytes past old end)" << std::endl;

  journaler.set_read_pos(new_start);
  journaler.set_write_pos(new_start);
  journaler.set_expire_pos(new_start);
  journaler.set_trimmed_pos(new_start);
  journaler.set_writeable();

  cout << "writing journal head" << std::endl;
  journaler.write_head(new C_SafeCond(&mylock, &cond, &done, &r));
  lock.Unlock();

  mylock.Lock();
  while (!done)
    cond.Wait(mylock);
  mylock.Unlock();

  Mutex::Locker l(lock);
  if (r != 0) {
    return r;
  }
 
  if (is_mdlog) {
    r = _write_reset_event(&journaler); // reset envent is specific for mdlog journal
    if (r != 0) {
      return r;
    }
  }
  cout << "done" << std::endl;

  return 0;
}

int Resetter::reset_hard()
{
  auto fs =  fsmap->get_filesystem(role.fscid);
  
  Journaler journaler("resetter", ino,
    fs->mds_map.get_metadata_pool(),
    CEPH_FS_ONDISK_MAGIC,
    objecter, 0, 0, &finisher);
  journaler.set_writeable();

  file_layout_t default_log_layout = MDCache::gen_default_log_layout(
      fsmap->get_filesystem(role.fscid)->mds_map);
  journaler.create(&default_log_layout, g_conf->mds_journal_format);

  C_SaferCond cond;
  {
    Mutex::Locker l(lock);
    journaler.write_head(&cond);
  }
  
  int r = cond.wait();
  if (r != 0) {
    derr << "Error writing journal header: " << cpp_strerror(r) << dendl;
    return r;
  }
  
  if (is_mdlog) // reset event is specific for mdlog journal
  {
    Mutex::Locker l(lock);
    r = _write_reset_event(&journaler);
    if (r != 0) {
      derr << "Error writing EResetJournal: " << cpp_strerror(r) << dendl;
      return r;
    }
  }
  
  if (is_mdlog) {
    dout(4) << "Successfully wrote new journal pointer and header for rank "
      << role << dendl;
  } else {
    dout(4) << "Successfully wrote header for rank " << role << dendl;
  }
  return 0;
}

int Resetter::_write_reset_event(Journaler *journaler)
{
  assert(journaler != NULL);

  LogEvent *le = new EResetJournal;

  bufferlist bl;
  le->encode_with_header(bl, CEPH_FEATURES_SUPPORTED_DEFAULT);
  
  cout << "writing EResetJournal entry" << std::endl;
  C_SaferCond cond;
  journaler->append_entry(bl);
  journaler->flush(&cond);

  return cond.wait();
}

