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

#ifndef CEPH_LOGSEGMENT_H
#define CEPH_LOGSEGMENT_H

#include "include/elist.h"
#include "include/interval_set.h"
#include "include/Context.h"
#include "include/auto_shared_ptr.h"
#include "MDSContext.h"
#include "mdstypes.h"
#include "CInode.h"
#include "CDentry.h"
#include "CDir.h"

#include "include/unordered_set.h"
#include <atomic>

using ceph::unordered_set;

class CDir;
class CInode;
class CDentry;
class MDSRankBase;
struct MDPeerUpdate;

using AutoSharedLogSegment = auto_shared_ptr<LogSegment>;
using WeakLogSegment = std::weak_ptr<LogSegment>;

class LogSegment: public std::enable_shared_from_this<LogSegment> {
 public:
  using seq_t = uint64_t;
  constexpr static const seq_t SEQ_MAX = UINT64_MAX;

  [[nodiscard]] static AutoSharedLogSegment create(uint64_t _seq, std::optional<uint64_t> off = std::nullopt)
  {
    return std::shared_ptr<LogSegment>(new LogSegment(_seq, off));
  }

  void try_to_expire(MDSRankBase *mds, MDSGatherBuilder &gather_bld, int op_prio);
  void purge_inodes_finish(interval_set<inodeno_t>& inos){
    purging_inodes.subtract(inos);
    if (NULL != purged_cb &&
	purging_inodes.empty())
      purged_cb->complete(0);
  }
  void set_purged_cb(MDSContext* c){
    ceph_assert(purged_cb == NULL);
    purged_cb = c;
  }
  void bounds_upkeep(uint64_t start_pos, uint64_t end_pos)
  {
    if (bounds.has_value()) {
      uint64_t offset = get_offset();
      ceph_assert(offset <= start_pos);
      uint64_t end = std::max(get_end(), end_pos);
      bounds = {offset, end};
    } else {
      bounds = {start_pos, end_pos};
    }

  }
  void bounds_upkeep(uint64_t pos)
  {
    bounds_upkeep(pos, pos);
  }
  inline uint64_t get_offset() const { return bounds.value().first; }
  inline uint64_t get_end() const { return bounds.value().second; }
  inline bool has_bounds() const { return bounds.has_value(); }
  inline bool end_is_safe(uint64_t safe_pos) { return has_bounds() && get_end() <= safe_pos; }

  const seq_t seq;
  uint64_t num_events = 0;

  // dirty items
  elist<CDir*>    dirty_dirfrags, new_dirfrags;
  elist<CInode*>  dirty_inodes;
  elist<CDentry*> dirty_dentries;

  elist<CInode*>  open_files;
  elist<CInode*>  dirty_parent_inodes;
  elist<CInode*>  dirty_dirfrag_dir;
  elist<CInode*>  dirty_dirfrag_nest;
  elist<CInode*>  dirty_dirfrag_dirfragtree;

  std::set<CInode*> truncating_inodes;
  interval_set<inodeno_t> purging_inodes;
  MDSContext* purged_cb = nullptr;

  std::map<int, ceph::unordered_set<version_t> > pending_commit_tids;  // mdstable
  std::set<metareqid_t> uncommitted_leaders;
  std::set<metareqid_t> uncommitted_peers;
  std::set<dirfrag_t> uncommitted_fragments;

  // client request ids
  std::map<int, ceph_tid_t> last_client_tids;

  // potentially dirty sessions
  std::set<entity_name_t> touched_sessions;

  // table version
  version_t inotablev = 0;
  version_t sessionmapv = 0;
  std::map<int,version_t> tablev;

 private:
  std::optional<std::pair<uint64_t, uint64_t>> bounds;
  // clients should use the `create` method
  LogSegment(uint64_t _seq, std::optional<uint64_t> off = std::nullopt)
      : seq(_seq)
      , dirty_dirfrags(member_offset(CDir, item_dirty))
      , new_dirfrags(member_offset(CDir, item_new))
      , dirty_inodes(member_offset(CInode, item_dirty))
      , dirty_dentries(member_offset(CDentry, item_dirty))
      , open_files(member_offset(CInode, item_open_file))
      , dirty_parent_inodes(member_offset(CInode, item_dirty_parent))
      , dirty_dirfrag_dir(member_offset(CInode, item_dirty_dirfrag_dir))
      , dirty_dirfrag_nest(member_offset(CInode, item_dirty_dirfrag_nest))
      , dirty_dirfrag_dirfragtree(member_offset(CInode, item_dirty_dirfrag_dirfragtree))
  {
    if (off.has_value()) {
      bounds = {off.value(), off.value()};
    } else {
      bounds = std::nullopt;
    }
  }
};

static inline std::ostream& operator<<(std::ostream& out, const LogSegment& ls) {
  return out << "LogSegment(" << ls.seq << "/0x" << std::hex << ls.get_offset()
             << std::dec << " events=" << ls.num_events << ")";
}

#endif
