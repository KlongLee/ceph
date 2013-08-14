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
 
/*
 * Placement Group Map. Placement Groups are logical sets of objects
 * that are replicated by the same set of devices. pgid=(r,hash(o)&m)
 * where & is a bit-wise AND and m=2^k-1
 */

#ifndef CEPH_PGMAP_H
#define CEPH_PGMAP_H

#include "common/debug.h"
#include "osd/osd_types.h"
#include "common/config.h"
#include <sstream>

#include "MonitorDBStore.h"

namespace ceph { class Formatter; }

class PGMap {
public:
  // the map
  version_t version;
  epoch_t last_osdmap_epoch;   // last osdmap epoch i applied to the pgmap
  epoch_t last_pg_scan;  // osdmap epoch
  hash_map<pg_t,pg_stat_t> pg_stat;
  hash_map<int32_t,osd_stat_t> osd_stat;
  set<int32_t> full_osds;
  set<int32_t> nearfull_osds;
  float full_ratio;
  float nearfull_ratio;

  class Incremental {
  public:
    version_t version;
    map<pg_t,pg_stat_t> pg_stat_updates;
    map<int32_t,osd_stat_t> osd_stat_updates;
    set<int32_t> osd_stat_rm;
    epoch_t osdmap_epoch;
    epoch_t pg_scan;  // osdmap epoch
    set<pg_t> pg_remove;
    float full_ratio;
    float nearfull_ratio;
    utime_t stamp;

    void encode(bufferlist &bl, uint64_t features=-1) const;
    void decode(bufferlist::iterator &bl);
    void dump(Formatter *f) const;
    static void generate_test_instances(list<Incremental*>& o);

    Incremental() : version(0), osdmap_epoch(0), pg_scan(0),
        full_ratio(0), nearfull_ratio(0) {}
  };


  // aggregate stats (soft state), generated by calc_stats()
  hash_map<int,int> num_pg_by_state;
  int64_t num_pg, num_osd;
  hash_map<int,pool_stat_t> pg_pool_sum;
  pool_stat_t pg_sum;
  osd_stat_t osd_sum;

  utime_t stamp;

  // recent deltas, and summation
  list< pair<pool_stat_t, utime_t> > pg_sum_deltas;
  pool_stat_t pg_sum_delta;
  utime_t stamp_delta;

  void update_delta(CephContext *cct, utime_t inc_stamp, pool_stat_t& pg_sum_old);
  void clear_delta();

  set<pg_t> creating_pgs;   // lru: front = new additions, back = recently pinged
  map<int,set<pg_t> > creating_pgs_by_osd;

  enum StuckPG {
    STUCK_INACTIVE,
    STUCK_UNCLEAN,
    STUCK_STALE,
    STUCK_NONE
  };
  
  PGMap()
    : version(0),
      last_osdmap_epoch(0), last_pg_scan(0),
      full_ratio(0), nearfull_ratio(0),
      num_pg(0),
      num_osd(0)
  {}

  void set_full_ratios(float full, float nearfull) {
    if (full_ratio == full && nearfull_ratio == nearfull)
      return;
    full_ratio = full;
    nearfull_ratio = nearfull;
    redo_full_sets();
  }

  version_t get_version() const {
    return version;
  }
  void set_version(version_t v) {
    version = v;
  }
  epoch_t get_last_osdmap_epoch() const {
    return last_osdmap_epoch;
  }
  void set_last_osdmap_epoch(epoch_t e) {
    last_osdmap_epoch = e;
  }
  epoch_t get_last_pg_scan() const {
    return last_pg_scan;
  }
  void set_last_pg_scan(epoch_t e) {
    last_pg_scan = e;
  }
  utime_t get_stamp() const {
    return stamp;
  }
  void set_stamp(utime_t s) {
    stamp = s;
  }

  void update_pg(pg_t pgid, bufferlist& bl);
  void remove_pg(pg_t pgid);
  void update_osd(int osd, bufferlist& bl);
  void remove_osd(int osd);

  void apply_incremental(CephContext *cct, const Incremental& inc);
  void redo_full_sets();
  void register_nearfull_status(int osd, const osd_stat_t& s);
  void calc_stats();
  void stat_pg_add(const pg_t &pgid, const pg_stat_t &s);
  void stat_pg_sub(const pg_t &pgid, const pg_stat_t &s);
  void stat_osd_add(const osd_stat_t &s);
  void stat_osd_sub(const osd_stat_t &s);
  
  void encode(bufferlist &bl, uint64_t features=-1) const;
  void decode(bufferlist::iterator &bl);

  void dirty_all(Incremental& inc);

  void dump(Formatter *f) const; 
  void dump_basic(Formatter *f) const;
  void dump_pg_stats(Formatter *f, bool brief) const;
  void dump_pool_stats(Formatter *f) const;
  void dump_osd_stats(Formatter *f) const;

  void dump_pg_stats_plain(ostream& ss,
			   const hash_map<pg_t, pg_stat_t>& pg_stats) const;
  void get_stuck_stats(StuckPG type, utime_t cutoff,
		       hash_map<pg_t, pg_stat_t>& stuck_pgs) const;
  void dump_stuck(Formatter *f, StuckPG type, utime_t cutoff) const;
  void dump_stuck_plain(ostream& ss, StuckPG type, utime_t cutoff) const;

  void dump(ostream& ss) const;

  void dump_osd_perf_stats(Formatter *f) const;
  void print_osd_perf_stats(std::ostream *ss) const;

  void recovery_summary(Formatter *f, ostream *out) const;
  void print_summary(Formatter *f, ostream *out) const;

  epoch_t calc_min_last_epoch_clean() const;

  static void generate_test_instances(list<PGMap*>& o);
};
WRITE_CLASS_ENCODER_FEATURES(PGMap::Incremental)
WRITE_CLASS_ENCODER_FEATURES(PGMap)

inline ostream& operator<<(ostream& out, const PGMap& m) {
  m.print_summary(NULL, &out);
  return out;
}

#endif
