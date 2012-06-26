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

namespace ceph { class Formatter; }

class PGMap {
public:
  // the map
  version_t version;
  epoch_t last_osdmap_epoch;   // last osdmap epoch i applied to the pgmap
  epoch_t last_pg_scan;  // osdmap epoch
  hash_map<pg_t,pg_stat_t> pg_stat;
  hash_map<int,osd_stat_t> osd_stat;
  set<int> full_osds;
  set<int> nearfull_osds;
  float full_ratio;
  float nearfull_ratio;

  class Incremental {
  public:
    version_t version;
    map<pg_t,pg_stat_t> pg_stat_updates;
    map<int,osd_stat_t> osd_stat_updates;
    set<int> osd_stat_rm;
    epoch_t osdmap_epoch;
    epoch_t pg_scan;  // osdmap epoch
    set<pg_t> pg_remove;
    float full_ratio;
    float nearfull_ratio;

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

  set<pg_t> creating_pgs;   // lru: front = new additions, back = recently pinged

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

  void apply_incremental(const Incremental& inc);
  void redo_full_sets();
  void calc_stats();
  void stat_pg_add(const pg_t &pgid, const pg_stat_t &s);
  void stat_pg_sub(const pg_t &pgid, const pg_stat_t &s);
  void stat_osd_add(const osd_stat_t &s);
  void stat_osd_sub(const osd_stat_t &s);
  
  void encode(bufferlist &bl, uint64_t features=-1) const;
  void decode(bufferlist::iterator &bl);

  void dump(Formatter *f) const; 
  void dump_basic(Formatter *f) const;
  void dump_pg_stats(Formatter *f) const;
  void dump_pool_stats(Formatter *f) const;
  void dump_osd_stats(Formatter *f) const;

  void dump_pg_stats_plain(ostream& ss,
			   const hash_map<pg_t, pg_stat_t>& pg_stats) const;
  void get_stuck_stats(StuckPG type, utime_t cutoff,
		       hash_map<pg_t, pg_stat_t>& stuck_pgs) const;
  void dump_stuck(Formatter *f, StuckPG type, utime_t cutoff) const;
  void dump_stuck_plain(ostream& ss, StuckPG type, utime_t cutoff) const;

  void dump(ostream& ss) const;

  void state_summary(ostream& ss) const;
  void recovery_summary(ostream& out) const;
  void print_summary(ostream& out) const;

  epoch_t calc_min_last_epoch_clean() const;

  static void generate_test_instances(list<PGMap*>& o);
};
WRITE_CLASS_ENCODER_FEATURES(PGMap::Incremental)
WRITE_CLASS_ENCODER_FEATURES(PGMap)

inline ostream& operator<<(ostream& out, const PGMap& m) {
  m.print_summary(out);
  return out;
}

#endif
