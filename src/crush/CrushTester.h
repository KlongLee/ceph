// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_CRUSH_TESTER_H
#define CEPH_CRUSH_TESTER_H

#include "crush/CrushWrapper.h"

class CrushTester {
  CrushWrapper& crush;
  ostream& err;
  int verbose;

  map<int, int> device_weight;
  int min_rule, max_rule;
  int min_x, max_x;
  int min_rep, max_rep;

  int num_batches;
  bool use_crush;

  bool batch_mark_down;
  bool down_percentage_marked;
  bool down_range_marked;
  float mark_down_percentage;
  int mark_down_start;
  int down_range;
  bool output_utilization;
  bool output_utilization_all;
  bool output_statistics;
  bool output_bad_mappings;
  bool output_choose_tries;

public:
  CrushTester(CrushWrapper& c, ostream& eo, int verbosity=0)
    : crush(c), err(eo), verbose(verbosity),
      min_rule(-1), max_rule(-1),
      min_x(-1), max_x(-1),
      min_rep(-1), max_rep(-1),
      num_batches(1),
      use_crush(true),
      batch_mark_down(false),
      down_percentage_marked(false),
      down_range_marked(false),
      mark_down_percentage(0.0),
      mark_down_start(0),
      down_range(1)
  { }

  void set_output(bool set_output_utilization,
		  bool set_output_utilization_all,
		  bool set_output_statistics,
		  bool set_output_bad_mappings,
		  bool set_output_choose_tries) {
    output_utilization = set_output_utilization;
    output_utilization_all = set_output_utilization_all;
    output_statistics = set_output_statistics;
    output_bad_mappings = set_output_bad_mappings;
    output_choose_tries = set_output_choose_tries;
  }
  void set_batches(int b) {
    num_batches = b;
  }
  void set_random_placement() {
    use_crush = false;
  }
  void set_range_down(int start, int range){
    batch_mark_down = true;
    down_range_marked = true;
    mark_down_start = start;
    down_range = range;
  }
  void set_percentage_down(float percent) {
    batch_mark_down = true;
    down_percentage_marked = true;
    mark_down_percentage = percent;
  }
  void set_device_weight(int dev, float f);

  void set_min_rep(int r) {
    min_rep = r;
  }
  void set_max_rep(int r) {
    max_rep = r;
  }
  void set_num_rep(int r) {
    min_rep = max_rep = r;
  }
  
  void set_min_x(int x) {
    min_x = x;
  }
  void set_max_x(int x) {
    max_x = x;
  }
  void set_x(int x) {
    min_x = max_x = x;
  }

  void set_min_rule(int rule) {
    min_rule = rule;
  }
  void set_max_rule(int rule) {
    max_rule = rule;
  }
  void set_rule(int rule) {
    min_rule = max_rule = rule;
  }

  int test();
};

#endif
