// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2012 New Dream Network/Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */

#ifndef TRACKEDREQUEST_H_
#define TRACKEDREQUEST_H_
#include <sstream>
#include <stdint.h>
#include <include/utime.h>
#include "common/Mutex.h"
#include "include/histogram.h"
#include "include/xlist.h"
#include "msg/Message.h"
#include <tr1/memory>

class TrackedOp;
typedef std::tr1::shared_ptr<TrackedOp> TrackedOpRef;

class OpTracker;
class OpHistory {
  set<pair<utime_t, TrackedOpRef> > arrived;
  set<pair<double, TrackedOpRef> > duration;
  void cleanup(utime_t now);
  bool shutdown;
  OpTracker *tracker;

public:
  OpHistory(OpTracker *tracker_) : shutdown(false), tracker(tracker_) {}
  ~OpHistory() {
    assert(arrived.empty());
    assert(duration.empty());
  }
  void insert(utime_t now, TrackedOpRef op);
  void dump_ops(utime_t now, Formatter *f);
  void on_shutdown();
};

class OpTracker {
  class RemoveOnDelete {
    OpTracker *tracker;
  public:
    RemoveOnDelete(OpTracker *tracker) : tracker(tracker) {}
    void operator()(TrackedOp *op);
  };
  friend class RemoveOnDelete;
  friend class OpRequest;
  friend class OpHistory;
  uint64_t seq;
  Mutex ops_in_flight_lock;
  xlist<TrackedOp *> ops_in_flight;
  OpHistory history;

protected:
  CephContext *cct;

public:
  OpTracker(CephContext *cct_) : seq(0), ops_in_flight_lock("OpTracker mutex"), history(this), cct(cct_) {}
  void dump_ops_in_flight(Formatter *f);
  void dump_historic_ops(Formatter *f);
  void register_inflight_op(xlist<TrackedOp*>::item *i);
  void unregister_inflight_op(TrackedOp *i);

  void get_age_ms_histogram(pow2_hist_t *h);

  /**
   * Look for Ops which are too old, and insert warning
   * strings for each Op that is too old.
   *
   * @param warning_strings A vector<string> reference which is filled
   * with a warning string for each old Op.
   * @return True if there are any Ops to warn on, false otherwise.
   */
  bool check_ops_in_flight(std::vector<string> &warning_strings);
  void mark_event(TrackedOp *op, const string &evt);
  void _mark_event(TrackedOp *op, const string &evt, utime_t now);

  void on_shutdown() {
    Mutex::Locker l(ops_in_flight_lock);
    history.on_shutdown();
  }
  ~OpTracker() {
    assert(ops_in_flight.empty());
  }

  template <typename T, typename TRef>
  TRef create_request(Message *ref)
  {
    TRef retval(new T(ref, this),
                RemoveOnDelete(this));

    _mark_event(retval.get(), "header_read", ref->get_recv_stamp());
    _mark_event(retval.get(), "throttled", ref->get_throttle_stamp());
    _mark_event(retval.get(), "all_read", ref->get_recv_complete_stamp());
    _mark_event(retval.get(), "dispatched", ref->get_dispatch_stamp());

    retval->init_from_message();

    return retval;
  }
};

class TrackedOp {
protected:
  list<pair<utime_t, string> > events; /// list of events and their times
  Mutex lock; /// to protect the events list
public:
  // move these to private once friended OpTracker
  Message *request;
  xlist<TrackedOp*>::item xitem;
  utime_t received_time;
  // figure out how to get rid of this one?
  uint8_t warn_interval_multiplier;
  string current;
  uint64_t seq;

  TrackedOp(Message *req) :
    lock("TrackedOp::lock"),
    request(req),
    xitem(this),
    warn_interval_multiplier(1),
    seq(0) {}

  virtual void init_from_message() {};

  virtual ~TrackedOp() {}

  utime_t get_arrived() const {
    return received_time;
  }
  // This function maybe needs some work; assumes last event is completion time
  double get_duration() const {
    return events.size() ?
      (events.rbegin()->first - received_time) :
      0.0;
  }

  virtual void mark_event(const string &event);
  virtual const char *state_string() const = 0;
  virtual void dump(utime_t now, Formatter *f) const = 0;
};

#endif
