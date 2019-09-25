// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_ASYNC_OP_TRACKER_H
#define CEPH_ASYNC_OP_TRACKER_H

#include <iostream>
#include "common/ceph_mutex.h"

struct Context;

class AsyncOpTracker {
public:
  AsyncOpTracker();
  ~AsyncOpTracker();

  void start_op();
  void finish_op();

  void wait_for_ops(Context *on_finish);

  bool empty();

  friend std::ostream &operator<<(std::ostream &os,
                                 const AsyncOpTracker &t) {
    os << "pending_ops=" << t.m_pending_ops << ", "
       << "on_finish=" << t.m_on_finish;
    return os;
  };

private:
  ceph::mutex m_lock = ceph::make_mutex("AsyncOpTracker::m_lock");
  uint32_t m_pending_ops = 0;
  Context *m_on_finish = nullptr;

};

#endif // CEPH_ASYNC_OP_TRACKER_H
