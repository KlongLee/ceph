// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_JOURNAL_FUTURE_IMPL_H
#define CEPH_JOURNAL_FUTURE_IMPL_H

#include "include/int_types.h"
#include "common/Mutex.h"
#include "common/RefCountedObj.h"
#include "journal/Future.h"
#include <list>
#include <boost/noncopyable.hpp>
#include <boost/intrusive_ptr.hpp>
#include "include/assert.h"

class Context;

namespace journal {

class FutureImpl;
typedef boost::intrusive_ptr<FutureImpl> FutureImplPtr;

class FutureImpl : public RefCountedObject, boost::noncopyable {
public:
  struct FlushHandler {
    virtual ~FlushHandler() {}
    virtual void flush(const FutureImplPtr &future) = 0;
    virtual void get() = 0;
    virtual void put() = 0;
  };
  typedef boost::intrusive_ptr<FlushHandler> FlushHandlerPtr;

  FutureImpl(const std::string &tag, uint64_t tid);

  void init(const FutureImplPtr &prev_future);

  inline const std::string &get_tag() const {
    return m_tag;
  }
  inline uint64_t get_tid() const {
    return m_tid;
  }

  void flush(Context *on_safe = NULL);
  void wait(Context *on_safe);

  bool is_complete() const;
  int get_return_value() const;

  inline bool is_flush_in_progress() const {
    Mutex::Locker locker(m_lock);
    return (m_flush_state == FLUSH_STATE_IN_PROGRESS);
  }
  inline void set_flush_in_progress() {
    Mutex::Locker locker(m_lock);
    m_flush_state = FLUSH_STATE_IN_PROGRESS;
  }

  bool attach(const FlushHandlerPtr &flush_handler);
  inline void detach() {
    Mutex::Locker locker(m_lock);
    assert(m_flush_handler);
    m_flush_handler.reset();
  }
  inline FlushHandlerPtr get_flush_handler() const {
    Mutex::Locker locker(m_lock);
    return m_flush_handler;
  }

  void safe(int r);

private:
  friend std::ostream &operator<<(std::ostream &, const FutureImpl &);

  typedef std::list<Context *> Contexts;

  enum FlushState {
    FLUSH_STATE_NONE,
    FLUSH_STATE_REQUESTED,
    FLUSH_STATE_IN_PROGRESS
  };

  struct C_ConsistentAck : public Context {
    FutureImplPtr future;
    C_ConsistentAck(FutureImpl *_future) : future(_future) {}
    virtual void complete(int r) {
      future->consistent(r);
      future.reset();
    }
    virtual void finish(int r) {}
  };

  std::string m_tag;
  uint64_t m_tid;

  mutable Mutex m_lock;
  FutureImplPtr m_prev_future;
  bool m_safe;
  bool m_consistent;
  int m_return_value;

  FlushHandlerPtr m_flush_handler;
  FlushState m_flush_state;

  C_ConsistentAck m_consistent_ack;
  Contexts m_contexts;

  void consistent(int r);
  void finish();
};

void intrusive_ptr_add_ref(FutureImpl::FlushHandler *p);
void intrusive_ptr_release(FutureImpl::FlushHandler *p);

std::ostream &operator<<(std::ostream &os, const FutureImpl &future);

} // namespace journal

using journal::operator<<;

#endif // CEPH_JOURNAL_FUTURE_IMPL_H
