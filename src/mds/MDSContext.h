// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2012 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */


#ifndef MDS_CONTEXT_H
#define MDS_CONTEXT_H

#include <vector>
#include <deque>

#include "include/Context.h"
#include "include/elist.h"
#include "include/spinlock.h"
#include "common/ceph_time.h"
#include "include/auto_shared_ptr.h"

class MDSRankBase;
class MDSRank;
class LogSegment;
using AutoSharedLogSegment = auto_shared_ptr<LogSegment>;

/**
 * Completion which has access to a reference to the global MDS instance.
 *
 * This class exists so that Context subclasses can provide the MDS pointer
 * from a pointer they already had, e.g. MDCache or Locker, rather than
 * necessarily having to carry around an extra MDS* pointer. 
 */
class MDSContext : public Context
{
public:
template<template<typename> class A>
  using vec_alloc = std::vector<MDSContext*, A<MDSContext*>>;
  using vec = vec_alloc<std::allocator>;

template<template<typename> class A>
  using que_alloc = std::deque<MDSContext*, A<MDSContext*>>;
  using que = que_alloc<std::allocator>;

  void complete(int r) override;
  virtual MDSRankBase *get_mds() = 0;
  virtual bool takes_lock() const { return false; }
};

/* Children of this could have used multiple inheritance with MDSHolder and
 * MDSContext but then get_mds() would be ambiguous.
 */
template<class T>
class MDSHolder : public T
{
public:
  MDSRankBase* get_mds() override {
    return mds;
  }

protected:
  MDSHolder() = delete;
  MDSHolder(MDSRankBase* mds) : mds(mds) {
    ceph_assert(mds != nullptr);
  }
  MDSHolder(MDSRank* mds);

  MDSRankBase* mds;
};

/**
 * General purpose, lets you pass in an MDS pointer.
 */
class MDSInternalContext : public MDSHolder<MDSContext>
{
public:
  MDSInternalContext() = delete;

protected:
  explicit MDSInternalContext(MDSRankBase *mds_) : MDSHolder(mds_) {}
  explicit MDSInternalContext(MDSRank *mds_) : MDSHolder(mds_) {}
};

/**
 * Wrap a regular Context up as an Internal context. Useful
 * if you're trying to work with one of our more generic frameworks.
 */
class MDSInternalContextWrapper : public MDSInternalContext
{
protected:
  Context *fin = nullptr;
  void finish(int r) override;
public:
  MDSInternalContextWrapper(MDSRankBase *m, Context *c) : MDSInternalContext(m), fin(c) {}
  MDSInternalContextWrapper(MDSRank *m, Context *c) : MDSInternalContext(m), fin(c) {}
};

class MDSLockingWrapper : public MDSContext 
{
  protected:
  Context *wrapped = nullptr;
  MDSRankBase* mds = nullptr;
  void complete(int r) override;
  void finish(int r) override
  {
    ceph_abort("this shouldn't be called");
  }
 public:
  MDSRankBase* get_mds() override { return mds; }
  bool takes_lock() const override { return true; }
  MDSLockingWrapper(Context* wrapped, MDSRankBase* mds) : wrapped(wrapped), mds(mds) { }
  MDSLockingWrapper(MDSContext *mds_wrapped) : wrapped(mds_wrapped), mds(mds_wrapped->get_mds()) { }
  ~MDSLockingWrapper()
  {
    if (wrapped) {
      delete wrapped;
    }
  }
};

class MDSIOContextBase : public MDSContext
{
public:
  MDSIOContextBase(bool track=true);
  virtual ~MDSIOContextBase();
  MDSIOContextBase(const MDSIOContextBase&) = delete;
  MDSIOContextBase& operator=(const MDSIOContextBase&) = delete;
  bool takes_lock() const override { return true; }

  void complete(int r) override;
  void complete_no_lock(int r);

  virtual void print(std::ostream& out) const = 0;

  static bool check_ios_in_flight(ceph::coarse_mono_time cutoff,
				  std::string& slow_count,
				  ceph::coarse_mono_time& oldest);
private:
  ceph::coarse_mono_time created_at;
  elist<MDSIOContextBase*>::item list_item;
  
  friend struct MDSIOContextList;
};

/**
 * Completion for an log operation, takes big MDSRank lock
 * before executing finish function. Update log's safe pos
 * after finish function return.
 */
class MDSLogContextBase : public MDSIOContextBase
{
protected:
  AutoSharedLogSegment log_segment;
  uint64_t event_start_pos = 0;
  uint64_t event_end_pos = 0;
public:
  MDSLogContextBase() = default;
  void complete(int r) final;
  bool takes_lock() const override { return true; }
  void set_event_bounds(const AutoSharedLogSegment& ls, uint64_t event_start, uint64_t event_end)
  {  
    log_segment = ls;
    event_start_pos = event_start;
    event_end_pos = event_end;
  }
  virtual void pre_finish(int r) {}
  void print(std::ostream& out) const override;
};

/**
 * Completion for an I/O operation, takes big MDSRank lock
 * before executing finish function.
 */
class MDSIOContext : public MDSHolder<MDSIOContextBase>
{
public:
  explicit MDSIOContext(MDSRankBase *mds_) : MDSHolder(mds_) {}
  explicit MDSIOContext(MDSRank *mds_) : MDSHolder(mds_) {}
};

/**
 * Wrap a regular Context up as an IO Context. Useful
 * if you're trying to work with one of our more generic frameworks.
 */
class MDSIOContextWrapper : public MDSHolder<MDSIOContextBase>
{
protected:
  Context *fin;
public:
  MDSIOContextWrapper(MDSRankBase *m, Context *c) : MDSHolder(m), fin(c) {}
  MDSIOContextWrapper(MDSRank *m, Context *c) : MDSHolder(m), fin(c) {}
  void finish(int r) override;
  void print(std::ostream& out) const override {
    out << "io_context_wrapper(" << fin << ")";
  }
};

/**
 * No-op for callers expecting MDSInternalContext
 */
class C_MDSInternalNoop : public MDSContext
{
public:
  void finish(int r) override {}
  void complete(int r) override { delete this; }
protected:
  MDSRankBase* get_mds() override final { return nullptr; }
};


/**
 * This class is used where you have an MDSInternalContext but
 * you sometimes want to call it back from an I/O completion.
 */
class C_IO_Wrapper : public MDSIOContext
{
protected:
  bool async;
  Context *wrapped;
  void finish(int r) override {
    wrapped->complete(r);
    wrapped = nullptr;
  }
public:
  C_IO_Wrapper(MDSRankBase *mds_, Context *wrapped_) :
    MDSIOContext(mds_), async(true), wrapped(wrapped_) {
    ceph_assert(wrapped != NULL);
  }
  C_IO_Wrapper(MDSRank *mds_, Context *wrapped_) :
    MDSIOContext(mds_), async(true), wrapped(wrapped_) {
    ceph_assert(wrapped != NULL);
  }

  ~C_IO_Wrapper() override {
    if (wrapped != nullptr) {
      delete wrapped;
      wrapped = nullptr;
    }
  }
  void complete(int r) final;
  void print(std::ostream& out) const override {
    out << "io_wrapper(" << wrapped << ")";
  }
};

using MDSGather = C_GatherBase<MDSContext, C_MDSInternalNoop>;
using MDSGatherBuilder = C_GatherBuilderBase<MDSContext, MDSGather>;

using MDSContextFactory = ContextFactory<MDSContext>;

#endif  // MDS_CONTEXT_H
