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


#ifndef CEPH_CONTEXT_H
#define CEPH_CONTEXT_H

#include "common/dout.h"

#include <boost/function.hpp>
#include <list>
#include <set>
#include <memory>

#include "include/assert.h"
#include "include/memory.h"

#define mydout(cct, v) lgeneric_subdout(cct, context, v)

/*
 * GenContext - abstract callback class
 */
template <typename T>
class GenContext {
  GenContext(const GenContext& other);
  const GenContext& operator=(const GenContext& other);

 protected:
  virtual void finish(T t) = 0;

 public:
  GenContext() {}
  virtual ~GenContext() {}       // we want a virtual destructor!!!

  template <typename C>
  void complete(C &&t) {
    finish(std::forward<C>(t));
    delete this;
  }
};

template <typename T>
using GenContextURef = std::unique_ptr<GenContext<T> >;

/*
 * Context - abstract callback class
 */
class Context {
  Context(const Context& other);
  const Context& operator=(const Context& other);

 protected:
  virtual void finish(int r) = 0;

 public:
  Context() {}
  virtual ~Context() {}       // we want a virtual destructor!!!
  virtual void complete(int r) {
    finish(r);
    delete this;
  }
};

/**
 * Simple context holding a single object
 */
template<class T>
class ContainerContext : public Context {
  T obj;
public:
  ContainerContext(T &obj) : obj(obj) {}
  void finish(int r) {}
};
template <typename T>
ContainerContext<T> *make_container_context(T &&t) {
  return new ContainerContext<T>(std::forward<T>(t));
}

template <class T>
struct Wrapper : public Context {
  Context *to_run;
  T val;
  Wrapper(Context *to_run, T val) : to_run(to_run), val(val) {}
  void finish(int r) {
    if (to_run)
      to_run->complete(r);
  }
};
struct RunOnDelete {
  Context *to_run;
  RunOnDelete(Context *to_run) : to_run(to_run) {}
  ~RunOnDelete() {
    if (to_run)
      to_run->complete(0);
  }
};
typedef ceph::shared_ptr<RunOnDelete> RunOnDeleteRef;

template <typename T>
struct LambdaContext : public Context {
  T t;
  LambdaContext(T &&t) : t(std::forward<T>(t)) {}
  void finish(int) {
    t();
  }
};
template <typename T>
LambdaContext<T> *make_lambda_context(T &&t) {
  return new LambdaContext<T>(std::move(t));
}

template <typename F, typename T>
struct LambdaGenContext : GenContext<T> {
  F f;
  LambdaGenContext(F &&f) : f(std::forward<F>(f)) {}
  void finish(T t) {
    f(std::forward<T>(t));
  }
};
template <typename T, typename F>
GenContextURef<T> make_gen_lambda_context(F &&f) {
  return GenContextURef<T>(new LambdaGenContext<F, T>(std::move(f)));
}

/*
 * finish and destroy a list of Contexts
 */
template<class A>
inline void finish_contexts(CephContext *cct, std::list<A*>& finished, 
                            int result = 0)
{
  if (finished.empty())
    return;

  list<A*> ls;
  ls.swap(finished); // swap out of place to avoid weird loops

  if (cct)
    mydout(cct, 10) << ls.size() << " contexts to finish with " << result << dendl;
  typename std::list<A*>::iterator it;
  for (it = ls.begin(); it != ls.end(); it++) {
    A *c = *it;
    if (cct)
      mydout(cct,10) << "---- " << c << dendl;
    c->complete(result);
  }
}

inline void finish_contexts(CephContext *cct, std::vector<Context*>& finished, 
                            int result = 0)
{
  if (finished.empty())
    return;

  vector<Context*> ls;
  ls.swap(finished); // swap out of place to avoid weird loops

  if (cct)
    mydout(cct,10) << ls.size() << " contexts to finish with " << result << dendl;
  for (std::vector<Context*>::iterator it = ls.begin(); 
       it != ls.end(); 
       it++) {
    Context *c = *it;
    if (cct)
      mydout(cct,10) << "---- " << c << dendl;
    c->complete(result);
  }
}

class C_NoopContext : public Context {
public:
  void finish(int r) { }
};


struct C_Lock : public Context {
  Mutex *lock;
  Context *fin;
  C_Lock(Mutex *l, Context *c) : lock(l), fin(c) {}
  ~C_Lock() {
    delete fin;
  }
  void finish(int r) {
    if (fin) {
      lock->Lock();
      fin->complete(r);
      fin = NULL;
      lock->Unlock();
    }
  }
};

/*
 * C_Contexts - set of Contexts
 *
 * ContextType must be an ancestor class of ContextInstanceType, or the same class.
 * ContextInstanceType must be default-constructable.
 */
template <class ContextType, class ContextInstanceType>
class C_ContextsBase : public ContextInstanceType {
public:
  CephContext *cct;
  std::list<ContextType*> contexts;

  C_ContextsBase(CephContext *cct_)
    : cct(cct_)
  {
  }

  void add(ContextType* c) {
    contexts.push_back(c);
  }
  void take(std::list<ContextType*>& ls) {
    contexts.splice(contexts.end(), ls);
  }
  void complete(int r) {
    // Neuter any ContextInstanceType custom complete(), because although
    // I want to look like it, I don't actually want to run its code.
    Context::complete(r);
  }
  void finish(int r) {
    finish_contexts(cct, contexts, r);
  }
  bool empty() { return contexts.empty(); }

  static ContextType *list_to_context(list<ContextType *> &cs) {
    if (cs.size() == 0) {
      return 0;
    } else if (cs.size() == 1) {
      ContextType *c = cs.front();
      cs.clear();
      return c;
    } else {
      C_ContextsBase<ContextType, ContextInstanceType> *c(new C_ContextsBase<ContextType, ContextInstanceType>(0));
      c->take(cs);
      return c;
    }
  }
};

typedef C_ContextsBase<Context, Context> C_Contexts;

/*
 * C_Gather
 *
 * ContextType must be an ancestor class of ContextInstanceType, or the same class.
 * ContextInstanceType must be default-constructable.
 *
 * BUG:? only reports error from last sub to have an error return
 */
template <class ContextType, class ContextInstanceType>
class C_GatherBase : public ContextType {
private:
  CephContext *cct;
  int result;
  ContextType *onfinish;
#ifdef DEBUG_GATHER
  std::set<ContextType*> waitfor;
#endif
  int sub_created_count;
  int sub_existing_count;
  mutable Mutex lock;
  bool activated;

  void sub_finish(ContextType* sub, int r) {
    lock.Lock();
#ifdef DEBUG_GATHER
    assert(waitfor.count(sub));
    waitfor.erase(sub);
#endif
    --sub_existing_count;
    mydout(cct,10) << "C_GatherBase " << this << ".sub_finish(r=" << r << ") " << sub
#ifdef DEBUG_GATHER
		    << " (remaining " << waitfor << ")"
#endif
		    << dendl;
    if (r < 0 && result == 0)
      result = r;
    if ((activated == false) || (sub_existing_count != 0)) {
      lock.Unlock();
      return;
    }
    lock.Unlock();
    delete_me();
  }

  void delete_me() {
    if (onfinish) {
      onfinish->complete(result);
      onfinish = 0;
    }
    delete this;
  }

  class C_GatherSub : public ContextInstanceType {
    C_GatherBase *gather;
  public:
    C_GatherSub(C_GatherBase *g) : gather(g) {}
    void complete(int r) {
      // Cancel any customized complete() functionality
      // from the Context subclass we're templated for,
      // we only want to hit that in onfinish, not at each
      // sub finish.  e.g. MDSInternalContext.
      Context::complete(r);
    }
    void finish(int r) {
      gather->sub_finish(this, r);
      gather = 0;
    }
    ~C_GatherSub() {
      if (gather)
	gather->sub_finish(this, 0);
    }
  };

public:
  C_GatherBase(CephContext *cct_, ContextType *onfinish_)
    : cct(cct_), result(0), onfinish(onfinish_),
      sub_created_count(0), sub_existing_count(0),
      lock("C_GatherBase::lock", true, false), //disable lockdep
      activated(false)
  {
    mydout(cct,10) << "C_GatherBase " << this << ".new" << dendl;
  }
  ~C_GatherBase() {
    mydout(cct,10) << "C_GatherBase " << this << ".delete" << dendl;
  }
  void set_finisher(ContextType *onfinish_) {
    Mutex::Locker l(lock);
    assert(!onfinish);
    onfinish = onfinish_;
  }
  void activate() {
    lock.Lock();
    assert(activated == false);
    activated = true;
    if (sub_existing_count != 0) {
      lock.Unlock();
      return;
    }
    lock.Unlock();
    delete_me();
  }
  ContextType *new_sub() {
    Mutex::Locker l(lock);
    assert(activated == false);
    sub_created_count++;
    sub_existing_count++;
    ContextType *s = new C_GatherSub(this);
#ifdef DEBUG_GATHER
    waitfor.insert(s);
#endif
    mydout(cct,10) << "C_GatherBase " << this << ".new_sub is " << sub_created_count << " " << s << dendl;
    return s;
  }
  void finish(int r) {
    ceph_abort();    // nobody should ever call me.
  }

  inline int get_sub_existing_count() const {
    Mutex::Locker l(lock);
    return sub_existing_count;
  }

  inline int get_sub_created_count() const {
    Mutex::Locker l(lock);
    return sub_created_count;
  }
};

/*
 * The C_GatherBuilder remembers each C_Context created by
 * C_GatherBuilder.new_sub() in a C_Gather.  When a C_Context created
 * by new_sub() is complete(), C_Gather forgets about it.  When
 * C_GatherBuilder notices that there are no C_Context left in
 * C_Gather, it calls complete() on the C_Context provided as the
 * second argument of the constructor (finisher).
 *
 * How to use C_GatherBuilder:
 *
 * 1. Create a C_GatherBuilder on the stack
 * 2. Call gather_bld.new_sub() as many times as you want to create new subs
 *    It is safe to call this 0 times, or 100, or anything in between.
 * 3. If you didn't supply a finisher in the C_GatherBuilder constructor,
 *    set one with gather_bld.set_finisher(my_finisher)
 * 4. Call gather_bld.activate()
 *
 * Example:
 *
 * C_SaferCond all_done;
 * C_GatherBuilder gb(g_ceph_context, all_done);
 * j.submit_entry(1, first, 0, gb.new_sub()); // add a C_Context to C_Gather
 * j.submit_entry(2, first, 0, gb.new_sub()); // add a C_Context to C_Gather
 * gb.activate(); // consume C_Context as soon as they complete()
 * all_done.wait(); // all_done is complete() after all new_sub() are complete()
 *
 * The finisher may be called at any point after step 4, including immediately
 * from the activate() function.
 * The finisher will never be called before activate().
 *
 * Note: Currently, subs must be manually freed by the caller (for some reason.)
 */
template <class ContextType, class GatherType>
class C_GatherBuilderBase
{
public:
  C_GatherBuilderBase(CephContext *cct_)
    : cct(cct_), c_gather(NULL), finisher(NULL), activated(false)
  {
  }
  C_GatherBuilderBase(CephContext *cct_, ContextType *finisher_)
    : cct(cct_), c_gather(NULL), finisher(finisher_), activated(false)
  {
  }
  ~C_GatherBuilderBase() {
    if (c_gather) {
      assert(activated); // Don't forget to activate your C_Gather!
    }
    else {
      delete finisher;
    }
  }
  ContextType *new_sub() {
    if (!c_gather) {
      c_gather = new GatherType(cct, finisher);
    }
    return c_gather->new_sub();
  }
  void activate() {
    if (!c_gather)
      return;
    assert(finisher != NULL);
    activated = true;
    c_gather->activate();
  }
  void set_finisher(ContextType *finisher_) {
    finisher = finisher_;
    if (c_gather)
      c_gather->set_finisher(finisher);
  }
  GatherType *get() const {
    return c_gather;
  }
  bool has_subs() const {
    return (c_gather != NULL);
  }
  int num_subs_created() {
    assert(!activated);
    if (c_gather == NULL)
      return 0;
    return c_gather->get_sub_created_count();
  }
  int num_subs_remaining() {
    assert(!activated);
    if (c_gather == NULL)
      return 0;
    return c_gather->get_sub_existing_count();
  }

private:
  CephContext *cct;
  GatherType *c_gather;
  ContextType *finisher;
  bool activated;
};

typedef C_GatherBase<Context, Context> C_Gather;
typedef C_GatherBuilderBase<Context, C_Gather > C_GatherBuilder;

class FunctionContext : public Context {
public:
  FunctionContext(boost::function<void(int)> &&callback)
    : m_callback(std::move(callback))
  {
  }

  virtual void finish(int r) {
    m_callback(r);
  }
private:
  boost::function<void(int)> m_callback;
};

#undef mydout

#endif
