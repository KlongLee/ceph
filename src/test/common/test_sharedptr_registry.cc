// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 Cloudwatt <libre.licensing@cloudwatt.com>
 *
 * Author: Loic Dachary <loic@dachary.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Library Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library Public License for more details.
 *
 */

#include <stdio.h>
#include <signal.h>
#include "common/Thread.h"
#include "common/sharedptr_registry.hpp"
#include "common/ceph_argparse.h"
#include "global/global_init.h"
#include <gtest/gtest.h>

using namespace std::tr1;

class SharedPtrRegistryTest : public SharedPtrRegistry<unsigned int, int> {
public:
  Mutex &get_lock() { return lock; }
  map<unsigned int, weak_ptr<int> > &get_contents() { return contents; }
};

class SharedPtrRegistry_all : public ::testing::Test {
public:

  class Thread_wait : public Thread {
  public:
    SharedPtrRegistryTest &registry;
    unsigned int key;
    int value;
    shared_ptr<int> ptr;
    SharedPtrRegistryTest::in_method_t in_method;

    Thread_wait(SharedPtrRegistryTest& _registry, unsigned int _key, int _value, SharedPtrRegistryTest::in_method_t _in_method) : 
      registry(_registry),
      key(_key),
      value(_value),
      in_method(_in_method)
    {
    }
    
    virtual void *entry() {
      switch(in_method) {
      case SharedPtrRegistryTest::LOOKUP_OR_CREATE:
	if (value) 
	  ptr = registry.lookup_or_create<int>(key, value);
	else
	  ptr = registry.lookup_or_create(key);
	break;
      case SharedPtrRegistryTest::LOOKUP:
	ptr = shared_ptr<int>(new int);
	*ptr = value;
	ptr = registry.lookup(key);
	break;
      case SharedPtrRegistryTest::UNDEFINED:
	break;
      }
      return NULL;
    }
  };

  static const useconds_t DELAY_MAX = 20 * 1000 * 1000;
  static useconds_t delay;

  bool wait_for(SharedPtrRegistryTest &registry, SharedPtrRegistryTest::in_method_t method) {
    do {
      //
      // the delay variable is supposed to be initialized to zero. It would be fine
      // to usleep(0) but we take this opportunity to test the loop. It will try 
      // again and therefore show that the logic ( increasing the delay ) actually
      // works. 
      //
      if (delay > 0)
	usleep(delay);
      {
	Mutex::Locker l(registry.get_lock());
	if (registry.in_method == method) 
	  break;
      }
      if (delay > 0)
	cout << "delay " << delay << "us, is not long enough, try again\n";
    } while (( delay = delay * 2 + 1) < DELAY_MAX);
    return delay < DELAY_MAX;
  }
};

useconds_t SharedPtrRegistry_all::delay = 0;

TEST_F(SharedPtrRegistry_all, lookup_or_create) {
  SharedPtrRegistryTest registry;
  unsigned int key = 1;
  int value = 2;
  shared_ptr<int> ptr = registry.lookup_or_create(key);
  *ptr = value;
  ASSERT_EQ(value, *registry.lookup_or_create(key));
}

TEST_F(SharedPtrRegistry_all, wait_lookup_or_create) {
  SharedPtrRegistryTest registry;

  //
  // simulate the following: The last reference to a shared_ptr goes
  // out of scope and the shared_ptr object is about to be removed and
  // marked as such. The weak_ptr stored in the registry will show
  // that it has expired(). However, the SharedPtrRegistry::OnRemoval
  // object not yet been called and did not get a chance to acquire
  // the lock. The lookup_or_create and lookup methods must detect
  // that situation and wait until the weak_ptr is removed from the
  // registry.
  //
  {
    unsigned int key = 1;
    {
      shared_ptr<int> ptr(new int);
      registry.get_contents()[key] = ptr;
    }
    EXPECT_FALSE(registry.get_contents()[key].lock());

    Thread_wait t(registry, key, 0, SharedPtrRegistryTest::LOOKUP_OR_CREATE);
    t.create();
    ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::LOOKUP_OR_CREATE));
    EXPECT_FALSE(t.ptr);
    registry.remove(key);
    ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::UNDEFINED));
    EXPECT_TRUE(t.ptr);
    t.join();
  }
  {
    unsigned int key = 2;
    int value = 3;
    {
      shared_ptr<int> ptr(new int);
      registry.get_contents()[key] = ptr;
    }
    EXPECT_FALSE(registry.get_contents()[key].lock());

    Thread_wait t(registry, key, value, SharedPtrRegistryTest::LOOKUP_OR_CREATE);
    t.create();
    ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::LOOKUP_OR_CREATE));
    EXPECT_FALSE(t.ptr);
    registry.remove(key);
    ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::UNDEFINED));
    EXPECT_TRUE(t.ptr);
    EXPECT_EQ(value, *t.ptr);
    t.join();
  }
}

TEST_F(SharedPtrRegistry_all, lookup) {
  SharedPtrRegistryTest registry;
  unsigned int key = 1;
  int value = 2;
  {
    shared_ptr<int> ptr = registry.lookup_or_create(key);
    *ptr = value;
    ASSERT_EQ(value, *registry.lookup(key));
  }
  ASSERT_FALSE(registry.lookup(key));
}

TEST_F(SharedPtrRegistry_all, wait_lookup) {
  SharedPtrRegistryTest registry;

  unsigned int key = 1;
  int value = 2;
  {
    shared_ptr<int> ptr(new int);
    registry.get_contents()[key] = ptr;
  }
  EXPECT_FALSE(registry.get_contents()[key].lock());

  Thread_wait t(registry, key, value, SharedPtrRegistryTest::LOOKUP);
  t.create();
  ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::LOOKUP));
  EXPECT_EQ(value, *t.ptr);
  registry.remove(key);
  ASSERT_TRUE(wait_for(registry, SharedPtrRegistryTest::UNDEFINED));
  EXPECT_FALSE(t.ptr);
  t.join();
}

TEST_F(SharedPtrRegistry_all, get_next) {

  {
    SharedPtrRegistry<unsigned int,int> registry;
    const unsigned int key = 0;
    pair<unsigned int, int> i;
    EXPECT_FALSE(registry.get_next(key, &i));
  }
  {
    SharedPtrRegistryTest registry;

    const unsigned int key2 = 333;
    shared_ptr<int> ptr2 = registry.lookup_or_create(key2);
    const int value2 = *ptr2 = 400;

    // entries with expired pointers are silentely ignored
    const unsigned int key_gone = 222;
    registry.get_contents()[key_gone] = shared_ptr<int>();

    const unsigned int key1 = 111;
    shared_ptr<int> ptr1 = registry.lookup_or_create(key1);
    const int value1 = *ptr1 = 800;

    pair<unsigned int, int> i;
    EXPECT_TRUE(registry.get_next(i.first, &i));
    EXPECT_EQ(key1, i.first);
    EXPECT_EQ(value1, i.second);

    EXPECT_TRUE(registry.get_next(i.first, &i));
    EXPECT_EQ(key2, i.first);
    EXPECT_EQ(value2, i.second);

    EXPECT_FALSE(registry.get_next(i.first, &i));
  }
}

class SharedPtrRegistry_destructor : public ::testing::Test {
public:

  typedef enum { UNDEFINED, YES, NO } DieEnum;
  static DieEnum died;

  struct TellDie {
    TellDie() { died = NO; }
    ~TellDie() { died = YES; }
    
    int value;
  };

  virtual void SetUp() {
    died = UNDEFINED;
  }
};

SharedPtrRegistry_destructor::DieEnum SharedPtrRegistry_destructor::died = SharedPtrRegistry_destructor::UNDEFINED;

TEST_F(SharedPtrRegistry_destructor, destructor) {
  SharedPtrRegistry<int,TellDie> registry;
  EXPECT_EQ(UNDEFINED, died);
  int key = 101;
  {
    shared_ptr<TellDie> a = registry.lookup_or_create(key);
    EXPECT_EQ(NO, died);
    EXPECT_TRUE(a);
  }
  EXPECT_EQ(YES, died);
  EXPECT_FALSE(registry.lookup(key));
}

int main(int argc, char **argv) {
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

// Local Variables:
// compile-command: "cd ../.. ; make unittest_sharedptr_registry && ./unittest_sharedptr_registry # --gtest_filter=*.* --log-to-stderr=true"
// End:
