// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_TEST_RADOS_TESTCASE_H
#define CEPH_TEST_RADOS_TESTCASE_H

#include "include/rados/librados.h"
#include "include/rados/librados.hpp"
#include "include/radosstriper/libradosstriper.h"
#include "include/radosstriper/libradosstriper.hpp"
#include "gtest/gtest.h"

#include <functional>
#include <mutex>
#include <memory>
#include <string>
#include <vector>

/**
 * These test cases create a temporary pool that lives as long as the
 * test case.  Each test within a test case gets a new ioctx and striper
 * set to a unique namespace within the pool.
 *
 * Since pool creation and deletion is slow, this allows many tests to
 * run faster.
 */
class StriperTest : public ::testing::Test {
public:
  StriperTest() {}
  ~StriperTest() override {}
protected:
  static void SetUpTestCase();
  static void TearDownTestCase();
  static rados_t s_cluster;
  static std::string pool_name;

  void SetUp() override;
  void TearDown() override;
  rados_t cluster = NULL;
  rados_ioctx_t ioctx = NULL;
  rados_striper_t striper = NULL;
};

class StriperTestPP : public ::testing::Test {
public:
  StriperTestPP() : cluster(s_cluster) {}
  ~StriperTestPP() override {}
  static void SetUpTestCase();
  static void TearDownTestCase();
protected:
  static librados::Rados s_cluster;
  static std::string pool_name;

  void SetUp() override;
  librados::Rados &cluster;
  librados::IoCtx ioctx;
  libradosstriper::RadosStriper striper;
};

struct TestData {
  uint32_t stripe_unit;
  uint32_t stripe_count;
  uint32_t object_size;
  size_t size;
};
// this is pure copy and paste from previous class
// but for the inheritance from TestWithParam
// with gtest >= 1.6, we couldd avoid this by using
// inheritance from WithParamInterface
class StriperTestParam : public ::testing::TestWithParam<TestData> {
public:
  StriperTestParam() : cluster(s_cluster) {}
  ~StriperTestParam() override {}
  static void SetUpTestCase();
  static void TearDownTestCase();
protected:
  static librados::Rados s_cluster;
  static std::string pool_name;

  void SetUp() override;
  librados::Rados &cluster;
  librados::IoCtx ioctx;
  libradosstriper::RadosStriper striper;
};

class StriperMaxSharedLockTest {
public:
  StriperMaxSharedLockTest()
    : ret{0},
      ioctx{std::make_unique<librados::IoCtx>()},
      cluster{std::make_unique<librados::Rados>()},
      striper{std::make_unique<libradosstriper::RadosStriper>()} {}

  void init();
  static void destory();

  static std::string pool_name;
  static librados::Rados s_cluster;

  int ret;
  std::unique_ptr<librados::IoCtx> ioctx;
  std::unique_ptr<librados::Rados> cluster;
  std::unique_ptr<libradosstriper::RadosStriper> striper;
};

class ParallelStriperMaxSharedLockTest {
public:
  ~ParallelStriperMaxSharedLockTest() {
    StriperMaxSharedLockTest::destory();
  }

  void sync_read(char *, const size_t, const size_t);
  void sync_write(char *, const size_t, const size_t);
  void async_read(char *, const size_t, const size_t);
  void async_write(char *, const size_t, const size_t);
  void access(std::function<int(rados_striper_t&)>, const size_t);

  std::mutex m;
  std::vector<std::unique_ptr<StriperMaxSharedLockTest>> refs;
};

#endif
