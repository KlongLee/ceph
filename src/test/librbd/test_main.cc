// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/rados/librados.hpp"
#include "global/global_context.h"
#include "test/librados/test.h"
#include "test/librados/test_cxx.h"
#include "test_support.h"
#include "gtest/gtest.h"
#include <iostream>
#include <string>

extern void register_test_librbd();
#ifdef TEST_LIBRBD_INTERNALS
extern void register_test_deep_copy();
extern void register_test_groups();
extern void register_test_image_watcher();
extern void register_test_internal();
extern void register_test_journal_entries();
extern void register_test_journal_replay();
extern void register_test_migration();
extern void register_test_mirroring();
extern void register_test_mirroring_watcher();
extern void register_test_object_map();
extern void register_test_operations();
extern void register_test_trash();
#if defined(WITH_RWL)
extern void register_test_blockguard();
extern void register_test_write_log_map();
#endif //defined(WITH_RWL)
#endif // TEST_LIBRBD_INTERNALS

int main(int argc, char **argv)
{
  setenv("RBD_FORCE_ALLOW_V1","1",1);
#if defined(WITH_RWL)
  /* Disable actual PMDK persistence guarantees for unit tests */
  setenv("PMEM_IS_PMEM_FORCE","1",1);
#else
  uint64_t features;

  if (get_features(&features)) {
    if (features & RBD_FEATURE_IMAGE_CACHE) {
      std::cout << "RBD_FEATURE_IMAGE_CACHE not supported in this build. No tests run." << std::endl;
      return 0;
    }
  }
#endif
  register_test_librbd();
#ifdef TEST_LIBRBD_INTERNALS
  register_test_deep_copy();
  register_test_groups();
  register_test_image_watcher();
  register_test_internal();
  register_test_journal_entries();
  register_test_journal_replay();
  register_test_migration();
  register_test_mirroring();
  register_test_mirroring_watcher();
  register_test_object_map();
  register_test_operations();
  register_test_trash();
#if defined(WITH_RWL)
  register_test_blockguard();
  register_test_write_log_map();
#endif //defined(WITH_RWL)
#endif // TEST_LIBRBD_INTERNALS

  ::testing::InitGoogleTest(&argc, argv);

  librados::Rados rados;
  std::string result = connect_cluster_pp(rados);
  if (result != "" ) {
    std::cerr << result << std::endl;
    return 1;
  }

#ifdef TEST_LIBRBD_INTERNALS
  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());
#endif // TEST_LIBRBD_INTERNALS

  int r = rados.conf_set("lockdep", "true");
  if (r < 0) {
    std::cerr << "failed to enable lockdep" << std::endl;
    return -r;
  }

  int seed = getpid();
  std::cout << "seed " << seed << std::endl;
  srand(seed);

  return RUN_ALL_TESTS();
}
