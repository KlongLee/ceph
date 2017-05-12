// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2011 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "gtest/gtest.h"
#include "include/rados/librados.h"

#include <sstream>
#include <string>
#include <string.h>
#include <errno.h>

using std::string;

TEST(LibRadosConfig, SimpleSet) {
  rados_t cl;
  int ret = rados_create(&cl, NULL);
  ASSERT_EQ(ret, 0);

  ret = rados_conf_set(cl, "leveldb_max_open_files", "21");
  ASSERT_EQ(ret, 0);

  char buf[128];
  memset(buf, 0, sizeof(buf));
  ret = rados_conf_get(cl, "leveldb_max_open_files", buf, sizeof(buf));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(string("21"), string(buf));

  rados_shutdown(cl);
}

TEST(LibRadosConfig, ArgV) {
  rados_t cl;
  int ret = rados_create(&cl, NULL);
  ASSERT_EQ(ret, 0);

  const char *argv[] = { "foo", "--leveldb-max-open-files", "2",
			 "--keyfile", "/tmp/my-keyfile", NULL };
  size_t argc = (sizeof(argv) / sizeof(argv[0])) - 1;
  rados_conf_parse_argv(cl, argc, argv);

  char buf[128];
  memset(buf, 0, sizeof(buf));
  ret = rados_conf_get(cl, "keyfile", buf, sizeof(buf));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(string("/tmp/my-keyfile"), string(buf));

  memset(buf, 0, sizeof(buf));
  ret = rados_conf_get(cl, "leveldb_max_open_files", buf, sizeof(buf));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(string("2"), string(buf));

  rados_shutdown(cl);
}

TEST(LibRadosConfig, DebugLevels) {
  rados_t cl;
  int ret = rados_create(&cl, NULL);
  ASSERT_EQ(ret, 0);

  ret = rados_conf_set(cl, "debug_rados", "3");
  ASSERT_EQ(ret, 0);

  char buf[128];
  memset(buf, 0, sizeof(buf));
  ret = rados_conf_get(cl, "debug_rados", buf, sizeof(buf));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(0, strncmp("3/", buf, 2));

  ret = rados_conf_set(cl, "debug_rados", "7/8");
  ASSERT_EQ(ret, 0);

  memset(buf, 0, sizeof(buf));
  ret = rados_conf_get(cl, "debug_rados", buf, sizeof(buf));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(0, strcmp("7/8", buf));

  ret = rados_conf_set(cl, "debug_rados", "foo");
  ASSERT_EQ(ret, -EINVAL);

  ret = rados_conf_set(cl, "debug_asdkfasdjfajksdf", "foo");
  ASSERT_EQ(ret, -ENOENT);

  ret = rados_conf_get(cl, "debug_radfjadfsdados", buf, sizeof(buf));
  ASSERT_EQ(ret, -ENOENT);

  rados_shutdown(cl);
}
