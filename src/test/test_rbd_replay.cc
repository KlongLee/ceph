// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 Adam Crume <adamcrume@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "common/escape.h"
#include "gtest/gtest.h"
#include <stdint.h>
#include <boost/foreach.hpp>
#include "rbd_replay/Deser.hpp"
#include "rbd_replay/ImageNameMap.hpp"


using rbd_replay::ImageNameMap;
using rbd_replay::NameMap;

std::ostream& operator<<(std::ostream& o, const ImageNameMap::Name& name) {
  return o << "('" << name.first << "', '" << name.second << "')";
}

static ImageNameMap::Name bad_mapping(ImageNameMap::Name input, std::string output) {
  return ImageNameMap::Name("xxx", "xxx");
}

static void add_mapping(ImageNameMap *map, std::string mapping_string) {
  ImageNameMap::Mapping mapping;
  if (!map->parse_mapping(mapping_string, &mapping)) {
    ASSERT_TRUE(false) << "Failed to parse mapping string '" << mapping_string << "'";
  }
  map->add_mapping(mapping);
}

static void add_mapping(NameMap *map, std::string mapping_string) {
  NameMap::Mapping mapping;
  if (!map->parse_mapping(mapping_string, &mapping)) {
    ASSERT_TRUE(false) << "Failed to parse mapping string '" << mapping_string << "'";
  }
  map->add_mapping(mapping);
}

TEST(RBDReplay, Deser) {
  const char data[] = {1, 2, 3, 4, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o', 1, 0};
  const std::string s(data, sizeof(data));
  std::istringstream iss(s);
  rbd_replay::Deser deser(iss);
  EXPECT_EQ(false, deser.eof());
  EXPECT_EQ(0x01020304u, deser.read_uint32_t());
  EXPECT_EQ(false, deser.eof());
  EXPECT_EQ("hello", deser.read_string());
  EXPECT_EQ(false, deser.eof());
  EXPECT_EQ(true, deser.read_bool());
  EXPECT_EQ(false, deser.eof());
  EXPECT_EQ(false, deser.read_bool());
  EXPECT_EQ(false, deser.eof());
  deser.read_uint8_t();
  EXPECT_EQ(true, deser.eof());
}

TEST(RBDReplay, ImageNameMap) {
  typedef ImageNameMap::Name Name;
  ImageNameMap m;
  m.set_bad_mapping_fallback(bad_mapping);
  add_mapping(&m, "x/y=y/x");
  add_mapping(&m, "a\\=b/c=h/i");
  add_mapping(&m, "a/b\\=c=j/k");
  add_mapping(&m, "a\\\\/b/c=d/e");
  add_mapping(&m, "a/b\\\\/c=f/g");
  add_mapping(&m, "image/snap_(.*)=image_$1/");
  add_mapping(&m, "bad/=///");
  EXPECT_EQ(Name("y", "x"), m.map(Name("x", "y")));
  EXPECT_EQ(Name("h", "i"), m.map(Name("a=b", "c")));
  EXPECT_EQ(Name("j", "k"), m.map(Name("a", "b=c")));
  EXPECT_EQ(Name("d", "e"), m.map(Name("a/b", "c")));
  EXPECT_EQ(Name("f", "g"), m.map(Name("a", "b/c")));
  EXPECT_EQ(Name("image_1", ""), m.map(Name("image", "snap_1")));
  EXPECT_EQ(Name("xxx", "xxx"), m.map(Name("bad", "")));
}

TEST(RBDReplay, NameMap) {
  NameMap m;
  add_mapping(&m, "x=y");
  add_mapping(&m, "image_(.*)=$1_image");
  EXPECT_EQ("y", m.map("x"));
  EXPECT_EQ("ab_image", m.map("image_ab"));
  EXPECT_EQ("asdf", m.map("asdf"));
}
