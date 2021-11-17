// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "mon/ConfigMap.h"

#include <iostream>
#include <string>
#include "crush/CrushWrapper.h"
#include "common/ceph_context.h"
#include "global/global_context.h"
#include "gtest/gtest.h"


TEST(ConfigMap, parse_key)
{
  ConfigMap cm;
  {
    std::string name, who;
    cm.parse_key("global/foo", &name, &who);
    ASSERT_EQ("foo", name);
    ASSERT_EQ("global", who);
  }
  {
    std::string name, who;
    cm.parse_key("mon/foo", &name, &who);
    ASSERT_EQ("foo", name);
    ASSERT_EQ("mon", who);
  }
  {
    std::string name, who;
    cm.parse_key("mon.a/foo", &name, &who);
    ASSERT_EQ("foo", name);
    ASSERT_EQ("mon.a", who);
  }
  {
    std::string name, who;
    cm.parse_key("mon.a/mgr/foo", &name, &who);
    ASSERT_EQ("mgr/foo", name);
    ASSERT_EQ("mon.a", who);
  }
  {
    std::string name, who;
    cm.parse_key("mon.a/a=b/foo", &name, &who);
    ASSERT_EQ("foo", name);
    ASSERT_EQ("mon.a/a=b", who);
  }
  {
    std::string name, who;
    cm.parse_key("mon.a/a=b/c=d/foo", &name, &who);
    ASSERT_EQ("foo", name);
    ASSERT_EQ("mon.a/a=b/c=d", who);
  }
}

TEST(ConfigMap, add_option)
{
  ConfigMap cm;
  auto cct = new CephContext(CEPH_ENTITY_TYPE_MON);
  int r;

  r = cm.add_option(
    cct, "foo", "global", "fooval",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.global.options.size());

  r = cm.add_option(
    cct, "foo", "mon", "fooval",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_type.size());
  ASSERT_EQ(1, cm.by_type["mon"].options.size());
  
  r = cm.add_option(
    cct, "foo", "mon.a", "fooval",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_id.size());
  ASSERT_EQ(1, cm.by_id["mon.a"].options.size());
}


TEST(ConfigMap, result_sections)
{
  ConfigMap cm;
  auto cct = new CephContext(CEPH_ENTITY_TYPE_MON);
  auto crush = new CrushWrapper;
  crush->finalize();

  int r;

  r = cm.add_option(
    cct, "foo", "global", "g",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.global.options.size());

  r = cm.add_option(
    cct, "foo", "mon", "m",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_type.size());
  ASSERT_EQ(1, cm.by_type["mon"].options.size());

  r = cm.add_option(
    cct, "foo", "mon.a", "a",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_id.size());
  ASSERT_EQ(1, cm.by_id["mon.a"].options.size());

  EntityName n;
  n.set(CEPH_ENTITY_TYPE_MON, "a");
  auto c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(1, c.size());
  ASSERT_EQ("a", c["foo"]);

  n.set(CEPH_ENTITY_TYPE_MON, "b");
  c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(1, c.size());
  ASSERT_EQ("m", c["foo"]);

  n.set(CEPH_ENTITY_TYPE_MDS, "c");
  c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(1, c.size());
  ASSERT_EQ("g", c["foo"]);
}

TEST(ConfigMap, add_profile)
{
  ConfigMap cm;
  auto cct = new CephContext(CEPH_ENTITY_TYPE_MON);
  int r;

  r = cm.add_profile(
    cct, "foo", "{\"level\": \"basic\", \"values\": {\"a\": {\"opt\": \"aaa\"}, \"b\": {\"opt\": \"bbb\"}}}",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.profiles.size());
  Profile& foo = cm.profiles.begin()->second;
  ASSERT_EQ(2, foo.profile.size());
  ASSERT_EQ(Option::LEVEL_BASIC, foo.opt->level);
  ASSERT_EQ(1, foo.profile["a"].options.size());
  ASSERT_EQ(1, foo.profile["b"].options.size());
  ASSERT_EQ(1, foo.profile["b"].options.count("opt"));
}

TEST(ConfigMap, result_profile)
{
  ConfigMap cm;
  auto cct = new CephContext(CEPH_ENTITY_TYPE_MON);
  auto crush = new CrushWrapper;
  crush->finalize();

  int r;

  r = cm.add_profile(
    cct, "bar", "{\"level\": \"basic\", \"values\": {\"a\": {\"foo\": \"aaa\"}, \"b\": {\"foo\": \"bbb\"}}}",
    [&](const std::string& name) {
      return nullptr;
    });
  
  r = cm.add_option(
    cct, "foo", "global", "g",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.global.options.size());

  r = cm.add_option(
    cct, "foo", "mon", "m",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_type.size());
  ASSERT_EQ(1, cm.by_type["mon"].options.size());

  r = cm.add_option(
    cct, "foo", "mon.a", "a",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_id.size());
  ASSERT_EQ(1, cm.by_id["mon.a"].options.size());

  r = cm.add_option(
    cct, "bar", "mon.a", "a",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(1, cm.by_id.size());
  ASSERT_EQ(2, cm.by_id["mon.a"].options.size());

  r = cm.add_option(
    cct, "bar", "mon.b", "b",
    [&](const std::string& name) {
      return nullptr;
    });
  ASSERT_EQ(0, r);
  ASSERT_EQ(2, cm.by_id.size());
  ASSERT_EQ(1, cm.by_id["mon.b"].options.size());

  EntityName n;
  n.set(CEPH_ENTITY_TYPE_MON, "a");
  auto c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(2, c.size());
  ASSERT_EQ("a", c["foo"]);
  ASSERT_EQ("a", c["bar"]);

  n.set(CEPH_ENTITY_TYPE_MON, "b");
  c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(2, c.size());
  ASSERT_EQ("bbb", c["foo"]);
  ASSERT_EQ("b", c["bar"]);

  n.set(CEPH_ENTITY_TYPE_MDS, "c");
  c = cm.generate_entity_map(
    n, {}, crush, "none", nullptr);
  ASSERT_EQ(1, c.size());
  ASSERT_EQ("g", c["foo"]);
}
