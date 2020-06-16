// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RBD_SCHEDULE_H
#define CEPH_RBD_SCHEDULE_H

#include "json_spirit/json_spirit.h"

#include <iostream>
#include <list>
#include <map>
#include <optional>
#include <string>
#include <boost/program_options.hpp>

namespace ceph { class Formatter; }

namespace rbd {

void add_level_spec_options(
  boost::program_options::options_description *options, bool allow_image=true);
int get_level_spec_args(const boost::program_options::variables_map &vm,
                        std::map<std::string, std::string> *args);
void add_schedule_options(
  boost::program_options::options_description *positional);
int get_schedule_args(const boost::program_options::variables_map &vm,
                      bool mandatory, std::map<std::string, std::string> *args);
void add_retention_options(
  boost::program_options::options_description *options, bool all);
int get_retention_args(const boost::program_options::variables_map &vm,
                       bool mandatory, bool all,
                       std::map<std::string, std::string> *args);

class Schedule {
public:
  Schedule() {
  }

  int parse(json_spirit::mValue &schedule_val);
  void dump(ceph::Formatter *f);

  friend std::ostream& operator<<(std::ostream& os, Schedule &s);

private:
  struct Item {
    std::string interval;
    std::optional<std::string> start_time;
  };

  std::string name;
  std::list<Item> items;
};

std::ostream& operator<<(std::ostream& os, Schedule &s);

class ScheduleList {
public:
  ScheduleList(bool allow_images=true) : allow_images(allow_images) {
  }

  int parse(const std::string &list);
  Schedule *find(const std::string &name);
  void dump(ceph::Formatter *f);

  friend std::ostream& operator<<(std::ostream& os, ScheduleList &l);

private:
  bool allow_images;
  std::map<std::string, Schedule> schedules;
};

std::ostream& operator<<(std::ostream& os, ScheduleList &l);

class RetentionPolicy {
public:
  RetentionPolicy() {
  }

  int parse(json_spirit::mValue &schedule_val);
  void dump(ceph::Formatter *f);

  friend std::ostream& operator<<(std::ostream& os, RetentionPolicy &p);

private:
  struct Item {
    std::string interval = "*";
    uint64_t count;
  };

  std::string name;
  std::list<Item> items;
};

std::ostream& operator<<(std::ostream& os, RetentionPolicy &p);

class RetentionPolicyList {
public:
  RetentionPolicyList() {
  }

  int parse(const std::string &list);
  RetentionPolicy *find(const std::string &name);
  void dump(ceph::Formatter *f);

  friend std::ostream& operator<<(std::ostream& os, RetentionPolicyList &l);

private:
  std::map<std::string, RetentionPolicy> policies;
};

std::ostream& operator<<(std::ostream& os, RetentionPolicyList &l);

} // namespace rbd

#endif // CEPH_RBD_SCHEDULE_H
