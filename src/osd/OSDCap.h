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
 * OSDCaps: Hold the capabilities associated with a single authenticated 
 * user key. These are specified by text strings of the form
 * "allow r" (which allows reading anything on the OSD)
 * "allow rwx auid foo[,bar,baz]" (which allows full access to listed auids)
 *  "allow rwx pool foo[,bar,baz]" (which allows full access to listed pools)
 * "allow *" (which allows full access to EVERYTHING)
 *
 * The OSD assumes that anyone with * caps is an admin and has full
 * message permissions. This means that only the monitor and the OSDs
 * should get *
 */

#ifndef CEPH_OSDCAP_H
#define CEPH_OSDCAP_H

#include <ostream>
using std::ostream;

#include "include/types.h"

static const __u8 OSD_CAP_R = 0x01;      // read
static const __u8 OSD_CAP_W = 0x02;      // write
static const __u8 OSD_CAP_X = 0x04;      // (class) execute
static const __u8 OSD_CAP_ANY = 0xff;    // *

typedef __u8 rwxa_t;

ostream& operator<<(ostream& out, rwxa_t p);

struct OSDCapSpec {
  rwxa_t allow;
  std::string class_name;
  std::string class_allow;

  OSDCapSpec() : allow(0) {}
  OSDCapSpec(rwxa_t v) : allow(v) {}
  OSDCapSpec(std::string n) : allow(0), class_name(n) {}
  OSDCapSpec(std::string n, std::string a) : allow(0), class_name(n), class_allow(a) {}

  bool allow_all() const {
    return allow & OSD_CAP_ANY;
  }
};

ostream& operator<<(ostream& out, const OSDCapSpec& s);


struct OSDCapMatch {
  // auid and pool_name are mutually exclusive
  int64_t auid;
  std::string pool_name;

  std::string object_prefix;

  OSDCapMatch() : auid(CEPH_AUTH_UID_DEFAULT) {}
  OSDCapMatch(std::string pl, std::string pre) : auid(CEPH_AUTH_UID_DEFAULT), pool_name(pl), object_prefix(pre) {}
  OSDCapMatch(uint64_t auid, std::string pre) : auid(auid), object_prefix(pre) {}

  /**
   * check if given request parameters match our constraints
   *
   * @param auid requesting user's auid
   * @param pool_name pool name
   * @param pool_auid pool's auid
   * @param object object name
   * @return true if we match, false otherwise
   */
  bool is_match(const std::string& pool_name, int64_t pool_auid, const std::string& object) const;
};

ostream& operator<<(ostream& out, const OSDCapMatch& m);


struct OSDCapGrant {
  OSDCapMatch match;
  OSDCapSpec spec;

  OSDCapGrant() {}
  OSDCapGrant(OSDCapMatch m, OSDCapSpec s) : match(m), spec(s) {}
};

ostream& operator<<(ostream& out, const OSDCapGrant& g);


struct OSDCap {
  std::vector<OSDCapGrant> grants;

  OSDCap() {}
  OSDCap(std::vector<OSDCapGrant> g) : grants(g) {}

  bool allow_all() const;
  void set_allow_all();
  bool parse(const std::string& str, ostream *err=NULL);

  const OSDCapSpec *get_cap(const std::string& pool_name, int64_t pool_auid, const std::string& object) const;
};

static inline ostream& operator<<(ostream& out, const OSDCap& cap) 
{
  return out << "osdcap" << cap.grants;
}

#endif
