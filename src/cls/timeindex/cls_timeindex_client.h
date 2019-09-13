// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_CLS_TIMEINDEX_CLIENT_H
#define CEPH_CLS_TIMEINDEX_CLIENT_H

#include "include/rados/librados.hpp"

#include "cls_timeindex_ops.h"

/**
 * timeindex objclass
 */
class TimeindexListCtx : public librados::ObjectOperationCompletion {
  std::vector<cls_timeindex_entry> *entries;
  std::string *marker;
  bool *truncated;

public:
  ///* ctor
  TimeindexListCtx(
    std::vector<cls_timeindex_entry> *_entries,
    std::string *_marker,
    bool *_truncated)
    : entries(_entries), marker(_marker), truncated(_truncated) {}

  ///* dtor
  ~TimeindexListCtx() {}

  void handle_completion(int r, bufferlist& bl) override {
    if (r >= 0) {
      cls_timeindex_list_ret ret;
      try {
        auto iter = bl.cbegin();
        decode(ret, iter);
        if (entries)
          *entries = ret.entries;
        if (truncated)
          *truncated = ret.truncated;
        if (marker)
          *marker = ret.marker;
      } catch (buffer::error& err) {
        // nothing we can do about it atm
      }
    }
  }
};

void cls_timeindex_add_prepare_entry(
  cls_timeindex_entry& entry,
  ceph::real_time key_timestamp,
  const std::string& key_ext,
  bufferlist& bl);

void cls_timeindex_add(
  librados::ObjectWriteOperation& op,
  const std::vector<cls_timeindex_entry>& entry);

void cls_timeindex_add(
  librados::ObjectWriteOperation& op,
  const cls_timeindex_entry& entry);

void cls_timeindex_add(
  librados::ObjectWriteOperation& op,
  ceph::real_time timestamp,
  const std::string& name,
  const bufferlist& bl);

void cls_timeindex_list(
  librados::ObjectReadOperation& op,
  ceph::real_time from,
  ceph::real_time to,
  const std::string& in_marker,
  const int max_entries,
  std::vector<cls_timeindex_entry>& entries,
  std::string *out_marker,
  bool *truncated);

void cls_timeindex_trim(
  librados::ObjectWriteOperation& op,
  ceph::real_time from_time,
  ceph::real_time to_time,
  const std::string& from_marker = std::string(),
  const std::string& to_marker = std::string());

// these overloads which call io_ctx.operate() should not be called in the rgw.
// rgw_rados_operate() should be called after the overloads w/o calls to io_ctx.operate()
#ifndef CLS_CLIENT_HIDE_IOCTX
int cls_timeindex_trim(
  librados::IoCtx& io_ctx,
  const std::string& oid,
  ceph::real_time from_time,
  ceph::real_time to_time,
  const std::string& from_marker = std::string(),
  const std::string& to_marker = std::string());
#endif

#endif
