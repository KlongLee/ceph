// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2019 Red Hat <contact@redhat.com>
 * Author: Adam C. Emerson
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef CEPH_RADOS_CLS_VERSION_H
#define CEPH_RADOS_CLS_VERSION_H

#include <boost/system/error_code.hpp>

#include "include/neorados/RADOS.hpp"
#include "include/expected.hpp"

#include "cls/version/cls_version_types.h"
#include "cls/version/cls_version_ops.h"

#include "neorados/cls/common.h"

namespace neorados::cls::version {
void set(WriteOp& op, obj_version& ver);

/* increase anyway */
void inc(WriteOp& op);

/* conditional increase, return -EAGAIN if condition fails */
void inc(WriteOp& op, obj_version& ver, VersionCond cond);

void read(ReadOp& op, obj_version *objv);

template<typename CT>
auto read(RADOS& r, const Object& o, const IOContext& ioc, CT&& ct)
{
  return exec<cls_version_read_ret>(r, o, ioc, "version"sv, "read"sv,
				    [](cls_version_read_ret&& ret) {
				      return std::move(ret.objv);
				    }, std::forward<CT>(ct));

}

void check(ReadOp& op, obj_version& ver, VersionCond cond);
void check(WriteOp& op, obj_version& ver, VersionCond cond);
}

#endif // CEPH_RADOS_CLS_VERSION_H
