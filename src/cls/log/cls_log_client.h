#ifndef CEPH_CLS_LOG_CLIENT_H
#define CEPH_CLS_LOG_CLIENT_H

#include "include/types.h"
#include "include/rados/librados.hpp"
#include "cls_log_types.h"

/*
 * log objclass
 */

void cls_log_add(librados::ObjectWriteOperation& op, cls_log_entry& entry);
void cls_log_add(librados::ObjectWriteOperation& op, const utime_t& timestamp,
                 const string& section, const string& name, bufferlist& bl);

void cls_log_list(librados::ObjectReadOperation& op, utime_t& from, utime_t& to,
                  string& in_marker, int max_entries, list<cls_log_entry>& entries,
                  string *out_marker, bool *truncated);

void cls_log_trim(librados::ObjectWriteOperation& op, utime_t& from, utime_t& to);
int cls_log_trim(librados::IoCtx& io_ctx, string& oid, utime_t& from, utime_t& to);

#endif
