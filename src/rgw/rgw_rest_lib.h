// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_REST_LIB_H
#define CEPH_RGW_REST_LIB_H

#include <functional>
#include "rgw_rest.h"
#include "rgw_common.h"
#include "rgw_lib.h"


/* XXX do we even need an RGWRESTMgr? */
class RGWRESTMgr_Lib : public RGWRESTMgr {
public:
  RGWRESTMgr_Lib() {}
  virtual ~RGWRESTMgr_Lib() {}
 #warning remove this
#if 0
  virtual RGWHandler* get_handler(struct req_state* s) { return nullptr; }
#endif
}; /* RGWRESTMgr_Lib */

/* rgw_lib RGWHandler */
class RGWHandler_REST_Lib : public RGWHandler_REST {
  friend class RGWRESTMgr_Lib;
public:

  virtual int authorize() {
    return RGW_Auth_S3::authorize(store, s);
  }

  RGWHandler_REST_Lib() {}
  virtual ~RGWHandler_REST_Lib() {}
  static int init_from_header(struct req_state *s);
}; /* RGWHandler_REST_Lib */


/* RGWOps */

class RGWListBuckets_ObjStore_Lib : public RGWListBuckets_ObjStore {
public:

  RGWListBuckets_ObjStore_Lib() {}
  ~RGWListBuckets_ObjStore_Lib() {}

  virtual void send_response_begin(bool has_buckets);
  virtual void send_response_data(RGWUserBuckets& buckets);
  virtual void send_response_end();

  int get_params() {
    limit = -1; /* no limit */
    return 0;
  }
}; /* RGWListBuckets_ObjStore_Lib */

class RGWListBucket_ObjStore_Lib : public RGWListBucket_ObjStore {
public:
  RGWListBucket_ObjStore_Lib() {
    default_max = 1000;
  }

  ~RGWListBucket_ObjStore_Lib() {}

  int get_params();
  virtual void send_response();

  virtual void send_versioned_response() {
    send_response();
  }
}; /* RGWListBucket_ObjStore_Lib */

class RGWStatBucket_ObjStore_Lib : public RGWStatBucket_ObjStore {
public:
  RGWStatBucket_ObjStore_Lib() {}
  ~RGWStatBucket_ObjStore_Lib() {}

  virtual void send_response();

}; /* RGWListBucket_ObjStore_Lib */

#endif /* CEPH_RGW_REST_LIB_H */
