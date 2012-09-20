#ifndef CEPH_RGW_REST_SWIFT_H
#define CEPH_RGW_REST_SWIFT_H
#define TIME_BUF_SIZE 128

#include "rgw_op.h"
#include "rgw_rest.h"

class RGWGetObj_ObjStore_SWIFT : public RGWGetObj_ObjStore {
public:
  RGWGetObj_ObjStore_SWIFT() {}
  ~RGWGetObj_ObjStore_SWIFT() {}

  int send_response(bufferlist& bl);
};

class RGWListBuckets_ObjStore_SWIFT : public RGWListBuckets_ObjStore {
  int limit_max;
  int limit;
  string marker;
public:
  RGWListBuckets_ObjStore_SWIFT() {
    limit_max = 10000;
    limit = limit_max;
  }
  ~RGWListBuckets_ObjStore_SWIFT() {}

  int get_params();
  void send_response();
};

class RGWListBucket_ObjStore_SWIFT : public RGWListBucket_ObjStore {
  string path;
public:
  RGWListBucket_ObjStore_SWIFT() {
    default_max = 10000;
  }
  ~RGWListBucket_ObjStore_SWIFT() {}

  int get_params();
  void send_response();
};

class RGWStatAccount_ObjStore_SWIFT : public RGWStatAccount_ObjStore {
public:
  RGWStatAccount_ObjStore_SWIFT() {
  }
  ~RGWStatAccount_ObjStore_SWIFT() {}

  void send_response();
};

class RGWStatBucket_ObjStore_SWIFT : public RGWStatBucket_ObjStore {
public:
  RGWStatBucket_ObjStore_SWIFT() {}
  ~RGWStatBucket_ObjStore_SWIFT() {}

  void send_response();
};

class RGWCreateBucket_ObjStore_SWIFT : public RGWCreateBucket_ObjStore {
public:
  RGWCreateBucket_ObjStore_SWIFT() {}
  ~RGWCreateBucket_ObjStore_SWIFT() {}

  int get_params();
  void send_response();
};

class RGWDeleteBucket_ObjStore_SWIFT : public RGWDeleteBucket_ObjStore {
public:
  RGWDeleteBucket_ObjStore_SWIFT() {}
  ~RGWDeleteBucket_ObjStore_SWIFT() {}

  void send_response();
};

class RGWPutObj_ObjStore_SWIFT : public RGWPutObj_ObjStore {
public:
  RGWPutObj_ObjStore_SWIFT() {}
  ~RGWPutObj_ObjStore_SWIFT() {}

  int get_params();
  void send_response();
};

class RGWPutMetadata_ObjStore_SWIFT : public RGWPutMetadata_ObjStore {
public:
  RGWPutMetadata_ObjStore_SWIFT() {}
  ~RGWPutMetadata_ObjStore_SWIFT() {}

  int get_params();
  void send_response();
};

class RGWDeleteObj_ObjStore_SWIFT : public RGWDeleteObj_ObjStore {
public:
  RGWDeleteObj_ObjStore_SWIFT() {}
  ~RGWDeleteObj_ObjStore_SWIFT() {}

  void send_response();
};

class RGWCopyObj_ObjStore_SWIFT : public RGWCopyObj_ObjStore {
public:
  RGWCopyObj_ObjStore_SWIFT() {}
  ~RGWCopyObj_ObjStore_SWIFT() {}

  int init_dest_policy();
  int get_params();
  void send_response();
};

class RGWGetACLs_ObjStore_SWIFT : public RGWGetACLs_ObjStore {
public:
  RGWGetACLs_ObjStore_SWIFT() {}
  ~RGWGetACLs_ObjStore_SWIFT() {}

  void send_response() {}
};

class RGWPutACLs_ObjStore_SWIFT : public RGWPutACLs_ObjStore {
public:
  RGWPutACLs_ObjStore_SWIFT() : RGWPutACLs_ObjStore() {}
  virtual ~RGWPutACLs_ObjStore_SWIFT() {}

  void send_response() {}
};


class RGWHandler_ObjStore_SWIFT : public RGWHandler_ObjStore {
protected:
  bool is_acl_op() {
    return false; // for now
  }
  bool is_obj_update_op() {
    return s->op == OP_POST;
  }

  RGWOp *get_retrieve_obj_op(bool get_data);
  RGWOp *get_retrieve_op(bool get_data);
  RGWOp *get_create_op();
  RGWOp *get_delete_op();
  RGWOp *get_post_op();
  RGWOp *get_copy_op();

  int init_from_header(struct req_state *s);
public:
  RGWHandler_ObjStore_SWIFT() : RGWHandler_ObjStore() {}
  virtual ~RGWHandler_ObjStore_SWIFT() {}

  bool filter_request(struct req_state *s);
  int validate_bucket_name(const string& bucket);

  int init(struct req_state *state, RGWClientIO *cio);
  int authorize();

  RGWAccessControlPolicy *alloc_policy() { return NULL; /* return new RGWAccessControlPolicy_SWIFT; */ }
  void free_policy(RGWAccessControlPolicy *policy) { delete policy; }
};

#endif
