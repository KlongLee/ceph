// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2009 Sage Weil <sage@newdream.net>
 * Copyright (C) 2015 Yehuda Sadeh <yehuda@redhat.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_RGW_COMMON_H
#define CEPH_RGW_COMMON_H

#include "common/ceph_crypto.h"
#include "common/perf_counters.h"
#include "acconfig.h"
#include "rgw_acl.h"
#include "rgw_cors.h"
#include "rgw_iam_policy.h"
#include "rgw_quota.h"
#include "rgw_string.h"
#include "rgw_website.h"
#include "cls/version/cls_version_types.h"
#include "cls/user/cls_user_types.h"
#include "cls/rgw/cls_rgw_types.h"
#include "include/rados/librados.hpp"

namespace ceph {
  class Formatter;
}

using ceph::crypto::MD5;


#define RGW_ATTR_PREFIX  "user.rgw."

#define RGW_HTTP_RGWX_ATTR_PREFIX "RGWX_ATTR_"
#define RGW_HTTP_RGWX_ATTR_PREFIX_OUT "Rgwx-Attr-"

#define RGW_AMZ_PREFIX "x-amz-"
#define RGW_AMZ_META_PREFIX RGW_AMZ_PREFIX "meta-"
#define RGW_AMZ_WEBSITE_REDIRECT_LOCATION RGW_AMZ_PREFIX "website-redirect-location"

#define RGW_SYS_PARAM_PREFIX "rgwx-"

#define RGW_ATTR_ACL		RGW_ATTR_PREFIX "acl"
#define RGW_ATTR_LC            RGW_ATTR_PREFIX "lc"
#define RGW_ATTR_CORS		RGW_ATTR_PREFIX "cors"
#define RGW_ATTR_ETAG    	RGW_ATTR_PREFIX "etag"
#define RGW_ATTR_BUCKETS	RGW_ATTR_PREFIX "buckets"
#define RGW_ATTR_META_PREFIX	RGW_ATTR_PREFIX RGW_AMZ_META_PREFIX
#define RGW_ATTR_CONTENT_TYPE	RGW_ATTR_PREFIX "content_type"
#define RGW_ATTR_CACHE_CONTROL	RGW_ATTR_PREFIX "cache_control"
#define RGW_ATTR_CONTENT_DISP	RGW_ATTR_PREFIX "content_disposition"
#define RGW_ATTR_CONTENT_ENC	RGW_ATTR_PREFIX "content_encoding"
#define RGW_ATTR_CONTENT_LANG	RGW_ATTR_PREFIX "content_language"
#define RGW_ATTR_EXPIRES	RGW_ATTR_PREFIX "expires"
#define RGW_ATTR_DELETE_AT 	RGW_ATTR_PREFIX "delete_at"
#define RGW_ATTR_ID_TAG    	RGW_ATTR_PREFIX "idtag"
#define RGW_ATTR_SHADOW_OBJ    	RGW_ATTR_PREFIX "shadow_name"
#define RGW_ATTR_MANIFEST    	RGW_ATTR_PREFIX "manifest"
#define RGW_ATTR_USER_MANIFEST  RGW_ATTR_PREFIX "user_manifest"
#define RGW_ATTR_AMZ_WEBSITE_REDIRECT_LOCATION	RGW_ATTR_PREFIX RGW_AMZ_WEBSITE_REDIRECT_LOCATION
#define RGW_ATTR_SLO_MANIFEST   RGW_ATTR_PREFIX "slo_manifest"
/* Information whether an object is SLO or not must be exposed to
 * user through custom HTTP header named X-Static-Large-Object. */
#define RGW_ATTR_SLO_UINDICATOR RGW_ATTR_META_PREFIX "static-large-object"
#define RGW_ATTR_X_ROBOTS_TAG	RGW_ATTR_PREFIX "x-robots-tag"

#define RGW_ATTR_PG_VER 	RGW_ATTR_PREFIX "pg_ver"
#define RGW_ATTR_SOURCE_ZONE    RGW_ATTR_PREFIX "source_zone"

#define RGW_ATTR_TEMPURL_KEY1   RGW_ATTR_META_PREFIX "temp-url-key"
#define RGW_ATTR_TEMPURL_KEY2   RGW_ATTR_META_PREFIX "temp-url-key-2"

/* Account/container quota of the Swift API. */
#define RGW_ATTR_QUOTA_NOBJS    RGW_ATTR_META_PREFIX "quota-count"
#define RGW_ATTR_QUOTA_MSIZE    RGW_ATTR_META_PREFIX "quota-bytes"

/* Static Web Site of Swift API. */
#define RGW_ATTR_WEB_INDEX      RGW_ATTR_META_PREFIX "web-index"
#define RGW_ATTR_WEB_ERROR      RGW_ATTR_META_PREFIX "web-error"
#define RGW_ATTR_WEB_LISTINGS   RGW_ATTR_META_PREFIX "web-listings"
#define RGW_ATTR_WEB_LIST_CSS   RGW_ATTR_META_PREFIX "web-listings-css"
#define RGW_ATTR_SUBDIR_MARKER  RGW_ATTR_META_PREFIX "web-directory-type"

#define RGW_ATTR_OLH_PREFIX     RGW_ATTR_PREFIX "olh."

#define RGW_ATTR_OLH_INFO       RGW_ATTR_OLH_PREFIX "info"
#define RGW_ATTR_OLH_VER        RGW_ATTR_OLH_PREFIX "ver"
#define RGW_ATTR_OLH_ID_TAG     RGW_ATTR_OLH_PREFIX "idtag"
#define RGW_ATTR_OLH_PENDING_PREFIX RGW_ATTR_OLH_PREFIX "pending."

#define RGW_ATTR_COMPRESSION    RGW_ATTR_PREFIX "compression"

/* IAM Policy */
#define RGW_ATTR_IAM_POLICY	RGW_ATTR_PREFIX "iam-policy"


/* RGW File Attributes */
#define RGW_ATTR_UNIX_KEY1      RGW_ATTR_PREFIX "unix-key1"
#define RGW_ATTR_UNIX1          RGW_ATTR_PREFIX "unix1"

#define RGW_ATTR_CRYPT_PREFIX   RGW_ATTR_PREFIX "crypt."
#define RGW_ATTR_CRYPT_MODE     RGW_ATTR_CRYPT_PREFIX "mode"
#define RGW_ATTR_CRYPT_KEYMD5   RGW_ATTR_CRYPT_PREFIX "keymd5"
#define RGW_ATTR_CRYPT_KEYID    RGW_ATTR_CRYPT_PREFIX "keyid"
#define RGW_ATTR_CRYPT_KEYSEL   RGW_ATTR_CRYPT_PREFIX "keysel"

#define RGW_BUCKETS_OBJ_SUFFIX ".buckets"

#define RGW_FORMAT_PLAIN        0
#define RGW_FORMAT_XML          1
#define RGW_FORMAT_JSON         2
#define RGW_FORMAT_HTML         3

#define RGW_CAP_READ            0x1
#define RGW_CAP_WRITE           0x2
#define RGW_CAP_ALL             (RGW_CAP_READ | RGW_CAP_WRITE)

#define RGW_REST_SWIFT          0x1
#define RGW_REST_SWIFT_AUTH     0x2
#define RGW_REST_S3             0x4
#define RGW_REST_WEBSITE     0x8

#define RGW_SUSPENDED_USER_AUID (uint64_t)-2

#define RGW_OP_TYPE_READ         0x01
#define RGW_OP_TYPE_WRITE        0x02
#define RGW_OP_TYPE_DELETE       0x04

#define RGW_OP_TYPE_MODIFY       (RGW_OP_TYPE_WRITE | RGW_OP_TYPE_DELETE)
#define RGW_OP_TYPE_ALL          (RGW_OP_TYPE_READ | RGW_OP_TYPE_WRITE | RGW_OP_TYPE_DELETE)

#define RGW_DEFAULT_MAX_BUCKETS 1000

#define RGW_DEFER_TO_BUCKET_ACLS_RECURSE 1
#define RGW_DEFER_TO_BUCKET_ACLS_FULL_CONTROL 2

#define STATUS_CREATED           1900
#define STATUS_ACCEPTED          1901
#define STATUS_NO_CONTENT        1902
#define STATUS_PARTIAL_CONTENT   1903
#define STATUS_REDIRECT          1904
#define STATUS_NO_APPLY          1905
#define STATUS_APPLIED           1906

#define ERR_INVALID_BUCKET_NAME  2000
#define ERR_INVALID_OBJECT_NAME  2001
#define ERR_NO_SUCH_BUCKET       2002
#define ERR_METHOD_NOT_ALLOWED   2003
#define ERR_INVALID_DIGEST       2004
#define ERR_BAD_DIGEST           2005
#define ERR_UNRESOLVABLE_EMAIL   2006
#define ERR_INVALID_PART         2007
#define ERR_INVALID_PART_ORDER   2008
#define ERR_NO_SUCH_UPLOAD       2009
#define ERR_REQUEST_TIMEOUT      2010
#define ERR_LENGTH_REQUIRED      2011
#define ERR_REQUEST_TIME_SKEWED  2012
#define ERR_BUCKET_EXISTS        2013
#define ERR_BAD_URL              2014
#define ERR_PRECONDITION_FAILED  2015
#define ERR_NOT_MODIFIED         2016
#define ERR_INVALID_UTF8         2017
#define ERR_UNPROCESSABLE_ENTITY 2018
#define ERR_TOO_LARGE            2019
#define ERR_TOO_MANY_BUCKETS     2020
#define ERR_INVALID_REQUEST      2021
#define ERR_TOO_SMALL            2022
#define ERR_NOT_FOUND            2023
#define ERR_PERMANENT_REDIRECT   2024
#define ERR_LOCKED               2025
#define ERR_QUOTA_EXCEEDED       2026
#define ERR_SIGNATURE_NO_MATCH   2027
#define ERR_INVALID_ACCESS_KEY   2028
#define ERR_MALFORMED_XML        2029
#define ERR_USER_EXIST           2030
#define ERR_NOT_SLO_MANIFEST     2031
#define ERR_EMAIL_EXIST          2032
#define ERR_KEY_EXIST            2033
#define ERR_INVALID_SECRET_KEY   2034
#define ERR_INVALID_KEY_TYPE     2035
#define ERR_INVALID_CAP          2036
#define ERR_INVALID_TENANT_NAME  2037
#define ERR_WEBSITE_REDIRECT     2038
#define ERR_NO_SUCH_WEBSITE_CONFIGURATION 2039
#define ERR_AMZ_CONTENT_SHA256_MISMATCH 2040
#define ERR_NO_SUCH_LC           2041
#define ERR_NO_SUCH_VERSION      2042
#define ERR_USER_SUSPENDED       2100
#define ERR_INTERNAL_ERROR       2200
#define ERR_NOT_IMPLEMENTED      2201
#define ERR_SERVICE_UNAVAILABLE  2202
#define ERR_ROLE_EXISTS          2203
#define ERR_MALFORMED_DOC        2204
#define ERR_NO_ROLE_FOUND        2205
#define ERR_DELETE_CONFLICT      2206

#ifndef UINT32_MAX
#define UINT32_MAX (0xffffffffu)
#endif

struct req_state;

typedef void *RGWAccessHandle;


/* perf counter */

extern PerfCounters *perfcounter;

extern int rgw_perf_start(CephContext *cct);
extern void rgw_perf_stop(CephContext *cct);

enum {
  l_rgw_first = 15000,
  l_rgw_req,
  l_rgw_failed_req,

  l_rgw_get,
  l_rgw_get_b,
  l_rgw_get_lat,

  l_rgw_put,
  l_rgw_put_b,
  l_rgw_put_lat,

  l_rgw_qlen,
  l_rgw_qactive,

  l_rgw_cache_hit,
  l_rgw_cache_miss,

  l_rgw_keystone_token_cache_hit,
  l_rgw_keystone_token_cache_miss,

  l_rgw_last,
};


 /* size should be the required string size + 1 */
extern int gen_rand_base64(CephContext *cct, char *dest, int size);
extern int gen_rand_alphanumeric(CephContext *cct, char *dest, int size);
extern int gen_rand_alphanumeric_lower(CephContext *cct, char *dest, int size);
extern int gen_rand_alphanumeric_upper(CephContext *cct, char *dest, int size);
extern int gen_rand_alphanumeric_no_underscore(CephContext *cct, char *dest, int size);
extern int gen_rand_alphanumeric_plain(CephContext *cct, char *dest, int size);

extern int gen_rand_alphanumeric_lower(CephContext *cct, string *str, int length);

enum RGWIntentEvent {
  DEL_OBJ = 0,
  DEL_DIR = 1,
};

enum RGWObjCategory {
  RGW_OBJ_CATEGORY_NONE      = 0,
  RGW_OBJ_CATEGORY_MAIN      = 1,
  RGW_OBJ_CATEGORY_SHADOW    = 2,
  RGW_OBJ_CATEGORY_MULTIMETA = 3,
};

/** Store error returns for output at a different point in the program */
struct rgw_err {
  rgw_err();
  void clear();
  bool is_clear() const;
  bool is_err() const;
  friend std::ostream& operator<<(std::ostream& oss, const rgw_err &err);

  int http_ret;
  int ret;
  std::string err_code;
  std::string message;
};



/* Helper class used for RGWHTTPArgs parsing */
class NameVal
{
   string str;
   string name;
   string val;
 public:
    explicit NameVal(string nv) : str(nv) {}

    int parse();

    string& get_name() { return name; }
    string& get_val() { return val; }
};

/** Stores the XML arguments associated with the HTTP request in req_state*/
class RGWHTTPArgs
{
  string str, empty_str;
  map<string, string> val_map;
  map<string, string> sys_val_map;
  map<string, string> sub_resources;
  bool has_resp_modifier;
  bool admin_subresource_added;
 public:
  RGWHTTPArgs() : has_resp_modifier(false), admin_subresource_added(false) {}

  /** Set the arguments; as received */
  void set(string s) {
    has_resp_modifier = false;
    val_map.clear();
    sub_resources.clear();
    str = s;
  }
  /** parse the received arguments */
  int parse();
  void append(const string& name, const string& val);
  /** Get the value for a specific argument parameter */
  const string& get(const string& name, bool *exists = NULL) const;
  int get_bool(const string& name, bool *val, bool *exists);
  int get_bool(const char *name, bool *val, bool *exists);
  void get_bool(const char *name, bool *val, bool def_val);

  /** Get the value for specific system argument parameter */
  std::string sys_get(const string& name, bool *exists = nullptr) const;

  /** see if a parameter is contained in this RGWHTTPArgs */
  bool exists(const char *name) const {
    return (val_map.find(name) != std::end(val_map));
  }
  bool sub_resource_exists(const char *name) const {
    return (sub_resources.find(name) != std::end(sub_resources));
  }
  map<string, string>& get_params() {
    return val_map;
  }
  const std::map<std::string, std::string>& get_sub_resources() const {
    return sub_resources;
  }
  unsigned get_num_params() const {
    return val_map.size();
  }
  bool has_response_modifier() const {
    return has_resp_modifier;
  }
  void set_system() { /* make all system params visible */
    map<string, string>::iterator iter;
    for (iter = sys_val_map.begin(); iter != sys_val_map.end(); ++iter) {
      val_map[iter->first] = iter->second;
    }
  }
  const string& get_str() {
    return str;
  }
};

const char *rgw_conf_get(const map<string, string, ltstr_nocase>& conf_map, const char *name, const char *def_val);
int rgw_conf_get_int(const map<string, string, ltstr_nocase>& conf_map, const char *name, int def_val);
bool rgw_conf_get_bool(const map<string, string, ltstr_nocase>& conf_map, const char *name, bool def_val);

class RGWEnv;

class RGWConf {
  friend class RGWEnv;
protected:
  void init(CephContext *cct, RGWEnv* env);
public:
  RGWConf()
    : enable_ops_log(1),
      enable_usage_log(1),
      defer_to_bucket_acls(0) {
  }

  int enable_ops_log;
  int enable_usage_log;
  uint8_t defer_to_bucket_acls;
};

class RGWEnv {
  std::map<string, string, ltstr_nocase> env_map;
public:
  RGWConf conf;

  void init(CephContext *cct);
  void init(CephContext *cct, char **envp);
  void set(const boost::string_ref& name, const boost::string_ref& val);
  const char *get(const char *name, const char *def_val = NULL);
  int get_int(const char *name, int def_val = 0);
  bool get_bool(const char *name, bool def_val = 0);
  size_t get_size(const char *name, size_t def_val = 0);
  bool exists(const char *name);
  bool exists_prefix(const char *prefix);

  void remove(const char *name);

  std::map<string, string, ltstr_nocase>& get_map() { return env_map; }
};

enum http_op {
  OP_GET,
  OP_PUT,
  OP_DELETE,
  OP_HEAD,
  OP_POST,
  OP_COPY,
  OP_OPTIONS,
  OP_UNKNOWN,
};

enum RGWOpType {
  RGW_OP_UNKNOWN = 0,
  RGW_OP_GET_OBJ,
  RGW_OP_LIST_BUCKETS,
  RGW_OP_STAT_ACCOUNT,
  RGW_OP_LIST_BUCKET,
  RGW_OP_GET_BUCKET_LOGGING,
  RGW_OP_GET_BUCKET_VERSIONING,
  RGW_OP_SET_BUCKET_VERSIONING,
  RGW_OP_GET_BUCKET_WEBSITE,
  RGW_OP_SET_BUCKET_WEBSITE,
  RGW_OP_STAT_BUCKET,
  RGW_OP_CREATE_BUCKET,
  RGW_OP_DELETE_BUCKET,
  RGW_OP_PUT_OBJ,
  RGW_OP_STAT_OBJ,
  RGW_OP_POST_OBJ,
  RGW_OP_PUT_METADATA_ACCOUNT,
  RGW_OP_PUT_METADATA_BUCKET,
  RGW_OP_PUT_METADATA_OBJECT,
  RGW_OP_SET_TEMPURL,
  RGW_OP_DELETE_OBJ,
  RGW_OP_COPY_OBJ,
  RGW_OP_GET_ACLS,
  RGW_OP_PUT_ACLS,
  RGW_OP_GET_CORS,
  RGW_OP_PUT_CORS,
  RGW_OP_DELETE_CORS,
  RGW_OP_OPTIONS_CORS,
  RGW_OP_GET_REQUEST_PAYMENT,
  RGW_OP_SET_REQUEST_PAYMENT,
  RGW_OP_INIT_MULTIPART,
  RGW_OP_COMPLETE_MULTIPART,
  RGW_OP_ABORT_MULTIPART,
  RGW_OP_LIST_MULTIPART,
  RGW_OP_LIST_BUCKET_MULTIPARTS,
  RGW_OP_DELETE_MULTI_OBJ,
  RGW_OP_BULK_DELETE,
  RGW_OP_SET_ATTRS,
  RGW_OP_GET_CROSS_DOMAIN_POLICY,
  RGW_OP_GET_HEALTH_CHECK,
  RGW_OP_GET_INFO,
  RGW_OP_CREATE_ROLE,
  RGW_OP_DELETE_ROLE,
  RGW_OP_GET_ROLE,
  RGW_OP_MODIFY_ROLE,
  RGW_OP_LIST_ROLES,
  RGW_OP_PUT_ROLE_POLICY,
  RGW_OP_GET_ROLE_POLICY,
  RGW_OP_LIST_ROLE_POLICIES,
  RGW_OP_DELETE_ROLE_POLICY,
  RGW_OP_PUT_BUCKET_POLICY,
  RGW_OP_GET_BUCKET_POLICY,
  RGW_OP_DELETE_BUCKET_POLICY,

  /* rgw specific */
  RGW_OP_ADMIN_SET_METADATA,
  RGW_OP_GET_OBJ_LAYOUT,
  RGW_OP_BULK_UPLOAD,
  RGW_OP_METADATA_SEARCH,
  RGW_OP_CONFIG_BUCKET_META_SEARCH,
  RGW_OP_GET_BUCKET_META_SEARCH,
  RGW_OP_DEL_BUCKET_META_SEARCH,
};

class RGWAccessControlPolicy;
class JSONObj;

struct RGWAccessKey {
  string id; // AccessKey
  string key; // SecretKey
  string subuser;

  RGWAccessKey() {}
  RGWAccessKey(std::string _id, std::string _key)
    : id(std::move(_id)), key(std::move(_key)) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 2, bl);
    ::encode(id, bl);
    ::encode(key, bl);
    ::encode(subuser, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
     DECODE_START_LEGACY_COMPAT_LEN_32(2, 2, 2, bl);
     ::decode(id, bl);
     ::decode(key, bl);
     ::decode(subuser, bl);
     DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void dump_plain(Formatter *f) const;
  void dump(Formatter *f, const string& user, bool swift) const;
  static void generate_test_instances(list<RGWAccessKey*>& o);

  void decode_json(JSONObj *obj);
  void decode_json(JSONObj *obj, bool swift);
};
WRITE_CLASS_ENCODER(RGWAccessKey)

struct RGWSubUser {
  string name;
  uint32_t perm_mask;

  RGWSubUser() : perm_mask(0) {}
  void encode(bufferlist& bl) const {
    ENCODE_START(2, 2, bl);
    ::encode(name, bl);
    ::encode(perm_mask, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
     DECODE_START_LEGACY_COMPAT_LEN_32(2, 2, 2, bl);
     ::decode(name, bl);
     ::decode(perm_mask, bl);
     DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void dump(Formatter *f, const string& user) const;
  static void generate_test_instances(list<RGWSubUser*>& o);

  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWSubUser)

class RGWUserCaps
{
  map<string, uint32_t> caps;

  int get_cap(const string& cap, string& type, uint32_t *perm);
  int add_cap(const string& cap);
  int remove_cap(const string& cap);
public:
  static int parse_cap_perm(const string& str, uint32_t *perm);
  int add_from_string(const string& str);
  int remove_from_string(const string& str);

  void encode(bufferlist& bl) const {
     ENCODE_START(1, 1, bl);
     ::encode(caps, bl);
     ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
     DECODE_START(1, bl);
     ::decode(caps, bl);
     DECODE_FINISH(bl);
  }
  int check_cap(const string& cap, uint32_t perm);
  bool is_valid_cap_type(const string& tp);
  void dump(Formatter *f) const;
  void dump(Formatter *f, const char *name) const;

  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWUserCaps)

void encode_json(const char *name, const obj_version& v, Formatter *f);
void encode_json(const char *name, const RGWUserCaps& val, Formatter *f);

void decode_json_obj(obj_version& v, JSONObj *obj);

enum RGWUserSourceType
{
  TYPE_NONE=0,
  TYPE_RGW=1,
  TYPE_KEYSTONE=2,
  TYPE_LDAP=3
};

struct RGWUserInfo
{
  uint64_t auid;
  rgw_user user_id;
  string display_name;
  string user_email;
  map<string, RGWAccessKey> access_keys;
  map<string, RGWAccessKey> swift_keys;
  map<string, RGWSubUser> subusers;
  __u8 suspended;
  int32_t max_buckets;
  uint32_t op_mask;
  RGWUserCaps caps;
  __u8 admin;
  __u8 system;
  string default_placement;
  list<string> placement_tags;
  RGWQuotaInfo bucket_quota;
  map<int, string> temp_url_keys;
  RGWQuotaInfo user_quota;
  uint32_t type;

  RGWUserInfo()
    : auid(0),
      suspended(0),
      max_buckets(RGW_DEFAULT_MAX_BUCKETS),
      op_mask(RGW_OP_TYPE_ALL),
      admin(0),
      system(0),
      type(TYPE_NONE) {
  }

  RGWAccessKey* get_key0() {
    if (access_keys.empty())
      return nullptr;
    else
      return &(access_keys.begin()->second);
  }

  void encode(bufferlist& bl) const {
     ENCODE_START(19, 9, bl);
     ::encode(auid, bl);
     string access_key;
     string secret_key;
     if (!access_keys.empty()) {
       map<string, RGWAccessKey>::const_iterator iter = access_keys.begin();
       const RGWAccessKey& k = iter->second;
       access_key = k.id;
       secret_key = k.key;
     }
     ::encode(access_key, bl);
     ::encode(secret_key, bl);
     ::encode(display_name, bl);
     ::encode(user_email, bl);
     string swift_name;
     string swift_key;
     if (!swift_keys.empty()) {
       map<string, RGWAccessKey>::const_iterator iter = swift_keys.begin();
       const RGWAccessKey& k = iter->second;
       swift_name = k.id;
       swift_key = k.key;
     }
     ::encode(swift_name, bl);
     ::encode(swift_key, bl);
     ::encode(user_id.id, bl);
     ::encode(access_keys, bl);
     ::encode(subusers, bl);
     ::encode(suspended, bl);
     ::encode(swift_keys, bl);
     ::encode(max_buckets, bl);
     ::encode(caps, bl);
     ::encode(op_mask, bl);
     ::encode(system, bl);
     ::encode(default_placement, bl);
     ::encode(placement_tags, bl);
     ::encode(bucket_quota, bl);
     ::encode(temp_url_keys, bl);
     ::encode(user_quota, bl);
     ::encode(user_id.tenant, bl);
     ::encode(admin, bl);
     ::encode(type, bl);
     ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
     DECODE_START_LEGACY_COMPAT_LEN_32(19, 9, 9, bl);
     if (struct_v >= 2) ::decode(auid, bl);
     else auid = CEPH_AUTH_UID_DEFAULT;
     string access_key;
     string secret_key;
    ::decode(access_key, bl);
    ::decode(secret_key, bl);
    if (struct_v < 6) {
      RGWAccessKey k;
      k.id = access_key;
      k.key = secret_key;
      access_keys[access_key] = k;
    }
    ::decode(display_name, bl);
    ::decode(user_email, bl);
    /* We populate swift_keys map later nowadays, but we have to decode. */
    string swift_name;
    string swift_key;
    if (struct_v >= 3) ::decode(swift_name, bl);
    if (struct_v >= 4) ::decode(swift_key, bl);
    if (struct_v >= 5)
      ::decode(user_id.id, bl);
    else
      user_id.id = access_key;
    if (struct_v >= 6) {
      ::decode(access_keys, bl);
      ::decode(subusers, bl);
    }
    suspended = 0;
    if (struct_v >= 7) {
      ::decode(suspended, bl);
    }
    if (struct_v >= 8) {
      ::decode(swift_keys, bl);
    }
    if (struct_v >= 10) {
      ::decode(max_buckets, bl);
    } else {
      max_buckets = RGW_DEFAULT_MAX_BUCKETS;
    }
    if (struct_v >= 11) {
      ::decode(caps, bl);
    }
    if (struct_v >= 12) {
      ::decode(op_mask, bl);
    } else {
      op_mask = RGW_OP_TYPE_ALL;
    }
    if (struct_v >= 13) {
      ::decode(system, bl);
      ::decode(default_placement, bl);
      ::decode(placement_tags, bl); /* tags of allowed placement rules */
    }
    if (struct_v >= 14) {
      ::decode(bucket_quota, bl);
    }
    if (struct_v >= 15) {
     ::decode(temp_url_keys, bl);
    }
    if (struct_v >= 16) {
      ::decode(user_quota, bl);
    }
    if (struct_v >= 17) {
      ::decode(user_id.tenant, bl);
    } else {
      user_id.tenant.clear();
    }
    if (struct_v >= 18) {
      ::decode(admin, bl);
    }
    if (struct_v >= 19) {
      ::decode(type, bl);
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<RGWUserInfo*>& o);

  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWUserInfo)

struct rgw_pool {
  string name;
  string ns;

  rgw_pool() {}
  rgw_pool(const rgw_pool& _p) : name(_p.name), ns(_p.ns) {}
  rgw_pool(const string& _s) {
    from_str(_s);
  }
  rgw_pool(const string& _name, const string& _ns) : name(_name), ns(_ns) {}

  string to_str() const;
  void from_str(const string& s);

  void init(const string& _s) {
    from_str(_s);
  }

  bool empty() const {
    return name.empty();
  }

  int compare(const rgw_pool& p) const {
    int r = name.compare(p.name);
    if (r != 0) {
      return r;
    }
    return ns.compare(p.ns);
  }

  void encode(bufferlist& bl) const {
     ENCODE_START(10, 10, bl);
    ::encode(name, bl);
    ::encode(ns, bl);
    ENCODE_FINISH(bl);
  }

  void decode_from_bucket(bufferlist::iterator& bl);

  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(10, 3, 3, bl);

    ::decode(name, bl);

    if (struct_v < 10) {

    /*
     * note that rgw_pool can be used where rgw_bucket was used before
     * therefore we inherit rgw_bucket's old versions. However, we only
     * need the first field from rgw_bucket. unless we add more fields
     * in which case we'll need to look at struct_v, and check the actual
     * version. Anything older than 10 needs to be treated as old rgw_bucket
     */

    } else {
      ::decode(ns, bl);
    }

    DECODE_FINISH(bl);
  }

  bool operator==(const rgw_pool& p) const {
    return (compare(p) == 0);
  }
  bool operator!=(const rgw_pool& p) const {
    return !(*this == p);
  }
  bool operator<(const rgw_pool& p) const {
    int r = name.compare(p.name);
    if (r == 0) {
      return (ns.compare(p.ns) < 0);
    }
    return (r < 0);
  }
};
WRITE_CLASS_ENCODER(rgw_pool)

struct rgw_data_placement_target {
  rgw_pool data_pool;
  rgw_pool data_extra_pool;
  rgw_pool index_pool;

  rgw_data_placement_target() {}

  rgw_data_placement_target(const rgw_pool& _data_pool, const rgw_pool& _data_extra_pool, const rgw_pool& _index_pool) 
         : data_pool(_data_pool), data_extra_pool(_data_extra_pool), index_pool(_index_pool) {}

  const rgw_pool& get_data_extra_pool() const {
    if (data_extra_pool.empty()) {
      return data_pool;
    }
    return data_extra_pool;
  }

  int compare(const rgw_data_placement_target& t) {
    int c = data_pool.compare(t.data_pool);
    if (c != 0) {
      return c;
    }
    c = data_extra_pool.compare(t.data_extra_pool);
    if (c != 0) {
      return c;
    }
    return index_pool.compare(t.index_pool);
  };

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};

inline ostream& operator<<(ostream& out, const rgw_pool& p) {
  out << p.to_str();
  return out;
}

struct rgw_raw_obj {
  rgw_pool pool;
  std::string oid;
  std::string loc;

  rgw_raw_obj() {}
  rgw_raw_obj(const rgw_pool& _pool, const std::string& _oid) {
    init(_pool, _oid);
  }
  rgw_raw_obj(const rgw_pool& _pool, const std::string& _oid, const string& _loc) : loc(_loc) {
    init(_pool, _oid);
  }

  void init(const rgw_pool& _pool, const std::string& _oid) {
    pool = _pool;
    oid = _oid;
  }

  bool empty() const {
    return oid.empty();
  }

  void encode(bufferlist& bl) const {
     ENCODE_START(6, 6, bl);
    ::encode(pool, bl);
    ::encode(oid, bl);
    ::encode(loc, bl);
    ENCODE_FINISH(bl);
  }

  void decode_from_rgw_obj(bufferlist::iterator& bl);

  void decode(bufferlist::iterator& bl) {
    unsigned ofs = bl.get_off();
    DECODE_START(6, bl);
    if (struct_v < 6) {
      /*
       * this object was encoded as rgw_obj, prior to rgw_raw_obj been split out of it,
       * let's decode it as rgw_obj and convert it
       */
      bl.seek(ofs);
      decode_from_rgw_obj(bl);
      return;
    }
    ::decode(pool, bl);
    ::decode(oid, bl);
    ::decode(loc, bl);
    DECODE_FINISH(bl);
  }

  bool operator<(const rgw_raw_obj& o) const {
    int r = pool.compare(o.pool);
    if (r == 0) {
      r = oid.compare(o.oid);
      if (r == 0) {
        r = loc.compare(o.loc);
      }
    }
    return (r < 0);
  }

  bool operator==(const rgw_raw_obj& o) const {
    return (pool == o.pool && oid == o.oid && loc == o.loc);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_raw_obj)

inline ostream& operator<<(ostream& out, const rgw_raw_obj& o) {
  out << o.pool << ":" << o.oid;
  return out;
}

struct rgw_bucket {
  std::string tenant;
  std::string name;
  std::string marker;
  std::string bucket_id;
  rgw_data_placement_target explicit_placement;

  std::string oid; /*
                    * runtime in-memory only info. If not empty, points to the bucket instance object
                    */

  rgw_bucket() { }
  // cppcheck-suppress noExplicitConstructor
  explicit rgw_bucket(const rgw_user& u, const cls_user_bucket& b) :
    tenant(u.tenant),
    name(b.name),
    marker(b.marker),
    bucket_id(b.bucket_id),
    explicit_placement(b.explicit_placement.data_pool,
                       b.explicit_placement.data_extra_pool,
                       b.explicit_placement.index_pool) {}

  void convert(cls_user_bucket *b) const {
    b->name = name;
    b->marker = marker;
    b->bucket_id = bucket_id;
    b->explicit_placement.data_pool = explicit_placement.data_pool.to_str();
    b->explicit_placement.data_extra_pool = explicit_placement.data_extra_pool.to_str();
    b->explicit_placement.index_pool = explicit_placement.index_pool.to_str();
  }

  void encode(bufferlist& bl) const {
     ENCODE_START(10, 10, bl);
    ::encode(name, bl);
    ::encode(marker, bl);
    ::encode(bucket_id, bl);
    ::encode(tenant, bl);
    bool encode_explicit = !explicit_placement.data_pool.empty();
    ::encode(encode_explicit, bl);
    if (encode_explicit) {
      ::encode(explicit_placement.data_pool, bl);
      ::encode(explicit_placement.data_extra_pool, bl);
      ::encode(explicit_placement.index_pool, bl);
    }
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(10, 3, 3, bl);
    ::decode(name, bl);
    if (struct_v < 10) {
      ::decode(explicit_placement.data_pool.name, bl);
    }
    if (struct_v >= 2) {
      ::decode(marker, bl);
      if (struct_v <= 3) {
        uint64_t id;
        ::decode(id, bl);
        char buf[16];
        snprintf(buf, sizeof(buf), "%llu", (long long)id);
        bucket_id = buf;
      } else {
        ::decode(bucket_id, bl);
      }
    }
    if (struct_v < 10) {
      if (struct_v >= 5) {
        ::decode(explicit_placement.index_pool.name, bl);
      } else {
        explicit_placement.index_pool = explicit_placement.data_pool;
      }
      if (struct_v >= 7) {
        ::decode(explicit_placement.data_extra_pool.name, bl);
      }
    }
    if (struct_v >= 8) {
      ::decode(tenant, bl);
    }
    if (struct_v >= 10) {
      bool decode_explicit = !explicit_placement.data_pool.empty();
      ::decode(decode_explicit, bl);
      if (decode_explicit) {
        ::decode(explicit_placement.data_pool, bl);
        ::decode(explicit_placement.data_extra_pool, bl);
        ::decode(explicit_placement.index_pool, bl);
      }
    }
    DECODE_FINISH(bl);
  }

  // format a key for the bucket/instance. pass delim=0 to skip a field
  std::string get_key(char tenant_delim = '/',
                      char id_delim = ':') const;

  const rgw_pool& get_data_extra_pool() const {
    return explicit_placement.get_data_extra_pool();
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bucket*>& o);

  bool operator<(const rgw_bucket& b) const {
    return name.compare(b.name) < 0;
  }
  bool operator==(const rgw_bucket& b) const {
    return (name == b.name) && (bucket_id == b.bucket_id);
  }
};
WRITE_CLASS_ENCODER(rgw_bucket)

inline ostream& operator<<(ostream& out, const rgw_bucket &b) {
  out << b.name << "[" << b.marker << "])";
  return out;
}

struct rgw_bucket_shard {
  rgw_bucket bucket;
  int shard_id;

  rgw_bucket_shard() : shard_id(-1) {}
  rgw_bucket_shard(const rgw_bucket& _b, int _sid) : bucket(_b), shard_id(_sid) {}

  std::string get_key(char tenant_delim = '/', char id_delim = ':',
                      char shard_delim = ':') const;

  bool operator<(const rgw_bucket_shard& b) const {
    if (bucket < b.bucket) {
      return true;
    }
    if (b.bucket < bucket) {
      return false;
    }
    return shard_id < b.shard_id;
  }
};


struct RGWObjVersionTracker {
  obj_version read_version;
  obj_version write_version;

  obj_version *version_for_read() {
    return &read_version;
  }

  obj_version *version_for_write() {
    if (write_version.ver == 0)
      return NULL;

    return &write_version;
  }

  obj_version *version_for_check() {
    if (read_version.ver == 0)
      return NULL;

    return &read_version;
  }

  void prepare_op_for_read(librados::ObjectReadOperation *op);
  void prepare_op_for_write(librados::ObjectWriteOperation *op);

  void apply_write() {
    read_version = write_version;
    write_version = obj_version();
  }

  void clear() {
    read_version = obj_version();
    write_version = obj_version();
  }

  void generate_new_write_ver(CephContext *cct);
};

enum RGWBucketFlags {
  BUCKET_SUSPENDED = 0x1,
  BUCKET_VERSIONED = 0x2,
  BUCKET_VERSIONS_SUSPENDED = 0x4,
};

enum RGWBucketIndexType {
  RGWBIType_Normal = 0,
  RGWBIType_Indexless = 1,
};

inline ostream& operator<<(ostream& out, const RGWBucketIndexType &index_type) 
{
  switch (index_type) {
    case RGWBIType_Normal:
      return out << "Normal";
    case RGWBIType_Indexless:
      return out << "Indexless";
    default:
      return out << "Unknown";
  }
}

struct RGWBucketInfo
{
  enum BIShardsHashType {
    MOD = 0
  };

  rgw_bucket bucket;
  rgw_user owner;
  uint32_t flags;
  string zonegroup;
  ceph::real_time creation_time;
  string placement_rule;
  bool has_instance_obj;
  RGWObjVersionTracker objv_tracker; /* we don't need to serialize this, for runtime tracking */
  obj_version ep_objv; /* entry point object version, for runtime tracking only */
  RGWQuotaInfo quota;

  // Represents the number of bucket index object shards:
  //   - value of 0 indicates there is no sharding (this is by default before this
  //     feature is implemented).
  //   - value of UINT32_T::MAX indicates this is a blind bucket.
  uint32_t num_shards;

  // Represents the bucket index shard hash type.
  uint8_t bucket_index_shard_hash_type;

  // Represents the shard number for blind bucket.
  const static uint32_t NUM_SHARDS_BLIND_BUCKET;

  bool requester_pays;

  bool has_website;
  RGWBucketWebsiteConf website_conf;

  RGWBucketIndexType index_type;

  bool swift_versioning;
  string swift_ver_location;

  map<string, uint32_t> mdsearch_config;


  void encode(bufferlist& bl) const {
     ENCODE_START(18, 4, bl);
     ::encode(bucket, bl);
     ::encode(owner.id, bl);
     ::encode(flags, bl);
     ::encode(zonegroup, bl);
     uint64_t ct = real_clock::to_time_t(creation_time);
     ::encode(ct, bl);
     ::encode(placement_rule, bl);
     ::encode(has_instance_obj, bl);
     ::encode(quota, bl);
     ::encode(num_shards, bl);
     ::encode(bucket_index_shard_hash_type, bl);
     ::encode(requester_pays, bl);
     ::encode(owner.tenant, bl);
     ::encode(has_website, bl);
     if (has_website) {
       ::encode(website_conf, bl);
     }
     ::encode((uint32_t)index_type, bl);
     ::encode(swift_versioning, bl);
     if (swift_versioning) {
       ::encode(swift_ver_location, bl);
     }
     ::encode(creation_time, bl);
     ::encode(mdsearch_config, bl);
     ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN_32(18, 4, 4, bl);
     ::decode(bucket, bl);
     if (struct_v >= 2) {
       string s;
       ::decode(s, bl);
       owner.from_str(s);
     }
     if (struct_v >= 3)
       ::decode(flags, bl);
     if (struct_v >= 5)
       ::decode(zonegroup, bl);
     if (struct_v >= 6) {
       uint64_t ct;
       ::decode(ct, bl);
       if (struct_v < 17)
	 creation_time = ceph::real_clock::from_time_t((time_t)ct);
     }
     if (struct_v >= 7)
       ::decode(placement_rule, bl);
     if (struct_v >= 8)
       ::decode(has_instance_obj, bl);
     if (struct_v >= 9)
       ::decode(quota, bl);
     if (struct_v >= 10)
       ::decode(num_shards, bl);
     if (struct_v >= 11)
       ::decode(bucket_index_shard_hash_type, bl);
     if (struct_v >= 12)
       ::decode(requester_pays, bl);
     if (struct_v >= 13)
       ::decode(owner.tenant, bl);
     if (struct_v >= 14) {
       ::decode(has_website, bl);
       if (has_website) {
         ::decode(website_conf, bl);
       } else {
         website_conf = RGWBucketWebsiteConf();
       }
     }
     if (struct_v >= 15) {
       uint32_t it;
       ::decode(it, bl);
       index_type = (RGWBucketIndexType)it;
     } else {
       index_type = RGWBIType_Normal;
     }
     swift_versioning = false;
     swift_ver_location.clear();
     if (struct_v >= 16) {
       ::decode(swift_versioning, bl);
       if (swift_versioning) {
         ::decode(swift_ver_location, bl);
       }
     }
     if (struct_v >= 17) {
       ::decode(creation_time, bl);
     }
     if (struct_v >= 18) {
       ::decode(mdsearch_config, bl);
     }
     DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<RGWBucketInfo*>& o);

  void decode_json(JSONObj *obj);

  bool versioned() const { return (flags & BUCKET_VERSIONED) != 0; }
  int versioning_status() { return flags & (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED); }
  bool versioning_enabled() { return versioning_status() == BUCKET_VERSIONED; }

  bool has_swift_versioning() const {
    /* A bucket may be versioned through one mechanism only. */
    return swift_versioning && !versioned();
  }

  RGWBucketInfo() : flags(0), has_instance_obj(false), num_shards(0), bucket_index_shard_hash_type(MOD), requester_pays(false),
                    has_website(false), swift_versioning(false) {}
};
WRITE_CLASS_ENCODER(RGWBucketInfo)

struct RGWBucketEntryPoint
{
  rgw_bucket bucket;
  rgw_user owner;
  ceph::real_time creation_time;
  bool linked;

  bool has_bucket_info;
  RGWBucketInfo old_bucket_info;

  RGWBucketEntryPoint() : linked(false), has_bucket_info(false) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(10, 8, bl);
    ::encode(bucket, bl);
    ::encode(owner.id, bl);
    ::encode(linked, bl);
    uint64_t ctime = (uint64_t)real_clock::to_time_t(creation_time);
    ::encode(ctime, bl);
    ::encode(owner, bl);
    ::encode(creation_time, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    bufferlist::iterator orig_iter = bl;
    DECODE_START_LEGACY_COMPAT_LEN_32(10, 4, 4, bl);
    if (struct_v < 8) {
      /* ouch, old entry, contains the bucket info itself */
      old_bucket_info.decode(orig_iter);
      has_bucket_info = true;
      return;
    }
    has_bucket_info = false;
    ::decode(bucket, bl);
    ::decode(owner.id, bl);
    ::decode(linked, bl);
    uint64_t ctime;
    ::decode(ctime, bl);
    if (struct_v < 10) {
      creation_time = real_clock::from_time_t((time_t)ctime);
    }
    if (struct_v >= 9) {
      ::decode(owner, bl);
    }
    if (struct_v >= 10) {
      ::decode(creation_time, bl);
    }
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWBucketEntryPoint)

struct RGWStorageStats
{
  RGWObjCategory category;
  uint64_t size;
  uint64_t size_rounded;
  uint64_t size_utilized{0}; //< size after compression, encryption
  uint64_t num_objects;

  RGWStorageStats()
    : category(RGW_OBJ_CATEGORY_NONE),
      size(0),
      size_rounded(0),
      num_objects(0) {}

  void dump(Formatter *f) const;
};

class RGWEnv;

/* Namespaced forward declarations. */
namespace rgw {
  namespace auth {
    namespace s3 {
      class RGWGetPolicyV2Extractor;
    }
    class Completer;
  }
  namespace io {
    class BasicClient;
  }
}


struct req_info {
  RGWEnv *env;
  RGWHTTPArgs args;
  map<string, string> x_meta_map;

  string host;
  const char *method;
  string script_uri;
  string request_uri;
  string request_uri_aws4;
  string effective_uri;
  string request_params;
  string domain;

  req_info(CephContext *cct, RGWEnv *_env);
  void rebuild_from(req_info& src);
  void init_meta_info(bool *found_bad_meta);
};

typedef cls_rgw_obj_key rgw_obj_index_key;

struct rgw_obj_key {
  string name;
  string instance;
  string ns;

  rgw_obj_key() {}
  // cppcheck-suppress noExplicitConstructor
  rgw_obj_key(const string& n) : name(n) {}
  rgw_obj_key(const string& n, const string& i) : name(n), instance(i) {}
  rgw_obj_key(const string& n, const string& i, const string& _ns) : name(n), instance(i), ns(_ns) {}

  rgw_obj_key(const rgw_obj_index_key& k) {
    parse_index_key(k.name, &name, &ns);
    instance = k.instance;
  }

  static void parse_index_key(const string& key, string *name, string *ns) {
    if (key[0] != '_') {
      *name = key;
      ns->clear();
      return;
    }
    if (key[1] == '_') {
      *name = key.substr(1);
      ns->clear();
      return;
    }
    ssize_t pos = key.find('_', 1);
    if (pos < 0) {
      /* shouldn't happen, just use key */
      *name = key;
      ns->clear();
      return;
    }

    *name = key.substr(pos + 1);
    *ns = key.substr(1, pos -1);
  }

  void set(const string& n) {
    name = n;
    instance.clear();
    ns.clear();
  }

  void set(const string& n, const string& i) {
    name = n;
    instance = i;
    ns.clear();
  }

  void set(const string& n, const string& i, const string& _ns) {
    name = n;
    instance = i;
    ns = _ns;
  }

  bool set(const rgw_obj_index_key& index_key) {
    if (!parse_raw_oid(index_key.name, this)) {
      return false;
    }
    instance = index_key.instance;
    return true;
  }

  void set_instance(const string& i) {
    instance = i;
  }

  string get_index_key_name() const {
    if (ns.empty()) {
      if (name.size() < 1 || name[0] != '_') {
        return name;
      }
      return string("_") + name;
    };

    char buf[ns.size() + 16];
    snprintf(buf, sizeof(buf), "_%s_", ns.c_str());
    return string(buf) + name;
  };

  void get_index_key(rgw_obj_index_key *key) const {
    key->name = get_index_key_name();
    key->instance = instance;
  }

  string get_loc() const {
    /*
     * For backward compatibility. Older versions used to have object locator on all objects,
     * however, the name was the effective object locator. This had the same effect as not
     * having object locator at all for most objects but the ones that started with underscore as
     * these were escaped.
     */
    if (name[0] == '_' && ns.empty()) {
      return name;
    }

    return string();
  }

  bool empty() const {
    return name.empty();
  }

  bool have_null_instance() const {
    return instance == "null";
  }

  bool have_instance() const {
    return !instance.empty();
  }

  bool need_to_encode_instance() const {
    return have_instance() && !have_null_instance();
  }

  string get_oid() const {
    if (ns.empty() && !need_to_encode_instance()) {
      if (name.size() < 1 || name[0] != '_') {
        return name;
      }
      return string("_") + name;
    }

    string oid = "_";
    oid.append(ns);
    if (need_to_encode_instance()) {
      oid.append(string(":") + instance);
    }
    oid.append("_");
    oid.append(name);
    return oid;
  }

  bool operator==(const rgw_obj_key& k) const {
    return (name.compare(k.name) == 0) &&
           (instance.compare(k.instance) == 0);
  }

  bool operator<(const rgw_obj_key& k) const {
    int r = name.compare(k.name);
    if (r == 0) {
      r = instance.compare(k.instance);
    }
    return (r < 0);
  }

  bool operator<=(const rgw_obj_key& k) const {
    return !(k < *this);
  }

  static void parse_ns_field(string& ns, string& instance) {
    int pos = ns.find(':');
    if (pos >= 0) {
      instance = ns.substr(pos + 1);
      ns = ns.substr(0, pos);
    } else {
      instance.clear();
    }
  }

  static bool parse_raw_oid(const string& oid, rgw_obj_key *key) {
    key->instance.clear();
    key->ns.clear();
    if (oid[0] != '_') {
      key->name = oid;
      return true;
    }

    if (oid.size() >= 2 && oid[1] == '_') {
      key->name = oid.substr(1);
      return true;
    }

    if (oid[0] != '_' || oid.size() < 3) // for namespace, min size would be 3: _x_
      return false;

    int pos = oid.find('_', 1);
    if (pos <= 1) // if it starts with __, it's not in our namespace
      return false;

    key->ns = oid.substr(1, pos - 1);
    parse_ns_field(key->ns, key->instance);

    key->name = oid.substr(pos + 1);
    return true;
  }

  /**
   * Translate a namespace-mangled object name to the user-facing name
   * existing in the given namespace.
   *
   * If the object is part of the given namespace, it returns true
   * and cuts down the name to the unmangled version. If it is not
   * part of the given namespace, it returns false.
   */
  static bool oid_to_key_in_ns(const string& oid, rgw_obj_key *key, const string& ns) {
    string obj_ns;
    bool ret = parse_raw_oid(oid, key);
    if (!ret) {
      return ret;
    }

    return (ns == key->ns);
  }

  /**
   * Given a mangled object name and an empty namespace string, this
   * function extracts the namespace into the string and sets the object
   * name to be the unmangled version.
   *
   * It returns true after successfully doing so, or
   * false if it fails.
   */
  static bool strip_namespace_from_name(string& name, string& ns, string& instance) {
    ns.clear();
    instance.clear();
    if (name[0] != '_') {
      return true;
    }

    size_t pos = name.find('_', 1);
    if (pos == string::npos) {
      return false;
    }

    if (name[1] == '_') {
      name = name.substr(1);
      return true;
    }

    size_t period_pos = name.find('.');
    if (period_pos < pos) {
      return false;
    }

    ns = name.substr(1, pos-1);
    name = name.substr(pos+1, string::npos);

    parse_ns_field(ns, instance);
    return true;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    ::encode(name, bl);
    ::encode(instance, bl);
    ::encode(ns, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    ::decode(name, bl);
    ::decode(instance, bl);
    if (struct_v >= 2) {
      ::decode(ns, bl);
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
};
WRITE_CLASS_ENCODER(rgw_obj_key)

inline ostream& operator<<(ostream& out, const rgw_obj_key &o) {
  if (o.instance.empty()) {
    return out << o.name;
  } else {
    return out << o.name << "[" << o.instance << "]";
  }
}

inline ostream& operator<<(ostream& out, const rgw_obj_index_key &o) {
  if (o.instance.empty()) {
    return out << o.name;
  } else {
    return out << o.name << "[" << o.instance << "]";
  }
}

struct rgw_aws4_auth {
  string date;
  string expires;
  string credential;
  string signedheaders;
  string signed_hdrs;
  string access_key_id;
  string credential_scope;
  string canonical_uri;
  string canonical_qs;
  string canonical_hdrs;
  string signature;
  string new_signature;
  string payload_hash;
  string seed_signature;
  string signing_key;
  char signing_k[CEPH_CRYPTO_HMACSHA256_DIGESTSIZE];
  bufferlist bl;
};

struct req_init_state {
  /* Keeps [[tenant]:]bucket until we parse the token. */
  string url_bucket;
  string src_bucket;
};

/* XXX why don't RGWRequest (or descendants) hold this state? */
class RGWRequest;

#include "rgw_auth.h"

/** Store all the state necessary to complete and respond to an HTTP request*/
struct req_state {
  CephContext *cct;
  rgw::io::BasicClient *cio;
  RGWRequest *req; /// XXX: re-remove??
  http_op op;
  RGWOpType op_type;
  bool content_started;
  int format;
  ceph::Formatter *formatter;
  string decoded_uri;
  string relative_uri;
  const char *length;
  int64_t content_length;
  map<string, string> generic_attrs;
  rgw_err err;
  bool expect_cont;
  bool header_ended;
  uint64_t obj_size;
  bool enable_ops_log;
  bool enable_usage_log;
  uint8_t defer_to_bucket_acls;
  uint32_t perm_mask;

  /* Set once when url_bucket is parsed and not violated thereafter. */
  string account_name;

  string bucket_tenant;
  string bucket_name;

  rgw_bucket bucket;
  rgw_obj_key object;
  string src_tenant_name;
  string src_bucket_name;
  rgw_obj_key src_object;
  ACLOwner bucket_owner;
  ACLOwner owner;

  string zonegroup_name;
  string zonegroup_endpoint;
  string bucket_instance_id;
  int bucket_instance_shard_id;

  string redirect;

  RGWBucketInfo bucket_info;
  map<string, bufferlist> bucket_attrs;
  bool bucket_exists;

  bool has_bad_meta;

  RGWUserInfo *user;

  struct {
    /* TODO(rzarzynski): switch out to the static_ptr for both members. */

    /* Object having the knowledge about an authenticated identity and allowing
     * to apply it during the authorization phase (verify_permission() methods
     * of a given RGWOp). Thus, it bounds authentication and authorization steps
     * through a well-defined interface. For more details, see rgw_auth.h. */
    std::unique_ptr<rgw::auth::Identity> identity;

    std::unique_ptr<rgw::auth::Completer> completer;

    /* A container for credentials of the S3's browser upload. It's necessary
     * because: 1) the ::authenticate() method of auth engines and strategies
     * take req_state only; 2) auth strategies live much longer than RGWOps -
     * there is no way to pass additional data dependencies through ctors. */
    class {
      /* Writer. */
      friend class RGWPostObj_ObjStore_S3;
      /* Reader. */
      friend class rgw::auth::s3::RGWGetPolicyV2Extractor;

      std::string access_key;
      std::string signature;
      ceph::bufferlist encoded_policy;
    } s3_postobj_creds;
  } auth;

  std::unique_ptr<RGWAccessControlPolicy> user_acl;
  RGWAccessControlPolicy *bucket_acl;
  RGWAccessControlPolicy *object_acl;

  rgw::IAM::Environment env;
  boost::optional<rgw::IAM::Policy> iam_policy;

  /* Is the request made by an user marked as a system one?
   * Being system user means we also have the admin status. */
  bool system_request;

  /* aws4 auth support */
  bool aws4_auth_needs_complete;
  bool aws4_auth_streaming_mode;
  unique_ptr<rgw_aws4_auth> aws4_auth;

  string canned_acl;
  bool has_acl_header;
  const char *http_auth;
  bool local_source; /* source is local */

  int prot_flags;

  /* Content-Disposition override for TempURL of Swift API. */
  struct {
    string override;
    string fallback;
  } content_disp;

  string host_id;

  req_info info;
  req_init_state init_state;

  utime_t time;
  void *obj_ctx;
  string dialect;
  string req_id;
  string trans_id;

  req_state(CephContext* _cct, RGWEnv* e, RGWUserInfo* u);
  ~req_state();

  bool is_err() const { return err.is_err(); }
};

void set_req_state_err(struct req_state*, int);
void set_req_state_err(struct req_state*, int, const string&);
void set_req_state_err(struct rgw_err&, int, const int);
void dump(struct req_state*);

/** Store basic data on bucket */
struct RGWBucketEnt {
  rgw_bucket bucket;
  size_t size;
  size_t size_rounded;
  real_time creation_time;
  uint64_t count;

  RGWBucketEnt() : size(0), size_rounded(0), count(0) {}

  explicit RGWBucketEnt(const rgw_user& u, const cls_user_bucket_entry& e)
    : bucket(u, e.bucket),
      size(e.size),
      size_rounded(e.size_rounded),
      creation_time(e.creation_time),
      count(e.count) {
  }

  void convert(cls_user_bucket_entry *b) const {
    bucket.convert(&b->bucket);
    b->size = size;
    b->size_rounded = size_rounded;
    b->creation_time = creation_time;
    b->count = count;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(6, 5, bl);
    uint64_t s = size;
    __u32 mt = ceph::real_clock::to_time_t(creation_time);
    string empty_str;  // originally had the bucket name here, but we encode bucket later
    ::encode(empty_str, bl);
    ::encode(s, bl);
    ::encode(mt, bl);
    ::encode(count, bl);
    ::encode(bucket, bl);
    s = size_rounded;
    ::encode(s, bl);
    ::encode(creation_time, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(6, 5, 5, bl);
    __u32 mt;
    uint64_t s;
    string empty_str;  // backward compatibility
    ::decode(empty_str, bl);
    ::decode(s, bl);
    ::decode(mt, bl);
    size = s;
    if (struct_v < 6) {
      creation_time = ceph::real_clock::from_time_t(mt);
    }
    if (struct_v >= 2)
      ::decode(count, bl);
    if (struct_v >= 3)
      ::decode(bucket, bl);
    if (struct_v >= 4)
      ::decode(s, bl);
    size_rounded = s;
    if (struct_v >= 6)
      ::decode(creation_time, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<RGWBucketEnt*>& o);
};
WRITE_CLASS_ENCODER(RGWBucketEnt)

struct rgw_obj {
  rgw_bucket bucket;
  rgw_obj_key key;

  bool in_extra_data{false}; /* in-memory only member, does not serialize */

  // Represents the hash index source for this object once it is set (non-empty)
  std::string index_hash_source;

  rgw_obj() {}
  rgw_obj(const rgw_bucket& b, const std::string& name) : bucket(b), key(name) {}
  rgw_obj(const rgw_bucket& b, const rgw_obj_key& k) : bucket(b), key(k) {}
  rgw_obj(const rgw_bucket& b, const rgw_obj_index_key& k) : bucket(b), key(k) {}

  void init(const rgw_bucket& b, const std::string& name) {
    bucket = b;
    key.set(name);
  }
  void init(const rgw_bucket& b, const std::string& name, const string& i, const string& n) {
    bucket = b;
    key.set(name, i, n);
  }
  void init_ns(const rgw_bucket& b, const std::string& name, const string& n) {
    bucket = b;
    key.name = name;
    key.instance.clear();
    key.ns = n;
  }

  bool empty() const {
    return key.empty();
  }

  void set_key(const rgw_obj_key& k) {
    key = k;
  }

  string get_oid() const {
    return key.get_oid();
  }

  const string& get_hash_object() const {
    return index_hash_source.empty() ? key.name : index_hash_source;
  }

  void set_in_extra_data(bool val) {
    in_extra_data = val;
  }

  bool is_in_extra_data() const {
    return in_extra_data;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(6, 6, bl);
    ::encode(bucket, bl);
    ::encode(key.ns, bl);
    ::encode(key.name, bl);
    ::encode(key.instance, bl);
//    ::encode(placement_id, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(6, 3, 3, bl);
    if (struct_v < 6) {
      string s;
      ::decode(bucket.name, bl); /* bucket.name */
      ::decode(s, bl); /* loc */
      ::decode(key.ns, bl);
      ::decode(key.name, bl);
      if (struct_v >= 2)
        ::decode(bucket, bl);
      if (struct_v >= 4)
        ::decode(key.instance, bl);
      if (key.ns.empty() && key.instance.empty()) {
        if (key.name[0] == '_') {
          key.name = key.name.substr(1);
        }
      } else {
        if (struct_v >= 5) {
          ::decode(key.name, bl);
        } else {
          ssize_t pos = key.name.find('_', 1);
          if (pos < 0) {
            throw buffer::error();
          }
          key.name = key.name.substr(pos);
        }
      }
    } else {
      ::decode(bucket, bl);
      ::decode(key.ns, bl);
      ::decode(key.name, bl);
      ::decode(key.instance, bl);
//      ::decode(placement_id, bl);
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<rgw_obj*>& o);

  bool operator==(const rgw_obj& o) const {
    return (key == o.key) &&
           (bucket == o.bucket);
  }
  bool operator<(const rgw_obj& o) const {
    int r = key.name.compare(o.key.name);
    if (r == 0) {
      r = bucket.bucket_id.compare(o.bucket.bucket_id); /* not comparing bucket.name, if bucket_id is equal so will be bucket.name */
      if (r == 0) {
        r = key.ns.compare(o.key.ns);
        if (r == 0) {
          r = key.instance.compare(o.key.instance);
        }
      }
    }

    return (r < 0);
  }

  const rgw_pool& get_explicit_data_pool() {
    if (!in_extra_data || bucket.explicit_placement.data_extra_pool.empty()) {
      return bucket.explicit_placement.data_pool;
    }
    return bucket.explicit_placement.data_extra_pool;
  }
};
WRITE_CLASS_ENCODER(rgw_obj)

struct rgw_cache_entry_info {
  string cache_locator;
  uint64_t gen;

  rgw_cache_entry_info() : gen(0) {}
};

inline ostream& operator<<(ostream& out, const rgw_obj &o) {
  return out << o.bucket.name << ":" << o.get_oid();
}

static inline void buf_to_hex(const unsigned char *buf, int len, char *str)
{
  int i;
  str[0] = '\0';
  for (i = 0; i < len; i++) {
    sprintf(&str[i*2], "%02x", (int)buf[i]);
  }
}

static inline int hexdigit(char c)
{
  if (c >= '0' && c <= '9')
    return (c - '0');
  c = toupper(c);
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 0xa;
  return -EINVAL;
}

static inline int hex_to_buf(const char *hex, char *buf, int len)
{
  int i = 0;
  const char *p = hex;
  while (*p) {
    if (i >= len)
      return -EINVAL;
    buf[i] = 0;
    int d = hexdigit(*p);
    if (d < 0)
      return d;
    buf[i] = d << 4;
    p++;
    if (!*p)
      return -EINVAL;
    d = hexdigit(*p);
    if (d < 0)
      return d;
    buf[i] += d;
    i++;
    p++;
  }
  return i;
}

static inline int rgw_str_to_bool(const char *s, int def_val)
{
  if (!s)
    return def_val;

  return (strcasecmp(s, "on") == 0 ||
          strcasecmp(s, "yes") == 0 ||
          strcasecmp(s, "1") == 0);
}

static inline void append_rand_alpha(CephContext *cct, const string& src, string& dest, int len)
{
  dest = src;
  char buf[len + 1];
  gen_rand_alphanumeric(cct, buf, len);
  dest.append("_");
  dest.append(buf);
}

static inline const char *rgw_obj_category_name(RGWObjCategory category)
{
  switch (category) {
  case RGW_OBJ_CATEGORY_NONE:
    return "rgw.none";
  case RGW_OBJ_CATEGORY_MAIN:
    return "rgw.main";
  case RGW_OBJ_CATEGORY_SHADOW:
    return "rgw.shadow";
  case RGW_OBJ_CATEGORY_MULTIMETA:
    return "rgw.multimeta";
  }

  return "unknown";
}

static inline uint64_t rgw_rounded_kb(uint64_t bytes)
{
  return (bytes + 1023) / 1024;
}

static inline uint64_t rgw_rounded_objsize(uint64_t bytes)
{
  return ((bytes + 4095) & ~4095);
}

static inline uint64_t rgw_rounded_objsize_kb(uint64_t bytes)
{
  return ((bytes + 4095) & ~4095) / 1024;
}

extern string rgw_string_unquote(const string& s);
extern void parse_csv_string(const string& ival, vector<string>& ovals);
extern int parse_key_value(string& in_str, string& key, string& val);
extern int parse_key_value(string& in_str, const char *delim, string& key, string& val);
/** time parsing */
extern int parse_time(const char *time_str, real_time *time);
extern bool parse_rfc2616(const char *s, struct tm *t);
extern bool parse_iso8601(const char *s, struct tm *t, uint32_t *pns = NULL, bool extended_format = true);
extern string rgw_trim_whitespace(const string& src);
extern boost::string_ref rgw_trim_whitespace(const boost::string_ref& src);
extern string rgw_trim_quotes(const string& val);

extern void rgw_to_iso8601(const real_time& t, char *dest, int buf_size);
extern void rgw_to_iso8601(const real_time& t, string *dest);

/** Check if the req_state's user has the necessary permissions
 * to do the requested action */
bool verify_user_permission(struct req_state * const s,
                            RGWAccessControlPolicy * const user_acl,
                            const int perm);
bool verify_user_permission(struct req_state * const s,
                            const int perm);
bool verify_bucket_permission(
  struct req_state * const s,
  const rgw_bucket& bucket,
  RGWAccessControlPolicy * const user_acl,
  RGWAccessControlPolicy * const bucket_acl,
  const boost::optional<rgw::IAM::Policy>& bucket_policy,
  const uint64_t op);
bool verify_bucket_permission(struct req_state * const s, const uint64_t op);
bool verify_bucket_permission_no_policy(
  struct req_state * const s,
  RGWAccessControlPolicy * const user_acl,
  RGWAccessControlPolicy * const bucket_acl,
  const int perm);
bool verify_bucket_permission_no_policy(struct req_state * const s,
					const int perm);
extern bool verify_object_permission(
  struct req_state * const s,
  const rgw_obj& obj,
  RGWAccessControlPolicy * const user_acl,
  RGWAccessControlPolicy * const bucket_acl,
  RGWAccessControlPolicy * const object_acl,
  const boost::optional<rgw::IAM::Policy>& bucket_policy,
  const uint64_t op);
extern bool verify_object_permission(struct req_state *s, uint64_t op);
extern bool verify_object_permission_no_policy(
  struct req_state * const s,
  RGWAccessControlPolicy * const user_acl,
  RGWAccessControlPolicy * const bucket_acl,
  RGWAccessControlPolicy * const object_acl,
  int perm);
extern bool verify_object_permission_no_policy(struct req_state *s,
					       int perm);
/** Convert an input URL into a sane object name
 * by converting %-escaped strings into characters, etc*/
extern void rgw_uri_escape_char(char c, string& dst);
extern bool url_decode(const std::string& src_str,
                       std::string& dest_str,
                       bool in_query = false);
extern void url_encode(const std::string& src,
                       string& dst);
extern std::string url_encode(const std::string& src);

/* destination should be CEPH_CRYPTO_HMACSHA1_DIGESTSIZE bytes long */
extern void calc_hmac_sha1(const char *key, int key_len,
                          const char *msg, int msg_len, char *dest);
/* destination should be CEPH_CRYPTO_HMACSHA256_DIGESTSIZE bytes long */
extern void calc_hmac_sha256(const char *key, int key_len, const char *msg, int msg_len, char *dest);
extern void calc_hash_sha256(const char *msg, int len, string& dest);
extern void calc_hash_sha256(const string& msg, string& dest);

using ceph::crypto::SHA256;
extern SHA256* calc_hash_sha256_open_stream();
extern void    calc_hash_sha256_update_stream(SHA256 *hash, const char *msg, int len);
extern string  calc_hash_sha256_close_stream(SHA256 **hash);

extern int rgw_parse_op_type_list(const string& str, uint32_t *perm);

namespace {
  constexpr uint32_t MATCH_POLICY_ACTION = 0x01;
  constexpr uint32_t MATCH_POLICY_RESOURCE = 0x02;
  constexpr uint32_t MATCH_POLICY_ARN = 0x04;
  constexpr uint32_t MATCH_POLICY_STRING = 0x08;
}

int match(const std::string& pattern, const std::string& input, uint32_t flag);
#endif
