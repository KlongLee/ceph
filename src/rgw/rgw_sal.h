// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#pragma once

#include "rgw_user.h"
#include "rgw_obj_manifest.h"

class RGWGetDataCB;
struct RGWObjState;
class RGWAccessListFilter;

struct RGWUsageIter {
  string read_iter;
  uint32_t index;

  RGWUsageIter() : index(0) {}
};

namespace rgw { namespace sal {

#define RGW_SAL_VERSION 1

class RGWUser;
class RGWBucket;
class RGWObject;
class RGWBucketList;

enum AttrsMod {
  ATTRSMOD_NONE    = 0,
  ATTRSMOD_REPLACE = 1,
  ATTRSMOD_MERGE   = 2
};

using RGWAttrs = std::map<std::string, ceph::buffer::list>;

class RGWStore : public DoutPrefixProvider {
  public:
    RGWStore() {}
    virtual ~RGWStore() = default;

    virtual std::unique_ptr<RGWUser> get_user(const rgw_user& u) = 0;
    virtual std::unique_ptr<RGWObject> get_object(const rgw_obj_key& k) = 0;
    virtual int get_bucket(RGWUser* u, const rgw_bucket& b, std::unique_ptr<RGWBucket>* bucket) = 0;
    virtual int get_bucket(RGWUser* u, const RGWBucketInfo& i, std::unique_ptr<RGWBucket>* bucket) = 0;
    virtual int get_bucket(RGWUser* u, const std::string& tenant, const std::string&name, std::unique_ptr<RGWBucket>* bucket) = 0;
    virtual int create_bucket(RGWUser& u, const rgw_bucket& b,
                            const std::string& zonegroup_id,
                            rgw_placement_rule& placement_rule,
                            std::string& swift_ver_location,
                            const RGWQuotaInfo * pquota_info,
                            const RGWAccessControlPolicy& policy,
			    RGWAttrs& attrs,
                            RGWBucketInfo& info,
                            obj_version& ep_objv,
			    bool exclusive,
			    bool obj_lock_enabled,
			    bool *existed,
			    req_info& req_info,
			    std::unique_ptr<RGWBucket>* bucket) = 0;
    virtual RGWBucketList* list_buckets(void) = 0;
    virtual bool is_meta_master() = 0;
    virtual int forward_request_to_master(RGWUser* user, obj_version *objv,
				  bufferlist& in_data, JSONParser *jp, req_info& info) = 0;
    virtual int defer_gc(RGWObjectCtx *rctx, RGWBucket* bucket, RGWObject* obj,
			 optional_yield y) = 0;
    virtual const RGWZoneGroup& get_zonegroup() = 0;
    virtual int get_zonegroup(const string& id, RGWZoneGroup& zonegroup) = 0;

    virtual void finalize(void)=0;

    virtual CephContext *ctx(void)=0;
};

class RGWUser {
  protected:
    RGWUserInfo info;

  public:
    RGWUser() : info() {}
    RGWUser(const rgw_user& _u) : info() { info.user_id = _u; }
    RGWUser(const RGWUserInfo& _i) : info(_i) {}
    virtual ~RGWUser() = default;

    virtual int list_buckets(const std::string& marker, const std::string& end_marker,
			     uint64_t max, bool need_stats, RGWBucketList& buckets) = 0;
    virtual RGWBucket* create_bucket(rgw_bucket& bucket, ceph::real_time creation_time) = 0;
    friend class RGWBucket;
    virtual std::string& get_display_name() { return info.display_name; }

    std::string& get_tenant() { return info.user_id.tenant; }
    const rgw_user& get_id() const { return info.user_id; }
    uint32_t get_type() const { return info.type; }
    int32_t get_max_buckets() const { return info.max_buckets; }
    const RGWUserCaps& get_caps() const { return info.caps; }

    /* Placeholders */
    virtual int load_by_id(optional_yield y) = 0;

    /* dang temporary; will be removed when User is complete */
    rgw_user& get_user() { return info.user_id; }
    RGWUserInfo& get_info() { return info; }

    friend inline ostream& operator<<(ostream& out, const RGWUser& u) {
      out << u.info.user_id;
      return out;
    }

    friend inline ostream& operator<<(ostream& out, const RGWUser* u) {
      if (!u)
	out << "<NULL>";
      else
	out << u->info.user_id;
      return out;
    }

    friend inline ostream& operator<<(ostream& out, const std::unique_ptr<RGWUser>& p) {
      out << p.get();
      return out;
    }

};

class RGWBucket {
  protected:
    RGWBucketEnt ent;
    RGWBucketInfo info;
    RGWUser* owner;
    RGWAttrs attrs;
    obj_version bucket_version;
    ceph::real_time mtime;

  public:

    struct ListParams {
      std::string prefix;
      std::string delim;
      rgw_obj_key marker;
      rgw_obj_key end_marker;
      std::string ns;
      bool enforce_ns{true};
      RGWAccessListFilter *filter{nullptr};
      bool list_versions{false};
      bool allow_unordered{false};
      int shard_id{0};
    };
    struct ListResults {
      vector<rgw_bucket_dir_entry> objs;
      map<std::string, bool> common_prefixes;
      bool is_truncated;
      rgw_obj_key next_marker;
    };

    RGWBucket() : ent(), info(), owner(nullptr), attrs(), bucket_version() {}
    RGWBucket(const rgw_bucket& _b) :
      ent(), info(), owner(nullptr), attrs(), bucket_version() { ent.bucket = _b; info.bucket = _b; }
    RGWBucket(const RGWBucketEnt& _e) :
      ent(_e), info(), owner(nullptr), attrs(), bucket_version() { info.bucket = ent.bucket; info.placement_rule = ent.placement_rule; }
    RGWBucket(const RGWBucketInfo& _i) :
      ent(), info(_i), owner(nullptr), attrs(), bucket_version() {ent.bucket = info.bucket; ent.placement_rule = info.placement_rule; }
    RGWBucket(const rgw_bucket& _b, RGWUser* _u) :
      ent(), info(), owner(_u), attrs(), bucket_version() { ent.bucket = _b; info.bucket = _b; }
    RGWBucket(const RGWBucketEnt& _e, RGWUser* _u) :
      ent(_e), info(), owner(_u), attrs(), bucket_version() { info.bucket = ent.bucket; info.placement_rule = ent.placement_rule; }
    RGWBucket(const RGWBucketInfo& _i, RGWUser* _u) :
      ent(), info(_i), owner(_u), attrs(), bucket_version() { ent.bucket = info.bucket;  ent.placement_rule = info.placement_rule;}
    virtual ~RGWBucket() = default;

    virtual int load_by_name(const std::string& tenant, const std::string& bucket_name, const std::string bucket_instance_id, RGWSysObjectCtx *rctx, optional_yield y) = 0;
    virtual std::unique_ptr<RGWObject> get_object(const rgw_obj_key& key) = 0;
    virtual int list(ListParams&, int, ListResults&, optional_yield y) = 0;
    virtual RGWObject* create_object(const rgw_obj_key& key /* Attributes */) = 0;
    virtual RGWAttrs& get_attrs(void) { return attrs; }
    virtual int set_attrs(RGWAttrs a) { attrs = a; return 0; }
    virtual int remove_bucket(bool delete_children, std::string prefix, std::string delimiter, bool forward_to_master, req_info* req_info, optional_yield y) = 0;
    virtual RGWAccessControlPolicy& get_acl(void) = 0;
    virtual int set_acl(RGWAccessControlPolicy& acl, optional_yield y) = 0;
    virtual int get_bucket_info(optional_yield y) = 0;
    virtual int get_bucket_stats(RGWBucketInfo& bucket_info, int shard_id,
				 std::string *bucket_ver, std::string *master_ver,
				 std::map<RGWObjCategory, RGWStorageStats>& stats,
				 std::string *max_marker = nullptr,
				 bool *syncstopped = nullptr) = 0;
    virtual int read_bucket_stats(optional_yield y) = 0;
    virtual int sync_user_stats() = 0;
    virtual int update_container_stats(void) = 0;
    virtual int check_bucket_shards(void) = 0;
    virtual int link(RGWUser* new_user, optional_yield y) = 0;
    virtual int unlink(RGWUser* new_user, optional_yield y) = 0;
    virtual int chown(RGWUser* new_user, RGWUser* old_user, optional_yield y) = 0;
    virtual int put_instance_info(bool exclusive, ceph::real_time mtime) = 0;
    virtual bool is_owner(RGWUser* user) = 0;
    virtual int check_empty(optional_yield y) = 0;
    virtual int check_quota(RGWQuotaInfo& user_quota, RGWQuotaInfo& bucket_quota, uint64_t obj_size, bool check_size_only = false) = 0;
    virtual int set_instance_attrs(RGWAttrs& attrs, optional_yield y) = 0;
    virtual int try_refresh_info(ceph::real_time *pmtime) = 0;
    virtual int read_usage(uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
			   bool *is_truncated, RGWUsageIter& usage_iter,
			   map<rgw_user_bucket, rgw_usage_log_entry>& usage) = 0;

    bool empty() const { return info.bucket.name.empty(); }
    const std::string& get_name() const { return info.bucket.name; }
    const std::string& get_tenant() const { return info.bucket.tenant; }
    const std::string& get_marker() const { return info.bucket.marker; }
    const std::string& get_bucket_id() const { return info.bucket.bucket_id; }
    size_t get_size() const { return ent.size; }
    size_t get_size_rounded() const { return ent.size_rounded; }
    uint64_t get_count() const { return ent.count; }
    rgw_placement_rule& get_placement_rule() { return info.placement_rule; }
    ceph::real_time& get_creation_time() { return info.creation_time; }
    ceph::real_time& get_modification_time() { return mtime; }
    obj_version& get_version() { return bucket_version; }
    void set_version(obj_version &ver) { bucket_version = ver; }
    bool versioned() { return info.versioned(); }
    bool versioning_enabled() { return info.versioning_enabled(); }

    void convert(cls_user_bucket_entry *b) const {
      ent.convert(b);
    }

    static bool empty(RGWBucket* b) { return (!b || b->empty()); }
    virtual std::unique_ptr<RGWBucket> clone() = 0;

    /* dang - This is temporary, until the API is completed */
    rgw_bucket& get_key() { return info.bucket; }
    RGWBucketInfo& get_info() { return info; }

    friend inline ostream& operator<<(ostream& out, const RGWBucket& b) {
      out << b.info.bucket;
      return out;
    }

    friend inline ostream& operator<<(ostream& out, const RGWBucket* b) {
      if (!b)
	out << "<NULL>";
      else
	out << b->info.bucket;
      return out;
    }

    friend inline ostream& operator<<(ostream& out, const std::unique_ptr<RGWBucket>& p) {
      out << p.get();
      return out;
    }


    friend class RGWBucketList;
  protected:
    virtual void set_ent(RGWBucketEnt& _ent) { ent = _ent; info.bucket = ent.bucket; info.placement_rule = ent.placement_rule; }
};


class RGWBucketList {
  std::map<std::string, std::unique_ptr<RGWBucket>> buckets;
  bool truncated;

public:
  RGWBucketList() : buckets(), truncated(false) {}
  RGWBucketList(RGWBucketList&& _bl) :
    buckets(std::move(_bl.buckets)),
    truncated(_bl.truncated)
    { }
  RGWBucketList& operator=(const RGWBucketList&) = delete;
  RGWBucketList& operator=(RGWBucketList&& _bl) {
    for (auto& ent : _bl.buckets) {
      buckets.emplace(ent.first, std::move(ent.second));
    }
    truncated = _bl.truncated;
    return *this;
  };

  map<std::string, std::unique_ptr<RGWBucket>>& get_buckets() { return buckets; }
  bool is_truncated(void) const { return truncated; }
  void set_truncated(bool trunc) { truncated = trunc; }
  void add(std::unique_ptr<RGWBucket> bucket) {
    buckets.emplace(bucket->info.bucket.name, std::move(bucket));
  }
  size_t count() const { return buckets.size(); }
  void clear(void) {
    buckets.clear();
    truncated = false;
  }
};

class RGWObject {
  protected:
    rgw_obj_key key;
    RGWBucket* bucket;
    std::string index_hash_source;
    uint64_t obj_size;
    RGWAttrs attrs;
    ceph::real_time mtime;
    bool delete_marker{false};
    bool in_extra_data{false};

  public:

    struct ReadOp {
      struct Params {
        const ceph::real_time *mod_ptr{nullptr};
        const ceph::real_time *unmod_ptr{nullptr};
        bool high_precision_time{false};
        uint32_t mod_zone_id{0};
        uint64_t mod_pg_ver{0};
        const char *if_match{nullptr};
        const char *if_nomatch{nullptr};
        ceph::real_time *lastmod{nullptr};
        rgw_obj *target_obj{nullptr}; // XXX dang remove?
      } params;

      struct Result {
        rgw_raw_obj head_obj;

        Result() : head_obj() {}
      } result;

      virtual ~ReadOp() = default;

      virtual int prepare(optional_yield y) = 0;
      virtual int read(int64_t ofs, int64_t end, bufferlist& bl, optional_yield y) = 0;
      virtual int iterate(int64_t ofs, int64_t end, RGWGetDataCB *cb, optional_yield y) = 0;
      virtual int get_manifest(RGWObjManifest **pmanifest, optional_yield y) = 0;
      virtual int get_attr(const char *name, bufferlist& dest, optional_yield y) = 0;
    };

    RGWObject()
      : key(),
      bucket(nullptr),
      index_hash_source(),
      obj_size(),
      attrs(),
      mtime() {}
    RGWObject(const rgw_obj_key& _k)
      : key(_k),
      bucket(),
      index_hash_source(),
      obj_size(),
      attrs(),
      mtime() {}
    RGWObject(const rgw_obj_key& _k, RGWBucket* _b)
      : key(_k),
      bucket(_b),
      index_hash_source(),
      obj_size(),
      attrs(),
      mtime() {}
    RGWObject(RGWObject& _o) = default;

    virtual ~RGWObject() = default;

    virtual int read(off_t offset, off_t length, std::iostream& stream) = 0;
    virtual int write(off_t offset, off_t length, std::iostream& stream) = 0;
    virtual int delete_object(RGWObjectCtx* obj_ctx, ACLOwner obj_owner,
			      ACLOwner bucket_owner, ceph::real_time unmod_since,
			      bool high_precision_time, uint64_t epoch,
			      std::string& version_id,optional_yield y) = 0;
    virtual int copy_object(RGWObjectCtx& obj_ctx, RGWUser* user,
               req_info *info, const rgw_zone_id& source_zone,
               rgw::sal::RGWObject* dest_object, rgw::sal::RGWBucket* dest_bucket,
               rgw::sal::RGWBucket* src_bucket,
               const rgw_placement_rule& dest_placement,
               ceph::real_time *src_mtime, ceph::real_time *mtime,
               const ceph::real_time *mod_ptr, const ceph::real_time *unmod_ptr,
               bool high_precision_time,
               const char *if_match, const char *if_nomatch,
               AttrsMod attrs_mod, bool copy_if_newer, RGWAttrs& attrs,
               RGWObjCategory category, uint64_t olh_epoch,
	       boost::optional<ceph::real_time> delete_at,
               string *version_id, string *tag, string *etag,
               void (*progress_cb)(off_t, void *), void *progress_data,
               const DoutPrefixProvider *dpp, optional_yield y) = 0;
    virtual RGWAccessControlPolicy& get_acl(void) = 0;
    virtual int set_acl(const RGWAccessControlPolicy& acl) = 0;
    virtual void set_atomic(RGWObjectCtx *rctx) const = 0;
    virtual void set_prefetch_data(RGWObjectCtx *rctx) = 0;

    bool empty() const { return key.empty(); }
    const std::string &get_name() const { return key.name; }

    virtual int get_obj_state(RGWObjectCtx *rctx, RGWBucket& bucket, RGWObjState **state, optional_yield y, bool follow_olh = false) = 0;
    virtual int set_obj_attrs(RGWObjectCtx* rctx, RGWAttrs* setattrs, RGWAttrs* delattrs, optional_yield y, rgw_obj* target_obj = NULL) = 0;
    virtual int get_obj_attrs(RGWObjectCtx *rctx, optional_yield y, rgw_obj* target_obj = NULL) = 0;
    virtual int modify_obj_attrs(RGWObjectCtx *rctx, const char *attr_name, bufferlist& attr_val, optional_yield y) = 0;
    virtual int delete_obj_attrs(RGWObjectCtx *rctx, const char *attr_name, optional_yield y) = 0;
    virtual int copy_obj_data(RGWObjectCtx& rctx, RGWBucket* dest_bucket, RGWObject* dest_obj, uint16_t olh_epoch, std::string* petag, const DoutPrefixProvider *dpp, optional_yield y) = 0;
    virtual bool is_expired() = 0;

    RGWAttrs& get_attrs(void) { return attrs; }
    ceph::real_time get_mtime(void) const { return mtime; }
    uint64_t get_obj_size(void) const { return obj_size; }
    RGWBucket* get_bucket(void) const { return bucket; }
    void set_bucket(RGWBucket* b) { bucket = b; }
    std::string get_hash_source(void) { return index_hash_source; }
    void set_hash_source(std::string s) { index_hash_source = s; }
    std::string get_oid(void) const { return key.get_oid(); }
    bool get_delete_marker(void) { return delete_marker; }
    bool get_in_extra_data(void) { return in_extra_data; }
    void set_in_extra_data(bool i) { in_extra_data = i; }
    int range_to_ofs(uint64_t obj_size, int64_t &ofs, int64_t &end);

    /* OPs */
    virtual std::unique_ptr<ReadOp> get_read_op(RGWObjectCtx *) = 0;

    /* OMAP */
    virtual int omap_get_vals_by_keys(const std::string& oid,
			      const std::set<std::string>& keys,
			      RGWAttrs *vals) = 0;

    static bool empty(RGWObject* o) { return (!o || o->empty()); }
    virtual std::unique_ptr<RGWObject> clone() = 0;

    /* dang - Not sure if we want this, but it simplifies things a lot */
    void set_obj_size(uint64_t s) { obj_size = s; }
    virtual void set_name(const std::string& n) { key = n; }
    virtual void set_key(const rgw_obj_key& k) { key = k; }
    virtual rgw_obj get_obj(void) const {
      rgw_obj obj(bucket->get_key(), key);
      obj.set_in_extra_data(in_extra_data);
      return obj;
    }
    virtual void gen_rand_obj_instance_name() = 0;

    /* dang - This is temporary, until the API is completed */
    rgw_obj_key& get_key() { return key; }
    void set_instance(const std::string &i) { key.set_instance(i); }
    const std::string &get_instance() const { return key.instance; }
    bool have_instance(void) { return key.have_instance(); }

    friend inline ostream& operator<<(ostream& out, const RGWObject& o) {
      out << o.key;
      return out;
    }
    friend inline ostream& operator<<(ostream& out, const RGWObject* o) {
      if (!o)
	out << "<NULL>";
      else
	out << o->key;
      return out;
    }
    friend inline ostream& operator<<(ostream& out, const std::unique_ptr<RGWObject>& p) {
      out << p.get();
      return out;
    }
};

} } // namespace rgw::sal

