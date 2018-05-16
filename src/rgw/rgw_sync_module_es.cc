// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_common.h"
#include "rgw_coroutine.h"
#include "rgw_sync_module.h"
#include "rgw_data_sync.h"
#include "rgw_sync_module_es.h"
#include "rgw_sync_module_es_rest.h"
#include "rgw_rest_conn.h"
#include "rgw_cr_rest.h"
#include "rgw_op.h"
#include "rgw_es_query.h"
#include "rgw_zone.h"

#include "services/svc_zone.h"

#include "include/str_list.h"

#include <boost/asio/yield.hpp>

#define dout_subsys ceph_subsys_rgw


/*
 * whitelist utility. Config string is a list of entries, where an entry is either an item,
 * a prefix, or a suffix. An item would be the name of the entity that we'd look up,
 * a prefix would be a string ending with an asterisk, a suffix would be a string starting
 * with an asterisk. For example:
 *
 *      bucket1, bucket2, foo*, *bar
 */
class ItemList {
  bool approve_all{false};

  set<string> entries;
  set<string> prefixes;
  set<string> suffixes;

  void parse(const string& str) {
    list<string> l;

    get_str_list(str, ",", l);

    for (auto& entry : l) {
      entry = rgw_trim_whitespace(entry);
      if (entry.empty()) {
        continue;
      }

      if (entry == "*") {
        approve_all = true;
        return;
      }

      if (entry[0] == '*') {
        suffixes.insert(entry.substr(1));
        continue;
      }

      if (entry.back() == '*') {
        prefixes.insert(entry.substr(0, entry.size() - 1));
        continue;
      }

      entries.insert(entry);
    }
  }

public:
  ItemList() {}
  void init(const string& str, bool def_val) {
    if (str.empty()) {
      approve_all = def_val;
    } else {
      parse(str);
    }
  }

  bool exists(const string& entry) {
    if (approve_all) {
      return true;
    }

    if (entries.find(entry) != entries.end()) {
      return true;
    }

    auto i = prefixes.upper_bound(entry);
    if (i != prefixes.begin()) {
      --i;
      if (boost::algorithm::starts_with(entry, *i)) {
        return true;
      }
    }

    for (i = suffixes.begin(); i != suffixes.end(); ++i) {
      if (boost::algorithm::ends_with(entry, *i)) {
        return true;
      }
    }

    return false;
  }
};

#define ES_NUM_SHARDS_MIN 5

#define ES_NUM_SHARDS_DEFAULT 16
#define ES_NUM_REPLICAS_DEFAULT 1

struct ESVersion {
  int major_ver;
  int minor_ver;

  ESVersion(int _major, int _minor): major_ver(_major), minor_ver(_minor) {}
  ESVersion(): major_ver(0), minor_ver(0) {}

  void from_str(const char* s) {
    sscanf(s, "%d.%d", &major_ver, &minor_ver);
  }

  std::string to_str() const {
    return std::to_string(major_ver) + "." + std::to_string(minor_ver);
  }

  void decode_json(JSONObj *obj);
};

bool operator >= (const ESVersion& v1, const ESVersion& v2)
{
  if (v1.major_ver == v2.major_ver)
    return v1.minor_ver >= v2.minor_ver;

  return v1.major_ver > v2.major_ver;
}

struct ESInfo {
  std::string name;
  std::string cluster_name;
  std::string cluster_uuid;
  ESVersion version;

  void decode_json(JSONObj *obj);
};

void ESInfo::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("name", name, obj);
  JSONDecoder::decode_json("cluster_name", cluster_name, obj);
  JSONDecoder::decode_json("cluster_uuid", cluster_uuid, obj);
  JSONDecoder::decode_json("version", version, obj);
}

void ESVersion::decode_json(JSONObj *obj)
{
  std::string s;
  JSONDecoder::decode_json("number", s, obj);
  this->from_str(s.c_str());
}

struct ElasticConfig {
  uint64_t sync_instance{0};
  string id;
  string index_path;
  std::unique_ptr<RGWRESTConn> conn;
  bool explicit_custom_meta{true};
  string override_index_path;
  ItemList index_buckets;
  ItemList allow_owners;
  uint32_t num_shards{0};
  uint32_t num_replicas{0};

  void init(CephContext *cct, const JSONFormattable& config) {
    string elastic_endpoint = config["endpoint"];
    id = string("elastic:") + elastic_endpoint;
    conn.reset(new RGWRESTConn(cct, nullptr, id, { elastic_endpoint }));
    explicit_custom_meta = config["explicit_custom_meta"](true);
    index_buckets.init(config["index_buckets_list"], true); /* approve all buckets by default */
    allow_owners.init(config["approved_owners_list"], true); /* approve all bucket owners by default */
    override_index_path = config["override_index_path"];
    num_shards = config["num_shards"](ES_NUM_SHARDS_DEFAULT);
    if (num_shards < ES_NUM_SHARDS_MIN) {
      num_shards = ES_NUM_SHARDS_MIN;
    }
    num_replicas = config["num_replicas"](ES_NUM_REPLICAS_DEFAULT);
  }

  void init_instance(const RGWRealm& realm, uint64_t instance_id) {
    sync_instance = instance_id;

    if (!override_index_path.empty()) {
      index_path = override_index_path;
      return;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "-%08x", (uint32_t)(sync_instance & 0xFFFFFFFF));

    index_path = "/rgw-" + realm.get_name() + buf;
  }

  string get_index_path() {
    return index_path;
  }

  string get_obj_path(const RGWBucketInfo& bucket_info, const rgw_obj_key& key) {
    return index_path +  "/object/" + url_encode(bucket_info.bucket.bucket_id + ":" + key.name + ":" + (key.instance.empty() ? "null" : key.instance));
  }

  bool should_handle_operation(RGWBucketInfo& bucket_info) {
    return index_buckets.exists(bucket_info.bucket.name) &&
           allow_owners.exists(bucket_info.owner.to_str());
  }
};

using ElasticConfigRef = std::shared_ptr<ElasticConfig>;

std::optional<const char*> es_type_to_str(const ESType& t) {
  switch (t) {
  case ESType::String: return "string";
  case ESType::Text: return "text";
  case ESType::Keyword: return "keyword";
  case ESType::Long: return "long";
  case ESType::Integer: return "integer";
  case ESType::Short: return "short";
  case ESType::Byte: return "byte";
  case ESType::Double: return "double";
  case ESType::Float: return "float";
  case ESType::Half_Float: return "half_float";
  case ESType::Scaled_Float: return "scaled_float";
  case ESType::Date: return "date";
  case ESType::Boolean: return "boolean";
  case ESType::Integer_Range: return "integer_range";
  case ESType::Float_Range: return "float_range";
  case ESType::Double_Range: return "date_range";
  case ESType::Date_Range: return "date_range";
  case ESType::Geo_Point: return "geo_point";
  case ESType::Ip: return "ip";
  default:
    return std::nullopt;
  }

}

struct es_dump_type {
  const char *type;
  const char *format;
  bool analyzed;
  std::string default_type;

  es_dump_type(const char *t, const char *f = nullptr, bool a = false) : type(t), format(f), analyzed(a) {}

  es_dump_type(ESType t, const char *f = nullptr, bool a = false,
               std::string default_type="text"): format(f), analyzed(a),
                                                 default_type(default_type) {
    type = es_type_to_str(t).value_or(default_type.c_str());
  }

  void dump(Formatter *f) const {
    encode_json("type", type, f);
    if (format) {
      encode_json("format", format, f);
    }
    if (!analyzed && strcmp(type, "string") == 0) {
      encode_json("index", "not_analyzed", f);
    }
  }
};

struct es_index_mappings {
  ESType string_type {ESType::String};

  void dump_custom(Formatter *f, const char *section, const char *type, const char *format) const {
    f->open_object_section(section);
    ::encode_json("type", "nested", f);
    f->open_object_section("properties");
    encode_json("name", es_dump_type(string_type), f);
    encode_json("value", es_dump_type(type, format), f);
    f->close_section(); // entry
    f->close_section(); // custom-string
  }

  void dump_custom(Formatter *f, const char* section, ESType t, const char *format) const {
    const auto s = es_type_to_str(t).value_or("text");
    dump_custom(f,section,s,format);
  }

  void dump(Formatter *f) const {
    f->open_object_section("object");
    f->open_object_section("properties");
    encode_json("bucket", es_dump_type(string_type), f);
    encode_json("name", es_dump_type(string_type), f);
    encode_json("instance", es_dump_type(string_type), f);
    encode_json("versioned_epoch", es_dump_type(ESType::Date), f);
    f->open_object_section("meta");
    f->open_object_section("properties");
    encode_json("cache_control", es_dump_type(string_type), f);
    encode_json("content_disposition", es_dump_type(string_type), f);
    encode_json("content_encoding", es_dump_type(string_type), f);
    encode_json("content_language", es_dump_type(string_type), f);
    encode_json("content_type", es_dump_type(string_type), f);
    encode_json("etag", es_dump_type(string_type), f);
    encode_json("expires", es_dump_type(string_type), f);
    f->open_object_section("mtime");
    ::encode_json("type", "date", f);
    ::encode_json("format", "strict_date_optional_time||epoch_millis", f);
    f->close_section(); // mtime
    encode_json("size", es_dump_type(ESType::Long), f);
    dump_custom(f, "custom-string", string_type, nullptr);
    dump_custom(f, "custom-int", "long", nullptr);
    dump_custom(f, "custom-date", "date", "strict_date_optional_time||epoch_millis");
    f->close_section(); // properties
    f->close_section(); // meta
    f->close_section(); // properties
    f->close_section(); // object
  }
};

struct es_index_settings {
  uint32_t num_replicas;
  uint32_t num_shards;

  es_index_settings(uint32_t _replicas, uint32_t _shards) : num_replicas(_replicas), num_shards(_shards) {}

  void dump(Formatter *f) const {
    encode_json("number_of_replicas", num_replicas, f);
    encode_json("number_of_shards", num_shards, f);
  }
};

struct es_index_config {
  es_index_settings settings;
  es_index_mappings mappings;

  es_index_config(es_index_settings& _s, es_index_mappings& _m) : settings(_s), mappings(_m) {}

  void dump(Formatter *f) const {
    encode_json("settings", settings, f);
    encode_json("mappings", mappings, f);
  }
};

static bool is_sys_attr(const std::string& attr_name){
  static constexpr std::initializer_list<const char*> rgw_sys_attrs =
                                                         {RGW_ATTR_PG_VER,
                                                          RGW_ATTR_SOURCE_ZONE,
                                                          RGW_ATTR_ID_TAG,
                                                          RGW_ATTR_TEMPURL_KEY1,
                                                          RGW_ATTR_TEMPURL_KEY2,
                                                          RGW_ATTR_UNIX1,
                                                          RGW_ATTR_UNIX_KEY1
  };

  return std::find(rgw_sys_attrs.begin(), rgw_sys_attrs.end(), attr_name) != rgw_sys_attrs.end();
}

struct es_obj_metadata {
  CephContext *cct;
  ElasticConfigRef es_conf;
  RGWBucketInfo bucket_info;
  rgw_obj_key key;
  ceph::real_time mtime;
  uint64_t size;
  map<string, bufferlist> attrs;
  uint64_t versioned_epoch;

  es_obj_metadata(CephContext *_cct, ElasticConfigRef _es_conf, const RGWBucketInfo& _bucket_info,
                  const rgw_obj_key& _key, ceph::real_time& _mtime, uint64_t _size,
                  map<string, bufferlist>& _attrs, uint64_t _versioned_epoch) : cct(_cct), es_conf(_es_conf), bucket_info(_bucket_info), key(_key),
                                                     mtime(_mtime), size(_size), attrs(std::move(_attrs)), versioned_epoch(_versioned_epoch) {}

  void dump(Formatter *f) const {
    map<string, string> out_attrs;
    map<string, string> custom_meta;
    RGWAccessControlPolicy policy;
    set<string> permissions;
    RGWObjTags obj_tags;

    for (auto i : attrs) {
      const string& attr_name = i.first;
      bufferlist& val = i.second;

      if (!boost::algorithm::starts_with(attr_name, RGW_ATTR_PREFIX)) {
        continue;
      }

      if (boost::algorithm::starts_with(attr_name, RGW_ATTR_META_PREFIX)) {
        custom_meta.emplace(attr_name.substr(sizeof(RGW_ATTR_META_PREFIX) - 1),
                            string(val.c_str(), (val.length() > 0 ? val.length() - 1 : 0)));
        continue;
      }

      if (boost::algorithm::starts_with(attr_name, RGW_ATTR_CRYPT_PREFIX)) {
        continue;
      }

      if (boost::algorithm::starts_with(attr_name, RGW_ATTR_OLH_PREFIX)) {
        // skip versioned object olh info
        continue;
      }

      if (attr_name == RGW_ATTR_ACL) {
        try {
          auto i = val.cbegin();
          decode(policy, i);
        } catch (buffer::error& err) {
          ldout(cct, 0) << "ERROR: failed to decode acl for " << bucket_info.bucket << "/" << key << dendl;
          continue;
        }

        const RGWAccessControlList& acl = policy.get_acl();

        permissions.insert(policy.get_owner().get_id().to_str());
        for (auto acliter : acl.get_grant_map()) {
          const ACLGrant& grant = acliter.second;
          if (grant.get_type().get_type() == ACL_TYPE_CANON_USER &&
              ((uint32_t)grant.get_permission().get_permissions() & RGW_PERM_READ) != 0) {
            rgw_user user;
            if (grant.get_id(user)) {
              permissions.insert(user.to_str());
            }
          }
        }
      } else if (attr_name == RGW_ATTR_TAGS) {
        try {
          auto tags_bl = val.cbegin();
          decode(obj_tags, tags_bl);
        } catch (buffer::error& err) {
          ldout(cct,0) << "ERROR: failed to decode obj tags for "
                       << bucket_info.bucket << "/" << key << dendl;
          continue;
        }
      } else if (attr_name == RGW_ATTR_COMPRESSION) {
        RGWCompressionInfo cs_info;
        try {
          auto vals_bl = val.cbegin();
          decode(cs_info, vals_bl);
        } catch (buffer::error& err) {
          ldout(cct,0) << "ERROR: failed to decode compression attr for "
                       << bucket_info.bucket << "/" << key << dendl;
          continue;
        }
        out_attrs.emplace("compression",std::move(cs_info.compression_type));
      } else {
        if (!is_sys_attr(attr_name)) {
          out_attrs.emplace(attr_name.substr(sizeof(RGW_ATTR_PREFIX) - 1),
                            std::string(val.c_str(), (val.length() > 0 ? val.length() - 1 : 0)));
        }
      }
    }
    ::encode_json("bucket", bucket_info.bucket.name, f);
    ::encode_json("name", key.name, f);
    string instance = key.instance;
    if (instance.empty())
      instance = "null";
    ::encode_json("instance", instance, f);
    ::encode_json("versioned_epoch", versioned_epoch, f);
    ::encode_json("owner", policy.get_owner(), f);
    ::encode_json("permissions", permissions, f);
    f->open_object_section("meta");
    ::encode_json("size", size, f);

    string mtime_str;
    rgw_to_iso8601(mtime, &mtime_str);
    ::encode_json("mtime", mtime_str, f);
    for (auto i : out_attrs) {
      ::encode_json(i.first.c_str(), i.second, f);
    }
    map<string, string> custom_str;
    map<string, string> custom_int;
    map<string, string> custom_date;

    for (auto i : custom_meta) {
      auto config = bucket_info.mdsearch_config.find(i.first);
      if (config == bucket_info.mdsearch_config.end()) {
        if (!es_conf->explicit_custom_meta) {
          /* default custom meta is of type string */
          custom_str[i.first] = i.second;
        } else {
          ldout(cct, 20) << "custom meta entry key=" << i.first << " not found in bucket mdsearch config: " << bucket_info.mdsearch_config << dendl;
        }
        continue;
      }
      switch (config->second) {
        case ESEntityTypeMap::ES_ENTITY_DATE:
          custom_date[i.first] = i.second;
          break;
        case ESEntityTypeMap::ES_ENTITY_INT:
          custom_int[i.first] = i.second;
          break;
        default:
          custom_str[i.first] = i.second;
      }
    }

    if (!custom_str.empty()) {
      f->open_array_section("custom-string");
      for (auto i : custom_str) {
        f->open_object_section("entity");
        ::encode_json("name", i.first.c_str(), f);
        ::encode_json("value", i.second, f);
        f->close_section();
      }
      f->close_section();
    }
    if (!custom_int.empty()) {
      f->open_array_section("custom-int");
      for (auto i : custom_int) {
        f->open_object_section("entity");
        ::encode_json("name", i.first.c_str(), f);
        ::encode_json("value", i.second, f);
        f->close_section();
      }
      f->close_section();
    }
    if (!custom_date.empty()) {
      f->open_array_section("custom-date");
      for (auto i : custom_date) {
        /*
         * try to exlicitly parse date field, otherwise elasticsearch could reject the whole doc,
         * which will end up with failed sync
         */
        real_time t;
        int r = parse_time(i.second.c_str(), &t);
        if (r < 0) {
          ldout(cct, 20) << __func__ << "(): failed to parse time (" << i.second << "), skipping encoding of custom date attribute" << dendl;
          continue;
        }

        string time_str;
        rgw_to_iso8601(t, &time_str);

        f->open_object_section("entity");
        ::encode_json("name", i.first.c_str(), f);
        ::encode_json("value", time_str.c_str(), f);
        f->close_section();
      }
      f->close_section();
    }
    f->close_section(); // meta
    const auto& m = obj_tags.get_tags();
    if (m.size() > 0){
      f->open_array_section("tagging");
      for (const auto &it : m) {
        f->open_object_section("tag");
        ::encode_json("key", it.first, f);
        ::encode_json("value",it.second, f);
        f->close_section();
      }
      f->close_section(); // tagging
    }
  }
};

class RGWElasticInitConfigCBCR : public RGWCoroutine {
  RGWDataSyncEnv *sync_env;
  ElasticConfigRef conf;
  ESInfo es_info;
public:
  RGWElasticInitConfigCBCR(RGWDataSyncEnv *_sync_env,
                          ElasticConfigRef _conf) : RGWCoroutine(_sync_env->cct),
                                                    sync_env(_sync_env),
                                                    conf(_conf) {}
  int operate() override {
    reenter(this) {
      ldout(sync_env->cct, 0) << ": init elasticsearch config zone=" << sync_env->source_zone << dendl;
      yield {
        auto hdrs = make_param_list(&conf->default_headers);
        call(new RGWReadRESTResourceCR<ESInfo> (sync_env->cct,
                                                conf->conn.get(),
                                                sync_env->http_manager,
                                                "/", nullptr /*params*/,
                                                &hdrs,
                                                &es_info));
      }
      if (retcode < 0) {
        return set_cr_error(retcode);
      }

      yield {
        string path = conf->get_index_path();
        ldout(sync_env->cct, 5) << "got elastic version=" << es_info.version.to_str() << dendl;

        es_index_settings settings(conf->num_replicas, conf->num_shards);
        es_index_mappings mappings;
        if (es_info.version >= ESVersion(5,0)) {
          ldout(sync_env->cct, 0) << "elasticsearch: using text type for string index mappings " << dendl;
          mappings.string_type = ESType::Text;
        }

        es_index_config index_conf(settings, mappings);
        std::map <string, string> hdrs = {{ "Content-Type", "application/json" }};
        call(new RGWPutRESTResourceCR<es_index_config, int> (sync_env->cct,
                                                             conf->conn.get(),
                                                             sync_env->http_manager,
                                                             path, nullptr /*params*/,
                                                             &hdrs,
                                                             index_conf, nullptr));
      }
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }

};

class RGWElasticHandleRemoteObjCBCR : public RGWStatRemoteObjCBCR {
  ElasticConfigRef conf;
  uint64_t versioned_epoch;
public:
  RGWElasticHandleRemoteObjCBCR(RGWDataSyncEnv *_sync_env,
                          RGWBucketInfo& _bucket_info, rgw_obj_key& _key,
                          ElasticConfigRef _conf, uint64_t _versioned_epoch) : RGWStatRemoteObjCBCR(_sync_env, _bucket_info, _key), conf(_conf),
                                                                               versioned_epoch(_versioned_epoch) {}
  int operate() override {
    reenter(this) {
      ldout(sync_env->cct, 10) << ": stat of remote obj: z=" << sync_env->source_zone
                               << " b=" << bucket_info.bucket << " k=" << key
                               << " size=" << size << " mtime=" << mtime << dendl;

      yield {
        string path = conf->get_obj_path(bucket_info, key);
        es_obj_metadata doc(sync_env->cct, conf, bucket_info, key, mtime, size, attrs, versioned_epoch);

        std::map <string, string> hdrs = {{ "Content-Type", "application/json" }};
        call(new RGWPutRESTResourceCR<es_obj_metadata, int>(sync_env->cct, conf->conn.get(),
                                                            sync_env->http_manager,
                                                            path, nullptr /* params */,
                                                            &hdrs,
                                                            doc, nullptr /* result */));

      }
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }
};

class RGWElasticHandleRemoteObjCR : public RGWCallStatRemoteObjCR {
  ElasticConfigRef conf;
  uint64_t versioned_epoch;
public:
  RGWElasticHandleRemoteObjCR(RGWDataSyncEnv *_sync_env,
                        RGWBucketInfo& _bucket_info, rgw_obj_key& _key,
                        ElasticConfigRef _conf, uint64_t _versioned_epoch) : RGWCallStatRemoteObjCR(_sync_env, _bucket_info, _key),
                                                           conf(_conf), versioned_epoch(_versioned_epoch) {
  }

  ~RGWElasticHandleRemoteObjCR() override {}

  RGWStatRemoteObjCBCR *allocate_callback() override {
    return new RGWElasticHandleRemoteObjCBCR(sync_env, bucket_info, key, conf, versioned_epoch);
  }
};

class RGWElasticRemoveRemoteObjCBCR : public RGWCoroutine {
  RGWDataSyncEnv *sync_env;
  RGWBucketInfo bucket_info;
  rgw_obj_key key;
  ceph::real_time mtime;
  ElasticConfigRef conf;
public:
  RGWElasticRemoveRemoteObjCBCR(RGWDataSyncEnv *_sync_env,
                          RGWBucketInfo& _bucket_info, rgw_obj_key& _key, const ceph::real_time& _mtime,
                          ElasticConfigRef _conf) : RGWCoroutine(_sync_env->cct), sync_env(_sync_env),
                                                        bucket_info(_bucket_info), key(_key),
                                                        mtime(_mtime), conf(_conf) {}
  int operate() override {
    reenter(this) {
      ldout(sync_env->cct, 10) << ": remove remote obj: z=" << sync_env->source_zone
                               << " b=" << bucket_info.bucket << " k=" << key << " mtime=" << mtime << dendl;
      yield {
        string path = conf->get_obj_path(bucket_info, key);

        call(new RGWDeleteRESTResourceCR(sync_env->cct, conf->conn.get(),
                                         sync_env->http_manager,
                                         path, nullptr /* params */));
      }
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }

};

class RGWElasticDataSyncModule : public RGWDataSyncModule {
  ElasticConfigRef conf;
public:
  RGWElasticDataSyncModule(CephContext *cct, const JSONFormattable& config) : conf(std::make_shared<ElasticConfig>()) {
    conf->init(cct, config);
  }
  ~RGWElasticDataSyncModule() override {}

  void init(RGWDataSyncEnv *sync_env, uint64_t instance_id) override {
    conf->init_instance(sync_env->store->svc.zone->get_realm(), instance_id);
  }

  RGWCoroutine *init_sync(RGWDataSyncEnv *sync_env) override {
    ldout(sync_env->cct, 5) << conf->id << ": init" << dendl;
    return new RGWElasticInitConfigCBCR(sync_env, conf);
  }
  RGWCoroutine *sync_object(RGWDataSyncEnv *sync_env, RGWBucketInfo& bucket_info, rgw_obj_key& key, std::optional<uint64_t> versioned_epoch, rgw_zone_set *zones_trace) override {
    ldout(sync_env->cct, 10) << conf->id << ": sync_object: b=" << bucket_info.bucket << " k=" << key << " versioned_epoch=" << versioned_epoch.value_or(0) << dendl;
    if (!conf->should_handle_operation(bucket_info)) {
      ldout(sync_env->cct, 10) << conf->id << ": skipping operation (bucket not approved)" << dendl;
      return nullptr;
    }
    return new RGWElasticHandleRemoteObjCR(sync_env, bucket_info, key, conf, versioned_epoch.value_or(0));
  }
  RGWCoroutine *remove_object(RGWDataSyncEnv *sync_env, RGWBucketInfo& bucket_info, rgw_obj_key& key, real_time& mtime, bool versioned, uint64_t versioned_epoch, rgw_zone_set *zones_trace) override {
    /* versioned and versioned epoch params are useless in the elasticsearch backend case */
    ldout(sync_env->cct, 10) << conf->id << ": rm_object: b=" << bucket_info.bucket << " k=" << key << " mtime=" << mtime << " versioned=" << versioned << " versioned_epoch=" << versioned_epoch << dendl;
    if (!conf->should_handle_operation(bucket_info)) {
      ldout(sync_env->cct, 10) << conf->id << ": skipping operation (bucket not approved)" << dendl;
      return nullptr;
    }
    return new RGWElasticRemoveRemoteObjCBCR(sync_env, bucket_info, key, mtime, conf);
  }
  RGWCoroutine *create_delete_marker(RGWDataSyncEnv *sync_env, RGWBucketInfo& bucket_info, rgw_obj_key& key, real_time& mtime,
                                     rgw_bucket_entry_owner& owner, bool versioned, uint64_t versioned_epoch, rgw_zone_set *zones_trace) override {
    ldout(sync_env->cct, 10) << conf->id << ": create_delete_marker: b=" << bucket_info.bucket << " k=" << key << " mtime=" << mtime
                            << " versioned=" << versioned << " versioned_epoch=" << versioned_epoch << dendl;
    ldout(sync_env->cct, 10) << conf->id << ": skipping operation (not handled)" << dendl;
    return NULL;
  }
  RGWRESTConn *get_rest_conn() {
    return conf->conn.get();
  }

  string get_index_path() {
    return conf->get_index_path();
  }
};

RGWElasticSyncModuleInstance::RGWElasticSyncModuleInstance(CephContext *cct, const JSONFormattable& config)
{
  data_handler = std::unique_ptr<RGWElasticDataSyncModule>(new RGWElasticDataSyncModule(cct, config));
}

RGWDataSyncModule *RGWElasticSyncModuleInstance::get_data_handler()
{
  return data_handler.get();
}

RGWRESTConn *RGWElasticSyncModuleInstance::get_rest_conn()
{
  return data_handler->get_rest_conn();
}

string RGWElasticSyncModuleInstance::get_index_path() {
  return data_handler->get_index_path();
}

RGWRESTMgr *RGWElasticSyncModuleInstance::get_rest_filter(int dialect, RGWRESTMgr *orig) {
  if (dialect != RGW_REST_S3) {
    return orig;
  }
  delete orig;
  return new RGWRESTMgr_MDSearch_S3();
}

int RGWElasticSyncModule::create_instance(CephContext *cct, const JSONFormattable& config, RGWSyncModuleInstanceRef *instance) {
  string endpoint = config["endpoint"];
  instance->reset(new RGWElasticSyncModuleInstance(cct, config));
  return 0;
}

