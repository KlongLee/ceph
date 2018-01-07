// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_ADMIN_COMMON_H
#define CEPH_RGW_ADMIN_COMMON_H

#include "rgw_user.h"

enum {
  OPT_NO_CMD = 0,
  OPT_USER_CREATE,
  OPT_USER_INFO,
  OPT_USER_MODIFY,
  OPT_USER_RM,
  OPT_USER_SUSPEND,
  OPT_USER_ENABLE,
  OPT_USER_CHECK,
  OPT_USER_STATS,
  OPT_USER_LIST,
  OPT_SUBUSER_CREATE,
  OPT_SUBUSER_MODIFY,
  OPT_SUBUSER_RM,
  OPT_KEY_CREATE,
  OPT_KEY_RM,
  OPT_BUCKETS_LIST,
  OPT_BUCKET_LIMIT_CHECK,
  OPT_BUCKET_LINK,
  OPT_BUCKET_UNLINK,
  OPT_BUCKET_STATS,
  OPT_BUCKET_CHECK,
  OPT_BUCKET_SYNC_STATUS,
  OPT_BUCKET_SYNC_INIT,
  OPT_BUCKET_SYNC_RUN,
  OPT_BUCKET_SYNC_DISABLE,
  OPT_BUCKET_SYNC_ENABLE,
  OPT_BUCKET_RM,
  OPT_BUCKET_REWRITE,
  OPT_BUCKET_RESHARD,
  OPT_POLICY,
  OPT_POOL_ADD,
  OPT_POOL_RM,
  OPT_POOLS_LIST,
  OPT_LOG_LIST,
  OPT_LOG_SHOW,
  OPT_LOG_RM,
  OPT_USAGE_SHOW,
  OPT_USAGE_TRIM,
  OPT_OBJECT_RM,
  OPT_OBJECT_UNLINK,
  OPT_OBJECT_STAT,
  OPT_OBJECT_REWRITE,
  OPT_OBJECTS_EXPIRE,
  OPT_BI_GET,
  OPT_BI_PUT,
  OPT_BI_LIST,
  OPT_BI_PURGE,
  OPT_OLH_GET,
  OPT_OLH_READLOG,
  OPT_QUOTA_SET,
  OPT_QUOTA_ENABLE,
  OPT_QUOTA_DISABLE,
  OPT_GC_LIST,
  OPT_GC_PROCESS,
  OPT_LC_LIST,
  OPT_LC_PROCESS,
  OPT_ORPHANS_FIND,
  OPT_ORPHANS_FINISH,
  OPT_ORPHANS_LIST_JOBS,
  OPT_ZONEGROUP_ADD,
  OPT_ZONEGROUP_CREATE,
  OPT_ZONEGROUP_DEFAULT,
  OPT_ZONEGROUP_DELETE,
  OPT_ZONEGROUP_GET,
  OPT_ZONEGROUP_MODIFY,
  OPT_ZONEGROUP_SET,
  OPT_ZONEGROUP_LIST,
  OPT_ZONEGROUP_REMOVE,
  OPT_ZONEGROUP_RENAME,
  OPT_ZONEGROUP_PLACEMENT_ADD,
  OPT_ZONEGROUP_PLACEMENT_MODIFY,
  OPT_ZONEGROUP_PLACEMENT_RM,
  OPT_ZONEGROUP_PLACEMENT_LIST,
  OPT_ZONEGROUP_PLACEMENT_DEFAULT,
  OPT_ZONE_CREATE,
  OPT_ZONE_DELETE,
  OPT_ZONE_GET,
  OPT_ZONE_MODIFY,
  OPT_ZONE_SET,
  OPT_ZONE_LIST,
  OPT_ZONE_RENAME,
  OPT_ZONE_DEFAULT,
  OPT_ZONE_PLACEMENT_ADD,
  OPT_ZONE_PLACEMENT_MODIFY,
  OPT_ZONE_PLACEMENT_RM,
  OPT_ZONE_PLACEMENT_LIST,
  OPT_CAPS_ADD,
  OPT_CAPS_RM,
  OPT_METADATA_GET,
  OPT_METADATA_PUT,
  OPT_METADATA_RM,
  OPT_METADATA_LIST,
  OPT_METADATA_SYNC_STATUS,
  OPT_METADATA_SYNC_INIT,
  OPT_METADATA_SYNC_RUN,
  OPT_MDLOG_LIST,
  OPT_MDLOG_AUTOTRIM,
  OPT_MDLOG_TRIM,
  OPT_MDLOG_FETCH,
  OPT_MDLOG_STATUS,
  OPT_SYNC_ERROR_LIST,
  OPT_BILOG_LIST,
  OPT_BILOG_TRIM,
  OPT_BILOG_STATUS,
  OPT_BILOG_AUTOTRIM,
  OPT_DATA_SYNC_STATUS,
  OPT_DATA_SYNC_INIT,
  OPT_DATA_SYNC_RUN,
  OPT_DATALOG_LIST,
  OPT_DATALOG_STATUS,
  OPT_DATALOG_TRIM,
  OPT_OPSTATE_LIST,
  OPT_OPSTATE_SET,
  OPT_OPSTATE_RENEW,
  OPT_OPSTATE_RM,
  OPT_REPLICALOG_GET,
  OPT_REPLICALOG_UPDATE,
  OPT_REPLICALOG_DELETE,
  OPT_REALM_CREATE,
  OPT_REALM_DELETE,
  OPT_REALM_GET,
  OPT_REALM_GET_DEFAULT,
  OPT_REALM_LIST,
  OPT_REALM_LIST_PERIODS,
  OPT_REALM_RENAME,
  OPT_REALM_SET,
  OPT_REALM_DEFAULT,
  OPT_REALM_PULL,
  OPT_PERIOD_DELETE,
  OPT_PERIOD_GET,
  OPT_PERIOD_GET_CURRENT,
  OPT_PERIOD_PULL,
  OPT_PERIOD_PUSH,
  OPT_PERIOD_LIST,
  OPT_PERIOD_UPDATE,
  OPT_PERIOD_COMMIT,
  OPT_GLOBAL_QUOTA_GET,
  OPT_GLOBAL_QUOTA_SET,
  OPT_GLOBAL_QUOTA_ENABLE,
  OPT_GLOBAL_QUOTA_DISABLE,
  OPT_SYNC_STATUS,
  OPT_ROLE_CREATE,
  OPT_ROLE_DELETE,
  OPT_ROLE_GET,
  OPT_ROLE_MODIFY,
  OPT_ROLE_LIST,
  OPT_ROLE_POLICY_PUT,
  OPT_ROLE_POLICY_LIST,
  OPT_ROLE_POLICY_GET,
  OPT_ROLE_POLICY_DELETE,
  OPT_RESHARD_ADD,
  OPT_RESHARD_LIST,
  OPT_RESHARD_STATUS,
  OPT_RESHARD_PROCESS,
  OPT_RESHARD_CANCEL,
};

enum ReplicaLogType {
  ReplicaLog_Invalid = 0,
  ReplicaLog_Metadata,
  ReplicaLog_Data,
  ReplicaLog_Bucket,
};

void usage();

int get_cmd(const char *cmd, const char *prev_cmd, const char *prev_prev_cmd, bool *need_more);

int parse_command(const string& access_key, int gen_access_key, const string& secret_key, int gen_secret_key,
                  vector<const char*>& args, int& opt_cmd, string& metadata_key, string& tenant, rgw_user& user_id);

int parse_commandline_parameters(vector<const char*>& args, rgw_user& user_id, string& tenant, string& access_key,
                                 string& subuser, string& secret_key, string& user_email, RGWUserAdminOpState& user_op,
                                 string& display_name, string& bucket_name, string& pool_name, rgw_pool& pool,
                                 string& object, string& object_version, string& client_id, string& op_id,
                                 string& state_str, string& op_mask_str, int& key_type, string& job_id,
                                 int& gen_access_key, int& gen_secret_key, int& show_log_entries, int& show_log_sum,
                                 int& skip_zero_entries, int& admin, bool& admin_specified, int& system,
                                 bool& system_specified, int& verbose, int& staging, int& commit,
                                 uint64_t& min_rewrite_size, uint64_t& max_rewrite_size,
                                 uint64_t& min_rewrite_stripe_size, int& max_buckets, bool& max_buckets_specified,
                                 int& max_entries, bool& max_entries_specified, int64_t& max_size, bool& have_max_size,
                                 int64_t& max_objects, bool& have_max_objects, string& date, string& start_date,
                                 string& end_date, int& num_shards, bool& num_shards_specified, int& max_concurrent_ios,
                                 uint64_t& orphan_stale_secs, int& shard_id, bool& specified_shard_id,
                                 string& daemon_id, bool& specified_daemon_id, string& access, uint32_t& perm_mask,
                                 bool& set_perm, map<int, string>& temp_url_keys, bool& set_temp_url_key,
                                 string& bucket_id, string& format, map<string, bool>& categories,
                                 int& delete_child_objects, int& pretty_format, int& purge_data, int& purge_keys,
                                 int& yes_i_really_mean_it, int& fix, int& remove_bad, int& check_head_obj_locator,
                                 int& check_objects, int& sync_stats, int& include_all, int& extra_info, int& bypass_gc,
                                 int& warnings_only, int& inconsistent_index, string& caps, string& infile,
                                 string& metadata_key, string& marker, string& start_marker, string& end_marker,
                                 string& quota_scope, string& replica_log_type_str, ReplicaLogType& replica_log_type,
                                 BIIndexType& bi_index_type, bool& is_master, bool& is_master_set, int& set_default,
                                 string& redirect_zone, bool& redirect_zone_set, bool& read_only, int& is_read_only_set,
                                 string& master_zone, string& period_id, string& period_epoch, string& remote,
                                 string& url, string& realm_id,string& realm_new_name, string& zonegroup_id,
                                 string& zonegroup_new_name, string& placement_id, list<string>& tags,
                                 list<string>& tags_add, list<string>& tags_rm, string& api_name, string& zone_id,
                                 string& zone_new_name, list<string>& endpoints, list<string>& sync_from,
                                 list<string>& sync_from_rm, bool& sync_from_all, int& sync_from_all_specified,
                                 string& source_zone_name, string& tier_type, bool& tier_type_specified,
                                 map<string, string, ltstr_nocase>& tier_config_add,
                                 map<string, string, ltstr_nocase>& tier_config_rm, boost::optional<string>& index_pool,
                                 boost::optional<string>& data_pool, boost::optional<string>& data_extra_pool,
                                 RGWBucketIndexType& placement_index_type, bool& index_type_specified,
                                 boost::optional<string>& compression_type, string& role_name, string& path,
                                 string& assume_role_doc, string& policy_name, string& perm_policy_doc,
                                 string& path_prefix);

int read_input(const string& infile, bufferlist& bl);

int init_bucket(RGWRados *store, const string& tenant_name, const string& bucket_name, const string& bucket_id,
                RGWBucketInfo& bucket_info, rgw_bucket& bucket, map<string, bufferlist> *pattrs = nullptr);

#endif //CEPH_RGW_ADMIN_COMMON_H