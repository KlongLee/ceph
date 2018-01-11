#include "rgw_admin_opt_bucket.h"

#include "rgw_orphan.h"
#include "rgw_data_sync.h"

static bool bucket_object_check_filter(const string& name)
{
  rgw_obj_key k;
  string ns; /* empty namespace */
  return rgw_obj_key::oid_to_key_in_ns(name, &k, ns);
}

static int check_obj_locator_underscore(RGWRados *store, RGWBucketInfo& bucket_info, rgw_obj& obj, rgw_obj_key& key,
                                        bool fix, bool remove_bad, Formatter *f) {
  f->open_object_section("object");
  f->open_object_section("key");
  f->dump_string("type", "head");
  f->dump_string("name", key.name);
  f->dump_string("instance", key.instance);
  f->close_section();

  string oid;
  string locator;

  get_obj_bucket_and_oid_loc(obj, oid, locator);

  f->dump_string("oid", oid);
  f->dump_string("locator", locator);


  RGWObjectCtx obj_ctx(store);

  RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);
  RGWRados::Object::Read read_op(&op_target);

  int ret = read_op.prepare();
  bool needs_fixing = (ret == -ENOENT);

  f->dump_bool("needs_fixing", needs_fixing);

  string status = (needs_fixing ? "needs_fixing" : "ok");

  if ((needs_fixing || remove_bad) && fix) {
    ret = store->fix_head_obj_locator(bucket_info, needs_fixing, remove_bad, key);
    if (ret < 0) {
      cerr << "ERROR: fix_head_object_locator() returned ret=" << ret << std::endl;
      goto done;
    }
    status = "fixed";
  }

  done:
  f->dump_string("status", status);

  f->close_section();

  return 0;
}

static int check_obj_tail_locator_underscore(RGWRados *store, RGWBucketInfo& bucket_info, rgw_obj& obj, rgw_obj_key& key, bool fix, Formatter *f) {
  f->open_object_section("object");
  f->open_object_section("key");
  f->dump_string("type", "tail");
  f->dump_string("name", key.name);
  f->dump_string("instance", key.instance);
  f->close_section();

  bool needs_fixing;
  string status;

  int ret = store->fix_tail_obj_locator(bucket_info, key, fix, &needs_fixing);
  if (ret < 0) {
    cerr << "ERROR: fix_tail_object_locator_underscore() returned ret=" << ret << std::endl;
    status = "failed";
  } else {
    status = (needs_fixing && !fix ? "needs_fixing" : "ok");
  }

  f->dump_bool("needs_fixing", needs_fixing);
  f->dump_string("status", status);

  f->close_section();

  return 0;
}

static int do_check_object_locator(RGWRados *store, const string& tenant_name, const string& bucket_name,
                            bool fix, bool remove_bad, Formatter *f)
{
  if (remove_bad && !fix) {
    cerr << "ERROR: can't have remove_bad specified without fix" << std::endl;
    return -EINVAL;
  }

  RGWBucketInfo bucket_info;
  rgw_bucket bucket;
  string bucket_id;

  f->open_object_section("bucket");
  f->dump_string("bucket", bucket_name);
  int ret = init_bucket(store, tenant_name, bucket_name, bucket_id, bucket_info, bucket);
  if (ret < 0) {
    cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
    return ret;
  }
  bool truncated;
  int count = 0;

  int max_entries = 1000;

  string prefix;
  string delim;
  vector<rgw_bucket_dir_entry> result;
  map<string, bool> common_prefixes;
  string ns;

  RGWRados::Bucket target(store, bucket_info);
  RGWRados::Bucket::List list_op(&target);

  string marker;

  list_op.params.prefix = prefix;
  list_op.params.delim = delim;
  list_op.params.marker = rgw_obj_key(marker);
  list_op.params.ns = ns;
  list_op.params.enforce_ns = true;
  list_op.params.list_versions = true;

  f->open_array_section("check_objects");
  do {
    ret = list_op.list_objects(max_entries - count, &result, &common_prefixes, &truncated);
    if (ret < 0) {
      cerr << "ERROR: store->list_objects(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    count += result.size();

    for (auto &iter : result) {
      rgw_obj_key key = iter.key;
      rgw_obj obj(bucket, key);

      if (key.name[0] == '_') {
        ret = check_obj_locator_underscore(store, bucket_info, obj, key, fix, remove_bad, f);

        if (ret >= 0) {
          ret = check_obj_tail_locator_underscore(store, bucket_info, obj, key, fix, f);
          if (ret < 0) {
            cerr << "ERROR: check_obj_tail_locator_underscore(): " << cpp_strerror(-ret) << std::endl;
            return -ret;
          }
        }
      }
    }
    f->flush(cout);
  } while (truncated && count < max_entries);
  f->close_section();
  f->close_section();

  f->flush(cout);

  return 0;
}

int set_bucket_sync_enabled(RGWRados *store, int opt_cmd, const string& tenant_name, const string& bucket_name)
{
  RGWBucketInfo bucket_info;
  map<string, bufferlist> attrs;
  RGWObjectCtx obj_ctx(store);

  int r = store->get_bucket_info(obj_ctx, tenant_name, bucket_name, bucket_info, nullptr, &attrs);
  if (r < 0) {
    cerr << "could not get bucket info for bucket=" << bucket_name << ": " << cpp_strerror(-r) << std::endl;
    return -r;
  }

  if (opt_cmd == OPT_BUCKET_SYNC_ENABLE) {
    bucket_info.flags &= ~BUCKET_DATASYNC_DISABLED;
  } else if (opt_cmd == OPT_BUCKET_SYNC_DISABLE) {
    bucket_info.flags |= BUCKET_DATASYNC_DISABLED;
  }

  r = store->put_bucket_instance_info(bucket_info, false, real_time(), &attrs);
  if (r < 0) {
    cerr << "ERROR: failed writing bucket instance info: " << cpp_strerror(-r) << std::endl;
    return -r;
  }

  int shards_num = bucket_info.num_shards? bucket_info.num_shards : 1;
  int shard_id = bucket_info.num_shards? 0 : -1;

  if (opt_cmd == OPT_BUCKET_SYNC_DISABLE) {
    r = store->stop_bi_log_entries(bucket_info, -1);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing stop bilog" << dendl;
      return r;
    }
  } else {
    r = store->resync_bi_log_entries(bucket_info, -1);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing resync bilog" << dendl;
      return r;
    }
  }

  for (int i = 0; i < shards_num; ++i, ++shard_id) {
    r = store->data_log->add_entry(bucket_info.bucket, shard_id);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing data log" << dendl;
      return r;
    }
  }

  return 0;
}

static int init_bucket_for_sync(RGWRados *store, const string& tenant, const string& bucket_name,
                         const string& bucket_id, rgw_bucket& bucket)
{
  RGWBucketInfo bucket_info;

  int ret = init_bucket(store, tenant, bucket_name, bucket_id, bucket_info, bucket);
  if (ret < 0) {
    cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
    return ret;
  }

  return 0;
}

int handle_opt_bucket_limit_check(const rgw_user& user_id, bool warnings_only, RGWBucketAdminOpState& bucket_op,
                                  RGWFormatterFlusher& flusher, RGWRados *store) {
  void *handle;
  std::list<std::string> user_ids;
  string metadata_key = "user";
  int max = 1000;

  bool truncated;
  int ret;

  if (! user_id.empty()) {
    user_ids.push_back(user_id.id);
    ret =
        RGWBucketAdminOp::limit_check(store, bucket_op, user_ids, flusher,
                                      warnings_only);
  } else {
    /* list users in groups of max-keys, then perform user-bucket
     * limit-check on each group */
    ret = store->meta_mgr->list_keys_init(metadata_key, &handle);
    if (ret < 0) {
      cerr << "ERROR: buckets limit check can't get user metadata_key: "
           << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    do {
      ret = store->meta_mgr->list_keys_next(handle, max, user_ids,
                                            &truncated);
      if (ret < 0 && ret != -ENOENT) {
        cerr << "ERROR: buckets limit check lists_keys_next(): "
             << cpp_strerror(-ret) << std::endl;
        break;
      } else {
        /* ok, do the limit checks for this group */
        ret =
            RGWBucketAdminOp::limit_check(store, bucket_op, user_ids, flusher,
                                          warnings_only);
        if (ret < 0)
          break;
      }
      user_ids.clear();
    } while (truncated);
    store->meta_mgr->list_keys_complete(handle);
  }
  return -ret;
}

int handle_opt_buckets_list(const string& bucket_name, const string& tenant, const string& bucket_id,
                            const string& marker, int max_entries, rgw_bucket& bucket,
                            RGWBucketAdminOpState& bucket_op, RGWFormatterFlusher& flusher,
                            RGWRados *store, Formatter *formatter) {
  if (bucket_name.empty()) {
    RGWBucketAdminOp::info(store, bucket_op, flusher);
  } else {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(store, tenant, bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    formatter->open_array_section("entries");
    bool truncated;
    int count = 0;
    if (max_entries < 0)
      max_entries = 1000;

    string prefix;
    string delim;
    vector<rgw_bucket_dir_entry> result;
    map<string, bool> common_prefixes;
    string ns;

    RGWRados::Bucket target(store, bucket_info);
    RGWRados::Bucket::List list_op(&target);

    list_op.params.prefix = prefix;
    list_op.params.delim = delim;
    list_op.params.marker = rgw_obj_key(marker);
    list_op.params.ns = ns;
    list_op.params.enforce_ns = false;
    list_op.params.list_versions = true;

    do {
      ret = list_op.list_objects(max_entries - count, &result, &common_prefixes, &truncated);
      if (ret < 0) {
        cerr << "ERROR: store->list_objects(): " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      count += result.size();

      for (auto &entry : result) {
        encode_json("entry", entry, formatter);
      }
      formatter->flush(cout);
    } while (truncated && count < max_entries);

    formatter->close_section();
    formatter->flush(cout);
  } /* have bucket_name */
  return 0;
}

int handle_opt_bucket_stats(RGWBucketAdminOpState& bucket_op, RGWFormatterFlusher& flusher,
                            RGWRados *store) {
  bucket_op.set_fetch_stats(true);

  int r = RGWBucketAdminOp::info(store, bucket_op, flusher);
  if (r < 0) {
    cerr << "failure: " << cpp_strerror(-r) << std::endl;
    return -r;
  }
  return 0;
}

int handle_opt_bucket_link(const string& bucket_id, RGWBucketAdminOpState& bucket_op, RGWRados *store) {
  string err;
  bucket_op.set_bucket_id(bucket_id);
  int r = RGWBucketAdminOp::link(store, bucket_op, &err);
  if (r < 0) {
    cerr << "failure: " << cpp_strerror(-r) << ": " << err << std::endl;
    return -r;
  }
  return 0;
}

int handle_opt_bucket_unlink(RGWBucketAdminOpState& bucket_op, RGWRados *store) {
  int r = RGWBucketAdminOp::unlink(store, bucket_op);
  if (r < 0) {
    cerr << "failure: " << cpp_strerror(-r) << std::endl;
    return -r;
  }
  return 0;
}

int handle_opt_bucket_rewrite(const string& bucket_name, const string& tenant, const string& bucket_id,
                              const string& start_date, const string& end_date,
                              int min_rewrite_size, int max_rewrite_size, uint64_t min_rewrite_stripe_size,
                              rgw_bucket& bucket, RGWRados *store, Formatter *formatter){
  if (bucket_name.empty()) {
    cerr << "ERROR: bucket not specified" << std::endl;
    return EINVAL;
  }

  RGWBucketInfo bucket_info;
  int ret = init_bucket(store, tenant, bucket_name, bucket_id, bucket_info, bucket);
  if (ret < 0) {
    cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
    return -ret;
  }

  uint64_t start_epoch = 0;
  uint64_t end_epoch = 0;

  if (!end_date.empty()) {
    ret = utime_t::parse_date(end_date, &end_epoch, nullptr);
    if (ret < 0) {
      cerr << "ERROR: failed to parse end date" << std::endl;
      return EINVAL;
    }
  }
  if (!start_date.empty()) {
    ret = utime_t::parse_date(start_date, &start_epoch, nullptr);
    if (ret < 0) {
      cerr << "ERROR: failed to parse start date" << std::endl;
      return EINVAL;
    }
  }

  bool is_truncated = true;

  rgw_obj_index_key marker;
  string prefix;

  formatter->open_object_section("result");
  formatter->dump_string("bucket", bucket_name);
  formatter->open_array_section("objects");
  while (is_truncated) {
    map<string, rgw_bucket_dir_entry> result;
    int r = store->cls_bucket_list(bucket_info, RGW_NO_SHARD, marker, prefix, 1000, true,
                                   result, &is_truncated, &marker,
                                   bucket_object_check_filter);

    if (r < 0 && r != -ENOENT) {
      cerr << "ERROR: failed operation r=" << r << std::endl;
    }

    if (r == -ENOENT)
      break;

    map<string, rgw_bucket_dir_entry>::iterator iter;
    for (iter = result.begin(); iter != result.end(); ++iter) {
      rgw_obj_key key = iter->second.key;
      rgw_bucket_dir_entry& entry = iter->second;

      formatter->open_object_section("object");
      formatter->dump_string("name", key.name);
      formatter->dump_string("instance", key.instance);
      formatter->dump_int("size", entry.meta.size);
      utime_t ut(entry.meta.mtime);
      ut.gmtime(formatter->dump_stream("mtime"));

      if ((entry.meta.size < min_rewrite_size) ||
          (entry.meta.size > max_rewrite_size) ||
          (start_epoch > 0 && start_epoch > (uint64_t)ut.sec()) ||
          (end_epoch > 0 && end_epoch < (uint64_t)ut.sec())) {
        formatter->dump_string("status", "Skipped");
      } else {
        rgw_obj obj(bucket, key);

        bool need_rewrite = true;
        if (min_rewrite_stripe_size > 0) {
          r = check_min_obj_stripe_size(store, bucket_info, obj, min_rewrite_stripe_size, &need_rewrite);
          if (r < 0) {
            ldout(store->ctx(), 0) << "WARNING: check_min_obj_stripe_size failed, r=" << r << dendl;
          }
        }
        if (!need_rewrite) {
          formatter->dump_string("status", "Skipped");
        } else {
          r = store->rewrite_obj(bucket_info, obj);
          if (r == 0) {
            formatter->dump_string("status", "Success");
          } else {
            formatter->dump_string("status", cpp_strerror(-r));
          }
        }
      }
      formatter->dump_int("flags", entry.flags);

      formatter->close_section();
      formatter->flush(cout);
    }
  }
  formatter->close_section();
  formatter->close_section();
  formatter->flush(cout);

  return 0;
}

int handle_opt_bucket_reshard(const string& bucket_name, const string& tenant, const string& bucket_id,
                              bool num_shards_specified, int num_shards, bool yes_i_really_mean_it, int max_entries,
                              bool verbose, RGWRados *store, Formatter *formatter) {
  const int DEFAULT_RESHARD_MAX_ENTRIES = 1000;
  rgw_bucket bucket;
  RGWBucketInfo bucket_info;
  map<string, bufferlist> attrs;

  int ret = check_reshard_bucket_params(store,
                                        bucket_name,
                                        tenant,
                                        bucket_id,
                                        num_shards_specified,
                                        num_shards,
                                        yes_i_really_mean_it,
                                        bucket,
                                        bucket_info,
                                        attrs);
  if (ret < 0) {
    return ret;
  }

  RGWBucketReshard br(store, bucket_info, attrs);

  if (max_entries < 1) {
    max_entries = DEFAULT_RESHARD_MAX_ENTRIES;
  }

  return br.execute(num_shards, max_entries,
                    verbose, &cout, formatter);
}

int handle_opt_bucket_check(bool check_head_obj_locator, const string& bucket_name, const string& tenant, bool fix,
                            bool remove_bad, RGWBucketAdminOpState& bucket_op, RGWFormatterFlusher& flusher,
                            RGWRados *store, Formatter *formatter) {
  if (check_head_obj_locator) {
    if (bucket_name.empty()) {
      cerr << "ERROR: need to specify bucket name" << std::endl;
      return EINVAL;
    }
    do_check_object_locator(store, tenant, bucket_name, fix, remove_bad, formatter);
  } else {
    RGWBucketAdminOp::check_index(store, bucket_op, flusher);
  }
  return 0;
}

int handle_opt_bucket_rm(bool inconsistent_index, bool bypass_gc, bool yes_i_really_mean_it,
                         RGWBucketAdminOpState& bucket_op, RGWRados *store) {
  if (!inconsistent_index) {
    RGWBucketAdminOp::remove_bucket(store, bucket_op, bypass_gc, true);
  } else {
    if (!yes_i_really_mean_it) {
      cerr << "using --inconsistent_index can corrupt the bucket index " << std::endl
           << "do you really mean it? (requires --yes-i-really-mean-it)" << std::endl;
      return 1;
    }
    RGWBucketAdminOp::remove_bucket(store, bucket_op, bypass_gc, false);
  }
  return 0;
}

int handle_opt_bucket_sync_init(const string& source_zone, const string& bucket_name, const string& bucket_id,
                                const string& tenant, RGWBucketAdminOpState& bucket_op, RGWRados *store) {
  if (source_zone.empty()) {
    cerr << "ERROR: source zone not specified" << std::endl;
    return EINVAL;
  }
  if (bucket_name.empty()) {
    cerr << "ERROR: bucket not specified" << std::endl;
    return EINVAL;
  }
  rgw_bucket bucket;
  int ret = init_bucket_for_sync(store, tenant, bucket_name, bucket_id, bucket);
  if (ret < 0) {
    return -ret;
  }
  RGWBucketSyncStatusManager sync(store, source_zone, bucket);

  ret = sync.init();
  if (ret < 0) {
    cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
    return -ret;
  }
  ret = sync.init_sync_status();
  if (ret < 0) {
    cerr << "ERROR: sync.init_sync_status() returned ret=" << ret << std::endl;
    return -ret;
  }
  return 0;
}

int handle_opt_bucket_sync_status(const string& source_zone, const string& bucket_name, const string& bucket_id,
                                  const string& tenant, RGWBucketAdminOpState& bucket_op, RGWRados *store, Formatter *formatter) {
  if (source_zone.empty()) {
    cerr << "ERROR: source zone not specified" << std::endl;
    return EINVAL;
  }
  if (bucket_name.empty()) {
    cerr << "ERROR: bucket not specified" << std::endl;
    return EINVAL;
  }
  rgw_bucket bucket;
  int ret = init_bucket_for_sync(store, tenant, bucket_name, bucket_id, bucket);
  if (ret < 0) {
    return -ret;
  }
  RGWBucketSyncStatusManager sync(store, source_zone, bucket);

  ret = sync.init();
  if (ret < 0) {
    cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
    return -ret;
  }
  ret = sync.read_sync_status();
  if (ret < 0) {
    cerr << "ERROR: sync.read_sync_status() returned ret=" << ret << std::endl;
    return -ret;
  }

  map<int, rgw_bucket_shard_sync_info>& sync_status = sync.get_sync_status();

  encode_json("sync_status", sync_status, formatter);
  formatter->flush(cout);

  return 0;
}

int handle_opt_bucket_sync_run(const string& source_zone, const string& bucket_name, const string& bucket_id,
                               const string& tenant, RGWBucketAdminOpState& bucket_op, RGWRados *store) {
  if (source_zone.empty()) {
    cerr << "ERROR: source zone not specified" << std::endl;
    return EINVAL;
  }
  if (bucket_name.empty()) {
    cerr << "ERROR: bucket not specified" << std::endl;
    return EINVAL;
  }
  rgw_bucket bucket;
  int ret = init_bucket_for_sync(store, tenant, bucket_name, bucket_id, bucket);
  if (ret < 0) {
    return -ret;
  }
  RGWBucketSyncStatusManager sync(store, source_zone, bucket);

  ret = sync.init();
  if (ret < 0) {
    cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
    return -ret;
  }

  ret = sync.run();
  if (ret < 0) {
    cerr << "ERROR: sync.run() returned ret=" << ret << std::endl;
    return -ret;
  }
  return 0;
}
