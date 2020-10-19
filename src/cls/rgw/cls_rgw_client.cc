// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>

#include "cls/rgw/cls_rgw_const.h"
#include "cls/rgw/cls_rgw_client.h"

#include "common/debug.h"

using std::list;
using std::map;
using std::pair;
using std::string;
using std::vector;

using ceph::real_time;

using namespace librados;

const string BucketIndexShardsManager::KEY_VALUE_SEPARATOR = "#";
const string BucketIndexShardsManager::SHARDS_SEPARATOR = ",";

/**
 * This class represents the bucket index object operation callback context.
 */
template <typename T>
class ClsBucketIndexOpCtx : public ObjectOperationCompletion {
private:
  T *data;
  int *ret_code;
public:
  ClsBucketIndexOpCtx(T* _data, int *_ret_code) : data(_data), ret_code(_ret_code) { ceph_assert(data); }
  ~ClsBucketIndexOpCtx() override {}
  void handle_completion(int r, bufferlist& outbl) override {
    if (r >= 0) {
      try {
        auto iter = outbl.cbegin();
        decode((*data), iter);
      } catch (ceph::buffer::error& err) {
        r = -EIO;
      }
    }
    if (ret_code) {
      *ret_code = r;
    }
  }
};

void BucketIndexAioManager::do_completion(int id) {
  std::lock_guard l{lock};

  auto iter = pendings.find(id);
  ceph_assert(iter != pendings.end());
  completions[id] = iter->second;
  pendings.erase(iter);

  // If the caller needs a list of finished objects, store them
  // for further processing
  auto miter = pending_objs.find(id);
  if (miter != pending_objs.end()) {
    completion_objs[id] = miter->second;
    pending_objs.erase(miter);
  }

  cond.notify_all();
}

bool BucketIndexAioManager::wait_for_completions(int valid_ret_code,
    int *num_completions, int *ret_code, map<int, string> *objs) {
  std::unique_lock locker{lock};
  if (pendings.empty() && completions.empty()) {
    return false;
  }

  if (completions.empty()) {
    // Wait for AIO completion
    cond.wait(locker);
  }

  // Clear the completed AIOs
  auto iter = completions.begin();
  for (; iter != completions.end(); ++iter) {
    int r = iter->second->get_return_value();
    if (objs && r == 0) { /* update list of successfully completed objs */
      auto liter = completion_objs.find(iter->first);
      if (liter != completion_objs.end()) {
        (*objs)[liter->first] = liter->second;
      }
    }
    if (ret_code && (r < 0 && r != valid_ret_code))
      (*ret_code) = r;
    iter->second->release();
  }
  if (num_completions)
    (*num_completions) = completions.size();
  completions.clear();

  return true;
}

// note: currently only called by tesing code
void cls_rgw_bucket_init_index(ObjectWriteOperation& o)
{
  bufferlist in;
  o.exec(RGW_CLASS, RGW_BUCKET_INIT_INDEX, in);
}

static bool issue_bucket_index_init_op(librados::IoCtx& io_ctx,
				       const string& oid,
				       BucketIndexAioManager *manager) {
  bufferlist in;
  librados::ObjectWriteOperation op;
  op.create(true);
  op.exec(RGW_CLASS, RGW_BUCKET_INIT_INDEX, in);
  return manager->aio_operate(io_ctx, oid, &op);
}

static bool issue_bucket_index_clean_op(librados::IoCtx& io_ctx,
					const string& oid,
					BucketIndexAioManager *manager) {
  bufferlist in;
  librados::ObjectWriteOperation op;
  op.remove();
  return manager->aio_operate(io_ctx, oid, &op);
}

static bool issue_bucket_set_tag_timeout_op(librados::IoCtx& io_ctx,
    const string& oid, uint64_t timeout, BucketIndexAioManager *manager) {
  bufferlist in;
  rgw_cls_tag_timeout_op call;
  call.tag_timeout = timeout;
  encode(call, in);
  ObjectWriteOperation op;
  op.exec(RGW_CLASS, RGW_BUCKET_SET_TAG_TIMEOUT, in);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBucketIndexInit::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_index_init_op(io_ctx, oid, &manager);
}

void CLSRGWIssueBucketIndexInit::cleanup()
{
  // Do best effort removal
  for (auto citer = objs_container.begin(); citer != iter; ++citer) {
    io_ctx.remove(citer->second);
  }
}

int CLSRGWIssueBucketIndexClean::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_index_clean_op(io_ctx, oid, &manager);
}

int CLSRGWIssueSetTagTimeout::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_set_tag_timeout_op(io_ctx, oid, tag_timeout, &manager);
}

void cls_rgw_bucket_update_stats(librados::ObjectWriteOperation& o,
				 bool absolute,
                                 const map<RGWObjCategory, rgw_bucket_category_stats>& stats)
{
  rgw_cls_bucket_update_stats_op call;
  call.absolute = absolute;
  call.stats = stats;
  bufferlist in;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_BUCKET_UPDATE_STATS, in);
}

void cls_rgw_bucket_prepare_op(ObjectWriteOperation& o, RGWModifyOp op, string& tag,
                               const cls_rgw_obj_key& key, const string& locator,
                               const rgw_zone_set& zones_trace)
{
  rgw_cls_obj_prepare_op call;
  call.op = op;
  call.tag = tag;
  call.key = key;
  call.locator = locator;
  call.zones_trace = zones_trace;
  bufferlist in;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_BUCKET_PREPARE_OP, in);
}

void CLSRGWCompleteModifyOpBase::complete_op(librados::ObjectWriteOperation& o,
                                             const rgw_bucket_entry_ver& ver,
                                             const rgw_bucket_dir_entry_meta& dir_meta,
                                             const std::list<cls_rgw_obj_key> *remove_objs) const
{
  bufferlist in;
  rgw_cls_obj_complete_op call;
  call.op = this->op;
  call.op_tag = this->op_tag;
  call.key = this->key;
  call.ver = ver;
  call.meta = dir_meta;
  call.log_op = this->log_op;
  call.bilog_flags = this->bilog_flags;
  if (remove_objs)
    call.remove_objs = *remove_objs;
  call.zones_trace = this->zones_trace;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_BUCKET_COMPLETE_OP, in);
}

void cls_rgw_bucket_list_op(librados::ObjectReadOperation& op,
                            const cls_rgw_obj_key& start_obj,
                            const std::string& filter_prefix,
                            const std::string& delimiter,
                            uint32_t num_entries,
                            bool list_versions,
                            rgw_cls_list_ret* result)
{
  bufferlist in;
  rgw_cls_list_op call;
  call.start_obj = start_obj;
  call.filter_prefix = filter_prefix;
  call.delimiter = delimiter;
  call.num_entries = num_entries;
  call.list_versions = list_versions;
  encode(call, in);

  op.exec(RGW_CLASS, RGW_BUCKET_LIST, in,
	  new ClsBucketIndexOpCtx<rgw_cls_list_ret>(result, NULL));
}

static bool issue_bucket_list_op(librados::IoCtx& io_ctx,
				 const string& oid,
				 const cls_rgw_obj_key& start_obj,
				 const string& filter_prefix,
				 const string& delimiter,
				 uint32_t num_entries,
				 bool list_versions,
				 BucketIndexAioManager *manager,
				 rgw_cls_list_ret *pdata)
{
  librados::ObjectReadOperation op;
  cls_rgw_bucket_list_op(op,
			 start_obj, filter_prefix, delimiter,
                         num_entries, list_versions, pdata);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBucketList::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_list_op(io_ctx, oid,
			      start_obj, filter_prefix, delimiter,
			      num_entries, list_versions, &manager,
			      &result[shard_id]);
}

void cls_rgw_remove_obj(librados::ObjectWriteOperation& o, list<string>& keep_attr_prefixes)
{
  bufferlist in;
  rgw_cls_obj_remove_op call;
  call.keep_attr_prefixes = keep_attr_prefixes;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_OBJ_REMOVE, in);
}

void cls_rgw_obj_store_pg_ver(librados::ObjectWriteOperation& o, const string& attr)
{
  bufferlist in;
  rgw_cls_obj_store_pg_ver_op call;
  call.attr = attr;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_OBJ_STORE_PG_VER, in);
}

void cls_rgw_obj_check_attrs_prefix(librados::ObjectOperation& o, const string& prefix, bool fail_if_exist)
{
  bufferlist in;
  rgw_cls_obj_check_attrs_prefix call;
  call.check_prefix = prefix;
  call.fail_if_exist = fail_if_exist;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_OBJ_CHECK_ATTRS_PREFIX, in);
}

void cls_rgw_obj_check_mtime(librados::ObjectOperation& o, const real_time& mtime, bool high_precision_time, RGWCheckMTimeType type)
{
  bufferlist in;
  rgw_cls_obj_check_mtime call;
  call.mtime = mtime;
  call.high_precision_time = high_precision_time;
  call.type = type;
  encode(call, in);
  o.exec(RGW_CLASS, RGW_OBJ_CHECK_MTIME, in);
}

int cls_rgw_bi_get(librados::IoCtx& io_ctx, const string oid,
                   BIIndexType index_type, cls_rgw_obj_key& key,
                   rgw_cls_bi_entry *entry)
{
  bufferlist in, out;
  rgw_cls_bi_get_op call;
  call.key = key;
  call.type = index_type;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_BI_GET, in, out);
  if (r < 0)
    return r;

  rgw_cls_bi_get_ret op_ret;
  auto iter = out.cbegin();
  try {
    decode(op_ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  *entry = op_ret.entry;

  return 0;
}

int cls_rgw_bi_put(librados::IoCtx& io_ctx, const string oid, rgw_cls_bi_entry& entry)
{
  bufferlist in, out;
  rgw_cls_bi_put_op call;
  call.entry = entry;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_BI_PUT, in, out);
  if (r < 0)
    return r;

  return 0;
}

void cls_rgw_bi_put(ObjectWriteOperation& op, const string oid, rgw_cls_bi_entry& entry)
{
  bufferlist in, out;
  rgw_cls_bi_put_op call;
  call.entry = entry;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BI_PUT, in);
}

int cls_rgw_bi_list(librados::IoCtx& io_ctx, const string oid,
                   const string& name, const string& marker, uint32_t max,
                   list<rgw_cls_bi_entry> *entries, bool *is_truncated)
{
  bufferlist in, out;
  rgw_cls_bi_list_op call;
  call.name = name;
  call.marker = marker;
  call.max = max;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_BI_LIST, in, out);
  if (r < 0)
    return r;

  rgw_cls_bi_list_ret op_ret;
  auto iter = out.cbegin();
  try {
    decode(op_ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  entries->swap(op_ret.entries);
  *is_truncated = op_ret.is_truncated;

  return 0;
}

void CLSRGWLinkOLHBase::link_olh(librados::ObjectWriteOperation& op,
                                 ceph::bufferlist& olh_tag,
                                 const rgw_bucket_dir_entry_meta *meta,
                                 uint64_t olh_epoch,
                                 ceph::real_time unmod_since,
                                 bool high_precision_time) const
{
  ceph::bufferlist in, out;
  rgw_cls_link_olh_op call;
  call.key = this->key;
  call.olh_tag = std::string(olh_tag.c_str(), olh_tag.length());
  call.op_tag = this->op_tag;
  call.op = this->op;
  if (meta) {
    call.meta = *meta;
  }
  call.olh_epoch = olh_epoch;
  call.log_op = this->log_op;
  call.unmod_since = unmod_since;
  call.high_precision_time = high_precision_time;
  call.zones_trace = this->zones_trace;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BUCKET_LINK_OLH, in);
}

void CLSRGWUnlinkInstance::unlink_instance(librados::ObjectWriteOperation& op,
                                           const std::string& olh_tag,
                                           uint64_t olh_epoch) const
{
  ceph::bufferlist in, out;
  rgw_cls_unlink_instance_op call;
  call.key = this->key;
  call.op_tag = this->op_tag;
  call.olh_epoch = olh_epoch;
  call.olh_tag = olh_tag;
  call.log_op = this->log_op;
  call.zones_trace = this->zones_trace;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BUCKET_UNLINK_INSTANCE, in);
}

void cls_rgw_get_olh_log(librados::ObjectReadOperation& op, const cls_rgw_obj_key& olh, uint64_t ver_marker, const string& olh_tag, rgw_cls_read_olh_log_ret& log_ret, int& op_ret)
{
  bufferlist in;
  rgw_cls_read_olh_log_op call;
  call.olh = olh;
  call.ver_marker = ver_marker;
  call.olh_tag = olh_tag;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BUCKET_READ_OLH_LOG, in, new ClsBucketIndexOpCtx<rgw_cls_read_olh_log_ret>(&log_ret, &op_ret));
}

void cls_rgw_trim_olh_log(librados::ObjectWriteOperation& op, const cls_rgw_obj_key& olh, uint64_t ver, const string& olh_tag)
{
  bufferlist in;
  rgw_cls_trim_olh_log_op call;
  call.olh = olh;
  call.ver = ver;
  call.olh_tag = olh_tag;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BUCKET_TRIM_OLH_LOG, in);
}

void cls_rgw_clear_olh(librados::ObjectWriteOperation& op, const cls_rgw_obj_key& olh, const string& olh_tag)
{
  bufferlist in;
  rgw_cls_bucket_clear_olh_op call;
  call.key = olh;
  call.olh_tag = olh_tag;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BUCKET_CLEAR_OLH, in);
}

void cls_rgw_bilog_list(librados::ObjectReadOperation& op,
                        const std::string& marker, uint32_t max,
                        cls_rgw_bi_log_list_ret *pdata, int *ret)
{
  cls_rgw_bi_log_list_op call;
  call.marker = marker;
  call.max = max;

  bufferlist in;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BI_LOG_LIST, in, new ClsBucketIndexOpCtx<cls_rgw_bi_log_list_ret>(pdata, ret));
}

static bool issue_bi_log_list_op(librados::IoCtx& io_ctx, const string& oid, int shard_id,
                                 BucketIndexShardsManager& marker_mgr, uint32_t max,
                                 BucketIndexAioManager *manager,
                                 cls_rgw_bi_log_list_ret *pdata)
{
  librados::ObjectReadOperation op;
  cls_rgw_bilog_list(op, marker_mgr.get(shard_id, ""), max, pdata, nullptr);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBILogList::issue_op(int shard_id, const string& oid)
{
  return issue_bi_log_list_op(io_ctx, oid, shard_id, marker_mgr, max, &manager, &result[shard_id]);
}

void cls_rgw_bilog_trim(librados::ObjectWriteOperation& op,
                        const std::string& start_marker,
                        const std::string& end_marker)
{
  cls_rgw_bi_log_trim_op call;
  call.start_marker = start_marker;
  call.end_marker = end_marker;

  bufferlist in;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_BI_LOG_TRIM, in);
}

static bool issue_bi_log_trim(librados::IoCtx& io_ctx, const string& oid, int shard_id,
                              BucketIndexShardsManager& start_marker_mgr,
                              BucketIndexShardsManager& end_marker_mgr, BucketIndexAioManager *manager) {
  cls_rgw_bi_log_trim_op call;
  librados::ObjectWriteOperation op;
  cls_rgw_bilog_trim(op, start_marker_mgr.get(shard_id, ""),
                     end_marker_mgr.get(shard_id, ""));
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBILogTrim::issue_op(int shard_id, const string& oid)
{
  return issue_bi_log_trim(io_ctx, oid, shard_id, start_marker_mgr, end_marker_mgr, &manager);
}

static bool issue_bucket_check_index_op(IoCtx& io_ctx, const string& oid, BucketIndexAioManager *manager,
    rgw_cls_check_index_ret *pdata) {
  bufferlist in;
  librados::ObjectReadOperation op;
  op.exec(RGW_CLASS, RGW_BUCKET_CHECK_INDEX, in, new ClsBucketIndexOpCtx<rgw_cls_check_index_ret>(
        pdata, NULL));
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBucketCheck::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_check_index_op(io_ctx, oid, &manager, &result[shard_id]);
}

static bool issue_bucket_rebuild_index_op(IoCtx& io_ctx, const string& oid,
    BucketIndexAioManager *manager) {
  bufferlist in;
  librados::ObjectWriteOperation op;
  op.exec(RGW_CLASS, RGW_BUCKET_REBUILD_INDEX, in);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueBucketRebuild::issue_op(int shard_id, const string& oid)
{
  return issue_bucket_rebuild_index_op(io_ctx, oid, &manager);
}

void cls_rgw_encode_suggestion(char op, rgw_bucket_dir_entry& dirent, bufferlist& updates)
{
  updates.append(op);
  encode(dirent, updates);
}

void cls_rgw_suggest_changes(ObjectWriteOperation& o, bufferlist& updates)
{
  o.exec(RGW_CLASS, RGW_DIR_SUGGEST_CHANGES, updates);
}

int CLSRGWIssueGetDirHeader::issue_op(int shard_id, const string& oid)
{
  cls_rgw_obj_key empty_key;
  string empty_prefix;
  string empty_delimiter;
  return issue_bucket_list_op(io_ctx, oid,
			      empty_key, empty_prefix, empty_delimiter,
			      0, false, &manager, &result[shard_id]);
}

static bool issue_resync_bi_log(librados::IoCtx& io_ctx, const string& oid, BucketIndexAioManager *manager)
{
  bufferlist in;
  librados::ObjectWriteOperation op;
  op.exec(RGW_CLASS, RGW_BI_LOG_RESYNC, in);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueResyncBucketBILog::issue_op(int shard_id, const string& oid)
{
  return issue_resync_bi_log(io_ctx, oid, &manager);
}

static bool issue_bi_log_stop(librados::IoCtx& io_ctx, const string& oid, BucketIndexAioManager *manager)
{
  bufferlist in;
  librados::ObjectWriteOperation op;
  op.exec(RGW_CLASS, RGW_BI_LOG_STOP, in);
  return manager->aio_operate(io_ctx, oid, &op); 
}

int CLSRGWIssueBucketBILogStop::issue_op(int shard_id, const string& oid)
{
  return issue_bi_log_stop(io_ctx, oid, &manager);
}

class GetDirHeaderCompletion : public ObjectOperationCompletion {
  RGWGetDirHeader_CB *ret_ctx;
public:
  explicit GetDirHeaderCompletion(RGWGetDirHeader_CB *_ctx) : ret_ctx(_ctx) {}
  ~GetDirHeaderCompletion() override {
    ret_ctx->put();
  }
  void handle_completion(int r, bufferlist& outbl) override {
    rgw_cls_list_ret ret;
    try {
      auto iter = outbl.cbegin();
      decode(ret, iter);
    } catch (ceph::buffer::error& err) {
      r = -EIO;
    }

    ret_ctx->handle_response(r, ret.dir.header);
  }
};

int cls_rgw_get_dir_header_async(IoCtx& io_ctx, string& oid, RGWGetDirHeader_CB *ctx)
{
  bufferlist in, out;
  rgw_cls_list_op call;
  call.num_entries = 0;
  encode(call, in);
  ObjectReadOperation op;
  GetDirHeaderCompletion *cb = new GetDirHeaderCompletion(ctx);
  op.exec(RGW_CLASS, RGW_BUCKET_LIST, in, cb);
  AioCompletion *c = librados::Rados::aio_create_completion(nullptr, nullptr);
  int r = io_ctx.aio_operate(oid, c, &op, NULL);
  c->release();
  if (r < 0)
    return r;

  return 0;
}

int cls_rgw_usage_log_read(IoCtx& io_ctx, const string& oid, const string& user, const string& bucket,
                           uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                           string& read_iter, map<rgw_user_bucket, rgw_usage_log_entry>& usage,
                           bool *is_truncated)
{
  if (is_truncated)
    *is_truncated = false;

  bufferlist in, out;
  rgw_cls_usage_log_read_op call;
  call.start_epoch = start_epoch;
  call.end_epoch = end_epoch;
  call.owner = user;
  call.max_entries = max_entries;
  call.bucket = bucket;
  call.iter = read_iter;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_USER_USAGE_LOG_READ, in, out);
  if (r < 0)
    return r;

  try {
    rgw_cls_usage_log_read_ret result;
    auto iter = out.cbegin();
    decode(result, iter);
    read_iter = result.next_iter;
    if (is_truncated)
      *is_truncated = result.truncated;

    usage = result.usage;
  } catch (ceph::buffer::error& e) {
    return -EINVAL;
  }

  return 0;
}

void cls_rgw_usage_log_trim(librados::ObjectWriteOperation& op, const string& user, const string& bucket, uint64_t start_epoch, uint64_t end_epoch)
{
  bufferlist in;
  rgw_cls_usage_log_trim_op call;
  call.start_epoch = start_epoch;
  call.end_epoch = end_epoch;
  call.user = user;
  call.bucket = bucket;
  encode(call, in);

  op.exec(RGW_CLASS, RGW_USER_USAGE_LOG_TRIM, in);
}

void cls_rgw_usage_log_clear(ObjectWriteOperation& op)
{
  bufferlist in;
  op.exec(RGW_CLASS, RGW_USAGE_LOG_CLEAR, in);
}

void cls_rgw_usage_log_add(ObjectWriteOperation& op, rgw_usage_log_info& info)
{
  bufferlist in;
  rgw_cls_usage_log_add_op call;
  call.info = info;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_USER_USAGE_LOG_ADD, in);
}

/* garbage collection */

void cls_rgw_gc_set_entry(ObjectWriteOperation& op, uint32_t expiration_secs, cls_rgw_gc_obj_info& info)
{
  bufferlist in;
  cls_rgw_gc_set_entry_op call;
  call.expiration_secs = expiration_secs;
  call.info = info;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_GC_SET_ENTRY, in);
}

void cls_rgw_gc_defer_entry(ObjectWriteOperation& op, uint32_t expiration_secs, const string& tag)
{
  bufferlist in;
  cls_rgw_gc_defer_entry_op call;
  call.expiration_secs = expiration_secs;
  call.tag = tag;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_GC_DEFER_ENTRY, in);
}

int cls_rgw_gc_list(IoCtx& io_ctx, string& oid, string& marker, uint32_t max, bool expired_only,
                    list<cls_rgw_gc_obj_info>& entries, bool *truncated, string& next_marker)
{
  bufferlist in, out;
  cls_rgw_gc_list_op call;
  call.marker = marker;
  call.max = max;
  call.expired_only = expired_only;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_GC_LIST, in, out);
  if (r < 0)
    return r;

  cls_rgw_gc_list_ret ret;
  try {
    auto iter = out.cbegin();
    decode(ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  entries.swap(ret.entries);

  if (truncated)
    *truncated = ret.truncated;
  next_marker = std::move(ret.next_marker);
  return r;
}

void cls_rgw_gc_remove(librados::ObjectWriteOperation& op, const vector<string>& tags)
{
  bufferlist in;
  cls_rgw_gc_remove_op call;
  call.tags = tags;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_GC_REMOVE, in);
}

int cls_rgw_lc_get_head(IoCtx& io_ctx, const string& oid, cls_rgw_lc_obj_head& head)
{
  bufferlist in, out;
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_GET_HEAD, in, out);
  if (r < 0)
    return r;

  cls_rgw_lc_get_head_ret ret;
  try {
    auto iter = out.cbegin();
    decode(ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }
  head = ret.head;

 return r;
}

int cls_rgw_lc_put_head(IoCtx& io_ctx, const string& oid, cls_rgw_lc_obj_head& head)
{
  bufferlist in, out;
  cls_rgw_lc_put_head_op call;
  call.head = head;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_PUT_HEAD, in, out);
  return r;
}

int cls_rgw_lc_get_next_entry(IoCtx& io_ctx, const string& oid, string& marker,
			      cls_rgw_lc_entry& entry)
{
  bufferlist in, out;
  cls_rgw_lc_get_next_entry_op call;
  call.marker = marker;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_GET_NEXT_ENTRY, in, out);
  if (r < 0)
    return r;

  cls_rgw_lc_get_next_entry_ret ret;
  try {
    auto iter = out.cbegin();
    decode(ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }
  entry = ret.entry;

 return r;
}

int cls_rgw_lc_rm_entry(IoCtx& io_ctx, const string& oid,
			const cls_rgw_lc_entry& entry)
{
  bufferlist in, out;
  cls_rgw_lc_rm_entry_op call;
  call.entry = entry;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_RM_ENTRY, in, out);
 return r;
}

int cls_rgw_lc_set_entry(IoCtx& io_ctx, const string& oid,
			 const cls_rgw_lc_entry& entry)
{
  bufferlist in, out;
  cls_rgw_lc_set_entry_op call;
  call.entry = entry;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_SET_ENTRY, in, out);
  return r;
}

int cls_rgw_lc_get_entry(IoCtx& io_ctx, const string& oid,
			 const std::string& marker, cls_rgw_lc_entry& entry)
{
  bufferlist in, out;
  cls_rgw_lc_get_entry_op call{marker};;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_GET_ENTRY, in, out);

  if (r < 0) {
    return r;
  }

  cls_rgw_lc_get_entry_ret ret;
  try {
    auto iter = out.cbegin();
    decode(ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  entry = std::move(ret.entry);
  return r;
}

int cls_rgw_lc_list(IoCtx& io_ctx, const string& oid,
                    const string& marker,
                    uint32_t max_entries,
                    vector<cls_rgw_lc_entry>& entries)
{
  bufferlist in, out;
  cls_rgw_lc_list_entries_op op;

  entries.clear();

  op.marker = marker;
  op.max_entries = max_entries;

  encode(op, in);

  int r = io_ctx.exec(oid, RGW_CLASS, RGW_LC_LIST_ENTRIES, in, out);
  if (r < 0)
    return r;

  cls_rgw_lc_list_entries_ret ret;
  try {
    auto iter = out.cbegin();
    decode(ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  std::sort(std::begin(ret.entries), std::end(ret.entries),
	    [](const cls_rgw_lc_entry& a, const cls_rgw_lc_entry& b)
	      { return a.bucket < b.bucket; });
  entries = std::move(ret.entries);
  return r;
}

void cls_rgw_reshard_add(librados::ObjectWriteOperation& op, const cls_rgw_reshard_entry& entry)
{
  bufferlist in;
  cls_rgw_reshard_add_op call;
  call.entry = entry;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_RESHARD_ADD, in);
}

int cls_rgw_reshard_list(librados::IoCtx& io_ctx, const string& oid, string& marker, uint32_t max,
                         list<cls_rgw_reshard_entry>& entries, bool* is_truncated)
{
  bufferlist in, out;
  cls_rgw_reshard_list_op call;
  call.marker = marker;
  call.max = max;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_RESHARD_LIST, in, out);
  if (r < 0)
    return r;

  cls_rgw_reshard_list_ret op_ret;
  auto iter = out.cbegin();
  try {
    decode(op_ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  entries.swap(op_ret.entries);
  *is_truncated = op_ret.is_truncated;

  return 0;
}

int cls_rgw_reshard_get(librados::IoCtx& io_ctx, const string& oid, cls_rgw_reshard_entry& entry)
{
  bufferlist in, out;
  cls_rgw_reshard_get_op call;
  call.entry = entry;
  encode(call, in);
  int r = io_ctx.exec(oid, RGW_CLASS, RGW_RESHARD_GET, in, out);
  if (r < 0)
    return r;

  cls_rgw_reshard_get_ret op_ret;
  auto iter = out.cbegin();
  try {
    decode(op_ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  entry = op_ret.entry;

  return 0;
}

void cls_rgw_reshard_remove(librados::ObjectWriteOperation& op, const cls_rgw_reshard_entry& entry)
{
  bufferlist in;
  cls_rgw_reshard_remove_op call;
  call.tenant = entry.tenant;
  call.bucket_name = entry.bucket_name;
  call.bucket_id = entry.bucket_id;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_RESHARD_REMOVE, in);
}

int cls_rgw_set_bucket_resharding(librados::IoCtx& io_ctx, const string& oid,
				  const cls_rgw_bucket_instance_entry& entry)
{
  bufferlist in, out;
  cls_rgw_set_bucket_resharding_op call;
  call.entry = entry;
  encode(call, in);
  return io_ctx.exec(oid, RGW_CLASS, RGW_SET_BUCKET_RESHARDING, in, out);
}

int cls_rgw_clear_bucket_resharding(librados::IoCtx& io_ctx, const string& oid)
{
  bufferlist in, out;
  cls_rgw_clear_bucket_resharding_op call;
  encode(call, in);
  return io_ctx.exec(oid, RGW_CLASS, RGW_CLEAR_BUCKET_RESHARDING, in, out);
}

int cls_rgw_get_bucket_resharding(librados::IoCtx& io_ctx, const string& oid,
				  cls_rgw_bucket_instance_entry *entry)
{
  bufferlist in, out;
  cls_rgw_get_bucket_resharding_op call;
  encode(call, in);
  int r= io_ctx.exec(oid, RGW_CLASS, RGW_GET_BUCKET_RESHARDING, in, out);
  if (r < 0)
    return r;

  cls_rgw_get_bucket_resharding_ret op_ret;
  auto iter = out.cbegin();
  try {
    decode(op_ret, iter);
  } catch (ceph::buffer::error& err) {
    return -EIO;
  }

  *entry = op_ret.new_instance;

  return 0;
}

void cls_rgw_guard_bucket_resharding(librados::ObjectOperation& op, int ret_err)
{
  bufferlist in, out;
  cls_rgw_guard_bucket_resharding_op call;
  call.ret_err = ret_err;
  encode(call, in);
  op.exec(RGW_CLASS, RGW_GUARD_BUCKET_RESHARDING, in);
}

static bool issue_set_bucket_resharding(librados::IoCtx& io_ctx, const string& oid,
                                        const cls_rgw_bucket_instance_entry& entry,
                                        BucketIndexAioManager *manager) {
  bufferlist in;
  cls_rgw_set_bucket_resharding_op call;
  call.entry = entry;
  encode(call, in);
  librados::ObjectWriteOperation op;
  op.exec(RGW_CLASS, RGW_SET_BUCKET_RESHARDING, in);
  return manager->aio_operate(io_ctx, oid, &op);
}

int CLSRGWIssueSetBucketResharding::issue_op(int shard_id, const string& oid)
{
  return issue_set_bucket_resharding(io_ctx, oid, entry, &manager);
}
