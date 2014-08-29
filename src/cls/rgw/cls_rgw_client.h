#ifndef CEPH_CLS_RGW_CLIENT_H
#define CEPH_CLS_RGW_CLIENT_H

#include "include/types.h"
#include "include/rados/librados.hpp"
#include "cls_rgw_types.h"
#include "common/RefCountedObj.h"

/*
 * This class manages AIO completions. This class is not completely thread-safe,
 * methods like *get_next* is not thread-safe and is expected to be called from
 * within one thread.
 */
class BucketIndexAioManager {
private:
  map<int, librados::AioCompletion*> pendings;
  list<librados::AioCompletion*> completions;
  int next;
  Mutex lock;
  Cond cond;
public:
  /*
   * Create a new instance.
   */
  BucketIndexAioManager() : pendings(), completions(), next(0),
      lock("BucketIndexAioManager::lock"), cond() {}

  /*
   * Add a new pending AIO completion instance.
   *
   * @param id         - the request ID.
   * @param completion - the AIO completion instance.
   */
  void add_pending(int id, librados::AioCompletion* completion) {
    Mutex::Locker l(lock);
    pendings[id] = completion;
  }

  /*
   * Do completion for the given AIO request.
   */
  void do_completion(int id);

  /*
   * Get next request ID. This method is not thread-safe.
   *
   * Return next request ID.
   */
  int get_next() { return next++; }

  /*
   * Wait for AIO completions.
   *
   * valid_ret_code  - valid AIO return code.
   * num_completions - number of completions.
   * ret_code        - return code of failed AIO.
   *
   * Return false if there is no pending AIO, true otherwise.
   */
  bool wait_for_completions(int valid_ret_code, int *num_completions, int *ret_code);
};

/*
 * Bucket index AIO request argument, this is used to pass a argument
 * to callback.
 */
struct BucketIndexAioArg : public RefCountedObject {
  BucketIndexAioArg(int _id, BucketIndexAioManager* _manager) :
    id(_id), manager(_manager) {}
  int id;
  BucketIndexAioManager* manager;
};

class RGWGetDirHeader_CB : public RefCountedObject {
public:
  virtual ~RGWGetDirHeader_CB() {}
  virtual void handle_response(int r, rgw_bucket_dir_header& header) = 0;
};

class BucketIndexShardsManager {
private:
  // Per shard setting manager, for example, marker.
  map<string, string> value_by_shards;
  const static char KEY_VALUE_SEPARATOR = '#';
  const static char SHARDS_SEPARATOR = ',';
public:
  void add_item(const string& shard, const string& value) {
    value_by_shards[shard] = value;
  }
  void to_string(string *out) const {
    if (out) {
      map<string, string>::const_iterator iter = value_by_shards.begin();
      // No shards
      if (value_by_shards.size() == 1) {
        *out = iter->second;
      } else {
        for (; iter != value_by_shards.end(); ++iter) {
          if (out->length()) {
            // Not the first item, append a separator first
            out->append(1, SHARDS_SEPARATOR);
          }
          out->append(iter->first);
          out->append(1, KEY_VALUE_SEPARATOR);
          out->append(iter->second);
        }
      }
    }
  }
};

/* bucket index */
void cls_rgw_bucket_init(librados::ObjectWriteOperation& o);

/**
 * Init bucket index objects.
 *
 * io_ctx      - IO context for rados.
 * bucket_objs - a lit of bucket index objects.
 * max_io      - the maximum number of AIO (for throttling).
 *
 * Reutrn 0 on success, a failure code otherwise.
 */
int cls_rgw_bucket_index_init_op(librados::IoCtx &io_ctx,
        const vector<string>& bucket_objs, uint32_t max_aio);

int cls_rgw_bucket_set_tag_timeout(librados::IoCtx& io_ctx,
    const vector<string>& bucket_objs, uint64_t tag_timeout, uint32_t max_aio);

void cls_rgw_bucket_prepare_op(librados::ObjectWriteOperation& o, RGWModifyOp op, string& tag,
                               string& name, string& locator, bool log_op);

void cls_rgw_bucket_complete_op(librados::ObjectWriteOperation& o, RGWModifyOp op, string& tag,
                                rgw_bucket_entry_ver& ver, string& name, rgw_bucket_dir_entry_meta& dir_meta,
				list<string> *remove_objs, bool log_op);

/**
 * List the bucket with the starting object and filter prefix.
 * NOTE: this method do listing requests for each bucket index shards identified by
 *       the keys of the *list_results* map, which means the map should be popludated
 *       by the caller to fill with each bucket index object id.
 *
 * io_ctx        - IO context for rados.
 * start_obj     - marker for the listing.
 * filter_prefix - filter prefix.
 * num_entries   - number of entries to request for each object (note the total
 *                 amount of entries returned depends on the number of shardings).
 * list_results  - the list results keyed by bucket index object id.
 * max_aio       - the maximum number of AIO (for throttling).
 *
 * Return 0 on success, a failure code otherwise.
*/
int cls_rgw_list_op(librados::IoCtx& io_ctx, const string & start_obj,
                    const string& filter_prefix, uint32_t num_entries,
                    map<string, struct rgw_cls_list_ret>& list_results,
                    uint32_t max_aio);

/**
 * Check the bucket index.
 *
 * io_ctx          - IO context for rados.
 * bucket_objs_ret - check result for all shards.
 * max_aio         - the maximum number of AIO (for throttling).
 *
 * Return 0 on success, a failure code otherwise.
 */
int cls_rgw_bucket_check_index_op(librados::IoCtx& io_ctx,
    map<string, struct rgw_cls_check_index_ret>& bucket_objs_ret, uint32_t max_aio);
int cls_rgw_bucket_rebuild_index_op(librados::IoCtx& io_ctx, const vector<string>& bucket_objs,
    uint32_t max_aio);
  
int cls_rgw_get_dir_header(librados::IoCtx& io_ctx, map<string, rgw_cls_list_ret>& dir_headers,
    uint32_t max_aio);
int cls_rgw_get_dir_header_async(librados::IoCtx& io_ctx, string& oid, RGWGetDirHeader_CB *ctx);

void cls_rgw_encode_suggestion(char op, rgw_bucket_dir_entry& dirent, bufferlist& updates);

void cls_rgw_suggest_changes(librados::ObjectWriteOperation& o, bufferlist& updates);

/* bucket index log */

int cls_rgw_bi_log_list(librados::IoCtx& io_ctx, string& oid, string& marker, uint32_t max,
                    list<rgw_bi_log_entry>& entries, bool *truncated);
int cls_rgw_bi_log_trim(librados::IoCtx& io_ctx, string& oid, string& start_marker, string& end_marker);

/* usage logging */
int cls_rgw_usage_log_read(librados::IoCtx& io_ctx, string& oid, string& user,
                           uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                           string& read_iter, map<rgw_user_bucket, rgw_usage_log_entry>& usage,
                           bool *is_truncated);

void cls_rgw_usage_log_trim(librados::ObjectWriteOperation& op, string& user,
                           uint64_t start_epoch, uint64_t end_epoch);

void cls_rgw_usage_log_add(librados::ObjectWriteOperation& op, rgw_usage_log_info& info);

/* garbage collection */
void cls_rgw_gc_set_entry(librados::ObjectWriteOperation& op, uint32_t expiration_secs, cls_rgw_gc_obj_info& info);
void cls_rgw_gc_defer_entry(librados::ObjectWriteOperation& op, uint32_t expiration_secs, const string& tag);

int cls_rgw_gc_list(librados::IoCtx& io_ctx, string& oid, string& marker, uint32_t max, bool expired_only,
                    list<cls_rgw_gc_obj_info>& entries, bool *truncated);

void cls_rgw_gc_remove(librados::ObjectWriteOperation& op, const list<string>& tags);

#endif
