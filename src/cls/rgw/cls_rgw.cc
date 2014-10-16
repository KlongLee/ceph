// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/int_types.h"
#include "include/types.h"

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "include/utime.h"
#include "objclass/objclass.h"
#include "cls/rgw/cls_rgw_ops.h"
#include "common/Clock.h"
#include "common/strtol.h"

#include "global/global_context.h"

CLS_VER(1,0)
CLS_NAME(rgw)

cls_handle_t h_class;
cls_method_handle_t h_rgw_bucket_init_index;
cls_method_handle_t h_rgw_bucket_set_tag_timeout;
cls_method_handle_t h_rgw_bucket_list;
cls_method_handle_t h_rgw_bucket_check_index;
cls_method_handle_t h_rgw_bucket_rebuild_index;
cls_method_handle_t h_rgw_bucket_prepare_op;
cls_method_handle_t h_rgw_bucket_complete_op;
cls_method_handle_t h_rgw_bucket_link_olh;
cls_method_handle_t h_rgw_bucket_read_olh_log;
cls_method_handle_t h_rgw_bucket_trim_olh_log;
cls_method_handle_t h_rgw_obj_remove;
cls_method_handle_t h_rgw_bi_log_list_op;
cls_method_handle_t h_rgw_dir_suggest_changes;
cls_method_handle_t h_rgw_user_usage_log_add;
cls_method_handle_t h_rgw_user_usage_log_read;
cls_method_handle_t h_rgw_user_usage_log_trim;
cls_method_handle_t h_rgw_gc_set_entry;
cls_method_handle_t h_rgw_gc_list;
cls_method_handle_t h_rgw_gc_remove;


#define ROUND_BLOCK_SIZE 4096


#define BI_PREFIX_CHAR 0x80

#define BI_BUCKET_OBJS_INDEX          0
#define BI_BUCKET_LOG_INDEX           1
#define BI_BUCKET_OBJ_INSTANCE_INDEX  2
#define BI_BUCKET_OLH_DATA_INDEX      3

#define BI_BUCKET_LAST_INDEX          4

static string bucket_index_prefixes[] = { "", /* special handling for the objs list index */
                                          "0_",     /* bucket log index */
                                          "1000_",  /* obj instance index */
                                          "1001_",  /* olh data index */

                                          /* this must be the last index */
                                          "9999_",};

static uint64_t get_rounded_size(uint64_t size)
{
  return (size + ROUND_BLOCK_SIZE - 1) & ~(ROUND_BLOCK_SIZE - 1);
}

static bool bi_is_objs_index(const string& s) {
  return ((unsigned char)s[0] != BI_PREFIX_CHAR);
}

int bi_entry_type(const string& s)
{
  if (bi_is_objs_index(s)) {
    return BI_BUCKET_OBJS_INDEX;
  }

  for (size_t i = 1;
       i < sizeof(bucket_index_prefixes) / sizeof(bucket_index_prefixes[0]);
       ++i) {
    const string& t = bucket_index_prefixes[i];

    if (s.compare(0, t.size(), t) == 0) {
      return i;
    }
  }

  return -EINVAL;
}

static void get_time_key(utime_t& ut, string *key)
{
  char buf[32];
  snprintf(buf, 32, "%011llu.%09u", (unsigned long long)ut.sec(), ut.nsec());
  *key = buf;
}

static void get_index_ver_key(cls_method_context_t hctx, uint64_t index_ver, string *key)
{
  char buf[48];
  snprintf(buf, sizeof(buf), "%011llu.%llu.%d", (unsigned long long)index_ver,
           (unsigned long long)cls_current_version(hctx),
           cls_current_subop_num(hctx));
  *key = buf;
}

static void bi_log_index_key(cls_method_context_t hctx, string& key, string& id, uint64_t index_ver)
{
  key = BI_PREFIX_CHAR;
  key.append(bucket_index_prefixes[BI_BUCKET_LOG_INDEX]);

  get_index_ver_key(hctx, index_ver, &id);
  key.append(id);
}

static int log_index_operation(cls_method_context_t hctx, cls_rgw_obj_key& obj_key, RGWModifyOp op,
                               string& tag, utime_t& timestamp,
                               rgw_bucket_entry_ver& ver, RGWPendingState state, uint64_t index_ver,
                               string& max_marker)
{
  bufferlist bl;

  struct rgw_bi_log_entry entry;

  entry.object = obj_key.name;
  entry.instance = obj_key.instance;
  entry.timestamp = timestamp;
  entry.op = op;
  entry.ver = ver;
  entry.state = state;
  entry.index_ver = index_ver;
  entry.tag = tag;

  string key;
  bi_log_index_key(hctx, key, entry.id, index_ver);

  ::encode(entry, bl);

  if (entry.id > max_marker)
    max_marker = entry.id;

  return cls_cxx_map_set_val(hctx, key, &bl);
}

/*
 * read list of objects, skips objects in the ugly namespace
 */
static int get_obj_vals(cls_method_context_t hctx, const string& start, const string& filter_prefix,
                        int num_entries, map<string, bufferlist> *pkeys)
{
  int ret = cls_cxx_map_get_vals(hctx, start, filter_prefix, num_entries, pkeys);
  if (ret < 0)
    return ret;

  if (pkeys->empty())
    return 0;

  map<string, bufferlist>::reverse_iterator last_element = pkeys->rbegin();
  if ((unsigned char)last_element->first[0] < BI_PREFIX_CHAR) {
    /* nothing to see here, move along */
    return 0;
  }

  map<string, bufferlist>::iterator first_element = pkeys->begin();
  if ((unsigned char)first_element->first[0] > BI_PREFIX_CHAR) {
    return 0;
  }

  /* let's rebuild the list, only keep entries we're interested in */
  map<string, bufferlist> old_keys;
  old_keys.swap(*pkeys);

  for (map<string, bufferlist>::iterator iter = old_keys.begin(); iter != old_keys.end(); ++iter) {
    if ((unsigned char)iter->first[0] != BI_PREFIX_CHAR) {
      (*pkeys)[iter->first] = iter->second;
    }
  }

  if (num_entries == (int)pkeys->size())
    return 0;

  map<string, bufferlist> new_keys;
  char c[] = { (char)(BI_PREFIX_CHAR + 1), 0 };
  string new_start = c;

  /* now get some more keys */
  ret = cls_cxx_map_get_vals(hctx, new_start, filter_prefix, num_entries - pkeys->size(), &new_keys);
  if (ret < 0)
    return ret;

  for (map<string, bufferlist>::iterator iter = new_keys.begin(); iter != new_keys.end(); ++iter) {
    (*pkeys)[iter->first] = iter->second;
  }

  return 0;
}

/*
 * get a monotonically decreasing string representation.
 * For num = x, num = y, where x > y, str(x) < str(y)
 * Another property is that string size starts short and grows as num increases
 */
static void decreasing_str(uint64_t num, string *str)
{
  char buf[32];
  if (num < 0x10) { /* 16 */
    snprintf(buf, sizeof(buf), "9%02lld", 15 - (long long)num);
  } else if (num < 0x100) { /* 256 */
    snprintf(buf, sizeof(buf), "8%03lld", 255 - (long long)num);
  } else if (num < 0x1000) /* 4096 */ {
    snprintf(buf, sizeof(buf), "7%04lld", 4095 - (long long)num);
  } else if (num < 0x10000) /* 65536 */ {
    snprintf(buf, sizeof(buf), "6%05lld", 65535 - (long long)num);
  } else if (num < 0x100000000) /* 4G */ {
    snprintf(buf, sizeof(buf), "5%010lld", 0xFFFFFFFF - (long long)num);
  } else {
    snprintf(buf, sizeof(buf), "4%020lld",  (long long)-num);
  }

  *str = buf;
}

/*
 * we now hold two different indexes for objects. The first one holds the list of objects in the
 * order that we want them to be listed. The second one only holds the objects instances (for
 * versioned objects), and they're not arranged in any particular order.
 * When listing objects we'll use the first index, when doing operations on the objects themselves
 * we'll use the second index. Note that regular objects only map to the first index anyway
 */

static void get_list_index_key(struct rgw_bucket_dir_entry& entry, string *index_key)
{
  *index_key = entry.key.name;

  if (!entry.key.instance.empty()) {
    string ver_str;
    decreasing_str(entry.ver.epoch, &ver_str);
    string instance_delim("\0i", 2);
    string ver_delim("\0v", 2);

    index_key->append(ver_delim);
    index_key->append(ver_str);
    index_key->append(instance_delim);
    index_key->append(entry.key.instance);
  }
}

static void encode_obj_index_key(const cls_rgw_obj_key& key, string *index_key)
{
  if (key.instance.empty()) {
    *index_key = key.name;
  } else {
    *index_key = BI_PREFIX_CHAR;
    index_key->append(bucket_index_prefixes[BI_BUCKET_OBJ_INSTANCE_INDEX]);
    index_key->append(key.name);
    string delim("\0i", 2);
    index_key->append(delim);
    index_key->append(key.instance);
  }
}

static void encode_olh_data_key(const cls_rgw_obj_key& key, string *index_key)
{
  *index_key = BI_PREFIX_CHAR;
  index_key->append(bucket_index_prefixes[BI_BUCKET_OLH_DATA_INDEX]);
  index_key->append(key.name);
}

template <class T>
static int read_index_entry(cls_method_context_t hctx, string& name, T *entry);

static int encode_list_index_key(cls_method_context_t hctx, const cls_rgw_obj_key& key, string *index_key)
{
  if (key.instance.empty()) {
    *index_key = key.name;
    return 0;
  }

  string obj_index_key;
  encode_obj_index_key(key, &obj_index_key);

  rgw_bucket_dir_entry entry;

  int ret = read_index_entry(hctx, obj_index_key, &entry);
  if (ret == -ENOENT) {
   /* couldn't find the entry, set key value after the current object */
    char buf[2] = { 0x1, 0 };
    string s(buf);
    *index_key  = key.name + s;
    return 0;
  }
  if (ret < 0) {
    CLS_LOG(1, "ERROR: encode_list_index_key(): cls_cxx_map_get_val returned %d\n", ret);
    return ret;
  }

  get_list_index_key(entry, index_key);

  return 0;
}

static void split_key(const string& key, list<string>& vals)
{
  size_t pos = 0;
  const char *p = key.c_str();
  while (pos < key.size()) {
    size_t len = strlen(p);
    vals.push_back(p);
    pos += len + 1;
    p += len + 1;
  }
}

/*
 * object index key structure:
 *
 * <obj name>\0[i<instance id>]
 */
static void decode_obj_index_key(const string& index_key, cls_rgw_obj_key *key)
{
  size_t len = strlen(index_key.c_str());

  key->instance.clear();

  if (len == index_key.size()) {
    key->name = index_key;
    return;
  }

  list<string> vals;
  split_key(index_key, vals);

  assert(!vals.empty());

  list<string>::iterator iter = vals.begin();
  key->name = *iter;
  iter++;

  assert(iter != vals.end());

  for (; iter != vals.end(); ++iter) {
    string& val = *iter;
    if (val[0] == 'i') {
      key->instance = val.substr(1);
    }
  }
}

/*
 * list index key structure:
 *
 * <obj name>\0[v<ver>\0i<instance id>]
 */
static void decode_list_index_key(const string& index_key, cls_rgw_obj_key *key, uint64_t *ver)
{
  size_t len = strlen(index_key.c_str());

  key->instance.clear();
  *ver = 0;

  if (len == index_key.size()) {
    key->name = index_key;
    return;
  }

  list<string> vals;
  split_key(index_key, vals);

  assert(!vals.empty());

  list<string>::iterator iter = vals.begin();
  key->name = *iter;
  iter++;

  assert(iter != vals.end());

  for (; iter != vals.end(); ++iter) {
    string& val = *iter;
    if (val[0] == 'i') {
      key->instance = val.substr(1);
    } else if (val[0] == 'v') {
      string err;
      const char *s = val.c_str() + 1;
      *ver = strict_strtoll(s, 10, &err);
      assert(err.empty());
    }
  }
}

int rgw_bucket_list(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator iter = in->begin();

  struct rgw_cls_list_op op;
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_list(): failed to decode request\n");
    return -EINVAL;
  }

  struct rgw_cls_list_ret ret;
  struct rgw_bucket_dir& new_dir = ret.dir;
  bufferlist header_bl;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;
  bufferlist::iterator header_iter = header_bl.begin();
  try {
    ::decode(new_dir.header, header_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_list(): failed to decode header\n");
    return -EINVAL;
  }

  bufferlist bl;

  map<string, bufferlist> keys;
  string start_key;
  encode_list_index_key(hctx, op.start_obj, &start_key);
  rc = get_obj_vals(hctx, start_key, op.filter_prefix, op.num_entries + 1, &keys);
  if (rc < 0)
    return rc;

  std::map<string, struct rgw_bucket_dir_entry>& m = new_dir.m;
  std::map<string, bufferlist>::iterator kiter = keys.begin();
  uint32_t i;

  bool done = false;

  for (i = 0; i < op.num_entries && kiter != keys.end(); ++i, ++kiter) {
    struct rgw_bucket_dir_entry entry;

    if (!bi_is_objs_index(kiter->first)) {
      done = true;
      break;
    }

    bufferlist& entrybl = kiter->second;
    bufferlist::iterator eiter = entrybl.begin();
    try {
      ::decode(entry, eiter);
    } catch (buffer::error& err) {
      CLS_LOG(1, "ERROR: rgw_bucket_list(): failed to decode entry, key=%s\n", kiter->first.c_str());
      return -EINVAL;
    }

    cls_rgw_obj_key key;
    uint64_t ver;
    decode_list_index_key(kiter->first, &key, &ver);

    if (!op.list_versions && !entry.is_visible()) {
      continue;
    }
    m[kiter->first] = entry;

    CLS_LOG(20, "got entry %s[%s] m.size()=%d\n", key.name.c_str(), key.instance.c_str(), (int)m.size());
  }

  ret.is_truncated = (kiter != keys.end() && !done);

  ::encode(ret, *out);
  return 0;
}

static int check_index(cls_method_context_t hctx, struct rgw_bucket_dir_header *existing_header, struct rgw_bucket_dir_header *calc_header)
{
  bufferlist header_bl;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;
  bufferlist::iterator header_iter = header_bl.begin();
  try {
    ::decode(*existing_header, header_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_list(): failed to decode header\n");
    return -EINVAL;
  }

  calc_header->tag_timeout = existing_header->tag_timeout;
  calc_header->ver = existing_header->ver;

  bufferlist bl;

  map<string, bufferlist> keys;
  string start_obj;
  string filter_prefix;

#define CHECK_CHUNK_SIZE 1000
  bool done = false;

  do {
    rc = get_obj_vals(hctx, start_obj, filter_prefix, CHECK_CHUNK_SIZE, &keys);
    if (rc < 0)
      return rc;

    std::map<string, bufferlist>::iterator kiter = keys.begin();
    for (; kiter != keys.end(); ++kiter) {
      if (!bi_is_objs_index(kiter->first)) {
        done = true;
        break;
      }

      struct rgw_bucket_dir_entry entry;
      bufferlist::iterator eiter = kiter->second.begin();
      try {
        ::decode(entry, eiter);
      } catch (buffer::error& err) {
        CLS_LOG(1, "ERROR: rgw_bucket_list(): failed to decode entry, key=%s\n", kiter->first.c_str());
        return -EIO;
      }
      struct rgw_bucket_category_stats& stats = calc_header->stats[entry.meta.category];
      stats.num_entries++;
      stats.total_size += entry.meta.accounted_size;
      stats.total_size_rounded += get_rounded_size(entry.meta.accounted_size);

      start_obj = kiter->first;
    }
  } while (keys.size() == CHECK_CHUNK_SIZE && !done);

  return 0;
}

int rgw_bucket_check_index(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  struct rgw_cls_check_index_ret ret;

  int rc = check_index(hctx, &ret.existing_header, &ret.calculated_header);
  if (rc < 0)
    return rc;

  ::encode(ret, *out);

  return 0;
}

static int write_bucket_header(cls_method_context_t hctx, struct rgw_bucket_dir_header *header)
{
  header->ver++;

  bufferlist header_bl;
  ::encode(*header, header_bl);
  return cls_cxx_map_write_header(hctx, &header_bl);
}


int rgw_bucket_rebuild_index(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  struct rgw_bucket_dir_header existing_header;
  struct rgw_bucket_dir_header calc_header;
  int rc = check_index(hctx, &existing_header, &calc_header);
  if (rc < 0)
    return rc;

  return write_bucket_header(hctx, &calc_header);
}


int rgw_bucket_init_index(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist bl;
  bufferlist::iterator iter;

  bufferlist header_bl;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0) {
    switch (rc) {
    case -ENODATA:
    case -ENOENT:
      break;
    default:
      return rc;
    }
  }

  if (header_bl.length() != 0) {
    CLS_LOG(1, "ERROR: index already initialized\n");
    return -EINVAL;
  }

  rgw_bucket_dir dir;

  return write_bucket_header(hctx, &dir.header);
}

int rgw_bucket_set_tag_timeout(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_tag_timeout_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_set_tag_timeout(): failed to decode request\n");
    return -EINVAL;
  }

  bufferlist header_bl;
  struct rgw_bucket_dir_header header;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;
  bufferlist::iterator header_iter = header_bl.begin();
  try {
    ::decode(header, header_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_complete_op(): failed to decode header\n");
    return -EINVAL;
  }

  header.tag_timeout = op.tag_timeout;

  return write_bucket_header(hctx, &header);
}

int rgw_bucket_prepare_op(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_obj_prepare_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_prepare_op(): failed to decode request\n");
    return -EINVAL;
  }

  if (op.tag.empty()) {
    CLS_LOG(1, "ERROR: tag is empty\n");
    return -EINVAL;
  }

  CLS_LOG(1, "rgw_bucket_prepare_op(): request: op=%d name=%s instance=%s tag=%s\n",
          op.op, op.key.name.c_str(), op.key.instance.c_str(), op.tag.c_str());

  // get on-disk state
  bufferlist cur_value;
  string key;
  encode_obj_index_key(op.key, &key);
  int rc = cls_cxx_map_get_val(hctx, key, &cur_value);
  if (rc < 0 && rc != -ENOENT)
    return rc;

  struct rgw_bucket_dir_entry entry;

  bool noent = (rc == -ENOENT);

  rc = 0;

  if (!noent) {
    try {
      bufferlist::iterator biter = cur_value.begin();
      ::decode(entry, biter);
    } catch (buffer::error& err) {
      CLS_LOG(1, "ERROR: rgw_bucket_prepare_op(): failed to decode entry\n");
      /* ignoring error */

      noent = true;
    }
  }

  if (noent) { // no entry, initialize fields
    entry.key = op.key;
    entry.ver = rgw_bucket_entry_ver();
    entry.exists = false;
    entry.locator = op.locator;
  }

  // fill in proper state
  struct rgw_bucket_pending_info& info = entry.pending_map[op.tag];
  info.timestamp = ceph_clock_now(g_ceph_context);
  info.state = CLS_RGW_STATE_PENDING_MODIFY;
  info.op = op.op;


  bufferlist header_bl;
  struct rgw_bucket_dir_header header;
  rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;

  bufferlist::iterator header_iter = header_bl.begin();
  try {
    ::decode(header, header_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_complete_op(): failed to decode header\n");
    return -EINVAL;
  }

  if (op.log_op) {
    rc = log_index_operation(hctx, op.key, op.op, op.tag, entry.meta.mtime,
                             entry.ver, info.state, header.ver, header.max_marker);
    if (rc < 0)
      return rc;
  }

  // write out new key to disk
  bufferlist info_bl;
  ::encode(entry, info_bl);
  encode_obj_index_key(op.key, &key);
  rc = cls_cxx_map_set_val(hctx, key, &info_bl);
  if (rc < 0)
    return rc;

  return write_bucket_header(hctx, &header);
}

static void unaccount_entry(struct rgw_bucket_dir_header& header, struct rgw_bucket_dir_entry& entry)
{
  struct rgw_bucket_category_stats& stats = header.stats[entry.meta.category];
  stats.num_entries--;
  stats.total_size -= entry.meta.accounted_size;
  stats.total_size_rounded -= get_rounded_size(entry.meta.accounted_size);
}

static void log_entry(const char *func, const char *str, struct rgw_bucket_dir_entry *entry)
{
  CLS_LOG(1, "%s(): %s: ver=%ld:%llu name=%s instance=%s locator=%s\n", func, str,
          (long)entry->ver.pool, (unsigned long long)entry->ver.epoch,
          entry->key.name.c_str(), entry->key.instance.c_str(), entry->locator.c_str());
}

static void log_entry(const char *func, const char *str, struct rgw_bucket_olh_entry *entry)
{
  CLS_LOG(1, "%s(): %s: epoch=%llu name=%s instance=%s tag=%s\n", func, str,
          (unsigned long long)entry->epoch, entry->key.name.c_str(), entry->key.instance.c_str(),
          entry->tag.c_str());
}

template <class T>
static int read_index_entry(cls_method_context_t hctx, string& name, T *entry)
{
  bufferlist current_entry;
  int rc = cls_cxx_map_get_val(hctx, name, &current_entry);
  if (rc < 0) {
    return rc;
  }

  bufferlist::iterator cur_iter = current_entry.begin();
  try {
    ::decode(*entry, cur_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: read_index_entry(): failed to decode entry\n");
    return -EIO;
  }

  log_entry(__func__, "existing entry", entry);
  return 0;
}

int rgw_bucket_complete_op(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_obj_complete_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_complete_op(): failed to decode request\n");
    return -EINVAL;
  }
  CLS_LOG(1, "rgw_bucket_complete_op(): request: op=%d name=%s instance=%s ver=%lu:%llu tag=%s\n",
          op.op, op.key.name.c_str(), op.key.instance.c_str(),
          (unsigned long)op.ver.pool, (unsigned long long)op.ver.epoch,
          op.tag.c_str());

  bufferlist header_bl;
  struct rgw_bucket_dir_header header;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;
  bufferlist::iterator header_iter = header_bl.begin();
  try {
    ::decode(header, header_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bucket_complete_op(): failed to decode header\n");
    return -EINVAL;
  }

  struct rgw_bucket_dir_entry entry;
  bool ondisk = true;

  string key;
  encode_obj_index_key(op.key, &key);
  rc = read_index_entry(hctx, key, &entry);
  if (rc == -ENOENT) {
    entry.key = op.key;
    entry.ver = op.ver;
    entry.meta = op.meta;
    entry.locator = op.locator;
    ondisk = false;
  } else if (rc < 0) {
    return rc;
  }

  entry.index_ver = header.ver;

  if (op.tag.size()) {
    map<string, struct rgw_bucket_pending_info>::iterator pinter = entry.pending_map.find(op.tag);
    if (pinter == entry.pending_map.end()) {
      CLS_LOG(1, "ERROR: couldn't find tag for pending operation\n");
      return -EINVAL;
    }
    entry.pending_map.erase(pinter);
  }

  bool cancel = false;
  bufferlist update_bl;

  if (op.tag.size() && op.op == CLS_RGW_OP_CANCEL) {
    CLS_LOG(1, "rgw_bucket_complete_op(): cancel requested\n");
    cancel = true;
  } else if (op.ver.pool == entry.ver.pool &&
             op.ver.epoch && op.ver.epoch <= entry.ver.epoch) {
    CLS_LOG(1, "rgw_bucket_complete_op(): skipping request, old epoch\n");
    cancel = true;
  }

  bufferlist op_bl;
  if (cancel) {
    if (op.log_op) {
      rc = log_index_operation(hctx, op.key, op.op, op.tag, entry.meta.mtime, entry.ver,
                               CLS_RGW_STATE_COMPLETE, header.ver, header.max_marker);
      if (rc < 0)
        return rc;
    }

    if (op.tag.size()) {
      bufferlist new_key_bl;
      ::encode(entry, new_key_bl);
      return cls_cxx_map_set_val(hctx, key, &new_key_bl);
    } else {
      return 0;
    }
  }

  if (entry.exists) {
    unaccount_entry(header, entry);
  }

  entry.ver = op.ver;
  switch ((int)op.op) {
  case CLS_RGW_OP_DEL:
    if (ondisk) {
      if (!entry.pending_map.size()) {
	int ret = cls_cxx_map_remove_key(hctx, key);
	if (ret < 0)
	  return ret;
      } else {
        entry.exists = false;
        bufferlist new_key_bl;
        ::encode(entry, new_key_bl);
	int ret = cls_cxx_map_set_val(hctx, key, &new_key_bl);
	if (ret < 0)
	  return ret;
      }
    } else {
      return -ENOENT;
    }
    break;
  case CLS_RGW_OP_ADD:
    {
      struct rgw_bucket_dir_entry_meta& meta = op.meta;
      struct rgw_bucket_category_stats& stats = header.stats[meta.category];
      entry.meta = meta;
      entry.key = op.key;
      entry.exists = true;
      entry.tag = op.tag;
      stats.num_entries++;
      stats.total_size += meta.accounted_size;
      stats.total_size_rounded += get_rounded_size(meta.accounted_size);
      bufferlist new_key_bl;
      ::encode(entry, new_key_bl);
      int ret = cls_cxx_map_set_val(hctx, key, &new_key_bl);
      if (ret < 0)
	return ret;
    }
    break;
  }

  if (op.log_op) {
    rc = log_index_operation(hctx, op.key, op.op, op.tag, entry.meta.mtime, entry.ver,
                             CLS_RGW_STATE_COMPLETE, header.ver, header.max_marker);
    if (rc < 0)
      return rc;
  }

  list<cls_rgw_obj_key>::iterator remove_iter;
  CLS_LOG(20, "rgw_bucket_complete_op(): remove_objs.size()=%d\n", (int)op.remove_objs.size());
  for (remove_iter = op.remove_objs.begin(); remove_iter != op.remove_objs.end(); ++remove_iter) {
    cls_rgw_obj_key& remove_key = *remove_iter;
    CLS_LOG(1, "rgw_bucket_complete_op(): removing entries, read_index_entry name=%s instance=%s\n",
            remove_key.name.c_str(), remove_key.instance.c_str());
    struct rgw_bucket_dir_entry remove_entry;
    string k;
    encode_obj_index_key(remove_key, &k);
    int ret = read_index_entry(hctx, k, &remove_entry);
    if (ret < 0) {
      CLS_LOG(1, "rgw_bucket_complete_op(): removing entries, read_index_entry name=%s instance=%s ret=%d\n",
            remove_key.name.c_str(), remove_key.instance.c_str(), ret);
      continue;
    }
    CLS_LOG(0, "rgw_bucket_complete_op(): entry.name=%s entry.instance=%s entry.meta.category=%d\n",
            remove_entry.key.name.c_str(), remove_entry.key.instance.c_str(), remove_entry.meta.category);
    unaccount_entry(header, remove_entry);

    if (op.log_op) {
      rc = log_index_operation(hctx, remove_key, CLS_RGW_OP_DEL, op.tag, remove_entry.meta.mtime,
                               remove_entry.ver, CLS_RGW_STATE_COMPLETE, header.ver, header.max_marker);
      if (rc < 0)
        continue;
    }

    ret = cls_cxx_map_remove_key(hctx, k);
    if (ret < 0) {
      CLS_LOG(1, "rgw_bucket_complete_op(): cls_cxx_map_remove_key, failed to remove entry, name=%s instance=%s read_index_entry ret=%d\n", remove_key.name.c_str(), remove_key.instance.c_str(), rc);
      continue;
    }
  }

  return write_bucket_header(hctx, &header);
}

template <class T>
static int write_entry(cls_method_context_t hctx, T& entry, const string& key)
{
  bufferlist bl;
  ::encode(entry, bl);
  return cls_cxx_map_set_val(hctx, key, &bl);
}

static int read_olh(cls_method_context_t hctx,cls_rgw_obj_key& obj_key, struct rgw_bucket_olh_entry *olh_data_entry, string *index_key, bool *found)
{
  cls_rgw_obj_key olh_key;
  olh_key.name = obj_key.name;

  encode_olh_data_key(olh_key, index_key);
  int ret = read_index_entry(hctx, *index_key, olh_data_entry);
  if (ret < 0 && ret != -ENOENT) {
    CLS_LOG(0, "ERROR: read_index_entry() olh_key=%s ret=%d", olh_key.name.c_str(), ret);
    return ret;
  }
  *found = (ret != -ENOENT);
  return 0;
}

static int read_key_list_entry(cls_method_context_t hctx, cls_rgw_obj_key& key, rgw_bucket_dir_entry *entry, string *idx)
{
  encode_list_index_key(hctx, key, idx);

  int ret = read_index_entry(hctx, *idx, entry);
  if (ret < 0) {
    CLS_LOG(0, "ERROR: read_index_entry() reading previous instance %s ret=%d", idx->c_str(), ret);
    return ret;
  }

  return 0;
}

static void update_olh_log(struct rgw_bucket_olh_entry& olh_data_entry, OLHLogOp op, const string& op_tag,
                           cls_rgw_obj_key& key, bool delete_marker)
{
  rgw_bucket_olh_log_entry& log_entry = olh_data_entry.pending_log[olh_data_entry.epoch];
  log_entry.epoch = olh_data_entry.epoch;
  log_entry.op = op;
  log_entry.op_tag = op_tag;
  log_entry.key = key;
  log_entry.delete_marker = delete_marker;
}

/*
 * write object instance entry, and if needed also the list entry
 */
static int write_obj_entries(cls_method_context_t hctx, struct rgw_bucket_dir_entry& instance_entry, const string& instance_idx)
{
  CLS_LOG(20, "write_entry() instance=%s idx=%s flags=%d", instance_entry.key.instance.c_str(), instance_idx.c_str(), instance_entry.flags);
  /* write the instance entry */
  int ret = write_entry(hctx, instance_entry, instance_idx);
  if (ret < 0) {
    CLS_LOG(0, "ERROR: write_entry() instance_key=%s ret=%d", instance_idx.c_str(), ret);
    return ret;
  }
  string instance_list_idx;
  get_list_index_key(instance_entry, &instance_list_idx);

  if (instance_idx != instance_list_idx) {
    CLS_LOG(20, "write_entry() idx=%s flags=%d", instance_list_idx.c_str(), instance_entry.flags);
    /* write a new list entry for the object instance */
    ret = write_entry(hctx, instance_entry, instance_list_idx);
    if (ret < 0) {
      CLS_LOG(0, "ERROR: write_entry() instance=%s instance_list_idx=%s ret=%d", instance_entry.key.instance.c_str(), instance_list_idx.c_str(), ret);
      return ret;
    }
  }
  return 0;
}


class BIVerObjEntry {
  cls_method_context_t hctx;
  cls_rgw_obj_key key;
  string instance_idx;

  struct rgw_bucket_dir_entry instance_entry;

  bool initialized;

public:
  BIVerObjEntry(cls_method_context_t& _hctx, const cls_rgw_obj_key& _key) : hctx(_hctx), key(_key), initialized(false) {
    encode_obj_index_key(key, &instance_idx);
  }

  int init() {
    int ret = read_index_entry(hctx, instance_idx, &instance_entry);
    if (ret < 0) {
      CLS_LOG(0, "ERROR: read_index_entry() key=%s ret=%d", instance_idx.c_str(), ret);
      return ret;
    }
    initialized = true;
    CLS_LOG(20, "read instance_entry key.name=%s key.instance=%s flags=%d", instance_entry.key.name.c_str(), instance_entry.key.instance.c_str(), instance_entry.flags);
    return 0;
  }

  void init_as_delete_marker() {
    /* a deletion marker, need to initialize it, there's no instance entry for it yet */
    instance_entry.key = key;
    instance_entry.flags = RGW_BUCKET_DIRENT_FLAG_DELETE_MARKER;

    initialized = true;
  }


  int unlink_list_entry() {
    if (instance_entry.ver.epoch > 0) {
      string list_idx;
      /* this instance has a previous list entry, remove that entry */
      get_list_index_key(instance_entry, &list_idx);
      int ret = cls_cxx_map_remove_key(hctx, list_idx);
      if (ret < 0) {
        CLS_LOG(0, "ERROR: cls_cxx_map_remove_key() list_idx=%s ret=%d", list_idx.c_str(), ret);
        return ret;
      }
    }
    return 0;
  }

  int write_entries(uint64_t flags_set, uint64_t flags_reset) {
    if (!initialized) {
      int ret = init();
      if (ret < 0) {
        return ret;
      }
    }
    instance_entry.flags |= flags_set;
    instance_entry.flags &= ~flags_reset;

    /* write the instance and list entries */
    int ret = write_obj_entries(hctx, instance_entry, instance_idx);
    if (ret < 0) {
      CLS_LOG(0, "ERROR: write_obj_entries() instance_idx=%s ret=%d", instance_idx.c_str(), ret);
      return ret;
    }

    return 0;
  }

  int set_current(uint64_t epoch) {
    if (instance_entry.ver.epoch > 0) {
      /* this instance has a previous list entry, remove that entry */
      int ret = unlink_list_entry();
      if (ret < 0) {
        return ret;
      }
    }

    instance_entry.ver.epoch = epoch;
    return write_entries(RGW_BUCKET_DIRENT_FLAG_VER | RGW_BUCKET_DIRENT_FLAG_CURRENT, 0);
  }

  int demote_current() {
    return write_entries(0, RGW_BUCKET_DIRENT_FLAG_CURRENT);
  }
};


class BIOLHEntry {
  cls_method_context_t hctx;
  cls_rgw_obj_key key;

  string olh_data_idx;
  struct rgw_bucket_olh_entry olh_data_entry;

  bool initialized;
public:
  BIOLHEntry(cls_method_context_t& _hctx, const cls_rgw_obj_key& _key) : hctx(_hctx), key(_key), initialized(false) { }

  int init(bool *exists) {
    /* read olh */
    int ret = read_olh(hctx, key, &olh_data_entry, &olh_data_idx, exists);
    if (ret < 0) {
      return ret;
    }

    inc_epoch();
    initialized = true;
    return 0;
  }

  void inc_epoch() {
    olh_data_entry.epoch++;
  }

  uint64_t get_epoch() {
    return olh_data_entry.epoch;
  }

  rgw_bucket_olh_entry& get_entry() {
    return olh_data_entry;
  }

  int update(cls_rgw_obj_key& key, bool delete_marker) {
    olh_data_entry.delete_marker = delete_marker;
    olh_data_entry.key = key;

    /* write the olh data entry */
    int ret = write_entry(hctx, olh_data_entry, olh_data_idx);
    if (ret < 0) {
      CLS_LOG(0, "ERROR: write_entry() olh_key=%s ret=%d", olh_data_idx.c_str(), ret);
      return ret;
    }

    return 0;
  }

  void update_log(OLHLogOp op, const string& op_tag, cls_rgw_obj_key& key, bool delete_marker) {
    update_olh_log(olh_data_entry, op, op_tag, key, delete_marker);
  }

};

/*
 * link an object version to an olh, update the relevant index entries. It will also handle the
 * deletion marker case. We have a few entries that we need to take care of. For object 'foo',
 * instance BAR, we'd update the following (not actual encoding):
 *  - olh data: [BI_BUCKET_OLH_DATA_INDEX]foo
 *  - object instance data: [BI_BUCKET_OBJ_INSTANCE_INDEX]foo,BAR
 *  - object instance list entry: foo,123,BAR
 *
 *  The instance list entry needs to be ordered by newer to older, so we generate an appropriate
 *  number string that follows the name.
 *  The top instance for each object is marked appropriately.
 *  We generate instance entry for deletion markers here, as they are not created prior.
 */
static int rgw_bucket_link_olh(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  string olh_data_idx;
  string instance_idx;
  struct rgw_bucket_olh_entry olh_data_entry;

  // decode request
  rgw_cls_link_olh_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: rgw_bucket_link_olh_op(): failed to decode request\n");
    return -EINVAL;
  }

  BIVerObjEntry obj(hctx, op.key);
  BIOLHEntry olh(hctx, op.key);

  /* read instance entry */
  if (!op.delete_marker) {
    int ret = obj.init();
    if (ret < 0) {
      return ret;
    }
  } else {
    /* a deletion marker, need to initialize it, there's no instance entry for it yet */
    obj.init_as_delete_marker();
  }

  /* read olh */
  bool olh_found;
  int ret = olh.init(&olh_found);
  if (ret < 0) {
    return ret;
  }

  if (olh_found) {
    /* found olh, previous instance is no longer the latest, need to update */
    BIVerObjEntry old_obj(hctx, olh.get_entry().key);

    ret = old_obj.demote_current();
    if (ret < 0) {
      CLS_LOG(0, "ERROR: could not demote current on previous key ret=%d", ret);
      return ret;
    }
  }

  /* might need to remove the plain object listing key */
  if (!op.key.instance.empty()) {
    struct rgw_bucket_dir_entry plain_entry;
    string plain_idx;
    cls_rgw_obj_key no_instance_key(op.key.name);

    ret = read_key_list_entry(hctx, no_instance_key, &plain_entry, &plain_idx);
    if (ret >= 0) {
#warning handle overwrite of non-olh object, need to update log
      ret = cls_cxx_map_remove_key(hctx, plain_idx);
    }
  }

  ret = olh.update(op.key, op.delete_marker);
  if (ret < 0) {
    CLS_LOG(0, "ERROR: failed to update olh ret=%d", ret);
    return ret;
  }

  /* write the instance and list entries */
  ret = obj.set_current(olh.get_epoch());
  if (ret < 0) {
    return ret;
  }

  /* update the olh log */

  olh.update_log(CLS_RGW_OLH_OP_LINK_OLH, op.op_tag, op.key, op.delete_marker);

  return 0;
}

static int rgw_bucket_read_olh_log(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_read_olh_log_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: rgw_bucket_read_olh_log(): failed to decode request\n");
    return -EINVAL;
  }

  if (!op.olh.instance.empty()) {
    CLS_LOG(1, "bad key passed in (non empty instance)");
    return -EINVAL;
  }

  struct rgw_bucket_olh_entry olh_data_entry;
  string olh_data_key;
  encode_olh_data_key(op.olh, &olh_data_key);
  int ret = read_index_entry(hctx, olh_data_key, &olh_data_entry);
  if (ret < 0 && ret != -ENOENT) {
    CLS_LOG(0, "ERROR: read_index_entry() olh_key=%s ret=%d", olh_data_key.c_str(), ret);
    return ret;
  }

  rgw_cls_read_olh_log_ret op_ret;

#define MAX_OLH_LOG_ENTRIES 1000
  map<uint64_t, rgw_bucket_olh_log_entry>& log = olh_data_entry.pending_log;

  if (log.begin()->first > op.ver_marker && log.size() <= MAX_OLH_LOG_ENTRIES) {
    op_ret.log = log;
    op_ret.is_truncated = false;
  } else {
    map<uint64_t, rgw_bucket_olh_log_entry>::iterator iter = log.upper_bound(op.ver_marker);

    for (int i = 0; i < MAX_OLH_LOG_ENTRIES && iter != log.end(); ++i, ++iter) {
      op_ret.log[iter->first] = iter->second;
    }
    op_ret.is_truncated = (iter != log.end());
  }

  ::encode(op_ret, *out);

  return 0;
}

static int rgw_bucket_trim_olh_log(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_trim_olh_log_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: rgw_bucket_trim_olh_log(): failed to decode request\n");
    return -EINVAL;
  }

  if (!op.olh.instance.empty()) {
    CLS_LOG(1, "bad key passed in (non empty instance)");
    return -EINVAL;
  }

  /* read olh entry */
  struct rgw_bucket_olh_entry olh_data_entry;
  string olh_data_key;
  encode_olh_data_key(op.olh, &olh_data_key);
  int ret = read_index_entry(hctx, olh_data_key, &olh_data_entry);
  if (ret < 0 && ret != -ENOENT) {
    CLS_LOG(0, "ERROR: read_index_entry() olh_key=%s ret=%d", olh_data_key.c_str(), ret);
    return ret;
  }

  /* remove all versions up to and including ver from the pending map */
  map<uint64_t, rgw_bucket_olh_log_entry>& log = olh_data_entry.pending_log;
  map<uint64_t, rgw_bucket_olh_log_entry>::iterator liter = log.begin();
  while (liter != log.end() && liter->first <= op.ver) {
    map<uint64_t, rgw_bucket_olh_log_entry>::iterator rm_iter = liter;
    ++liter;
    log.erase(rm_iter);
  }

  /* write the olh data entry */
  ret = write_entry(hctx, olh_data_entry, olh_data_key);
  if (ret < 0) {
    CLS_LOG(0, "ERROR: write_entry() olh_key=%s ret=%d", olh_data_key.c_str(), ret);
    return ret;
  }

  return 0;
}

int rgw_dir_suggest_changes(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  CLS_LOG(1, "rgw_dir_suggest_changes()");

  bufferlist header_bl;
  struct rgw_bucket_dir_header header;
  bool header_changed = false;
  int rc = cls_cxx_map_read_header(hctx, &header_bl);
  if (rc < 0)
    return rc;

  uint64_t tag_timeout;

  try {
    bufferlist::iterator header_iter = header_bl.begin();
    ::decode(header, header_iter);
  } catch (buffer::error& error) {
    CLS_LOG(1, "ERROR: rgw_dir_suggest_changes(): failed to decode header\n");
    return -EINVAL;
  }

  tag_timeout = (header.tag_timeout ? header.tag_timeout : CEPH_RGW_TAG_TIMEOUT);

  bufferlist::iterator in_iter = in->begin();

  while (!in_iter.end()) {
    __u8 op;
    rgw_bucket_dir_entry cur_change;
    rgw_bucket_dir_entry cur_disk;
    try {
      ::decode(op, in_iter);
      ::decode(cur_change, in_iter);
    } catch (buffer::error& err) {
      CLS_LOG(1, "ERROR: rgw_dir_suggest_changes(): failed to decode request\n");
      return -EINVAL;
    }

    bufferlist cur_disk_bl;
    string cur_change_key;
    encode_obj_index_key(cur_change.key, &cur_change_key);
    int ret = cls_cxx_map_get_val(hctx, cur_change_key, &cur_disk_bl);
    if (ret < 0 && ret != -ENOENT)
      return -EINVAL;

    if (cur_disk_bl.length()) {
      bufferlist::iterator cur_disk_iter = cur_disk_bl.begin();
      try {
        ::decode(cur_disk, cur_disk_iter);
      } catch (buffer::error& error) {
        CLS_LOG(1, "ERROR: rgw_dir_suggest_changes(): failed to decode cur_disk\n");
        return -EINVAL;
      }

      utime_t cur_time = ceph_clock_now(g_ceph_context);
      map<string, struct rgw_bucket_pending_info>::iterator iter =
                cur_disk.pending_map.begin();
      while(iter != cur_disk.pending_map.end()) {
        map<string, struct rgw_bucket_pending_info>::iterator cur_iter=iter++;
        if (cur_time > (cur_iter->second.timestamp + tag_timeout)) {
          cur_disk.pending_map.erase(cur_iter);
        }
      }
    }

    CLS_LOG(20, "cur_disk.pending_map.empty()=%d op=%d cur_disk.exists=%d cur_change.pending_map.size()=%d cur_change.exists=%d\n",
	    cur_disk.pending_map.empty(), (int)op, cur_disk.exists,
	    (int)cur_change.pending_map.size(), cur_change.exists);

    if (cur_disk.pending_map.empty()) {
      if (cur_disk.exists) {
        struct rgw_bucket_category_stats& old_stats = header.stats[cur_disk.meta.category];
        CLS_LOG(10, "total_entries: %" PRId64 " -> %" PRId64 "\n", old_stats.num_entries, old_stats.num_entries - 1);
        old_stats.num_entries--;
        old_stats.total_size -= cur_disk.meta.accounted_size;
        old_stats.total_size_rounded -= get_rounded_size(cur_disk.meta.accounted_size);
        header_changed = true;
      }
      struct rgw_bucket_category_stats& stats =
          header.stats[cur_change.meta.category];
      switch(op) {
      case CEPH_RGW_REMOVE:
        CLS_LOG(10, "CEPH_RGW_REMOVE name=%s instance=%s\n", cur_change.key.name.c_str(), cur_change.key.instance.c_str());
	ret = cls_cxx_map_remove_key(hctx, cur_change_key);
	if (ret < 0)
	  return ret;
        break;
      case CEPH_RGW_UPDATE:
        CLS_LOG(10, "CEPH_RGW_UPDATE name=%s instance=%s total_entries: %" PRId64 " -> %" PRId64 "\n",
                cur_change.key.name.c_str(), cur_change.key.instance.c_str(), stats.num_entries, stats.num_entries + 1);
        stats.num_entries++;
        stats.total_size += cur_change.meta.accounted_size;
        stats.total_size_rounded += get_rounded_size(cur_change.meta.accounted_size);
        header_changed = true;
        cur_change.index_ver = header.ver;
        bufferlist cur_state_bl;
        ::encode(cur_change, cur_state_bl);
        ret = cls_cxx_map_set_val(hctx, cur_change_key, &cur_state_bl);
        if (ret < 0)
	  return ret;
        break;
      }
    }
  }

  if (header_changed) {
    return write_bucket_header(hctx, &header);
  }
  return 0;
}

static int rgw_obj_remove(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  // decode request
  rgw_cls_obj_remove_op op;
  bufferlist::iterator iter = in->begin();
  try {
    ::decode(op, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: %s(): failed to decode request", __func__);
    return -EINVAL;
  }

  if (op.keep_attr_prefixes.empty()) {
    return cls_cxx_remove(hctx);
  }

  map<string, bufferlist> attrset;
  int ret = cls_cxx_getxattrs(hctx, &attrset);
  if (ret < 0 && ret != -ENOENT) {
    CLS_LOG(0, "ERROR: %s(): cls_cxx_getxattrs() returned %d", __func__, ret);
    return ret;
  }

  CLS_LOG(20, "%s(): removing object", __func__);
  ret = cls_cxx_remove(hctx);
  if (ret < 0) {
    CLS_LOG(0, "ERROR: %s(): cls_cxx_remove returned %d", __func__, ret);
    return ret;
  }

  map<string, bufferlist> new_attrs;
  for (list<string>::iterator iter = op.keep_attr_prefixes.begin();
       iter != op.keep_attr_prefixes.end(); ++iter) {
    string& check_prefix = *iter;

    for (map<string, bufferlist>::iterator aiter = attrset.lower_bound(check_prefix);
         aiter != attrset.end(); ++aiter) {
      const string& attr = aiter->first;

      if (attr.substr(0, check_prefix.size()) > check_prefix) {
        break;
      }

      ret = cls_cxx_setxattr(hctx, attr.c_str(), &aiter->second);
      CLS_LOG(20, "%s(): setting attr: %s", __func__, attr.c_str());
      if (ret < 0) {
        CLS_LOG(0, "ERROR: %s(): cls_cxx_setxattr (attr=%s) returned %d", __func__, attr.c_str(), ret);
        return ret;
      }
    }
  }



  return 0;
}

int bi_log_record_decode(bufferlist& bl, rgw_bi_log_entry& e)
{
  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(e, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: failed to decode rgw_bi_log_entry");
    return -EIO;
  }
  return 0;
}

static int bi_log_iterate_entries(cls_method_context_t hctx, const string& marker, const string& end_marker,
                              string& key_iter, uint32_t max_entries, bool *truncated,
                              int (*cb)(cls_method_context_t, const string&, rgw_bi_log_entry&, void *),
                              void *param)
{
  CLS_LOG(10, "bi_log_iterate_range");

  map<string, bufferlist> keys;
  string filter_prefix, end_key;
  bufferlist start_bl;
  bool start_key_added = false;
  uint32_t i = 0;
  string key;

  if (truncated)
    *truncated = false;

  string start_key;
  if (key_iter.empty()) {
    key = BI_PREFIX_CHAR;
    key.append(bucket_index_prefixes[BI_BUCKET_LOG_INDEX]);
    key.append(marker);

    start_key = key;
    int ret = cls_cxx_map_get_val(hctx, start_key, &start_bl);
    if ((ret < 0) && (ret != -ENOENT)) {
        return ret;
    } 
  } else {
    start_key = key_iter;
  }

  if (end_marker.empty()) {
    end_key = BI_PREFIX_CHAR;
    end_key.append(bucket_index_prefixes[BI_BUCKET_LAST_INDEX]);
  } else {
    end_key = BI_PREFIX_CHAR;
    end_key.append(bucket_index_prefixes[BI_BUCKET_LOG_INDEX]);
    end_key.append(end_marker);
  }

  CLS_LOG(0, "bi_log_iterate_entries start_key=%s end_key=%s\n", start_key.c_str(), end_key.c_str());

  string filter;

  do {
#define BI_NUM_KEYS 128
    int ret = cls_cxx_map_get_vals(hctx, start_key, filter, BI_NUM_KEYS, &keys);
    if (ret < 0)
      return ret;

    if ((start_bl.length() > 0) && (!start_key_added)) {
      keys[start_key] = start_bl;
      start_key_added = true;
    }
    map<string, bufferlist>::iterator iter = keys.begin();
    if (iter == keys.end())
      break;

    for (; iter != keys.end(); ++iter) {
      const string& key = iter->first;
      rgw_bi_log_entry e;

      CLS_LOG(0, "bi_log_iterate_entries key=%s bl.length=%d\n", key.c_str(), (int)iter->second.length());

      if (key.compare(end_key) > 0)
        return 0;

      ret = bi_log_record_decode(iter->second, e);
      if (ret < 0)
        return ret;

      if (max_entries && (i >= max_entries)) {
        if (truncated)
          *truncated = true;
        key_iter = key;
        return 0;
      }

      ret = cb(hctx, key, e, param);
      if (ret < 0)
        return ret;
      i++;

    }
    --iter;
    start_key = iter->first;
  } while (true);
  return 0;
}

static int bi_log_list_cb(cls_method_context_t hctx, const string& key, rgw_bi_log_entry& info, void *param)
{
  list<rgw_bi_log_entry> *l = (list<rgw_bi_log_entry> *)param;
  l->push_back(info);
  return 0;
}

static int bi_log_list_entries(cls_method_context_t hctx, const string& marker,
			   uint32_t max, list<rgw_bi_log_entry>& entries, bool *truncated)
{
  string key_iter;
  string end_marker;
  int ret = bi_log_iterate_entries(hctx, marker, end_marker,
                              key_iter, max, truncated,
                              bi_log_list_cb, &entries);
  return ret;
}

static int rgw_bi_log_list(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_bi_log_list_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bi_log_list(): failed to decode entry\n");
    return -EINVAL;
  }

  cls_rgw_bi_log_list_ret op_ret;
  int ret = bi_log_list_entries(hctx, op.marker, op.max, op_ret.entries, &op_ret.truncated);
  if (ret < 0)
    return ret;

  ::encode(op_ret, *out);

  return 0;
}

static int bi_log_list_trim_cb(cls_method_context_t hctx, const string& key, rgw_bi_log_entry& info, void *param)
{
  list<rgw_bi_log_entry> *entries = (list<rgw_bi_log_entry> *)param;

  entries->push_back(info);
  return 0;
}

static int bi_log_remove_entry(cls_method_context_t hctx, rgw_bi_log_entry& entry)
{
  string key;
  key = BI_PREFIX_CHAR;
  key.append(bucket_index_prefixes[BI_BUCKET_LOG_INDEX]);
  key.append(entry.id);
  return cls_cxx_map_remove_key(hctx, key);
}

static int bi_log_list_trim_entries(cls_method_context_t hctx,
                                    const string& start_marker, const string& end_marker,
			            list<rgw_bi_log_entry>& entries, bool *truncated)
{
  string key_iter;
#define MAX_TRIM_ENTRIES 1000 /* max entries to trim in a single operation */
  int ret = bi_log_iterate_entries(hctx, start_marker, end_marker,
                              key_iter, MAX_TRIM_ENTRIES, truncated,
                              bi_log_list_trim_cb, &entries);
  return ret;
}

static int rgw_bi_log_trim(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_bi_log_trim_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_bi_log_list(): failed to decode entry\n");
    return -EINVAL;
  }

  cls_rgw_bi_log_list_ret op_ret;
  list<rgw_bi_log_entry> entries;
#define MAX_TRIM_ENTRIES 1000 /* don't do more than that in a single operation */
  bool truncated;
  int ret = bi_log_list_trim_entries(hctx, op.start_marker, op.end_marker, entries, &truncated);
  if (ret < 0)
    return ret;

  if (entries.empty())
    return -ENODATA;

  list<rgw_bi_log_entry>::iterator iter;
  for (iter = entries.begin(); iter != entries.end(); ++iter) {
    rgw_bi_log_entry& entry = *iter;

    ret = bi_log_remove_entry(hctx, entry);
    if (ret < 0)
      return ret;
  }

  return 0;
}

static void usage_record_prefix_by_time(uint64_t epoch, string& key)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%011llu", (long long unsigned)epoch);
  key = buf;
}

static void usage_record_prefix_by_user(string& user, uint64_t epoch, string& key)
{
  char buf[user.size() + 32];
  snprintf(buf, sizeof(buf), "%s_%011llu_", user.c_str(), (long long unsigned)epoch);
  key = buf;
}

static void usage_record_name_by_time(uint64_t epoch, string& user, string& bucket, string& key)
{
  char buf[32 + user.size() + bucket.size()];
  snprintf(buf, sizeof(buf), "%011llu_%s_%s", (long long unsigned)epoch, user.c_str(), bucket.c_str());
  key = buf;
}

static void usage_record_name_by_user(string& user, uint64_t epoch, string& bucket, string& key)
{
  char buf[32 + user.size() + bucket.size()];
  snprintf(buf, sizeof(buf), "%s_%011llu_%s", user.c_str(), (long long unsigned)epoch, bucket.c_str());
  key = buf;
}

static int usage_record_decode(bufferlist& record_bl, rgw_usage_log_entry& e)
{
  bufferlist::iterator kiter = record_bl.begin();
  try {
    ::decode(e, kiter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: usage_record_decode(): failed to decode record_bl\n");
    return -EINVAL;
  }

  return 0;
}

int rgw_user_usage_log_add(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  CLS_LOG(10, "rgw_user_usage_log_add()");

  bufferlist::iterator in_iter = in->begin();
  rgw_cls_usage_log_add_op op;

  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_user_usage_log_add(): failed to decode request\n");
    return -EINVAL;
  }

  rgw_usage_log_info& info = op.info;
  vector<rgw_usage_log_entry>::iterator iter;

  for (iter = info.entries.begin(); iter != info.entries.end(); ++iter) {
    rgw_usage_log_entry& entry = *iter;
    string key_by_time;
    usage_record_name_by_time(entry.epoch, entry.owner, entry.bucket, key_by_time);

    CLS_LOG(10, "rgw_user_usage_log_add user=%s bucket=%s\n", entry.owner.c_str(), entry.bucket.c_str());

    bufferlist record_bl;
    int ret = cls_cxx_map_get_val(hctx, key_by_time, &record_bl);
    if (ret < 0 && ret != -ENOENT) {
      CLS_LOG(1, "ERROR: rgw_user_usage_log_add(): cls_cxx_map_read_key returned %d\n", ret);
      return -EINVAL;
    }
    if (ret >= 0) {
      rgw_usage_log_entry e;
      ret = usage_record_decode(record_bl, e);
      if (ret < 0)
        return ret;
      CLS_LOG(10, "rgw_user_usage_log_add aggregating existing bucket\n");
      entry.aggregate(e);
    }

    bufferlist new_record_bl;
    ::encode(entry, new_record_bl);
    ret = cls_cxx_map_set_val(hctx, key_by_time, &new_record_bl);
    if (ret < 0)
      return ret;

    string key_by_user;
    usage_record_name_by_user(entry.owner, entry.epoch, entry.bucket, key_by_user);
    ret = cls_cxx_map_set_val(hctx, key_by_user, &new_record_bl);
    if (ret < 0)
      return ret;
  }

  return 0;
}

static int usage_iterate_range(cls_method_context_t hctx, uint64_t start, uint64_t end,
                            string& user, string& key_iter, uint32_t max_entries, bool *truncated,
                            int (*cb)(cls_method_context_t, const string&, rgw_usage_log_entry&, void *),
                            void *param)
{
  CLS_LOG(10, "usage_iterate_range");

  map<string, bufferlist> keys;
#define NUM_KEYS 32
  string filter_prefix;
  string start_key, end_key;
  bool by_user = !user.empty();
  uint32_t i = 0;
  string user_key;

  if (truncated)
    *truncated = false;

  if (!by_user) {
    usage_record_prefix_by_time(end, end_key);
  } else {
    user_key = user;
    user_key.append("_");
  }

  if (key_iter.empty()) {
    if (by_user) {
      usage_record_prefix_by_user(user, start, start_key);
    } else {
      usage_record_prefix_by_time(start, start_key);
    }
  } else {
    start_key = key_iter;
  }

  do {
    CLS_LOG(20, "usage_iterate_range start_key=%s", start_key.c_str());
    int ret = cls_cxx_map_get_vals(hctx, start_key, filter_prefix, NUM_KEYS, &keys);
    if (ret < 0)
      return ret;


    map<string, bufferlist>::iterator iter = keys.begin();
    if (iter == keys.end())
      break;

    for (; iter != keys.end(); ++iter) {
      const string& key = iter->first;
      rgw_usage_log_entry e;

      if (!by_user && key.compare(end_key) >= 0) {
        CLS_LOG(20, "usage_iterate_range reached key=%s, done", key.c_str());
        return 0;
      }

      if (by_user && key.compare(0, user_key.size(), user_key) != 0) {
        CLS_LOG(20, "usage_iterate_range reached key=%s, done", key.c_str());
        return 0;
      }

      ret = usage_record_decode(iter->second, e);
      if (ret < 0)
        return ret;

      if (e.epoch < start)
	continue;

      /* keys are sorted by epoch, so once we're past end we're done */
      if (e.epoch >= end)
        return 0;

      ret = cb(hctx, key, e, param);
      if (ret < 0)
        return ret;


      i++;
      if (max_entries && (i > max_entries)) {
        CLS_LOG(20, "usage_iterate_range reached max_entries (%d), done", max_entries);
        *truncated = true;
        key_iter = key;
        return 0;
      }
    }
    --iter;
    start_key = iter->first;
  } while (true);
  return 0;
}

static int usage_log_read_cb(cls_method_context_t hctx, const string& key, rgw_usage_log_entry& entry, void *param)
{
  map<rgw_user_bucket, rgw_usage_log_entry> *usage = (map<rgw_user_bucket, rgw_usage_log_entry> *)param;
  rgw_user_bucket ub(entry.owner, entry.bucket);
  rgw_usage_log_entry& le = (*usage)[ub];
  le.aggregate(entry);
 
  return 0;
}

int rgw_user_usage_log_read(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  CLS_LOG(10, "rgw_user_usage_log_read()");

  bufferlist::iterator in_iter = in->begin();
  rgw_cls_usage_log_read_op op;

  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_user_usage_log_read(): failed to decode request\n");
    return -EINVAL;
  }

  rgw_cls_usage_log_read_ret ret_info;
  map<rgw_user_bucket, rgw_usage_log_entry> *usage = &ret_info.usage;
  string iter = op.iter;
#define MAX_ENTRIES 1000
  uint32_t max_entries = (op.max_entries ? op.max_entries : MAX_ENTRIES);
  int ret = usage_iterate_range(hctx, op.start_epoch, op.end_epoch, op.owner, iter, max_entries, &ret_info.truncated, usage_log_read_cb, (void *)usage);
  if (ret < 0)
    return ret;

  if (ret_info.truncated)
    ret_info.next_iter = iter;

  ::encode(ret_info, *out);
  return 0;
}

static int usage_log_trim_cb(cls_method_context_t hctx, const string& key, rgw_usage_log_entry& entry, void *param)
{
  string key_by_time;
  string key_by_user;

  usage_record_name_by_time(entry.epoch, entry.owner, entry.bucket, key_by_time);
  usage_record_name_by_user(entry.owner, entry.epoch, entry.bucket, key_by_user);

  int ret = cls_cxx_map_remove_key(hctx, key_by_time);
  if (ret < 0)
    return ret;

  return cls_cxx_map_remove_key(hctx, key_by_user);
}

int rgw_user_usage_log_trim(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  CLS_LOG(10, "rgw_user_usage_log_trim()");

  /* only continue if object exists! */
  int ret = cls_cxx_stat(hctx, NULL, NULL);
  if (ret < 0)
    return ret;

  bufferlist::iterator in_iter = in->begin();
  rgw_cls_usage_log_trim_op op;

  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_user_log_usage_log_trim(): failed to decode request\n");
    return -EINVAL;
  }

  string iter;
  ret = usage_iterate_range(hctx, op.start_epoch, op.end_epoch, op.user, iter, 0, NULL, usage_log_trim_cb, NULL);
  if (ret < 0)
    return ret;

  return 0;
}

/*
 * We hold the garbage collection chain data under two different indexes: the first 'name' index
 * keeps them under a unique tag that represents the chains, and a second 'time' index keeps
 * them by their expiration timestamp
 */
#define GC_OBJ_NAME_INDEX 0
#define GC_OBJ_TIME_INDEX 1

static string gc_index_prefixes[] = { "0_",
                                      "1_" };

static void prepend_index_prefix(const string& src, int index, string *dest)
{
  *dest = gc_index_prefixes[index];
  dest->append(src);
}

static int gc_omap_get(cls_method_context_t hctx, int type, const string& key, cls_rgw_gc_obj_info *info)
{
  string index;
  prepend_index_prefix(key, type, &index);

  bufferlist bl;
  int ret = cls_cxx_map_get_val(hctx, index, &bl);
  if (ret < 0)
    return ret;

  try {
    bufferlist::iterator iter = bl.begin();
    ::decode(*info, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: rgw_cls_gc_omap_get(): failed to decode index=%s\n", index.c_str());
  }

  return 0;
}

static int gc_omap_set(cls_method_context_t hctx, int type, const string& key, const cls_rgw_gc_obj_info *info)
{
  bufferlist bl;
  ::encode(*info, bl);

  string index = gc_index_prefixes[type];
  index.append(key);

  int ret = cls_cxx_map_set_val(hctx, index, &bl);
  if (ret < 0)
    return ret;

  return 0;
}

static int gc_omap_remove(cls_method_context_t hctx, int type, const string& key)
{
  string index = gc_index_prefixes[type];
  index.append(key);

  bufferlist bl;
  int ret = cls_cxx_map_remove_key(hctx, index);
  if (ret < 0)
    return ret;

  return 0;
}

static bool key_in_index(const string& key, int index_type)
{
  const string& prefix = gc_index_prefixes[index_type]; 
  return (key.compare(0, prefix.size(), prefix) == 0);
}


static int gc_update_entry(cls_method_context_t hctx, uint32_t expiration_secs,
                           cls_rgw_gc_obj_info& info)
{
  cls_rgw_gc_obj_info old_info;
  int ret = gc_omap_get(hctx, GC_OBJ_NAME_INDEX, info.tag, &old_info);
  if (ret == 0) {
    string key;
    get_time_key(old_info.time, &key);
    ret = gc_omap_remove(hctx, GC_OBJ_TIME_INDEX, key);
    if (ret < 0 && ret != -ENOENT) {
      CLS_LOG(0, "ERROR: failed to remove key=%s\n", key.c_str());
      return ret;
    }
  }
  info.time = ceph_clock_now(g_ceph_context);
  info.time += expiration_secs;
  ret = gc_omap_set(hctx, GC_OBJ_NAME_INDEX, info.tag, &info);
  if (ret < 0)
    return ret;

  string key;
  get_time_key(info.time, &key);
  ret = gc_omap_set(hctx, GC_OBJ_TIME_INDEX, key, &info);
  if (ret < 0)
    goto done_err;

  return 0;

done_err:
  CLS_LOG(0, "ERROR: gc_set_entry error info.tag=%s, ret=%d\n", info.tag.c_str(), ret);
  gc_omap_remove(hctx, GC_OBJ_NAME_INDEX, info.tag);
  return ret;
}

static int gc_defer_entry(cls_method_context_t hctx, const string& tag, uint32_t expiration_secs)
{
  cls_rgw_gc_obj_info info;
  int ret = gc_omap_get(hctx, GC_OBJ_NAME_INDEX, tag, &info);
  if (ret == -ENOENT)
    return 0;
  if (ret < 0)
    return ret;
  return gc_update_entry(hctx, expiration_secs, info);
}

int gc_record_decode(bufferlist& bl, cls_rgw_gc_obj_info& e)
{
  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(e, iter);
  } catch (buffer::error& err) {
    CLS_LOG(0, "ERROR: failed to decode cls_rgw_gc_obj_info");
    return -EIO;
  }
  return 0;
}

static int rgw_cls_gc_set_entry(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_gc_set_entry_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_cls_gc_set_entry(): failed to decode entry\n");
    return -EINVAL;
  }

  return gc_update_entry(hctx, op.expiration_secs, op.info);
}

static int rgw_cls_gc_defer_entry(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_gc_defer_entry_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_cls_gc_defer_entry(): failed to decode entry\n");
    return -EINVAL;
  }

  return gc_defer_entry(hctx, op.tag, op.expiration_secs);
}

static int gc_iterate_entries(cls_method_context_t hctx, const string& marker, bool expired_only,
                              string& key_iter, uint32_t max_entries, bool *truncated,
                              int (*cb)(cls_method_context_t, const string&, cls_rgw_gc_obj_info&, void *),
                              void *param)
{
  CLS_LOG(10, "gc_iterate_range");

  map<string, bufferlist> keys;
  string filter_prefix, end_key;
  uint32_t i = 0;
  string key;

  if (truncated)
    *truncated = false;

  string start_key;
  if (key_iter.empty()) {
    prepend_index_prefix(marker, GC_OBJ_TIME_INDEX, &start_key);
  } else {
    start_key = key_iter;
  }

  if (expired_only) {
    utime_t now = ceph_clock_now(g_ceph_context);
    string now_str;
    get_time_key(now, &now_str);
    prepend_index_prefix(now_str, GC_OBJ_TIME_INDEX, &end_key);

    CLS_LOG(0, "gc_iterate_entries end_key=%s\n", end_key.c_str());
  }

  string filter;

  do {
#define GC_NUM_KEYS 32
    int ret = cls_cxx_map_get_vals(hctx, start_key, filter, GC_NUM_KEYS, &keys);
    if (ret < 0)
      return ret;


    map<string, bufferlist>::iterator iter = keys.begin();
    if (iter == keys.end())
      break;

    for (; iter != keys.end(); ++iter) {
      const string& key = iter->first;
      cls_rgw_gc_obj_info e;

      CLS_LOG(10, "gc_iterate_entries key=%s\n", key.c_str());

      if (!end_key.empty() && key.compare(end_key) >= 0)
        return 0;

      if (!key_in_index(key, GC_OBJ_TIME_INDEX))
	return 0;

      ret = gc_record_decode(iter->second, e);
      if (ret < 0)
        return ret;

      if (max_entries && (i >= max_entries)) {
        if (truncated)
          *truncated = true;
        key_iter = key;
        return 0;
      }

      ret = cb(hctx, key, e, param);
      if (ret < 0)
        return ret;
      i++;

    }
    --iter;
    start_key = iter->first;
  } while (true);
  return 0;
}

static int gc_list_cb(cls_method_context_t hctx, const string& key, cls_rgw_gc_obj_info& info, void *param)
{
  list<cls_rgw_gc_obj_info> *l = (list<cls_rgw_gc_obj_info> *)param;
  l->push_back(info);
  return 0;
}

static int gc_list_entries(cls_method_context_t hctx, const string& marker,
			   uint32_t max, bool expired_only,
                           list<cls_rgw_gc_obj_info>& entries, bool *truncated)
{
  string key_iter;
  int ret = gc_iterate_entries(hctx, marker, expired_only,
                              key_iter, max, truncated,
                              gc_list_cb, &entries);
  return ret;
}

static int rgw_cls_gc_list(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_gc_list_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_cls_gc_list(): failed to decode entry\n");
    return -EINVAL;
  }

  cls_rgw_gc_list_ret op_ret;
  int ret = gc_list_entries(hctx, op.marker, op.max, op.expired_only, op_ret.entries, &op_ret.truncated);
  if (ret < 0)
    return ret;

  ::encode(op_ret, *out);

  return 0;
}

static int gc_remove(cls_method_context_t hctx, list<string>& tags)
{
  list<string>::iterator iter;

  for (iter = tags.begin(); iter != tags.end(); ++iter) {
    string& tag = *iter;
    cls_rgw_gc_obj_info info;
    int ret = gc_omap_get(hctx, GC_OBJ_NAME_INDEX, tag, &info);
    if (ret == -ENOENT) {
      CLS_LOG(0, "couldn't find tag in name index tag=%s\n", tag.c_str());
      continue;
    }

    if (ret < 0)
      return ret;

    string time_key;
    get_time_key(info.time, &time_key);
    ret = gc_omap_remove(hctx, GC_OBJ_TIME_INDEX, time_key);
    if (ret < 0 && ret != -ENOENT)
      return ret;
    if (ret == -ENOENT) {
      CLS_LOG(0, "couldn't find key in time index key=%s\n", time_key.c_str());
    }

    ret = gc_omap_remove(hctx, GC_OBJ_NAME_INDEX, tag);
    if (ret < 0 && ret != -ENOENT)
      return ret;
  }

  return 0;
}

static int rgw_cls_gc_remove(cls_method_context_t hctx, bufferlist *in, bufferlist *out)
{
  bufferlist::iterator in_iter = in->begin();

  cls_rgw_gc_remove_op op;
  try {
    ::decode(op, in_iter);
  } catch (buffer::error& err) {
    CLS_LOG(1, "ERROR: rgw_cls_gc_remove(): failed to decode entry\n");
    return -EINVAL;
  }

  return gc_remove(hctx, op.tags);
}

void __cls_init()
{
  CLS_LOG(1, "Loaded rgw class!");

  cls_register("rgw", &h_class);

  /* bucket index */
  cls_register_cxx_method(h_class, "bucket_init_index", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_init_index, &h_rgw_bucket_init_index);
  cls_register_cxx_method(h_class, "bucket_set_tag_timeout", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_set_tag_timeout, &h_rgw_bucket_set_tag_timeout);
  cls_register_cxx_method(h_class, "bucket_list", CLS_METHOD_RD, rgw_bucket_list, &h_rgw_bucket_list);
  cls_register_cxx_method(h_class, "bucket_check_index", CLS_METHOD_RD, rgw_bucket_check_index, &h_rgw_bucket_check_index);
  cls_register_cxx_method(h_class, "bucket_rebuild_index", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_rebuild_index, &h_rgw_bucket_rebuild_index);
  cls_register_cxx_method(h_class, "bucket_prepare_op", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_prepare_op, &h_rgw_bucket_prepare_op);
  cls_register_cxx_method(h_class, "bucket_complete_op", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_complete_op, &h_rgw_bucket_complete_op);
  cls_register_cxx_method(h_class, "bucket_link_olh", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_link_olh, &h_rgw_bucket_link_olh);
  cls_register_cxx_method(h_class, "bucket_read_olh_log", CLS_METHOD_RD, rgw_bucket_read_olh_log, &h_rgw_bucket_read_olh_log);
  cls_register_cxx_method(h_class, "bucket_trim_olh_log", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bucket_trim_olh_log, &h_rgw_bucket_trim_olh_log);

  cls_register_cxx_method(h_class, "obj_remove", CLS_METHOD_RD | CLS_METHOD_WR, rgw_obj_remove, &h_rgw_obj_remove);

  cls_register_cxx_method(h_class, "bi_log_list", CLS_METHOD_RD, rgw_bi_log_list, &h_rgw_bi_log_list_op);
  cls_register_cxx_method(h_class, "bi_log_trim", CLS_METHOD_RD | CLS_METHOD_WR, rgw_bi_log_trim, &h_rgw_bi_log_list_op);
  cls_register_cxx_method(h_class, "dir_suggest_changes", CLS_METHOD_RD | CLS_METHOD_WR, rgw_dir_suggest_changes, &h_rgw_dir_suggest_changes);

  /* usage logging */
  cls_register_cxx_method(h_class, "user_usage_log_add", CLS_METHOD_RD | CLS_METHOD_WR, rgw_user_usage_log_add, &h_rgw_user_usage_log_add);
  cls_register_cxx_method(h_class, "user_usage_log_read", CLS_METHOD_RD, rgw_user_usage_log_read, &h_rgw_user_usage_log_read);
  cls_register_cxx_method(h_class, "user_usage_log_trim", CLS_METHOD_RD | CLS_METHOD_WR, rgw_user_usage_log_trim, &h_rgw_user_usage_log_trim);

  /* garbage collection */
  cls_register_cxx_method(h_class, "gc_set_entry", CLS_METHOD_RD | CLS_METHOD_WR, rgw_cls_gc_set_entry, &h_rgw_gc_set_entry);
  cls_register_cxx_method(h_class, "gc_defer_entry", CLS_METHOD_RD | CLS_METHOD_WR, rgw_cls_gc_defer_entry, &h_rgw_gc_set_entry);
  cls_register_cxx_method(h_class, "gc_list", CLS_METHOD_RD, rgw_cls_gc_list, &h_rgw_gc_list);
  cls_register_cxx_method(h_class, "gc_remove", CLS_METHOD_RD | CLS_METHOD_WR, rgw_cls_gc_remove, &h_rgw_gc_remove);

  return;
}

