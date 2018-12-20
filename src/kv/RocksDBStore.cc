// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <set>
#include <map>
#include <string>
#include <memory>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rocksdb/db.h"
#include "rocksdb/table.h"
#include "rocksdb/env.h"
#include "rocksdb/slice.h"
#include "rocksdb/cache.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/utilities/convenience.h"
#include "rocksdb/merge_operator.h"

using std::string;
#include "common/perf_counters.h"
#include "common/PriorityCache.h"
#include "include/str_list.h"
#include "include/stringify.h"
#include "include/str_map.h"
#include "KeyValueDB.h"
#include "RocksDBStore.h"

#include "common/debug.h"

#define dout_context cct
#define dout_subsys ceph_subsys_rocksdb
#undef dout_prefix
#define dout_prefix *_dout << "rocksdb: "

static bufferlist to_bufferlist(rocksdb::Slice in) {
  bufferlist bl;
  bl.append(bufferptr(in.data(), in.size()));
  return bl;
}

static rocksdb::SliceParts prepare_sliceparts(const bufferlist &bl,
					      vector<rocksdb::Slice> *slices)
{
  unsigned n = 0;
  for (auto& buf : bl.buffers()) {
    (*slices)[n].data_ = buf.c_str();
    (*slices)[n].size_ = buf.length();
    n++;
  }
  return rocksdb::SliceParts(slices->data(), slices->size());
}

struct RocksDBStore::ColumnFamilyData {
    string options;                   ///< specific configure option string for this CF
    ColumnFamilyHandle handle;        ///< handle to column family
    ColumnFamilyData(const string &options, ColumnFamilyHandle handle = ColumnFamilyHandle())
      : options(options), handle(handle) {}
    ColumnFamilyData() {}
  };

//
// One of these for the default rocksdb column family, routing each prefix
// to the appropriate MergeOperator.
//
class RocksDBStore::MergeOperatorRouter
  : public rocksdb::AssociativeMergeOperator
{
protected:
  const RocksDBStore& store;
  mutable std::string name;
public:
  const char *Name() const override {
    // Construct a name that rocksDB will validate against. We want to
    // do this in a way that doesn't constrain the ordering of calls
    // to set_merge_operator, so sort the merge operators and then
    // construct a name from all of those parts.
    name.clear();
    map<std::string,std::string> names;

    for (auto& p : store.merge_ops) {
      names[p.first] = p.second->name();
    }
    for (auto& p : store.cf_mono_handles) {
      names.erase(p.first);
    }
    for (auto& p : names) {
      name += '.';
      name += p.first;
      name += ':';
      name += p.second;
    }
    return name.c_str();
  }

  explicit MergeOperatorRouter(const RocksDBStore &store) : store(store) {}

  bool Merge(const rocksdb::Slice& key,
	     const rocksdb::Slice* existing_value,
	     const rocksdb::Slice& value,
	     std::string* new_value,
	     rocksdb::Logger* logger) const override {
    // for default column family
    // extract prefix from key and compare against each registered merge op;
    // even though merge operator for explicit CF is included in merge_ops,
    // it won't be picked up, since it won't match.
    for (auto& p : store.merge_ops) {
      if (p.first.compare(0, p.first.length(),
			  key.data(), p.first.length()) == 0 &&
	  key.data()[p.first.length()] == 0) {
	if (existing_value) {
	  p.second->merge(existing_value->data(), existing_value->size(),
			  value.data(), value.size(),
			  new_value);
	} else {
	  p.second->merge_nonexistent(value.data(), value.size(), new_value);
	}
	break;
      }
    }
    return true; // OK :)
  }
};

//
// One of these per non-default column family, linked directly to the
// merge operator for that CF/prefix (if any).
//
class RocksDBStore::MergeOperatorLinker
  : public rocksdb::AssociativeMergeOperator
{
private:
  std::shared_ptr<KeyValueDB::MergeOperator> mop;
public:
  explicit MergeOperatorLinker(const std::shared_ptr<KeyValueDB::MergeOperator> &o) : mop(o) {}

  const char *Name() const override {
    return mop->name();
  }

  bool Merge(const rocksdb::Slice& key,
	     const rocksdb::Slice* existing_value,
	     const rocksdb::Slice& value,
	     std::string* new_value,
	     rocksdb::Logger* logger) const override {
    if (existing_value) {
      mop->merge(existing_value->data(), existing_value->size(),
		 value.data(), value.size(),
		 new_value);
    } else {
      mop->merge_nonexistent(value.data(), value.size(), new_value);
    }
    return true;
  }
};

//
// Merge operator that encompasses all prefixes.
//
class RocksDBStore::MergeOperatorAll : public RocksDBStore::MergeOperatorRouter
{
public:
  const char *Name() const override {
    name.clear();
    for (auto& p : store.merge_ops) {
      name += '.';
      name += p.first;
      name += ':';
      name += p.second->name();
    }
    return name.c_str();
  }

  explicit MergeOperatorAll(const RocksDBStore &store) : MergeOperatorRouter(store) {}
};

struct RocksWBHandler: public rocksdb::WriteBatch::Handler {
  RocksWBHandler(const RocksDBStore& db) : db(db) {}
  const RocksDBStore& db;
  std::stringstream seen ;
  int num_seen = 0;
  static string pretty_binary_string(const string& in) {
    char buf[10];
    string out;
    out.reserve(in.length() * 3);
    enum { NONE, HEX, STRING } mode = NONE;
    unsigned from = 0, i;
    for (i=0; i < in.length(); ++i) {
      if ((in[i] < 32 || (unsigned char)in[i] > 126) ||
        (mode == HEX && in.length() - i >= 4 &&
        ((in[i] < 32 || (unsigned char)in[i] > 126) ||
        (in[i+1] < 32 || (unsigned char)in[i+1] > 126) ||
        (in[i+2] < 32 || (unsigned char)in[i+2] > 126) ||
        (in[i+3] < 32 || (unsigned char)in[i+3] > 126)))) {

        if (mode == STRING) {
          out.append(in.substr(from, i - from));
          out.push_back('\'');
        }
        if (mode != HEX) {
          out.append("0x");
          mode = HEX;
        }
        if (in.length() - i >= 4) {
          // print a whole u32 at once
          snprintf(buf, sizeof(buf), "%08x",
                (uint32_t)(((unsigned char)in[i] << 24) |
                          ((unsigned char)in[i+1] << 16) |
                          ((unsigned char)in[i+2] << 8) |
                          ((unsigned char)in[i+3] << 0)));
          i += 3;
        } else {
          snprintf(buf, sizeof(buf), "%02x", (int)(unsigned char)in[i]);
        }
        out.append(buf);
      } else {
        if (mode != STRING) {
          out.push_back('\'');
          mode = STRING;
          from = i;
        }
      }
    }
    if (mode == STRING) {
      out.append(in.substr(from, i - from));
      out.push_back('\'');
    }
    return out;
  }
  void dump(const char* op_name,
            uint32_t column_family_id,
            const rocksdb::Slice& key,
            const rocksdb::Slice* value = nullptr) {
    string prefix;
    string key_to_decode;
    ssize_t size = value ? value->size() : -1;
    seen << std::endl << op_name << "(";

    bool mono = false;
    if (column_family_id != 0) {
      auto cf = db.cf_get_by_rocksdb_ID(column_family_id);
      seen << " column family = " << cf.first;
      if (db.cf_get_mono_handle(cf.first) != nullptr) {
        prefix = cf.first;
        key_to_decode = key.ToString();
        mono = true;
      }
    }
    if (!mono) {
      db.split_key(key, &prefix, &key_to_decode);
    }
    seen << " prefix = " << prefix;
    seen << " key = " << pretty_binary_string(key_to_decode);
    if (size != -1)
      seen << " value size = " << std::to_string(size);
    seen << ")";
    num_seen++;
  }
  void Put(const rocksdb::Slice& key,
                  const rocksdb::Slice& value) override {
    dump("Put", 0, key, &value);
  }
  rocksdb::Status PutCF(uint32_t column_family_id, const rocksdb::Slice& key,
                           const rocksdb::Slice& value) override {
    dump("PutCF", column_family_id, key, &value);
    return rocksdb::Status::OK();
  }
  void SingleDelete(const rocksdb::Slice& key) override {
    dump("SingleDelete", 0, key);
  }
  rocksdb::Status SingleDeleteCF(uint32_t column_family_id, const rocksdb::Slice& key) override {
    dump("SingleDeleteCF", column_family_id, key);
    return rocksdb::Status::OK();
  }
  void Delete(const rocksdb::Slice& key) override {
    dump("Delete", 0, key);
  }
  rocksdb::Status DeleteCF(uint32_t column_family_id, const rocksdb::Slice& key) override {
    dump("DeleteCF", column_family_id, key);
    return rocksdb::Status::OK();
  }

  void Merge(const rocksdb::Slice& key,
                    const rocksdb::Slice& value) override {
    dump("Merge", 0, key, &value);
  }
  rocksdb::Status MergeCF(uint32_t column_family_id, const rocksdb::Slice& key,
                         const rocksdb::Slice& value) override {
    dump("MergeCF", column_family_id, key, &value);
    return rocksdb::Status::OK();
  }

  bool Continue() override { return num_seen < 50; }
};

int RocksDBStore::set_merge_operator(
  const string& prefix,
  std::shared_ptr<KeyValueDB::MergeOperator> mop)
{
  // If you fail here, it's because you can't do this on an open database
  ceph_assert(db == nullptr);
  merge_ops.emplace(prefix, mop);
  return 0;
}

uint64_t RocksDBStore::get_estimated_size(map<string,uint64_t> &extra) {
  DIR *store_dir = opendir(path.c_str());
  if (!store_dir) {
    lderr(cct) << __func__ << " something happened opening the store: "
        << cpp_strerror(errno) << dendl;
    return 0;
  }

  uint64_t total_size = 0;
  uint64_t sst_size = 0;
  uint64_t log_size = 0;
  uint64_t misc_size = 0;

  struct dirent *entry = NULL;
  while ((entry = readdir(store_dir)) != NULL) {
    string n(entry->d_name);

    if (n == "." || n == "..")
      continue;

    string fpath = path + '/' + n;
    struct stat s;
    int err = stat(fpath.c_str(), &s);
    if (err < 0)
      err = -errno;
    // we may race against rocksdb while reading files; this should only
    // happen when those files are being updated, data is being shuffled
    // and files get removed, in which case there's not much of a problem
    // as we'll get to them next time around.
    if (err == -ENOENT) {
      continue;
    }
    if (err < 0) {
      lderr(cct) << __func__ << " error obtaining stats for " << fpath
          << ": " << cpp_strerror(err) << dendl;
      goto err;
    }

    size_t pos = n.find_last_of('.');
    if (pos == string::npos) {
      misc_size += s.st_size;
      continue;
    }

    string ext = n.substr(pos+1);
    if (ext == "sst") {
      sst_size += s.st_size;
    } else if (ext == "log") {
      log_size += s.st_size;
    } else {
      misc_size += s.st_size;
    }
  }

  total_size = sst_size + log_size + misc_size;

  extra["sst"] = sst_size;
  extra["log"] = log_size;
  extra["misc"] = misc_size;
  extra["total"] = total_size;

  err:
  closedir(store_dir);
  return total_size;
}

class CephRocksdbLogger : public rocksdb::Logger {
  CephContext *cct;
public:
  explicit CephRocksdbLogger(CephContext *c) : cct(c) {
    cct->get();
  }
  ~CephRocksdbLogger() override {
    cct->put();
  }

  // Write an entry to the log file with the specified format.
  void Logv(const char* format, va_list ap) override {
    Logv(rocksdb::INFO_LEVEL, format, ap);
  }

  // Write an entry to the log file with the specified log level
  // and format.  Any log with level under the internal log level
  // of *this (see @SetInfoLogLevel and @GetInfoLogLevel) will not be
  // printed.
  void Logv(const rocksdb::InfoLogLevel log_level, const char* format,
	    va_list ap) override {
    int v = rocksdb::NUM_INFO_LOG_LEVELS - log_level - 1;
    dout(ceph::dout::need_dynamic(v));
    char buf[65536];
    vsnprintf(buf, sizeof(buf), format, ap);
    *_dout << buf << dendl;
  }
};

rocksdb::Logger *create_rocksdb_ceph_logger()
{
  return new CephRocksdbLogger(g_ceph_context);
}

static int string2bool(const string &val, bool &b_val)
{
  if (strcasecmp(val.c_str(), "false") == 0) {
    b_val = false;
    return 0;
  } else if (strcasecmp(val.c_str(), "true") == 0) {
    b_val = true;
    return 0;
  } else {
    std::string err;
    int b = strict_strtol(val.c_str(), 10, &err);
    if (!err.empty())
      return -EINVAL;
    b_val = !!b;
    return 0;
  }
}
  
int RocksDBStore::tryInterpret(const string &key, const string &val, rocksdb::Options &opt)
{
  if (key == "compaction_threads") {
    std::string err;
    int f = strict_iecstrtoll(val.c_str(), &err);
    if (!err.empty())
      return -EINVAL;
    //Low priority threadpool is used for compaction
    opt.env->SetBackgroundThreads(f, rocksdb::Env::Priority::LOW);
  } else if (key == "flusher_threads") {
    std::string err;
    int f = strict_iecstrtoll(val.c_str(), &err);
    if (!err.empty())
      return -EINVAL;
    //High priority threadpool is used for flusher
    opt.env->SetBackgroundThreads(f, rocksdb::Env::Priority::HIGH);
  } else if (key == "compact_on_mount") {
    int ret = string2bool(val, compact_on_mount);
    if (ret != 0)
      return ret;
  } else if (key == "disableWAL") {
    int ret = string2bool(val, disableWAL);
    if (ret != 0)
      return ret;
  } else {
    //unrecognize config options.
    return -EINVAL;
  }
  return 0;
}

int RocksDBStore::ParseOptionsFromString(const string &opt_str, rocksdb::Options &opt)
{
  return ParseOptionsFromStringStatic(cct, opt_str, opt,
    [&](const string& k, const string& v, rocksdb::Options& o) {
      return tryInterpret(k, v, o);
    }
  );
}

int RocksDBStore::ParseOptionsFromStringStatic(
  CephContext *cct,
  const string& opt_str,
  rocksdb::Options& opt,
  function<int(const string&, const string&, rocksdb::Options&)> interp)
{
  map<string, string> str_map;
  int r = get_str_map(opt_str, &str_map, ",\n;");
  if (r < 0)
    return r;
  map<string, string>::iterator it;
  for (it = str_map.begin(); it != str_map.end(); ++it) {
    string this_opt = it->first + "=" + it->second;
    rocksdb::Status status =
      rocksdb::GetOptionsFromString(opt, this_opt, &opt);
    if (!status.ok()) {
      r = interp != nullptr ? interp(it->first, it->second, opt) : -1;
      if (r < 0) {
        derr << status.ToString() << dendl;
        return -EINVAL;
      }
    }
    lgeneric_dout(cct, 0) << " set rocksdb option " << it->first
      << " = " << it->second << dendl;
  }
  return 0;
}

int RocksDBStore::init(string _options_str)
{
  options_str = _options_str;
  rocksdb::Options opt;
  //try parse options
  if (options_str.length()) {
    int r = ParseOptionsFromString(options_str, opt);
    if (r != 0) {
      return -EINVAL;
    }
  }
  return 0;
}

int RocksDBStore::create_db_dir()
{
  if (env) {
    unique_ptr<rocksdb::Directory> dir;
    env->NewDirectory(path, &dir);
  } else {
    int r = ::mkdir(path.c_str(), 0755);
    if (r < 0)
      r = -errno;
    if (r < 0 && r != -EEXIST) {
      derr << __func__ << " failed to create " << path << ": " << cpp_strerror(r)
	   << dendl;
      return r;
    }
  }
  return 0;
}

int RocksDBStore::open(ostream &out, const std::vector<ColumnFamily>& options)
{
  return _open(out, false, options);
}

int RocksDBStore::open_read_only(ostream &out, const std::vector<ColumnFamily>& options)
{
  return _open(out, true, options);
}

int RocksDBStore::_open(ostream &out, bool read_only, const std::vector<ColumnFamily>& options)
{
  RWLock::WLocker l(api_lock);
  int r = create_db_dir();
  if (r < 0)
    return r;
  r = load_rocksdb_options(false, rocksdb_options);
  if (r) {
    dout(1) << __func__ << " load rocksdb options failed" << dendl;
    return r;
  }

  rocksdb::Status status;
  std::vector<string> existing_cfs;
  status = rocksdb::DB::ListColumnFamilies(
    rocksdb::DBOptions(rocksdb_options), path, &existing_cfs);
  dout(1) << __func__ << " existing column families: " << existing_cfs << dendl;
  if (existing_cfs.empty()) {
    // no column families
    if (read_only) {
      status = rocksdb::DB::OpenForReadOnly(rocksdb_options, path, &db);
    } else {
      status = rocksdb::DB::Open(rocksdb_options, path, &db);
    }
    if (!status.ok()) {
      derr << status.ToString() << dendl;
      return -EINVAL;
    }
    default_cf = db->DefaultColumnFamily();
  } else {
    // we cannot change column families for a created database.  so, map
    // what options we are given to whatever cf's already exist.
    std::vector<rocksdb::ColumnFamilyDescriptor> column_family_descriptors;
    for (auto& cf_name : existing_cfs) {
      // copy default CF settings, block cache, merge operators as
      // the base for new CF
      rocksdb::ColumnFamilyOptions cf_opt(rocksdb_options);
      std::string cf_specific_options;
      for (auto& i : options) {
        if (i.name == cf_name) {
          cf_specific_options = i.option;
          break;
        }
      }
      //mark existence of new column_family
      column_families.emplace(cf_name, ColumnFamilyData(cf_specific_options, ColumnFamilyHandle()));
      status = rocksdb::GetColumnFamilyOptionsFromString(
          cf_opt, cf_specific_options, &cf_opt);
      if (!status.ok()) {
        derr << __func__ << " invalid db column family options for CF '"
            << cf_name << "': " << cf_specific_options << dendl;
        return -EINVAL;
      }
      //find proper merge operator for column family
      std::shared_ptr<rocksdb::MergeOperator> mo = cf_get_merge_operator(cf_name);
      cf_opt.merge_operator = mo;
      column_family_descriptors.push_back(
          rocksdb::ColumnFamilyDescriptor(cf_name, cf_opt));
    }
    std::vector<rocksdb::ColumnFamilyHandle*> handles;
    if (read_only) {
      status = rocksdb::DB::OpenForReadOnly(rocksdb::DBOptions(rocksdb_options),
                               path, column_family_descriptors, &handles, &db);

    } else {
      status = rocksdb::DB::Open(rocksdb::DBOptions(rocksdb_options),
                               path, column_family_descriptors, &handles, &db);
    }
    
    if (!status.ok()) {
      derr << status.ToString() << dendl;
      return -EINVAL;
    }

    for (size_t i = 0; i < existing_cfs.size(); ++i) {
      if (existing_cfs[i] == rocksdb::kDefaultColumnFamilyName) {
        default_cf = handles[i];
        must_close_default_cf = true;
      } else {
        // add_column_family(existing_cfs[i], static_cast<void*>(handles[i]));
        // store the new CF handle
        auto it = merge_ops.find(existing_cfs[i]);
        if (it != merge_ops.end()) {
          //this is creation of mono column family
          cf_mono_handles.emplace(existing_cfs[i], cf_wrap_handle(handles[i]));
        }
        column_families[existing_cfs[i]].handle = cf_wrap_handle(handles[i]);
      }
    }
  }
  ceph_assert(default_cf != nullptr);
  perf_counters_register();
  if (compact_on_mount) {
    derr << "Compacting rocksdb store..." << dendl;
    compact();
    derr << "Finished compacting rocksdb store" << dendl;
  }
  return 0;
}

int RocksDBStore::create_and_open(ostream &out,
				  const vector<ColumnFamily>& to_create)
{
  RWLock::WLocker l(api_lock);
  int r = create_db_dir();
  if (r < 0)
    return r;
  r = load_rocksdb_options(true, rocksdb_options);
  if (r < 0)
    return r;
  rocksdb::Status status;
  status = rocksdb::DB::Open(rocksdb_options, path, &db);
  if (!status.ok()) {
    derr << status.ToString() << dendl;
    return -EINVAL;
  }
  default_cf = db->DefaultColumnFamily();
  ceph_assert(default_cf != nullptr);
  r=0;
  for (size_t i=0; r==0 && i < to_create.size(); i++) {
    r = cf_create(to_create[i].name, to_create[i].option);
    if (r < 0)
      return r;
  }
  perf_counters_register();

  return r;
}

int RocksDBStore::load_rocksdb_options(bool create_if_missing, rocksdb::Options& opt)
{
  rocksdb::Status status;

  if (options_str.length()) {
    int r = ParseOptionsFromString(options_str, opt);
    if (r != 0) {
      return -EINVAL;
    }
  }

  if (g_conf()->rocksdb_perf)  {
    dbstats = rocksdb::CreateDBStatistics();
    opt.statistics = dbstats;
  }

  opt.create_if_missing = create_if_missing;
  if (kv_options.count("separate_wal_dir")) {
    opt.wal_dir = path + ".wal";
  }

  // Since ceph::for_each_substr doesn't return a value and
  // std::stoull does throw, we may as well just catch everything here.
  try {
    if (kv_options.count("db_paths")) {
      list<string> paths;
      get_str_list(kv_options["db_paths"], "; \t", paths);
      for (auto& p : paths) {
	size_t pos = p.find(',');
	if (pos == std::string::npos) {
	  derr << __func__ << " invalid db path item " << p << " in "
	       << kv_options["db_paths"] << dendl;
	  return -EINVAL;
	}
	string path = p.substr(0, pos);
	string size_str = p.substr(pos + 1);
	uint64_t size = atoll(size_str.c_str());
	if (!size) {
	  derr << __func__ << " invalid db path item " << p << " in "
	       << kv_options["db_paths"] << dendl;
	  return -EINVAL;
	}
	opt.db_paths.push_back(rocksdb::DbPath(path, size));
	dout(10) << __func__ << " db_path " << path << " size " << size << dendl;
      }
    }
  } catch (const std::system_error& e) {
    return -e.code().value();
  }

  if (g_conf()->rocksdb_log_to_ceph_log) {
    opt.info_log.reset(new CephRocksdbLogger(g_ceph_context));
  }

  if (priv) {
    dout(10) << __func__ << " using custom Env " << priv << dendl;
    opt.env = static_cast<rocksdb::Env*>(priv);
  }

  opt.env->SetAllowNonOwnerAccess(false);

  // caches
  if (!set_cache_flag) {
    cache_size = g_conf()->rocksdb_cache_size;
  }
  uint64_t row_cache_size = cache_size * g_conf()->rocksdb_cache_row_ratio;
  uint64_t block_cache_size = cache_size - row_cache_size;

  if (g_conf()->rocksdb_cache_type == "binned_lru") {
    bbt_opts.block_cache = rocksdb_cache::NewBinnedLRUCache(
      cct,
      block_cache_size,
      g_conf()->rocksdb_cache_shard_bits);
  } else if (g_conf()->rocksdb_cache_type == "lru") {
    bbt_opts.block_cache = rocksdb::NewLRUCache(
      block_cache_size,
      g_conf()->rocksdb_cache_shard_bits);
  } else if (g_conf()->rocksdb_cache_type == "clock") {
    bbt_opts.block_cache = rocksdb::NewClockCache(
      block_cache_size,
      g_conf()->rocksdb_cache_shard_bits);
    if (!bbt_opts.block_cache) {
      derr << "rocksdb_cache_type '" << g_conf()->rocksdb_cache_type
           << "' chosen, but RocksDB not compiled with LibTBB. "
           << dendl;
      return -EINVAL;
    }
  } else {
    derr << "unrecognized rocksdb_cache_type '" << g_conf()->rocksdb_cache_type
      << "'" << dendl;
    return -EINVAL;
  }
  bbt_opts.block_size = g_conf()->rocksdb_block_size;

  if (row_cache_size > 0)
    opt.row_cache = rocksdb::NewLRUCache(row_cache_size,
				     g_conf()->rocksdb_cache_shard_bits);
  uint64_t bloom_bits = g_conf().get_val<uint64_t>("rocksdb_bloom_bits_per_key");
  if (bloom_bits > 0) {
    dout(10) << __func__ << " set bloom filter bits per key to "
	     << bloom_bits << dendl;
    bbt_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(bloom_bits));
  }
  using std::placeholders::_1;
  if (g_conf().with_val<std::string>("rocksdb_index_type",
				    std::bind(std::equal_to<std::string>(), _1,
					      "binary_search")))
    bbt_opts.index_type = rocksdb::BlockBasedTableOptions::IndexType::kBinarySearch;
  if (g_conf().with_val<std::string>("rocksdb_index_type",
				    std::bind(std::equal_to<std::string>(), _1,
					      "hash_search")))
    bbt_opts.index_type = rocksdb::BlockBasedTableOptions::IndexType::kHashSearch;
  if (g_conf().with_val<std::string>("rocksdb_index_type",
				    std::bind(std::equal_to<std::string>(), _1,
					      "two_level")))
    bbt_opts.index_type = rocksdb::BlockBasedTableOptions::IndexType::kTwoLevelIndexSearch;
  if (!bbt_opts.no_block_cache) {
    bbt_opts.cache_index_and_filter_blocks =
        g_conf().get_val<bool>("rocksdb_cache_index_and_filter_blocks");
    bbt_opts.cache_index_and_filter_blocks_with_high_priority =
        g_conf().get_val<bool>("rocksdb_cache_index_and_filter_blocks_with_high_priority");
    bbt_opts.pin_l0_filter_and_index_blocks_in_cache =
      g_conf().get_val<bool>("rocksdb_pin_l0_filter_and_index_blocks_in_cache");
  }
  bbt_opts.partition_filters = g_conf().get_val<bool>("rocksdb_partition_filters");
  if (g_conf().get_val<Option::size_t>("rocksdb_metadata_block_size") > 0)
    bbt_opts.metadata_block_size = g_conf().get_val<Option::size_t>("rocksdb_metadata_block_size");

  opt.table_factory.reset(rocksdb::NewBlockBasedTableFactory(bbt_opts));
  dout(10) << __func__ << " block size " << g_conf()->rocksdb_block_size
           << ", block_cache size " << byte_u_t(block_cache_size)
	   << ", row_cache size " << byte_u_t(row_cache_size)
	   << "; shards "
	   << (1 << g_conf()->rocksdb_cache_shard_bits)
	   << ", type " << g_conf()->rocksdb_cache_type
	   << dendl;

  opt.merge_operator.reset(new MergeOperatorRouter(*this));

  return 0;
}

void RocksDBStore::perf_counters_register()
{
  PerfCountersBuilder plb(g_ceph_context, "rocksdb", l_rocksdb_first, l_rocksdb_last);
  plb.add_u64_counter(l_rocksdb_gets, "get", "Gets");
  plb.add_u64_counter(l_rocksdb_txns, "submit_transaction", "Submit transactions");
  plb.add_u64_counter(l_rocksdb_txns_sync, "submit_transaction_sync", "Submit transactions sync");
  plb.add_time_avg(l_rocksdb_get_latency, "get_latency", "Get latency");
  plb.add_time_avg(l_rocksdb_submit_latency, "submit_latency", "Submit Latency");
  plb.add_time_avg(l_rocksdb_submit_sync_latency, "submit_sync_latency", "Submit Sync Latency");
  plb.add_u64_counter(l_rocksdb_compact, "compact", "Compactions");
  plb.add_u64_counter(l_rocksdb_compact_range, "compact_range", "Compactions by range");
  plb.add_u64_counter(l_rocksdb_compact_queue_merge, "compact_queue_merge", "Mergings of ranges in compaction queue");
  plb.add_u64(l_rocksdb_compact_queue_len, "compact_queue_len", "Length of compaction queue");
  plb.add_time_avg(l_rocksdb_write_wal_time, "rocksdb_write_wal_time", "Rocksdb write wal time");
  plb.add_time_avg(l_rocksdb_write_memtable_time, "rocksdb_write_memtable_time", "Rocksdb write memtable time");
  plb.add_time_avg(l_rocksdb_write_delay_time, "rocksdb_write_delay_time", "Rocksdb write delay time");
  plb.add_time_avg(l_rocksdb_write_pre_and_post_process_time,
      "rocksdb_write_pre_and_post_time", "total time spent on writing a record, excluding write process");
  logger = plb.create_perf_counters();
  cct->get_perfcounters_collection()->add(logger);
}

int RocksDBStore::column_family_list(vector<std::string>& cf_names)
{
  RWLock::RLocker l(api_lock);
  cf_names.clear();
  rocksdb::Status status;
  std::vector<string> existing_cfs;
  status = rocksdb::DB::ListColumnFamilies(
    rocksdb::DBOptions(rocksdb_options), path, &existing_cfs);
  if (!status.ok()) {
    derr << status.ToString() << dendl;
    return -EINVAL;
  }
  cf_names = existing_cfs;
  return 0;
}

int RocksDBStore::column_family_create(const std::string& cf_name, const std::string& cf_options)
{
  RWLock::WLocker l(api_lock);
  return cf_create(cf_name, cf_options);
}

int RocksDBStore::column_family_delete(const std::string& cf_name)
{
  return -1;
}

KeyValueDB::ColumnFamilyHandle RocksDBStore::column_family_handle(const std::string& cf_name) const
{
  RWLock::RLocker l(api_lock);
  auto it = column_families.find(cf_name);
  if (it == column_families.end())
    return KeyValueDB::ColumnFamilyHandle();
 return it->second.handle;
}

/**
 * Get merge operator for column family.
 */
std::shared_ptr<rocksdb::MergeOperator>
RocksDBStore::cf_get_merge_operator(const std::string& cf_name) const
{
  auto i = merge_ops.find(cf_name);
  if (i != merge_ops.end()) {
    return std::shared_ptr<rocksdb::MergeOperator>(new MergeOperatorLinker(i->second));
  }
  //Column family name is not exact to any defined merge operators.
  //Use all-prefix merge operator.
  return std::shared_ptr<rocksdb::MergeOperator>(new RocksDBStore::MergeOperatorAll(*this));
}

/**
 * Returns handle to mono column family.
 * Does not return handles for regular column family, even if name matches
 */
rocksdb::ColumnFamilyHandle* RocksDBStore::cf_get_mono_handle(const std::string& cf_name) const
{
  auto iter = cf_mono_handles.find(cf_name);
  if (iter == cf_mono_handles.end())
    return nullptr;
  else
    return static_cast<rocksdb::ColumnFamilyHandle*>(iter->second.priv);
}

/**
 * Returns handle to column family.
 * This works for both mono column families and regular column families.
 */
rocksdb::ColumnFamilyHandle* RocksDBStore::cf_get_handle(const std::string& cf_name) const
{
  auto it = column_families.find(cf_name);
   if (it == column_families.end())
     return nullptr;
  return static_cast<rocksdb::ColumnFamilyHandle*>(it->second.handle.priv);
}

/**
 * Determines how 'prefix' should be handled.
 * It is a convenience function that allow to better structuralize conditions
 * in functions that operate on both mono column families and regular column families.
 *
 * Param:
 *  - cf [in] column family handle as requested by client
 *       [out] fixed column family handle after redirection
 *  - prefix [in] as requested by client
 * Result:
 *  true - we operate on mono column family, false - we operate on normal column family
 */
bool RocksDBStore::cf_check_mode(rocksdb::ColumnFamilyHandle* &cf, const string &prefix) const
{
  if (cf != nullptr) {
    return false;
  }
  cf = cf_get_mono_handle(prefix);
  if (cf != nullptr)
    return true;
  cf = default_cf;
  return false;
}

std::pair<std::string, RocksDBStore::ColumnFamilyHandle>
RocksDBStore::cf_get_by_rocksdb_ID(uint32_t ID) const
{
  for (auto& i : column_families) {
    rocksdb::ColumnFamilyHandle* cfh =
      static_cast<rocksdb::ColumnFamilyHandle*>(i.second.handle.priv);
    if (cfh->GetID() == ID)
      return std::make_pair(cfh->GetName(), i.second.handle);
  }
  return std::make_pair(std::string(), ColumnFamilyHandle());
}

int RocksDBStore::cf_create(const std::string& cf_name, const std::string& cf_options)
{
  rocksdb::Status status;
  // copy default CF settings, block cache, merge operators as
  // the base for new CF
  rocksdb::ColumnFamilyOptions cf_opt(rocksdb_options);
  // user input options will override the base options
  status = rocksdb::GetColumnFamilyOptionsFromString(
      cf_opt, cf_options, &cf_opt);
  if (!status.ok()) {
    derr << __func__ << " invalid db column family option string for CF: "
        << cf_name << dendl;
    return -EINVAL;
  }
  // find proper merge operator for column family
  std::shared_ptr<rocksdb::MergeOperator> mo = cf_get_merge_operator(cf_name);
  cf_opt.merge_operator = mo;

  rocksdb::ColumnFamilyHandle *cf_handle;
  status = db->CreateColumnFamily(cf_opt, cf_name, &cf_handle);
  if (!status.ok()) {
    derr << __func__ << " Failed to create rocksdb column family: "
        << cf_name << dendl;
    return -EINVAL;
  }
  // store the new CF handle
  auto i = merge_ops.find(cf_name);
  if (i != merge_ops.end()) {
    //this is creation of mono column family
    cf_mono_handles.emplace(cf_name, cf_wrap_handle(cf_handle));
  }
  column_families.emplace(cf_name, ColumnFamilyData(cf_options, cf_wrap_handle(cf_handle)));
  return 0;
}


KeyValueDB::ColumnFamilyHandle RocksDBStore::cf_wrap_handle(rocksdb::ColumnFamilyHandle* rocks_cfh)
{
  KeyValueDB::ColumnFamilyHandle cfh;
  cfh.priv = static_cast<void*>(rocks_cfh);
  return cfh;
}


int RocksDBStore::_test_init(const string& dir)
{
  rocksdb::Options options;
  options.create_if_missing = true;
  rocksdb::DB *db;
  rocksdb::Status status = rocksdb::DB::Open(options, dir, &db);
  delete db;
  db = nullptr;
  return status.ok() ? 0 : -EIO;
}

RocksDBStore::RocksDBStore(CephContext *c, const string &path, map<string,string> opt, void *p) :
  cct(c),
  logger(NULL),
  path(path),
  kv_options(opt),
  priv(p),
  db(NULL),
  env(static_cast<rocksdb::Env*>(p)),
  dbstats(NULL),
  api_lock("RocksDBStore::api_lock"),
  compact_queue_lock("RocksDBStore::compact_thread_lock"),
  compact_queue_stop(false),
  compact_thread(this),
  compact_on_mount(false),
  disableWAL(false),
  delete_range_threshold(cct->_conf.get_val<uint64_t>("rocksdb_delete_range_threshold"))
{}

RocksDBStore::~RocksDBStore()
{
  close();
  delete logger;

  // Ensure db is destroyed before dependent db_cache and filterpolicy
  for (auto& p : column_families) {
    db->DestroyColumnFamilyHandle(
      static_cast<rocksdb::ColumnFamilyHandle*>(p.second.handle.priv));
  }
  if (must_close_default_cf) {
    db->DestroyColumnFamilyHandle(default_cf);
    must_close_default_cf = false;
  }
  default_cf = nullptr;
  delete db;
  db = nullptr;

  if (priv) {
    delete static_cast<rocksdb::Env*>(priv);
  }
}

void RocksDBStore::close()
{
  // stop compaction thread
  compact_queue_lock.lock();
  if (compact_thread.is_started()) {
    dout(1) << __func__ << " waiting for compaction thread to stop" << dendl;
    compact_queue_stop = true;
    compact_queue_cond.notify_all();
    compact_queue_lock.unlock();
    compact_thread.join();
    dout(1) << __func__ << " compaction thread to stopped" << dendl;    
  } else {
    compact_queue_lock.unlock();
  }

  if (logger)
    cct->get_perfcounters_collection()->remove(logger);
}

int RocksDBStore::repair(std::ostream &out)
{
  rocksdb::Options opt;
  int r = load_rocksdb_options(false, opt);
  if (r) {
    dout(1) << __func__ << " load rocksdb options failed" << dendl;
    out << "load rocksdb options failed" << std::endl;
    return r;
  }
  rocksdb::Status status = rocksdb::RepairDB(path, opt);
  if (status.ok()) {
    return 0;
  } else {
    out << "repair rocksdb failed : " << status.ToString() << std::endl;
    return 1;
  }
}

void RocksDBStore::split_stats(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
}

bool RocksDBStore::get_property(
  const std::string &property,
  uint64_t *out)
{
  return db->GetIntProperty(property, out);
}

int64_t RocksDBStore::estimate_prefix_size(const string& prefix,
					   const string& key_prefix,
                                           KeyValueDB::ColumnFamilyHandle cfh)
{
  rocksdb::ColumnFamilyHandle* cf =
    static_cast<rocksdb::ColumnFamilyHandle *>(cfh.priv);
  bool is_mono = cf_check_mode(cf, prefix);
  uint64_t size = 0;
  uint8_t flags =
    //rocksdb::DB::INCLUDE_MEMTABLES |  // do not include memtables...
    rocksdb::DB::INCLUDE_FILES;
  if (is_mono) {
    string start = key_prefix + string(1, '\x00');
    string limit = key_prefix + string("\xff\xff\xff\xff");
    rocksdb::Range r(start, limit);
    db->GetApproximateSizes(cf, &r, 1, &size, flags);
  } else {
    string start = combine_strings(prefix, key_prefix);
    string limit = combine_strings(prefix, key_prefix + "\xff\xff\xff\xff");
    rocksdb::Range r(start, limit);
    db->GetApproximateSizes(cf, &r, 1, &size, flags);
  }
  return size;
}

void RocksDBStore::get_statistics(Formatter *f)
{
  if (!g_conf()->rocksdb_perf)  {
    dout(20) << __func__ << " RocksDB perf is disabled, can't probe for stats"
	     << dendl;
    return;
  }

  if (g_conf()->rocksdb_collect_compaction_stats) {
    std::string stat_str;
    bool status = db->GetProperty("rocksdb.stats", &stat_str);
    if (status) {
      f->open_object_section("rocksdb_statistics");
      f->dump_string("rocksdb_compaction_statistics", "");
      vector<string> stats;
      split_stats(stat_str, '\n', stats);
      for (auto st :stats) {
        f->dump_string("", st);
      }
      f->close_section();
    }
  }
  if (g_conf()->rocksdb_collect_extended_stats) {
    if (dbstats) {
      f->open_object_section("rocksdb_extended_statistics");
      string stat_str = dbstats->ToString();
      vector<string> stats;
      split_stats(stat_str, '\n', stats);
      f->dump_string("rocksdb_extended_statistics", "");
      for (auto st :stats) {
        f->dump_string(".", st);
      }
      f->close_section();
    }
    f->open_object_section("rocksdbstore_perf_counters");
    logger->dump_formatted(f,0);
    f->close_section();
  }
  if (g_conf()->rocksdb_collect_memory_stats) {
    f->open_object_section("rocksdb_memtable_statistics");
    std::string str;
    if (!bbt_opts.no_block_cache) {
      str.append(stringify(bbt_opts.block_cache->GetUsage()));
      f->dump_string("block_cache_usage", str.data());
      str.clear();
      str.append(stringify(bbt_opts.block_cache->GetPinnedUsage()));
      f->dump_string("block_cache_pinned_blocks_usage", str);
      str.clear();
    }
    db->GetProperty("rocksdb.cur-size-all-mem-tables", &str);
    f->dump_string("rocksdb_memtable_usage", str);
    str.clear();
    db->GetProperty("rocksdb.estimate-table-readers-mem", &str);
    f->dump_string("rocksdb_index_filter_blocks_usage", str);
    f->close_section();
  }
}

int RocksDBStore::submit_common(rocksdb::WriteOptions& woptions, KeyValueDB::Transaction t) 
{
  // enable rocksdb breakdown
  // considering performance overhead, default is disabled
  if (g_conf()->rocksdb_perf) {
    rocksdb::SetPerfLevel(rocksdb::PerfLevel::kEnableTimeExceptForMutex);
    rocksdb::get_perf_context()->Reset();
  }

  RocksDBTransactionImpl * _t =
    static_cast<RocksDBTransactionImpl *>(t.get());
  woptions.disableWAL = disableWAL;
  lgeneric_subdout(cct, rocksdb, 30) << __func__;
  RocksWBHandler bat_txc(*this);
  _t->bat.Iterate(&bat_txc);
  *_dout << " Rocksdb transaction: " << bat_txc.seen.str() << dendl;
  
  rocksdb::Status s = db->Write(woptions, &_t->bat);
  if (!s.ok()) {
    RocksWBHandler rocks_txc(*this);
    _t->bat.Iterate(&rocks_txc);
    derr << __func__ << " error: " << s.ToString() << " code = " << s.code()
         << " Rocksdb transaction: " << rocks_txc.seen.str() << dendl;
  }

  if (g_conf()->rocksdb_perf) {
    utime_t write_memtable_time;
    utime_t write_delay_time;
    utime_t write_wal_time;
    utime_t write_pre_and_post_process_time;
    write_wal_time.set_from_double(
	static_cast<double>(rocksdb::get_perf_context()->write_wal_time)/1000000000);
    write_memtable_time.set_from_double(
	static_cast<double>(rocksdb::get_perf_context()->write_memtable_time)/1000000000);
    write_delay_time.set_from_double(
	static_cast<double>(rocksdb::get_perf_context()->write_delay_time)/1000000000);
    write_pre_and_post_process_time.set_from_double(
	static_cast<double>(rocksdb::get_perf_context()->write_pre_and_post_process_time)/1000000000);
    logger->tinc(l_rocksdb_write_memtable_time, write_memtable_time);
    logger->tinc(l_rocksdb_write_delay_time, write_delay_time);
    logger->tinc(l_rocksdb_write_wal_time, write_wal_time);
    logger->tinc(l_rocksdb_write_pre_and_post_process_time, write_pre_and_post_process_time);
  }

  return s.ok() ? 0 : -1;
}

int RocksDBStore::submit_transaction(KeyValueDB::Transaction t) 
{
  utime_t start = ceph_clock_now();
  rocksdb::WriteOptions woptions;
  woptions.sync = false;

  int result = submit_common(woptions, t);

  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_txns);
  logger->tinc(l_rocksdb_submit_latency, lat);
  
  return result;
}

int RocksDBStore::submit_transaction_sync(KeyValueDB::Transaction t)
{
  utime_t start = ceph_clock_now();
  rocksdb::WriteOptions woptions;
  // if disableWAL, sync can't set
  woptions.sync = !disableWAL;
  
  int result = submit_common(woptions, t);
  
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_txns_sync);
  logger->tinc(l_rocksdb_submit_sync_latency, lat);

  return result;
}

RocksDBStore::RocksDBTransactionImpl::RocksDBTransactionImpl(RocksDBStore *_db)
: db(_db), cf_handle(nullptr) {}

void RocksDBStore::RocksDBTransactionImpl::put_bat(
  rocksdb::WriteBatch& bat,
  rocksdb::ColumnFamilyHandle *cf,
  const string &key,
  const bufferlist &to_set_bl)
{
  // bufferlist::c_str() is non-constant, so we can't call c_str()
  if (to_set_bl.is_contiguous() && to_set_bl.length() > 0) {
    bat.Put(cf,
	    rocksdb::Slice(key),
	    rocksdb::Slice(to_set_bl.buffers().front().c_str(),
			   to_set_bl.length()));
  } else {
    rocksdb::Slice key_slice(key);
    vector<rocksdb::Slice> value_slices(to_set_bl.buffers().size());
    bat.Put(cf,
	    rocksdb::SliceParts(&key_slice, 1),
            prepare_sliceparts(to_set_bl, &value_slices));
  }
}

void RocksDBStore::RocksDBTransactionImpl::set(
  const string &prefix,
  const string &k,
  const bufferlist &to_set_bl)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    put_bat(bat, cf, k, to_set_bl);
  } else {
    string key = combine_strings(prefix, k);
    put_bat(bat, cf, key, to_set_bl);
  }
}

void RocksDBStore::RocksDBTransactionImpl::set(
  const string &prefix,
  const char *k, size_t keylen,
  const bufferlist &to_set_bl)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    string key(k, keylen);  // fixme?
    put_bat(bat, cf, key, to_set_bl);
  } else {
    string key;
    combine_strings(prefix, k, keylen, &key);
    put_bat(bat, cf, key, to_set_bl);
  }
}

void RocksDBStore::RocksDBTransactionImpl::rmkey(const string &prefix,
					         const string &k)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    bat.Delete(cf, rocksdb::Slice(k));
  } else {
    bat.Delete(cf, combine_strings(prefix, k));
  }
}

void RocksDBStore::RocksDBTransactionImpl::rmkey(const string &prefix,
					         const char *k,
						 size_t keylen)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    bat.Delete(cf, rocksdb::Slice(k, keylen));
  } else {
    string key;
    combine_strings(prefix, k, keylen, &key);
    bat.Delete(cf, rocksdb::Slice(key));
  }
}

void RocksDBStore::RocksDBTransactionImpl::rm_single_key(const string &prefix,
					                 const string &k)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    bat.SingleDelete(cf, k);
  } else {
    bat.SingleDelete(cf, combine_strings(prefix, k));
  }
}

void RocksDBStore::RocksDBTransactionImpl::rmkeys_by_prefix(const string &prefix)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  bool is_mono = db->cf_check_mode(cf, prefix);
  uint64_t cnt = db->delete_range_threshold;
  bat.SetSavePoint();
  auto it = db->get_iterator(prefix);
  for (it->seek_to_first(); it->valid(); it->next()) {
    if (!cnt) {
      bat.RollbackToSavePoint();
      if (is_mono) {
        string endprefix = "\xff\xff\xff\xff";  // FIXME: this is cheating...
        bat.DeleteRange(cf, string(), endprefix);
      } else {
        string endprefix = prefix;
        endprefix.push_back('\x01');
	bat.DeleteRange(cf,
                        combine_strings(prefix, string()),
                        combine_strings(endprefix, string()));
      }
      return;
    }
    if (is_mono) {
      bat.Delete(cf, rocksdb::Slice(it->key()));
    } else {
      bat.Delete(cf, combine_strings(prefix, it->key()));
    }
    --cnt;
  }
  bat.PopSavePoint();
}

void RocksDBStore::RocksDBTransactionImpl::rm_range_keys(const string &prefix,
                                                         const string &start,
                                                         const string &end)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  bool is_mono = db->cf_check_mode(cf, prefix);
  uint64_t cnt = db->delete_range_threshold;
  auto it = db->get_iterator(prefix);
  bat.SetSavePoint();
  it->lower_bound(start);
  while (it->valid()) {
    if (it->key() >= end) {
      break;
    }
    if (!cnt) {
      bat.RollbackToSavePoint();
      if (is_mono) {
        bat.DeleteRange(cf, rocksdb::Slice(start), rocksdb::Slice(end));
      } else {
        bat.DeleteRange(cf,
                        rocksdb::Slice(combine_strings(prefix, start)),
                        rocksdb::Slice(combine_strings(prefix, end)));
      }
      return;
    }
    if (is_mono) {
      bat.Delete(cf, rocksdb::Slice(it->key()));
    } else {
      bat.Delete(cf, combine_strings(prefix, it->key()));
    }
    it->next();
    --cnt;
  }
  bat.PopSavePoint();
}

void RocksDBStore::RocksDBTransactionImpl::merge(
  const string &prefix,
  const string &k,
  const bufferlist &to_set_bl)
{
  rocksdb::ColumnFamilyHandle* cf = cf_handle;
  if (db->cf_check_mode(cf, prefix)) {
    // special mono column family case
    // bufferlist::c_str() is non-constant, so we can't call c_str()
    if (to_set_bl.is_contiguous() && to_set_bl.length() > 0) {
      bat.Merge(
       cf,
       rocksdb::Slice(k),
       rocksdb::Slice(to_set_bl.buffers().front().c_str(), to_set_bl.length()));
    } else {
      // make a copy
      rocksdb::Slice key_slice(k);
      vector<rocksdb::Slice> value_slices(to_set_bl.buffers().size());
      bat.Merge(cf, rocksdb::SliceParts(&key_slice, 1),
                prepare_sliceparts(to_set_bl, &value_slices));
    }
    return;
  } else {
    string key = combine_strings(prefix, k);
    // bufferlist::c_str() is non-constant, so we can't call c_str()
    if (to_set_bl.is_contiguous() && to_set_bl.length() > 0) {
      bat.Merge(
       cf,
       rocksdb::Slice(key),
       rocksdb::Slice(to_set_bl.buffers().front().c_str(), to_set_bl.length()));
    } else {
      // make a copy
      rocksdb::Slice key_slice(key);
      vector<rocksdb::Slice> value_slices(to_set_bl.buffers().size());
      bat.Merge(
       cf,
       rocksdb::SliceParts(&key_slice, 1),
       prepare_sliceparts(to_set_bl, &value_slices));
    }
  }
}

void RocksDBStore::RocksDBTransactionImpl::select(
    KeyValueDB::ColumnFamilyHandle column_family_handle)
{
  if (column_family_handle.priv != nullptr)
    cf_handle = static_cast<rocksdb::ColumnFamilyHandle *>(column_family_handle.priv);
  else
    cf_handle = nullptr;
}

int RocksDBStore::get(
    const string &prefix,
    const std::set<string> &keys,
    std::map<string, bufferlist> *out)
{
  utime_t start = ceph_clock_now();
  auto cf = cf_get_mono_handle(prefix);
  if (cf) {
    for (auto& key : keys) {
      std::string value;
      auto status = db->Get(rocksdb::ReadOptions(),
			    cf,
			    rocksdb::Slice(key),
			    &value);
      if (status.ok()) {
	(*out)[key].append(value);
      } else if (status.IsIOError()) {
	ceph_abort_msg(status.getState());
      }
    }
  } else {
    for (auto& key : keys) {
      std::string value;
      string k = combine_strings(prefix, key);
      auto status = db->Get(rocksdb::ReadOptions(),
			    default_cf,
			    rocksdb::Slice(k),
			    &value);
      if (status.ok()) {
	(*out)[key].append(value);
      } else if (status.IsIOError()) {
	ceph_abort_msg(status.getState());
      }
    }
  }
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_gets);
  logger->tinc(l_rocksdb_get_latency, lat);
  return 0;
}

int RocksDBStore::get(
    const string &prefix,
    const string &key,
    bufferlist *out)
{
  ceph_assert(out && (out->length() == 0));
  utime_t start = ceph_clock_now();
  int r = 0;
  string value;
  rocksdb::Status s;
  auto cf = cf_get_mono_handle(prefix);
  if (cf) {
    s = db->Get(rocksdb::ReadOptions(),
		cf,
		rocksdb::Slice(key),
		&value);
  } else {
    string k = combine_strings(prefix, key);
    s = db->Get(rocksdb::ReadOptions(),
		default_cf,
		rocksdb::Slice(k),
		&value);
  }
  if (s.ok()) {
    out->append(value);
  } else if (s.IsNotFound()) {
    r = -ENOENT;
  } else {
    ceph_abort_msg(s.getState());
  }
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_gets);
  logger->tinc(l_rocksdb_get_latency, lat);
  return r;
}

int RocksDBStore::get(
  const string& prefix,
  const char *key,
  size_t keylen,
  bufferlist *out)
{
  ceph_assert(out && (out->length() == 0));
  utime_t start = ceph_clock_now();
  int r = 0;
  string value;
  rocksdb::Status s;
  auto cf = cf_get_mono_handle(prefix);
  if (cf) {
    s = db->Get(rocksdb::ReadOptions(),
		cf,
		rocksdb::Slice(key, keylen),
		&value);
  } else {
    string k;
    combine_strings(prefix, key, keylen, &k);
    s = db->Get(rocksdb::ReadOptions(),
		default_cf,
		rocksdb::Slice(k),
		&value);
  }
  if (s.ok()) {
    out->append(value);
  } else if (s.IsNotFound()) {
    r = -ENOENT;
  } else {
    ceph_abort_msg(s.getState());
  }
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_gets);
  logger->tinc(l_rocksdb_get_latency, lat);
  return r;
}

int RocksDBStore::get(
    KeyValueDB::ColumnFamilyHandle cf_handle,
    const std::string &prefix,
    const std::set<std::string> &keys,
    std::map<std::string, bufferlist> *out) {
  utime_t start = ceph_clock_now();
  auto cf = static_cast<rocksdb::ColumnFamilyHandle*>(cf_handle.priv);
  if (cf_check_mode(cf, prefix)) {
    for (auto& key : keys) {
      std::string value;
      auto status = db->Get(rocksdb::ReadOptions(),
                            cf,
                            rocksdb::Slice(key),
                            &value);
      if (status.ok()) {
        (*out)[key].append(value);
      } else if (status.IsIOError()) {
        ceph_abort_msg(status.getState());
      }
    }
  } else {
    for (auto& key : keys) {
      std::string value;
      string k = combine_strings(prefix, key);
      auto status = db->Get(rocksdb::ReadOptions(),
                            cf,
                            rocksdb::Slice(k),
                            &value);
      if (status.ok()) {
        (*out)[key].append(value);
      } else if (status.IsIOError()) {
        ceph_abort_msg(status.getState());
      }
    }
  }
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_gets);
  logger->tinc(l_rocksdb_get_latency, lat);
  return 0;
}

int RocksDBStore::get(
    KeyValueDB::ColumnFamilyHandle cf_handle,
    const string &prefix,
    const string &key,
    bufferlist *out)
{
  ceph_assert(out && (out->length() == 0));
  utime_t start = ceph_clock_now();
  int r = 0;
  string value;
  rocksdb::Status s;
  auto cf = static_cast<rocksdb::ColumnFamilyHandle*>(cf_handle.priv);
  if (cf_check_mode(cf, prefix)) {
    s = db->Get(rocksdb::ReadOptions(),
                cf,
                rocksdb::Slice(key),
                &value);
  } else {
    string k = combine_strings(prefix, key);
    s = db->Get(rocksdb::ReadOptions(),
                cf,
                rocksdb::Slice(k),
                &value);
  }
  if (s.ok()) {
    out->append(value);
  } else if (s.IsNotFound()) {
    r = -ENOENT;
  } else {
    ceph_abort_msg(s.getState());
  }
  utime_t lat = ceph_clock_now() - start;
  logger->inc(l_rocksdb_gets);
  logger->tinc(l_rocksdb_get_latency, lat);
  return r;
}

int RocksDBStore::split_key(rocksdb::Slice in, string *prefix, string *key)
{
  size_t prefix_len = 0;
  
  // Find separator inside Slice
  char* separator = (char*) memchr(in.data(), 0, in.size());
  if (separator == NULL)
     return -EINVAL;
  prefix_len = size_t(separator - in.data());
  if (prefix_len >= in.size())
    return -EINVAL;

  // Fetch prefix and/or key directly from Slice
  if (prefix)
    *prefix = string(in.data(), prefix_len);
  if (key)
    *key = string(separator+1, in.size()-prefix_len-1);
  return 0;
}

void RocksDBStore::compact()
{
  logger->inc(l_rocksdb_compact);
  rocksdb::CompactRangeOptions options;
  db->CompactRange(options, default_cf, nullptr, nullptr);
  for (auto cf : column_families) {
    db->CompactRange(
      options,
      static_cast<rocksdb::ColumnFamilyHandle*>(cf.second.handle.priv),
      nullptr, nullptr);
  }
}


void RocksDBStore::compact_thread_entry()
{
  std::unique_lock l{compact_queue_lock};
  dout(10) << __func__ << " enter" << dendl;
  while (!compact_queue_stop) {
    if (!compact_queue.empty()) {
      pair<string,string> range = compact_queue.front();
      compact_queue.pop_front();
      logger->set(l_rocksdb_compact_queue_len, compact_queue.size());
      l.unlock();
      logger->inc(l_rocksdb_compact_range);
      if (range.first.empty() && range.second.empty()) {
        compact();
      } else {
        compact_range(range.first, range.second);
      }
      l.lock();
      continue;
    }
    dout(10) << __func__ << " waiting" << dendl;
    compact_queue_cond.wait(l);
  }
  dout(10) << __func__ << " exit" << dendl;
}

void RocksDBStore::compact_range_async(const string& start, const string& end)
{
  std::lock_guard l(compact_queue_lock);

  // try to merge adjacent ranges.  this is O(n), but the queue should
  // be short.  note that we do not cover all overlap cases and merge
  // opportunities here, but we capture the ones we currently need.
  list< pair<string,string> >::iterator p = compact_queue.begin();
  while (p != compact_queue.end()) {
    if (p->first == start && p->second == end) {
      // dup; no-op
      return;
    }
    if (start <= p->first && p->first <= end) {
      // new region crosses start of existing range
      // select right bound that is bigger
      compact_queue.push_back(make_pair(start, end > p->second ? end : p->second));
      compact_queue.erase(p);
      logger->inc(l_rocksdb_compact_queue_merge);
      break;
    }
    if (start <= p->second && p->second <= end) {
      // new region crosses end of existing range
      //p->first < p->second and p->second <= end, so p->first <= end.
      //But we break if previous condition, so start > p->first.
      compact_queue.push_back(make_pair(p->first, end));
      compact_queue.erase(p);
      logger->inc(l_rocksdb_compact_queue_merge);
      break;
    }
    ++p;
  }
  if (p == compact_queue.end()) {
    // no merge, new entry.
    compact_queue.push_back(make_pair(start, end));
    logger->set(l_rocksdb_compact_queue_len, compact_queue.size());
  }
  compact_queue_cond.notify_all();
  if (!compact_thread.is_started()) {
    compact_thread.create("rstore_compact");
  }
}
bool RocksDBStore::check_omap_dir(string &omap_dir)
{
  rocksdb::Options options;
  options.create_if_missing = true;
  rocksdb::DB *db;
  rocksdb::Status status = rocksdb::DB::Open(options, omap_dir, &db);
  delete db;
  db = nullptr;
  return status.ok();
}
void RocksDBStore::compact_range(const string& start, const string& end)
{
  rocksdb::CompactRangeOptions options;
  rocksdb::Slice cstart(start);
  rocksdb::Slice cend(end);
  db->CompactRange(options, &cstart, &cend);
}

RocksDBStore::RocksDBWholeSpaceIteratorImpl::~RocksDBWholeSpaceIteratorImpl()
{
  delete dbiter;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::seek_to_first()
{
  dbiter->SeekToFirst();
  ceph_assert(!dbiter->status().IsIOError());
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::seek_to_first(const string &prefix)
{
  rocksdb::Slice slice_prefix(prefix);
  dbiter->Seek(slice_prefix);
  ceph_assert(!dbiter->status().IsIOError());
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::seek_to_last()
{
  dbiter->SeekToLast();
  ceph_assert(!dbiter->status().IsIOError());
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::seek_to_last(const string &prefix)
{
  string limit = past_prefix(prefix);
  rocksdb::Slice slice_limit(limit);
  dbiter->Seek(slice_limit);

  if (!dbiter->Valid()) {
    dbiter->SeekToLast();
  } else {
    dbiter->Prev();
  }
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::upper_bound(const string &prefix, const string &after)
{
  lower_bound(prefix, after);
  if (valid()) {
  pair<string,string> key = raw_key();
    if (key.first == prefix && key.second == after)
      next();
  }
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::lower_bound(const string &prefix, const string &to)
{
  string bound = combine_strings(prefix, to);
  rocksdb::Slice slice_bound(bound);
  dbiter->Seek(slice_bound);
  return dbiter->status().ok() ? 0 : -1;
}
bool RocksDBStore::RocksDBWholeSpaceIteratorImpl::valid()
{
  return dbiter->Valid();
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::next()
{
  if (valid()) {
    dbiter->Next();
  }
  ceph_assert(!dbiter->status().IsIOError());
  return dbiter->status().ok() ? 0 : -1;
}
int RocksDBStore::RocksDBWholeSpaceIteratorImpl::prev()
{
  if (valid()) {
    dbiter->Prev();
  }
  ceph_assert(!dbiter->status().IsIOError());
  return dbiter->status().ok() ? 0 : -1;
}
string RocksDBStore::RocksDBWholeSpaceIteratorImpl::key()
{
  string out_key;
  split_key(dbiter->key(), 0, &out_key);
  return out_key;
}
pair<string,string> RocksDBStore::RocksDBWholeSpaceIteratorImpl::raw_key()
{
  string prefix, key;
  split_key(dbiter->key(), &prefix, &key);
  return make_pair(prefix, key);
}

bool RocksDBStore::RocksDBWholeSpaceIteratorImpl::raw_key_is_prefixed(const string &prefix) {
  // Look for "prefix\0" right in rocksb::Slice
  rocksdb::Slice key = dbiter->key();
  if ((key.size() > prefix.length()) && (key[prefix.length()] == '\0')) {
    return memcmp(key.data(), prefix.c_str(), prefix.length()) == 0;
  } else {
    return false;
  }
}

bufferlist RocksDBStore::RocksDBWholeSpaceIteratorImpl::value()
{
  return to_bufferlist(dbiter->value());
}

size_t RocksDBStore::RocksDBWholeSpaceIteratorImpl::key_size()
{
  return dbiter->key().size();
}

size_t RocksDBStore::RocksDBWholeSpaceIteratorImpl::value_size()
{
  return dbiter->value().size();
}

bufferptr RocksDBStore::RocksDBWholeSpaceIteratorImpl::value_as_ptr()
{
  rocksdb::Slice val = dbiter->value();
  return bufferptr(val.data(), val.size());
}

int RocksDBStore::RocksDBWholeSpaceIteratorImpl::status()
{
  return dbiter->status().ok() ? 0 : -1;
}

string RocksDBStore::past_prefix(const string &prefix)
{
  string limit = prefix;
  limit.push_back(1);
  return limit;
}

RocksDBStore::WholeSpaceIterator RocksDBStore::get_wholespace_iterator()
{
  return std::make_shared<RocksDBWholeSpaceIteratorImpl>(
    db->NewIterator(rocksdb::ReadOptions(), default_cf));
}

RocksDBStore::WholeSpaceIterator RocksDBStore::get_wholespace_iterator_cf(ColumnFamilyHandle cfh)
{
  rocksdb::ColumnFamilyHandle *cf_handle =
      static_cast<rocksdb::ColumnFamilyHandle*>(cfh.priv);
  if (cfh.priv == nullptr)
      cf_handle = default_cf;
  return std::make_shared<RocksDBWholeSpaceIteratorImpl>(
    db->NewIterator(rocksdb::ReadOptions(), cf_handle));
}

class CFIteratorImpl : public KeyValueDB::IteratorImpl {
protected:
  string prefix;
  rocksdb::Iterator *dbiter;
public:
  explicit CFIteratorImpl(const std::string& p,
				 rocksdb::Iterator *iter)
    : prefix(p), dbiter(iter) { }
  ~CFIteratorImpl() {
    delete dbiter;
  }

  int seek_to_first() override {
    dbiter->SeekToFirst();
    return dbiter->status().ok() ? 0 : -1;
  }
  int seek_to_last() override {
    dbiter->SeekToLast();
    return dbiter->status().ok() ? 0 : -1;
  }
  int upper_bound(const string &after) override {
    lower_bound(after);
    if (valid() && (key() == after)) {
      next();
    }
    return dbiter->status().ok() ? 0 : -1;
  }
  int lower_bound(const string &to) override {
    rocksdb::Slice slice_bound(to);
    dbiter->Seek(slice_bound);
    return dbiter->status().ok() ? 0 : -1;
  }
  int next() override {
    if (valid()) {
      dbiter->Next();
    }
    return dbiter->status().ok() ? 0 : -1;
  }
  int prev() override {
    if (valid()) {
      dbiter->Prev();
    }
    return dbiter->status().ok() ? 0 : -1;
  }
  bool valid() override {
    return dbiter->Valid();
  }
  string key() override {
    return dbiter->key().ToString();
  }
  std::pair<std::string, std::string> raw_key() override {
    return make_pair(prefix, key());
  }
  bufferlist value() override {
    return to_bufferlist(dbiter->value());
  }
  bufferptr value_as_ptr() override {
    rocksdb::Slice val = dbiter->value();
    return bufferptr(val.data(), val.size());
  }
  int status() override {
    return dbiter->status().ok() ? 0 : -1;
  }
};

KeyValueDB::Iterator RocksDBStore::get_iterator(const std::string& prefix)
{
  rocksdb::ColumnFamilyHandle *cf_handle = cf_get_mono_handle(prefix);
  if (cf_handle) {
    return std::make_shared<CFIteratorImpl>(
      prefix,
      db->NewIterator(rocksdb::ReadOptions(), cf_handle));
  } else {
    return KeyValueDB::get_iterator(prefix);
  }
}

KeyValueDB::Iterator RocksDBStore::get_iterator_cf(ColumnFamilyHandle cfh, const std::string& prefix)
{
  rocksdb::ColumnFamilyHandle *cf_handle =
    static_cast<rocksdb::ColumnFamilyHandle*>(cfh.priv);
  if (cfh.priv == nullptr)
    cf_handle = default_cf;
  return std::make_shared<CFIteratorImpl>(
    prefix,
    db->NewIterator(rocksdb::ReadOptions(), cf_handle));
}
