#ifndef CEPH_RGWCACHE_H
#define CEPH_RGWCACHE_H

#include "rgw_rados.h"
#include <string>
#include <map>
#include "include/types.h"
#include "include/utime.h"
#include "include/assert.h"

enum {
  UPDATE_OBJ,
  REMOVE_OBJ,
};

#define CACHE_FLAG_DATA           0x1
#define CACHE_FLAG_XATTRS         0x2
#define CACHE_FLAG_META           0x4
#define CACHE_FLAG_MODIFY_XATTRS  0x8

#define mydout(v) lsubdout(T::cct, rgw, v)

struct ObjectMetaInfo {
  uint64_t size;
  time_t mtime;

  ObjectMetaInfo() : size(0), mtime(0) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 2, bl);
    ::encode(size, bl);
    utime_t t(mtime, 0);
    ::encode(t, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, bl);
    ::decode(size, bl);
    utime_t t;
    ::decode(t, bl);
    mtime = t.sec();
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<ObjectMetaInfo*>& o);
};
WRITE_CLASS_ENCODER(ObjectMetaInfo)

struct ObjectCacheInfo {
  int status;
  uint32_t flags;
  bufferlist data;
  map<string, bufferlist> xattrs;
  map<string, bufferlist> rm_xattrs;
  ObjectMetaInfo meta;

  ObjectCacheInfo() : status(0), flags(0) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(3, 3, bl);
    ::encode(status, bl);
    ::encode(flags, bl);
    ::encode(data, bl);
    ::encode(xattrs, bl);
    ::encode(meta, bl);
    ::encode(rm_xattrs, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(3, 3, 3, bl);
    ::decode(status, bl);
    ::decode(flags, bl);
    ::decode(data, bl);
    ::decode(xattrs, bl);
    ::decode(meta, bl);
    if (struct_v >= 2)
      ::decode(rm_xattrs, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<ObjectCacheInfo*>& o);
};
WRITE_CLASS_ENCODER(ObjectCacheInfo)

struct RGWCacheNotifyInfo {
  uint32_t op;
  rgw_obj obj;
  ObjectCacheInfo obj_info;
  off_t ofs;
  string ns;

  RGWCacheNotifyInfo() : op(0), ofs(0) {}

  void encode(bufferlist& obl) const {
    ENCODE_START(2, 2, obl);
    ::encode(op, obl);
    ::encode(obj, obl);
    ::encode(obj_info, obl);
    ::encode(ofs, obl);
    ::encode(ns, obl);
    ENCODE_FINISH(obl);
  }
  void decode(bufferlist::iterator& ibl) {
    DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, ibl);
    ::decode(op, ibl);
    ::decode(obj, ibl);
    ::decode(obj_info, ibl);
    ::decode(ofs, ibl);
    ::decode(ns, ibl);
    DECODE_FINISH(ibl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<RGWCacheNotifyInfo*>& o);
};
WRITE_CLASS_ENCODER(RGWCacheNotifyInfo)

struct ObjectCacheEntry {
  ObjectCacheInfo info;
  std::list<string>::iterator lru_iter;
};

class ObjectCache {
  std::map<string, ObjectCacheEntry> cache_map;
  std::list<string> lru;
  Mutex lock;
  CephContext *cct;

  void touch_lru(string& name, std::list<string>::iterator& lru_iter);
  void remove_lru(string& name, std::list<string>::iterator& lru_iter);
public:
  ObjectCache() : lock("ObjectCache"), cct(NULL) { }
  int get(std::string& name, ObjectCacheInfo& bl, uint32_t mask);
  void put(std::string& name, ObjectCacheInfo& bl);
  void remove(std::string& name);
  void set_ctx(CephContext *_cct) { cct = _cct; }
};

template <class T>
class RGWCache  : public T
{
  ObjectCache cache;

  int list_objects_raw_init(rgw_bucket& bucket, RGWAccessHandle *handle) {
    return T::list_objects_raw_init(bucket, handle);
  }
  int list_objects_raw_next(RGWObjEnt& obj, RGWAccessHandle *handle) {
    return T::list_objects_raw_next(obj, handle);
  }

  string normal_name(rgw_bucket& bucket, std::string& oid) {
    string& bucket_name = bucket.name;
    char buf[bucket_name.size() + 1 + oid.size() + 1];
    const char *bucket_str = bucket_name.c_str();
    const char *oid_str = oid.c_str();
    sprintf(buf, "%s+%s", bucket_str, oid_str);
    return string(buf);
  }

  void normalize_bucket_and_obj(rgw_bucket& src_bucket, string& src_obj, rgw_bucket& dst_bucket, string& dst_obj);
  string normal_name(rgw_obj& obj) {
    return normal_name(obj.bucket, obj.object);
  }

  int initialize() {
    int ret;
    cache.set_ctx(T::cct);
    ret = T::initialize();
    if (ret < 0)
      return ret;

    ret = T::init_watch();
    return ret;
  }

  void finalize() {
    T::finalize_watch();
    T::finalize();
  }
  int distribute(const string& normal_name, rgw_obj& obj, ObjectCacheInfo& obj_info, int op);
  int watch_cb(int opcode, uint64_t ver, bufferlist& bl);
public:
  RGWCache() {}

  int set_attr(void *ctx, rgw_obj& obj, const char *name, bufferlist& bl);
  int set_attrs(void *ctx, rgw_obj& obj, 
                map<string, bufferlist>& attrs,
                map<string, bufferlist>* rmattrs);
  int put_obj_meta(void *ctx, rgw_obj& obj, uint64_t size, time_t *mtime,
                   map<std::string, bufferlist>& attrs, RGWObjCategory category, bool exclusive,
                   map<std::string, bufferlist>* rmattrs, const bufferlist *data,
                   RGWObjManifest *manifest, const string *ptag);

  int put_obj_data(void *ctx, rgw_obj& obj, const char *data,
              off_t ofs, size_t len, bool exclusive);

  int get_obj(void *ctx, void **handle, rgw_obj& obj, bufferlist& bl, off_t ofs, off_t end);

  int obj_stat(void *ctx, rgw_obj& obj, uint64_t *psize, time_t *pmtime, map<string, bufferlist> *attrs, bufferlist *first_chunk);

  int delete_obj(void *ctx, rgw_obj& obj);
};

template <class T>
void RGWCache<T>::normalize_bucket_and_obj(rgw_bucket& src_bucket, string& src_obj, rgw_bucket& dst_bucket, string& dst_obj)
{
  if (src_obj.size()) {
    dst_bucket = src_bucket;
    dst_obj = src_obj;
  } else {
    dst_bucket = T::params.domain_root;
    dst_obj = src_bucket.name;
  }
}

template <class T>
int RGWCache<T>::delete_obj(void *ctx, rgw_obj& obj)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  if (bucket.name[0] != '.')
    return T::delete_obj(ctx, obj);

  string name = normal_name(obj);
  cache.remove(name);

  ObjectCacheInfo info;
  distribute(name, obj, info, REMOVE_OBJ);

  return T::delete_obj(ctx, obj);
}

template <class T>
int RGWCache<T>::get_obj(void *ctx, void **handle, rgw_obj& obj, bufferlist& obl, off_t ofs, off_t end)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  if (bucket.name[0] != '.' || ofs != 0)
    return T::get_obj(ctx, handle, obj, obl, ofs, end);

  string name = normal_name(obj.bucket, oid);

  ObjectCacheInfo info;
  if (cache.get(name, info, CACHE_FLAG_DATA) == 0) {
    if (info.status < 0)
      return info.status;

    bufferlist& bl = info.data;

    bufferlist::iterator i = bl.begin();

    obl.clear();

    i.copy_all(obl);
    return bl.length();
  }
  int r = T::get_obj(ctx, handle, obj, obl, ofs, end);
  if (r < 0) {
    if (r == -ENOENT) { // only update ENOENT, we'd rather retry other errors
      info.status = r;
      cache.put(name, info);
    }
    return r;
  }

  bufferptr p(r);
  bufferlist& bl = info.data;
  bl.clear();
  bufferlist::iterator o = obl.begin();
  o.copy_all(bl);
  info.status = 0;
  info.flags = CACHE_FLAG_DATA;
  cache.put(name, info);
  return r;
}

template <class T>
int RGWCache<T>::set_attr(void *ctx, rgw_obj& obj, const char *attr_name, bufferlist& bl)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  ObjectCacheInfo info;
  bool cacheable = false;
  if (bucket.name[0] == '.') {
    cacheable = true;
    info.xattrs[attr_name] = bl;
    info.status = 0;
    info.flags = CACHE_FLAG_MODIFY_XATTRS;
  }
  int ret = T::set_attr(ctx, obj, attr_name, bl);
  if (cacheable) {
    string name = normal_name(bucket, oid);
    if (ret >= 0) {
      cache.put(name, info);
      int r = distribute(name, obj, info, UPDATE_OBJ);
      if (r < 0)
        mydout(0) << "ERROR: failed to distribute cache for " << obj << dendl;
    } else {
     cache.remove(name);
    }
  }

  return ret;
}

template <class T>
int RGWCache<T>::set_attrs(void *ctx, rgw_obj& obj, 
                           map<string, bufferlist>& attrs,
                           map<string, bufferlist>* rmattrs) 
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  ObjectCacheInfo info;
  bool cacheable = false;
  if (bucket.name[0] == '.') {
    cacheable = true;
    info.xattrs = attrs;
    if (rmattrs)
      info.rm_xattrs = *rmattrs;
    info.status = 0;
    info.flags = CACHE_FLAG_MODIFY_XATTRS;
  }
  int ret = T::set_attrs(ctx, obj, attrs, rmattrs);
  if (cacheable) {
    string name = normal_name(bucket, oid);
    if (ret >= 0) {
      cache.put(name, info);
      int r = distribute(name, obj, info, UPDATE_OBJ);
      if (r < 0)
        mydout(0) << "ERROR: failed to distribute cache for " << obj << dendl;
    } else {
     cache.remove(name);
    }
  }

  return ret;
}

template <class T>
int RGWCache<T>::put_obj_meta(void *ctx, rgw_obj& obj, uint64_t size, time_t *mtime,
                              map<std::string, bufferlist>& attrs, RGWObjCategory category, bool exclusive,
                              map<std::string, bufferlist>* rmattrs, const bufferlist *data,
                              RGWObjManifest *manifest, const string *ptag)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  ObjectCacheInfo info;
  bool cacheable = false;
  if (bucket.name[0] == '.') {
    cacheable = true;
    info.xattrs = attrs;
    info.status = 0;
    info.flags = CACHE_FLAG_XATTRS;
    if (data) {
      info.data = *data;
      info.flags |= CACHE_FLAG_DATA;
    }
  }
  int ret = T::put_obj_meta(ctx, obj, size, mtime, attrs, category, exclusive, rmattrs, data, manifest, ptag);
  if (cacheable) {
    string name = normal_name(bucket, oid);
    if (ret >= 0) {
      cache.put(name, info);
      int r = distribute(name, obj, info, UPDATE_OBJ);
      if (r < 0)
        mydout(0) << "ERROR: failed to distribute cache for " << obj << dendl;
    } else {
     cache.remove(name);
    }
  }

  return ret;
}

template <class T>
int RGWCache<T>::put_obj_data(void *ctx, rgw_obj& obj, const char *data,
              off_t ofs, size_t len, bool exclusive)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  ObjectCacheInfo info;
  bool cacheable = false;
  if ((bucket.name[0] == '.') && ((ofs == 0) || (ofs == -1))) {
    cacheable = true;
    bufferptr p(len);
    memcpy(p.c_str(), data, len);
    bufferlist& bl = info.data;
    bl.append(p);
    info.meta.size = bl.length();
    info.status = 0;
    info.flags = CACHE_FLAG_DATA;
  }
  int ret = T::put_obj_data(ctx, obj, data, ofs, len, exclusive);
  if (cacheable) {
    string name = normal_name(bucket, oid);
    if (ret >= 0) {
      cache.put(name, info);
      int r = distribute(name, obj, info, UPDATE_OBJ);
      if (r < 0)
        mydout(0) << "ERROR: failed to distribute cache for " << obj << dendl;
    } else {
     cache.remove(name);
    }
  }

  return ret;
}

template <class T>
int RGWCache<T>::obj_stat(void *ctx, rgw_obj& obj, uint64_t *psize, time_t *pmtime, map<string, bufferlist> *attrs, bufferlist *first_chunk)
{
  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(obj.bucket, obj.object, bucket, oid);
  if (bucket.name[0] != '.')
    return T::obj_stat(ctx, obj, psize, pmtime, attrs, first_chunk);

  string name = normal_name(bucket, oid);

  uint64_t size;
  time_t mtime;

  ObjectCacheInfo info;
  int r = cache.get(name, info, CACHE_FLAG_META | CACHE_FLAG_XATTRS);
  if (r == 0) {
    if (info.status < 0)
      return info.status;

    size = info.meta.size;
    mtime = info.meta.mtime;
    goto done;
  }
  r = T::obj_stat(ctx, obj, &size, &mtime, &info.xattrs, first_chunk);
  if (r < 0) {
    if (r == -ENOENT) {
      info.status = r;
      cache.put(name, info);
    }
    return r;
  }
  info.status = 0;
  info.meta.mtime = mtime;
  info.meta.size = size;
  info.flags = CACHE_FLAG_META | CACHE_FLAG_XATTRS;
  cache.put(name, info);
done:
  if (psize)
    *psize = size;
  if (pmtime)
    *pmtime = mtime;
  if (attrs)
    *attrs = info.xattrs;
  return 0;
}

template <class T>
int RGWCache<T>::distribute(const string& normal_name, rgw_obj& obj, ObjectCacheInfo& obj_info, int op)
{
  RGWCacheNotifyInfo info;

  info.op = op;

  info.obj_info = obj_info;
  info.obj = obj;
  bufferlist bl;
  ::encode(info, bl);
  int ret = T::distribute(normal_name, bl);
  return ret;
}

template <class T>
int RGWCache<T>::watch_cb(int opcode, uint64_t ver, bufferlist& bl)
{
  RGWCacheNotifyInfo info;

  try {
    bufferlist::iterator iter = bl.begin();
    ::decode(info, iter);
  } catch (buffer::end_of_buffer& err) {
    mydout(0) << "ERROR: got bad notification" << dendl;
    return -EIO;
  } catch (buffer::error& err) {
    mydout(0) << "ERROR: buffer::error" << dendl;
    return -EIO;
  }

  rgw_bucket bucket;
  string oid;
  normalize_bucket_and_obj(info.obj.bucket, info.obj.object, bucket, oid);
  string name = normal_name(bucket, oid);

  switch (info.op) {
  case UPDATE_OBJ:
    cache.put(name, info.obj_info);
    break;
  case REMOVE_OBJ:
    cache.remove(name);
    break;
  default:
    mydout(0) << "WARNING: got unknown notification op: " << info.op << dendl;
    return -EINVAL;
  }

  return 0;
}

#endif
