// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_LIBRBD_IMAGECTX_H
#define CEPH_LIBRBD_IMAGECTX_H

#include <inttypes.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "common/Mutex.h"
#include "common/snap_types.h"
#include "include/buffer.h"
#include "include/rbd/librbd.hpp"
#include "include/rbd_types.h"
#include "include/types.h"
#include "osdc/ObjectCacher.h"

#include "librbd/cls_rbd_client.h"
#include "librbd/LibrbdWriteback.h"
#include "librbd/SnapInfo.h"

class CephContext;
class PerfCounters;

namespace librbd {

  class WatchCtx;

  struct ImageCtx {
    CephContext *cct;
    PerfCounters *perfcounter;
    struct rbd_obj_header_ondisk header;
    ::SnapContext snapc;
    std::vector<librados::snap_t> snaps; // this mirrors snapc.snaps, but is in
                                         // a format librados can understand
    std::map<std::string, SnapInfo> snaps_by_name;
    uint64_t snap_id;
    bool snap_exists; // false if our snap_id was deleted
    std::set<std::pair<std::string, std::string> > locks;
    bool exclusive_locked;
    std::string name;
    std::string snap_name;
    IoCtx data_ctx, md_ctx;
    WatchCtx *wctx;
    int refresh_seq;    ///< sequence for refresh requests
    int last_refresh;   ///< last completed refresh
    Mutex refresh_lock;
    Mutex lock; // protects access to snapshot and header information
    Mutex cache_lock; // used as client_lock for the ObjectCacher

    bool old_format;
    uint8_t order;
    uint64_t size;
    uint64_t features;
    std::string object_prefix;
    std::string header_oid;
    std::string id; // only used for new-format images
    cls_client::parent_info parent_md;
    ImageCtx *parent;

    ObjectCacher *object_cacher;
    LibrbdWriteback *writeback_handler;
    ObjectCacher::ObjectSet *object_set;

    /**
     * Either image_name or image_id must be set.
     * If id is not known, pass the empty std::string,
     * and init() will look it up.
     */
    ImageCtx(const std::string &image_name, const std::string &image_id,
             const char *snap, IoCtx& p);
    ~ImageCtx();
    int init();
    void perf_start(std::string name);
    void perf_stop();
    int snap_set(std::string in_snap_name);
    void snap_unset();
    librados::snap_t get_snap_id(std::string in_snap_name) const;
    int get_snap_name(snapid_t snap_id, std::string *out_snap_name) const;
    int get_snap_size(std::string in_snap_name, uint64_t *out_size) const;
    void add_snap(std::string in_snap_name, librados::snap_t id,
		  uint64_t in_size, uint64_t features,
		  cls_client::parent_info parent);

    uint64_t get_image_size(librados::snap_t in_snap_id) const;
    int get_features(librados::snap_t in_snap_id,
		     uint64_t *out_features) const;
    int64_t get_parent_pool_id(librados::snap_t in_snap_id) const;
    std::string get_parent_image_id(librados::snap_t in_snap_id) const;
    uint64_t get_parent_snap_id(librados::snap_t in_snap_id) const;
    int get_parent_overlap(librados::snap_t in_snap_id,
			   uint64_t *overlap) const;
    void aio_read_from_cache(object_t o, bufferlist *bl, size_t len,
			     uint64_t off, Context *onfinish);
    void write_to_cache(object_t o, bufferlist& bl, size_t len, uint64_t off);
    int read_from_cache(object_t o, bufferlist *bl, size_t len, uint64_t off);
    int flush_cache();
    void shutdown_cache();
    void invalidate_cache();
    int register_watch();
    void unregister_watch();
  };
}

#endif
