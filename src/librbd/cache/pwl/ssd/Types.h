// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
      
#ifndef CEPH_LIBRBD_CACHE_SSD_TYPES_H
#define CEPH_LIBRBD_CACHE_SSD_TYPES_H
  
#include "acconfig.h"
    
#include "librbd/io/Types.h"
#include "librbd/cache/pwl/Types.h"

namespace librbd {
namespace cache {
namespace pwl {
namespace ssd {

struct SuperBlockWrapper{
  WriteLogSuperblock superblock;

  DENC(SuperBlockWrapper, v, p) {
    DENC_START(1, 1, p);
    denc(v.superblock, p);
    DENC_FINISH(p);
  }

  void dump(Formatter *f) const {
    f->dump_object("super", superblock);
  }

  static void generate_test_instances(std::list<SuperBlockWrapper*>& ls) {
    ls.push_back(new SuperBlockWrapper());
    ls.push_back(new SuperBlockWrapper);
    ls.back()->superblock.layout_version = 3;
    ls.back()->superblock.cur_sync_gen = 1;
    ls.back()->superblock.pool_size = 10737418240;
    ls.back()->superblock.flushed_sync_gen = 1;
    ls.back()->superblock.block_size = 4096;
    ls.back()->superblock.num_log_entries = 0;
    ls.back()->superblock.first_free_entry = 30601;
    ls.back()->superblock.first_valid_entry = 2;
  }
};

} // namespace ssd
} // namespace pwl
} // namespace cache
} // namespace librbd

WRITE_CLASS_DENC(librbd::cache::pwl::ssd::SuperBlockWrapper)

#endif // CEPH_LIBRBD_CACHE_SSD_TYPES_H
