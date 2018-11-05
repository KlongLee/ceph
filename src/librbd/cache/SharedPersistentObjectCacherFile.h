// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_CACHE_STORE_SYNC_FILE
#define CEPH_LIBRBD_CACHE_STORE_SYNC_FILE

#include "include/buffer_fwd.h"
#include <sys/mman.h>
#include <string>

struct Context;
struct ContextWQ;
class CephContext;

namespace librbd {

namespace cache {

class SyncFile {
public:
  SyncFile(CephContext *cct, const std::string &name);
  ~SyncFile();

  // TODO use IO queue instead of individual commands so operations can be
  // submitted in batch

  // TODO use scatter/gather API

  int create();
  int open_file();

  void read(uint64_t offset, uint64_t length, ceph::bufferlist *bl, Context *on_finish);

  void write(uint64_t offset, ceph::bufferlist &&bl, bool fdatasync, Context *on_finish);

  int write_object_to_file(ceph::bufferlist read_buf, uint64_t object_len);
  int read_object_from_file(ceph::bufferlist* read_buf, uint64_t object_off, uint64_t object_len);
  uint64_t get_file_size();

private:
  CephContext *cct;
  std::string m_name;
  int m_fd;
};

} // namespace cache
} // namespace librbd

#endif // CEPH_LIBRBD_CACHE_STORE_SYNC_FILE
