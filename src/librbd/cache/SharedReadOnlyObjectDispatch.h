// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_CACHE_SHARED_PERSISTENT_OBJECT_CACHER_OBJECT_DISPATCH_H
#define CEPH_LIBRBD_CACHE_SHARED_PERSISTENT_OBJECT_CACHER_OBJECT_DISPATCH_H

#include "common/Mutex.h"
#include "SharedPersistentObjectCacher.h"
#include "librbd/io/ObjectDispatchInterface.h"
#include "tools/ceph_immutable_object_cache/CacheClient.h"


namespace librbd {

class ImageCtx;

namespace cache {

template <typename ImageCtxT = ImageCtx>
class SharedReadOnlyObjectDispatch : public io::ObjectDispatchInterface {
public:
  static SharedReadOnlyObjectDispatch* create(ImageCtxT* image_ctx) {
    return new SharedReadOnlyObjectDispatch(image_ctx);
  }

  SharedReadOnlyObjectDispatch(ImageCtxT* image_ctx);
  ~SharedReadOnlyObjectDispatch() override;

  io::ObjectDispatchLayer get_object_dispatch_layer() const override {
    return io::OBJECT_DISPATCH_LAYER_SHARED_PERSISTENT_CACHE;
  }

  void init();
  void shut_down(Context* on_finish) {
    m_image_ctx->op_work_queue->queue(on_finish, 0);
  }

  bool read(
      const std::string &oid, uint64_t object_no, uint64_t object_off,
      uint64_t object_len, librados::snap_t snap_id, int op_flags,
      const ZTracer::Trace &parent_trace, ceph::bufferlist* read_data,
      io::ExtentMap* extent_map, int* object_dispatch_flags,
      io::DispatchResult* dispatch_result, Context** on_finish,
      Context* on_dispatched) override;

  bool discard(
      const std::string &oid, uint64_t object_no, uint64_t object_off,
      uint64_t object_len, const ::SnapContext &snapc, int discard_flags,
      const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
      uint64_t* journal_tid, io::DispatchResult* dispatch_result,
      Context** on_finish, Context* on_dispatched) {
    return false;
  }

  bool write(
      const std::string &oid, uint64_t object_no, uint64_t object_off,
      ceph::bufferlist&& data, const ::SnapContext &snapc, int op_flags,
      const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
      uint64_t* journal_tid, io::DispatchResult* dispatch_result,
      Context** on_finish, Context* on_dispatched) {
    return false;
  }

  bool write_same(
      const std::string &oid, uint64_t object_no, uint64_t object_off,
      uint64_t object_len, io::Extents&& buffer_extents,
      ceph::bufferlist&& data, const ::SnapContext &snapc, int op_flags,
      const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
      uint64_t* journal_tid, io::DispatchResult* dispatch_result,
      Context** on_finish, Context* on_dispatched) {
    return false;
  }

  bool compare_and_write(
      const std::string &oid, uint64_t object_no, uint64_t object_off,
      ceph::bufferlist&& cmp_data, ceph::bufferlist&& write_data,
      const ::SnapContext &snapc, int op_flags,
      const ZTracer::Trace &parent_trace, uint64_t* mismatch_offset,
      int* object_dispatch_flags, uint64_t* journal_tid,
      io::DispatchResult* dispatch_result, Context** on_finish,
      Context* on_dispatched) {
    return false;
  }

  bool flush(
      io::FlushSource flush_source, const ZTracer::Trace &parent_trace,
      io::DispatchResult* dispatch_result, Context** on_finish,
      Context* on_dispatched) {
    return false;
  }

  bool invalidate_cache(Context* on_finish) {
    return false;
  }

  bool reset_existence_cache(Context* on_finish) {
    return false;
  }

  void extent_overwritten(
      uint64_t object_no, uint64_t object_off, uint64_t object_len,
      uint64_t journal_tid, uint64_t new_journal_tid) {
  }

private:

  int handle_read_cache(
      bool cache,
      const std::string &oid, uint64_t read_off,
      uint64_t read_len, ceph::bufferlist* read_data,
      io::DispatchResult* dispatch_result,
      Context* on_dispatched);
  int handle_register_volume(bool reg);
  void client_handle_request(std::string msg);

  ImageCtxT* m_image_ctx;

  ceph::immutable_obj_cache::CacheClient *m_cache_client = nullptr;
  SharedPersistentObjectCacher<ImageCtxT> *m_object_store = nullptr;
};

} // namespace cache
} // namespace librbd

extern template class librbd::cache::SharedReadOnlyObjectDispatch<librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CACHE_OBJECT_CACHER_OBJECT_DISPATCH_H
