// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_MIRROR_DEMOTE_REQUEST_H
#define CEPH_LIBRBD_MIRROR_DEMOTE_REQUEST_H

#include "cls/rbd/cls_rbd_types.h"
#include "librbd/mirror/Types.h"

struct Context;

namespace librbd {

struct ImageCtx;

namespace mirror {

template <typename ImageCtxT = librbd::ImageCtx>
class DemoteRequest {
public:
  static DemoteRequest *create(ImageCtxT &image_ctx, int64_t group_pool_id,
                               const std::string &group_id,
                               const std::string &group_snap_id,
                               uint64_t *snap_id, Context *on_finish) {
    return new DemoteRequest(image_ctx, group_pool_id, group_id,
                             group_snap_id, snap_id, on_finish);
  }
  static DemoteRequest *create(ImageCtxT &image_ctx, Context *on_finish) {
    return new DemoteRequest(image_ctx, -1, {}, {}, nullptr, on_finish);
  }

  DemoteRequest(ImageCtxT &image_ctx, int64_t group_pool_id,
                const std::string &group_id, const std::string &group_snap_id,
                uint64_t *snap_id, Context *on_finish)
    : m_image_ctx(image_ctx), m_group_pool_id(group_pool_id),
      m_group_id(group_id), m_group_snap_id(group_snap_id), m_snap_id(snap_id),
      m_on_finish(on_finish) {
  }

  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * GET_INFO
   *    |
   *    v
   * ACQUIRE_LOCK * * * *
   *    |               *
   *    v               *
   * DEMOTE             *
   *    |               *
   *    v               *
   * RELEASE_LOCK       *
   *    |               *
   *    v               *
   * <finish> < * * * * *
   *
   * @endverbatim
   */

  ImageCtxT &m_image_ctx;
  const int64_t m_group_pool_id;
  const std::string m_group_id;
  const std::string m_group_snap_id;
  uint64_t *m_snap_id;
  Context *m_on_finish;

  int m_ret_val = 0;
  bool m_blocked_requests = false;

  cls::rbd::MirrorImage m_mirror_image;
  PromotionState m_promotion_state = PROMOTION_STATE_PRIMARY;
  std::string m_primary_mirror_uuid;

  void get_info();
  void handle_get_info(int r);

  void acquire_lock();
  void handle_acquire_lock(int r);

  void demote();
  void handle_demote(int r);

  void release_lock();
  void handle_release_lock(int r);

  void finish(int r);

};

} // namespace mirror
} // namespace librbd

extern template class librbd::mirror::DemoteRequest<librbd::ImageCtx>;

#endif // CEPH_LIBRBD_MIRROR_DEMOTE_REQUEST_H
