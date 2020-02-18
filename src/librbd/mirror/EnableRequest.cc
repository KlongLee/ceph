// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/mirror/EnableRequest.h"
#include "common/dout.h"
#include "common/errno.h"
#include "cls/rbd/cls_rbd_client.h"
#include "librbd/ImageState.h"
#include "librbd/Journal.h"
#include "librbd/Utils.h"
#include "librbd/mirror/ImageStateUpdateRequest.h"
#include "librbd/mirror/snapshot/CreatePrimaryRequest.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::mirror::EnableRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace mirror {

using util::create_context_callback;
using util::create_rados_callback;

template <typename I>
EnableRequest<I>::EnableRequest(librados::IoCtx &io_ctx,
                                const std::string &image_id,
                                I* image_ctx,
                                cls::rbd::MirrorImageMode mode,
                                const std::string &non_primary_global_image_id,
                                ContextWQ *op_work_queue, Context *on_finish)
  : m_io_ctx(io_ctx), m_image_id(image_id), m_image_ctx(image_ctx),
    m_mode(mode), m_non_primary_global_image_id(non_primary_global_image_id),
    m_op_work_queue(op_work_queue), m_on_finish(on_finish),
    m_cct(reinterpret_cast<CephContext*>(io_ctx.cct())) {
}

template <typename I>
void EnableRequest<I>::send() {
  get_mirror_image();
}

template <typename I>
void EnableRequest<I>::get_mirror_image() {
  ldout(m_cct, 10) << dendl;

  librados::ObjectReadOperation op;
  cls_client::mirror_image_get_start(&op, m_image_id);

  using klass = EnableRequest<I>;
  librados::AioCompletion *comp =
    create_rados_callback<klass, &klass::handle_get_mirror_image>(this);
  m_out_bl.clear();
  int r = m_io_ctx.aio_operate(RBD_MIRRORING, comp, &op, &m_out_bl);
  ceph_assert(r == 0);
  comp->release();
}

template <typename I>
void EnableRequest<I>::handle_get_mirror_image(int r) {
  ldout(m_cct, 10) << "r=" << r << dendl;

  if (r == 0) {
    auto iter = m_out_bl.cbegin();
    r = cls_client::mirror_image_get_finish(&iter, &m_mirror_image);
  }

  if (r == 0) {
    if (m_mirror_image.mode != m_mode) {
      lderr(m_cct) << "invalid current image mirror mode" << dendl;
      r = -EINVAL;
    } else if (m_mirror_image.state == cls::rbd::MIRROR_IMAGE_STATE_ENABLED) {
      ldout(m_cct, 10) << "mirroring is already enabled" << dendl;
    } else {
      lderr(m_cct) << "currently disabling" << dendl;
      r = -EINVAL;
    }
    finish(r);
    return;
  }

  if (r != -ENOENT) {
    lderr(m_cct) << "failed to retrieve mirror image: " << cpp_strerror(r)
                 << dendl;
    finish(r);
    return;
  }

  r = 0;
  m_mirror_image.mode = m_mode;
  if (m_non_primary_global_image_id.empty()) {
    uuid_d uuid_gen;
    uuid_gen.generate_random();
    m_mirror_image.global_image_id = uuid_gen.to_string();
  } else {
    m_mirror_image.global_image_id = m_non_primary_global_image_id;
  }

  get_tag_owner();
}

template <typename I>
void EnableRequest<I>::get_tag_owner() {
  if (m_mirror_image.mode == cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT ||
      !m_non_primary_global_image_id.empty()) {
    create_primary_snapshot();
    return;
  }

  ldout(m_cct, 10)  << dendl;

  using klass = EnableRequest<I>;
  Context *ctx = create_context_callback<
      klass, &klass::handle_get_tag_owner>(this);
  librbd::Journal<>::is_tag_owner(m_io_ctx, m_image_id, &m_is_primary,
                                  m_op_work_queue, ctx);
}

template <typename I>
void EnableRequest<I>::handle_get_tag_owner(int r) {
  ldout(m_cct, 10) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to check tag ownership: " << cpp_strerror(r)
                 << dendl;
    finish(r);
    return;
  }

  if (!m_is_primary) {
    lderr(m_cct) << "last journal tag not owned by local cluster" << dendl;
    finish(-EINVAL);
    return;
  }

  image_state_update();
}

template <typename I>
void EnableRequest<I>::create_primary_snapshot() {
  if (!m_non_primary_global_image_id.empty()) {
    image_state_update();
    return;
  }

  ldout(m_cct, 10) << dendl;

  ceph_assert(m_image_ctx != nullptr);
  auto ctx = create_context_callback<
    EnableRequest<I>,
    &EnableRequest<I>::handle_create_primary_snapshot>(this);
  auto req = snapshot::CreatePrimaryRequest<I>::create(
    m_image_ctx, m_mirror_image.global_image_id,
    snapshot::CREATE_PRIMARY_FLAG_IGNORE_EMPTY_PEERS, &m_snap_id, ctx);
  req->send();
}

template <typename I>
void EnableRequest<I>::handle_create_primary_snapshot(int r) {
  ldout(m_cct, 10) << "r=" << r << dendl;

  image_state_update();
}

template <typename I>
void EnableRequest<I>::image_state_update() {
  ldout(m_cct, 10) << dendl;

  auto ctx = create_context_callback<
    EnableRequest<I>, &EnableRequest<I>::handle_image_state_update>(this);
  auto req = ImageStateUpdateRequest<I>::create(
    m_io_ctx, m_image_id, cls::rbd::MIRROR_IMAGE_STATE_ENABLED,
    m_mirror_image, ctx);
  req->send();
}

template <typename I>
void EnableRequest<I>::handle_image_state_update(int r) {
  ldout(m_cct, 10) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to enable mirroring: " << cpp_strerror(r)
                 << dendl;
  }

  finish(r);
}

template <typename I>
void EnableRequest<I>::finish(int r) {
  ldout(m_cct, 10) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace mirror
} // namespace librbd

template class librbd::mirror::EnableRequest<librbd::ImageCtx>;
