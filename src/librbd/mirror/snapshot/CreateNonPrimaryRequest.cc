// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/mirror/snapshot/CreateNonPrimaryRequest.h"
#include "common/dout.h"
#include "common/errno.h"
#include "cls/rbd/cls_rbd_client.h"
#include "librbd/ImageCtx.h"
#include "librbd/ImageState.h"
#include "librbd/Operations.h"
#include "librbd/Utils.h"
#include "librbd/mirror/snapshot/Utils.h"
#include "librbd/mirror/snapshot/WriteImageStateRequest.h"

#define dout_subsys ceph_subsys_rbd

#undef dout_prefix
#define dout_prefix *_dout << "librbd::mirror::snapshot::CreateNonPrimaryRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace mirror {
namespace snapshot {

using librbd::util::create_context_callback;
using librbd::util::create_rados_callback;

template <typename I>
void CreateNonPrimaryRequest<I>::send() {
  refresh_image();
}

template <typename I>
void CreateNonPrimaryRequest<I>::refresh_image() {
  if (!m_image_ctx->state->is_refresh_required()) {
    get_mirror_image();
    return;
  }

  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << dendl;

  auto ctx = create_context_callback<
    CreateNonPrimaryRequest<I>,
    &CreateNonPrimaryRequest<I>::handle_refresh_image>(this);
  m_image_ctx->state->refresh(ctx);
}

template <typename I>
void CreateNonPrimaryRequest<I>::handle_refresh_image(int r) {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(cct) << "failed to refresh image: " << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  get_mirror_image();
}

template <typename I>
void CreateNonPrimaryRequest<I>::get_mirror_image() {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << dendl;

  librados::ObjectReadOperation op;
  cls_client::mirror_image_get_start(&op, m_image_ctx->id);

  librados::AioCompletion *comp = create_rados_callback<
    CreateNonPrimaryRequest<I>,
    &CreateNonPrimaryRequest<I>::handle_get_mirror_image>(this);
  int r = m_image_ctx->md_ctx.aio_operate(RBD_MIRRORING, comp, &op, &m_out_bl);
  ceph_assert(r == 0);
  comp->release();
}

template <typename I>
void CreateNonPrimaryRequest<I>::handle_get_mirror_image(int r) {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << "r=" << r << dendl;

  cls::rbd::MirrorImage mirror_image;
  if (r == 0) {
    auto iter = m_out_bl.cbegin();
    r = cls_client::mirror_image_get_finish(&iter, &mirror_image);
  }

  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve mirroring state: " << cpp_strerror(r)
               << dendl;
    finish(r);
    return;
  }

  if (mirror_image.mode != cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    lderr(cct) << "snapshot based mirroring is not enabled" << dendl;
    finish(-EINVAL);
    return;
  }

  if (!is_orphan() && !util::can_create_non_primary_snapshot(m_image_ctx)) {
    finish(-EINVAL);
    return;
  }

  uuid_d uuid_gen;
  uuid_gen.generate_random();
  m_snap_name = ".mirror.non_primary." + mirror_image.global_image_id + "." +
    uuid_gen.to_string();

  create_snapshot();
}

template <typename I>
void CreateNonPrimaryRequest<I>::create_snapshot() {
  CephContext *cct = m_image_ctx->cct;

  cls::rbd::MirrorSnapshotNamespace ns{
    (m_demoted ? cls::rbd::MIRROR_SNAPSHOT_STATE_NON_PRIMARY_DEMOTED :
                 cls::rbd::MIRROR_SNAPSHOT_STATE_NON_PRIMARY), {},
    m_primary_mirror_uuid, m_primary_snap_id};
  ns.snap_seqs = m_snap_seqs;
  ns.complete = is_orphan();
  ldout(cct, 20) << "ns=" << ns << dendl;

  auto ctx = create_context_callback<
    CreateNonPrimaryRequest<I>,
    &CreateNonPrimaryRequest<I>::handle_create_snapshot>(this);
  m_image_ctx->operations->snap_create(ns, m_snap_name, ctx);
}

template <typename I>
void CreateNonPrimaryRequest<I>::handle_create_snapshot(int r) {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(cct) << "failed to create mirror snapshot: " << cpp_strerror(r)
               << dendl;
    finish(r);
    return;
  }

  write_image_state();
}

template <typename I>
void CreateNonPrimaryRequest<I>::write_image_state() {
  uint64_t snap_id;
  {
    std::shared_lock image_locker{m_image_ctx->image_lock};
    snap_id = m_image_ctx->get_snap_id(
      cls::rbd::MirrorSnapshotNamespace{}, m_snap_name);
  }

  if (m_snap_id != nullptr) {
    *m_snap_id = snap_id;
  }

  if (is_orphan()) {
    finish(0);
    return;
  }

  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << dendl;

  auto ctx = create_context_callback<
    CreateNonPrimaryRequest<I>,
    &CreateNonPrimaryRequest<I>::handle_write_image_state>(this);

  auto req = WriteImageStateRequest<I>::create(m_image_ctx, snap_id,
                                               m_image_state, ctx);
  req->send();
}

template <typename I>
void CreateNonPrimaryRequest<I>::handle_write_image_state(int r) {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(cct) << "failed to write image state: " << cpp_strerror(r)
               << dendl;
    finish(r);
    return;
  }

  finish(0);
}

template <typename I>
void CreateNonPrimaryRequest<I>::finish(int r) {
  CephContext *cct = m_image_ctx->cct;
  ldout(cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace snapshot
} // namespace mirror
} // namespace librbd

template class librbd::mirror::snapshot::CreateNonPrimaryRequest<librbd::ImageCtx>;
