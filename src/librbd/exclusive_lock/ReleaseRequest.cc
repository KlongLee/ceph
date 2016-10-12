// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/exclusive_lock/ReleaseRequest.h"
#include "cls/lock/cls_lock_client.h"
#include "cls/lock/cls_lock_types.h"
#include "common/dout.h"
#include "common/errno.h"
#include "librbd/AioImageRequestWQ.h"
#include "librbd/ExclusiveLock.h"
#include "librbd/Lock.h"
#include "librbd/ImageState.h"
#include "librbd/ImageWatcher.h"
#include "librbd/Journal.h"
#include "librbd/ObjectMap.h"
#include "librbd/Utils.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::exclusive_lock::ReleaseRequest: "

namespace librbd {
namespace exclusive_lock {

using util::create_async_context_callback;
using util::create_context_callback;
using util::create_rados_safe_callback;

template <typename I>
ReleaseRequest<I>* ReleaseRequest<I>::create(I &image_ctx, Lock *managed_lock,
                                             Context *on_finish,
                                             bool shutting_down) {
  return new ReleaseRequest(image_ctx, managed_lock, on_finish, shutting_down);
}

template <typename I>
ReleaseRequest<I>::ReleaseRequest(I &image_ctx, Lock *managed_lock,
                                  Context *on_finish, bool shutting_down)
  : m_image_ctx(image_ctx), m_managed_lock(managed_lock),
    m_on_finish(create_async_context_callback(image_ctx, on_finish)),
    m_shutting_down(shutting_down), m_object_map(nullptr), m_journal(nullptr) {
}

template <typename I>
ReleaseRequest<I>::~ReleaseRequest() {
  if (!m_shutting_down) {
    m_image_ctx.state->handle_prepare_lock_complete();
  }
}

template <typename I>
void ReleaseRequest<I>::send() {
  send_prepare_lock();
}

template <typename I>
void ReleaseRequest<I>::send_prepare_lock() {
  if (m_shutting_down) {
    send_cancel_op_requests();
    return;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  // release the lock if the image is not busy performing other actions
  Context *ctx = create_context_callback<
    ReleaseRequest<I>, &ReleaseRequest<I>::handle_prepare_lock>(this);
  m_image_ctx.state->prepare_lock(ctx);
}

template <typename I>
Context *ReleaseRequest<I>::handle_prepare_lock(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  send_cancel_op_requests();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_cancel_op_requests() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = ReleaseRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_cancel_op_requests>(this);
  m_image_ctx.cancel_async_requests(ctx);
}

template <typename I>
Context *ReleaseRequest<I>::handle_cancel_op_requests(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  assert(*ret_val == 0);

  send_block_writes();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_block_writes() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = ReleaseRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_block_writes>(this);

  {
    RWLock::RLocker owner_locker(m_image_ctx.owner_lock);
    if (m_image_ctx.test_features(RBD_FEATURE_JOURNALING)) {
      m_image_ctx.aio_work_queue->set_require_lock_on_read();
    }
    m_image_ctx.aio_work_queue->block_writes(ctx);
  }
}

template <typename I>
Context *ReleaseRequest<I>::handle_block_writes(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val < 0) {
    m_image_ctx.aio_work_queue->unblock_writes();
    return m_on_finish;
  }

  send_image_flush_notifies();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_image_flush_notifies() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = ReleaseRequest<I>;
  Context *ctx =
    create_context_callback<klass, &klass::handle_image_flush_notifies>(this);
  m_image_ctx.image_watcher->flush(ctx);
}

template <typename I>
Context *ReleaseRequest<I>::handle_image_flush_notifies(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  assert(*ret_val == 0);
  send_close_journal();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_close_journal() {
  {
    RWLock::WLocker snap_locker(m_image_ctx.snap_lock);
    std::swap(m_journal, m_image_ctx.journal);
  }

  if (m_journal == nullptr) {
    send_close_object_map();
    return;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = ReleaseRequest<I>;
  Context *ctx = create_context_callback<klass, &klass::handle_close_journal>(
    this);
  m_journal->close(ctx);
}

template <typename I>
Context *ReleaseRequest<I>::handle_close_journal(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val < 0) {
    // error implies some journal events were not flushed -- continue
    lderr(cct) << "failed to close journal: " << cpp_strerror(*ret_val)
               << dendl;
  }

  delete m_journal;

  send_close_object_map();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_close_object_map() {
  {
    RWLock::WLocker snap_locker(m_image_ctx.snap_lock);
    std::swap(m_object_map, m_image_ctx.object_map);
  }

  if (m_object_map == nullptr) {
    send_unlock();
    return;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = ReleaseRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_close_object_map>(this);
  m_object_map->close(ctx);
}

template <typename I>
Context *ReleaseRequest<I>::handle_close_object_map(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  // object map shouldn't return errors
  assert(*ret_val == 0);
  delete m_object_map;

  send_unlock();
  return nullptr;
}

template <typename I>
void ReleaseRequest<I>::send_unlock() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  m_managed_lock->release_lock(m_on_finish);
}

} // namespace exclusive_lock
} // namespace librbd

template class librbd::exclusive_lock::ReleaseRequest<librbd::ImageCtx>;
