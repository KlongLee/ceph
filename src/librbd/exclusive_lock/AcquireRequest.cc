// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/exclusive_lock/AcquireRequest.h"
#include "cls/lock/cls_lock_client.h"
#include "cls/lock/cls_lock_types.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/WorkQueue.h"
#include "include/stringify.h"
#include "librbd/ExclusiveLock.h"
#include "librbd/ImageCtx.h"
#include "librbd/Journal.h"
#include "librbd/ObjectMap.h"
#include "librbd/Utils.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::exclusive_lock::AcquireRequest: "

namespace librbd {
namespace exclusive_lock {

using util::create_async_context_callback;
using util::create_context_callback;
using util::create_rados_ack_callback;
using util::create_rados_safe_callback;

namespace {

template <typename I>
struct C_BlacklistClient : public Context {
  I &image_ctx;
  std::string locker_address;
  Context *on_finish;

  C_BlacklistClient(I &image_ctx, const std::string &locker_address,
                    Context *on_finish)
    : image_ctx(image_ctx), locker_address(locker_address),
      on_finish(on_finish) {
  }

  virtual void finish(int r) override {
    librados::Rados rados(image_ctx.md_ctx);
    r = rados.blacklist_add(locker_address,
                            image_ctx.blacklist_expire_seconds);
    on_finish->complete(r);
  }
};

} // anonymous namespace

template <typename I>
AcquireRequest<I>* AcquireRequest<I>::create(I &image_ctx,
                                             const std::string &cookie,
                                             Context *on_finish) {
  return new AcquireRequest(image_ctx, cookie, on_finish);
}

template <typename I>
AcquireRequest<I>::AcquireRequest(I &image_ctx, const std::string &cookie,
                                  Context *on_finish)
  : m_image_ctx(image_ctx), m_cookie(cookie),
    m_on_finish(create_async_context_callback(image_ctx, on_finish)),
    m_object_map(nullptr), m_journal(nullptr) {
}

template <typename I>
void AcquireRequest<I>::send() {
  send_lock();
}

template <typename I>
void AcquireRequest<I>::send_lock() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  librados::ObjectWriteOperation op;
  rados::cls::lock::lock(&op, RBD_LOCK_NAME, LOCK_EXCLUSIVE, m_cookie,
                         ExclusiveLock<I>::WATCHER_LOCK_TAG, "", utime_t(), 0);

  using klass = AcquireRequest<I>;
  librados::AioCompletion *rados_completion =
    create_rados_safe_callback<klass, &klass::handle_lock>(this);
  int r = m_image_ctx.md_ctx.aio_operate(m_image_ctx.header_oid,
                                         rados_completion, &op);
  assert(r == 0);
  rados_completion->release();
}

template <typename I>
Context *AcquireRequest<I>::handle_lock(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val == 0) {
    return send_open_journal();
  } else if (*ret_val != -EBUSY) {
    lderr(cct) << "failed to lock: " << cpp_strerror(*ret_val) << dendl;
    return m_on_finish;
  }

  send_get_lockers();
  return nullptr;
}

template <typename I>
Context *AcquireRequest<I>::send_open_journal() {
  if (!m_image_ctx.test_features(RBD_FEATURE_JOURNALING)) {
    return send_open_object_map();
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = AcquireRequest<I>;
  Context *ctx = create_context_callback<klass, &klass::handle_open_journal>(
    this);
  m_journal = m_image_ctx.create_journal();
  m_journal->open(ctx);
  return nullptr;
}

template <typename I>
Context *AcquireRequest<I>::handle_open_journal(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val < 0) {
    lderr(cct) << "failed to open journal: " << cpp_strerror(*ret_val) << dendl;

    delete m_journal;
    return m_on_finish;
  }

  assert(m_image_ctx.journal == nullptr);
  return send_open_object_map();
}

template <typename I>
Context *AcquireRequest<I>::send_open_object_map() {
  if (!m_image_ctx.test_features(RBD_FEATURE_OBJECT_MAP)) {
    apply();
    return m_on_finish;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  using klass = AcquireRequest<I>;
  Context *ctx = create_context_callback<klass, &klass::handle_open_object_map>(
    this);
  m_object_map = m_image_ctx.create_object_map(CEPH_NOSNAP);
  m_object_map->open(ctx);
  return nullptr;
}

template <typename I>
Context *AcquireRequest<I>::handle_open_object_map(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  // object map should never result in an error
  assert(*ret_val == 0);
  return send_lock_object_map();
}

template <typename I>
Context *AcquireRequest<I>::send_lock_object_map() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  assert(m_object_map != nullptr);

  using klass = AcquireRequest<I>;
  Context *ctx = create_context_callback<klass, &klass::handle_lock_object_map>(
    this);
  m_object_map->lock(ctx);
  return nullptr;
}

template <typename I>
Context *AcquireRequest<I>::handle_lock_object_map(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  // object map should never result in an error
  assert(*ret_val == 0);

  apply();
  return m_on_finish;
}

template <typename I>
void AcquireRequest<I>::send_get_lockers() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  librados::ObjectReadOperation op;
  rados::cls::lock::get_lock_info_start(&op, RBD_LOCK_NAME);

  using klass = AcquireRequest<I>;
  librados::AioCompletion *rados_completion =
    create_rados_ack_callback<klass, &klass::handle_get_lockers>(this);
  m_out_bl.clear();
  int r = m_image_ctx.md_ctx.aio_operate(m_image_ctx.header_oid,
                                         rados_completion, &op, &m_out_bl);
  assert(r == 0);
  rados_completion->release();
}

template <typename I>
Context *AcquireRequest<I>::handle_get_lockers(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  std::map<rados::cls::lock::locker_id_t,
           rados::cls::lock::locker_info_t> lockers;
  ClsLockType lock_type;
  std::string lock_tag;
  if (*ret_val == 0) {
    bufferlist::iterator it = m_out_bl.begin();
    *ret_val = rados::cls::lock::get_lock_info_finish(&it, &lockers,
                                                      &lock_type, &lock_tag);
  }

  if (*ret_val < 0) {
    lderr(cct) << "failed to retrieve lockers: " << cpp_strerror(*ret_val)
               << dendl;
    return m_on_finish;
  }

  if (lockers.empty()) {
    ldout(cct, 20) << "no lockers detected" << dendl;
    send_lock();
    return nullptr;
  }

  if (lock_tag != ExclusiveLock<I>::WATCHER_LOCK_TAG) {
    ldout(cct, 5) <<"locked by external mechanism: tag=" << lock_tag << dendl;
    *ret_val = -EBUSY;
    return m_on_finish;
  }

  if (lock_type == LOCK_SHARED) {
    ldout(cct, 5) << "shared lock type detected" << dendl;
    *ret_val = -EBUSY;
    return m_on_finish;
  }

  std::map<rados::cls::lock::locker_id_t,
           rados::cls::lock::locker_info_t>::iterator iter = lockers.begin();
  if (!ExclusiveLock<I>::decode_lock_cookie(iter->first.cookie,
                                            &m_locker_handle)) {
    ldout(cct, 5) << "locked by external mechanism: "
                  << "cookie=" << iter->first.cookie << dendl;
    *ret_val = -EBUSY;
    return m_on_finish;
  }

  m_locker_entity = iter->first.locker;
  m_locker_cookie = iter->first.cookie;
  m_locker_address = stringify(iter->second.addr);
  if (m_locker_cookie.empty() || m_locker_address.empty()) {
    ldout(cct, 20) << "no valid lockers detected" << dendl;
    send_lock();
    return nullptr;
  }

  ldout(cct, 10) << "retrieved exclusive locker: "
                 << m_locker_entity << "@" << m_locker_address << dendl;
  send_get_watchers();
  return nullptr;
}

template <typename I>
void AcquireRequest<I>::send_get_watchers() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  librados::ObjectReadOperation op;
  op.list_watchers(&m_watchers, &m_watchers_ret_val);

  using klass = AcquireRequest<I>;
  librados::AioCompletion *rados_completion =
    create_rados_ack_callback<klass, &klass::handle_get_watchers>(this);
  m_out_bl.clear();
  int r = m_image_ctx.md_ctx.aio_operate(m_image_ctx.header_oid,
                                         rados_completion, &op, &m_out_bl);
  assert(r == 0);
  rados_completion->release();
}

template <typename I>
Context *AcquireRequest<I>::handle_get_watchers(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val == 0) {
    *ret_val = m_watchers_ret_val;
  }
  if (*ret_val < 0) {
    lderr(cct) << "failed to retrieve watchers: " << cpp_strerror(*ret_val)
               << dendl;
    return m_on_finish;
  }

  for (auto &watcher : m_watchers) {
    if ((strncmp(m_locker_address.c_str(),
                 watcher.addr, sizeof(watcher.addr)) == 0) &&
        (m_locker_handle == watcher.cookie)) {
      ldout(cct, 10) << "lock owner is still alive" << dendl;

      *ret_val = -EAGAIN;
      return m_on_finish;
    }
  }

  send_blacklist();
  return nullptr;
}

template <typename I>
void AcquireRequest<I>::send_blacklist() {
  if (!m_image_ctx.blacklist_on_break_lock) {
    send_break_lock();
    return;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  // TODO: need async version of RadosClient::blacklist_add
  using klass = AcquireRequest<I>;
  Context *ctx = create_context_callback<klass, &klass::handle_blacklist>(
    this);
  m_image_ctx.op_work_queue->queue(new C_BlacklistClient<I>(m_image_ctx,
                                                            m_locker_address,
                                                            ctx), 0);
}

template <typename I>
Context *AcquireRequest<I>::handle_blacklist(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val < 0) {
    lderr(cct) << "failed to blacklist lock owner: " << cpp_strerror(*ret_val)
               << dendl;
    return m_on_finish;
  }
  send_break_lock();
  return nullptr;
}

template <typename I>
void AcquireRequest<I>::send_break_lock() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << dendl;

  librados::ObjectWriteOperation op;
  rados::cls::lock::break_lock(&op, RBD_LOCK_NAME, m_locker_cookie,
                               m_locker_entity);

  using klass = AcquireRequest<I>;
  librados::AioCompletion *rados_completion =
    create_rados_safe_callback<klass, &klass::handle_break_lock>(this);
  int r = m_image_ctx.md_ctx.aio_operate(m_image_ctx.header_oid,
                                         rados_completion, &op);
  assert(r == 0);
  rados_completion->release();
}

template <typename I>
Context *AcquireRequest<I>::handle_break_lock(int *ret_val) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 10) << __func__ << ": r=" << *ret_val << dendl;

  if (*ret_val == -ENOENT) {
    *ret_val = 0;
  } else if (*ret_val < 0) {
    lderr(cct) << "failed to break lock: " << cpp_strerror(*ret_val) << dendl;
    return m_on_finish;
  }

  send_lock();
  return nullptr;
}

template <typename I>
void AcquireRequest<I>::apply() {
  RWLock::WLocker snap_locker(m_image_ctx.snap_lock);
  assert(m_image_ctx.object_map == nullptr);
  m_image_ctx.object_map = m_object_map;

  assert(m_image_ctx.journal == nullptr);
  m_image_ctx.journal = m_journal;
}

} // namespace exclusive_lock
} // namespace librbd

template class librbd::exclusive_lock::AcquireRequest<librbd::ImageCtx>;
