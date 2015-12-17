// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/journal/Replay.h"
#include "common/WorkQueue.h"
#include "librbd/AioCompletion.h"
#include "librbd/AioImageRequest.h"
#include "librbd/ImageCtx.h"
#include "librbd/internal.h"
#include "librbd/Operations.h"
#include "librbd/Utils.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::journal::Replay: "

namespace librbd {
namespace journal {

namespace {

static NoOpProgressContext no_op_progress_callback;

} // anonymous namespace


template <typename I>
Replay<I>::Replay(I &image_ctx)
  : m_image_ctx(image_ctx), m_lock("Replay<I>::m_lock"), m_flush_ctx(nullptr),
    m_ret_val(0) {
}

template <typename I>
Replay<I>::~Replay() {
  assert(m_op_contexts.empty() && m_aio_completions.empty());
}

template <typename I>
int Replay<I>::process(bufferlist::iterator it, Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << dendl;

  RWLock::RLocker owner_lock(m_image_ctx.owner_lock);
  journal::EventEntry event_entry;
  try {
    ::decode(event_entry, it);
  } catch (const buffer::error &err) {
    lderr(cct) << "failed to decode event entry: " << err.what() << dendl;
    return -EINVAL;
  }

  boost::apply_visitor(EventVisitor(this, on_safe), event_entry.event);
  return 0;
}

template <typename I>
void Replay<I>::flush(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << dendl;

  on_finish = util::create_async_context_callback(
    m_image_ctx, on_finish);
  {
    Mutex::Locker locker(m_lock);
    assert(m_flush_ctx == nullptr);
    m_flush_ctx = on_finish;

    if (!m_op_contexts.empty() || !m_aio_completions.empty()) {
      return;
    }
  }
  on_finish->complete(m_ret_val);
}

template <typename I>
void Replay<I>::handle_event(const journal::AioDiscardEvent &event,
                             Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": AIO discard event" << dendl;

  AioCompletion *aio_comp = create_aio_completion(on_safe);
  AioImageRequest<I>::aio_discard(&m_image_ctx, aio_comp, event.offset,
                                  event.length);
}

template <typename I>
void Replay<I>::handle_event(const journal::AioWriteEvent &event,
                             Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": AIO write event" << dendl;

  bufferlist data = event.data;
  AioCompletion *aio_comp = create_aio_completion(on_safe);
  AioImageRequest<I>::aio_write(&m_image_ctx, aio_comp, event.offset,
                                event.length, data.c_str(), 0);
}

template <typename I>
void Replay<I>::handle_event(const journal::AioFlushEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": AIO flush event" << dendl;

  AioCompletion *aio_comp = create_aio_completion(on_safe);
  AioImageRequest<I>::aio_flush(&m_image_ctx, aio_comp);
}

template <typename I>
void Replay<I>::handle_event(const journal::OpFinishEvent &event,
                             Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Op finish event" << dendl;
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapCreateEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap create event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_create(event.snap_name.c_str(), on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapRemoveEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap remove event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_remove(event.snap_name.c_str(), on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapRenameEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap rename event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_rename(event.snap_id, event.snap_name.c_str(),
                                      on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapProtectEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap protect event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_protect(event.snap_name.c_str(), on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapUnprotectEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap unprotect event"
                 << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_unprotect(event.snap_name.c_str(), on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::SnapRollbackEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Snap rollback start event"
                 << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->snap_rollback(event.snap_name.c_str(),
                                        no_op_progress_callback, on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::RenameEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Rename event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->rename(event.image_name.c_str(), on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::ResizeEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Resize start event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->resize(event.size, no_op_progress_callback,
                                 on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::FlattenEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": Flatten start event" << dendl;

  Context *on_finish = create_op_context_callback(on_safe);
  m_image_ctx.operations->flatten(no_op_progress_callback, on_finish);
}

template <typename I>
void Replay<I>::handle_event(const journal::UnknownEvent &event,
			     Context *on_safe) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << this << " " << __func__ << ": unknown event" << dendl;
  on_safe->complete(0);
}

template <typename I>
Context *Replay<I>::create_op_context_callback(Context *on_safe) {
  C_OpOnFinish *on_finish;
  {
    on_finish = new C_OpOnFinish(this);
    m_op_contexts[on_finish] = on_safe;
  }
  return on_finish;
}

template <typename I>
void Replay<I>::handle_op_context_callback(Context *on_op_finish, int r) {
  Context *on_safe = nullptr;
  Context *on_flush = nullptr;
  {
    Mutex::Locker locker(m_lock);
    auto it = m_op_contexts.find(on_op_finish);
    assert(it != m_op_contexts.end());

    if (m_ret_val == 0 && r < 0) {
      m_ret_val = r;
    }

    on_safe = it->second;
    m_op_contexts.erase(it);
    if (m_op_contexts.empty() && m_aio_completions.empty()) {
      on_flush = m_flush_ctx;
    }
  }

  on_safe->complete(r);
  if (on_flush != nullptr) {
    on_flush->complete(m_ret_val);
  }
}

template <typename I>
AioCompletion *Replay<I>::create_aio_completion(Context *on_safe) {
  Mutex::Locker locker(m_lock);
  AioCompletion *aio_comp = AioCompletion::create(this, aio_completion_callback,
                                                  nullptr);
  m_aio_completions.insert(std::pair<AioCompletion*,Context*>(
			     aio_comp, on_safe));
  return aio_comp;
}

template <typename I>
void Replay<I>::handle_aio_completion(AioCompletion *aio_comp) {
  int r;
  Context *on_safe = nullptr;
  Context *on_flush = nullptr;
  {
    Mutex::Locker locker(m_lock);
    AioCompletions::iterator it = m_aio_completions.find(aio_comp);
    assert(it != m_aio_completions.end());

    r = aio_comp->get_return_value();
    if (m_ret_val == 0 && r < 0) {
      m_ret_val = r;
    }

    CephContext *cct = m_image_ctx.cct;
    ldout(cct, 20) << this << " " << __func__ << ": "
                   << "aio_comp=" << aio_comp << ", "
                   << "r=" << r << dendl;

    on_safe = it->second;
    m_aio_completions.erase(it);
    if (m_op_contexts.empty() && m_aio_completions.empty()) {
      on_flush = m_flush_ctx;
    }
  }

  on_safe->complete(r);
  if (on_flush != nullptr) {
    on_flush->complete(m_ret_val);
  }
}

template <typename I>
void Replay<I>::aio_completion_callback(completion_t cb, void *arg) {
  Replay *replay = reinterpret_cast<Replay *>(arg);
  AioCompletion *aio_comp = reinterpret_cast<AioCompletion *>(cb);

  replay->handle_aio_completion(aio_comp);
  aio_comp->release();
}

} // namespace journal
} // namespace librbd

template class librbd::journal::Replay<librbd::ImageCtx>;
