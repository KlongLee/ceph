// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_JOURNAL_REPLAY_H
#define CEPH_LIBRBD_JOURNAL_REPLAY_H

#include "include/int_types.h"
#include "include/buffer_fwd.h"
#include "include/Context.h"
#include "include/unordered_map.h"
#include "include/rbd/librbd.hpp"
#include "common/Mutex.h"
#include "librbd/journal/Entries.h"
#include <boost/variant.hpp>
#include <map>

namespace librbd {

class AioCompletion;
class ImageCtx;

namespace journal {

template <typename ImageCtxT = ImageCtx>
class Replay {
public:
  static Replay *create(ImageCtxT &image_ctx) {
    return new Replay(image_ctx);
  }

  Replay(ImageCtxT &image_ctx);
  ~Replay();

  int process(bufferlist::iterator it, Context *on_safe = NULL);
  void flush(Context *on_finish);

private:
  typedef ceph::unordered_map<Context *, Context *> OpContexts;
  typedef std::map<AioCompletion*,Context*> AioCompletions;

  struct C_OpOnFinish : public Context {
    Replay *replay;
    C_OpOnFinish(Replay *replay) : replay(replay) {
    }
    virtual void finish(int r) override {
      replay->handle_op_context_callback(this, r);
    }
  };

  struct EventVisitor : public boost::static_visitor<void> {
    Replay *replay;
    Context *on_safe;

    EventVisitor(Replay *_replay, Context *_on_safe)
      : replay(_replay), on_safe(_on_safe) {
    }

    template <typename Event>
    inline void operator()(const Event &event) const {
      replay->handle_event(event, on_safe);
    }
  };

  ImageCtxT &m_image_ctx;

  Mutex m_lock;

  OpContexts m_op_contexts;
  AioCompletions m_aio_completions;
  Context *m_flush_ctx;
  int m_ret_val;

  void handle_event(const AioDiscardEvent &event, Context *on_safe);
  void handle_event(const AioWriteEvent &event, Context *on_safe);
  void handle_event(const AioFlushEvent &event, Context *on_safe);
  void handle_event(const OpFinishEvent &event, Context *on_safe);
  void handle_event(const SnapCreateEvent &event, Context *on_safe);
  void handle_event(const SnapRemoveEvent &event, Context *on_safe);
  void handle_event(const SnapRenameEvent &event, Context *on_safe);
  void handle_event(const SnapProtectEvent &event, Context *on_safe);
  void handle_event(const SnapUnprotectEvent &event, Context *on_safe);
  void handle_event(const SnapRollbackEvent &event, Context *on_safe);
  void handle_event(const RenameEvent &event, Context *on_safe);
  void handle_event(const ResizeEvent &event, Context *on_safe);
  void handle_event(const FlattenEvent &event, Context *on_safe);
  void handle_event(const UnknownEvent &event, Context *on_safe);

  Context *create_op_context_callback(Context *on_safe);
  void handle_op_context_callback(Context *on_op_finish, int r);

  AioCompletion *create_aio_completion(Context *on_safe);
  void handle_aio_completion(AioCompletion *aio_comp);

  static void aio_completion_callback(completion_t cb, void *arg);
};

} // namespace journal
} // namespace librbd

extern template class librbd::journal::Replay<librbd::ImageCtx>;

#endif // CEPH_LIBRBD_JOURNAL_REPLAY_H
