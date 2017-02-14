// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_EXCLUSIVE_LOCK_H
#define CEPH_LIBRBD_EXCLUSIVE_LOCK_H

#include "librbd/ManagedLock.h"
#include "librbd/ImageCtx.h"

namespace librbd {

template <typename ImageCtxT = ImageCtx>
class ExclusiveLock : public ManagedLock<ImageCtxT> {
public:
  static ExclusiveLock *create(ImageCtxT &image_ctx) {
    return new ExclusiveLock<ImageCtxT>(image_ctx);
  }

  ExclusiveLock(ImageCtxT &image_ctx);

  bool accept_requests(int *ret_val) const;

  void block_requests(int r);
  void unblock_requests();

  void init(uint64_t features, Context *on_init);
  void shut_down(Context *on_shutdown);

<<<<<<< HEAD
=======
  void try_lock(Context *on_tried_lock);
  void request_lock(Context *on_locked);
  void release_lock(Context *on_released);

  void reacquire_lock(Context *on_reacquired = nullptr);

>>>>>>> ce8edcfed6cd908779efd229202eab1232d16f1c
  void handle_peer_notification(int r);

protected:
  virtual void shutdown_handler(int r, Context *on_finish);
  virtual void pre_acquire_lock_handler(Context *on_finish);
  virtual void post_acquire_lock_handler(int r, Context *on_finish);
  virtual void pre_release_lock_handler(bool shutting_down,
                                        Context *on_finish);
  virtual void post_release_lock_handler(bool shutting_down, int r,
                                         Context *on_finish);

private:

  /**
   * @verbatim
   *
   * <start>                              * * > WAITING_FOR_REGISTER --------\
   *    |                                 * (watch not registered)           |
   *    |                                 *                                  |
   *    |                                 * * > WAITING_FOR_PEER ------------\
   *    |                                 * (request_lock busy)              |
   *    |                                 *                                  |
   *    |                                 * * * * * * * * * * * * * *        |
   *    |                                                           *        |
   *    v            (init)            (try_lock/request_lock)      *        |
   * UNINITIALIZED  -------> UNLOCKED ------------------------> ACQUIRING <--/
   *                            ^                                   |
   *                            |                                   v
   *                         RELEASING                        POST_ACQUIRING
   *                            |                                   |
   *                            |                                   |
   *                            |          (release_lock)           v
   *                      PRE_RELEASING <------------------------ LOCKED
   *
   * <LOCKED state>
   *    |
   *    v
   * REACQUIRING -------------------------------------> <finish>
   *    .                                                 ^
   *    .                                                 |
   *    . . . > <RELEASE action> ---> <ACQUIRE action> ---/
   *
   * <UNLOCKED/LOCKED states>
   *    |
   *    |
   *    v
   * PRE_SHUTTING_DOWN ---> SHUTTING_DOWN ---> SHUTDOWN ---> <finish>
   *
   * @endverbatim
   */

  struct C_InitComplete;

  ImageCtxT& m_image_ctx;
  Context *m_pre_post_callback = nullptr;

  uint32_t m_request_blocked_count = 0;
  int m_request_blocked_ret_val = 0;

  int m_acquire_lock_peer_ret_val = 0;

  void handle_init_complete(uint64_t features);
  void handle_post_acquiring_lock(int r);
  void handle_post_acquired_lock(int r);
};

} // namespace librbd

#endif // CEPH_LIBRBD_EXCLUSIVE_LOCK_H
