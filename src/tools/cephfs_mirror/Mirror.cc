// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/ceph_argparse.h"
#include "common/ceph_context.h"
#include "common/common_init.h"
#include "common/Cond.h"
#include "common/debug.h"
#include "common/errno.h"
#include "common/Timer.h"
#include "common/WorkQueue.h"
#include "include/types.h"
#include "json_spirit/json_spirit.h"
#include "mon/MonClient.h"
#include "msg/Messenger.h"
#include "aio_utils.h"
#include "Mirror.h"


#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_cephfs_mirror
#undef dout_prefix
#define dout_prefix *_dout << "cephfs::mirror::Mirror " << __func__

namespace cephfs {
namespace mirror {

namespace {

class SafeTimerSingleton : public SafeTimer {
public:
  ceph::mutex timer_lock = ceph::make_mutex("cephfs::mirror::timer_lock");

  explicit SafeTimerSingleton(CephContext *cct)
    : SafeTimer(cct, timer_lock, true) {
    init();
  }

  ~SafeTimerSingleton() {
    std::scoped_lock locker(timer_lock);
    shutdown();
  }
};

class ThreadPoolSingleton : public ThreadPool {
public:
  ContextWQ *work_queue = nullptr;

  explicit ThreadPoolSingleton(CephContext *cct)
    : ThreadPool(cct, "Mirror::thread_pool", "tp_mirror", 1) {
    work_queue = new ContextWQ("Mirror::work_queue", ceph::make_timespan(60), this);

    start();
  }

  ~ThreadPoolSingleton() override {
    work_queue->drain();
    delete work_queue;

    stop();
  }
};

} // anonymous namespace

struct Mirror::C_EnableMirroring : Context {
  Mirror *mirror;
  Filesystem filesystem;
  uint64_t pool_id;

  C_EnableMirroring(Mirror *mirror, const Filesystem &filesystem, uint64_t pool_id)
    : mirror(mirror),
      filesystem(filesystem),
      pool_id(pool_id) {
  }

  void finish(int r) override {
    enable_mirroring();
  }

  void enable_mirroring() {
    Context *ctx = new C_CallbackAdapter<C_EnableMirroring,
                                         &C_EnableMirroring::handle_enable_mirroring>(this);
    mirror->enable_mirroring(filesystem, pool_id, ctx);
  }

  void handle_enable_mirroring(int r) {
    mirror->handle_enable_mirroring(filesystem, r);
    delete this;
  }

  // context needs to live post completion
  void complete(int r) override {
    finish(r);
  }
};

struct Mirror::C_DisableMirroring : Context {
  Mirror *mirror;
  Filesystem filesystem;

  C_DisableMirroring(Mirror *mirror, const Filesystem &filesystem)
    : mirror(mirror),
      filesystem(filesystem) {
  }

  void finish(int r) override {
    disable_mirroring();
  }

  void disable_mirroring() {
    Context *ctx = new C_CallbackAdapter<C_DisableMirroring,
                                         &C_DisableMirroring::handle_disable_mirroring>(this);
    mirror->disable_mirroring(filesystem, ctx);
  }

  void handle_disable_mirroring(int r) {
    mirror->handle_disable_mirroring(filesystem, r);
    delete this;
  }

  // context needs to live post completion
  void complete(int r) override {
    finish(r);
  }
};

struct Mirror::C_PeerUpdate : Context {
  Mirror *mirror;
  Filesystem filesystem;
  Peer peer;
  bool remove = false;

  C_PeerUpdate(Mirror *mirror, const Filesystem &filesystem,
               const Peer &peer)
    : mirror(mirror),
      filesystem(filesystem),
      peer(peer) {
  }
  C_PeerUpdate(Mirror *mirror, const Filesystem &filesystem,
               const Peer &peer, bool remove)
    : mirror(mirror),
      filesystem(filesystem),
      peer(peer),
      remove(remove) {
  }

  void finish(int r) override {
    if (remove) {
      mirror->remove_peer(filesystem, peer);
    } else {
      mirror->add_peer(filesystem, peer);
    }
  }
};

struct Mirror::C_RestartMirroring : Context {
  Mirror *mirror;
  Filesystem filesystem;
  uint64_t pool_id;
  Peers peers;

  C_RestartMirroring(Mirror *mirror, const Filesystem &filesystem,
                     uint64_t pool_id, const Peers &peers)
    : mirror(mirror),
      filesystem(filesystem),
      pool_id(pool_id),
      peers(peers) {
  }

  void finish(int r) override {
    disable_mirroring();
  }

  void disable_mirroring() {
    Context *ctx = new C_CallbackAdapter<C_RestartMirroring,
                                         &C_RestartMirroring::handle_disable_mirroring>(this);
    mirror->disable_mirroring(filesystem, ctx);
  }

  void handle_disable_mirroring(int r) {
    enable_mirroring();
  }

  void enable_mirroring() {
    std::scoped_lock locker(mirror->m_lock);
    Context *ctx = new C_CallbackAdapter<C_RestartMirroring,
                                         &C_RestartMirroring::handle_enable_mirroring>(this);
    mirror->enable_mirroring(filesystem, pool_id, ctx, true);
  }

  void handle_enable_mirroring(int r) {
    mirror->handle_enable_mirroring(filesystem, peers, r);
    delete this;
  }

  // context needs to live post completion
  void complete(int r) override {
    finish(r);
  }
};

Mirror::Mirror(CephContext *cct, const std::vector<const char*> &args,
                MonClient *monc, Messenger *msgr)
  : m_cct(cct),
    m_args(args),
    m_monc(monc),
    m_msgr(msgr),
    m_listener(this),
    m_last_blocklist_check(ceph_clock_now()) {
  auto thread_pool = &(cct->lookup_or_create_singleton_object<ThreadPoolSingleton>(
                         "cephfs::mirror::thread_pool", false, cct));
  auto safe_timer = &(cct->lookup_or_create_singleton_object<SafeTimerSingleton>(
                        "cephfs::mirror::safe_timer", false, cct));
  m_work_queue = thread_pool->work_queue;
  m_timer = safe_timer;
  m_timer_lock = &safe_timer->timer_lock;
  std::scoped_lock timer_lock(*m_timer_lock);
  schedule_mirror_update_task();
}

Mirror::~Mirror() {
  dout(10) << dendl;
}

int Mirror::init_mon_client() {
  dout(20) << dendl;

  m_monc->set_messenger(m_msgr);
  m_monc->set_want_keys(CEPH_ENTITY_TYPE_MON);

  int r = m_monc->init();
  if (r < 0) {
    derr << ": failed to init mon client: " << cpp_strerror(r) << dendl;
    return r;
  }

  r = m_monc->authenticate(m_cct->_conf->client_mount_timeout);
  if (r < 0) {
    derr << ": failed to authenticate to monitor: " << cpp_strerror(r) << dendl;
    return r;
  }

  client_t me = m_monc->get_global_id();
  m_msgr->set_myname(entity_name_t::CLIENT(me.v));
  return 0;
}

int Mirror::init(std::string &reason) {
  dout(20) << dendl;

  std::scoped_lock locker(m_lock);
  int r = init_mon_client();
  if (r < 0) {
    return r;
  }

  return 0;
}

void Mirror::shutdown() {
  dout(20) << dendl;

  std::unique_lock locker(m_lock);
  if (m_mirror_actions.empty()) {
    return;
  }

  m_stopping = true;
  m_cond.notify_all();
  m_cond.wait(locker, [this] {return m_stopped;});
}

void Mirror::handle_signal(int signum) {
  dout(10) << ": signal=" << signum << dendl;
  ceph_assert(signum == SIGTERM || signum == SIGINT);
  shutdown();
  ::exit(0);
}

void Mirror::handle_enable_mirroring(const Filesystem &filesystem,
                                     const Peers &peers, int r) {
  dout(20) << ": filesystem=" << filesystem << ", peers=" << peers
           << ", r=" << r << dendl;

  std::scoped_lock locker(m_lock);
  auto &mirror_action = m_mirror_actions.at(filesystem);
  ceph_assert(mirror_action.action_in_progress);

  mirror_action.action_in_progress = false;
  m_cond.notify_all();
  if (r < 0) {
    derr << ": failed to initialize FSMirror for filesystem=" << filesystem
         << ": " << cpp_strerror(r) << dendl;
    return;
  }

  for (auto &peer : peers) {
    mirror_action.fs_mirror->add_peer(peer);
  }

  dout(10) << ": Initialized FSMirror for filesystem=" << filesystem << dendl;
}

void Mirror::handle_enable_mirroring(const Filesystem &filesystem, int r) {
  dout(20) << ": filesystem=" << filesystem << ", r=" << r << dendl;

  std::scoped_lock locker(m_lock);
  auto &mirror_action = m_mirror_actions.at(filesystem);
  ceph_assert(mirror_action.action_in_progress);

  mirror_action.action_in_progress = false;
  m_cond.notify_all();
  if (r < 0) {
    derr << ": failed to initialize FSMirror for filesystem=" << filesystem
         << ": " << cpp_strerror(r) << dendl;
    return;
  }

  dout(10) << ": Initialized FSMirror for filesystem=" << filesystem << dendl;
}

void Mirror::enable_mirroring(const Filesystem &filesystem, uint64_t local_pool_id,
                              Context *on_finish, bool is_restart) {
  ceph_assert(ceph_mutex_is_locked(m_lock));

  auto &mirror_action = m_mirror_actions.at(filesystem);
  if (is_restart) {
    ceph_assert(mirror_action.action_in_progress);
    mirror_action.fs_mirror.reset();
  } else {
    ceph_assert(!mirror_action.action_in_progress);
  }

  ceph_assert(!mirror_action.fs_mirror);

  dout(10) << ": starting FSMirror: filesystem=" << filesystem << dendl;

  mirror_action.action_in_progress = true;
  mirror_action.fs_mirror = std::make_unique<FSMirror>(m_cct, filesystem, local_pool_id,
                                                       m_args, m_work_queue);
  mirror_action.fs_mirror->init(new C_AsyncCallback<ContextWQ>(m_work_queue, on_finish));
}

void Mirror::mirroring_enabled(const Filesystem &filesystem, uint64_t local_pool_id) {
  dout(10) << ": filesystem=" << filesystem << ", pool_id=" << local_pool_id << dendl;

  std::scoped_lock locker(m_lock);
  if (m_stopping) {
    return;
  }

  auto p = m_mirror_actions.emplace(filesystem, MirrorAction(local_pool_id));
  auto &mirror_action = p.first->second;
  mirror_action.action_ctxs.push_back(new C_EnableMirroring(this, filesystem, local_pool_id));
}

void Mirror::handle_disable_mirroring(const Filesystem &filesystem, int r) {
  dout(10) << ": filesystem=" << filesystem << ", r=" << r << dendl;

  std::scoped_lock locker(m_lock);
  auto &mirror_action = m_mirror_actions.at(filesystem);

  if (!mirror_action.fs_mirror->is_failed()) {
    ceph_assert(mirror_action.action_in_progress);
    mirror_action.action_in_progress = false;
    m_cond.notify_all();
  }

  if (!m_stopping) {
    mirror_action.fs_mirror.reset();
    if (mirror_action.action_ctxs.empty()) {
      dout(10) << ": no pending actions for filesystem=" << filesystem << dendl;
      m_mirror_actions.erase(filesystem);
    }
  }
}

void Mirror::disable_mirroring(const Filesystem &filesystem, Context *on_finish) {
  ceph_assert(ceph_mutex_is_locked(m_lock));

  auto &mirror_action = m_mirror_actions.at(filesystem);
  ceph_assert(mirror_action.fs_mirror);
  ceph_assert(!mirror_action.action_in_progress);

  if (mirror_action.fs_mirror->is_failed()) {
    dout(10) << ": init failed for filesystem=" << filesystem << dendl;
    m_work_queue->queue(on_finish, -EINVAL);
    return;
  }

  mirror_action.action_in_progress = true;
  mirror_action.fs_mirror->shutdown(new C_AsyncCallback<ContextWQ>(m_work_queue, on_finish));
}

void Mirror::mirroring_disabled(const Filesystem &filesystem) {
  dout(10) << ": filesystem=" << filesystem << dendl;

  std::scoped_lock locker(m_lock);
  if (m_stopping) {
    dout(5) << "shutting down" << dendl;
    return;
  }

  auto &mirror_action = m_mirror_actions.at(filesystem);
  mirror_action.action_ctxs.push_back(new C_DisableMirroring(this, filesystem));
}

void Mirror::add_peer(const Filesystem &filesystem, const Peer &peer) {
  ceph_assert(ceph_mutex_is_locked(m_lock));

  auto &mirror_action = m_mirror_actions.at(filesystem);
  ceph_assert(mirror_action.fs_mirror);
  ceph_assert(!mirror_action.action_in_progress);

  mirror_action.fs_mirror->add_peer(peer);
}

void Mirror::peer_added(const Filesystem &filesystem, const Peer &peer) {
  dout(20) << ": filesystem=" << filesystem << ", peer=" << peer << dendl;

  std::scoped_lock locker(m_lock);
  if (m_stopping) {
    dout(5) << "shutting down" << dendl;
    return;
  }

  auto &mirror_action = m_mirror_actions.at(filesystem);
  mirror_action.action_ctxs.push_back(new C_PeerUpdate(this, filesystem, peer));
}

void Mirror::remove_peer(const Filesystem &filesystem, const Peer &peer) {
  ceph_assert(ceph_mutex_is_locked(m_lock));

  auto &mirror_action = m_mirror_actions.at(filesystem);
  ceph_assert(mirror_action.fs_mirror);
  ceph_assert(!mirror_action.action_in_progress);

  mirror_action.fs_mirror->remove_peer(peer);
}

void Mirror::peer_removed(const Filesystem &filesystem, const Peer &peer) {
  dout(20) << ": filesystem=" << filesystem << ", peer=" << peer << dendl;

  std::scoped_lock locker(m_lock);
  if (m_stopping) {
    dout(5) << "shutting down" << dendl;
    return;
  }

  auto &mirror_action = m_mirror_actions.at(filesystem);
  mirror_action.action_ctxs.push_back(new C_PeerUpdate(this, filesystem, peer, true));
}

void Mirror::update_fs_mirrors() {
  dout(20) << dendl;

  double blocklist_interval = g_ceph_context->_conf.get_val<std::chrono::seconds>
    ("cephfs_mirror_restart_mirror_on_blocklist_interval").count();
  auto now = ceph_clock_now();
  bool check_blocklist = blocklist_interval > 0 && ((now - m_last_blocklist_check) >= blocklist_interval);

  {
    std::scoped_lock locker(m_lock);
    for (auto &[filesystem, mirror_action] : m_mirror_actions) {
      if (check_blocklist && !mirror_action.action_in_progress
          && mirror_action.fs_mirror && mirror_action.fs_mirror->is_blocklisted()) {
        // about to restart blocklisted mirror instance -- nothing
        // should interfere
        dout(5) << ": filesystem=" << filesystem << " is blocklisted -- restarting" << dendl;
        auto peers = mirror_action.fs_mirror->get_peers();
        mirror_action.action_ctxs.push_front(
          new C_RestartMirroring(this, filesystem, mirror_action.pool_id, peers));
      }
      if (!mirror_action.action_ctxs.empty() && !mirror_action.action_in_progress) {
        auto ctx = std::move(mirror_action.action_ctxs.front());
        mirror_action.action_ctxs.pop_front();
        ctx->complete(0);
      }
    }

    if (check_blocklist) {
      m_last_blocklist_check = now;
    }
  }

  schedule_mirror_update_task();
}

void Mirror::schedule_mirror_update_task() {
  ceph_assert(m_timer_task == nullptr);
  ceph_assert(ceph_mutex_is_locked(*m_timer_lock));

  m_timer_task = new LambdaContext([this](int _) {
                                     m_timer_task = nullptr;
                                     update_fs_mirrors();
                                   });
  double after = g_ceph_context->_conf.get_val<std::chrono::seconds>
    ("cephfs_mirror_mirror_action_update_interval").count();
  dout(20) << ": scheduling fs mirror update (" << m_timer_task << ") after "
           << after << " seconds" << dendl;
  m_timer->add_event_after(after, m_timer_task);
}

void Mirror::run() {
  dout(20) << dendl;

  std::unique_lock locker(m_lock);
  m_cluster_watcher.reset(new ClusterWatcher(m_cct, m_monc, m_listener));
  m_msgr->add_dispatcher_tail(m_cluster_watcher.get());

  m_cluster_watcher->init();
  m_cond.wait(locker, [this]{return m_stopping;});

  locker.unlock();
  {
    std::scoped_lock timer_lock(*m_timer_lock);
    if (m_timer_task != nullptr) {
      dout(10) << ": canceling timer task=" << m_timer_task << dendl;
      m_timer->cancel_event(m_timer_task);
      m_timer_task = nullptr;
    }
  }
  locker.lock();

  for (auto &[filesystem, mirror_action] : m_mirror_actions) {
    dout(10) << ": trying to shutdown filesystem=" << filesystem << dendl;
    // wait for in-progress action and shutdown
    m_cond.wait(locker, [&mirror_action=mirror_action] 
                {return !mirror_action.action_in_progress;});
    if (mirror_action.fs_mirror &&
        !mirror_action.fs_mirror->is_stopping() &&
        !mirror_action.fs_mirror->is_failed()) {
      C_SaferCond cond;
      mirror_action.fs_mirror->shutdown(new C_AsyncCallback<ContextWQ>(m_work_queue, &cond));
      int r = cond.wait();
      dout(10) << ": shutdown filesystem=" << filesystem << ", r=" << r << dendl;
    }
  }

  m_stopped = true;
  m_cond.notify_all();
}

} // namespace mirror
} // namespace cephfs

