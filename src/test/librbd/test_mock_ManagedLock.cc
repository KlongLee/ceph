// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "test/librbd/test_mock_fixture.h"
#include "test/librbd/test_support.h"
#include "librbd/ManagedLock.h"
#include "librbd/managed_lock/AcquireRequest.h"
#include "librbd/managed_lock/ReacquireRequest.h"
#include "librbd/managed_lock/ReleaseRequest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <list>

namespace librbd {

struct MockManagedLockImageCtx : public MockImageCtx {
  MockManagedLockImageCtx(ImageCtx &image_ctx) : MockImageCtx(image_ctx) {}
};

namespace watcher {
template <>
struct Traits<MockManagedLockImageCtx> {
  typedef librbd::MockImageWatcher Watcher;
};
}

namespace managed_lock {

template<typename T>
struct BaseRequest {
  static std::list<T *> s_requests;
  Context *on_finish = nullptr;
  bool exclusive;

  static T* create(librados::IoCtx& ioctx, MockImageWatcher *watcher,
                   ContextWQ *work_queue, const std::string& oid,
                   const std::string& cookie, bool exclusive,
                   Context *on_finish) {
    assert(!s_requests.empty());
    T* req = s_requests.front();
    req->on_finish = on_finish;
    req->exclusive = exclusive;
    s_requests.pop_front();
    return req;
  }

  BaseRequest() {
    s_requests.push_back(reinterpret_cast<T*>(this));
  }
};

template<typename T>
std::list<T *> BaseRequest<T>::s_requests;

template <>
struct AcquireRequest<MockManagedLockImageCtx> : public BaseRequest<AcquireRequest<MockManagedLockImageCtx> > {
  MOCK_METHOD0(send, void());
};

template <>
struct ReacquireRequest<MockManagedLockImageCtx> : public BaseRequest<ReacquireRequest<MockManagedLockImageCtx> > {
  static ReacquireRequest* create(librados::IoCtx &ioctx, const std::string& oid,
                                const string& old_cookie, const std::string& new_cookie,
                                bool exclusive, Context *on_finish) {
    return BaseRequest::create(ioctx, nullptr, nullptr, oid, new_cookie,
                               exclusive, on_finish);
  }

  MOCK_METHOD0(send, void());
};

template <>
struct ReleaseRequest<MockManagedLockImageCtx> : public BaseRequest<ReleaseRequest<MockManagedLockImageCtx> > {
  static ReleaseRequest *create(librados::IoCtx& ioctx, MockImageWatcher *watcher,
                                ContextWQ *work_queue, const std::string& oid,
                                const std::string& cookie, Context *on_finish) {
    return BaseRequest::create(ioctx, watcher, work_queue, oid, cookie, false,
                               on_finish);
  }
  MOCK_METHOD0(send, void());
};

} // namespace managed_lock
} // namespace librbd

// template definitions
#include "librbd/ManagedLock.cc"
template class librbd::ManagedLock<librbd::MockManagedLockImageCtx>;


ACTION_P3(QueueRequest, request, r, wq) {
  if (request->on_finish != nullptr) {
    if (wq != nullptr) {
      wq->queue(request->on_finish, r);
    } else {
      request->on_finish->complete(r);
    }
  }
}

ACTION_P2(QueueContext, r, wq) {
  wq->queue(arg0, r);
}

namespace librbd {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::InSequence;
using ::testing::Return;

class TestMockManagedLock : public TestMockFixture {
public:
  typedef ManagedLock<MockManagedLockImageCtx> MockManagedLock;
  typedef managed_lock::AcquireRequest<MockManagedLockImageCtx> MockAcquireRequest;
  typedef managed_lock::ReacquireRequest<MockManagedLockImageCtx> MockReacquireRequest;
  typedef managed_lock::ReleaseRequest<MockManagedLockImageCtx> MockReleaseRequest;

  void expect_get_watch_handle(MockImageWatcher &mock_watcher,
                               uint64_t watch_handle = 1234567890) {
    EXPECT_CALL(mock_watcher, get_watch_handle())
      .WillOnce(Return(watch_handle));
  }

  void expect_acquire_lock(MockImageWatcher &watcher,
                           ContextWQ *work_queue,
                           MockAcquireRequest &acquire_request, int r) {
    expect_get_watch_handle(watcher);
    EXPECT_CALL(acquire_request, send())
                  .WillOnce(QueueRequest(&acquire_request, r, work_queue));
  }

  void expect_release_lock(ContextWQ *work_queue,
                           MockReleaseRequest &release_request, int r) {
    EXPECT_CALL(release_request, send())
                  .WillOnce(QueueRequest(&release_request, r, work_queue));
  }

  void expect_reacquire_lock(MockImageWatcher& watcher,
                             ContextWQ *work_queue,
                             MockReacquireRequest &mock_reacquire_request,
                             int r) {
    expect_get_watch_handle(watcher, 98765);
    EXPECT_CALL(mock_reacquire_request, send())
                  .WillOnce(QueueRequest(&mock_reacquire_request, r, work_queue));
  }

  void expect_flush_notifies(MockImageWatcher *mock_watcher) {
    EXPECT_CALL(*mock_watcher, flush(_))
                  .WillOnce(CompleteContext(0, (ContextWQ *)nullptr));
  }

  int when_acquire_exclusive_lock(MockManagedLock &managed_lock) {
    C_SaferCond ctx;
    {
      managed_lock.acquire_exclusive_lock(&ctx);
    }
    return ctx.wait();
  }
  int when_acquire_shared_lock(MockManagedLock &managed_lock) {
    C_SaferCond ctx;
    {
      managed_lock.acquire_shared_lock(&ctx);
    }
    return ctx.wait();
  }

  int when_release_lock(MockManagedLock &managed_lock) {
    C_SaferCond ctx;
    {
      managed_lock.release_lock(&ctx);
    }
    return ctx.wait();
  }
  int when_shut_down(MockManagedLock &managed_lock) {
    C_SaferCond ctx;
    {
      managed_lock.shut_down(&ctx);
    }
    return ctx.wait();
  }

  bool is_exclusive_lock_owner(MockManagedLock &managed_lock) {
    return managed_lock.is_exclusive_lock_owner();
  }

  bool is_shared_lock_owner(MockManagedLock &managed_lock) {
    return managed_lock.is_shared_lock_owner();
  }

};

TEST_F(TestMockManagedLock, StateTransitions) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);
  InSequence seq;

  MockAcquireRequest request_lock_acquire1;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire1, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockReleaseRequest request_release;
  expect_release_lock(ictx->op_work_queue, request_release, 0);
  ASSERT_EQ(0, when_release_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockAcquireRequest request_lock_acquire2;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire2, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockReleaseRequest request_release2;
  expect_release_lock(ictx->op_work_queue, request_release2, 0);
  ASSERT_EQ(0, when_release_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockAcquireRequest request_shared_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_shared_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_shared_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
  ASSERT_TRUE(is_shared_lock_owner(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireExLockExLockedState) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireShLockShLockedState) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_shared_lock(managed_lock));
  ASSERT_EQ(0, when_acquire_shared_lock(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireShLockExLockedState) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_EQ(-EPERM, when_acquire_shared_lock(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireExLockShLockedState) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_shared_lock(managed_lock));
  ASSERT_EQ(-EPERM, when_acquire_exclusive_lock(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireLockAlreadyLocked) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, -EAGAIN);
  ASSERT_EQ(-EAGAIN, when_acquire_exclusive_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireLockBusy) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, -EBUSY);
  ASSERT_EQ(-EBUSY, when_acquire_exclusive_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireLockError) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue, try_lock_acquire, -EINVAL);

  ASSERT_EQ(-EINVAL, when_acquire_exclusive_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, AcquireLockBlacklist) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  // will abort after seeing blacklist error (avoid infinite request loop)
  MockAcquireRequest request_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire, -EBLACKLISTED);
  ASSERT_EQ(-EBLACKLISTED, when_acquire_exclusive_lock(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, ReleaseLockUnlockedState) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  ASSERT_EQ(0, when_release_lock(managed_lock));

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, ReleaseLockError) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest try_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      try_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));

  MockReleaseRequest release;
  expect_release_lock(ictx->op_work_queue, release, -EINVAL);

  ASSERT_EQ(-EINVAL, when_release_lock(managed_lock));
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
}

TEST_F(TestMockManagedLock, ConcurrentRequests) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  expect_get_watch_handle(*mock_image_ctx.image_watcher);

  C_SaferCond wait_for_send_ctx1;
  MockAcquireRequest acquire_error;
  EXPECT_CALL(acquire_error, send())
                .WillOnce(Notify(&wait_for_send_ctx1));

  MockAcquireRequest request_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue, request_acquire, 0);

  MockReleaseRequest release;
  C_SaferCond wait_for_send_ctx2;
  EXPECT_CALL(release, send())
                .WillOnce(Notify(&wait_for_send_ctx2));

  C_SaferCond acquire_request_ctx1;
  managed_lock.acquire_exclusive_lock(&acquire_request_ctx1);

  C_SaferCond acquire_lock_ctx1;
  C_SaferCond acquire_lock_ctx2;
  managed_lock.acquire_exclusive_lock(&acquire_lock_ctx1);
  managed_lock.acquire_exclusive_lock(&acquire_lock_ctx2);

  // fail the try_lock
  ASSERT_EQ(0, wait_for_send_ctx1.wait());
  acquire_error.on_finish->complete(-EINVAL);
  ASSERT_EQ(-EINVAL, acquire_request_ctx1.wait());

  C_SaferCond acquire_lock_ctx3;
  managed_lock.acquire_exclusive_lock(&acquire_lock_ctx3);

  C_SaferCond release_lock_ctx1;
  managed_lock.release_lock(&release_lock_ctx1);

  // all three pending request locks should complete
  ASSERT_EQ(-EINVAL, acquire_lock_ctx1.wait());
  ASSERT_EQ(-EINVAL, acquire_lock_ctx2.wait());
  ASSERT_EQ(0, acquire_lock_ctx3.wait());

  // proceed with the release
  ASSERT_EQ(0, wait_for_send_ctx2.wait());
  release.on_finish->complete(0);
  ASSERT_EQ(0, release_lock_ctx1.wait());

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, ConcurrentExclusiveSharedRequests) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  expect_get_watch_handle(*mock_image_ctx.image_watcher);

  C_SaferCond wait_for_send_ctx1;
  MockAcquireRequest request_ex_acquire;
  EXPECT_CALL(request_ex_acquire, send())
                .WillOnce(Notify(&wait_for_send_ctx1));

  expect_get_watch_handle(*mock_image_ctx.image_watcher);

  C_SaferCond wait_for_send_ctx2;
  MockAcquireRequest request_sh_acquire;
  EXPECT_CALL(request_sh_acquire, send())
                .WillOnce(Notify(&wait_for_send_ctx2));

  MockReleaseRequest release;
  C_SaferCond wait_for_send_ctx3;
  EXPECT_CALL(release, send())
                .WillOnce(Notify(&wait_for_send_ctx3));

  C_SaferCond acquire_ex_ctx1;
  managed_lock.acquire_exclusive_lock(&acquire_ex_ctx1);

  C_SaferCond acquire_sh_ctx1;
  managed_lock.acquire_shared_lock(&acquire_sh_ctx1);

  // fail the exclusive_lock
  ASSERT_EQ(0, wait_for_send_ctx1.wait());
  request_ex_acquire.on_finish->complete(-EINVAL);
  ASSERT_EQ(-EINVAL, acquire_ex_ctx1.wait());

  // succeed the shared lock
  ASSERT_EQ(0, wait_for_send_ctx2.wait());
  request_sh_acquire.on_finish->complete(0);
  ASSERT_EQ(0, acquire_sh_ctx1.wait());
  ASSERT_TRUE(managed_lock.is_shared_lock_owner());

  C_SaferCond release_lock_ctx1;
  managed_lock.release_lock(&release_lock_ctx1);

  // proceed with the release
  ASSERT_EQ(0, wait_for_send_ctx3.wait());
  release.on_finish->complete(0);
  ASSERT_EQ(0, release_lock_ctx1.wait());

  expect_get_watch_handle(*mock_image_ctx.image_watcher);

  C_SaferCond wait_for_send_ctx4;
  MockAcquireRequest request_ex_acquire2;
  EXPECT_CALL(request_ex_acquire2, send())
                .WillOnce(Notify(&wait_for_send_ctx4));

  MockReleaseRequest release2;
  expect_release_lock(ictx->op_work_queue, release2, 0);

  C_SaferCond acquire_ex_ctx2;
  managed_lock.acquire_exclusive_lock(&acquire_ex_ctx2);

  C_SaferCond acquire_sh_ctx2;
  managed_lock.acquire_shared_lock(&acquire_sh_ctx2);

  // succeed the exclusive_lock
  ASSERT_EQ(0, wait_for_send_ctx4.wait());
  request_ex_acquire2.on_finish->complete(0);
  ASSERT_EQ(0, acquire_ex_ctx2.wait());

  ASSERT_EQ(-EPERM, acquire_sh_ctx2.wait());
  ASSERT_TRUE(managed_lock.is_exclusive_lock_owner());

  C_SaferCond release_lock_ctx2;
  managed_lock.release_lock(&release_lock_ctx2);

  expect_get_watch_handle(*mock_image_ctx.image_watcher);

  C_SaferCond wait_for_send_ctx5;
  MockAcquireRequest request_sh_acquire2;
  EXPECT_CALL(request_sh_acquire2, send())
                .WillOnce(Notify(&wait_for_send_ctx5));

  MockReleaseRequest release3;
  expect_release_lock(ictx->op_work_queue, release3, 0);

  C_SaferCond acquire_sh_ctx3;
  managed_lock.acquire_shared_lock(&acquire_sh_ctx3);

  C_SaferCond acquire_ex_ctx3;
  managed_lock.acquire_exclusive_lock(&acquire_ex_ctx3);

  // succeed the exclusive_lock
  ASSERT_EQ(0, wait_for_send_ctx5.wait());
  request_sh_acquire2.on_finish->complete(0);
  ASSERT_EQ(0, acquire_sh_ctx3.wait());

  ASSERT_EQ(-EPERM, acquire_ex_ctx3.wait());
  ASSERT_TRUE(managed_lock.is_shared_lock_owner());

  ASSERT_EQ(0, when_shut_down(managed_lock));
}

TEST_F(TestMockManagedLock, ReacquireExLock) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest request_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockReacquireRequest mock_reacquire_request;
  C_SaferCond reacquire_ctx;
  expect_reacquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                        mock_reacquire_request, 0);
  managed_lock.reacquire_lock(&reacquire_ctx);
  ASSERT_EQ(0, reacquire_ctx.wait());
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
}

TEST_F(TestMockManagedLock, ReacquireShLock) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest request_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_shared_lock(managed_lock));
  ASSERT_TRUE(is_shared_lock_owner(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  MockReacquireRequest mock_reacquire_request;
  C_SaferCond reacquire_ctx;
  expect_reacquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                        mock_reacquire_request, 0);
  managed_lock.reacquire_lock(&reacquire_ctx);
  ASSERT_EQ(0, reacquire_ctx.wait());
  ASSERT_TRUE(is_shared_lock_owner(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
  ASSERT_FALSE(is_shared_lock_owner(managed_lock));
}

TEST_F(TestMockManagedLock, ReacquireLockError) {
  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockManagedLockImageCtx mock_image_ctx(*ictx);
  MockManagedLock managed_lock(ictx->md_ctx, ictx->op_work_queue,
                               ictx->header_oid, mock_image_ctx.image_watcher);

  InSequence seq;

  MockAcquireRequest request_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      request_lock_acquire, 0);
  ASSERT_EQ(0, when_acquire_exclusive_lock(managed_lock));
  ASSERT_TRUE(is_exclusive_lock_owner(managed_lock));

  MockReacquireRequest mock_reacquire_request;
  C_SaferCond reacquire_ctx;
  expect_reacquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                        mock_reacquire_request, -EOPNOTSUPP);

  MockReleaseRequest reacquire_lock_release;
  expect_release_lock(ictx->op_work_queue, reacquire_lock_release, 0);

  MockAcquireRequest reacquire_lock_acquire;
  expect_acquire_lock(*mock_image_ctx.image_watcher, ictx->op_work_queue,
                      reacquire_lock_acquire, 0);

  managed_lock.reacquire_lock(&reacquire_ctx);
  ASSERT_EQ(-EOPNOTSUPP, reacquire_ctx.wait());

  MockReleaseRequest shutdown_release;
  expect_release_lock(ictx->op_work_queue, shutdown_release, 0);
  ASSERT_EQ(0, when_shut_down(managed_lock));
  ASSERT_FALSE(is_exclusive_lock_owner(managed_lock));
}

} // namespace librbd
