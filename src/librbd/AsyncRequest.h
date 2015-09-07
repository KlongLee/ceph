// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_LIBRBD_ASYNC_REQUEST_H
#define CEPH_LIBRBD_ASYNC_REQUEST_H

#include "include/int_types.h"
#include "include/Context.h"
#include "include/rados/librados.hpp"
#include "include/xlist.h"

/* DARWIN Missing ERESTART */
#include "include/compat.h"

namespace librbd {

class ImageCtx;

class AsyncRequest
{
public:
  AsyncRequest(ImageCtx &image_ctx, Context *on_finish);
  virtual ~AsyncRequest();

  void complete(int r) {
    if (should_complete(r)) {
      r = filter_return_code(r);
      finish(r);
      m_on_finish->complete(r);
      delete this;
    }
  }

  virtual void send() = 0;

  inline bool is_canceled() const {
    return m_canceled;
  }
  inline void cancel() {
    m_canceled = true;
  }

protected:
  ImageCtx &m_image_ctx;
  Context *m_on_finish;

  librados::AioCompletion *create_callback_completion();
  Context *create_callback_context();
  Context *create_async_callback_context();

  void async_complete(int r);

  virtual bool should_complete(int r) = 0;
  virtual int filter_return_code(int r) const {
    return r;
  }

  virtual void finish(int r) {
  }
private:
  bool m_canceled;
  xlist<AsyncRequest *>::item m_xlist_item;
};

class C_AsyncRequest : public Context
{
public:
  C_AsyncRequest(AsyncRequest *req)
    : m_req(req)
  {
  }

protected:
  virtual void finish(int r) {
    m_req->complete(r);
  }

private:
  AsyncRequest *m_req;
};

} // namespace librbd

#endif //CEPH_LIBRBD_ASYNC_REQUEST_H
