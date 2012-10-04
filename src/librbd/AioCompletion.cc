// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>

#include "common/ceph_context.h"
#include "common/dout.h"

#include "librbd/AioRequest.h"
#include "librbd/internal.h"

#include "librbd/AioCompletion.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::AioCompletion: "

namespace librbd {

  void AioCompletion::complete_request(CephContext *cct, ssize_t r)
  {
    ldout(cct, 20) << "AioCompletion::complete_request() this="
		   << (void *)this << " complete_cb=" << (void *)complete_cb << dendl;
    lock.Lock();
    if (rval >= 0) {
      if (r < 0 && r != -EEXIST)
	rval = r;
      else if (r > 0)
	rval += r;
    }
    assert(pending_count);
    int count = --pending_count;
    if (!count) {
      if (rval >= 0 && aio_type == AIO_TYPE_READ) {
	// FIXME: make the destriper write directly into a buffer so
	// that we avoid shuffling pointers and copying zeros around.
	bufferlist bl;
	destriper.assemble_result(bl, true);
	assert(bl.length() == read_buf_len);
	bl.copy(0, read_buf_len, read_buf);
	ldout(cct, 20) << "AioCompletion::complete_request() copied resulting " << bl.length()
		       << " bytes to " << (void*)read_buf << dendl;
      }      

      complete();
    }
    put_unlock();
  }

  void C_AioRead::finish(int r)
  {
    ldout(m_cct, 10) << "C_AioRead::finish() " << this << " r = " << r << dendl;
    if (r >= 0 || r == -ENOENT) { // this was a sparse_read operation
      ldout(m_cct, 10) << " got " << m_req->m_ext_map
		       << " for " << m_req->m_buffer_extents
		       << " bl " << m_req->data().length() << dendl;
      m_completion->destriper.add_partial_sparse_result(m_req->data(),
							m_req->m_ext_map, m_req->m_object_off,
							m_req->m_buffer_extents);
      r = m_req->m_object_len;
    }
    m_completion->complete_request(m_cct, r);
  }

  void C_CacheRead::finish(int r)
  {
    m_completion->complete(r);
    delete m_req;
  }
}
