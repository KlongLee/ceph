// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "CreateImageRequest.h"
#include "CloseImageRequest.h"
#include "OpenImageRequest.h"
#include "common/debug.h"
#include "common/errno.h"
#include "common/WorkQueue.h"
#include "cls/rbd/cls_rbd_client.h"
#include "journal/Journaler.h"
#include "journal/Settings.h"
#include "librbd/ImageCtx.h"
#include "librbd/ImageState.h"
#include "librbd/internal.h"
#include "librbd/Utils.h"
#include "librbd/image/CreateRequest.h"
#include "librbd/image/CloneRequest.h"
#include "librbd/journal/Types.h"
#include "tools/rbd_mirror/Threads.h"
#include "tools/rbd_mirror/image_replayer/Utils.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd_mirror
#undef dout_prefix
#define dout_prefix *_dout << "rbd::mirror::image_replayer::CreateImageRequest: " \
                           << this << " " << __func__ << ": "

using librbd::util::create_async_context_callback;
using librbd::util::create_context_callback;
using librbd::util::create_rados_callback;

namespace rbd {
namespace mirror {
namespace image_replayer {

template <typename I>
CreateImageRequest<I>::CreateImageRequest(Threads<I>* threads,
                                          librados::IoCtx &local_io_ctx,
                                          const std::string &global_image_id,
                                          const std::string &remote_mirror_uuid,
                                          const std::string &local_image_name,
					  const std::string &local_image_id,
                                          I *remote_image_ctx,
                                          Context *on_finish)
  : m_threads(threads), m_local_io_ctx(local_io_ctx),
    m_global_image_id(global_image_id),
    m_remote_mirror_uuid(remote_mirror_uuid),
    m_local_image_name(local_image_name), m_local_image_id(local_image_id),
    m_remote_image_ctx(remote_image_ctx), m_on_finish(on_finish) {
}

template <typename I>
void CreateImageRequest<I>::send() {
  int r = validate_parent();
  if (r < 0) {
    error(r);
    return;
  }

  if (m_remote_parent_spec.pool_id == -1) {
    create_image();
  } else {
    get_local_parent_mirror_uuid();
  }
}

template <typename I>
void CreateImageRequest<I>::create_image() {
  dout(10) << dendl;

  using klass = CreateImageRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_create_image>(this);

  RWLock::RLocker image_locker(m_remote_image_ctx->image_lock);

  auto& config{
    reinterpret_cast<CephContext*>(m_local_io_ctx.cct())->_conf};

  librbd::ImageOptions image_options;
  populate_image_options(&image_options);

  auto req = librbd::image::CreateRequest<I>::create(
    config, m_local_io_ctx, m_local_image_name, m_local_image_id,
    m_remote_image_ctx->size, image_options, m_global_image_id,
    m_remote_mirror_uuid, false, m_remote_image_ctx->op_work_queue, ctx);
  req->send();
}

template <typename I>
void CreateImageRequest<I>::handle_create_image(int r) {
  dout(10) << "r=" << r << dendl;
  if (r == -EBADF) {
    dout(5) << "image id " << m_local_image_id << " already in-use" << dendl;
    finish(r);
    return;
  } else if (r < 0) {
    derr << "failed to create local image: " << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  finish(0);
}

template <typename I>
void CreateImageRequest<I>::get_local_parent_mirror_uuid() {
  dout(10) << dendl;

  librados::ObjectReadOperation op;
  librbd::cls_client::mirror_uuid_get_start(&op);

  librados::AioCompletion *aio_comp = create_rados_callback<
    CreateImageRequest<I>,
    &CreateImageRequest<I>::handle_get_local_parent_mirror_uuid>(this);
  m_out_bl.clear();
  int r = m_local_parent_io_ctx.aio_operate(RBD_MIRRORING, aio_comp, &op,
                                            &m_out_bl);
  ceph_assert(r == 0);
  aio_comp->release();
}

template <typename I>
void CreateImageRequest<I>::handle_get_local_parent_mirror_uuid(int r) {
  if (r >= 0) {
    auto it = m_out_bl.cbegin();
    r = librbd::cls_client::mirror_uuid_get_finish(
      &it, &m_local_parent_mirror_uuid);
    if (r >= 0 && m_local_parent_mirror_uuid.empty()) {
      r = -ENOENT;
    }
  }

  dout(10) << "r=" << r << dendl;
  if (r < 0) {
    if (r == -ENOENT) {
      dout(5) << "local parent mirror uuid missing" << dendl;
    } else {
      derr << "failed to retrieve local parent mirror uuid: " << cpp_strerror(r)
           << dendl;
    }
    finish(r);
    return;
  }

  dout(15) << "local_parent_mirror_uuid=" << m_local_parent_mirror_uuid
           << dendl;
  get_remote_parent_client_state();
}

template <typename I>
void CreateImageRequest<I>::get_remote_parent_client_state() {
  dout(10) << dendl;

  m_remote_journaler = new Journaler(m_threads->work_queue, m_threads->timer,
                                     &m_threads->timer_lock,
                                     m_remote_parent_io_ctx,
                                     m_remote_parent_spec.image_id,
                                     m_local_parent_mirror_uuid, {}, nullptr);

  Context *ctx = create_async_context_callback(
    m_threads->work_queue, create_context_callback<
      CreateImageRequest<I>,
      &CreateImageRequest<I>::handle_get_remote_parent_client_state>(this));
  m_remote_journaler->get_client(m_local_parent_mirror_uuid, &m_client, ctx);
}

template <typename I>
void CreateImageRequest<I>::handle_get_remote_parent_client_state(int r) {
  dout(10) << "r=" << r << dendl;

  delete m_remote_journaler;
  m_remote_journaler = nullptr;

  librbd::journal::MirrorPeerClientMeta mirror_peer_client_meta;
  if (r == -ENOENT) {
    dout(15) << "client not registered to parent image" << dendl;
    finish(r);
    return;
  } else if (r < 0) {
    derr << "failed to retrieve parent client: " << cpp_strerror(r) << dendl;
    finish(r);
    return;
  } else if (!util::decode_client_meta(m_client, &mirror_peer_client_meta)) {
    // require operator intervention since the data is corrupt
    derr << "failed to decode parent client: " << cpp_strerror(r) << dendl;
    finish(-EBADMSG);
    return;
  } else if (mirror_peer_client_meta.state !=
               librbd::journal::MIRROR_PEER_STATE_REPLAYING) {
    // avoid possible race w/ incomplete parent image since the parent snapshot
    // might be deleted if the sync restarts
    dout(15) << "parent image still syncing" << dendl;
    finish(-ENOENT);
    return;
  }

  get_parent_global_image_id();
}


template <typename I>
void CreateImageRequest<I>::get_parent_global_image_id() {
  dout(10) << dendl;

  librados::ObjectReadOperation op;
  librbd::cls_client::mirror_image_get_start(&op,
                                             m_remote_parent_spec.image_id);

  librados::AioCompletion *aio_comp = create_rados_callback<
    CreateImageRequest<I>,
    &CreateImageRequest<I>::handle_get_parent_global_image_id>(this);
  m_out_bl.clear();
  int r = m_remote_parent_io_ctx.aio_operate(RBD_MIRRORING, aio_comp, &op,
                                             &m_out_bl);
  ceph_assert(r == 0);
  aio_comp->release();
}

template <typename I>
void CreateImageRequest<I>::handle_get_parent_global_image_id(int r) {
  dout(10) << "r=" << r << dendl;
  if (r == 0) {
    cls::rbd::MirrorImage mirror_image;
    auto iter = m_out_bl.cbegin();
    r = librbd::cls_client::mirror_image_get_finish(&iter, &mirror_image);
    if (r == 0) {
      m_parent_global_image_id = mirror_image.global_image_id;
      dout(15) << "parent_global_image_id=" << m_parent_global_image_id
               << dendl;
    }
  }

  if (r == -ENOENT) {
    dout(10) << "parent image " << m_remote_parent_spec.image_id
             << " not mirrored" << dendl;
    finish(r);
    return;
  } else if (r < 0) {
    derr << "failed to retrieve global image id for parent image "
         << m_remote_parent_spec.image_id << ": " << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  get_local_parent_image_id();
}

template <typename I>
void CreateImageRequest<I>::get_local_parent_image_id() {
  dout(10) << dendl;

  librados::ObjectReadOperation op;
  librbd::cls_client::mirror_image_get_image_id_start(
    &op, m_parent_global_image_id);

  librados::AioCompletion *aio_comp = create_rados_callback<
    CreateImageRequest<I>,
    &CreateImageRequest<I>::handle_get_local_parent_image_id>(this);
  m_out_bl.clear();
  int r = m_local_parent_io_ctx.aio_operate(RBD_MIRRORING, aio_comp, &op,
                                            &m_out_bl);
  ceph_assert(r == 0);
  aio_comp->release();
}

template <typename I>
void CreateImageRequest<I>::handle_get_local_parent_image_id(int r) {
  dout(10) << "r=" << r << dendl;

  if (r == 0) {
    auto iter = m_out_bl.cbegin();
    r = librbd::cls_client::mirror_image_get_image_id_finish(
      &iter, &m_local_parent_spec.image_id);
  }

  if (r == -ENOENT) {
    dout(10) << "parent image " << m_parent_global_image_id << " not "
             << "registered locally" << dendl;
    finish(r);
    return;
  } else if (r < 0) {
    derr << "failed to retrieve local image id for parent image "
         << m_parent_global_image_id << ": " << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  open_remote_parent_image();
}

template <typename I>
void CreateImageRequest<I>::open_remote_parent_image() {
  dout(10) << dendl;

  Context *ctx = create_context_callback<
    CreateImageRequest<I>,
    &CreateImageRequest<I>::handle_open_remote_parent_image>(this);
  OpenImageRequest<I> *request = OpenImageRequest<I>::create(
    m_remote_parent_io_ctx, &m_remote_parent_image_ctx,
    m_remote_parent_spec.image_id, true, ctx);
  request->send();
}

template <typename I>
void CreateImageRequest<I>::handle_open_remote_parent_image(int r) {
  dout(10) << "r=" << r << dendl;
  if (r < 0) {
    derr << "failed to open remote parent image " << m_parent_pool_name << "/"
         << m_remote_parent_spec.image_id << dendl;
    finish(r);
    return;
  }

  clone_image();
}

template <typename I>
void CreateImageRequest<I>::clone_image() {
  dout(10) << dendl;

  std::string snap_name;
  cls::rbd::SnapshotNamespace snap_namespace;
  {
    RWLock::RLocker remote_image_locker(m_remote_parent_image_ctx->image_lock);
    auto it = m_remote_parent_image_ctx->snap_info.find(
      m_remote_parent_spec.snap_id);
    if (it != m_remote_parent_image_ctx->snap_info.end()) {
      snap_name = it->second.name;
      snap_namespace = it->second.snap_namespace;
    }
  }

  librbd::ImageOptions opts;
  populate_image_options(&opts);

  auto& config{
    reinterpret_cast<CephContext*>(m_local_io_ctx.cct())->_conf};

  using klass = CreateImageRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_clone_image>(this);

  librbd::image::CloneRequest<I> *req = librbd::image::CloneRequest<I>::create(
    config, m_local_parent_io_ctx, m_local_parent_spec.image_id, snap_name,
    CEPH_NOSNAP, m_local_io_ctx, m_local_image_name, m_local_image_id, opts,
    m_global_image_id, m_remote_mirror_uuid, m_remote_image_ctx->op_work_queue,
    ctx);
  req->send();
}

template <typename I>
void CreateImageRequest<I>::handle_clone_image(int r) {
  dout(10) << "r=" << r << dendl;
  if (r == -EBADF) {
    dout(5) << "image id " << m_local_image_id << " already in-use" << dendl;
    finish(r);
    return;
  } else if (r < 0) {
    derr << "failed to clone image " << m_parent_pool_name << "/"
         << m_remote_parent_spec.image_id << " to "
         << m_local_image_name << dendl;
    m_ret_val = r;
  }

  close_remote_parent_image();
}

template <typename I>
void CreateImageRequest<I>::close_remote_parent_image() {
  dout(10) << dendl;
  Context *ctx = create_context_callback<
    CreateImageRequest<I>,
    &CreateImageRequest<I>::handle_close_remote_parent_image>(this);
  CloseImageRequest<I> *request = CloseImageRequest<I>::create(
    &m_remote_parent_image_ctx, ctx);
  request->send();
}

template <typename I>
void CreateImageRequest<I>::handle_close_remote_parent_image(int r) {
  dout(10) << "r=" << r << dendl;
  if (r < 0) {
    derr << "error encountered closing remote parent image: "
         << cpp_strerror(r) << dendl;
  }

  finish(m_ret_val);
}

template <typename I>
void CreateImageRequest<I>::error(int r) {
  dout(10) << "r=" << r << dendl;

  m_threads->work_queue->queue(create_context_callback<
    CreateImageRequest<I>, &CreateImageRequest<I>::finish>(this), r);
}

template <typename I>
void CreateImageRequest<I>::finish(int r) {
  dout(10) << "r=" << r << dendl;
  m_on_finish->complete(r);
  delete this;
}

template <typename I>
int CreateImageRequest<I>::validate_parent() {
  RWLock::RLocker owner_locker(m_remote_image_ctx->owner_lock);
  RWLock::RLocker image_locker(m_remote_image_ctx->image_lock);

  m_remote_parent_spec = m_remote_image_ctx->parent_md.spec;

  // scan all remote snapshots for a linked parent
  for (auto &snap_info_pair : m_remote_image_ctx->snap_info) {
    auto &parent_spec = snap_info_pair.second.parent.spec;
    if (parent_spec.pool_id == -1) {
      continue;
    } else if (m_remote_parent_spec.pool_id == -1) {
      m_remote_parent_spec = parent_spec;
      continue;
    }

    if (m_remote_parent_spec != parent_spec) {
      derr << "remote image parent spec mismatch" << dendl;
      return -EINVAL;
    }
  }

  if (m_remote_parent_spec.pool_id == -1) {
    return 0;
  }

  // map remote parent pool to local parent pool
  librados::Rados remote_rados(m_remote_image_ctx->md_ctx);
  int r = remote_rados.ioctx_create2(m_remote_parent_spec.pool_id,
                                     m_remote_parent_io_ctx);
  if (r < 0) {
    derr << "failed to open remote parent pool " << m_remote_parent_spec.pool_id
         << ": " << cpp_strerror(r) << dendl;
    return r;
  }

  m_parent_pool_name = m_remote_parent_io_ctx.get_pool_name();

  librados::Rados local_rados(m_local_io_ctx);
  r = local_rados.ioctx_create(m_parent_pool_name.c_str(),
                               m_local_parent_io_ctx);
  if (r < 0) {
    derr << "failed to open local parent pool " << m_parent_pool_name << ": "
         << cpp_strerror(r) << dendl;
    return r;
  }

  return 0;
}

template <typename I>
void CreateImageRequest<I>::populate_image_options(
    librbd::ImageOptions* image_options) {
  image_options->set(RBD_IMAGE_OPTION_FEATURES,
                     (m_remote_image_ctx->features &
                        ~RBD_FEATURES_IMPLICIT_ENABLE));
  image_options->set(RBD_IMAGE_OPTION_ORDER, m_remote_image_ctx->order);
  image_options->set(RBD_IMAGE_OPTION_STRIPE_UNIT,
                     m_remote_image_ctx->stripe_unit);
  image_options->set(RBD_IMAGE_OPTION_STRIPE_COUNT,
                     m_remote_image_ctx->stripe_count);

  // Determine the data pool for the local image as follows:
  // 1. If the local pool has a default data pool, use it.
  // 2. If the remote image has a data pool different from its metadata pool and
  //    a pool with the same name exists locally, use it.
  // 3. Don't set the data pool explicitly.
  std::string data_pool;
  librados::Rados local_rados(m_local_io_ctx);
  auto default_data_pool = g_ceph_context->_conf.get_val<std::string>("rbd_default_data_pool");
  auto remote_md_pool = m_remote_image_ctx->md_ctx.get_pool_name();
  auto remote_data_pool = m_remote_image_ctx->data_ctx.get_pool_name();

  if (default_data_pool != "") {
    data_pool = default_data_pool;
  } else if (remote_data_pool != remote_md_pool) {
    if (local_rados.pool_lookup(remote_data_pool.c_str()) >= 0) {
      data_pool = remote_data_pool;
    }
  }

  if (data_pool != "") {
    image_options->set(RBD_IMAGE_OPTION_DATA_POOL, data_pool);
  }
}

} // namespace image_replayer
} // namespace mirror
} // namespace rbd

template class rbd::mirror::image_replayer::CreateImageRequest<librbd::ImageCtx>;
