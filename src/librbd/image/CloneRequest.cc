// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "cls/rbd/cls_rbd_client.h"
#include "cls/rbd/cls_rbd_types.h"
#include "common/dout.h"
#include "common/errno.h"
#include "include/ceph_assert.h"
#include "librbd/ImageState.h"
#include "librbd/image/AttachParentRequest.h"
#include "librbd/image/CloneRequest.h"
#include "librbd/image/CreateRequest.h"
#include "librbd/image/RemoveRequest.h"
#include "librbd/image/RefreshRequest.h"
#include "librbd/mirror/EnableRequest.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::image::CloneRequest: " << this << " " \
                           << __func__ << ": "

#define MAX_KEYS 64

namespace librbd {
namespace image {

using util::create_rados_callback;
using util::create_context_callback;
using util::create_async_context_callback;

template <typename I>
CloneRequest<I>::CloneRequest(IoCtx& parent_io_ctx,
                              const std::string& parent_image_id,
                              const std::string& parent_snap_name,
                              uint64_t parent_snap_id,
                              IoCtx &c_ioctx,
			      const std::string &c_name,
			      const std::string &c_id,
			      ImageOptions c_options,
			      const std::string &non_primary_global_image_id,
			      const std::string &primary_mirror_uuid,
			      ContextWQ *op_work_queue, Context *on_finish)
  : m_parent_io_ctx(parent_io_ctx), m_parent_image_id(parent_image_id),
    m_parent_snap_name(parent_snap_name), m_parent_snap_id(parent_snap_id),
    m_ioctx(c_ioctx), m_name(c_name), m_id(c_id), m_opts(c_options),
    m_non_primary_global_image_id(non_primary_global_image_id),
    m_primary_mirror_uuid(primary_mirror_uuid),
    m_op_work_queue(op_work_queue), m_on_finish(on_finish),
    m_use_p_features(true) {

  m_cct = reinterpret_cast<CephContext *>(m_ioctx.cct());

  bool default_format_set;
  m_opts.is_set(RBD_IMAGE_OPTION_FORMAT, &default_format_set);
  if (!default_format_set) {
    m_opts.set(RBD_IMAGE_OPTION_FORMAT, static_cast<uint64_t>(2));
  }

  ldout(m_cct, 20) << "parent_pool_id=" << parent_io_ctx.get_id() << ", "
                   << "parent_image_id=" << parent_image_id << ", "
		   << "parent_snap=" << parent_snap_name << "/"
                   << parent_snap_id << " clone to "
                   << "pool_id=" << m_ioctx.get_id() << ", "
                   << "name=" << m_name << ", "
                   << "opts=" << m_opts << dendl;
}

template <typename I>
void CloneRequest<I>::send() {
  ldout(m_cct, 20) << dendl;
  validate_options();
}

template <typename I>
void CloneRequest<I>::validate_options() {
  ldout(m_cct, 20) << dendl;

  uint64_t format = 0;
  m_opts.get(RBD_IMAGE_OPTION_FORMAT, &format);
  if (format < 2) {
    lderr(m_cct) << "format 2 or later required for clone" << dendl;
    complete(-EINVAL);
    return;
  }

  if (m_opts.get(RBD_IMAGE_OPTION_FEATURES, &m_features) == 0) {
    if (m_features & ~RBD_FEATURES_ALL) {
      lderr(m_cct) << "librbd does not support requested features" << dendl;
      complete(-ENOSYS);
      return;
    }
    m_use_p_features = false;
  }

  std::string default_clone_format = m_cct->_conf.get_val<std::string>(
    "rbd_default_clone_format");
  if (default_clone_format == "1") {
    m_clone_format = 1;
  } else if (default_clone_format == "auto") {
    librados::Rados rados(m_ioctx);
    int8_t min_compat_client;
    int8_t require_min_compat_client;
    int r = rados.get_min_compatible_client(&min_compat_client,
                                            &require_min_compat_client);
    if (r < 0) {
      complete(r);
      return;
    }
    if (std::max(min_compat_client, require_min_compat_client) <
          CEPH_RELEASE_MIMIC) {
      m_clone_format = 1;
    }
  }

  if (m_clone_format == 1 &&
      m_parent_io_ctx.get_namespace() != m_ioctx.get_namespace()) {
    ldout(m_cct, 1) << "clone v2 required for cross-namespace clones" << dendl;
    complete(-EXDEV);
    return;
  }

  open_parent();
}

template <typename I>
void CloneRequest<I>::open_parent() {
  ldout(m_cct, 20) << dendl;
  ceph_assert(m_parent_snap_name.empty() ^ (m_parent_snap_id == CEPH_NOSNAP));

  if (m_parent_snap_id != CEPH_NOSNAP) {
    m_parent_image_ctx = I::create("", m_parent_image_id, m_parent_snap_id,
                                   m_parent_io_ctx, true);
  } else {
    m_parent_image_ctx = I::create("", m_parent_image_id,
                                   m_parent_snap_name.c_str(), m_parent_io_ctx,
                                   true);
  }

  Context *ctx = create_context_callback<
    CloneRequest<I>, &CloneRequest<I>::handle_open_parent>(this);
  m_parent_image_ctx->state->open(OPEN_FLAG_SKIP_OPEN_PARENT, ctx);
}

template <typename I>
void CloneRequest<I>::handle_open_parent(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    m_parent_image_ctx->destroy();
    m_parent_image_ctx = nullptr;

    lderr(m_cct) << "failed to open parent image: " << cpp_strerror(r) << dendl;
    complete(r);
    return;
  }

  m_parent_snap_id = m_parent_image_ctx->snap_id;
  m_pspec = {m_parent_io_ctx.get_id(), m_parent_io_ctx.get_namespace(),
             m_parent_image_id, m_parent_snap_id};
  validate_parent();
}

template <typename I>
void CloneRequest<I>::validate_parent() {
  ldout(m_cct, 20) << dendl;

  if (m_parent_image_ctx->operations_disabled) {
    lderr(m_cct) << "image operations disabled due to unsupported op features"
                 << dendl;
    m_r_saved = -EROFS;
    close_parent();
    return;
  }

  if (m_parent_image_ctx->snap_id == CEPH_NOSNAP) {
    lderr(m_cct) << "image to be cloned must be a snapshot" << dendl;
    m_r_saved = -EINVAL;
    close_parent();
    return;
  }

  if (m_parent_image_ctx->old_format) {
    lderr(m_cct) << "parent image must be in new format" << dendl;
    m_r_saved = -EINVAL;
    close_parent();
    return;
  }

  m_parent_image_ctx->snap_lock.get_read();
  uint64_t p_features = m_parent_image_ctx->features;
  m_size = m_parent_image_ctx->get_image_size(m_parent_image_ctx->snap_id);

  bool snap_protected;
  int r = m_parent_image_ctx->is_snap_protected(m_parent_image_ctx->snap_id, &snap_protected);
  m_parent_image_ctx->snap_lock.put_read();

  if ((p_features & RBD_FEATURE_LAYERING) != RBD_FEATURE_LAYERING) {
    lderr(m_cct) << "parent image must support layering" << dendl;
    m_r_saved = -ENOSYS;
    close_parent();
    return;
  }
  if (m_use_p_features) {
    m_features = (p_features & ~RBD_FEATURES_IMPLICIT_ENABLE);
  }

  if (r < 0) {
    lderr(m_cct) << "unable to locate parent's snapshot" << dendl;
    m_r_saved = r;
    close_parent();
    return;
  }

  if (m_clone_format == 1 && !snap_protected) {
    lderr(m_cct) << "parent snapshot must be protected" << dendl;
    m_r_saved = -EINVAL;
    close_parent();
    return;
  }

  validate_child();
}

template <typename I>
void CloneRequest<I>::validate_child() {
  ldout(m_cct, 20) << dendl;

  if ((m_features & RBD_FEATURE_LAYERING) != RBD_FEATURE_LAYERING) {
    lderr(m_cct) << "cloning image must support layering" << dendl;
    m_r_saved = -ENOSYS;
    close_parent();
    return;
  }

  using klass = CloneRequest<I>;
  librados::AioCompletion *comp = create_rados_callback<
    klass, &klass::handle_validate_child>(this);

  librados::ObjectReadOperation op;
  op.stat(NULL, NULL, NULL);

  int r = m_ioctx.aio_operate(util::old_header_name(m_name), comp, &op,
                              &m_out_bl);
  ceph_assert(r == 0);
  comp->release();
}

template <typename I>
void CloneRequest<I>::handle_validate_child(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r != -ENOENT) {
    lderr(m_cct) << "rbd image " << m_name << " already exists" << dendl;
    m_r_saved = r;
    close_parent();
    return;
  }

  create_child();
}

template <typename I>
void CloneRequest<I>::create_child() {
  ldout(m_cct, 20) << dendl;

  uint64_t order = m_parent_image_ctx->order;
  if (m_opts.get(RBD_IMAGE_OPTION_ORDER, &order) != 0) {
    m_opts.set(RBD_IMAGE_OPTION_ORDER, order);
  }
  m_opts.set(RBD_IMAGE_OPTION_FEATURES, m_features);

  using klass = CloneRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_create_child>(this);

  RWLock::RLocker snap_locker(m_parent_image_ctx->snap_lock);
  CreateRequest<I> *req = CreateRequest<I>::create(
    m_ioctx, m_name, m_id, m_size, m_opts, m_non_primary_global_image_id,
    m_primary_mirror_uuid, true, m_op_work_queue, ctx);
  req->send();
}

template <typename I>
void CloneRequest<I>::handle_create_child(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "error creating child: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    close_parent();
    return;
  }
  open_child();
}

template <typename I>
void CloneRequest<I>::open_child() {
  ldout(m_cct, 20) << dendl;

  m_imctx = I::create(m_name, "", nullptr, m_ioctx, false);

  using klass = CloneRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_open_child>(this);

  uint64_t flags = OPEN_FLAG_SKIP_OPEN_PARENT;
  if ((m_features & RBD_FEATURE_MIGRATING) != 0) {
    flags |= OPEN_FLAG_IGNORE_MIGRATING;
  }

  m_imctx->state->open(flags, ctx);
}

template <typename I>
void CloneRequest<I>::handle_open_child(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    m_imctx->destroy();
    m_imctx = nullptr;

    lderr(m_cct) << "Error opening new image: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    remove_child();
    return;
  }

  attach_parent();
}

template <typename I>
void CloneRequest<I>::attach_parent() {
  ldout(m_cct, 20) << dendl;

  auto ctx = create_context_callback<
    CloneRequest<I>, &CloneRequest<I>::handle_attach_parent>(this);
  auto req = AttachParentRequest<I>::create(
    *m_imctx, m_pspec, m_size, ctx);
  req->send();
}

template <typename I>
void CloneRequest<I>::handle_attach_parent(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to attach parent: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    close_child();
    return;
  }

  v2_set_op_feature();
}

template <typename I>
void CloneRequest<I>::v2_set_op_feature() {
  if (m_clone_format == 1) {
    v1_add_child();
    return;
  }

  ldout(m_cct, 20) << dendl;

  librados::ObjectWriteOperation op;
  cls_client::op_features_set(&op, RBD_OPERATION_FEATURE_CLONE_CHILD,
                              RBD_OPERATION_FEATURE_CLONE_CHILD);

  auto aio_comp = create_rados_callback<
    CloneRequest<I>, &CloneRequest<I>::handle_v2_set_op_feature>(this);
  int r = m_ioctx.aio_operate(m_imctx->header_oid, aio_comp, &op);
  ceph_assert(r == 0);
  aio_comp->release();
}

template <typename I>
void CloneRequest<I>::handle_v2_set_op_feature(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to enable clone v2: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    close_child();
    return;
  }

  v2_child_attach();
}

template <typename I>
void CloneRequest<I>::v2_child_attach() {
  ldout(m_cct, 20) << dendl;

  librados::ObjectWriteOperation op;
  cls_client::child_attach(&op, m_parent_image_ctx->snap_id,
                           {m_imctx->md_ctx.get_id(),
                            m_imctx->md_ctx.get_namespace(),
                            m_imctx->id});

  auto aio_comp = create_rados_callback<
    CloneRequest<I>, &CloneRequest<I>::handle_v2_child_attach>(this);
  int r = m_parent_image_ctx->md_ctx.aio_operate(m_parent_image_ctx->header_oid, aio_comp, &op);
  ceph_assert(r == 0);
  aio_comp->release();
}

template <typename I>
void CloneRequest<I>::handle_v2_child_attach(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to attach child image: " << cpp_strerror(r)
                 << dendl;
    m_r_saved = r;
    close_child();
    return;
  }

  metadata_list();
}

template <typename I>
void CloneRequest<I>::v1_add_child() {
  ldout(m_cct, 20) << dendl;

  librados::ObjectWriteOperation op;
  cls_client::add_child(&op, m_pspec, m_id);

  using klass = CloneRequest<I>;
  librados::AioCompletion *comp =
    create_rados_callback<klass, &klass::handle_v1_add_child>(this);
  int r = m_ioctx.aio_operate(RBD_CHILDREN, comp, &op);
  ceph_assert(r == 0);
  comp->release();
}

template <typename I>
void CloneRequest<I>::handle_v1_add_child(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "couldn't add child: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    close_child();
    return;
  }

  v1_refresh();
}

template <typename I>
void CloneRequest<I>::v1_refresh() {
  ldout(m_cct, 20) << dendl;

  using klass = CloneRequest<I>;
  RefreshRequest<I> *req = RefreshRequest<I>::create(
    *m_imctx, false, false,
    create_context_callback<klass, &klass::handle_v1_refresh>(this));
  req->send();
}

template <typename I>
void CloneRequest<I>::handle_v1_refresh(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  bool snap_protected = false;
  if (r == 0) {
    m_parent_image_ctx->snap_lock.get_read();
    r = m_parent_image_ctx->is_snap_protected(m_parent_image_ctx->snap_id, &snap_protected);
    m_parent_image_ctx->snap_lock.put_read();
  }

  if (r < 0 || !snap_protected) {
    m_r_saved = -EINVAL;
    close_child();
    return;
  }

  metadata_list();
}

template <typename I>
void CloneRequest<I>::metadata_list() {
  ldout(m_cct, 20) << ": "
                   << "start_key=" << m_last_metadata_key << dendl;

  librados::ObjectReadOperation op;
  cls_client::metadata_list_start(&op, m_last_metadata_key, 0);

  using klass = CloneRequest<I>;
  librados::AioCompletion *comp =
    create_rados_callback<klass, &klass::handle_metadata_list>(this);
  m_out_bl.clear();
  m_parent_image_ctx->md_ctx.aio_operate(m_parent_image_ctx->header_oid,
				comp, &op, &m_out_bl);
  comp->release();
}

template <typename I>
void CloneRequest<I>::handle_metadata_list(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  map<string, bufferlist> metadata;
  if (r == 0) {
    auto it = m_out_bl.cbegin();
    r = cls_client::metadata_list_finish(&it, &metadata);
  }

  if (r < 0) {
    if (r == -EOPNOTSUPP || r == -EIO) {
      ldout(m_cct, 10) << "config metadata not supported by OSD" << dendl;
      get_mirror_mode();
    } else {
      lderr(m_cct) << "couldn't list metadata: " << cpp_strerror(r) << dendl;
      m_r_saved = r;
      close_child();
    }
    return;
  }

  if (!metadata.empty()) {
    m_pairs.insert(metadata.begin(), metadata.end());
    m_last_metadata_key = m_pairs.rbegin()->first;
  }

  if (metadata.size() == MAX_KEYS) {
    metadata_list();
  } else {
    metadata_set();
  }
}

template <typename I>
void CloneRequest<I>::metadata_set() {
  if (m_pairs.empty()) {
    get_mirror_mode();
    return;
  }

  ldout(m_cct, 20) << dendl;

  librados::ObjectWriteOperation op;
  cls_client::metadata_set(&op, m_pairs);

  using klass = CloneRequest<I>;
  librados::AioCompletion *comp =
    create_rados_callback<klass, &klass::handle_metadata_set>(this);
  int r = m_ioctx.aio_operate(m_imctx->header_oid, comp, &op);
  ceph_assert(r == 0);
  comp->release();
}

template <typename I>
void CloneRequest<I>::handle_metadata_set(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "couldn't set metadata: " << cpp_strerror(r) << dendl;
    m_r_saved = r;
    close_child();
  } else {
    get_mirror_mode();
  }
}

template <typename I>
void CloneRequest<I>::get_mirror_mode() {
  ldout(m_cct, 20) << dendl;

  if (!m_imctx->test_features(RBD_FEATURE_JOURNALING)) {
    close_child();
    return;
  }

  librados::ObjectReadOperation op;
  cls_client::mirror_mode_get_start(&op);

  using klass = CloneRequest<I>;
  librados::AioCompletion *comp =
    create_rados_callback<klass, &klass::handle_get_mirror_mode>(this);
  m_out_bl.clear();
  m_imctx->md_ctx.aio_operate(RBD_MIRRORING,
			      comp, &op, &m_out_bl);
  comp->release();
}

template <typename I>
void CloneRequest<I>::handle_get_mirror_mode(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r == 0) {
    auto it = m_out_bl.cbegin();
    r = cls_client::mirror_mode_get_finish(&it, &m_mirror_mode);
  }

  if (r < 0 && r != -ENOENT) {
    lderr(m_cct) << "failed to retrieve mirror mode: " << cpp_strerror(r)
                 << dendl;

    m_r_saved = r;
    close_child();
  } else {
    if (m_mirror_mode == cls::rbd::MIRROR_MODE_POOL ||
	!m_non_primary_global_image_id.empty()) {
      enable_mirror();
    } else {
      close_child();
    }
  }
}

template <typename I>
void CloneRequest<I>::enable_mirror() {
  ldout(m_cct, 20) << dendl;

  using klass = CloneRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_enable_mirror>(this);

  mirror::EnableRequest<I> *req = mirror::EnableRequest<I>::create(
    m_imctx->md_ctx, m_id, m_non_primary_global_image_id,
    m_imctx->op_work_queue, ctx);
  req->send();
}

template <typename I>
void CloneRequest<I>::handle_enable_mirror(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to enable mirroring: " << cpp_strerror(r)
               << dendl;
    m_r_saved = r;
  }
  close_child();
}

template <typename I>
void CloneRequest<I>::close_child() {
  ldout(m_cct, 20) << dendl;

  ceph_assert(m_imctx != nullptr);

  using klass = CloneRequest<I>;
  Context *ctx = create_async_context_callback(
    *m_imctx, create_context_callback<
      klass, &klass::handle_close_child>(this));
  m_imctx->state->close(ctx);
}

template <typename I>
void CloneRequest<I>::handle_close_child(int r) {
  ldout(m_cct, 20) << dendl;

  m_imctx->destroy();
  m_imctx = nullptr;

  if (r < 0) {
    lderr(m_cct) << "couldn't close image: " << cpp_strerror(r) << dendl;
    if (m_r_saved == 0) {
      m_r_saved = r;
    }
  }

  if (m_r_saved < 0) {
    remove_child();
    return;
  }

  close_parent();
}

template <typename I>
void CloneRequest<I>::remove_child() {
  ldout(m_cct, 20) << dendl;

  using klass = CloneRequest<I>;
  Context *ctx = create_context_callback<
    klass, &klass::handle_remove_child>(this);

  auto req = librbd::image::RemoveRequest<I>::create(
   m_ioctx, m_name, m_id, false, false, m_no_op, m_op_work_queue, ctx);
  req->send();
}

template <typename I>
void CloneRequest<I>::handle_remove_child(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "Error removing failed clone: "
		 << cpp_strerror(r) << dendl;
  }

  close_parent();
}

template <typename I>
void CloneRequest<I>::close_parent() {
  ldout(m_cct, 20) << dendl;
  ceph_assert(m_parent_image_ctx != nullptr);

  Context *ctx = create_async_context_callback(
    *m_parent_image_ctx, create_context_callback<
      CloneRequest<I>, &CloneRequest<I>::handle_close_parent>(this));
  m_parent_image_ctx->state->close(ctx);
}

template <typename I>
void CloneRequest<I>::handle_close_parent(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  m_parent_image_ctx->destroy();
  m_parent_image_ctx = nullptr;

  if (r < 0) {
    lderr(m_cct) << "failed to close parent image: "
		 << cpp_strerror(r) << dendl;
    if (m_r_saved == 0) {
      m_r_saved = r;
    }
  }

  complete(m_r_saved);
}

template <typename I>
void CloneRequest<I>::complete(int r) {
  ldout(m_cct, 20) << "r=" << r << dendl;

  if (r == 0) {
    ldout(m_cct, 20) << "done." << dendl;
  }

  m_on_finish->complete(r);
  delete this;
}

} //namespace image
} //namespace librbd

template class librbd::image::CloneRequest<librbd::ImageCtx>;
