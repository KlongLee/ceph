// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/api/Mirror.h"
#include "include/rados/librados.hpp"
#include "include/stringify.h"
#include "common/ceph_json.h"
#include "common/dout.h"
#include "common/errno.h"
#include "cls/rbd/cls_rbd_client.h"
#include "librbd/AsioEngine.h"
#include "librbd/ImageCtx.h"
#include "librbd/ImageState.h"
#include "librbd/Journal.h"
#include "librbd/MirroringWatcher.h"
#include "librbd/Operations.h"
#include "librbd/Utils.h"
#include "librbd/api/Group.h"
#include "librbd/api/Image.h"
#include "librbd/api/Namespace.h"
#include "librbd/api/Utils.h"
#include "librbd/group/ListSnapshotsRequest.h"
#include "librbd/mirror/DemoteRequest.h"
#include "librbd/mirror/DisableRequest.h"
#include "librbd/mirror/EnableRequest.h"
#include "librbd/mirror/GetInfoRequest.h"
#include "librbd/mirror/GetStatusRequest.h"
#include "librbd/mirror/GetUuidRequest.h"
#include "librbd/mirror/PromoteRequest.h"
#include "librbd/mirror/Types.h"
#include "librbd/MirroringWatcher.h"
#include "librbd/mirror/snapshot/CreatePrimaryRequest.h"
#include "librbd/mirror/snapshot/ImageMeta.h"
#include "librbd/mirror/snapshot/UnlinkPeerRequest.h"
#include "librbd/mirror/snapshot/Utils.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/scope_exit.hpp>
#include "json_spirit/json_spirit.h"

#include <algorithm>

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::api::Mirror: " << __func__ << ": "

namespace librbd {
namespace api {

namespace {

int get_config_key(librados::Rados& rados, const std::string& key,
                   std::string* value) {
  std::string cmd =
    "{"
      "\"prefix\": \"config-key get\", "
      "\"key\": \"" + key + "\""
    "}";

  bufferlist in_bl;
  bufferlist out_bl;

  int r = rados.mon_command(cmd, in_bl, &out_bl, nullptr);
  if (r == -EINVAL) {
    return -EOPNOTSUPP;
  } else if (r < 0 && r != -ENOENT) {
    return r;
  }

  *value = out_bl.to_str();
  return 0;
}

int set_config_key(librados::Rados& rados, const std::string& key,
                   const std::string& value) {
  std::string cmd;
  if (value.empty()) {
    cmd = "{"
            "\"prefix\": \"config-key rm\", "
            "\"key\": \"" + key + "\""
          "}";
  } else {
    cmd = "{"
            "\"prefix\": \"config-key set\", "
            "\"key\": \"" + key + "\", "
            "\"val\": \"" + value + "\""
          "}";
  }
  bufferlist in_bl;
  bufferlist out_bl;

  int r = rados.mon_command(cmd, in_bl, &out_bl, nullptr);
  if (r == -EINVAL) {
    return -EOPNOTSUPP;
  } else if (r < 0) {
    return r;
  }

  return 0;
}

std::string get_peer_config_key_name(int64_t pool_id,
                                     const std::string& peer_uuid) {
  return RBD_MIRROR_PEER_CONFIG_KEY_PREFIX + stringify(pool_id) + "/" +
           peer_uuid;
}

int remove_peer_config_key(librados::IoCtx& io_ctx,
                           const std::string& peer_uuid) {
  int64_t pool_id = io_ctx.get_id();
  auto key = get_peer_config_key_name(pool_id, peer_uuid);

  librados::Rados rados(io_ctx);
  int r = set_config_key(rados, key, "");
  if (r < 0 && r != -ENOENT && r != -EPERM) {
    return r;
  }
  return 0;
}

int create_bootstrap_user(CephContext* cct, librados::Rados& rados,
                          std::string* peer_client_id, std::string* cephx_key) {
  ldout(cct, 20) << dendl;

  // retrieve peer CephX user from config-key
  int r = get_config_key(rados, RBD_MIRROR_PEER_CLIENT_ID_CONFIG_KEY,
                         peer_client_id);
  if (r == -EACCES) {
      ldout(cct, 5) << "insufficient permissions to get peer-client-id "
                    << "config-key" << dendl;
      return r;
  } else if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve peer client id key: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (r == -ENOENT || peer_client_id->empty()) {
    ldout(cct, 20) << "creating new peer-client-id config-key" << dendl;

    *peer_client_id = "rbd-mirror-peer";
    r = set_config_key(rados, RBD_MIRROR_PEER_CLIENT_ID_CONFIG_KEY,
                       *peer_client_id);
    if (r == -EACCES) {
      ldout(cct, 5) << "insufficient permissions to update peer-client-id "
                    << "config-key" << dendl;
      return r;
    } else if (r < 0) {
      lderr(cct) << "failed to update peer client id key: "
                 << cpp_strerror(r) << dendl;
      return r;
    }
  }
  ldout(cct, 20) << "peer_client_id=" << *peer_client_id << dendl;

  // create peer client user
  std::string cmd =
    R"({)" \
    R"(  "prefix": "auth get-or-create",)" \
    R"(  "entity": "client.)" + *peer_client_id + R"(",)" \
    R"(  "caps": [)" \
    R"(    "mon", "profile rbd-mirror-peer",)" \
    R"(    "osd", "profile rbd"],)" \
    R"(  "format": "json")" \
    R"(})";

  bufferlist in_bl;
  bufferlist out_bl;

  r = rados.mon_command(cmd, in_bl, &out_bl, nullptr);
  if (r == -EINVAL) {
    ldout(cct, 5) << "caps mismatch for existing user" << dendl;
    return -EEXIST;
  } else if (r == -EACCES) {
    ldout(cct, 5) << "insufficient permissions to create user" << dendl;
    return r;
  } else if (r < 0) {
    lderr(cct) << "failed to create or update RBD mirroring bootstrap user: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  // extract key from response
  bool json_valid = false;
  json_spirit::mValue json_root;
  if(json_spirit::read(out_bl.to_str(), json_root)) {
    try {
      auto& json_obj = json_root.get_array()[0].get_obj();
      *cephx_key = json_obj["key"].get_str();
      json_valid = true;
    } catch (std::runtime_error&) {
    }
  }

  if (!json_valid) {
    lderr(cct) << "invalid auth keyring JSON received" << dendl;
    return -EBADMSG;
  }

  return 0;
}

int create_bootstrap_peer(CephContext* cct, librados::IoCtx& io_ctx,
                          mirror_peer_direction_t direction,
                          const std::string& site_name, const std::string& fsid,
                          const std::string& client_id, const std::string& key,
                          const std::string& mon_host,
                          const std::string& cluster1,
                          const std::string& cluster2) {
  ldout(cct, 20) << dendl;

  std::string peer_uuid;
  std::vector<mirror_peer_site_t> peers;
  int r = Mirror<>::peer_site_list(io_ctx, &peers);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  if (peers.empty()) {
    r = Mirror<>::peer_site_add(io_ctx, &peer_uuid, direction, site_name,
                                "client." + client_id);
    if (r < 0) {
      lderr(cct) << "failed to add " << cluster1 << " peer to "
                 << cluster2 << " " << "cluster: " << cpp_strerror(r) << dendl;
      return r;
    }
  } else if (peers[0].site_name != site_name &&
             peers[0].site_name != fsid) {
    // only support a single peer
    lderr(cct) << "multiple peers are not currently supported" << dendl;
    return -EINVAL;
  } else {
    peer_uuid = peers[0].uuid;

    if (peers[0].site_name != site_name) {
      r = Mirror<>::peer_site_set_name(io_ctx, peer_uuid, site_name);
      if (r < 0) {
        // non-fatal attempt to update site name
        lderr(cct) << "failed to update peer site name" << dendl;
      }
    }
  }

  Mirror<>::Attributes attributes {
    {"mon_host", mon_host},
    {"key", key}};
  r = Mirror<>::peer_site_set_attributes(io_ctx, peer_uuid, attributes);
  if (r < 0) {
    lderr(cct) << "failed to update " << cluster1 << " cluster connection "
               << "attributes in " << cluster2 << " cluster: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  return 0;
}

int list_mirror_images(librados::IoCtx& io_ctx,
                       std::set<std::string>& mirror_image_ids) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());

  std::string last_read = "";
  int max_read = 1024;
  int r;
  do {
    std::map<std::string, std::string> mirror_images;
    r =  cls_client::mirror_image_list(&io_ctx, last_read, max_read, true /* XXXMG */,
                                       &mirror_images);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "error listing mirrored image directory: "
                 << cpp_strerror(r) << dendl;
      return r;
    }
    for (auto it = mirror_images.begin(); it != mirror_images.end(); ++it) {
      mirror_image_ids.insert(it->first);
    }
    if (!mirror_images.empty()) {
      last_read = mirror_images.rbegin()->first;
    }
    r = mirror_images.size();
  } while (r == max_read);

  return 0;
}

struct C_ImageGetInfo : public Context {
  mirror_image_info_t *mirror_image_info;
  mirror_image_mode_t *mirror_image_mode;
  Context *on_finish;

  cls::rbd::MirrorImage mirror_image;
  mirror::PromotionState promotion_state = mirror::PROMOTION_STATE_PRIMARY;
  std::string primary_mirror_uuid;

  C_ImageGetInfo(mirror_image_info_t *mirror_image_info,
                 mirror_image_mode_t *mirror_image_mode,  Context *on_finish)
    : mirror_image_info(mirror_image_info),
      mirror_image_mode(mirror_image_mode), on_finish(on_finish) {
  }

  void finish(int r) override {
    if (r < 0 && r != -ENOENT) {
      on_finish->complete(r);
      return;
    }

    if (mirror_image_info != nullptr) {
      mirror_image_info->global_id = mirror_image.global_image_id;
      mirror_image_info->state = static_cast<rbd_mirror_image_state_t>(
        mirror_image.state);
      mirror_image_info->primary = (
        promotion_state == mirror::PROMOTION_STATE_PRIMARY);
    }

    if (mirror_image_mode != nullptr) {
      *mirror_image_mode =
        static_cast<rbd_mirror_image_mode_t>(mirror_image.mode);
    }

    on_finish->complete(0);
  }
};

struct C_ImageGetGlobalStatus : public C_ImageGetInfo {
  std::string image_name;
  mirror_image_global_status_t *mirror_image_global_status;

  cls::rbd::MirrorImageStatus mirror_image_status_internal;

  C_ImageGetGlobalStatus(
      const std::string &image_name,
      mirror_image_global_status_t *mirror_image_global_status,
      Context *on_finish)
    : C_ImageGetInfo(&mirror_image_global_status->info, nullptr, on_finish),
      image_name(image_name),
      mirror_image_global_status(mirror_image_global_status) {
  }

  void finish(int r) override {
    if (r < 0 && r != -ENOENT) {
      on_finish->complete(r);
      return;
    }

    mirror_image_global_status->name = image_name;
    mirror_image_global_status->site_statuses.clear();
    mirror_image_global_status->site_statuses.reserve(
      mirror_image_status_internal.mirror_image_site_statuses.size());
    for (auto& site_status :
           mirror_image_status_internal.mirror_image_site_statuses) {
      mirror_image_global_status->site_statuses.push_back({
        site_status.mirror_uuid,
        static_cast<mirror_image_status_state_t>(site_status.state),
        site_status.description, site_status.last_update.sec(),
        site_status.up});
    }
    C_ImageGetInfo::finish(0);
  }
};

template <typename I>
struct C_ImageSnapshotCreate : public Context {
  I *ictx;
  uint64_t snap_create_flags;
  int64_t group_pool_id;
  std::string group_id;
  std::string group_snap_id;
  uint64_t *snap_id;
  Context *on_finish;

  cls::rbd::MirrorImage mirror_image;
  mirror::PromotionState promotion_state;
  std::string primary_mirror_uuid;

  C_ImageSnapshotCreate(I *ictx, uint64_t snap_create_flags,
                        int64_t group_pool_id,
                        const std::string &group_id,
                        const std::string &group_snap_id,
                        uint64_t *snap_id,
                        Context *on_finish)
    : ictx(ictx), snap_create_flags(snap_create_flags),
      group_pool_id(group_pool_id), group_id(group_id),
      group_snap_id(group_snap_id), snap_id(snap_id),
      on_finish(on_finish) {
  }

  void finish(int r) override {
    if (r < 0 && r != -ENOENT) {
      on_finish->complete(r);
      return;
    }

    if (mirror_image.mode != cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT ||
        mirror_image.state != cls::rbd::MIRROR_IMAGE_STATE_ENABLED) {
      lderr(ictx->cct) << "snapshot based mirroring is not enabled" << dendl;
      on_finish->complete(-EINVAL);
      return;
    }

    auto req = mirror::snapshot::CreatePrimaryRequest<I>::create(
      ictx, mirror_image.global_image_id, CEPH_NOSNAP, snap_create_flags, 0U,
      group_pool_id, group_id, group_snap_id, snap_id, on_finish);
    req->send();
  }
};

int group_image_list_by_id(librados::IoCtx& group_ioctx,
                           const std::string &group_id,
                           std::vector<cls::rbd::GroupImageStatus> *image_ids) {
  CephContext *cct = (CephContext *)group_ioctx.cct();

  std::string group_header_oid = librbd::util::group_header_name(group_id);

  ldout(cct, 20) << "listing images in group id " << group_header_oid << dendl;
  image_ids->clear();

  int r = 0;
  const int max_read = 1024;
  cls::rbd::GroupImageSpec start_last;
  do {
    std::vector<cls::rbd::GroupImageStatus> image_ids_page;

    r = cls_client::group_image_list(&group_ioctx, group_header_oid,
                                     start_last, max_read, &image_ids_page);

    if (r < 0) {
      lderr(cct) << "error reading image list from group: "
	<< cpp_strerror(-r) << dendl;
      return r;
    }
    image_ids->insert(image_ids->end(),
		     image_ids_page.begin(), image_ids_page.end());

    if (image_ids_page.size() > 0)
      start_last = image_ids_page.rbegin()->spec;

    r = image_ids_page.size();
  } while (r == max_read);

  return 0;
}

template <typename I>
void close_images(std::vector<I *> *image_ctxs) {
  std::vector<C_SaferCond> on_finishes(image_ctxs->size());

  for (size_t i = 0; i < image_ctxs->size(); i++) {
    (*image_ctxs)[i]->state->close(&on_finishes[i]);
  }

  for (auto &on_finish : on_finishes) {
    on_finish.wait();
  }

  image_ctxs->clear();
}

template <typename I>
int open_group_images(IoCtx& group_ioctx, const std::string &group_id,
                      std::vector<I *> *image_ctxs) {
  std::vector<cls::rbd::GroupImageStatus> images;
  int r = group_image_list_by_id(group_ioctx, group_id, &images);
  if (r < 0) {
    return r;
  }

  std::vector<C_SaferCond> on_finishes(images.size());
  int ret_code = 0;
  size_t i = 0;
  for ( ; i < images.size(); i++) {
    auto &image = images[i];
    librbd::IoCtx image_io_ctx;
    r = librbd::util::create_ioctx(group_ioctx, "image", image.spec.pool_id, {},
                                   &image_io_ctx);
    if (r < 0) {
      ret_code = r;
      break;
    }

    librbd::ImageCtx* image_ctx = new ImageCtx("", image.spec.image_id.c_str(),
					       nullptr, image_io_ctx, false);

    image_ctx->state->open(0, &on_finishes[i]);

    image_ctxs->push_back(image_ctx);
  }

  for (size_t j = 0; j < i; j++) {
    r = on_finishes[j].wait();
    if (r < 0 && ret_code == 0) {
      ret_code = r;
    }
  }

  if (ret_code != 0) {
    close_images(image_ctxs);
    return ret_code;
  }

  return 0;
}

std::string calc_ind_mirror_snap_name(uint64_t pool_id,
                                      const std::string &group_id,
                                      const std::string &snap_id) {
  std::stringstream ind_snap_name_stream;
  ind_snap_name_stream << ".mirror." << std::hex << pool_id << "_"
                       << group_id << "_" << snap_id;
  return ind_snap_name_stream.str();
}

int get_last_mirror_snapshot_state(librados::IoCtx &group_ioctx,
                                   const std::string &group_id,
                                   cls::rbd::MirrorSnapshotState *state) {
  std::vector<cls::rbd::GroupSnapshot> snaps;

  C_SaferCond cond;
  auto req = group::ListSnapshotsRequest<>::create(group_ioctx, group_id,
                                                   &snaps, &cond);
  req->send();
  int r = cond.wait();
  if (r < 0) {
    return r;
  }

  for (auto it = snaps.rbegin(); it != snaps.rend(); it++) {
    auto ns = boost::get<cls::rbd::MirrorGroupSnapshotNamespace>(
        &it->snapshot_namespace);
    if (ns != nullptr) {
      // XXXMG: check primary_mirror_uuid matches?
      *state = ns->state;
      return 0;
    }
  }

  return -ENOENT;
}

} // anonymous namespace

template <typename I>
int Mirror<I>::image_enable(I *ictx, mirror_image_mode_t mode,
                            bool relax_same_pool_parent_check) {
  return Mirror<I>::image_enable(ictx, -1, {}, {}, mode,
                                 relax_same_pool_parent_check, nullptr);
}

template <typename I>
int Mirror<I>::image_enable(I *ictx, int64_t group_pool_id,
                            const std::string &group_id,
                            const std::string &group_snap_id,
                            mirror_image_mode_t mode,
                            bool relax_same_pool_parent_check,
                            uint64_t *snap_id) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << " mode=" << mode
                 << "group_snap=(" << group_pool_id << " "
                 << group_id << " " << group_snap_id << ")"
                 << " relax_same_pool_parent_check="
                 << relax_same_pool_parent_check <<  dendl;

  int r = ictx->state->refresh_if_required();
  if (r < 0) {
    return r;
  }

  cls::rbd::MirrorMode mirror_mode;
  r = cls_client::mirror_mode_get(&ictx->md_ctx, &mirror_mode);
  if (r < 0) {
    lderr(cct) << "cannot enable mirroring: failed to retrieve mirror mode: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  if (mirror_mode != cls::rbd::MIRROR_MODE_IMAGE) {
    lderr(cct) << "cannot enable mirroring in the current pool mirroring mode"
               << dendl;
    return -EINVAL;
  }

  // is mirroring not enabled for the parent?
  {
    std::shared_lock image_locker{ictx->image_lock};
    ImageCtx *parent = ictx->parent;
    if (parent) {
      if (parent->md_ctx.get_id() != ictx->md_ctx.get_id() ||
          !relax_same_pool_parent_check) {
        cls::rbd::MirrorImage mirror_image_internal;
        r = cls_client::mirror_image_get(&(parent->md_ctx), parent->id,
                                         &mirror_image_internal);
        if (r == -ENOENT) {
          lderr(cct) << "mirroring is not enabled for the parent" << dendl;
          return -EINVAL;
        }
      }
    }
  }

  if (mode == RBD_MIRROR_IMAGE_MODE_JOURNAL &&
      !ictx->test_features(RBD_FEATURE_JOURNALING)) {
    uint64_t features = RBD_FEATURE_JOURNALING;
    if (!ictx->test_features(RBD_FEATURE_EXCLUSIVE_LOCK)) {
      features |= RBD_FEATURE_EXCLUSIVE_LOCK;
    }
    r = ictx->operations->update_features(features, true);
    if (r < 0) {
      lderr(cct) << "cannot enable journaling: " << cpp_strerror(r) << dendl;
      return r;
    }
  }

  C_SaferCond ctx;
  auto req = mirror::EnableRequest<ImageCtx>::create(
      ictx, static_cast<cls::rbd::MirrorImageMode>(mode), "", false,
      group_pool_id, group_id, group_snap_id, snap_id, &ctx);
  req->send();

  r = ctx.wait();
  if (r < 0) {
    lderr(cct) << "cannot enable mirroring: " << cpp_strerror(r) << dendl;
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_disable(I *ictx, bool force) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  int r = ictx->state->refresh_if_required();
  if (r < 0) {
    return r;
  }

  cls::rbd::MirrorMode mirror_mode;
  r = cls_client::mirror_mode_get(&ictx->md_ctx, &mirror_mode);
  if (r < 0) {
    lderr(cct) << "cannot disable mirroring: failed to retrieve pool "
      "mirroring mode: " << cpp_strerror(r) << dendl;
    return r;
  }

  if (mirror_mode != cls::rbd::MIRROR_MODE_IMAGE) {
    lderr(cct) << "cannot disable mirroring in the current pool mirroring "
      "mode" << dendl;
    return -EINVAL;
  }

  // is mirroring  enabled for the image?
  cls::rbd::MirrorImage mirror_image_internal;
  r = cls_client::mirror_image_get(&ictx->md_ctx, ictx->id,
                                   &mirror_image_internal);
  if (r == -ENOENT) {
    // mirroring is not enabled for this image
    ldout(cct, 20) << "ignoring disable command: mirroring is not enabled for "
                   << "this image" << dendl;
    return 0;
  } else if (r == -EOPNOTSUPP) {
    ldout(cct, 5) << "mirroring not supported by OSD" << dendl;
    return r;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror image metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  mirror_image_internal.state = cls::rbd::MIRROR_IMAGE_STATE_DISABLING;
  r = cls_client::mirror_image_set(&ictx->md_ctx, ictx->id,
                                   mirror_image_internal);
  if (r < 0) {
    lderr(cct) << "cannot disable mirroring: " << cpp_strerror(r) << dendl;
    return r;
  }

  bool rollback = false;
  BOOST_SCOPE_EXIT_ALL(ictx, &mirror_image_internal, &rollback) {
    if (rollback) {
      // restore the mask bit for treating the non-primary feature as read-only
      ictx->image_lock.lock();
      ictx->read_only_mask |= IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
      ictx->image_lock.unlock();

      ictx->state->handle_update_notification();

      // attempt to restore the image state
      CephContext *cct = ictx->cct;
      mirror_image_internal.state = cls::rbd::MIRROR_IMAGE_STATE_ENABLED;
      int r = cls_client::mirror_image_set(&ictx->md_ctx, ictx->id,
                                           mirror_image_internal);
      if (r < 0) {
        lderr(cct) << "failed to re-enable image mirroring: "
                   << cpp_strerror(r) << dendl;
      }
    }
  };

  std::unique_lock image_locker{ictx->image_lock};
  std::map<librados::snap_t, SnapInfo> snap_info = ictx->snap_info;
  for (auto &info : snap_info) {
    cls::rbd::ParentImageSpec parent_spec{ictx->md_ctx.get_id(),
                                          ictx->md_ctx.get_namespace(),
                                          ictx->id, info.first};
    std::vector<librbd::linked_image_spec_t> child_images;
    r = Image<I>::list_children(ictx, parent_spec, &child_images);
    if (r < 0) {
      rollback = true;
      return r;
    }

    if (child_images.empty()) {
      continue;
    }

    librados::IoCtx child_io_ctx;
    int64_t child_pool_id = -1;
    for (auto &child_image : child_images){
      std::string pool = child_image.pool_name;
      if (child_pool_id == -1 ||
          child_pool_id != child_image.pool_id ||
          child_io_ctx.get_namespace() != child_image.pool_namespace) {
        r = librbd::util::create_ioctx(ictx->md_ctx, "child image",
                                       child_image.pool_id,
                                       child_image.pool_namespace,
                                       &child_io_ctx);
        if (r < 0) {
          rollback = true;
          return r;
        }

        child_pool_id = child_image.pool_id;
      }

      cls::rbd::MirrorImage child_mirror_image_internal;
      r = cls_client::mirror_image_get(&child_io_ctx, child_image.image_id,
                                       &child_mirror_image_internal);
      if (r != -ENOENT) {
        rollback = true;
        lderr(cct) << "mirroring is enabled on one or more children "
                   << dendl;
        return -EBUSY;
      }
    }
  }
  image_locker.unlock();

  if (mirror_image_internal.mode == cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    // don't let the non-primary feature bit prevent image updates
    ictx->image_lock.lock();
    ictx->read_only_mask &= ~IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
    ictx->image_lock.unlock();

    r = ictx->state->refresh();
    if (r < 0) {
      rollback = true;
      return r;
    }

    // remove any snapshot-based mirroring image-meta from image
    std::string mirror_uuid;
    r = uuid_get(ictx->md_ctx, &mirror_uuid);
    if (r < 0) {
      rollback = true;
      return r;
    }

    r = ictx->operations->metadata_remove(
      mirror::snapshot::util::get_image_meta_key(mirror_uuid));
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "cannot remove snapshot image-meta key: " << cpp_strerror(r)
                 << dendl;
      rollback = true;
      return r;
    }
  }

  C_SaferCond ctx;
  auto req = mirror::DisableRequest<ImageCtx>::create(ictx, force, true,
                                                      &ctx);
  req->send();

  r = ctx.wait();
  if (r < 0) {
    lderr(cct) << "cannot disable mirroring: " << cpp_strerror(r) << dendl;
    rollback = true;
    return r;
  }

  if (mirror_image_internal.mode == cls::rbd::MIRROR_IMAGE_MODE_JOURNAL) {
    r = ictx->operations->update_features(RBD_FEATURE_JOURNALING, false);
    if (r < 0) {
      lderr(cct) << "cannot disable journaling: " << cpp_strerror(r) << dendl;
      // not fatal
    }
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_promote(I *ictx, bool force) {
  CephContext *cct = ictx->cct;

  C_SaferCond ctx;
  Mirror<I>::image_promote(ictx, force, &ctx);
  int r = ctx.wait();
  if (r < 0) {
    lderr(cct) << "failed to promote image" << dendl;
    return r;
  }

  return 0;
}

template <typename I>
void Mirror<I>::image_promote(I *ictx, bool force, Context *on_finish) {
  return Mirror<I>::image_promote(ictx, -1, {}, {}, force, nullptr, on_finish);
}

template <typename I>
void Mirror<I>::image_promote(I *ictx, int64_t group_pool_id,
                              const std::string &group_id,
                              const std::string &group_snap_id,
                              bool force, uint64_t *snap_id,
                              Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << ", "
                 << "force=" << force << dendl;

  // don't let the non-primary feature bit prevent image updates
  ictx->image_lock.lock();
  ictx->read_only_mask &= ~IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
  ictx->image_lock.unlock();

  auto on_promote = new LambdaContext([ictx, on_finish](int r) {
      ictx->image_lock.lock();
      ictx->read_only_mask |= IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
      ictx->image_lock.unlock();

      ictx->state->handle_update_notification();
      on_finish->complete(r);
    });

  auto on_refresh = new LambdaContext(
    [ictx, force, group_pool_id, group_id, group_snap_id, snap_id,
     on_promote](int r) {
      if (r < 0) {
        lderr(ictx->cct) << "refresh failed: " << cpp_strerror(r) << dendl;
        on_promote->complete(r);
        return;
      }

      auto req = mirror::PromoteRequest<>::create(*ictx, force, group_pool_id,
                                                  group_id, group_snap_id,
                                                  snap_id, on_promote);
      req->send();
    });
  ictx->state->refresh(on_refresh);
}

template <typename I>
int Mirror<I>::image_demote(I *ictx) {
  CephContext *cct = ictx->cct;

  C_SaferCond ctx;
  Mirror<I>::image_demote(ictx, &ctx);
  int r = ctx.wait();
  if (r < 0) {
    lderr(cct) << "failed to demote image" << dendl;
    return r;
  }

  return 0;
}

template <typename I>
void Mirror<I>::image_demote(I *ictx, Context *on_finish) {
  return Mirror<I>::image_demote(ictx, -1, {}, {}, nullptr, on_finish);
}

template <typename I>
void Mirror<I>::image_demote(I *ictx, int64_t group_pool_id,
                             const std::string &group_id,
                             const std::string &group_snap_id,
                             uint64_t *snap_id, Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  auto on_cleanup = new LambdaContext([ictx, on_finish](int r) {
      ictx->image_lock.lock();
      ictx->read_only_mask |= IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
      ictx->image_lock.unlock();

      ictx->state->handle_update_notification();

      on_finish->complete(r);
    });
  auto on_refresh = new LambdaContext(
    [ictx, group_pool_id, group_id, group_snap_id, snap_id, on_cleanup](int r) {
      if (r < 0) {
        lderr(ictx->cct) << "refresh failed: " << cpp_strerror(r) << dendl;
        on_cleanup->complete(r);
        return;
      }

      auto req = mirror::DemoteRequest<>::create(*ictx, group_pool_id,
                                                 group_id, group_snap_id,
                                                 snap_id, on_cleanup);
      req->send();
    });

  // ensure we can create a snapshot after setting the non-primary
  // feature bit
  ictx->image_lock.lock();
  ictx->read_only_mask &= ~IMAGE_READ_ONLY_FLAG_NON_PRIMARY;
  ictx->image_lock.unlock();

  ictx->state->refresh(on_refresh);
}

template <typename I>
int Mirror<I>::image_resync(I *ictx) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  int r = ictx->state->refresh_if_required();
  if (r < 0) {
    return r;
  }

  cls::rbd::MirrorImage mirror_image;
  mirror::PromotionState promotion_state;
  std::string primary_mirror_uuid;
  C_SaferCond get_info_ctx;
  auto req = mirror::GetInfoRequest<I>::create(*ictx, &mirror_image,
                                               &promotion_state,
                                               &primary_mirror_uuid,
                                               &get_info_ctx);
  req->send();

  r = get_info_ctx.wait();
  if (r < 0) {
    return r;
  }

  if (promotion_state == mirror::PROMOTION_STATE_PRIMARY) {
    lderr(cct) << "image is primary, cannot resync to itself" << dendl;
    return -EINVAL;
  }

  if (mirror_image.mode == cls::rbd::MIRROR_IMAGE_MODE_JOURNAL) {
    // flag the journal indicating that we want to rebuild the local image
    r = Journal<I>::request_resync(ictx);
    if (r < 0) {
      lderr(cct) << "failed to request resync: " << cpp_strerror(r) << dendl;
      return r;
    }
  } else if (mirror_image.mode == cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    std::string mirror_uuid;
    r = uuid_get(ictx->md_ctx, &mirror_uuid);
    if (r < 0) {
      return r;
    }

    mirror::snapshot::ImageMeta image_meta(ictx, mirror_uuid);

    C_SaferCond load_meta_ctx;
    image_meta.load(&load_meta_ctx);
    r = load_meta_ctx.wait();
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "failed to load mirror image-meta: " << cpp_strerror(r)
                 << dendl;
      return r;
    }

    image_meta.resync_requested = true;

    C_SaferCond save_meta_ctx;
    image_meta.save(&save_meta_ctx);
    r = save_meta_ctx.wait();
    if (r < 0) {
      lderr(cct) << "failed to request resync: " << cpp_strerror(r) << dendl;
      return r;
    }
  } else {
    lderr(cct) << "unknown mirror mode" << dendl;
    return -EINVAL;
  }

  return 0;
}

template <typename I>
void Mirror<I>::image_get_info(I *ictx, mirror_image_info_t *mirror_image_info,
                               Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  auto on_refresh = new LambdaContext(
    [ictx, mirror_image_info, on_finish](int r) {
      if (r < 0) {
        lderr(ictx->cct) << "refresh failed: " << cpp_strerror(r) << dendl;
        on_finish->complete(r);
        return;
      }

      auto ctx = new C_ImageGetInfo(mirror_image_info, nullptr, on_finish);
      auto req = mirror::GetInfoRequest<I>::create(*ictx, &ctx->mirror_image,
                                                   &ctx->promotion_state,
                                                   &ctx->primary_mirror_uuid,
                                                   ctx);
      req->send();
    });

  if (ictx->state->is_refresh_required()) {
    ictx->state->refresh(on_refresh);
  } else {
    on_refresh->complete(0);
  }
}

template <typename I>
int Mirror<I>::image_get_info(I *ictx, mirror_image_info_t *mirror_image_info) {
  C_SaferCond ctx;
  image_get_info(ictx, mirror_image_info, &ctx);

  int r = ctx.wait();
  if (r < 0) {
    return r;
  }
  return 0;
}

template <typename I>
void Mirror<I>::image_get_info(librados::IoCtx& io_ctx,
                               asio::ContextWQ *op_work_queue,
                               const std::string &image_id,
                               mirror_image_info_t *mirror_image_info,
                               Context *on_finish) {
  auto cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "pool_id=" << io_ctx.get_id() << ", image_id=" << image_id
                 << dendl;

  auto ctx = new C_ImageGetInfo(mirror_image_info, nullptr, on_finish);
  auto req = mirror::GetInfoRequest<I>::create(io_ctx, op_work_queue, image_id,
                                               &ctx->mirror_image,
                                               &ctx->promotion_state,
                                               &ctx->primary_mirror_uuid, ctx);
  req->send();
}

template <typename I>
int Mirror<I>::image_get_info(librados::IoCtx& io_ctx,
                              asio::ContextWQ *op_work_queue,
                              const std::string &image_id,
                              mirror_image_info_t *mirror_image_info) {
  C_SaferCond ctx;
  image_get_info(io_ctx, op_work_queue, image_id, mirror_image_info, &ctx);

  int r = ctx.wait();
  if (r < 0) {
    return r;
  }
  return 0;
}

template <typename I>
void Mirror<I>::image_get_mode(I *ictx, mirror_image_mode_t *mode,
                               Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  auto ctx = new C_ImageGetInfo(nullptr, mode, on_finish);
  auto req = mirror::GetInfoRequest<I>::create(*ictx, &ctx->mirror_image,
                                               &ctx->promotion_state,
                                               &ctx->primary_mirror_uuid, ctx);
  req->send();
}

template <typename I>
int Mirror<I>::image_get_mode(I *ictx, mirror_image_mode_t *mode) {
  C_SaferCond ctx;
  image_get_mode(ictx, mode, &ctx);

  int r = ctx.wait();
  if (r < 0) {
    return r;
  }
  return 0;
}

template <typename I>
void Mirror<I>::image_get_global_status(I *ictx,
                                        mirror_image_global_status_t *status,
                                        Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  auto ctx = new C_ImageGetGlobalStatus(ictx->name, status, on_finish);
  auto req = mirror::GetStatusRequest<I>::create(
    *ictx, &ctx->mirror_image_status_internal, &ctx->mirror_image,
    &ctx->promotion_state, ctx);
  req->send();
}

template <typename I>
int Mirror<I>::image_get_global_status(I *ictx,
                                       mirror_image_global_status_t *status) {
  C_SaferCond ctx;
  image_get_global_status(ictx, status, &ctx);

  int r = ctx.wait();
  if (r < 0) {
    return r;
  }
  return 0;
}

template <typename I>
int Mirror<I>::image_get_instance_id(I *ictx, std::string *instance_id) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  cls::rbd::MirrorImage mirror_image;
  int r = cls_client::mirror_image_get(&ictx->md_ctx, ictx->id, &mirror_image);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve mirroring state: " << cpp_strerror(r)
               << dendl;
    return r;
  } else if (mirror_image.state != cls::rbd::MIRROR_IMAGE_STATE_ENABLED) {
    lderr(cct) << "mirroring is not currently enabled" << dendl;
    return -EINVAL;
  }

  entity_inst_t instance;
  r = cls_client::mirror_image_instance_get(&ictx->md_ctx,
                                            mirror_image.global_image_id,
                                            &instance);
  if (r < 0) {
    if (r != -ENOENT && r != -ESTALE) {
      lderr(cct) << "failed to get mirror image instance: " << cpp_strerror(r)
                 << dendl;
    }
    return r;
  }

  *instance_id = stringify(instance.name.num());
  return 0;
}

template <typename I>
int Mirror<I>::site_name_get(librados::Rados& rados, std::string* name) {
  CephContext *cct = reinterpret_cast<CephContext *>(rados.cct());
  ldout(cct, 20) << dendl;

  int r = get_config_key(rados, RBD_MIRROR_SITE_NAME_CONFIG_KEY, name);
  if (r == -EOPNOTSUPP) {
    return r;
  } else if (r == -ENOENT || name->empty()) {
    // default to the cluster fsid
    r = rados.cluster_fsid(name);
    if (r < 0) {
      lderr(cct) << "failed to retrieve cluster fsid: " << cpp_strerror(r)
                 << dendl;
    }
    return r;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve site name: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::site_name_set(librados::Rados& rados, const std::string& name) {
  CephContext *cct = reinterpret_cast<CephContext *>(rados.cct());

  std::string site_name{name};
  boost::algorithm::trim(site_name);
  ldout(cct, 20) << "site_name=" << site_name << dendl;

  int r = set_config_key(rados, RBD_MIRROR_SITE_NAME_CONFIG_KEY, name);
  if (r == -EOPNOTSUPP) {
    return r;
  } else if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to update site name: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::mode_get(librados::IoCtx& io_ctx,
                        rbd_mirror_mode_t *mirror_mode) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  cls::rbd::MirrorMode mirror_mode_internal;
  int r = cls_client::mirror_mode_get(&io_ctx, &mirror_mode_internal);
  if (r < 0) {
    lderr(cct) << "failed to retrieve mirror mode: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  switch (mirror_mode_internal) {
  case cls::rbd::MIRROR_MODE_DISABLED:
  case cls::rbd::MIRROR_MODE_IMAGE:
  case cls::rbd::MIRROR_MODE_POOL:
    *mirror_mode = static_cast<rbd_mirror_mode_t>(mirror_mode_internal);
    break;
  default:
    lderr(cct) << "unknown mirror mode ("
               << static_cast<uint32_t>(mirror_mode_internal) << ")"
               << dendl;
    return -EINVAL;
  }
  return 0;
}

template <typename I>
int Mirror<I>::mode_set(librados::IoCtx& io_ctx,
                        rbd_mirror_mode_t mirror_mode) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  cls::rbd::MirrorMode next_mirror_mode;
  switch (mirror_mode) {
  case RBD_MIRROR_MODE_DISABLED:
  case RBD_MIRROR_MODE_IMAGE:
  case RBD_MIRROR_MODE_POOL:
    next_mirror_mode = static_cast<cls::rbd::MirrorMode>(mirror_mode);
    break;
  default:
    lderr(cct) << "unknown mirror mode ("
               << static_cast<uint32_t>(mirror_mode) << ")" << dendl;
    return -EINVAL;
  }

  int r;
  if (next_mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    // fail early if pool still has peers registered and attempting to disable
    std::vector<cls::rbd::MirrorPeer> mirror_peers;
    r = cls_client::mirror_peer_list(&io_ctx, &mirror_peers);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "failed to list peers: " << cpp_strerror(r) << dendl;
      return r;
    } else if (!mirror_peers.empty()) {
      lderr(cct) << "mirror peers still registered" << dendl;
      return -EBUSY;
    }
  }

  cls::rbd::MirrorMode current_mirror_mode;
  r = cls_client::mirror_mode_get(&io_ctx, &current_mirror_mode);
  if (r < 0) {
    lderr(cct) << "failed to retrieve mirror mode: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  if (current_mirror_mode == next_mirror_mode) {
    return 0;
  } else if (current_mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    uuid_d uuid_gen;
    uuid_gen.generate_random();
    r = cls_client::mirror_uuid_set(&io_ctx, uuid_gen.to_string());
    if (r < 0) {
      lderr(cct) << "failed to allocate mirroring uuid: " << cpp_strerror(r)
                 << dendl;
      return r;
    }
  }

  if (current_mirror_mode != cls::rbd::MIRROR_MODE_IMAGE) {
    r = cls_client::mirror_mode_set(&io_ctx, cls::rbd::MIRROR_MODE_IMAGE);
    if (r < 0) {
      lderr(cct) << "failed to set mirror mode to image: "
                 << cpp_strerror(r) << dendl;
      return r;
    }

    r = MirroringWatcher<>::notify_mode_updated(io_ctx,
                                                cls::rbd::MIRROR_MODE_IMAGE);
    if (r < 0) {
      lderr(cct) << "failed to send update notification: " << cpp_strerror(r)
                 << dendl;
    }
  }

  if (next_mirror_mode == cls::rbd::MIRROR_MODE_IMAGE) {
    return 0;
  }

  if (next_mirror_mode == cls::rbd::MIRROR_MODE_POOL) {
    std::map<std::string, std::string> images;
    r = Image<I>::list_images_v2(io_ctx, &images);
    if (r < 0) {
      lderr(cct) << "failed listing images: " << cpp_strerror(r) << dendl;
      return r;
    }

    for (const auto& img_pair : images) {
      uint64_t features;
      uint64_t incompatible_features;
      r = cls_client::get_features(
          &io_ctx, librbd::util::header_name(img_pair.second), true, &features,
          &incompatible_features);
      if (r < 0) {
        lderr(cct) << "error getting features for image " << img_pair.first
                   << ": " << cpp_strerror(r) << dendl;
        return r;
      }

      // Enable only journal based mirroring

      if ((features & RBD_FEATURE_JOURNALING) != 0) {
        I *img_ctx = I::create("", img_pair.second, nullptr, io_ctx, false);
        r = img_ctx->state->open(0);
        if (r < 0) {
          lderr(cct) << "error opening image "<< img_pair.first << ": "
                     << cpp_strerror(r) << dendl;
          return r;
        }

        r = image_enable(img_ctx, RBD_MIRROR_IMAGE_MODE_JOURNAL, true);
        int close_r = img_ctx->state->close();
        if (r < 0) {
          lderr(cct) << "error enabling mirroring for image "
                     << img_pair.first << ": " << cpp_strerror(r) << dendl;
          return r;
        } else if (close_r < 0) {
          lderr(cct) << "failed to close image " << img_pair.first << ": "
                     << cpp_strerror(close_r) << dendl;
          return close_r;
        }
      }
    }
  } else if (next_mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    while (true) {
      bool retry_busy = false;
      bool pending_busy = false;

      std::set<std::string> image_ids;
      r = list_mirror_images(io_ctx, image_ids);
      if (r < 0) {
        lderr(cct) << "failed listing images: " << cpp_strerror(r) << dendl;
        return r;
      }

      for (const auto& img_id : image_ids) {
        if (current_mirror_mode == cls::rbd::MIRROR_MODE_IMAGE) {
          cls::rbd::MirrorImage mirror_image;
          r = cls_client::mirror_image_get(&io_ctx, img_id, &mirror_image);
          if (r < 0 && r != -ENOENT) {
            lderr(cct) << "failed to retrieve mirroring state for image id "
                       << img_id << ": " << cpp_strerror(r) << dendl;
            return r;
          }
          if (mirror_image.state == cls::rbd::MIRROR_IMAGE_STATE_ENABLED) {
            lderr(cct) << "failed to disable mirror mode: there are still "
                       << "images with mirroring enabled" << dendl;
            return -EINVAL;
          }
        } else {
          I *img_ctx = I::create("", img_id, nullptr, io_ctx, false);
          r = img_ctx->state->open(0);
          if (r < 0) {
            lderr(cct) << "error opening image id "<< img_id << ": "
                       << cpp_strerror(r) << dendl;
            return r;
          }

          r = image_disable(img_ctx, false);
          int close_r = img_ctx->state->close();
          if (r == -EBUSY) {
            pending_busy = true;
          } else if (r < 0) {
            lderr(cct) << "error disabling mirroring for image id " << img_id
                       << cpp_strerror(r) << dendl;
            return r;
          } else if (close_r < 0) {
            lderr(cct) << "failed to close image id " << img_id << ": "
                       << cpp_strerror(close_r) << dendl;
            return close_r;
          } else if (pending_busy) {
            // at least one mirrored image was successfully disabled, so we can
            // retry any failures caused by busy parent/child relationships
            retry_busy = true;
          }
        }
      }

      if (!retry_busy && pending_busy) {
        lderr(cct) << "error disabling mirroring for one or more images"
                   << dendl;
        return -EBUSY;
      } else if (!retry_busy) {
        break;
      }
    }
  }

  r = cls_client::mirror_mode_set(&io_ctx, next_mirror_mode);
  if (r < 0) {
    lderr(cct) << "failed to set mirror mode: " << cpp_strerror(r) << dendl;
    return r;
  }

  r = MirroringWatcher<>::notify_mode_updated(io_ctx, next_mirror_mode);
  if (r < 0) {
    lderr(cct) << "failed to send update notification: " << cpp_strerror(r)
               << dendl;
  }
  return 0;
}

template <typename I>
int Mirror<I>::uuid_get(librados::IoCtx& io_ctx, std::string* mirror_uuid) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  C_SaferCond ctx;
  uuid_get(io_ctx, mirror_uuid, &ctx);
  int r = ctx.wait();
  if (r < 0) {
    if (r != -ENOENT) {
      lderr(cct) << "failed to retrieve mirroring uuid: " << cpp_strerror(r)
                 << dendl;
    }
    return r;
  }

  return 0;
}

template <typename I>
void Mirror<I>::uuid_get(librados::IoCtx& io_ctx, std::string* mirror_uuid,
                         Context* on_finish) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  auto req = mirror::GetUuidRequest<I>::create(io_ctx, mirror_uuid, on_finish);
  req->send();
}

template <typename I>
int Mirror<I>::peer_bootstrap_create(librados::IoCtx& io_ctx,
                                     std::string* token) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  auto mirror_mode = cls::rbd::MIRROR_MODE_DISABLED;
  int r = cls_client::mirror_mode_get(&io_ctx, &mirror_mode);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve mirroring mode: " << cpp_strerror(r)
               << dendl;
    return r;
  } else if (mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    return -EINVAL;
  }

  // retrieve the cluster fsid
  std::string fsid;
  librados::Rados rados(io_ctx);
  r = rados.cluster_fsid(&fsid);
  if (r < 0) {
    lderr(cct) << "failed to retrieve cluster fsid: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  std::string peer_client_id;
  std::string cephx_key;
  r = create_bootstrap_user(cct, rados, &peer_client_id, &cephx_key);
  if (r < 0) {
    return r;
  }

  std::string mon_host = cct->_conf.get_val<std::string>("mon_host");
  ldout(cct, 20) << "mon_host=" << mon_host << dendl;

  // format the token response
  bufferlist token_bl;
  token_bl.append(
    R"({)" \
      R"("fsid":")" + fsid + R"(",)" + \
      R"("client_id":")" + peer_client_id + R"(",)" + \
      R"("key":")" + cephx_key + R"(",)" + \
      R"("mon_host":")" + \
        boost::replace_all_copy(mon_host, "\"", "\\\"") + R"(")" + \
    R"(})");
  ldout(cct, 20) << "token=" << token_bl.to_str() << dendl;

  bufferlist base64_bl;
  token_bl.encode_base64(base64_bl);
  *token = base64_bl.to_str();

  return 0;
}

template <typename I>
int Mirror<I>::peer_bootstrap_import(librados::IoCtx& io_ctx,
                                     rbd_mirror_peer_direction_t direction,
                                     const std::string& token) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  if (direction != RBD_MIRROR_PEER_DIRECTION_RX &&
      direction != RBD_MIRROR_PEER_DIRECTION_RX_TX) {
    lderr(cct) << "invalid mirror peer direction" << dendl;
    return -EINVAL;
  }

  bufferlist token_bl;
  try {
    bufferlist base64_bl;
    base64_bl.append(token);
    token_bl.decode_base64(base64_bl);
  } catch (buffer::error& err) {
    lderr(cct) << "failed to decode base64" << dendl;
    return -EINVAL;
  }

  ldout(cct, 20) << "token=" << token_bl.to_str() << dendl;

  bool json_valid = false;
  std::string expected_remote_fsid;
  std::string remote_client_id;
  std::string remote_key;
  std::string remote_mon_host;

  json_spirit::mValue json_root;
  if(json_spirit::read(token_bl.to_str(), json_root)) {
    try {
      auto& json_obj = json_root.get_obj();
      expected_remote_fsid = json_obj["fsid"].get_str();
      remote_client_id = json_obj["client_id"].get_str();
      remote_key = json_obj["key"].get_str();
      remote_mon_host = json_obj["mon_host"].get_str();
      json_valid = true;
    } catch (std::runtime_error&) {
    }
  }

  if (!json_valid) {
    lderr(cct) << "invalid bootstrap token JSON received" << dendl;
    return -EINVAL;
  }

  // sanity check import process
  std::string local_fsid;
  librados::Rados rados(io_ctx);
  int r = rados.cluster_fsid(&local_fsid);
  if (r < 0) {
    lderr(cct) << "failed to retrieve cluster fsid: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  std::string local_site_name;
  r = site_name_get(rados, &local_site_name);
  if (r < 0) {
    lderr(cct) << "failed to retrieve cluster site name: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  // attempt to connect to remote cluster
  librados::Rados remote_rados;
  remote_rados.init(remote_client_id.c_str());

  auto remote_cct = reinterpret_cast<CephContext*>(remote_rados.cct());
  remote_cct->_conf.set_val("mon_host", remote_mon_host);
  remote_cct->_conf.set_val("key", remote_key);

  r = remote_rados.connect();
  if (r < 0) {
    lderr(cct) << "failed to connect to peer cluster: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  std::string remote_fsid;
  r = remote_rados.cluster_fsid(&remote_fsid);
  if (r < 0) {
    lderr(cct) << "failed to retrieve remote cluster fsid: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (local_fsid == remote_fsid) {
    lderr(cct) << "cannot import token for local cluster" << dendl;
    return -EINVAL;
  } else if (expected_remote_fsid != remote_fsid) {
    lderr(cct) << "unexpected remote cluster fsid" << dendl;
    return -EINVAL;
  }

  std::string remote_site_name;
  r = site_name_get(remote_rados, &remote_site_name);
  if (r < 0) {
    lderr(cct) << "failed to retrieve remote cluster site name: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (local_site_name == remote_site_name) {
    lderr(cct) << "cannot import token for duplicate site name" << dendl;
    return -EINVAL;
  }

  librados::IoCtx remote_io_ctx;
  r = remote_rados.ioctx_create(io_ctx.get_pool_name().c_str(), remote_io_ctx);
  if (r == -ENOENT) {
    ldout(cct, 10) << "remote pool does not exist" << dendl;
    return r;
  } else if (r < 0) {
    lderr(cct) << "failed to open remote pool '" << io_ctx.get_pool_name()
               << "': " << cpp_strerror(r) << dendl;
    return r;
  }

  auto remote_mirror_mode = cls::rbd::MIRROR_MODE_DISABLED;
  r = cls_client::mirror_mode_get(&remote_io_ctx, &remote_mirror_mode);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve remote mirroring mode: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (remote_mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    return -ENOSYS;
  }

  auto local_mirror_mode = cls::rbd::MIRROR_MODE_DISABLED;
  r = cls_client::mirror_mode_get(&io_ctx, &local_mirror_mode);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve local mirroring mode: " << cpp_strerror(r)
               << dendl;
    return r;
  } else if (local_mirror_mode == cls::rbd::MIRROR_MODE_DISABLED) {
    // copy mirror mode from remote peer
    r = mode_set(io_ctx, static_cast<rbd_mirror_mode_t>(remote_mirror_mode));
    if (r < 0) {
      return r;
    }
  }

  if (direction == RBD_MIRROR_PEER_DIRECTION_RX_TX) {
    // create a local mirror peer user and export it to the remote cluster
    std::string local_client_id;
    std::string local_key;
    r = create_bootstrap_user(cct, rados, &local_client_id, &local_key);
    if (r < 0) {
      return r;
    }

    std::string local_mon_host = cct->_conf.get_val<std::string>("mon_host");

    // create local cluster peer in remote cluster
    r = create_bootstrap_peer(cct, remote_io_ctx,
                              RBD_MIRROR_PEER_DIRECTION_RX_TX, local_site_name,
                              local_fsid, local_client_id, local_key,
                              local_mon_host, "local", "remote");
    if (r < 0) {
      return r;
    }
  }

  // create remote cluster peer in local cluster
  r = create_bootstrap_peer(cct, io_ctx, direction, remote_site_name,
                            remote_fsid, remote_client_id, remote_key,
                            remote_mon_host, "remote", "local");
  if (r < 0) {
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::peer_site_add(librados::IoCtx& io_ctx, std::string *uuid,
                             mirror_peer_direction_t direction,
                             const std::string &site_name,
                             const std::string &client_name) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "name=" << site_name << ", "
                 << "client=" << client_name << dendl;

  if (cct->_conf->cluster == site_name) {
    lderr(cct) << "cannot add self as remote peer" << dendl;
    return -EINVAL;
  }

  if (direction == RBD_MIRROR_PEER_DIRECTION_TX) {
    return -EINVAL;
  }

  int r;
  do {
    uuid_d uuid_gen;
    uuid_gen.generate_random();

    *uuid = uuid_gen.to_string();
    r = cls_client::mirror_peer_add(
      &io_ctx, {*uuid, static_cast<cls::rbd::MirrorPeerDirection>(direction),
                site_name, client_name, ""});
    if (r == -ESTALE) {
      ldout(cct, 5) << "duplicate UUID detected, retrying" << dendl;
    } else if (r < 0) {
      lderr(cct) << "failed to add mirror peer '" << site_name << "': "
                 << cpp_strerror(r) << dendl;
      return r;
    }
  } while (r == -ESTALE);
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_remove(librados::IoCtx& io_ctx,
                                const std::string &uuid) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << dendl;

  int r = remove_peer_config_key(io_ctx, uuid);
  if (r < 0) {
    lderr(cct) << "failed to remove peer attributes '" << uuid << "': "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = cls_client::mirror_peer_remove(&io_ctx, uuid);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to remove peer '" << uuid << "': "
               << cpp_strerror(r) << dendl;
    return r;
  }

  std::vector<std::string> names;
  r = Namespace<I>::list(io_ctx, &names);
  if (r < 0) {
    return r;
  }

  names.push_back("");

  librados::IoCtx ns_io_ctx;
  ns_io_ctx.dup(io_ctx);

  for (auto &name : names) {
    ns_io_ctx.set_namespace(name);

    std::set<std::string> image_ids;
    r = list_mirror_images(ns_io_ctx, image_ids);
    if (r < 0) {
      lderr(cct) << "failed listing images in "
                 << (name.empty() ? "default" : name) << " namespace : "
                 << cpp_strerror(r) << dendl;
      return r;
    }

    for (const auto& image_id : image_ids) {
      cls::rbd::MirrorImage mirror_image;
      r = cls_client::mirror_image_get(&ns_io_ctx, image_id, &mirror_image);
      if (r == -ENOENT) {
        continue;
      }
      if (r < 0) {
        lderr(cct) << "error getting mirror info for image " << image_id
                   << ": " << cpp_strerror(r) << dendl;
        return r;
      }
      if (mirror_image.mode != cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
        continue;
      }

      // Snapshot based mirroring. Unlink the peer from mirroring snapshots.
      // TODO: optimize.

      I *img_ctx = I::create("", image_id, nullptr, ns_io_ctx, false);
      img_ctx->read_only_mask &= ~IMAGE_READ_ONLY_FLAG_NON_PRIMARY;

      r = img_ctx->state->open(0);
      if (r == -ENOENT) {
        continue;
      }
      if (r < 0) {
        lderr(cct) << "error opening image " << image_id << ": "
                   << cpp_strerror(r) << dendl;
        return r;
      }

      std::list<uint64_t> snap_ids;
      {
        std::shared_lock image_locker{img_ctx->image_lock};
        for (auto &it : img_ctx->snap_info) {
          auto info = boost::get<cls::rbd::MirrorSnapshotNamespace>(
            &it.second.snap_namespace);
          if (info && info->mirror_peer_uuids.count(uuid)) {
            snap_ids.push_back(it.first);
          }
        }
      }
      for (auto snap_id : snap_ids) {
        C_SaferCond cond;
        auto req = mirror::snapshot::UnlinkPeerRequest<I>::create(
          img_ctx, snap_id, uuid, &cond);
        req->send();
        r = cond.wait();
        if (r == -ENOENT) {
          r = 0;
        }
        if (r < 0) {
          break;
        }
      }

      int close_r = img_ctx->state->close();
      if (r < 0) {
        lderr(cct) << "error unlinking peer for image " << image_id << ": "
                   << cpp_strerror(r) << dendl;
        return r;
      } else if (close_r < 0) {
        lderr(cct) << "failed to close image " << image_id << ": "
                   << cpp_strerror(close_r) << dendl;
        return close_r;
      }
    }
  }

  return 0;
}

template <typename I>
int Mirror<I>::peer_site_list(librados::IoCtx& io_ctx,
                              std::vector<mirror_peer_site_t> *peers) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  std::vector<cls::rbd::MirrorPeer> mirror_peers;
  int r = cls_client::mirror_peer_list(&io_ctx, &mirror_peers);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  peers->clear();
  peers->reserve(mirror_peers.size());
  for (auto &mirror_peer : mirror_peers) {
    mirror_peer_site_t peer;
    peer.uuid = mirror_peer.uuid;
    peer.direction = static_cast<mirror_peer_direction_t>(
      mirror_peer.mirror_peer_direction);
    peer.site_name = mirror_peer.site_name;
    peer.mirror_uuid = mirror_peer.mirror_uuid;
    peer.client_name = mirror_peer.client_name;
    peer.last_seen = mirror_peer.last_seen.sec();
    peers->push_back(peer);
  }
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_set_client(librados::IoCtx& io_ctx,
                                    const std::string &uuid,
                                    const std::string &client_name) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << ", "
                 << "client=" << client_name << dendl;

  int r = cls_client::mirror_peer_set_client(&io_ctx, uuid, client_name);
  if (r < 0) {
    lderr(cct) << "failed to update client '" << uuid << "': "
               << cpp_strerror(r) << dendl;
    return r;
  }
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_set_name(librados::IoCtx& io_ctx,
                                  const std::string &uuid,
                                  const std::string &site_name) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << ", "
                 << "name=" << site_name << dendl;

  if (cct->_conf->cluster == site_name) {
    lderr(cct) << "cannot set self as remote peer" << dendl;
    return -EINVAL;
  }

  int r = cls_client::mirror_peer_set_cluster(&io_ctx, uuid, site_name);
  if (r < 0) {
    lderr(cct) << "failed to update site '" << uuid << "': "
               << cpp_strerror(r) << dendl;
    return r;
  }
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_set_direction(librados::IoCtx& io_ctx,
                                       const std::string &uuid,
                                       mirror_peer_direction_t direction) {
  cls::rbd::MirrorPeerDirection mirror_peer_direction = static_cast<
    cls::rbd::MirrorPeerDirection>(direction);

  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << ", "
                 << "direction=" << mirror_peer_direction << dendl;

  int r = cls_client::mirror_peer_set_direction(&io_ctx, uuid,
                                                mirror_peer_direction);
  if (r < 0) {
    lderr(cct) << "failed to update direction '" << uuid << "': "
               << cpp_strerror(r) << dendl;
    return r;
  }
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_get_attributes(librados::IoCtx& io_ctx,
                                        const std::string &uuid,
                                        Attributes* attributes) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << dendl;

  attributes->clear();

  librados::Rados rados(io_ctx);
  std::string value;
  int r = get_config_key(rados, get_peer_config_key_name(io_ctx.get_id(), uuid),
                         &value);
  if (r == -ENOENT || value.empty()) {
    return -ENOENT;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve peer attributes: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  bool json_valid = false;
  json_spirit::mValue json_root;
  if(json_spirit::read(value, json_root)) {
    try {
      auto& json_obj = json_root.get_obj();
      for (auto& pairs : json_obj) {
        (*attributes)[pairs.first] = pairs.second.get_str();
      }
      json_valid = true;
    } catch (std::runtime_error&) {
    }
  }

  if (!json_valid) {
    lderr(cct) << "invalid peer attributes JSON received" << dendl;
    return -EINVAL;
  }
  return 0;
}

template <typename I>
int Mirror<I>::peer_site_set_attributes(librados::IoCtx& io_ctx,
                                        const std::string &uuid,
                                        const Attributes& attributes) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "uuid=" << uuid << ", "
                 << "attributes=" << attributes << dendl;

  std::vector<mirror_peer_site_t> mirror_peers;
  int r = peer_site_list(io_ctx, &mirror_peers);
  if (r < 0) {
    return r;
  }

  if (std::find_if(mirror_peers.begin(), mirror_peers.end(),
                   [&uuid](const librbd::mirror_peer_site_t& peer) {
                     return uuid == peer.uuid;
                   }) == mirror_peers.end()) {
    ldout(cct, 5) << "mirror peer uuid " << uuid << " does not exist" << dendl;
    return -ENOENT;
  }

  std::stringstream ss;
  ss << "{";
  for (auto& pair : attributes) {
    ss << "\\\"" << pair.first << "\\\": "
       << "\\\"" << pair.second << "\\\"";
    if (&pair != &(*attributes.rbegin())) {
      ss << ", ";
    }
  }
  ss << "}";

  librados::Rados rados(io_ctx);
  r = set_config_key(rados, get_peer_config_key_name(io_ctx.get_id(), uuid),
                     ss.str());
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to update peer attributes: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_global_status_list(
    librados::IoCtx& io_ctx, const std::string &start_id, size_t max,
    IdToMirrorImageGlobalStatus *images) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  int r;

  std::map<std::string, std::string> id_to_name;
  {
    std::map<std::string, std::string> name_to_id;
    r = Image<I>::list_images_v2(io_ctx, &name_to_id);
    if (r < 0) {
      return r;
    }
    for (auto it : name_to_id) {
      id_to_name[it.second] = it.first;
    }
  }

  std::map<std::string, cls::rbd::MirrorImage> images_;
  std::map<std::string, cls::rbd::MirrorImageStatus> statuses_;

  r = librbd::cls_client::mirror_image_status_list(&io_ctx, start_id, max,
      					           &images_, &statuses_);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror image statuses: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  const std::string STATUS_NOT_FOUND("status not found");
  for (auto it = images_.begin(); it != images_.end(); ++it) {
    auto &image_id = it->first;
    auto &info = it->second;
    if (info.state == cls::rbd::MIRROR_IMAGE_STATE_DISABLED) {
      continue;
    }

    auto &image_name = id_to_name[image_id];
    if (image_name.empty()) {
      lderr(cct) << "failed to find image name for image " << image_id << ", "
      	         << "using image id as name" << dendl;
      image_name = image_id;
    }

    mirror_image_global_status_t& global_status = (*images)[image_id];
    global_status.name = image_name;
    global_status.info = mirror_image_info_t{
        info.global_image_id,
        static_cast<mirror_image_state_t>(info.state),
        false}; // XXX: To set "primary" right would require an additional call.

    bool found_local_site_status = false;
    auto s_it = statuses_.find(image_id);
    if (s_it != statuses_.end()) {
      auto& status = s_it->second;

      global_status.site_statuses.reserve(
        status.mirror_image_site_statuses.size());
      for (auto& site_status : status.mirror_image_site_statuses) {
        if (site_status.mirror_uuid ==
              cls::rbd::MirrorImageSiteStatus::LOCAL_MIRROR_UUID) {
          found_local_site_status = true;
        }

        global_status.site_statuses.push_back(mirror_image_site_status_t{
          site_status.mirror_uuid,
          static_cast<mirror_image_status_state_t>(site_status.state),
          site_status.state == cls::rbd::MIRROR_IMAGE_STATUS_STATE_UNKNOWN ?
            STATUS_NOT_FOUND : site_status.description,
          site_status.last_update.sec(), site_status.up});
      }
    }

    if (!found_local_site_status) {
      global_status.site_statuses.push_back(mirror_image_site_status_t{
        cls::rbd::MirrorImageSiteStatus::LOCAL_MIRROR_UUID,
        MIRROR_IMAGE_STATUS_STATE_UNKNOWN, STATUS_NOT_FOUND, 0, false});
    }
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_status_summary(librados::IoCtx& io_ctx,
                                    MirrorImageStatusStates *states) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());

  std::vector<cls::rbd::MirrorPeer> mirror_peers;
  int r = cls_client::mirror_peer_list(&io_ctx, &mirror_peers);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::map<cls::rbd::MirrorImageStatusState, int32_t> states_;
  r = cls_client::mirror_image_status_get_summary(&io_ctx, mirror_peers,
                                                  &states_);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to get mirror status summary: "
               << cpp_strerror(r) << dendl;
    return r;
  }
  for (auto &s : states_) {
    (*states)[static_cast<mirror_image_status_state_t>(s.first)] = s.second;
  }
  return 0;
}

template <typename I>
int Mirror<I>::image_instance_id_list(
    librados::IoCtx& io_ctx, const std::string &start_image_id, size_t max,
    std::map<std::string, std::string> *instance_ids) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  std::map<std::string, entity_inst_t> instances;

  int r = librbd::cls_client::mirror_image_instance_list(
      &io_ctx, start_image_id, max, &instances);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror image instances: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  for (auto it : instances) {
    (*instance_ids)[it.first] = stringify(it.second.name.num());
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_info_list(
    librados::IoCtx& io_ctx, mirror_image_mode_t *mode_filter,
    const std::string &start_id, size_t max,
    std::map<std::string, std::pair<mirror_image_mode_t,
                                    mirror_image_info_t>> *entries) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "pool=" << io_ctx.get_pool_name() << ", mode_filter="
                 << (mode_filter ? stringify(*mode_filter) : "null")
                 << ", start_id=" << start_id << ", max=" << max << dendl;

  std::string last_read = start_id;
  entries->clear();

  while (entries->size() < max) {
    std::map<std::string, cls::rbd::MirrorImage> images;
    std::map<std::string, cls::rbd::MirrorImageStatus> statuses;

    int r = librbd::cls_client::mirror_image_status_list(&io_ctx, last_read,
                                                         max, &images,
                                                         &statuses);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "failed to list mirror image statuses: "
                 << cpp_strerror(r) << dendl;
      return r;
    }

    if (images.empty()) {
      break;
    }

    AsioEngine asio_engine(io_ctx);

    for (auto &it : images) {
      auto &image_id = it.first;
      auto &image = it.second;
      auto mode = static_cast<mirror_image_mode_t>(image.mode);

      if ((mode_filter && mode != *mode_filter) ||
          image.state != cls::rbd::MIRROR_IMAGE_STATE_ENABLED) {
        continue;
      }

      // need to call get_info for every image to retrieve promotion state

      mirror_image_info_t info;
      r = image_get_info(io_ctx, asio_engine.get_work_queue(), image_id, &info);
      if (r < 0) {
        continue;
      }

      (*entries)[image_id] = std::make_pair(mode, info);
      if (entries->size() == max) {
        break;
      }
    }

    last_read = images.rbegin()->first;
  }

  return 0;
}

template <typename I>
int Mirror<I>::image_snapshot_create(I *ictx, uint32_t flags,
                                     uint64_t *snap_id) {
  C_SaferCond ctx;
  Mirror<I>::image_snapshot_create(ictx, flags, snap_id, &ctx);

  return ctx.wait();
}

template <typename I>
void Mirror<I>::image_snapshot_create(I *ictx, uint32_t flags,
                                      uint64_t *snap_id, Context *on_finish) {
  return Mirror<I>::image_snapshot_create(ictx, flags, -1, {}, {}, snap_id,
                                          on_finish);
}

template <typename I>
void Mirror<I>::image_snapshot_create(I *ictx, uint32_t flags,
                                      int64_t group_pool_id,
                                      const std::string &group_id,
                                      const std::string &group_snap_id,
                                      uint64_t *snap_id, Context *on_finish) {
  CephContext *cct = ictx->cct;
  ldout(cct, 20) << "ictx=" << ictx << dendl;

  uint64_t snap_create_flags = 0;
  int r = librbd::util::snap_create_flags_api_to_internal(cct, flags,
                                                          &snap_create_flags);
  if (r < 0) {
    on_finish->complete(r);
    return;
  }

  auto on_refresh = new LambdaContext(
    [ictx, snap_create_flags, group_pool_id, group_id, group_snap_id, snap_id,
     on_finish](int r) {
      if (r < 0) {
        lderr(ictx->cct) << "refresh failed: " << cpp_strerror(r) << dendl;
        on_finish->complete(r);
        return;
      }

      auto ctx = new C_ImageSnapshotCreate<I>(ictx, snap_create_flags,
                                              group_pool_id, group_id,
                                              group_snap_id,  snap_id,
                                              on_finish);
      auto req = mirror::GetInfoRequest<I>::create(*ictx, &ctx->mirror_image,
                                                   &ctx->promotion_state,
                                                   &ctx->primary_mirror_uuid,
                                                   ctx);
      req->send();
    });

  if (ictx->state->is_refresh_required()) {
    ictx->state->refresh(on_refresh);
  } else {
    on_refresh->complete(0);
  }
}

template <typename I>
int Mirror<I>::group_list(IoCtx& io_ctx, std::vector<std::string> *names) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());

  std::set<std::string> group_ids;
  std::string last_read = "";
  int max_read = 1024;
  int r;
  do {
    std::map<std::string, cls::rbd::MirrorGroup> mirror_groups;
    r =  cls_client::mirror_group_list(&io_ctx, last_read, max_read,
                                       &mirror_groups);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "error listing mirrored image directory: "
                 << cpp_strerror(r) << dendl;
      return r;
    }
    for (auto &[group_id, mirror_group] : mirror_groups) {
      group_ids.insert(group_id);
    }
    if (!mirror_groups.empty()) {
      last_read = mirror_groups.rbegin()->first;
    }
    r = mirror_groups.size();
  } while (r == max_read);

  if (group_ids.empty()) {
    return 0;
  }

  std::map <std::string, std::string> name_to_id_map;
  r = Group<I>::list(io_ctx, &name_to_id_map);
  if (r < 0) {
    return r;
  }

  for (auto &[name, group_id] : name_to_id_map) {
    if (group_ids.count(group_id) > 0) {
      names->push_back(name);
    }
  }
  return 0;
}

template <typename I>
int Mirror<I>::group_enable(IoCtx& group_ioctx, const char *group_name,
                            mirror_image_mode_t mirror_image_mode) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name
		 << " mirror image mode " << mirror_image_mode << dendl;

  if (mirror_image_mode != RBD_MIRROR_IMAGE_MODE_SNAPSHOT) {
    return -EOPNOTSUPP;
  }

  std::string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorMode mirror_mode;
  r = cls_client::mirror_mode_get(&group_ioctx, &mirror_mode);
  if (r < 0) {
    lderr(cct) << "cannot enable mirroring: failed to retrieve mirror mode: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  if (mirror_mode != cls::rbd::MIRROR_MODE_IMAGE) {
    lderr(cct) << "cannot enable mirroring in the current pool mirroring mode"
               << dendl;
    return -EINVAL;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -EOPNOTSUPP) {
    ldout(cct, 5) << "group mirroring not supported by OSD" << dendl;
    return r;
  } else if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  auto mode = static_cast<rbd_mirror_image_mode_t>(
      mirror_group.mirror_image_mode);
  if (mode != mirror_image_mode) {
    lderr(cct) << "mirroring for group " << group_name
               << " already enabled with different mirror image mode " << mode
               << dendl;
    return -EINVAL;
  }

  if (mirror_group.state == cls::rbd::MIRROR_GROUP_STATE_ENABLED) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " already enabled" << dendl;
    return 0;
  }

  if (mirror_group.state == cls::rbd::MIRROR_GROUP_STATE_ENABLING) {
    lderr(cct) << "enabling mirroring for group " << group_name
               << " either in progress or was interrupted" << dendl;
    return -EINVAL;
  }

  // XXXMG: remove code duplication

  std::vector<cls::rbd::MirrorPeer> peers;
  r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::vector<mirror_image_info_t> mirror_images(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < on_finishes.size(); i++) {
    image_get_info(image_ctxs[i], &mirror_images[i], &on_finishes[i]);
  }

  int ret_code = 0;
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code != 0) {
        ret_code = r;
      }
    } else if (mirror_images[i].state == RBD_MIRROR_IMAGE_ENABLED) {
      lderr(cct) << "image " << image_ctxs[i]->name << " has mirroring enabled"
                 << dendl;
      ret_code = -EINVAL;
    }
  }

  if (ret_code != 0) {
    close_images(&image_ctxs);
    return ret_code;
  }

  uuid_d uuid_gen;
  uuid_gen.generate_random();
  mirror_group = {uuid_gen.to_string(),
                  static_cast<cls::rbd::MirrorImageMode>(mirror_image_mode),
                  cls::rbd::MIRROR_GROUP_STATE_ENABLING};
  r = cls_client::mirror_group_set(&group_ioctx, group_id, mirror_group);
  if (r < 0) {
    lderr(cct) << "failed to set mirroring group metadata: "
               << cpp_strerror(r) << dendl;
    close_images(&image_ctxs);
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  std::vector<uint64_t> snap_ids(image_ctxs.size());

  for (size_t i = 0; i < image_ctxs.size(); i++) {
    r = image_enable(image_ctxs[i], group_ioctx.get_id(), group_id,
                     group_snap_id, mirror_image_mode, false, &snap_ids[i]);
    if (r < 0) {
      break;
    }
  }

  auto image_count = image_ctxs.size();

  close_images(&image_ctxs);

  if (r < 0) {
    int rr = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                           group_snap.id);
    if (rr < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(rr) << dendl;
    }

    // TODO: try to remove the created image snapshots
    return r;
  }

  group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to update group snapshot metadata: "
               << cpp_strerror(r) << dendl;
  }

  mirror_group.state = cls::rbd::MIRROR_GROUP_STATE_ENABLED;
  r = cls_client::mirror_group_set(&group_ioctx, group_id, mirror_group);
  if (r < 0) {
    lderr(cct) << "failed to update mirroring group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = MirroringWatcher<I>::notify_group_updated(
    group_ioctx, cls::rbd::MIRROR_GROUP_STATE_ENABLED, group_id,
    mirror_group.global_group_id, image_count);
  if (r < 0) {
    lderr(cct) << "failed to notify mirroring group updated: "
               << cpp_strerror(r) << dendl;
    // not fatal
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_disable(IoCtx& group_ioctx, const char *group_name,
                            bool force) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name
		 << " force " << force << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -EOPNOTSUPP) {
    ldout(cct, 5) << "group mirroring not supported by OSD" << dendl;
    return r;
  } else if (r == -ENOENT) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " already disabled" << dendl;
    return 0;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  mirror_group.state = cls::rbd::MIRROR_GROUP_STATE_DISABLING;
  r = cls_client::mirror_group_set(&group_ioctx, group_id, mirror_group);
  if (r < 0) {
    lderr(cct) << "failed to update mirroring group metadata: "
               << cpp_strerror(r) << dendl;
    close_images(&image_ctxs);
    return r;
  }

  r = MirroringWatcher<I>::notify_group_updated(
    group_ioctx, cls::rbd::MIRROR_GROUP_STATE_DISABLED, group_id,
    mirror_group.global_group_id, image_ctxs.size());
  if (r < 0) {
    lderr(cct) << "failed to notify mirroring group updated: "
               << cpp_strerror(r) << dendl;
    // not fatal
  }

  for (auto image_ctx : image_ctxs) {
    r = image_disable(image_ctx, force);
    if (r < 0) {
      break;
    }
  }

  auto image_count = image_ctxs.size();

  close_images(&image_ctxs);

  if (r < 0) {
    return r;
  }

  std::vector<cls::rbd::GroupSnapshot> snaps;
  C_SaferCond cond;
  auto req = group::ListSnapshotsRequest<>::create(group_ioctx, group_id,
                                                   &snaps, &cond);
  req->send();
  r = cond.wait();
  if (r < 0) {
    // ignore
  }

  for (auto &snap : snaps) {
    auto ns = boost::get<cls::rbd::MirrorGroupSnapshotNamespace>(
        &snap.snapshot_namespace);
    if (ns == nullptr) {
      continue;
    }
    r = util::group_snap_remove(group_ioctx, group_id, snap);
    if (r < 0) {
      // ignore
    }
  }

  r = cls_client::mirror_group_remove(&group_ioctx, group_id);
  if (r < 0) {
    lderr(cct) << "failed to remove mirroring group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = MirroringWatcher<I>::notify_group_updated(
    group_ioctx, cls::rbd::MIRROR_GROUP_STATE_DISABLED, group_id,
    mirror_group.global_group_id, image_count);
  if (r < 0) {
    lderr(cct) << "failed to notify mirroring group updated: "
               << cpp_strerror(r) << dendl;
    // not fatal
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_promote(IoCtx& group_ioctx, const char *group_name,
                             bool force) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name
		 << " force " << force << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -ENOENT) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " disabled" << dendl;
    return -EINVAL;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (mirror_group.mirror_image_mode !=
             cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    return -EOPNOTSUPP;
  }

  cls::rbd::MirrorSnapshotState state;
  r = get_last_mirror_snapshot_state(group_ioctx, group_id, &state);
  if (r == -ENOENT) {
    state = cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY_DEMOTED; // XXXMG?
    r = 0;
  }
  if (r < 0) {
    return r;
  }

  if (state == cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY) {
    lderr(cct) << "group " << group_name << " is already primary" << dendl;
    return -EINVAL;
  } else if (state == cls::rbd::MIRROR_SNAPSHOT_STATE_NON_PRIMARY && !force) {
    lderr(cct) << "group " << group_name
               << " is still primary within a remote cluster" << dendl;
    return -EBUSY;
  }

  std::vector<cls::rbd::MirrorPeer> peers;
  r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  // XXXMG: Requesting exclusive locks for images?
  // XXXMG: notify quiesce?

  std::vector<uint64_t> snap_ids(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < on_finishes.size(); i++) {
    image_promote(image_ctxs[i], group_ioctx.get_id(), group_id, group_snap_id,
                  force, &snap_ids[i], &on_finishes[i]);
  }

  int ret_code = 0;
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code == 0) {
        ret_code = r;
      }
    } else {
      group_snap.snaps[i].snap_id = snap_ids[i];
    }
  }

  if (ret_code < 0) {
    r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                      group_snap.id);
    if (r < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
    }
  } else {
    group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
    r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
    if (r < 0) {
      lderr(cct) << "failed to update group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
      ret_code = r;
    }
  }

  close_images(&image_ctxs);

  return ret_code;
}

template <typename I>
int Mirror<I>::group_demote(IoCtx& group_ioctx, const char *group_name) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -ENOENT) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " disabled" << dendl;
    return -EINVAL;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (mirror_group.mirror_image_mode !=
             cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    return -EOPNOTSUPP;
  }

  cls::rbd::MirrorSnapshotState state;
  r = get_last_mirror_snapshot_state(group_ioctx, group_id, &state);
  if (r == -ENOENT) {
    state = cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY;
    r = 0;
  }
  if (r < 0) {
    return r;
  }

  if (state != cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY) {
    lderr(cct) << "group " << group_name << " is not primary" << dendl;
    return -EINVAL;
  }

  std::vector<cls::rbd::MirrorPeer> peers;
  r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY_DEMOTED,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  // XXXMG: Requesting exclusive locks for images?
  // XXXMG: notify quiesce?

  std::vector<uint64_t> snap_ids(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < on_finishes.size(); i++) {
    image_demote(image_ctxs[i], group_ioctx.get_id(), group_id, group_snap_id,
                 &snap_ids[i], &on_finishes[i]);
  }

  int ret_code = 0;
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code == 0) {
        ret_code = r;
      }
    } else {
      group_snap.snaps[i].snap_id = snap_ids[i];
    }
  }

  if (ret_code < 0) {
    r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                      group_snap.id);
    if (r < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
    }
  } else {
    group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
    r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
    if (r < 0) {
      lderr(cct) << "failed to update group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
      ret_code = r;
    }
  }

  close_images(&image_ctxs);

  return ret_code;
}

template <typename I>
int Mirror<I>::group_resync(IoCtx& group_ioctx, const char *group_name) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -ENOENT) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " disabled" << dendl;
    return -EINVAL;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (mirror_group.mirror_image_mode !=
             cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    return -EOPNOTSUPP;
  }

  cls::rbd::MirrorSnapshotState state;
  r = get_last_mirror_snapshot_state(group_ioctx, group_id, &state);
  if (r == -ENOENT) {
    state = cls::rbd::MIRROR_SNAPSHOT_STATE_NON_PRIMARY;
    r = 0;
  }
  if (r < 0) {
    return r;
  }

  if (state == cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY) {
    lderr(cct) << "group " << group_name
               << " is primary, cannot resync to itself" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  // XXXMG: remove mirror group snapshots

  for (auto image_ctx : image_ctxs) {
    r = image_resync(image_ctx);
    if (r < 0) {
      break;
    }
  }

  close_images(&image_ctxs);

  if (r < 0) {
    return r;
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_create_snapshot(IoCtx& group_ioctx, const char *group_name,
                                     uint32_t flags, std::string *snap_id) {
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name
		 << " flags " << flags << dendl;

  uint64_t internal_flags = 0;
  int r = librbd::util::snap_create_flags_api_to_internal(cct, flags,
                                                          &internal_flags);
  if (r < 0) {
    return r;
  }

  std::string group_id;
  r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY, group_name,
                             &group_id);
  if (r < 0) {
    lderr(cct) << "error reading group id object: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::vector<cls::rbd::MirrorPeer> peers;
  r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  cls::rbd::MirrorGroup mirror_group;
  r = cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_group);
  if (r == -ENOENT) {
    ldout(cct, 10) << "mirroring for group " << group_name
                   << " disabled" << dendl;
    return -EINVAL;
  } else if (r < 0) {
    lderr(cct) << "failed to retrieve mirror group metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  } else if (mirror_group.mirror_image_mode !=
             cls::rbd::MIRROR_IMAGE_MODE_SNAPSHOT) {
    return -EOPNOTSUPP;
  }

  cls::rbd::MirrorSnapshotState state;
  r = get_last_mirror_snapshot_state(group_ioctx, group_id, &state);
  if (r == -ENOENT) {
    state = cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY;
    r = 0;
  }
  if (r < 0) {
    return r;
  }

  if (state != cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY) {
    lderr(cct) << "group " << group_name << " is not primary" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  // XXXMG: Requesting exclusive locks for images?

  std::vector<uint64_t> quiesce_requests;
  if ((internal_flags & SNAP_CREATE_FLAG_SKIP_NOTIFY_QUIESCE) == 0) {
    NoOpProgressContext prog_ctx;
    r = util::notify_quiesce(image_ctxs, prog_ctx, &quiesce_requests);
    if (r < 0 &&
        (internal_flags & SNAP_CREATE_FLAG_IGNORE_NOTIFY_QUIESCE_ERROR) == 0) {
      close_images(&image_ctxs);
      return r;
    }
  }

  std::vector<uint64_t> snap_ids(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < on_finishes.size(); i++) {
    image_snapshot_create(image_ctxs[i], RBD_SNAP_CREATE_SKIP_QUIESCE,
                          group_ioctx.get_id(), group_id, group_snap_id,
                          &snap_ids[i], &on_finishes[i]);
  }

  int ret_code = 0;
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code == 0) {
        ret_code = r;
      }
    } else {
      group_snap.snaps[i].snap_id = snap_ids[i];
    }
  }

  if (ret_code < 0) {
    r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                      group_snap.id);
    if (r < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
    }
  } else {
    group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
    r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
    if (r < 0) {
      lderr(cct) << "failed to update group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
      ret_code = r;
    }
  }

  if (!quiesce_requests.empty()) {
    util::notify_unquiesce(image_ctxs, quiesce_requests);
  }

  // TODO: try to remove created snapshots in a failure case

  close_images(&image_ctxs);

  if (ret_code < 0) {
    return ret_code;
  }

  *snap_id = group_snap.id;

  return 0;
}

template <typename I>
int Mirror<I>::group_image_add(IoCtx &group_ioctx,
                               const std::string &group_id,
                               IoCtx &image_ioctx,
                               const std::string &image_id) {
  cls::rbd::MirrorGroup mirror_info;
  if (cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_info) < 0 ||
      mirror_info.state != cls::rbd::MIRROR_GROUP_STATE_ENABLED) {
    return 0;
  }

  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "group io_ctx=" << &group_ioctx << " group_id=" << group_id
                 << "image io_ctx=" << &group_ioctx << " image id=" << image_id
		 << dendl;

  auto mode = static_cast<mirror_image_mode_t>(mirror_info.mirror_image_mode);

  // XXXMG: remove code duplication

  std::vector<cls::rbd::MirrorPeer> peers;
  int r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  // XXXMG: notify quiesce?

  std::vector<uint64_t> snap_ids(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < image_ctxs.size(); i++) {
    if (image_ctxs[i]->md_ctx.get_id() == image_ioctx.get_id() &&
        image_ctxs[i]->id == image_id) {
      r = image_enable(image_ctxs[i], group_ioctx.get_id(), group_id,
                       group_snap_id, mode, false, &snap_ids[i]);
      on_finishes[i].complete(r);
    } else {
      image_snapshot_create(image_ctxs[i], RBD_SNAP_CREATE_SKIP_QUIESCE,
                            group_ioctx.get_id(), group_id, group_snap_id,
                            &snap_ids[i], &on_finishes[i]);
    }
  }

  int ret_code = 0;
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code == 0) {
        ret_code = r;
      }
    } else {
      group_snap.snaps[i].snap_id = snap_ids[i];
    }
  }

  auto image_count = image_ctxs.size();

  close_images(&image_ctxs);

  if (ret_code < 0) {
    r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                      group_snap.id);
    if (r < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
    }

    // TODO: try to remove the created image snapshots
    return ret_code;
  }

  group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to update group snapshot metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = MirroringWatcher<I>::notify_group_updated(
    group_ioctx, cls::rbd::MIRROR_GROUP_STATE_ENABLED, group_id,
    mirror_info.global_group_id, image_count);
  if (r < 0) {
    lderr(cct) << "failed to notify mirroring group updated: "
               << cpp_strerror(r) << dendl;
    // not fatal
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_image_remove(IoCtx &group_ioctx,
                                  const std::string &group_id,
                                  IoCtx &image_ioctx,
                                  const std::string &image_id) {
  cls::rbd::MirrorGroup mirror_info;
  if (cls_client::mirror_group_get(&group_ioctx, group_id, &mirror_info) < 0 ||
      mirror_info.state != cls::rbd::MIRROR_GROUP_STATE_ENABLED) {
    return 0;
  }

  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "group io_ctx=" << &group_ioctx << " group_id=" << group_id
                 << "image io_ctx=" << &group_ioctx << " image id=" << image_id
		 << dendl;

  // XXXMG: remove code duplication

  std::vector<cls::rbd::MirrorPeer> peers;
  int r = cls_client::mirror_peer_list(&group_ioctx, &peers);
  if (r < 0) {
    lderr(cct) << "error reading mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::set<std::string> mirror_peer_uuids;
  for (auto &peer : peers) {
    if (peer.mirror_peer_direction == cls::rbd::MIRROR_PEER_DIRECTION_RX) {
      continue;
    }
    mirror_peer_uuids.insert(peer.uuid);
  }

  if (mirror_peer_uuids.empty()) {
    lderr(cct) << "no mirror tx peers configured for the pool" << dendl;
    return -EINVAL;
  }

  std::vector<I *> image_ctxs;
  r = open_group_images(group_ioctx, group_id, &image_ctxs);
  if (r < 0) {
    return r;
  }

  std::string group_snap_id = librbd::util::generate_uuid(group_ioctx);

  cls::rbd::GroupSnapshot group_snap{
      group_snap_id,
      cls::rbd::MirrorGroupSnapshotNamespace{
          cls::rbd::MIRROR_SNAPSHOT_STATE_PRIMARY,
          mirror_peer_uuids, {}, {}},
      calc_ind_mirror_snap_name(group_ioctx.get_id(), group_id, group_snap_id),
      cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE};

  for (auto image_ctx: image_ctxs) {
    if (image_ctx->md_ctx.get_id() == image_ioctx.get_id() &&
        image_ctx->id == image_id) {
      continue;
    }
    group_snap.snaps.emplace_back(image_ctx->md_ctx.get_id(), image_ctx->id,
                                  CEPH_NOSNAP);
  }

  std::string group_header_oid = librbd::util::group_header_name(group_id);
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to set group snapshot metadata: " << cpp_strerror(r)
               << dendl;
    close_images(&image_ctxs);
    return r;
  }

  // XXXMG: notify quiesce?

  std::vector<uint64_t> snap_ids(image_ctxs.size());
  std::vector<C_SaferCond> on_finishes(image_ctxs.size());

  for (size_t i = 0; i < image_ctxs.size(); i++) {
    if (image_ctxs[i]->md_ctx.get_id() == image_ioctx.get_id() &&
        image_ctxs[i]->id == image_id) {
      r = image_disable(image_ctxs[i], true);
      snap_ids[i] = CEPH_NOSNAP;
      on_finishes[i].complete(r);
    } else {
      image_snapshot_create(image_ctxs[i], RBD_SNAP_CREATE_SKIP_QUIESCE,
                            group_ioctx.get_id(), group_id, group_snap_id,
                            &snap_ids[i], &on_finishes[i]);
    }
  }

  int ret_code = 0;
  group_snap.snaps.clear();
  for (size_t i = 0; i < on_finishes.size(); i++) {
    r = on_finishes[i].wait();
    if (r < 0) {
      if (ret_code == 0) {
        ret_code = r;
      }
    }
    if (image_ctxs[i]->md_ctx.get_id() == image_ioctx.get_id() &&
        image_ctxs[i]->id == image_id) {
      continue;
    }
    group_snap.snaps.emplace_back(image_ctxs[i]->md_ctx.get_id(),
                                  image_ctxs[i]->id, snap_ids[i]);
  }

  auto image_count = image_ctxs.size();

  close_images(&image_ctxs);

  if (ret_code < 0) {
    r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
                                      group_snap.id);
    if (r < 0) {
      lderr(cct) << "failed to remove group snapshot metadata: "
                 << cpp_strerror(r) << dendl;
    }

    // TODO: try to remove the created image snapshots
    return ret_code;
  }

  group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;
  r = cls_client::group_snap_set(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    lderr(cct) << "failed to update group snapshot metadata: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = MirroringWatcher<I>::notify_group_updated(
    group_ioctx, cls::rbd::MIRROR_GROUP_STATE_ENABLED, group_id,
    mirror_info.global_group_id, image_count);
  if (r < 0) {
    lderr(cct) << "failed to notify mirroring group updated: "
               << cpp_strerror(r) << dendl;
    // not fatal
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_status_list(librados::IoCtx& io_ctx,
                                 const std::string &start_id, size_t max,
                                 IdToMirrorGroupStatus *groups) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  std::map<std::string, std::string> id_to_name;
  int max_read = 1024;
  std::string last_read = "";
  int r;
  do {
    std::map<std::string, std::string> groups;
    r = cls_client::group_dir_list(&io_ctx, RBD_GROUP_DIRECTORY, last_read,
                                   max_read, &groups);
    if (r < 0) {
      if (r != -ENOENT) {
        lderr(cct) << "error listing groups in directory: "
                   << cpp_strerror(r) << dendl;
      } else {
        r = 0;
      }
      return r;
    }
    for (auto &[name, group_id] : groups) {
      id_to_name[group_id] = name;
    }
    r = groups.size();
  } while (r == max_read);

  std::map<std::string, cls::rbd::MirrorGroup> groups_internal;
  std::map<std::string, cls::rbd::MirrorGroupStatus> statuses_internal;

  r = librbd::cls_client::mirror_group_status_list(&io_ctx, start_id, max,
      					           &groups_internal,
                                                   &statuses_internal);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror group statuses: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  const std::string STATUS_NOT_FOUND("status not found");
  for (auto &[group_id, info] : groups_internal) {
    auto &group_name = id_to_name[group_id];
    if (group_name.empty()) {
      lderr(cct) << "failed to resolve name for group " << group_id << ", "
                 << "using group id as name" << dendl;
      group_name = group_id;
    }

    mirror_group_status_t &status = (*groups)[group_id];
    status.name = group_name;
    status.info.global_id = info.global_group_id;
    status.info.mirror_image_mode =
        static_cast<rbd_mirror_image_mode_t>(info.mirror_image_mode);
    status.info.state = static_cast<mirror_group_state_t>(info.state);

    bool found_local_site_status = false;
    auto s_it = statuses_internal.find(group_id);
    if (s_it != statuses_internal.end()) {
      auto &status_internal = s_it->second;

      status.site_statuses.resize(
          status_internal.mirror_group_site_statuses.size());
      size_t idx = 0;
      for (auto &s : status_internal.mirror_group_site_statuses) {
        mirror_group_site_status_t &site_status  = status.site_statuses[idx++];
        site_status.mirror_uuid = s.mirror_uuid;
        site_status.state = static_cast<mirror_group_status_state_t>(s.state);
        site_status.description = s.description;
        for (auto &[spec, si] : s.mirror_images) {
          auto &mirror_image =
              site_status.mirror_images[{spec.pool_id, spec.global_image_id}];
          mirror_image.mirror_uuid = si.mirror_uuid;
          mirror_image.state = static_cast<mirror_image_status_state_t>(si.state);
          mirror_image.description = si.description;
          mirror_image.last_update = si.last_update.sec();
          mirror_image.up = si.up;
        }
        site_status.last_update = s.last_update.sec();
        site_status.up = s.up;
        if (s.mirror_uuid == cls::rbd::MirrorGroupSiteStatus::LOCAL_MIRROR_UUID) {
          found_local_site_status = true;
        }
      }
    }

    if (!found_local_site_status) {
      status.site_statuses.push_back(mirror_group_site_status_t{
          cls::rbd::MirrorGroupSiteStatus::LOCAL_MIRROR_UUID,
          MIRROR_GROUP_STATUS_STATE_UNKNOWN,
          STATUS_NOT_FOUND, {}, {}, false});
    }
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_status_summary(librados::IoCtx& io_ctx,
                                    MirrorGroupStatusStates *states) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  std::vector<cls::rbd::MirrorPeer> mirror_peers;
  int r = cls_client::mirror_peer_list(&io_ctx, &mirror_peers);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror peers: " << cpp_strerror(r) << dendl;
    return r;
  }

  std::map<cls::rbd::MirrorGroupStatusState, int32_t> states_internal;
  r = cls_client::mirror_group_status_get_summary(&io_ctx, mirror_peers,
                                                  &states_internal);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to get mirror status summary: "
               << cpp_strerror(r) << dendl;
    return r;
  }
  for (auto &s : states_internal) {
    (*states)[static_cast<mirror_group_status_state_t>(s.first)] = s.second;
  }
  return 0;
}

template <typename I>
int Mirror<I>::group_instance_id_list(librados::IoCtx& io_ctx,
                                      const std::string &start_group_id,
                                      size_t max,
                                      std::map<std::string, std::string> *ids) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << dendl;

  std::map<std::string, entity_inst_t> instances;
  int r = librbd::cls_client::mirror_group_instance_list(
      &io_ctx, start_group_id, max, &instances);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to list mirror group instances: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  for (auto it : instances) {
    (*ids)[it.first] = stringify(it.second.name.num());
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_info_list(
    librados::IoCtx& io_ctx, mirror_image_mode_t *mode_filter,
    const std::string &start_id, size_t max,
    std::map<std::string, mirror_group_info_t> *entries) {
  CephContext *cct = reinterpret_cast<CephContext *>(io_ctx.cct());
  ldout(cct, 20) << "pool=" << io_ctx.get_pool_name() << ", mode_filter="
                 << (mode_filter ? stringify(*mode_filter) : "null")
                 << ", start_id=" << start_id << ", max=" << max << dendl;

  std::string last_read = start_id;
  entries->clear();

  while (entries->size() < max) {
    std::map<std::string, cls::rbd::MirrorGroup> groups;
    std::map<std::string, cls::rbd::MirrorGroupStatus> statuses;

    int r = librbd::cls_client::mirror_group_status_list(&io_ctx, last_read,
                                                         max, &groups,
                                                         &statuses);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "failed to list mirror image statuses: "
                 << cpp_strerror(r) << dendl;
      return r;
    }

    for (auto &[group_id, group] : groups) {
      auto mode = static_cast<mirror_image_mode_t>(group.mirror_image_mode);

      if ((mode_filter && mode != *mode_filter) ||
          group.state != cls::rbd::MIRROR_GROUP_STATE_ENABLED) {
        continue;
      }

      auto &info = (*entries)[group_id];
      info.global_id = group.global_group_id;
      info.mirror_image_mode = mode;
      info.state = static_cast<rbd_mirror_group_state_t>(group.state);

      if (entries->size() == max) {
        break;
      }
    }

    if (groups.size() != max) {
      break;
    }

    last_read = groups.rbegin()->first;
  }

  return 0;
}

template <typename I>
int Mirror<I>::group_get_info(librados::IoCtx& io_ctx,
                              const std::string &group_name,
                              mirror_group_info_t *mirror_group_info) {
  CephContext *cct((CephContext *)io_ctx.cct());
  ldout(cct, 20) << "group_name=" << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&io_ctx, RBD_GROUP_DIRECTORY, group_name,
                                 &group_id);
  if (r < 0) {
    lderr(cct) << "error getting id of group " << group_name << ": "
               << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r =  cls_client::mirror_group_get(&io_ctx, group_id, &mirror_group);
  if (r < 0) {
    lderr(cct) << "failed to get mirror group info: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  mirror_group_info->global_id = mirror_group.global_group_id;
  mirror_group_info->mirror_image_mode =
      static_cast<rbd_mirror_image_mode_t>(mirror_group.mirror_image_mode);
  mirror_group_info->state =
      static_cast<rbd_mirror_group_state_t>(mirror_group.state);

  return 0;
}

template <typename I>
int Mirror<I>::group_get_status(librados::IoCtx& io_ctx,
                                const std::string &group_name,
                                mirror_group_status_t *status) {
  CephContext *cct((CephContext *)io_ctx.cct());
  ldout(cct, 20) << "group_name=" << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&io_ctx, RBD_GROUP_DIRECTORY, group_name,
                                 &group_id);
  if (r < 0) {
    lderr(cct) << "error getting id of group " << group_name << ": "
               << cpp_strerror(r) << dendl;
    return r;
  }

  status->name = group_name;
  r = group_get_info(io_ctx, group_name, &status->info);
  if (r < 0) {
    return r;
  }

  cls::rbd::MirrorGroupStatus status_internal;
  r =  cls_client::mirror_group_status_get(&io_ctx, status->info.global_id,
                                           &status_internal);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to get mirror group status: " << cpp_strerror(r)
               << dendl;
    return r;
  }

  status->site_statuses.resize(
      status_internal.mirror_group_site_statuses.size());
  size_t idx = 0;
  for (auto &s : status_internal.mirror_group_site_statuses) {
    mirror_group_site_status_t &site_status  = status->site_statuses[idx++];
    site_status.mirror_uuid = s.mirror_uuid;
    site_status.state = static_cast<mirror_group_status_state_t>(s.state);
    site_status.description = s.description;
    for (auto &[spec, si] : s.mirror_images) {
      auto &mirror_image = site_status.mirror_images[{spec.pool_id,
                                                      spec.global_image_id}];
      mirror_image.mirror_uuid = si.mirror_uuid;
      mirror_image.state = static_cast<mirror_image_status_state_t>(si.state);
      mirror_image.description = si.description;
      mirror_image.last_update = si.last_update.sec();
      mirror_image.up = si.up;
    }
    site_status.last_update = s.last_update.sec();
    site_status.up = s.up;
  }
  return 0;
}

template <typename I>
int Mirror<I>::group_get_instance_id(librados::IoCtx& io_ctx,
                                     const std::string &group_name,
                                     std::string *instance_id) {
  CephContext *cct((CephContext *)io_ctx.cct());
  ldout(cct, 20) << "group_name=" << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&io_ctx, RBD_GROUP_DIRECTORY, group_name,
                                 &group_id);
  if (r < 0) {
    lderr(cct) << "error getting id of group " << group_name << ": "
               << cpp_strerror(r) << dendl;
    return r;
  }

  cls::rbd::MirrorGroup mirror_group;
  r =  cls_client::mirror_group_get(&io_ctx, group_id, &mirror_group);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to retrieve mirroring state: " << cpp_strerror(r)
               << dendl;
    return r;
  } else if (mirror_group.state != cls::rbd::MIRROR_GROUP_STATE_ENABLED) {
    lderr(cct) << "mirroring is not currently enabled" << dendl;
    return -EINVAL;
  }

  entity_inst_t instance;
  r = cls_client::mirror_group_instance_get(&io_ctx,
                                            mirror_group.global_group_id,
                                            &instance);
  if (r < 0) {
    if (r != -ENOENT && r != -ESTALE) {
      lderr(cct) << "failed to get mirror group instance: " << cpp_strerror(r)
                 << dendl;
    }
    return r;
  }

  *instance_id = stringify(instance.name.num());
  return 0;
}

} // namespace api
} // namespace librbd

template class librbd::api::Mirror<librbd::ImageCtx>;
