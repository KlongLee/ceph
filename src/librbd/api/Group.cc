// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/errno.h"

#include "librbd/ExclusiveLock.h"
#include "librbd/api/Group.h"
#include "librbd/ImageCtx.h"
#include "librbd/ImageState.h"
#include "librbd/Operations.h"
#include "librbd/Utils.h"
#include "librbd/io/AioCompletion.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::api::Group: " << __func__ << ": "

using std::map;
using std::pair;
using std::set;
using std::string;
using std::vector;
// list binds to list() here, so std::list is explicitly used below

using ceph::bufferlist;
using librados::snap_t;
using librados::IoCtx;
using librados::Rados;


namespace librbd {
namespace api {

namespace {

string generate_uuid(librados::IoCtx& io_ctx)
{
  Rados rados(io_ctx);
  uint64_t bid = rados.get_instance_id();

  uint32_t extra = rand() % 0xFFFFFFFF;
  ostringstream bid_ss;
  bid_ss << std::hex << bid << std::hex << extra;
  return bid_ss.str();
}

int group_snap_list(librados::IoCtx& group_ioctx, const char *group_name,
		    std::vector<cls::rbd::GroupSnapshot> *cls_snaps)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  librados::Rados rados(group_ioctx);

  string group_id;
  vector<string> ind_snap_names;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }
  string group_header_oid = util::group_header_name(group_id);

  const int max_read = 1024;
  cls::rbd::GroupSnapshot snap_last;

  for (;;) {
    vector<cls::rbd::GroupSnapshot> snaps_page;

    r = cls_client::group_snap_list(&group_ioctx, group_header_oid,
				    snap_last, max_read, &snaps_page);

    if (r < 0) {
      lderr(cct) << "error reading snap list from consistency group: "
	<< cpp_strerror(-r) << dendl;
      return r;
    }
    cls_snaps->insert(cls_snaps->end(), snaps_page.begin(), snaps_page.end());
    if (snaps_page.size() < max_read) {
      break;
    }
    snap_last = *snaps_page.rbegin();
  }

  return 0;
}

std::string calc_ind_image_snap_name(uint64_t pool_id,
				     std::string group_id,
				     std::string snap_id)
{
  std::stringstream ind_snap_name_stream;
  ind_snap_name_stream << std::setw(16) << std::setfill('0') << std::hex <<
			  pool_id <<
			  "_" << group_id <<
			  "_" << snap_id;
  return ind_snap_name_stream.str();
}

int group_image_list(librados::IoCtx& group_ioctx, const char *group_name,
		     std::vector<cls::rbd::GroupImageStatus> *image_ids)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();

  string group_id;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }
  string group_header_oid = util::group_header_name(group_id);

  ldout(cct, 20) << "listing images in group name "
		 << group_name << " group id " << group_header_oid << dendl;
  image_ids->clear();

  const int max_read = 1024;
  cls::rbd::GroupImageSpec start_last;
  do {
    std::vector<cls::rbd::GroupImageStatus> image_ids_page;

    r = cls_client::group_image_list(&group_ioctx, group_header_oid,
				     start_last, max_read, &image_ids_page);

    if (r < 0) {
      lderr(cct) << "error reading image list from consistency group: "
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

int group_image_remove(librados::IoCtx& group_ioctx, string group_id,
		       librados::IoCtx& image_ioctx, string image_id)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();

  string group_header_oid = util::group_header_name(group_id);

  string image_header_oid = util::header_name(image_id);

  ldout(cct, 20) << "removing image " << image_id
		 << " image id " << image_header_oid << dendl;

  cls::rbd::GroupSpec group_spec(group_id, group_ioctx.get_id());

  cls::rbd::GroupImageStatus incomplete_st(image_id, image_ioctx.get_id(),
				cls::rbd::GROUP_IMAGE_LINK_STATE_INCOMPLETE);

  cls::rbd::GroupImageSpec spec(image_id, image_ioctx.get_id());

  int r = cls_client::group_image_set(&group_ioctx, group_header_oid,
				      incomplete_st);

  if (r < 0) {
    lderr(cct) << "couldn't put image into removing state: "
	       << cpp_strerror(-r) << dendl;
    return r;
  }

  r = cls_client::image_remove_group(&image_ioctx, image_header_oid,
				     group_spec);
  if ((r < 0) && (r != -ENOENT)) {
    lderr(cct) << "couldn't remove group reference from image"
	       << cpp_strerror(-r) << dendl;
    return r;
  }

  r = cls_client::group_image_remove(&group_ioctx, group_header_oid, spec);
  if (r < 0) {
    lderr(cct) << "couldn't remove image from group"
	       << cpp_strerror(-r) << dendl;
    return r;
  }

  return 0;
}

int group_snap_remove_by_record(librados::IoCtx& group_ioctx,
				const cls::rbd::GroupSnapshot& group_snap,
				const std::string& group_id,
				const std::string& group_header_oid) {

  CephContext *cct = (CephContext *)group_ioctx.cct();
  librados::Rados rados(group_ioctx);
  std::vector<C_SaferCond*> on_finishes;
  int r, ret_code;

  std::vector<librbd::IoCtx*> io_ctxs;
  std::vector<librbd::ImageCtx*> ictxs;

  std::string image_snap_name;

  cls::rbd::SnapshotNamespace ne;

  ldout(cct, 20) << "Removing snapshots" << dendl;
  int snap_count = group_snap.snaps.size();

  for (int i = 0; i < snap_count; ++i) {
    librbd::IoCtx image_io_ctx;
    r = rados.ioctx_create2(group_snap.snaps[i].pool, image_io_ctx);
    if (r < 0) {
      ldout(cct, 1) << "Failed to create io context for image" << dendl;
    }

    librbd::ImageCtx* image_ctx = new ImageCtx("", group_snap.snaps[i].image_id,
					       nullptr, image_io_ctx, false);

    C_SaferCond* on_finish = new C_SaferCond;

    image_ctx->state->open(false, on_finish);

    ictxs.push_back(image_ctx);
    on_finishes.push_back(on_finish);
  }

  ret_code = 0;
  for (int i = 0; i < snap_count; ++i) {
    r = on_finishes[i]->wait();
    delete on_finishes[i];
    if (r < 0) {
      delete ictxs[i];
      ictxs[i] = nullptr;
      ret_code = r;
    }
  }
  if (ret_code != 0) {
    goto finish;
  }

  ne = cls::rbd::GroupSnapshotNamespace(group_ioctx.get_id(),
					group_id,
					group_snap.id);

  ldout(cct, 20) << "Opened participating images. " <<
		    "Deleting snapshots themselves." << dendl;

  for (int i = 0; i < snap_count; ++i) {
    ImageCtx *ictx = ictxs[i];
    ldout(cct, 20) << "Removing individual snapshot with name: " <<
      image_snap_name << dendl;
    on_finishes[i] = new C_SaferCond;

    std::string snap_name;
    ictx->snap_lock.get_read();
    snap_t snap_id = ictx->get_snap_id_from_namespace(ne);
    r = ictx->get_snap_name(snap_id, &snap_name);
    ictx->snap_lock.put_read();
    if (r >= 0) {
      ictx->operations->snap_remove(ne, snap_name.c_str(), on_finishes[i]);
    }
    // We are ok to ignore missing image snapshots. The snapshot could have been inconsistent in the first place.
  }

  for (int i = 0; i < snap_count; ++i) {
    r = on_finishes[i]->wait();
    delete on_finishes[i];
    if (r < 0 && r != -ENOENT) { // if previous attempts to remove this snapshot failed then the image's snapshot may not exist
      lderr(cct) << "Failed deleting image snapshot. Ret code: " << r << dendl;
      ret_code = r;
    }
  }

  if (ret_code != 0) {
    goto finish;
  }

  ldout(cct, 20) << "Removed images snapshots removing snapshot record." <<
    dendl;

  r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
      group_snap.id);
  if (r < 0) {
    ret_code = r;
    goto finish;
  }

finish:
  for (int i = 0; i < snap_count; ++i) {
    if (ictxs[i] != nullptr) {
      ictxs[i]->state->close();
    }
  }
  return ret_code;
}

class GetGroupVisitor : public boost::static_visitor<int> {
public:
  librados::IoCtx *image_ioctx;
  group_snap_t group_snap;

  explicit GetGroupVisitor(librados::IoCtx *_image_ioctx) : image_ioctx(_image_ioctx) {};

  template <typename T>
  inline int operator()(const T&) const {
    // ignore other than GroupSnapshotNamespace types.
    return -1;
  }

  inline int operator()(const cls::rbd::GroupSnapshotNamespace& snap_namespace) {
    librados::Rados rados(*image_ioctx);
    IoCtx group_ioctx;
    int r = rados.ioctx_create2(snap_namespace.group_pool, group_ioctx);
    if (r < 0) {
      return r;
    }

    cls::rbd::GroupSnapshot group_snapshot;

    std::string group_name;
    r = cls_client::dir_get_name(&group_ioctx, RBD_GROUP_DIRECTORY,
				 snap_namespace.group_id, &group_name);
    if (r < 0) {
      return r;
    }

    string group_header_oid = util::group_header_name(snap_namespace.group_id);

    r = cls_client::group_snap_get_by_id(&group_ioctx,
					 group_header_oid,
					 snap_namespace.group_snapshot_id,
					 &group_snapshot);
    if (r < 0) {
      return r;
    }

    group_snap.group_pool = group_ioctx.get_id();
    group_snap.group_name = group_name;
    group_snap.group_snap_name = group_snapshot.name;

    return 0;
  }
};

} // anonymous namespace

template <typename I>
int Group<I>::image_remove_by_id(librados::IoCtx& group_ioctx,
                                 const char *group_name,
                                 librados::IoCtx& image_ioctx,
                                 const char *image_id)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
    << " group name " << group_name << " image "
    << &image_ioctx << " id " << image_id << dendl;

  string group_id;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY, group_name,
      &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
      << cpp_strerror(r)
      << dendl;
    return r;
  }

  ldout(cct, 20) << "removing image from group name " << group_name
		  << " group id " << group_id << dendl;

  return group_image_remove(group_ioctx, group_id, image_ioctx, string(image_id));
}

template <typename I>
int Group<I>::create(librados::IoCtx& io_ctx, const char *group_name)
{
  CephContext *cct = (CephContext *)io_ctx.cct();

  string id = generate_uuid(io_ctx);

  ldout(cct, 2) << "adding consistency group to directory..." << dendl;

  int r = cls_client::group_dir_add(&io_ctx, RBD_GROUP_DIRECTORY, group_name,
                                    id);
  if (r < 0) {
    lderr(cct) << "error adding consistency group to directory: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }
  string header_oid = util::group_header_name(id);

  r = io_ctx.create(header_oid, true);
  if (r < 0) {
    lderr(cct) << "error creating group header: " << cpp_strerror(r) << dendl;
    goto err_remove_from_dir;
  }

  return 0;

err_remove_from_dir:
  int remove_r = cls_client::group_dir_remove(&io_ctx, RBD_GROUP_DIRECTORY,
					      group_name, id);
  if (remove_r < 0) {
    lderr(cct) << "error cleaning up consistency group from rbd_directory "
	       << "object after creation failed: " << cpp_strerror(remove_r)
	       << dendl;
  }

  return r;
}

template <typename I>
int Group<I>::remove(librados::IoCtx& io_ctx, const char *group_name)
{
  CephContext *cct((CephContext *)io_ctx.cct());
  ldout(cct, 20) << "group_remove " << &io_ctx << " " << group_name << dendl;

  std::string group_id;
  int r = cls_client::dir_get_id(&io_ctx, RBD_GROUP_DIRECTORY,
				 std::string(group_name), &group_id);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "error getting id of group" << dendl;
    return r;
  }
  string group_header_oid = util::group_header_name(group_id);

  std::vector<cls::rbd::GroupSnapshot> snaps;
  r = group_snap_list(io_ctx, group_name, &snaps);

  for (auto &snap : snaps) {
    r = group_snap_remove_by_record(io_ctx, snap, group_id, group_header_oid);
    if (r < 0) {
      return r;
    }
  }

  std::vector<cls::rbd::GroupImageStatus> images;
  r = group_image_list(io_ctx, group_name, &images);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "error listing group images" << dendl;
    return r;
  }

  for (auto image : images) {
    librados::Rados rados(io_ctx);
    IoCtx image_ioctx;
    r = rados.ioctx_create2(image.spec.pool_id, image_ioctx);
    if (r < 0) {
      lderr(cct) << "error creating image_ioctx" << dendl;
      return r;
    }
    r = group_image_remove(io_ctx, group_id, image_ioctx, image.spec.image_id);
    if (r < 0 && r != -ENOENT) {
      lderr(cct) << "error removing image from a group" << dendl;
      return r;
    }
  }

  string header_oid = util::group_header_name(group_id);

  r = io_ctx.remove(header_oid);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "error removing header: " << cpp_strerror(-r) << dendl;
    return r;
  }

  r = cls_client::group_dir_remove(&io_ctx, RBD_GROUP_DIRECTORY,
				       group_name, group_id);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "error removing group from directory" << dendl;
    return r;
  }

  return 0;
}

template <typename I>
int Group<I>::list(IoCtx& io_ctx, vector<string> *names)
{
  CephContext *cct = (CephContext *)io_ctx.cct();
  ldout(cct, 20) << "io_ctx=" << &io_ctx << dendl;

  int max_read = 1024;
  string last_read = "";
  int r;
  do {
    map<string, string> groups;
    r = cls_client::group_dir_list(&io_ctx, RBD_GROUP_DIRECTORY, last_read,
                                   max_read, &groups);
    if (r == -ENOENT) {
      return 0; // Ignore missing rbd group directory. It means we don't have any groups yet.
    }
    if (r < 0) {
      if (r != -ENOENT) {
        lderr(cct) << "error listing group in directory: "
                   << cpp_strerror(r) << dendl;
      } else {
        r = 0;
      }
      return r;
    }
    for (pair<string, string> group : groups) {
      names->push_back(group.first);
    }
    if (!groups.empty()) {
      last_read = groups.rbegin()->first;
    }
    r = groups.size();
  } while (r == max_read);

  return 0;
}

template <typename I>
int Group<I>::image_add(librados::IoCtx& group_ioctx, const char *group_name,
			librados::IoCtx& image_ioctx, const char *image_name)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name << " image "
		 << &image_ioctx << " name " << image_name << dendl;

  string group_id;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY, group_name,
                                 &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }
  string group_header_oid = util::group_header_name(group_id);


  ldout(cct, 20) << "adding image to group name " << group_name
		 << " group id " << group_header_oid << dendl;

  string image_id;

  r = cls_client::dir_get_id(&image_ioctx, RBD_DIRECTORY, image_name,
                             &image_id);
  if (r < 0) {
    lderr(cct) << "error reading image id object: "
	       << cpp_strerror(-r) << dendl;
    return r;
  }

  string image_header_oid = util::header_name(image_id);

  ldout(cct, 20) << "adding image " << image_name
		 << " image id " << image_header_oid << dendl;

  cls::rbd::GroupImageStatus incomplete_st(
    image_id, image_ioctx.get_id(),
    cls::rbd::GROUP_IMAGE_LINK_STATE_INCOMPLETE);
  cls::rbd::GroupImageStatus attached_st(
    image_id, image_ioctx.get_id(), cls::rbd::GROUP_IMAGE_LINK_STATE_ATTACHED);

  r = cls_client::group_image_set(&group_ioctx, group_header_oid,
				  incomplete_st);

  cls::rbd::GroupSpec group_spec(group_id, group_ioctx.get_id());

  if (r < 0) {
    lderr(cct) << "error adding image reference to consistency group: "
	       << cpp_strerror(-r) << dendl;
    return r;
  }

  r = cls_client::image_add_group(&image_ioctx, image_header_oid, group_spec);
  if (r < 0) {
    lderr(cct) << "error adding group reference to image: "
	       << cpp_strerror(-r) << dendl;
    cls::rbd::GroupImageSpec spec(image_id, image_ioctx.get_id());
    cls_client::group_image_remove(&group_ioctx, group_header_oid, spec);
    // Ignore errors in the clean up procedure.
    return r;
  }

  r = cls_client::group_image_set(&group_ioctx, group_header_oid,
				  attached_st);

  return r;
}

template <typename I>
int Group<I>::image_remove(librados::IoCtx& group_ioctx, const char *group_name,
		           librados::IoCtx& image_ioctx, const char *image_name)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
    << " group name " << group_name << " image "
    << &image_ioctx << " name " << image_name << dendl;

  string group_id;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY, group_name,
      &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
      << cpp_strerror(r)
      << dendl;
    return r;
  }

  ldout(cct, 20) << "removing image from group name " << group_name
    << " group id " << group_id << dendl;

  string image_id;
  r = cls_client::dir_get_id(&image_ioctx, RBD_DIRECTORY, image_name,
      &image_id);
  if (r < 0) {
    lderr(cct) << "error reading image id object: "
      << cpp_strerror(-r) << dendl;
    return r;
  }

  r = group_image_remove(group_ioctx, group_id, image_ioctx, image_id);

  return r;
}

template <typename I>
int Group<I>::image_list(librados::IoCtx& group_ioctx,
			 const char *group_name,
			 std::vector<group_image_status_t>* images)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  ldout(cct, 20) << "io_ctx=" << &group_ioctx
		 << " group name " << group_name << dendl;

  std::vector<cls::rbd::GroupImageStatus> image_ids;

  group_image_list(group_ioctx, group_name, &image_ids);

  for (auto image_id : image_ids) {
    librados::Rados rados(group_ioctx);
    IoCtx ioctx;
    int r = rados.ioctx_create2(image_id.spec.pool_id, ioctx);
    if (r < 0) {
      return r;
    }
    std::string image_name;
    r = cls_client::dir_get_name(&ioctx, RBD_DIRECTORY,
				 image_id.spec.image_id, &image_name);
    if (r < 0) {
      return r;
    }

    images->push_back(
	group_image_status_t {
	   image_name,
	   ioctx.get_id(),
	   static_cast<group_image_state_t>(image_id.state)});
  }

  return 0;
}

template <typename I>
int Group<I>::image_get_group(I *ictx, group_spec_t *group_spec)
{
  int r = ictx->state->refresh_if_required();
  if (r < 0)
    return r;

  if (-1 != ictx->group_spec.pool_id) {
    librados::Rados rados(ictx->md_ctx);
    IoCtx ioctx;
    r = rados.ioctx_create2(ictx->group_spec.pool_id, ioctx);
    if (r < 0)
      return r;

    std::string group_name;
    r = cls_client::dir_get_name(&ioctx, RBD_GROUP_DIRECTORY,
				 ictx->group_spec.group_id, &group_name);
    if (r < 0)
      return r;
    group_spec->pool = ioctx.get_id();
    group_spec->name = group_name;
  } else {
    group_spec->pool = RBD_GROUP_INVALID_POOL;
    group_spec->name = "";
  }

  return 0;
}

template <typename I>
int Group<I>::snap_create(librados::IoCtx& group_ioctx,
    const char *group_name, const char *snap_name)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  librados::Rados rados(group_ioctx);

  string group_id;
  cls::rbd::GroupSnapshot group_snap;
  vector<cls::rbd::ImageSnapshotSpec> image_snaps;
  std::string ind_snap_name;

  std::vector<librbd::IoCtx*> io_ctxs;
  std::vector<librbd::ImageCtx*> ictxs;
  std::vector<C_SaferCond*> on_finishes;

  cls::rbd::SnapshotNamespace ne;

  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }

  std::vector<cls::rbd::GroupImageStatus> images;
  r = group_image_list(group_ioctx, group_name, &images);
  if (r < 0) {
    return r;
  }
  int image_count = images.size();

  ldout(cct, 20) << "Found " << image_count << " images in group" << dendl;

  image_snaps = vector<cls::rbd::ImageSnapshotSpec>(image_count,
      cls::rbd::ImageSnapshotSpec());

  for (int i = 0; i < image_count; ++i) {
    image_snaps[i].pool = images[i].spec.pool_id;
    image_snaps[i].image_id = images[i].spec.image_id;
  }

  string group_header_oid = util::group_header_name(group_id);

  group_snap.id = generate_uuid(group_ioctx);
  group_snap.name = string(snap_name);
  group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_INCOMPLETE;
  group_snap.snaps = image_snaps;

  r = cls_client::group_snap_add(&group_ioctx, group_header_oid, group_snap);
  if (r == -EEXIST) {
    lderr(cct) << "snapshot with this name already exists: "
	       << cpp_strerror(r)
	       << dendl;
  }
  int ret_code = 0;
  if (r < 0) {
    ret_code = r;
    goto finish;
  }

  for (auto image: images) {
    librbd::IoCtx* image_io_ctx = new librbd::IoCtx;

    r = rados.ioctx_create2(image.spec.pool_id, *image_io_ctx);
    if (r < 0) {
      ldout(cct, 1) << "Failed to create io context for image" << dendl;
    }

    ldout(cct, 20) << "Openning image with id" << image.spec.image_id << dendl;

    librbd::ImageCtx* image_ctx = new ImageCtx("", image.spec.image_id.c_str(),
					       nullptr, *image_io_ctx, false);

    C_SaferCond* on_finish = new C_SaferCond;

    image_ctx->state->open(false, on_finish);

    ictxs.push_back(image_ctx);
    on_finishes.push_back(on_finish);
  }
  ldout(cct, 20) << "Issued open request waiting for the completion" << dendl;
  ret_code = 0;
  for (int i = 0; i < image_count; ++i) {

    ldout(cct, 20) << "Waiting for completion on on_finish: " <<
      on_finishes[i] << dendl;

    r = on_finishes[i]->wait();
    delete on_finishes[i];
    if (r < 0) {
      delete ictxs[i];
      ictxs[i] = nullptr;
      ret_code = r;
    }
  }
  if (ret_code != 0) {
    goto remove_record;
  }
  ldout(cct, 20) << "Requesting exclusive locks for images" << dendl;

  for (auto ictx: ictxs) {
    RWLock::RLocker owner_lock(ictx->owner_lock);
    if (ictx->exclusive_lock != nullptr) {
      ictx->exclusive_lock->block_requests(-EBUSY);
    }
  }
  for (int i = 0; i < image_count; ++i) {
    ImageCtx *ictx = ictxs[i];
    RWLock::RLocker owner_lock(ictx->owner_lock);

    on_finishes[i] = new C_SaferCond;
    if (ictx->exclusive_lock != nullptr) {
      ictx->exclusive_lock->acquire_lock(on_finishes[i]);
    }
  }

  ret_code = 0;
  for (int i = 0; i < image_count; ++i) {
    r = 0;
    ImageCtx *ictx = ictxs[i];
    if (ictx->exclusive_lock != nullptr) {
      r = on_finishes[i]->wait();
    }
    delete on_finishes[i];
    if (r < 0) {
      ret_code = r;
    }
  }
  if (ret_code != 0) {
    goto remove_record;
  }

  ind_snap_name = calc_ind_image_snap_name(group_ioctx.get_id(), group_id,
      group_snap.id);
  ne = cls::rbd::GroupSnapshotNamespace(group_ioctx.get_id(), group_id,
      group_snap.id);

  for (int i = 0; i < image_count; ++i) {
    ImageCtx *ictx = ictxs[i];

    C_SaferCond* on_finish = new C_SaferCond;

    ictx->operations->snap_create(ne, ind_snap_name.c_str(), on_finish);

    on_finishes[i] = on_finish;
  }

  ret_code = 0;
  for (int i = 0; i < image_count; ++i) {
    r = on_finishes[i]->wait();
    delete on_finishes[i];
    if (r < 0) {
      ret_code = r;
    } else {
      ImageCtx *ictx = ictxs[i];
      ictx->snap_lock.get_read();
      snap_t snap_id = ictx->get_snap_id_from_namespace(ne);
      ictx->snap_lock.put_read();
      if (snap_id == CEPH_NOSNAP) {
	ldout(cct, 20) <<
	  "Couldn't find supposedly created snapshot with namespace: " <<
	  ne << dendl;
	ret_code = -ENOENT;
      } else {
	image_snaps[i].snap_id = snapid_t(snap_id);
	image_snaps[i].pool = ictx->data_ctx.get_id();
	image_snaps[i].image_id = ictx->id;
      }
    }
  }
  if (ret_code != 0) {
    goto remove_image_snaps;
  }

  group_snap.snaps = image_snaps;
  group_snap.state = cls::rbd::GROUP_SNAPSHOT_STATE_COMPLETE;

  r = cls_client::group_snap_update(&group_ioctx, group_header_oid, group_snap);
  if (r < 0) {
    ret_code = r;
    goto remove_image_snaps;
  }

  goto finish;

remove_image_snaps:

  for (int i = 0; i < image_count; ++i) {
    ImageCtx *ictx = ictxs[i];
    ldout(cct, 20) << "Removing individual snapshot with name: " <<
      ind_snap_name << dendl;

    on_finishes[i] = new C_SaferCond;
    std::string snap_name;
    ictx->snap_lock.get_read();
    snap_t snap_id = ictx->get_snap_id_from_namespace(ne);
    r = ictx->get_snap_name(snap_id, &snap_name);
    ictx->snap_lock.put_read();
    if (r >= 0) {
      ictx->operations->snap_remove(ne, snap_name.c_str(), on_finishes[i]);
    }
    // Ignore missing image snapshots. The whole snapshot could have been inconsistent.
  }

  for (int i = 0, n = on_finishes.size(); i < n; ++i) {
    r = on_finishes[i]->wait();
    delete on_finishes[i];
    if (r < 0 && r != -ENOENT) { // if previous attempts to remove this snapshot failed then the image's snapshot may not exist
      lderr(cct) << "Failed cleaning up image snapshot. Ret code: " << r << dendl;
      // just report error, but don't abort the process
    }
  }

remove_record:
  r = cls_client::group_snap_remove(&group_ioctx, group_header_oid,
      group_snap.id);
  if (r < 0) {
    lderr(cct) << "error while cleaning up group snapshot" << dendl;
    // we ignore return value in clean up
  }

finish:
  for (int i = 0, n = ictxs.size(); i < n; ++i) {
    if (ictxs[i] != nullptr) {
      ictxs[i]->state->close();
    }
  }
  return ret_code;
}

template <typename I>
int Group<I>::snap_remove(librados::IoCtx& group_ioctx, const char *group_name,
			  const char *snap_name)
{
  CephContext *cct = (CephContext *)group_ioctx.cct();
  librados::Rados rados(group_ioctx);

  std::vector<cls::rbd::GroupSnapshot> snaps;
  std::vector<C_SaferCond*> on_finishes;

  string group_id;
  int r = cls_client::dir_get_id(&group_ioctx, RBD_GROUP_DIRECTORY,
				 group_name, &group_id);
  if (r < 0) {
    lderr(cct) << "error reading consistency group id object: "
	       << cpp_strerror(r)
	       << dendl;
    return r;
  }
  string group_header_oid = util::group_header_name(group_id);

  r = group_snap_list(group_ioctx, group_name, &snaps);
  if (r < 0) {
    return r;
  }
  cls::rbd::GroupSnapshot *group_snap = nullptr;
  for (auto &snap : snaps) {
    if (snap.name == string(snap_name)) {
      group_snap = &snap;
      break;
    }
  }
  if (group_snap == nullptr) {
    return -ENOENT;
  }

  r = group_snap_remove_by_record(group_ioctx, *group_snap, group_id,
      group_header_oid);

  return r;
}

template <typename I>
int Group<I>::snap_list(librados::IoCtx& group_ioctx, const char *group_name,
			std::vector<group_snap_spec_t> *snaps)
{
  std::vector<cls::rbd::GroupSnapshot> cls_snaps;

  int r = group_snap_list(group_ioctx, group_name, &cls_snaps);
  if (r < 0) {
    return r;
  }

  for (auto snap : cls_snaps) {
    snaps->push_back(
	group_snap_spec_t {
	   snap.name,
	   static_cast<group_snap_state_t>(snap.state)});

  }
  return 0;
}

template <typename I>
int Group<I>::snap_get_group(I *ictx,
			     uint64_t snap_id,
			     group_snap_t *group_snap) {
    const SnapInfo *snap_info;
    {
      RWLock::RLocker l(ictx->snap_lock);
      snap_info = ictx->get_snap_info(snap_id);
      if (snap_info) {
	GetGroupVisitor ggv = GetGroupVisitor(&ictx->data_ctx);
	int r = boost::apply_visitor(ggv, snap_info->snap_namespace);
	if (r < 0) {
	  return r;
	}
	*group_snap = ggv.group_snap;
      }
    }
    return 0;
}

template <typename I>
int Group<I>::snap_get_namespace_type(I *ictx,
				      uint64_t snap_id,
				      snap_namespace_type_t *namespace_type) {
  const SnapInfo *snap_info;
  {
    RWLock::RLocker l(ictx->snap_lock);
    snap_info = ictx->get_snap_info(snap_id);
    if (snap_info) {
      *namespace_type = static_cast<snap_namespace_type_t>(
			      get_namespace_type(snap_info->snap_namespace));
    }
  }
  return 0;
}


} // namespace api
} // namespace librbd

template class librbd::api::Group<librbd::ImageCtx>;
