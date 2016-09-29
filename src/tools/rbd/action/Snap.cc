// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "tools/rbd/ArgumentTypes.h"
#include "tools/rbd/Shell.h"
#include "tools/rbd/Utils.h"
#include "include/types.h"
#include "include/stringify.h"
#include "common/errno.h"
#include "common/Formatter.h"
#include "common/TextTable.h"
#include <iostream>
#include <boost/program_options.hpp>

namespace rbd {
namespace action {
namespace snap {

namespace at = argument_types;
namespace po = boost::program_options;

static bool is_not_user_snap_namespace(const librbd::snap_info_t &snap_info)
{
  return boost::get<librbd::user_snap_namespace_t>(&snap_info.snap_namespace) ==
	 nullptr;
}

class ToStringVisitor : public boost::static_visitor<std::string> {
public:
  template <typename T>
  inline std::string operator()(const T& t) const {
    return t.to_string();
  }
};

class FormatVisitor : public boost::static_visitor<void> {
public:

  explicit FormatVisitor(ceph::Formatter *f) : formatter(f) {}

  template <typename T>
  inline void operator()(const T& t) const {
    t.dump(formatter);
  }
private:
  ceph::Formatter *formatter;

};

int do_list_snaps(librbd::Image& image, Formatter *f, bool all_snaps)
{
  std::vector<librbd::snap_info_t> snaps;
  TextTable t;
  int r;

  r = image.snap_list(snaps);
  if (r < 0)
    return r;

  if (!all_snaps) {
    snaps.erase(remove_if(snaps.begin(),
			  snaps.end(),
			  is_not_user_snap_namespace),
		snaps.end());
  }

  if (f) {
    f->open_array_section("snapshots");
  } else {
    t.define_column("SNAPID", TextTable::RIGHT, TextTable::RIGHT);
    t.define_column("NAME", TextTable::LEFT, TextTable::LEFT);
    t.define_column("SIZE", TextTable::RIGHT, TextTable::RIGHT);
    if (all_snaps) {
      t.define_column("NAMESPACE", TextTable::LEFT, TextTable::LEFT);
    }
  }

  for (std::vector<librbd::snap_info_t>::iterator s = snaps.begin();
       s != snaps.end(); ++s) {
    if (f) {
      f->open_object_section("snapshot");
      f->dump_unsigned("id", s->id);
      f->dump_string("name", s->name);
      f->dump_unsigned("size", s->size);
      if (all_snaps) {
	f->open_object_section("namespace");
	boost::apply_visitor(FormatVisitor(f), s->snap_namespace);
	f->close_section();
      }
      f->close_section();
    } else {
      std::string namespace_string;
      if (all_snaps) {
	namespace_string = static_cast<std::string>(
				  boost::apply_visitor(ToStringVisitor(),
						       s->snap_namespace));
      }
      t << s->id << s->name << stringify(prettybyte_t(s->size));
      if (all_snaps) {
	t << namespace_string;
      }
      t << TextTable::endrow;
    }
  }

  if (f) {
    f->close_section();
    f->flush(std::cout);
  } else if (snaps.size()) {
    std::cout << t;
  }

  return 0;
}

int do_add_snap(librbd::Image& image, const char *snapname)
{
  int r = image.snap_create(snapname);
  if (r < 0)
    return r;

  return 0;
}

int do_remove_snap(librbd::Image& image, const char *snapname, bool force,
		   bool no_progress)
{
  uint32_t flags = force? RBD_SNAP_REMOVE_FORCE : 0;
  int r = 0;
  utils::ProgressContext pc("Removing snap", no_progress);
  
  r = image.snap_remove2(snapname, flags, pc);
  if (r < 0) {
    pc.fail();
    return r;
  }

  pc.finish();
  return 0;
}

int do_rollback_snap(librbd::Image& image, const char *snapname,
                     bool no_progress)
{
  utils::ProgressContext pc("Rolling back to snapshot", no_progress);
  int r = image.snap_rollback_with_progress(snapname, pc);
  if (r < 0) {
    pc.fail();
    return r;
  }
  pc.finish();
  return 0;
}

int do_purge_snaps(librbd::Image& image, bool no_progress)
{
  utils::ProgressContext pc("Removing all snapshots", no_progress);
  std::vector<librbd::snap_info_t> snaps;
  bool is_protected = false;
  int r = image.snap_list(snaps);
  if (r < 0) {
    pc.fail();
    return r;
  } else if (0 == snaps.size()) {
    return 0;
  } else {
    for (size_t i = 0; i < snaps.size(); ++i) {
      r = image.snap_is_protected(snaps[i].name.c_str(), &is_protected);
      if (r < 0) {
        pc.fail();
        return r;
      } else if (is_protected == true) {
        pc.fail();
        std::cerr << "\r" << "rbd: snapshot '" << snaps[i].name.c_str()
                  << "' is protected from removal." << std::endl;
        return -EBUSY;
      }
    }
    for (size_t i = 0; i < snaps.size(); ++i) {
      r = image.snap_remove(snaps[i].name.c_str());
      if (r < 0) {
        pc.fail();
        return r;
      }
      pc.update_progress(i + 1, snaps.size());
    }

    pc.finish();
    return 0;
  }
}

int do_protect_snap(librbd::Image& image, const char *snapname)
{
  int r = image.snap_protect(snapname);
  if (r < 0)
    return r;

  return 0;
}

int do_unprotect_snap(librbd::Image& image, const char *snapname)
{
  int r = image.snap_unprotect(snapname);
  if (r < 0)
    return r;

  return 0;
}

int do_set_limit(librbd::Image& image, uint64_t limit)
{
  return image.snap_set_limit(limit);
}

int do_clear_limit(librbd::Image& image)
{
  return image.snap_set_limit(UINT64_MAX);
}

void get_list_arguments(po::options_description *positional,
                        po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_format_options(options);
  at::add_all_option(options, "list snapshots from all namespaces");
}

int execute_list(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  bool all_snaps = vm[at::ALL_NAME].as<bool>();
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_NONE, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  at::Format::Formatter formatter;
  r = utils::get_formatter(vm, &formatter);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", true, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = do_list_snaps(image, formatter.get(), all_snaps);
  if (r < 0) {
    cerr << "rbd: failed to list snapshots: " << cpp_strerror(r)
         << std::endl;
    return r;
  }
  return 0;
}

void get_create_arguments(po::options_description *positional,
                          po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
}

int execute_create(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED, utils::SPEC_VALIDATION_SNAP);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = do_add_snap(image, snap_name.c_str());
  if (r < 0) {
    cerr << "rbd: failed to create snapshot: " << cpp_strerror(r)
         << std::endl;
    return r;
  }
  return 0;
}

void get_remove_arguments(po::options_description *positional,
                          po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
  
  options->add_options()
    ("force", po::bool_switch(), "flatten children and unprotect snapshot if needed.");
}

int execute_remove(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  bool force = vm["force"].as<bool>();
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = do_remove_snap(image, snap_name.c_str(), force, vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    if (r == -EBUSY) {
      std::cerr << "rbd: snapshot '" << snap_name << "' "
                << "is protected from removal." << std::endl;
    } else {
      std::cerr << "rbd: failed to remove snapshot: " << cpp_strerror(r)
                << std::endl;
    }
    return r;
  }
  return 0;
}

void get_purge_arguments(po::options_description *positional,
                         po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
}

int execute_purge(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_NONE, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = do_purge_snaps(image, vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    if (r != -EBUSY) {
      std::cerr << "rbd: removing snaps failed: " << cpp_strerror(r)
                << std::endl;
    }
    return r;
  }
  return 0;
}

void get_rollback_arguments(po::options_description *positional,
                            po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
}

int execute_rollback(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = do_rollback_snap(image, snap_name.c_str(),
                       vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    std::cerr << "rbd: rollback failed: " << cpp_strerror(r) << std::endl;
    return r;
  }
  return 0;
}

void get_protect_arguments(po::options_description *positional,
                           po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
}

int execute_protect(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  bool is_protected = false;
  r = image.snap_is_protected(snap_name.c_str(), &is_protected);
  if (r < 0) {
    std::cerr << "rbd: protecting snap failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  } else if (is_protected) {
    std::cerr << "rbd: snap is already protected" << std::endl;
    return -EBUSY;
  }

  r = do_protect_snap(image, snap_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: protecting snap failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  return 0;
}

void get_unprotect_arguments(po::options_description *positional,
                             po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
}

int execute_unprotect(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED, utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }
  
  bool is_protected = false;
  r = image.snap_is_protected(snap_name.c_str(), &is_protected);
  if (r < 0) {
    std::cerr << "rbd: unprotecting snap failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  } else if (!is_protected) {
    std::cerr << "rbd: snap is already unprotected" << std::endl;
    return -EINVAL;
  }

  r = do_unprotect_snap(image, snap_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: unprotecting snap failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  return 0;
}

void get_set_limit_arguments(po::options_description *pos,
			     po::options_description *opt) {
  at::add_image_spec_options(pos, opt, at::ARGUMENT_MODIFIER_NONE);
  at::add_limit_option(opt);
}

int execute_set_limit(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;
  uint64_t limit;

  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_NONE, utils::SPEC_VALIDATION_NONE);

  if (vm.count(at::LIMIT)) {
    limit = vm[at::LIMIT].as<uint64_t>();
  } else {
    return -ERANGE;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
				 &io_ctx, &image);
  if (r < 0) {
      return r;
  }

  r = do_set_limit(image, limit);
  if (r < 0) {
    std::cerr << "rbd: setting snapshot limit failed: " << cpp_strerror(r)
	      << std::endl;
    return r;
  }
  return 0;
}

void get_clear_limit_arguments(po::options_description *pos,
			       po::options_description *opt) {
  at::add_image_spec_options(pos, opt, at::ARGUMENT_MODIFIER_NONE);
}

int execute_clear_limit(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string snap_name;

  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &image_name,
    &snap_name, utils::SNAPSHOT_PRESENCE_NONE, utils::SPEC_VALIDATION_NONE);

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
				 &io_ctx, &image);
  if (r < 0) {
      return r;
  }

  r = do_clear_limit(image);
  if (r < 0) {
    std::cerr << "rbd: clearing snapshot limit failed: " << cpp_strerror(r)
	      << std::endl;
    return r;
  }
  return 0;
}

void get_rename_arguments(po::options_description *positional,
                          po::options_description *options) {
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_SOURCE);
  at::add_snap_spec_options(positional, options, at::ARGUMENT_MODIFIER_DEST);
}

int execute_rename(const po::variables_map &vm) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string image_name;
  std::string src_snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_SOURCE, &arg_index, &pool_name, &image_name,
    &src_snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return -r;
  }

  std::string dest_pool_name(pool_name);
  std::string dest_image_name;
  std::string dest_snap_name;
  r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_DEST, &arg_index, &dest_pool_name,
    &dest_image_name, &dest_snap_name, utils::SNAPSHOT_PRESENCE_REQUIRED,
    utils::SPEC_VALIDATION_SNAP);
  if (r < 0) {
    return -r;
  }

  if (pool_name != dest_pool_name) {
    std::cerr << "rbd: source and destination pool must be the same"
              << std::endl;
    return -EINVAL;
  } else if (image_name != dest_image_name) {
    std::cerr << "rbd: source and destination image name must be the same"
              << std::endl;
    return -EINVAL;
  }
  
  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, image_name, "", false, &rados,
                                 &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = image.snap_rename(src_snap_name.c_str(), dest_snap_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: renaming snap failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  return 0;
}

Shell::Action action_list(
  {"snap", "list"}, {"snap", "ls"}, "Dump list of image snapshots.", "",
  &get_list_arguments, &execute_list);
Shell::Action action_create(
  {"snap", "create"}, {"snap", "add"}, "Create a snapshot.", "",
  &get_create_arguments, &execute_create);
Shell::Action action_remove(
  {"snap", "remove"}, {"snap", "rm"}, "Deletes a snapshot.", "",
  &get_remove_arguments, &execute_remove);
Shell::Action action_purge(
  {"snap", "purge"}, {}, "Deletes all snapshots.", "",
  &get_purge_arguments, &execute_purge);
Shell::Action action_rollback(
  {"snap", "rollback"}, {"snap", "revert"}, "Rollback image to snapshot.", "",
  &get_rollback_arguments, &execute_rollback);
Shell::Action action_protect(
  {"snap", "protect"}, {}, "Prevent a snapshot from being deleted.", "",
  &get_protect_arguments, &execute_protect);
Shell::Action action_unprotect(
  {"snap", "unprotect"}, {}, "Allow a snapshot to be deleted.", "",
  &get_unprotect_arguments, &execute_unprotect);
Shell::Action action_set_limit(
  {"snap", "limit", "set"}, {}, "Limit the number of snapshots.", "",
  &get_set_limit_arguments, &execute_set_limit);
Shell::Action action_clear_limit(
  {"snap", "limit", "clear"}, {}, "Remove snapshot limit.", "",
  &get_clear_limit_arguments, &execute_clear_limit);
Shell::Action action_rename(
  {"snap", "rename"}, {}, "Rename a snapshot.", "",
  &get_rename_arguments, &execute_rename);

} // namespace snap
} // namespace action
} // namespace rbd
