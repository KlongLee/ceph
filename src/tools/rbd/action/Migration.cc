// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/errno.h"

#include "tools/rbd/ArgumentTypes.h"
#include "tools/rbd/Shell.h"
#include "tools/rbd/Utils.h"

#include <iostream>
#include <boost/program_options.hpp>

namespace rbd {
namespace action {
namespace migration {

namespace at = argument_types;
namespace po = boost::program_options;

static int do_prepare(librados::IoCtx& io_ctx, const std::string &image_name,
                      librados::IoCtx& dest_io_ctx,
                      const std::string &dest_image_name,
                      librbd::ImageOptions& opts) {
  int r = librbd::RBD().migration_prepare(io_ctx, image_name.c_str(),
                                          dest_io_ctx, dest_image_name.c_str(),
                                          opts);
  if (r < 0) {
    std::cerr << "rbd: preparing migration failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  return 0;
}

static int do_execute(librados::IoCtx& io_ctx, const std::string &image_name,
                      bool no_progress) {
  utils::ProgressContext pc("Image migration", no_progress);
  int r = librbd::RBD().migration_execute_with_progress(io_ctx,
                                                        image_name.c_str(), pc);
  if (r < 0) {
    pc.fail();
    std::cerr << "rbd: migration failed: " << cpp_strerror(r) << std::endl;
    return r;
  }
  pc.finish();
  return 0;
}

static int do_abort(librados::IoCtx& io_ctx, const std::string &image_name,
                    bool no_progress) {
  utils::ProgressContext pc("Abort image migration", no_progress);
  int r = librbd::RBD().migration_abort_with_progress(io_ctx,
                                                      image_name.c_str(), pc);
  if (r < 0) {
    pc.fail();
    std::cerr << "rbd: aborting migration failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  pc.finish();
  return 0;
}

static int do_commit(librados::IoCtx& io_ctx, const std::string &image_name,
                     bool no_progress) {
  utils::ProgressContext pc("Commit image migration", no_progress);
  int r = librbd::RBD().migration_commit_with_progress(io_ctx,
                                                       image_name.c_str(), pc);
  if (r < 0) {
    pc.fail();
    std::cerr << "rbd: committing migration failed: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  pc.finish();
  return 0;
}

void get_prepare_arguments(po::options_description *positional,
                           po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_SOURCE);
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_DEST);
  at::add_create_image_options(options, true);
  at::add_flatten_option(options);
}

int execute_prepare(const po::variables_map &vm,
                    const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_SOURCE, &arg_index, &pool_name, &namespace_name,
    &image_name, nullptr, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, namespace_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  io_ctx.set_osdmap_full_try();

  std::string dest_pool_name;
  std::string dest_namespace_name;
  std::string dest_image_name;
  r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_DEST, &arg_index, &dest_pool_name,
    &dest_namespace_name, &dest_image_name, nullptr, false,
    utils::SNAPSHOT_PRESENCE_NONE, utils::SPEC_VALIDATION_FULL);
  if (r < 0) {
    return r;
  }

  librbd::ImageOptions opts;
  r = utils::get_image_options(vm, true, &opts);
  if (r < 0) {
    return r;
  }

  librados::IoCtx dest_io_ctx;
  if (!dest_pool_name.empty()) {
    r = utils::init_io_ctx(rados, dest_pool_name, dest_namespace_name,
                           &dest_io_ctx);
    if (r < 0) {
      return r;
    }
  }

  r = do_prepare(io_ctx, image_name, dest_pool_name.empty() ? io_ctx :
                 dest_io_ctx, dest_image_name, opts);
  if (r < 0) {
    return r;
  }

  return 0;
}

void get_execute_arguments(po::options_description *positional,
                           po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
}

int execute_execute(const po::variables_map &vm,
                    const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, nullptr, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, namespace_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  io_ctx.set_osdmap_full_try();

  r = do_execute(io_ctx, image_name, vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    return r;
  }

  return 0;
}

void get_abort_arguments(po::options_description *positional,
                          po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
}

int execute_abort(const po::variables_map &vm,
                  const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, nullptr, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, namespace_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  io_ctx.set_osdmap_full_try();

  r = do_abort(io_ctx, image_name, vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    return r;
  }

  return 0;
}

void get_commit_arguments(po::options_description *positional,
                          po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_no_progress_option(options);
}

int execute_commit(const po::variables_map &vm,
                   const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, nullptr, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, namespace_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  io_ctx.set_osdmap_full_try();

  r = do_commit(io_ctx, image_name, vm[at::NO_PROGRESS].as<bool>());
  if (r < 0) {
    return r;
  }

  return 0;
}

Shell::Action action_prepare(
  {"migration", "prepare"}, {}, "Prepare image migration.",
  at::get_long_features_help(), &get_prepare_arguments, &execute_prepare);

Shell::Action action_execute(
  {"migration", "execute"}, {}, "Execute image migration.", "",
  &get_execute_arguments, &execute_execute);

Shell::Action action_abort(
  {"migration", "abort"}, {}, "Cancel interrupted image migration.", "",
  &get_abort_arguments, &execute_abort);

Shell::Action action_commit(
  {"migration", "commit"}, {}, "Commit image migration.", "",
  &get_commit_arguments, &execute_commit);

} // namespace migration
} // namespace action
} // namespace rbd
