// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "tools/rbd/ArgumentTypes.h"
#include "tools/rbd/Shell.h"
#include "tools/rbd/Utils.h"
#include "common/errno.h"
#include "common/Formatter.h"
#include "include/rbd/cg_types.h"

namespace rbd {
namespace action {
namespace consgrp {

namespace at = argument_types;
namespace po = boost::program_options;

int execute_create(const po::variables_map &vm) {
  std::string cg_name = utils::get_positional_argument(vm, 0);
  std::string pool_name;
  if (vm.count(at::POOL_NAME)) {
    pool_name = vm[at::POOL_NAME].as<std::string>();
  }

  if (pool_name.empty()) {
    pool_name = at::DEFAULT_POOL_NAME;
  }

  if (cg_name.empty()) {
    std::cerr << "rbd: "
              << "consistency group name was not specified" << std::endl;
    return -EINVAL;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;

  int r = utils::init(pool_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  librbd::RBD rbd;
  r = rbd.create_cg(io_ctx, cg_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: create error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  return 0;
}

int execute_remove(const po::variables_map &vm) {
  std::string cg_name = utils::get_positional_argument(vm, 0);
  std::string pool_name;
  if (vm.count(at::POOL_NAME)) {
    pool_name = vm[at::POOL_NAME].as<std::string>();
  }

  if (pool_name.empty()) {
    pool_name = at::DEFAULT_POOL_NAME;
  }

  if (cg_name.empty()) {
    std::cerr << "rbd: "
              << "consistency group name was not specified" << std::endl;
    return -EINVAL;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;

  int r = utils::init(pool_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }
  librbd::RBD rbd;

  r = rbd.remove_cg(io_ctx, cg_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: remove error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  return 0;
}

int execute_list(const po::variables_map &vm) {

  size_t arg_index = 0;
  std::string pool_name = utils::get_pool_name(vm, &arg_index);

  at::Format::Formatter formatter;
  int r = utils::get_formatter(vm, &formatter);
  if (r < 0) {
    return r;
  }
  Formatter *f = formatter.get();

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }

  librbd::RBD rbd;
  std::vector<std::string> names;
  r = rbd.list_cgs(io_ctx, names);

  if (r == -ENOENT)
    r = 0;
  if (r < 0)
    return r;

  if (f)
    f->open_array_section("consistency_groups");
  for (auto i : names) {
     if (f)
       f->dump_string("name", i);
     else
       std::cout << i << std::endl;
  }
  if (f) {
    f->close_section();
    f->flush(std::cout);
  }


  return 0;
}

int execute_add(const po::variables_map &vm) {
  //size_t arg_index = 0;
  std::string pool_name;
  std::string cg_name;

  std::string image_pool_name;
  std::string image_name;

  if (vm.count(at::POOL_NAME)) {
    pool_name = vm[at::POOL_NAME].as<std::string>();
  }

  if (vm.count(at::CG_NAME)) {
    cg_name = vm[at::CG_NAME].as<std::string>();
  }

  std::string image_spec = utils::get_positional_argument(vm, 0);
  int r = utils::extract_spec(image_spec, &image_pool_name,
                              &image_name, nullptr);
  if (r < 0) {
    std::cerr << "rbd: image add error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  if (pool_name.empty()) {
    pool_name = at::DEFAULT_POOL_NAME;
  }

  if (cg_name.empty()) {
    std::cerr << "rbd: consistency group name was not specified" << std::endl;
    return -EINVAL;
  }

  if (image_pool_name.empty()) {
    image_pool_name = at::DEFAULT_POOL_NAME;
  }

  if (image_name.empty()) {
    std::cerr << "rbd: image name was not specified" << std::endl;
    return -EINVAL;
  }

  librados::Rados rados;

  librados::IoCtx cg_io_ctx;
  r = utils::init(pool_name, &rados, &cg_io_ctx);
  if (r < 0) {
    return r;
  }

  librados::IoCtx image_io_ctx;
  r = utils::init(image_pool_name, &rados, &image_io_ctx);
  if (r < 0) {
    return r;
  }

  librbd::RBD rbd;
  r = rbd.cg_add_image(cg_io_ctx, cg_name.c_str(),
                       image_io_ctx, image_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: add image error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  return 0;
}

int execute_remove_image(const po::variables_map &vm) {
  std::string pool_name;
  std::string cg_name;

  std::string image_pool_name;
  std::string image_name;

  if (vm.count(at::POOL_NAME)) {
    pool_name = vm[at::POOL_NAME].as<std::string>();
  }

  if (vm.count(at::CG_NAME)) {
    cg_name = vm[at::CG_NAME].as<std::string>();
  }

  std::string image_spec = utils::get_positional_argument(vm, 0);
  int r = utils::extract_spec(image_spec, &image_pool_name,
                              &image_name, nullptr);
  if (r < 0) {
    std::cerr << "rbd: image remove error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  if (pool_name.empty()) {
    pool_name = at::DEFAULT_POOL_NAME;
  }

  if (cg_name.empty()) {
    std::cerr << "rbd: "
              << "consistency group name was not specified" << std::endl;
    return -EINVAL;
  }

  if (image_pool_name.empty()) {
    image_pool_name = at::DEFAULT_POOL_NAME;
  }

  if (image_name.empty()) {
    std::cerr << "rbd: "
              << "image name was not specified" << std::endl;
    return -EINVAL;
  }

  librados::Rados rados;

  librados::IoCtx cg_io_ctx;
  r = utils::init(pool_name, &rados, &cg_io_ctx);
  if (r < 0) {
    return r;
  }

  librados::IoCtx image_io_ctx;
  r = utils::init(image_pool_name, &rados, &image_io_ctx);
  if (r < 0) {
    return r;
  }

  librbd::RBD rbd;
  r = rbd.cg_remove_image(cg_io_ctx, cg_name.c_str(),
                          image_io_ctx, image_name.c_str());
  if (r < 0) {
    std::cerr << "rbd: remove image error: " << cpp_strerror(r) << std::endl;
    return r;
  }

  return 0;
}

int execute_list_images(const po::variables_map &vm) {
  std::string cg_name = utils::get_positional_argument(vm, 0);
  size_t arg_index = 1;
  std::string pool_name = utils::get_pool_name(vm, &arg_index);

  if (pool_name.empty()) {
    pool_name = at::DEFAULT_POOL_NAME;
  }

  if (cg_name.empty()) {
    std::cerr << "rbd: "
              << "consistency group name was not specified" << std::endl;
    return -EINVAL;
  }

  at::Format::Formatter formatter;
  int r = utils::get_formatter(vm, &formatter);
  if (r < 0) {
    return r;
  }
  Formatter *f = formatter.get();

  librados::Rados rados;
  librados::IoCtx io_ctx;
  r = utils::init(pool_name, &rados, &io_ctx);
  if (r < 0) {
    return r;
  }

  librbd::RBD rbd;
  std::vector<std::tuple<std::string, int64_t, int>> images;

  r = rbd.cg_list_images(io_ctx, cg_name.c_str(), images);

  if (r == -ENOENT)
    r = 0;
  if (r < 0)
    return r;

  if (f)
    f->open_array_section("consistency_groups");
  for (auto i : images) {
    std::string image_name = std::get<0>(i);
    int64_t pool_id = std::get<1>(i);
    int state = std::get<2>(i);
    std::string state_string;
    if (LINK_DIRTY == state) {
      state_string = "dirty";
    }
    if (r < 0)
      return r;
    if (f) {
      f->dump_string("image name", image_name);
      f->dump_int("pool id", pool_id);
      f->dump_int("state", state);
    } else
      std::cout << pool_id << "." << image_name << " " << state_string << std::endl;
  }
  if (f) {
    f->close_section();
    f->flush(std::cout);
  }

  return 0;
}

void get_create_arguments(po::options_description *positional,
                          po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()(at::CG_NAME.c_str(), "Name of consistency group");
}

void get_remove_arguments(po::options_description *positional,
                          po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()(at::CG_NAME.c_str(), "Name of consistency group");
}

void get_list_arguments(po::options_description *positional,
                        po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  at::add_format_options(options);
}

void get_add_arguments(po::options_description *positional,
                       po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  at::add_cg_option(options);
  positional->add_options()
    (at::IMAGE_SPEC.c_str(),
     "image specification\n"
     "(example: [<pool-name>/]<image-name>)");
}

void get_remove_image_arguments(po::options_description *positional,
                                po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  at::add_cg_option(options);
  positional->add_options()
    (at::IMAGE_SPEC.c_str(),
     "image specification\n"
     "(example: [<pool-name>/]<image-name>)");
}

void get_list_images_arguments(po::options_description *positional,
                               po::options_description *options) {
  add_pool_option(options, at::ARGUMENT_MODIFIER_NONE);
  at::add_format_options(options);
  positional->add_options()(at::CG_NAME.c_str(), "Name of consistency group");
}

Shell::Action action_create(
  {"cg", "create"}, {}, "Create a consistency group.",
  "", &get_create_arguments, &execute_create);
Shell::Action action_remove(
  {"cg", "remove"}, {"cg", "rm"}, "Delete a consistency group.",
  "", &get_remove_arguments, &execute_remove);
Shell::Action action_list(
  {"cg", "list"}, {"cg", "ls"}, "Dump list of consistency groups.",
  "", &get_list_arguments, &execute_list);
Shell::Action action_add(
  {"cg", "image", "add"}, {}, "Add an image to a consistency group.",
  "", &get_add_arguments, &execute_add);
Shell::Action action_remove_image(
  {"cg", "image", "remove"}, {}, "Remove an image from a consistency group.",
  "", &get_remove_image_arguments, &execute_remove_image);
Shell::Action action_list_images(
  {"cg", "images", "list"}, {}, "Dump list of images in a consistency group.",
  "", &get_list_images_arguments, &execute_list_images);
} // namespace snap
} // namespace action
} // namespace rbd
