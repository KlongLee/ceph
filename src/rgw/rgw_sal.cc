// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <system_error>
#include <unistd.h>
#include <sstream>

#include "common/errno.h"
//#include "common/dout.h"

#include "rgw_sal.h"
#include "rgw_sal_rados.h"
#include "driver/rados/config/store.h"
#include "driver/json_config/store.h"
#include "rgw_d3n_datacache.h"

#ifdef WITH_RADOSGW_DBSTORE
#include "rgw_sal_dbstore.h"
#include "driver/dbstore/config/store.h"
#endif
#ifdef WITH_RADOSGW_D4N
#include "driver/d4n/rgw_sal_d4n.h" 
#endif

#ifdef WITH_RADOSGW_MOTR
#include "driver/motr/rgw_sal_motr.h"
#endif

#ifdef WITH_RADOSGW_DAOS
#include "driver/daos/rgw_sal_daos.h"
#endif

#define dout_subsys ceph_subsys_rgw
//#define dout_context g_ceph_context

extern "C" {
#ifdef WITH_RADOSGW_POSIX
extern rgw::sal::Driver* newPOSIXDriver(rgw::sal::Driver* next,
                                        void* io_context);
#endif
extern rgw::sal::Driver *newBaseFilter(rgw::sal::Driver *next,
                                       void* io_context);
#ifdef WITH_RADOSGW_D4N 
extern rgw::sal::Driver* newD4NFilter(rgw::sal::Driver* next,
                                      void* io_context);
#endif
}

static const char* drivers[] = {
  "rados",
  "d3n",
#ifdef WITH_RADOSGW_DBSTORE
  "dbstore",
#endif
#ifdef WITH_RADOSGW_MOTR
  "motr",
#endif
#ifdef WITH_RADOSGW_DAOS
  "daos",
#endif
};

static const char* filters[] = {
  "base",
#ifdef WITH_RADOSGW_D4N 
  "d4n",
#endif
#ifdef WITH_RADOSGW_POSIX
  "posix",
#endif
};

static const int dlopen_flags = RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND;

rgw::sal::Driver *DriverManager::init_storage_provider(const DoutPrefixProvider* dpp,
                                                       CephContext* cct,
                                                       const Config& cfg,
                                                       boost::asio::io_context& io_context,
                                                       const rgw::SiteConfig& site_config,
                                                       bool use_gc_thread,
                                                       bool use_lc_thread,
                                                       bool quota_threads,
                                                       bool run_sync_thread,
                                                       bool run_reshard_thread,
                                                       bool run_notification_thread,
                                                       bool use_cache,
                                                       bool use_gc, optional_yield y)
{
  rgw::sal::Driver *driver = nullptr;
  rgw::sal::Driver *next = nullptr;
  void *dl = nullptr;
  bool is_driver = false;
  bool is_filter = false;
  rgw::sal::rgw_sal_new_driver_fn newDriver = nullptr;
  auto plugin_dir = cct->_conf.get_val<std::string>("plugin_dir");
  auto dlname = (plugin_dir.ends_with("/ceph")
    ? fmt::format("{}/rgw_sal/librgw_sal_{}.so", plugin_dir, cfg.store_name)
    : fmt::format("{}/ceph/rgw_sal/librgw_sal_{}.so", plugin_dir, cfg.store_name));
  for (unsigned int i = 0; i < sizeof drivers/sizeof drivers[0]; i++) {
    if (cfg.store_name.compare(drivers[i])) {
      is_driver = true; break;
    }
  }
  if (is_driver) {
    dl = dlopen(dlname.c_str(), dlopen_flags);
    if (dl) {
      newDriver = (rgw::sal::rgw_sal_new_driver_fn)dlsym(dl, "new_Driver");
      if (newDriver)
        driver = newDriver(dpp, cct, false, io_context, site_config, use_gc_thread, use_lc_thread, quota_threads, run_sync_thread, run_reshard_thread, run_notification_thread, use_cache, use_gc, y);
      // if (dlclose(dl) < 0)
      //   ldpp_dout(dpp, 0) << "WARNING: dlclose() failed" << dendl;
    } else {
      auto scratch = fmt::format("couldn't open {}", dlname.c_str());
      std::cerr << scratch.c_str() << std::endl;
    }
    driver->dl = dl;

    if (driver->initialize(cct, dpp) < 0) {
      delete driver;
      return nullptr;
    }
  }

  for (unsigned int i = 0; i < sizeof filters/sizeof filters[0]; i++) {
    if (cfg.filter_name.compare(filters[i])) {
      is_filter = true; break;
    }
  }
  if (is_filter) {
    if (cfg.filter_name.compare("base") == 0) {
      next = driver;
      driver = newBaseFilter(next, &io_context);
    }
#ifdef WITH_RADOSGW_D4N 
    else if (cfg.filter_name.compare("d4n") == 0) {
      next = driver;
      driver = newD4NFilter(next, &io_context);
    }
#endif
#ifdef WITH_RADOSGW_POSIX
    else if (cfg.filter_name.compare("posix") == 0) {
      ldpp_dout(dpp, 20) << "Creating POSIX driver" << dendl;
      next = driver;
      driver = newPOSIXDriver(next, &io_context);
    }
#endif
    if (driver->initialize(cct, dpp) < 0) {
      delete driver;
      delete next;
      return nullptr;
    }
  }
  return driver;
}

static const char* raw_drivers[] = {
  "rados",
#ifdef WITH_RADOSGW_DBSTORE
  "dbstore",
#endif
#ifdef WITH_RADOSGW_MOTR
  "motr",
#endif
#ifdef WITH_RADOSGW_DAOS
  "daos",
#endif
};

static const char* raw_filters[] = {
  "base",
};

rgw::sal::Driver *DriverManager::init_raw_storage_provider(const DoutPrefixProvider* dpp,
                                                           CephContext* cct,
                                                           const Config& cfg,
                                                           boost::asio::io_context& io_context,
                                                           const rgw::SiteConfig& site_config)
{
  rgw::sal::Driver *driver = nullptr;
  rgw::sal::Driver *next = nullptr;
  bool is_driver = false;
  bool is_filter = false;
  void *dl = nullptr;
  rgw::sal::rgw_sal_new_driver_fn newDriver = nullptr;
  auto plugin_dir = cct->_conf.get_val<std::string>("plugin_dir");
  auto dlname = (plugin_dir.ends_with("/ceph")
    ? fmt::format("{}/rgw_sal/librgw_sal_{}.so", plugin_dir, cfg.store_name)
    : fmt::format("{}/ceph/rgw_sal/librgw_sal_{}.so", plugin_dir, cfg.store_name));
  for (unsigned int i = 0; i < sizeof raw_drivers/sizeof raw_drivers[0]; i++) {
    if (cfg.store_name.compare(drivers[i])) {
      is_driver = true; break;
    }
  }
  if (is_driver) {
    dl = dlopen(dlname.c_str(), dlopen_flags);
    if (dl) {
      newDriver = (rgw::sal::rgw_sal_new_driver_fn)dlsym(dl, "new_Driver");
      if (newDriver)
        driver = newDriver(dpp, cct, true, io_context, site_config, false, false, false, false, false, false, false, false, null_yield);
      // if (dlclose(dl) < 0)
      //  ldpp_dout(dpp, 0) << "WARNING: dlclose() failed" << dendl;
    }
    driver->dl = dl;

    if (driver->initialize(cct, dpp) < 0) {
      delete driver;
      return nullptr;
    }
  }

  for (unsigned int i = 0; i < sizeof raw_filters/sizeof raw_filters[0]; i++) {
    if (cfg.filter_name.compare(raw_filters[i])) {
      is_filter = true; break;
    }
  }
  if (is_filter) {
    if (cfg.filter_name.compare("base") == 0) {
      next = driver;
      driver = newBaseFilter(next, &io_context);
    }

    if (driver->initialize(cct, dpp) < 0) {
      delete driver;
      delete next;
      return nullptr;
    }
  }

  return driver;
}

void DriverManager::close_storage(rgw::sal::Driver *driver)
{
  // void *dl = nullptr; // FIXME

  if (!driver)
    return;

  // dl = driver->dl; driver->dl = nullptr; // FIXME

  driver->finalize();

  delete driver;

  // FIXME
  // if (dl)
  //   dlclose(dl);
}

DriverManager::Config DriverManager::get_config(bool admin, CephContext* cct)
{
  DriverManager::Config cfg;

  // make sure the plugin registry is up
  cfg.plugin_reg = cct->get_plugin_registry();

  // Get the store backend
  const auto& config_store = g_conf().get_val<std::string>("rgw_backend_store");
  if (config_store == "rados") {
    cfg.store_name = "rados";

    /* Check to see if d3n is configured, but only for non-admin */
    const auto& d3n = g_conf().get_val<bool>("rgw_d3n_l1_local_datacache_enabled");
    if (!admin && d3n) {
      if (g_conf().get_val<Option::size_t>("rgw_max_chunk_size") !=
	  g_conf().get_val<Option::size_t>("rgw_obj_stripe_size")) {
	lsubdout(cct, rgw_datacache, 0) << "rgw_d3n:  WARNING: D3N DataCache disabling (D3N requires that the chunk_size equals stripe_size)" << dendl;
      } else if (!g_conf().get_val<bool>("rgw_beast_enable_async")) {
	lsubdout(cct, rgw_datacache, 0) << "rgw_d3n:  WARNING: D3N DataCache disabling (D3N requires yield context - rgw_beast_enable_async=true)" << dendl;
      } else {
	cfg.store_name = "d3n";
      }
    }
  }
#ifdef WITH_RADOSGW_DBSTORE
  else if (config_store == "dbstore") {
    cfg.store_name = "dbstore";
  }
#endif
#ifdef WITH_RADOSGW_MOTR
  else if (config_store == "motr") {
    cfg.store_name = "motr";
  }
#endif
#ifdef WITH_RADOSGW_DAOS
  else if (config_store == "daos") {
    cfg.store_name = "daos";
  }
#endif

  // Get the filter
  cfg.filter_name = "none";
  const auto& config_filter = g_conf().get_val<std::string>("rgw_filter");
  if (config_filter == "base") {
    cfg.filter_name = "base";
  } else if (config_filter == "posix") {
    cfg.filter_name = "posix";
  }
#ifdef WITH_RADOSGW_D4N
  else if (config_filter == "d4n") {
    cfg.filter_name= "d4n";
  }
#endif

  return cfg;
}

namespace rgw::sal {
int Object::range_to_ofs(uint64_t obj_size, int64_t &ofs, int64_t &end)
{
  if (ofs < 0) {
    ofs += obj_size;
    if (ofs < 0)
      ofs = 0;
    end = obj_size - 1;
  } else if (end < 0) {
    end = obj_size - 1;
  }

  if (obj_size > 0) {
    if (ofs >= (off_t)obj_size) {
      return -ERANGE;
    }
    if (end >= (off_t)obj_size) {
      end = obj_size - 1;
    }
  }
  return 0;
}
}
