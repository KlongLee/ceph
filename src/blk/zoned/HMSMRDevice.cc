// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2020 Abutalib Aghayev
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "HMSMRDevice.h"
extern "C" {
#include <libzbd/zbd.h>
}
#include "common/debug.h"
#include "common/errno.h"

#define dout_context cct
#define dout_subsys ceph_subsys_bdev
#undef dout_prefix
#define dout_prefix *_dout << "smrbdev(" << this << " " << path << ") "

using namespace std;

HMSMRDevice::HMSMRDevice(CephContext* cct,
			 aio_callback_t cb,
			 void *cbpriv,
			 aio_callback_t d_cb,
			 void *d_cbpriv)
  : KernelDevice(cct, cb, cbpriv, d_cb, d_cbpriv)
{
}

bool HMSMRDevice::support(const std::string& path)
{
  return zbd_device_is_zoned(path.c_str()) == 1;
}

int HMSMRDevice::_post_open()
{
  dout(10) << __func__ << dendl;

  zbd_fd = zbd_open(path.c_str(), O_RDWR | O_DIRECT | O_LARGEFILE, nullptr);
  if (zbd_fd < 0) {
    derr << __func__ << " zbd_open failed on " << path << ": "
	 << cpp_strerror(errno) << dendl;
    return -errno;
  }

  unsigned int nr_zones = 0;
  std::vector<zbd_zone> zones;
  if (zbd_report_nr_zones(zbd_fd, 0, 0, ZBD_RO_NOT_WP, &nr_zones) != 0) {
    derr << __func__ << " zbd_report_nr_zones failed on " << path << ": "
	 << cpp_strerror(errno) << dendl;
    goto fail;
  }

  zones.resize(nr_zones);
  if (zbd_report_zones(zbd_fd, 0, 0, ZBD_RO_NOT_WP, zones.data(), &nr_zones) != 0) {
    derr << __func__ << " zbd_report_zones failed on " << path << dendl;
    goto fail;
  }

  zone_size = zbd_zone_len(&zones[0]);
  conventional_region_size = nr_zones * zone_size;

  dout(10) << __func__ << " setting zone size to " << zone_size
	   << " and conventional region size to " << conventional_region_size
           << dendl;

  return 0;

fail:
  zbd_close(zbd_fd);
  zbd_fd = -1;
  return -errno;
}


void HMSMRDevice::_pre_close()
{
  if (zbd_fd >= 0) {
    zbd_close(zbd_fd);
    zbd_fd = -1;
  }
}

void HMSMRDevice::reset_all_zones()
{
  dout(10) << __func__ << dendl;
  zbd_reset_zones(zbd_fd, conventional_region_size, 0);
}

void HMSMRDevice::reset_zones(const std::set<uint64_t>& zones)
{
  dout(10) << __func__ << " 0x" << std::hex << zones << std::dec << dendl;
  for (auto zone_num : zones) {
    if (zbd_reset_zones(zbd_fd, zone_num * zone_size, zone_size) != 0) {
      derr << __func__ << " resetting zone failed for zone 0x" << std::hex
	   << zone_num << std::dec << dendl;
    }
  }
}
