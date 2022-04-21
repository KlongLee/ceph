// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * (C) Copyright IBM Corporation 2022
 * Author: Martin Ohmacht <mohmacht@us.ibm.com>
 *
 * Based on the file ceph/src/common/blkdev.cc
 * Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
 *
 * And also based on the file src/erasure-code/clay/ErasureCodeClay.h
 * Copyright (C) 2018 Indian Institute of Science <office.ece@iisc.ac.in>
 *
 * Author: Myna Vajha <mynaramana@gmail.com>
 *
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef CEPH_EXT_BLK_DEV_VDO_H
#define CEPH_EXT_BLK_DEV_VDO_H

#include "extblkdev/ExtBlkDevInterface.h"
#include "include/compat.h"

class ExtBlkDevVdo final : public ceph::ExtBlkDevInterface
{
  int fd = -1;      ///< fd for vdo sysfs directory
  std::string name;
  ceph::ExtBlkDevProfile profile;
public:
  explicit ExtBlkDevVdo(){}
  ~ExtBlkDevVdo(){
    if(fd>=0)
      VOID_TEMP_FAILURE_RETRY(::close(fd));
  }
  static int _get_vdo_stats_handle(const char *devname, std::string *vdo_name);
  static int get_vdo_stats_handle(std::string devname, std::string *vdo_name);
  static int64_t get_vdo_stat(int vdo_fd, const char *property);
  virtual int init(ceph::ExtBlkDevProfile &profile_a, std::ostream *ss);
  virtual const ceph::ExtBlkDevProfile &get_profile() const {return profile;}
  virtual const std::string& get_devname() const {return name;}
  virtual int get_thin_utilization(uint64_t *total, uint64_t *avail, std::ostream *ss);
  virtual int collect_metadata(const std::string& prefix, std::map<std::string,std::string> *pm);
};

#endif
