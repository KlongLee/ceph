// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph distributed storage system
 *
 * (C) Copyright IBM Corporation 2022
 * Author: Martin Ohmacht <mohmacht@us.ibm.com>
 *
 * Based on the file src/erasure-code/clay/ErasureCodePluginClay.h
 * Copyright (C) 2018 Indian Institute of Science <office.ece@iisc.ac.in>
 *
 * Author: Myna Vajha <mynaramana@gmail.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 * 
 */

#ifndef CEPH_EXT_BLK_DEV_PLUGIN_VDO_H
#define CEPH_EXT_BLK_DEV_PLUGIN_VDO_H

#include "ExtBlkDevVdo.h"

class ExtBlkDevPluginVdo : public ceph::ExtBlkDevPlugin {
public:
  int factory(ceph::ExtBlkDevProfile &profile,
	      ceph::ExtBlkDevInterfaceRef *ext_blk_dev,
	      std::ostream *ss) override;
};

#endif
