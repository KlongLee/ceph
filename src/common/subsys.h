// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */


/**
 * This header describes the subsystems (each one gets a "--debug-<subsystem>"
 * log verbosity setting), along with their default verbosities.
 */

DEFAULT_SUBSYS(0, 5)
SUBSYS(lockdep, 0, 1)
SUBSYS(context, 0, 1)
SUBSYS(crush, 1, 1)
SUBSYS(mds, 1, 5)
SUBSYS(mds_balancer, 1, 5)
SUBSYS(mds_locker, 1, 5)
SUBSYS(mds_log, 1, 5)
SUBSYS(mds_log_expire, 1, 5)
SUBSYS(mds_migrator, 1, 5)
SUBSYS(buffer, 0, 1)
SUBSYS(timer, 0, 1)
SUBSYS(filer, 0, 1)
SUBSYS(striper, 0, 1)
SUBSYS(objecter, 0, 1)
SUBSYS(rados, 0, 5)
SUBSYS(rbd, 0, 5)
SUBSYS(rbd_mirror, 0, 5)
SUBSYS(rbd_replay, 0, 5)
SUBSYS(journaler, 0, 5)
SUBSYS(objectcacher, 0, 5)
SUBSYS(immutable_obj_cache, 0, 5)
SUBSYS(client, 0, 5)
SUBSYS(osd, 1, 5)
SUBSYS(optracker, 0, 5)
SUBSYS(objclass, 0, 5)
SUBSYS(filestore, 1, 3)
SUBSYS(journal, 1, 3)
SUBSYS(ms, 0, 0)
SUBSYS(mon, 1, 5)
SUBSYS(monc, 0, 10)
SUBSYS(paxos, 1, 5)
SUBSYS(tp, 0, 5)
SUBSYS(auth, 1, 5)
SUBSYS(crypto, 1, 5)
SUBSYS(finisher, 1, 1)
SUBSYS(reserver, 1, 1)
SUBSYS(heartbeatmap, 1, 5)
SUBSYS(perfcounter, 1, 5)
SUBSYS(rgw, 1, 5)                 // log level for the Rados gateway
SUBSYS(rgw_sync, 1, 5)
SUBSYS(civetweb, 1, 10)
SUBSYS(javaclient, 1, 5)
SUBSYS(asok, 1, 5)
SUBSYS(throttle, 1, 1)
SUBSYS(refs, 0, 0)
SUBSYS(compressor, 1, 5)
SUBSYS(bluestore, 1, 5)
SUBSYS(bluefs, 1, 5)
SUBSYS(bdev, 1, 3)
SUBSYS(kstore, 1, 5)
SUBSYS(rocksdb, 4, 5)
SUBSYS(leveldb, 4, 5)
SUBSYS(memdb, 4, 5)
SUBSYS(fuse, 1, 5)
SUBSYS(mgr, 1, 5)
SUBSYS(mgrc, 1, 5)
SUBSYS(dpdk, 1, 5)
SUBSYS(eventtrace, 1, 5)
SUBSYS(prioritycache, 1, 5)
SUBSYS(test, 0, 5)
