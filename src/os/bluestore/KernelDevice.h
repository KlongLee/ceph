// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef CEPH_OS_BLUESTORE_KERNELDEVICE_H
#define CEPH_OS_BLUESTORE_KERNELDEVICE_H

#include <atomic>

#include "include/types.h"
#include "include/interval_set.h"
#include "common/Thread.h"
#include "include/utime.h"

#include "ceph_aio.h"
#include "BlockDevice.h"

#define RW_IO_MAX (INT_MAX & CEPH_PAGE_MASK)


class KernelDevice : public BlockDevice {
  std::vector<int> fd_directs, fd_buffereds;
  bool enable_wrt = true;
  std::string path;
  bool aio, dio;

  int vdo_fd = -1;      ///< fd for vdo sysfs directory
  string vdo_name;

  std::string devname;  ///< kernel dev name (/sys/block/$devname), if any

  ceph::mutex debug_lock = ceph::make_mutex("KernelDevice::debug_lock");
  interval_set<uint64_t> debug_inflight;

  std::atomic<bool> io_since_flush = {false};
  ceph::mutex flush_mutex = ceph::make_mutex("KernelDevice::flush_mutex");

  std::unique_ptr<io_queue_t> io_queue;
  aio_callback_t discard_callback;
  void *discard_callback_priv;
  bool aio_stop;
  bool discard_started;
  bool discard_stop;

  ceph::mutex discard_lock = ceph::make_mutex("KernelDevice::discard_lock");
  ceph::condition_variable discard_cond;
  bool discard_running = false;
  interval_set<uint64_t> discard_queued;
  interval_set<uint64_t> discard_finishing;

  struct AioCompletionThread : public Thread {
    KernelDevice *bdev;
    explicit AioCompletionThread(KernelDevice *b) : bdev(b) {}
    void *entry() override {
      bdev->_aio_thread();
      return NULL;
    }
  } aio_thread;

  struct DiscardThread : public Thread {
    KernelDevice *bdev;
    explicit DiscardThread(KernelDevice *b) : bdev(b) {}
    void *entry() override {
      bdev->_discard_thread();
      return NULL;
    }
  } discard_thread;

  std::atomic_int injecting_crash;

  void _aio_thread();
  void _discard_thread();
  int queue_discard(interval_set<uint64_t> &to_release) override;

  int _aio_start();
  void _aio_stop();

  int _discard_start();
  void _discard_stop();

  void _aio_log_start(IOContext *ioc, uint64_t offset, uint64_t length);
  void _aio_log_finish(IOContext *ioc, uint64_t offset, uint64_t length);

  int _sync_write(uint64_t off, bufferlist& bl, bool buffered, int write_hint);

  int _lock();

  int direct_read_unaligned(uint64_t off, uint64_t len, char *buf);

  // stalled aio debugging
  aio_list_t debug_queue;
  ceph::mutex debug_queue_lock = ceph::make_mutex("KernelDevice::debug_queue_lock");
  aio_t *debug_oldest = nullptr;
  utime_t debug_stall_since;
  void debug_aio_link(aio_t& aio);
  void debug_aio_unlink(aio_t& aio);

  void _detect_vdo();
  int choose_fd(bool buffered, int write_hint) const;

public:
  KernelDevice(CephContext* cct, aio_callback_t cb, void *cbpriv, aio_callback_t d_cb, void *d_cbpriv);

  void aio_submit(IOContext *ioc) override;
  void discard_drain() override;

  int collect_metadata(const std::string& prefix, map<std::string,std::string> *pm) const override;
  int get_devname(std::string *s) const override {
    if (devname.empty()) {
      return -ENOENT;
    }
    *s = devname;
    return 0;
  }
  int get_devices(std::set<std::string> *ls) const override;

  bool get_thin_utilization(uint64_t *total, uint64_t *avail) const override;

  int read(uint64_t off, uint64_t len, bufferlist *pbl,
	   IOContext *ioc,
	   bool buffered) override;
  int aio_read(uint64_t off, uint64_t len, bufferlist *pbl,
	       IOContext *ioc) override;
  int read_random(uint64_t off, uint64_t len, char *buf, bool buffered) override;

  int write(uint64_t off, bufferlist& bl, bool buffered, int write_hint = WRITE_LIFE_NOT_SET) override;
  int aio_write(uint64_t off, bufferlist& bl,
		IOContext *ioc,
		bool buffered,
		int write_hint = WRITE_LIFE_NOT_SET) override;
  int flush() override;
  int discard(uint64_t offset, uint64_t len) override;

  // for managing buffered readers/writers
  int invalidate_cache(uint64_t off, uint64_t len) override;
  int open(const std::string& path) override;
  void close() override;
};

#endif
