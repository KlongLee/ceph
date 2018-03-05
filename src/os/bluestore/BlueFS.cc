// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "boost/algorithm/string.hpp" 
#include "BlueFS.h"

#include "common/debug.h"
#include "common/errno.h"
#include "common/perf_counters.h"
#include "BlockDevice.h"
#include "Allocator.h"
#include "include/ceph_assert.h"

#define dout_context cct
#define dout_subsys ceph_subsys_bluefs
#undef dout_prefix
#define dout_prefix *_dout << "bluefs "

MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::File, bluefs_file, bluefs);
MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::Dir, bluefs_dir, bluefs);
MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::FileWriter, bluefs_file_writer, bluefs);
MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::FileReaderBuffer,
			      bluefs_file_reader_buffer, bluefs);
MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::FileReader, bluefs_file_reader, bluefs);
MEMPOOL_DEFINE_OBJECT_FACTORY(BlueFS::FileLock, bluefs_file_lock, bluefs);

static void wal_discard_cb(void *priv, void* priv2) {
  BlueFS *bluefs = static_cast<BlueFS*>(priv);
  interval_set<uint64_t> *tmp = static_cast<interval_set<uint64_t>*>(priv2);
  bluefs->handle_discard(BlueFS::BDEV_WAL, *tmp);
}

static void db_discard_cb(void *priv, void* priv2) {
  BlueFS *bluefs = static_cast<BlueFS*>(priv);
  interval_set<uint64_t> *tmp = static_cast<interval_set<uint64_t>*>(priv2);
  bluefs->handle_discard(BlueFS::BDEV_DB, *tmp);
}

static void slow_discard_cb(void *priv, void* priv2) {
  BlueFS *bluefs = static_cast<BlueFS*>(priv);
  interval_set<uint64_t> *tmp = static_cast<interval_set<uint64_t>*>(priv2);
  bluefs->handle_discard(BlueFS::BDEV_SLOW, *tmp);
}

BlueFS::BlueFS(CephContext* cct)
  : cct(cct),
    bdev(MAX_BDEV),
    ioc(MAX_BDEV),
    block_all(MAX_BDEV)
{
  discard_cb[BDEV_WAL] = wal_discard_cb;
  discard_cb[BDEV_DB] = db_discard_cb;
  discard_cb[BDEV_SLOW] = slow_discard_cb;
  if (cct->_conf->bluefs_bdev_discard == "sync")
    discard_mode = BlockDevice::DISCARD_SYNC;
  else if (cct->_conf->bluefs_bdev_discard == "async")
    discard_mode = BlockDevice::DISCARD_ASYNC;
  else if (cct->_conf->bluefs_bdev_discard == "periodic")
    discard_mode = BlockDevice::DISCARD_PERIODIC;
  else
    discard_mode = BlockDevice::DISCARD_NONE;
}

BlueFS::~BlueFS()
{
  for (auto p : ioc) {
    if (p)
      p->aio_wait();
  }
  for (auto p : bdev) {
    if (p) {
      p->close();
      delete p;
    }
  }
  for (auto p : ioc) {
    delete p;
  }
}

void BlueFS::_init_logger()
{
  PerfCountersBuilder b(cct, "bluefs",
                        l_bluefs_first, l_bluefs_last);
  b.add_u64_counter(l_bluefs_gift_bytes, "gift_bytes",
		    "Bytes gifted from BlueStore", NULL, 0, unit_t(UNIT_BYTES));
  b.add_u64_counter(l_bluefs_reclaim_bytes, "reclaim_bytes",
		    "Bytes reclaimed by BlueStore", NULL, 0, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_db_total_bytes, "db_total_bytes",
	    "Total bytes (main db device)",
	    "b", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_db_used_bytes, "db_used_bytes",
	    "Used bytes (main db device)",
	    "u", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_wal_total_bytes, "wal_total_bytes",
	    "Total bytes (wal device)",
	    "walb", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_wal_used_bytes, "wal_used_bytes",
	    "Used bytes (wal device)",
	    "walu", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_slow_total_bytes, "slow_total_bytes",
	    "Total bytes (slow device)",
	    "slob", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_slow_used_bytes, "slow_used_bytes",
	    "Used bytes (slow device)",
	    "slou", PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64(l_bluefs_num_files, "num_files", "File count",
	    "f", PerfCountersBuilder::PRIO_USEFUL);
  b.add_u64(l_bluefs_log_bytes, "log_bytes", "Size of the metadata log",
	    "jlen", PerfCountersBuilder::PRIO_INTERESTING, unit_t(UNIT_BYTES));
  b.add_u64_counter(l_bluefs_log_compactions, "log_compactions",
		    "Compactions of the metadata log");
  b.add_u64_counter(l_bluefs_logged_bytes, "logged_bytes",
		    "Bytes written to the metadata log", "j",
		    PerfCountersBuilder::PRIO_CRITICAL, unit_t(UNIT_BYTES));
  b.add_u64_counter(l_bluefs_files_written_wal, "files_written_wal",
		    "Files written to WAL");
  b.add_u64_counter(l_bluefs_files_written_sst, "files_written_sst",
		    "Files written to SSTs");
  b.add_u64_counter(l_bluefs_bytes_written_wal, "bytes_written_wal",
		    "Bytes written to WAL", "wal",
		    PerfCountersBuilder::PRIO_CRITICAL);
  b.add_u64_counter(l_bluefs_bytes_written_sst, "bytes_written_sst",
		    "Bytes written to SSTs", "sst",
		    PerfCountersBuilder::PRIO_CRITICAL, unit_t(UNIT_BYTES));
  b.add_u64_counter(l_bluefs_bytes_written_slow, "bytes_written_slow",
		    "Bytes written to WAL/SSTs at slow device", NULL,
		    PerfCountersBuilder::PRIO_USEFUL, unit_t(UNIT_BYTES));
  b.add_u64_counter(l_bluefs_max_bytes_wal, "max_bytes_wal",
		    "Maximum bytes allocated from WAL");
  b.add_u64_counter(l_bluefs_max_bytes_db, "max_bytes_db",
		    "Maximum bytes allocated from DB");
  b.add_u64_counter(l_bluefs_max_bytes_slow, "max_bytes_slow",
		    "Maximum bytes allocated from SLOW");
  logger = b.create_perf_counters();
  cct->get_perfcounters_collection()->add(logger);
}

void BlueFS::_shutdown_logger()
{
  cct->get_perfcounters_collection()->remove(logger);
  delete logger;
}

void BlueFS::_update_logger_stats()
{
  // we must be holding the lock
  logger->set(l_bluefs_num_files, file_map.size());
  logger->set(l_bluefs_log_bytes, log_writer->file->fnode.size);

  if (alloc[BDEV_WAL]) {
    logger->set(l_bluefs_wal_total_bytes, block_all[BDEV_WAL].size());
    logger->set(l_bluefs_wal_used_bytes,
		block_all[BDEV_WAL].size() - alloc[BDEV_WAL]->get_free());
  }
  if (alloc[BDEV_DB]) {
    logger->set(l_bluefs_db_total_bytes, block_all[BDEV_DB].size());
    logger->set(l_bluefs_db_used_bytes,
		block_all[BDEV_DB].size() - alloc[BDEV_DB]->get_free());
  }
  if (alloc[BDEV_SLOW]) {
    logger->set(l_bluefs_slow_total_bytes, block_all[BDEV_SLOW].size());
    logger->set(l_bluefs_slow_used_bytes,
		block_all[BDEV_SLOW].size() - alloc[BDEV_SLOW]->get_free());
  }
}

int BlueFS::add_block_device(unsigned id, const string& path, bool trim,
			     bool shared_with_bluestore)
{
  dout(10) << __func__ << " bdev " << id << " path " << path << dendl;
  ceph_assert(id < bdev.size());
  ceph_assert(bdev[id] == NULL);
  BlockDevice *b = BlockDevice::create(cct, path, NULL, NULL,
				       discard_cb[id], static_cast<void*>(this));
  if (shared_with_bluestore) {
    b->set_no_exclusive_lock();
  }
  int r = b->open(path);
  if (r < 0) {
    delete b;
    return r;
  }
  if (trim) {
    b->discard(0, b->get_size());
  }

  dout(1) << __func__ << " bdev " << id << " path " << path
	  << " size " << byte_u_t(b->get_size()) << dendl;
  bdev[id] = b;
  ioc[id] = new IOContext(cct, NULL);
  return 0;
}

bool BlueFS::bdev_support_label(unsigned id)
{
  ceph_assert(id < bdev.size());
  ceph_assert(bdev[id]);
  return bdev[id]->supported_bdev_label();
}

uint64_t BlueFS::get_block_device_size(unsigned id)
{
  if (id < bdev.size() && bdev[id])
    return bdev[id]->get_size();
  return 0;
}

void BlueFS::_add_block_extent(unsigned id, uint64_t offset, uint64_t length)
{
  dout(1) << __func__ << " bdev " << id
	  << " 0x" << std::hex << offset << "~" << length << std::dec
	  << dendl;

  ceph_assert(id < bdev.size());
  ceph_assert(bdev[id]);
  ceph_assert(bdev[id]->get_size() >= offset + length);
  block_all[id].insert(offset, length);

  if (id < alloc.size() && alloc[id]) {
    log_t.op_alloc_add(id, offset, length);
    alloc[id]->init_add_free(offset, length);
  }

  if (logger)
    logger->inc(l_bluefs_gift_bytes, length);
  dout(10) << __func__ << " done" << dendl;
}

int BlueFS::reclaim_blocks(unsigned id, uint64_t want,
			   PExtentVector *extents)
{
  std::unique_lock l(lock);
  dout(1) << __func__ << " bdev " << id
          << " want 0x" << std::hex << want << std::dec << dendl;
  ceph_assert(id < alloc.size());
  ceph_assert(alloc[id]);

  int64_t got = alloc[id]->allocate(want, cct->_conf->bluefs_alloc_size, 0,
				    extents);
  ceph_assert(got != 0);
  if (got < 0) {
    derr << __func__ << " failed to allocate space to return to bluestore"
      << dendl;
    alloc[id]->dump();
    return got;
  }

  for (auto& p : *extents) {
    block_all[id].erase(p.offset, p.length);
    log_t.op_alloc_rm(id, p.offset, p.length);
  }

  flush_bdev();
  int r = _flush_and_sync_log(l);
  ceph_assert(r == 0);

  logger->inc(l_bluefs_reclaim_bytes, got);
  dout(1) << __func__ << " bdev " << id << " want 0x" << std::hex << want
	  << " got " << *extents << dendl;
  return 0;
}

void BlueFS::handle_discard(unsigned id, interval_set<uint64_t>& to_release)
{
  dout(10) << __func__ << " bdev " << id << dendl;
  ceph_assert(alloc[id]);
  alloc[id]->release(to_release);
}

uint64_t BlueFS::get_used()
{
  std::lock_guard l(lock);
  uint64_t used = 0;
  for (unsigned id = 0; id < MAX_BDEV; ++id) {
    if (alloc[id]) {
      used += block_all[id].size() - alloc[id]->get_free();
    }
  }
  return used;
}

uint64_t BlueFS::get_total(unsigned id)
{
  std::lock_guard l(lock);
  ceph_assert(id < block_all.size());
  return block_all[id].size();
}

uint64_t BlueFS::get_free(unsigned id)
{
  std::lock_guard l(lock);
  ceph_assert(id < alloc.size());
  return alloc[id]->get_free();
}

void BlueFS::dump_perf_counters(Formatter *f)
{
  f->open_object_section("bluefs_perf_counters");
  logger->dump_formatted(f,0);
  f->close_section();
}

void BlueFS::dump_block_extents(ostream& out)
{
  for (unsigned i = 0; i < MAX_BDEV; ++i) {
    if (!bdev[i]) {
      continue;
    }
    auto owned = get_total(i);
    auto free = get_free(i);
    out << i << " : device size 0x" << std::hex << bdev[i]->get_size()
        << " : own 0x" << block_all[i]
        << " = 0x" << owned
        << " : using 0x" << owned - free
        << std::dec << "\n";
  }
}

void BlueFS::get_usage(vector<pair<uint64_t,uint64_t>> *usage)
{
  std::lock_guard l(lock);
  usage->resize(bdev.size());
  for (unsigned id = 0; id < bdev.size(); ++id) {
    if (!bdev[id]) {
      (*usage)[id] = make_pair(0, 0);
      continue;
    }
    (*usage)[id].first = alloc[id]->get_free();
    (*usage)[id].second = block_all[id].size();
    uint64_t used =
      (block_all[id].size() - (*usage)[id].first) * 100 / block_all[id].size();
    dout(10) << __func__ << " bdev " << id
	     << " free " << (*usage)[id].first
	     << " (" << byte_u_t((*usage)[id].first) << ")"
	     << " / " << (*usage)[id].second
	     << " (" << byte_u_t((*usage)[id].second) << ")"
	     << ", used " << used << "%"
	     << dendl;
  }
}

int BlueFS::get_block_extents(unsigned id, interval_set<uint64_t> *extents)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " bdev " << id << dendl;
  if (id >= block_all.size())
    return -EINVAL;
  *extents = block_all[id];
  return 0;
}

int BlueFS::mkfs(uuid_d osd_uuid)
{
  std::unique_lock l(lock);
  dout(1) << __func__
	  << " osd_uuid " << osd_uuid
	  << dendl;

  _init_alloc();
  _init_logger();

  super.version = 1;
  super.block_size = bdev[BDEV_DB]->get_block_size();
  super.osd_uuid = osd_uuid;
  super.uuid.generate_random();
  dout(1) << __func__ << " uuid " << super.uuid << dendl;

  // init log
  FileRef log_file = new File;
  log_file->fnode.ino = 1;
  log_file->fnode.prefer_bdev = BDEV_WAL;
  int r = _allocate(
    log_file->fnode.prefer_bdev,
    cct->_conf->bluefs_max_log_runway,
    &log_file->fnode);
  ceph_assert(r == 0);
  log_writer = _create_writer(log_file);

  // initial txn
  log_t.op_init();
  for (unsigned bdev = 0; bdev < MAX_BDEV; ++bdev) {
    interval_set<uint64_t>& p = block_all[bdev];
    if (p.empty())
      continue;
    for (interval_set<uint64_t>::iterator q = p.begin(); q != p.end(); ++q) {
      dout(20) << __func__ << " op_alloc_add " << bdev << " 0x"
               << std::hex << q.get_start() << "~" << q.get_len() << std::dec
               << dendl;
      log_t.op_alloc_add(bdev, q.get_start(), q.get_len());
    }
  }
  _flush_and_sync_log(l);

  // write supers
  super.log_fnode = log_file->fnode;
  _write_super(BDEV_DB);
  flush_bdev();

  // clean up
  super = bluefs_super_t();
  _close_writer(log_writer);
  log_writer = NULL;
  block_all.clear();
  _stop_alloc();
  _shutdown_logger();

  dout(10) << __func__ << " success" << dendl;
  return 0;
}

void BlueFS::_init_alloc()
{
  dout(20) << __func__ << dendl;
  alloc.resize(MAX_BDEV);
  pending_release.resize(MAX_BDEV);
  for (unsigned id = 0; id < bdev.size(); ++id) {
    if (!bdev[id]) {
      continue;
    }
    ceph_assert(bdev[id]->get_size());
    alloc[id] = Allocator::create(cct, cct->_conf->bluefs_allocator,
				  bdev[id]->get_size(),
				  cct->_conf->bluefs_alloc_size,
				  discard_mode == BlockDevice::DISCARD_PERIODIC);
    interval_set<uint64_t>& p = block_all[id];
    for (interval_set<uint64_t>::iterator q = p.begin(); q != p.end(); ++q) {
      alloc[id]->init_add_free(q.get_start(), q.get_len());
    }
  }
}

void BlueFS::_stop_alloc()
{
  dout(20) << __func__ << dendl;
  for (auto p : bdev) {
    if (p)
      p->discard_drain();
  }

  for (auto p : alloc) {
    if (p != nullptr)  {
      p->shutdown();
      delete p;
    }
  }
  alloc.clear();
}

int BlueFS::mount()
{
  dout(1) << __func__ << dendl;

  int r = _open_super();
  if (r < 0) {
    derr << __func__ << " failed to open super: " << cpp_strerror(r) << dendl;
    goto out;
  }

  block_all.clear();
  block_all.resize(MAX_BDEV);
  _init_alloc();

  r = _replay(false, false);
  if (r < 0) {
    derr << __func__ << " failed to replay log: " << cpp_strerror(r) << dendl;
    _stop_alloc();
    goto out;
  }

  // init freelist
  for (auto& p : file_map) {
    dout(30) << __func__ << " noting alloc for " << p.second->fnode << dendl;
    for (auto& q : p.second->fnode.extents) {
      alloc[q.bdev]->init_rm_free(q.offset, q.length);
    }
  }

  // set up the log for future writes
  log_writer = _create_writer(_get_file(1));
  ceph_assert(log_writer->file->fnode.ino == 1);
  log_writer->pos = log_writer->file->fnode.size;
  dout(10) << __func__ << " log write pos set to 0x"
           << std::hex << log_writer->pos << std::dec
           << dendl;

  _init_logger();
  return 0;

 out:
  super = bluefs_super_t();
  return r;
}

void BlueFS::umount()
{
  dout(1) << __func__ << dendl;

  sync_metadata();

  _close_writer(log_writer);
  log_writer = NULL;

  _stop_alloc();
  file_map.clear();
  dir_map.clear();
  super = bluefs_super_t();
  log_t.clear();
  _shutdown_logger();
}

int BlueFS::prepare_new_device(int id)
{
  dout(1) << __func__ << dendl;

  if(id == BDEV_NEWDB) {
    int new_log_dev_cur = BDEV_WAL;
    int new_log_dev_next = BDEV_WAL;
    if (!bdev[BDEV_WAL]) {
      new_log_dev_cur = BDEV_NEWDB;
      new_log_dev_next = BDEV_DB;
    }
    _rewrite_log_sync(false,
      BDEV_NEWDB,
      new_log_dev_cur,
      new_log_dev_next,
      RENAME_DB2SLOW);
    //}
  } else if(id == BDEV_NEWWAL) {
    _rewrite_log_sync(false, BDEV_DB, BDEV_NEWWAL, BDEV_WAL, REMOVE_WAL);
  } else {
    assert(false);
  }
  return 0;
}

void BlueFS::collect_metadata(map<string,string> *pm, unsigned skip_bdev_id)
{
  if (skip_bdev_id != BDEV_DB && bdev[BDEV_DB])
    bdev[BDEV_DB]->collect_metadata("bluefs_db_", pm);
  if (bdev[BDEV_WAL])
    bdev[BDEV_WAL]->collect_metadata("bluefs_wal_", pm);
}

void BlueFS::get_devices(set<string> *ls)
{
  for (unsigned i = 0; i < MAX_BDEV; ++i) {
    if (bdev[i]) {
      bdev[i]->get_devices(ls);
    }
  }
}

int BlueFS::fsck()
{
  std::lock_guard l(lock);
  dout(1) << __func__ << dendl;
  // hrm, i think we check everything on mount...
  return 0;
}

int BlueFS::_write_super(int dev)
{
  // build superblock
  bufferlist bl;
  encode(super, bl);
  uint32_t crc = bl.crc32c(-1);
  encode(crc, bl);
  dout(10) << __func__ << " super block length(encoded): " << bl.length() << dendl;
  dout(10) << __func__ << " superblock " << super.version << dendl;
  dout(10) << __func__ << " log_fnode " << super.log_fnode << dendl;
  ceph_assert(bl.length() <= get_super_length());
  bl.append_zero(get_super_length() - bl.length());

  bdev[dev]->write(get_super_offset(), bl, false, WRITE_LIFE_SHORT);
  dout(20) << __func__ << " v " << super.version
           << " crc 0x" << std::hex << crc
           << " offset 0x" << get_super_offset() << std::dec
           << dendl;
  return 0;
}

int BlueFS::_open_super()
{
  dout(10) << __func__ << dendl;

  bufferlist bl;
  uint32_t expected_crc, crc;
  int r;

  // always the second block
  r = bdev[BDEV_DB]->read(get_super_offset(), get_super_length(),
			  &bl, ioc[BDEV_DB], false);
  if (r < 0)
    return r;

  auto p = bl.cbegin();
  decode(super, p);
  {
    bufferlist t;
    t.substr_of(bl, 0, p.get_off());
    crc = t.crc32c(-1);
  }
  decode(expected_crc, p);
  if (crc != expected_crc) {
    derr << __func__ << " bad crc on superblock, expected 0x"
         << std::hex << expected_crc << " != actual 0x" << crc << std::dec
         << dendl;
    return -EIO;
  }
  dout(10) << __func__ << " superblock " << super.version << dendl;
  dout(10) << __func__ << " log_fnode " << super.log_fnode << dendl;
  return 0;
}

int BlueFS::_replay(bool noop, bool to_stdout)
{
  dout(10) << __func__ << (noop ? " NO-OP" : "") << dendl;
  ino_last = 1;  // by the log
  log_seq = 0;

  FileRef log_file;
  log_file = _get_file(1);
  if (!noop) {
    log_file->fnode = super.log_fnode;
  } else {
    // do not use fnode from superblock in 'noop' mode - log_file's one should
    // be fine and up-to-date
    ceph_assert(log_file->fnode.ino == 1);
    ceph_assert(log_file->fnode.extents.size() != 0);
  }
  dout(10) << __func__ << " log_fnode " << super.log_fnode << dendl;
  if (unlikely(to_stdout)) {
    std::cout << " log_fnode " << super.log_fnode << std::endl;
  } 

  FileReader *log_reader = new FileReader(
    log_file, cct->_conf->bluefs_max_prefetch,
    false,  // !random
    true);  // ignore eof
  while (true) {
    ceph_assert((log_reader->buf.pos & ~super.block_mask()) == 0);
    uint64_t pos = log_reader->buf.pos;
    uint64_t read_pos = pos;
    bufferlist bl;
    {
      int r = _read(log_reader, &log_reader->buf, read_pos, super.block_size,
		    &bl, NULL);
      ceph_assert(r == (int)super.block_size);
      read_pos += r;
    }
    uint64_t more = 0;
    uint64_t seq;
    uuid_d uuid;
    {
      auto p = bl.cbegin();
      __u8 a, b;
      uint32_t len;
      decode(a, p);
      decode(b, p);
      decode(len, p);
      decode(uuid, p);
      decode(seq, p);
      if (len + 6 > bl.length()) {
	more = round_up_to(len + 6 - bl.length(), super.block_size);
      }
    }
    if (uuid != super.uuid) {
      dout(10) << __func__ << " 0x" << std::hex << pos << std::dec
               << ": stop: uuid " << uuid << " != super.uuid " << super.uuid
               << dendl;
      break;
    }
    if (seq != log_seq + 1) {
      dout(10) << __func__ << " 0x" << std::hex << pos << std::dec
               << ": stop: seq " << seq << " != expected " << log_seq + 1
               << dendl;
      break;
    }
    if (more) {
      dout(20) << __func__ << " need 0x" << std::hex << more << std::dec
               << " more bytes" << dendl;
      bufferlist t;
      int r = _read(log_reader, &log_reader->buf, read_pos, more, &t, NULL);
      if (r < (int)more) {
	dout(10) << __func__ << " 0x" << std::hex << pos
                 << ": stop: len is 0x" << bl.length() + more << std::dec
                 << ", which is past eof" << dendl;
	break;
      }
      ceph_assert(r == (int)more);
      bl.claim_append(t);
      read_pos += r;
    }
    bluefs_transaction_t t;
    try {
      auto p = bl.cbegin();
      decode(t, p);
    }
    catch (buffer::error& e) {
      dout(10) << __func__ << " 0x" << std::hex << pos << std::dec
               << ": stop: failed to decode: " << e.what()
               << dendl;
      delete log_reader;
      return -EIO;
    }
    ceph_assert(seq == t.seq);
    dout(10) << __func__ << " 0x" << std::hex << pos << std::dec
             << ": " << t << dendl;
    if (unlikely(to_stdout)) {
      std::cout << " 0x" << std::hex << pos << std::dec
                << ": " << t << std::endl;
    }

    auto p = t.op_bl.cbegin();
    while (!p.end()) {
      __u8 op;
      decode(op, p);
      switch (op) {

      case bluefs_transaction_t::OP_INIT:
	dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                 << ":  op_init" << dendl;
        if (unlikely(to_stdout)) {
          std::cout << " 0x" << std::hex << pos << std::dec
                    << ":  op_init" << std::endl;
        }

	ceph_assert(t.seq == 1);
	break;

      case bluefs_transaction_t::OP_JUMP:
        {
	  uint64_t next_seq;
	  uint64_t offset;
	  decode(next_seq, p);
	  decode(offset, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
		   << ":  op_jump seq " << next_seq
		   << " offset 0x" << std::hex << offset << std::dec << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_jump seq " << next_seq
                      << " offset 0x" << std::hex << offset << std::dec
                      << std::endl;
          }

	  ceph_assert(next_seq >= log_seq);
	  log_seq = next_seq - 1; // we will increment it below
	  uint64_t skip = offset - read_pos;
	  if (skip) {
	    bufferlist junk;
	    int r = _read(log_reader, &log_reader->buf, read_pos, skip, &junk,
			  NULL);
	    if (r != (int)skip) {
	      dout(10) << __func__ << " 0x" << std::hex << read_pos
		       << ": stop: failed to skip to " << offset
		       << std::dec << dendl;
	      ceph_abort_msg("problem with op_jump");
	    }
	  }
	}
	break;

      case bluefs_transaction_t::OP_JUMP_SEQ:
        {
	  uint64_t next_seq;
	  decode(next_seq, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_jump_seq " << next_seq << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_jump_seq " << next_seq << std::endl;
          }

	  ceph_assert(next_seq >= log_seq);
	  log_seq = next_seq - 1; // we will increment it below
	}
	break;

      case bluefs_transaction_t::OP_ALLOC_ADD:
        {
	  __u8 id;
	  uint64_t offset, length;
	  decode(id, p);
	  decode(offset, p);
	  decode(length, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_alloc_add " << " " << (int)id
                   << ":0x" << std::hex << offset << "~" << length << std::dec
                   << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_alloc_add " << " " << (int)id
                      << ":0x" << std::hex << offset << "~" << length << std::dec
                      << std::endl;
          }

	  if (!noop) {
	    block_all[id].insert(offset, length);
	    alloc[id]->init_add_free(offset, length);
	  }
	}
	break;

      case bluefs_transaction_t::OP_ALLOC_RM:
        {
	  __u8 id;
	  uint64_t offset, length;
	  decode(id, p);
	  decode(offset, p);
	  decode(length, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_alloc_rm " << " " << (int)id
                   << ":0x" << std::hex << offset << "~" << length << std::dec
                   << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_alloc_rm " << " " << (int)id
                      << ":0x" << std::hex << offset << "~" << length << std::dec
                      << std::endl;
          }

	  if (!noop) {
	    block_all[id].erase(offset, length);
	    alloc[id]->init_rm_free(offset, length);
	  }
	}
	break;

      case bluefs_transaction_t::OP_DIR_LINK:
        {
	  string dirname, filename;
	  uint64_t ino;
	  decode(dirname, p);
	  decode(filename, p);
	  decode(ino, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_dir_link " << " " << dirname << "/" << filename
                   << " to " << ino
		   << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_dir_link " << " " << dirname << "/" << filename
                      << " to " << ino
                      << std::endl;
          }

	  if (!noop) {
	    FileRef file = _get_file(ino);
	    ceph_assert(file->fnode.ino);
	    map<string,DirRef>::iterator q = dir_map.find(dirname);
	    ceph_assert(q != dir_map.end());
	    map<string,FileRef>::iterator r = q->second->file_map.find(filename);
	    ceph_assert(r == q->second->file_map.end());
	    q->second->file_map[filename] = file;
	    ++file->refs;
	  }
	}
	break;

      case bluefs_transaction_t::OP_DIR_UNLINK:
        {
	  string dirname, filename;
	  decode(dirname, p);
	  decode(filename, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_dir_unlink " << " " << dirname << "/" << filename
                   << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_dir_unlink " << " " << dirname << "/" << filename
                      << std::endl;
          }
 
	  if (!noop) {
	    map<string,DirRef>::iterator q = dir_map.find(dirname);
	    ceph_assert(q != dir_map.end());
	    map<string,FileRef>::iterator r = q->second->file_map.find(filename);
	    ceph_assert(r != q->second->file_map.end());
            ceph_assert(r->second->refs > 0); 
	    --r->second->refs;
	    q->second->file_map.erase(r);
	  }
	}
	break;

      case bluefs_transaction_t::OP_DIR_CREATE:
        {
	  string dirname;
	  decode(dirname, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_dir_create " << dirname << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_dir_create " << dirname << std::endl;
          }

	  if (!noop) {
	    map<string,DirRef>::iterator q = dir_map.find(dirname);
	    ceph_assert(q == dir_map.end());
	    dir_map[dirname] = new Dir;
	  }
	}
	break;

      case bluefs_transaction_t::OP_DIR_REMOVE:
        {
	  string dirname;
	  decode(dirname, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_dir_remove " << dirname << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_dir_remove " << dirname << std::endl;
          }

	  if (!noop) {
	    map<string,DirRef>::iterator q = dir_map.find(dirname);
	    ceph_assert(q != dir_map.end());
	    ceph_assert(q->second->file_map.empty());
	    dir_map.erase(q);
	  }
	}
	break;

      case bluefs_transaction_t::OP_FILE_UPDATE:
        {
	  bluefs_fnode_t fnode;
	  decode(fnode, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_file_update " << " " << fnode << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_file_update " << " " << fnode << std::endl;
          }

	  if (!noop) {
	    FileRef f = _get_file(fnode.ino);
	    f->fnode = fnode;
	    if (fnode.ino > ino_last) {
	      ino_last = fnode.ino;
	    }
	  }
	}
	break;

      case bluefs_transaction_t::OP_FILE_REMOVE:
        {
	  uint64_t ino;
	  decode(ino, p);
	  dout(20) << __func__ << " 0x" << std::hex << pos << std::dec
                   << ":  op_file_remove " << ino << dendl;
          if (unlikely(to_stdout)) {
            std::cout << " 0x" << std::hex << pos << std::dec
                      << ":  op_file_remove " << ino << std::endl;
          }

	  if (!noop) {
	    auto p = file_map.find(ino);
	    ceph_assert(p != file_map.end());
	    file_map.erase(p);
	  }
	}
	break;

      default:
	derr << __func__ << " 0x" << std::hex << pos << std::dec
             << ": stop: unrecognized op " << (int)op << dendl;
	delete log_reader;
        return -EIO;
      }
    }
    ceph_assert(p.end());

    // we successfully replayed the transaction; bump the seq and log size
    ++log_seq;
    log_file->fnode.size = log_reader->buf.pos;
  }

  dout(10) << __func__ << " log file size was 0x"
           << std::hex << log_file->fnode.size << std::dec << dendl;
  if (unlikely(to_stdout)) {
    std::cout << " log file size was 0x"
              << std::hex << log_file->fnode.size << std::dec << std::endl;
  }

  delete log_reader;

  if (!noop) {
    // verify file link counts are all >0
    for (auto& p : file_map) {
      if (p.second->refs == 0 &&
	  p.second->fnode.ino > 1) {
	derr << __func__ << " file with link count 0: " << p.second->fnode
	     << dendl;
	return -EIO;
      }
    }
  }

  dout(10) << __func__ << " done" << dendl;
  return 0;
}

int BlueFS::log_dump()
{
  // only dump log file's content
  int r = _replay(true, true);
  if (r < 0) {
    derr << __func__ << " failed to replay log: " << cpp_strerror(r) << dendl;
    return r;
  }

  return 0;
}

int BlueFS::device_migrate_to_existing(
  CephContext *cct,
  const set<int>& devs_source,
  int dev_target)
{
  vector<byte> buf;
  bool buffered = cct->_conf->bluefs_buffered_io;

  assert(dev_target < (int)MAX_BDEV);

  int flags = 0;
  flags |= devs_source.count(BDEV_DB) ?
    (REMOVE_DB | RENAME_SLOW2DB) : 0;
  flags |= devs_source.count(BDEV_WAL) ? REMOVE_WAL : 0;
  int dev_target_new = dev_target;

  // Slow device without separate DB one is addressed via BDEV_DB
  // Hence need renaming.
  if ((flags & REMOVE_DB) && dev_target == BDEV_SLOW) {
    dev_target_new = BDEV_DB;
    dout(0) << __func__ << " super to be written to " << dev_target << dendl;
  }

  for (auto& p : file_map) {
    //do not copy log
    if (p.second->fnode.ino == 1) {
      continue;
    }
    auto& fnode_extents = p.second->fnode.extents;

    for (auto ext_it = fnode_extents.begin();
      ext_it != p.second->fnode.extents.end();
      ++ext_it) {
      if (ext_it->bdev != dev_target && devs_source.count(ext_it->bdev)) {
       bluefs_extent_t old_ext = *ext_it;
	PExtentVector extents;
	auto l =
	  _allocate_without_fallback(dev_target, old_ext.length, &extents);
	if (l == 0) {
	  buf.resize(old_ext.length);
	  int r = bdev[old_ext.bdev]->read_random(
	    old_ext.offset,
	    old_ext.length,
	    (char*)&buf.at(0),
	    buffered);
	  if (r != 0) {
	    derr << __func__ << " failed to read 0x" << std::hex
	      << old_ext.offset << "~" <<old_ext.length << std::dec
	      << " from " << (int)dev_target << dendl;
	    return -EIO;
	  }

	  assert(extents.size() > 0);
	  uint64_t src_buf_pos = 0;
	  {
	    // overwrite existing extent
	    *ext_it=
	      bluefs_extent_t(dev_target_new, extents[0].offset, extents[0].length);
	    bufferlist bl;
	    bl.append((char*)&buf.at(src_buf_pos), extents[0].length);
	    int r = bdev[dev_target]->write(extents[0].offset, bl, buffered);
	    ceph_assert(r == 0);
	    src_buf_pos += extents[0].length;
	  }
	  // then insert more extents if needed
	  for( size_t i = 1; i < extents.size(); ++i) {
	    bufferlist bl;
	    bl.append((char*)&buf.at(src_buf_pos), extents[i].length);
	    ++ext_it;
	    ext_it = fnode_extents.emplace(ext_it, dev_target_new,
	      extents[i].offset, extents[i].length);
	    int r = bdev[dev_target]->write(extents[i].offset, bl, buffered);
	    ceph_assert(r == 0);
	    src_buf_pos += extents[i].length;
	  }
	  {
	    PExtentVector to_release;
	    to_release.emplace_back(old_ext.offset, old_ext.length);
	    alloc[old_ext.bdev]->release(to_release);
	  }

	} else {
	  derr << __func__ << " unable to allocate len 0x" << std::hex
	    << old_ext.length << std::dec << " from " << (int)dev_target
	    << dendl;
	  return -ENOSPC;
	}
      } else if (dev_target != dev_target_new && ext_it->bdev == dev_target) {
	ext_it->bdev = dev_target_new;
      }
    }
    auto& prefer_bdev = p.second->fnode.prefer_bdev;
    if (prefer_bdev != dev_target && devs_source.count(prefer_bdev)) {
      prefer_bdev = dev_target_new;
    }
  }
  // new logging device in the current naming scheme
  int new_log_dev_cur = bdev[BDEV_WAL] ?
    BDEV_WAL :
    bdev[BDEV_DB] ? BDEV_DB : BDEV_SLOW;

  // new logging device in new naming scheme
  int new_log_dev_next = new_log_dev_cur;

  if (devs_source.count(new_log_dev_cur)) {
    // SLOW device is addressed via BDEV_DB too hence either WAL or DB
    new_log_dev_next = (flags & REMOVE_WAL) || !bdev[BDEV_WAL] ?
      BDEV_DB :
      BDEV_WAL;

    dout(0) << __func__ << " log moved from " << new_log_dev_cur
      << " to " << new_log_dev_next << dendl;

    new_log_dev_cur =
      (flags & REMOVE_DB) && new_log_dev_next == BDEV_DB ?
        BDEV_SLOW :
        new_log_dev_next;
  }

  _rewrite_log_sync(
    false,
    (flags & REMOVE_DB) ? BDEV_SLOW : BDEV_DB,
    new_log_dev_cur,
    new_log_dev_next,
    flags);
  return 0;
}

int BlueFS::device_migrate_to_new(
  CephContext *cct,
  const set<int>& devs_source,
  int dev_target)
{
  vector<byte> buf;
  bool buffered = cct->_conf->bluefs_buffered_io;

  assert(dev_target == (int)BDEV_NEWDB || (int)BDEV_NEWWAL);

  int flags = 0;

  flags |= devs_source.count(BDEV_DB) ?
    (!bdev[BDEV_SLOW] ? RENAME_DB2SLOW: REMOVE_DB) :
    0;
  flags |= devs_source.count(BDEV_WAL) ? REMOVE_WAL : 0;
  int dev_target_new = dev_target;

  for (auto& p : file_map) {
    //do not copy log
    if (p.second->fnode.ino == 1) {
      continue;
    }
    auto& fnode_extents = p.second->fnode.extents;

    for (auto ext_it = fnode_extents.begin();
      ext_it != p.second->fnode.extents.end();
      ++ext_it) {
      if (ext_it->bdev != dev_target && devs_source.count(ext_it->bdev)) {
       bluefs_extent_t old_ext = *ext_it;
	PExtentVector extents;
	auto l =
	  _allocate_without_fallback(dev_target, old_ext.length, &extents);
	if (l == 0) {
	  buf.resize(old_ext.length);
	  int r = bdev[old_ext.bdev]->read_random(
	    old_ext.offset,
	    old_ext.length,
	    (char*)&buf.at(0),
	    buffered);
	  dout(10)<<__func__<<" read = "<<r<<dendl;
	  if (r != 0) {
	    derr << __func__ << " failed to read 0x" << std::hex
	      << old_ext.offset << "~" <<old_ext.length << std::dec
	      << " from " << (int)dev_target << dendl;
	    return -EIO;
	  }

	  assert(extents.size() > 0);
	  uint64_t src_buf_pos = 0;
	  {
	    // overwrite existing extent
	    *ext_it=
	      bluefs_extent_t(dev_target_new, extents[0].offset, extents[0].length);
	    bufferlist bl;
	    bl.append((char*)&buf.at(src_buf_pos), extents[0].length);
	    int r = bdev[dev_target]->write(extents[0].offset, bl, buffered);
	    ceph_assert(r == 0);
	    src_buf_pos += extents[0].length;
	  }
	  // then insert more extents if needed
	  for( size_t i = 1; i < extents.size(); ++i) {
	    bufferlist bl;
	    bl.append((char*)&buf.at(src_buf_pos), extents[i].length);
	    ++ext_it;
	    ext_it = fnode_extents.emplace(ext_it, dev_target_new,
	      extents[i].offset, extents[i].length);
	    int r = bdev[dev_target]->write(extents[i].offset, bl, buffered);
	    ceph_assert(r == 0);
	    src_buf_pos += extents[i].length;
	  }
	  {
	    PExtentVector to_release;
	    to_release.emplace_back(old_ext.offset, old_ext.length);
	    alloc[old_ext.bdev]->release(to_release);
	  }
	} else {
	  derr << __func__ << " unable to allocate len 0x" << std::hex
	    << old_ext.length << std::dec << " from " << (int)dev_target
	    << dendl;
	  return -ENOSPC;
	}
      } else if (dev_target != dev_target_new && ext_it->bdev == dev_target) {
	ext_it->bdev = dev_target_new;
      }
    }
    auto& prefer_bdev = p.second->fnode.prefer_bdev;
    if (prefer_bdev != dev_target && devs_source.count(prefer_bdev)) {
      prefer_bdev = dev_target_new;
    }
  }
  // new logging device in the current naming scheme
  int new_log_dev_cur =
    bdev[BDEV_NEWWAL] ?
      BDEV_NEWWAL :
      bdev[BDEV_WAL] && !(flags & REMOVE_WAL) ?
        BDEV_WAL :
	bdev[BDEV_NEWDB] ?
	  BDEV_NEWDB :
	  bdev[BDEV_DB] && !(flags & REMOVE_DB)?
	    BDEV_DB :
	    BDEV_SLOW;

  // new logging device in new naming scheme
  int new_log_dev_next =
    new_log_dev_cur == BDEV_NEWWAL ?
      BDEV_WAL :
      new_log_dev_cur == BDEV_NEWDB ?
	BDEV_DB :
        new_log_dev_cur;

  int super_dev =
    dev_target == BDEV_NEWDB ?
      BDEV_NEWDB :
      bdev[BDEV_DB] ?
        BDEV_DB :
	BDEV_SLOW;

  _rewrite_log_sync(
    false,
    super_dev,
    new_log_dev_cur,
    new_log_dev_next,
    flags);
  return 0;
}

BlueFS::FileRef BlueFS::_get_file(uint64_t ino)
{
  auto p = file_map.find(ino);
  if (p == file_map.end()) {
    FileRef f = new File;
    file_map[ino] = f;
    dout(30) << __func__ << " ino " << ino << " = " << f
	     << " (new)" << dendl;
    return f;
  } else {
    dout(30) << __func__ << " ino " << ino << " = " << p->second << dendl;
    return p->second;
  }
}

void BlueFS::_drop_link(FileRef file)
{
  dout(20) << __func__ << " had refs " << file->refs
	   << " on " << file->fnode << dendl;
  ceph_assert(file->refs > 0);
  --file->refs;
  if (file->refs == 0) {
    dout(20) << __func__ << " destroying " << file->fnode << dendl;
    ceph_assert(file->num_reading.load() == 0);
    log_t.op_file_remove(file->fnode.ino);
    for (auto& r : file->fnode.extents) {
      pending_release[r.bdev].insert(r.offset, r.length);
    }
    file_map.erase(file->fnode.ino);
    file->deleted = true;

    if (file->dirty_seq) {
      ceph_assert(file->dirty_seq > log_seq_stable);
      ceph_assert(dirty_files.count(file->dirty_seq));
      auto it = dirty_files[file->dirty_seq].iterator_to(*file);
      dirty_files[file->dirty_seq].erase(it);
      file->dirty_seq = 0;
    }
  }
}

int BlueFS::_read_random(
  FileReader *h,         ///< [in] read from here
  uint64_t off,          ///< [in] offset
  size_t len,            ///< [in] this many bytes
  char *out)             ///< [out] optional: or copy it here
{
  dout(10) << __func__ << " h " << h
           << " 0x" << std::hex << off << "~" << len << std::dec
	   << " from " << h->file->fnode << dendl;

  ++h->file->num_reading;

  if (!h->ignore_eof &&
      off + len > h->file->fnode.size) {
    if (off > h->file->fnode.size)
      len = 0;
    else
      len = h->file->fnode.size - off;
    dout(20) << __func__ << " reaching (or past) eof, len clipped to 0x"
	     << std::hex << len << std::dec << dendl;
  }

  int ret = 0;
  while (len > 0) {
    uint64_t x_off = 0;
    auto p = h->file->fnode.seek(off, &x_off);
    uint64_t l = std::min(p->length - x_off, static_cast<uint64_t>(len));
    dout(20) << __func__ << " read buffered 0x"
             << std::hex << x_off << "~" << l << std::dec
             << " of " << *p << dendl;
    int r = bdev[p->bdev]->read_random(p->offset + x_off, l, out,
				       cct->_conf->bluefs_buffered_io);
    ceph_assert(r == 0);
    off += l;
    len -= l;
    ret += l;
    out += l;
  }

  dout(20) << __func__ << " got " << ret << dendl;
  --h->file->num_reading;
  return ret;
}

int BlueFS::_read(
  FileReader *h,         ///< [in] read from here
  FileReaderBuffer *buf, ///< [in] reader state
  uint64_t off,          ///< [in] offset
  size_t len,            ///< [in] this many bytes
  bufferlist *outbl,     ///< [out] optional: reference the result here
  char *out)             ///< [out] optional: or copy it here
{
  dout(10) << __func__ << " h " << h
           << " 0x" << std::hex << off << "~" << len << std::dec
	   << " from " << h->file->fnode << dendl;

  ++h->file->num_reading;

  if (!h->ignore_eof &&
      off + len > h->file->fnode.size) {
    if (off > h->file->fnode.size)
      len = 0;
    else
      len = h->file->fnode.size - off;
    dout(20) << __func__ << " reaching (or past) eof, len clipped to 0x"
	     << std::hex << len << std::dec << dendl;
  }
  if (outbl)
    outbl->clear();

  int ret = 0;
  while (len > 0) {
    size_t left;
    if (off < buf->bl_off || off >= buf->get_buf_end()) {
      buf->bl.clear();
      buf->bl_off = off & super.block_mask();
      uint64_t x_off = 0;
      auto p = h->file->fnode.seek(buf->bl_off, &x_off);
      uint64_t want = round_up_to(len + (off & ~super.block_mask()),
				  super.block_size);
      want = std::max(want, buf->max_prefetch);
      uint64_t l = std::min(p->length - x_off, want);
      uint64_t eof_offset = round_up_to(h->file->fnode.size, super.block_size);
      if (!h->ignore_eof &&
	  buf->bl_off + l > eof_offset) {
	l = eof_offset - buf->bl_off;
      }
      dout(20) << __func__ << " fetching 0x"
               << std::hex << x_off << "~" << l << std::dec
               << " of " << *p << dendl;
      int r = bdev[p->bdev]->read(p->offset + x_off, l, &buf->bl, ioc[p->bdev],
				  cct->_conf->bluefs_buffered_io);
      ceph_assert(r == 0);
    }
    left = buf->get_buf_remaining(off);
    dout(20) << __func__ << " left 0x" << std::hex << left
             << " len 0x" << len << std::dec << dendl;

    int r = std::min(len, left);
    if (outbl) {
      bufferlist t;
      t.substr_of(buf->bl, off - buf->bl_off, r);
      outbl->claim_append(t);
    }
    if (out) {
      // NOTE: h->bl is normally a contiguous buffer so c_str() is free.
      memcpy(out, buf->bl.c_str() + off - buf->bl_off, r);
      out += r;
    }

    dout(30) << __func__ << " result chunk (0x"
             << std::hex << r << std::dec << " bytes):\n";
    bufferlist t;
    t.substr_of(buf->bl, off - buf->bl_off, r);
    t.hexdump(*_dout);
    *_dout << dendl;

    off += r;
    len -= r;
    ret += r;
    buf->pos += r;
  }

  dout(20) << __func__ << " got " << ret << dendl;
  ceph_assert(!outbl || (int)outbl->length() == ret);
  --h->file->num_reading;
  return ret;
}

void BlueFS::_invalidate_cache(FileRef f, uint64_t offset, uint64_t length)
{
  dout(10) << __func__ << " file " << f->fnode
	   << " 0x" << std::hex << offset << "~" << length << std::dec
           << dendl;
  if (offset & ~super.block_mask()) {
    offset &= super.block_mask();
    length = round_up_to(length, super.block_size);
  }
  uint64_t x_off = 0;
  auto p = f->fnode.seek(offset, &x_off);
  while (length > 0 && p != f->fnode.extents.end()) {
    uint64_t x_len = std::min(p->length - x_off, length);
    bdev[p->bdev]->invalidate_cache(p->offset + x_off, x_len);
    dout(20) << __func__  << " 0x" << std::hex << x_off << "~" << x_len
             << std:: dec << " of " << *p << dendl;
    offset += x_len;
    length -= x_len;
  }
}

uint64_t BlueFS::_estimate_log_size()
{
  int avg_dir_size = 40;  // fixme
  int avg_file_size = 12;
  uint64_t size = 4096 * 2;
  size += file_map.size() * (1 + sizeof(bluefs_fnode_t));
  for (auto& p : block_all)
    size += p.num_intervals() * (1 + 1 + sizeof(uint64_t) * 2);
  size += dir_map.size() + (1 + avg_dir_size);
  size += file_map.size() * (1 + avg_dir_size + avg_file_size);
  return round_up_to(size, super.block_size);
}

void BlueFS::compact_log()
{
  std::unique_lock l(lock);
  if (cct->_conf->bluefs_compact_log_sync) {
     _compact_log_sync();
  } else {
    _compact_log_async(l);
  }
}

bool BlueFS::_should_compact_log()
{
  uint64_t current = log_writer->file->fnode.size;
  uint64_t expected = _estimate_log_size();
  float ratio = (float)current / (float)expected;
  dout(10) << __func__ << " current 0x" << std::hex << current
	   << " expected " << expected << std::dec
	   << " ratio " << ratio
	   << (new_log ? " (async compaction in progress)" : "")
	   << dendl;
  if (new_log ||
      current < cct->_conf->bluefs_log_compact_min_size ||
      ratio < cct->_conf->bluefs_log_compact_min_ratio) {
    return false;
  }
  return true;
}

void BlueFS::_compact_log_dump_metadata(bluefs_transaction_t *t,
					int flags)
{
  t->seq = 1;
  t->uuid = super.uuid;
  dout(20) << __func__ << " op_init" << dendl;

  t->op_init();
  for (unsigned bdev = 0; bdev < MAX_BDEV; ++bdev) {
    interval_set<uint64_t>& p = block_all[bdev];
    for (interval_set<uint64_t>::iterator q = p.begin(); q != p.end(); ++q) {
      auto bdev_new = bdev;
      if ((flags & REMOVE_WAL) && bdev == BDEV_WAL) {
	continue;
      }
      if ((flags & REMOVE_DB) && bdev == BDEV_DB) {
	continue;
      }
      if ((flags & RENAME_SLOW2DB) && bdev == BDEV_SLOW) {
	bdev_new = BDEV_DB;
      }
      if ((flags & RENAME_DB2SLOW) && bdev == BDEV_DB) {
	bdev_new = BDEV_SLOW;
      }
      if (bdev == BDEV_NEWDB) {
	// REMOVE_DB xor RENAME_DB
	ceph_assert(!(flags & REMOVE_DB) != !(flags & RENAME_DB2SLOW));
	ceph_assert(!(flags & RENAME_SLOW2DB));
	bdev_new = BDEV_DB;
      }
      if (bdev == BDEV_NEWWAL) {
	ceph_assert(flags & REMOVE_WAL);
	bdev_new = BDEV_WAL;
      }
      dout(20) << __func__ << " op_alloc_add " << bdev_new << " 0x"
               << std::hex << q.get_start() << "~" << q.get_len() << std::dec
               << dendl;
      t->op_alloc_add(bdev_new, q.get_start(), q.get_len());
    }
  }
  for (auto& p : file_map) {
    if (p.first == 1)
      continue;
    ceph_assert(p.first > 1);

    for(auto& e : p.second->fnode.extents) {
      auto bdev = e.bdev;
      auto bdev_new = bdev;
      ceph_assert(!((flags & REMOVE_WAL) && bdev == BDEV_WAL));
      if ((flags & RENAME_SLOW2DB) && bdev == BDEV_SLOW) {
	bdev_new = BDEV_DB;
      }
      if ((flags & RENAME_DB2SLOW) && bdev == BDEV_DB) {
	bdev_new = BDEV_SLOW;
      }
      if (bdev == BDEV_NEWDB) {
	// REMOVE_DB xor RENAME_DB
	ceph_assert(!(flags & REMOVE_DB) != !(flags & RENAME_DB2SLOW));
	ceph_assert(!(flags & RENAME_SLOW2DB));
	bdev_new = BDEV_DB;
      }
      if (bdev == BDEV_NEWWAL) {
	ceph_assert(flags & REMOVE_WAL);
	bdev_new = BDEV_WAL;
      }
      e.bdev = bdev_new;
    }
    dout(20) << __func__ << " op_file_update " << p.second->fnode << dendl;
    t->op_file_update(p.second->fnode);
  }
  for (auto& p : dir_map) {
    dout(20) << __func__ << " op_dir_create " << p.first << dendl;
    t->op_dir_create(p.first);
    for (auto& q : p.second->file_map) {
      dout(20) << __func__ << " op_dir_link " << p.first << "/" << q.first
	       << " to " << q.second->fnode.ino << dendl;
      t->op_dir_link(p.first, q.first, q.second->fnode.ino);
    }
  }
}

void BlueFS::_compact_log_sync()
{
  dout(10) << __func__ << dendl;
  _rewrite_log_sync(true,
    BDEV_DB,
    log_writer->file->fnode.prefer_bdev,
    log_writer->file->fnode.prefer_bdev,
    0);
  logger->inc(l_bluefs_log_compactions);
}

void BlueFS::_rewrite_log_sync(bool allocate_with_fallback,
			       int super_dev,
			       int log_dev,
			       int log_dev_new,
			       int flags)
{
  File *log_file = log_writer->file.get();

  // clear out log (be careful who calls us!!!)
  log_t.clear();

  dout(20) << __func__ << " super_dev:" << super_dev
                       << " log_dev:" << log_dev
                       << " log_dev_new:" << log_dev_new
		       << " flags:" << flags
		       << dendl;
  bluefs_transaction_t t;
  _compact_log_dump_metadata(&t, flags);

  dout(20) << __func__ << " op_jump_seq " << log_seq << dendl;
  t.op_jump_seq(log_seq);

  bufferlist bl;
  encode(t, bl);
  _pad_bl(bl);

  uint64_t need = bl.length() + cct->_conf->bluefs_max_log_runway;
  dout(20) << __func__ << " need " << need << dendl;

  mempool::bluefs::vector<bluefs_extent_t> old_extents;
  uint64_t old_allocated = 0;
  int r;
  log_file->fnode.swap_extents(old_extents, old_allocated);
  if (allocate_with_fallback) {
    r = _allocate(log_dev, need, &log_file->fnode);
    ceph_assert(r == 0);
  } else {
    PExtentVector extents;
    r = _allocate_without_fallback(log_dev,
			       need,
			       &extents);
    ceph_assert(r == 0);
    for (auto& p : extents) {
      log_file->fnode.append_extent(
	bluefs_extent_t(log_dev, p.offset, p.length));
    }
  }

  _close_writer(log_writer);

  log_file->fnode.size = bl.length();
  log_writer = _create_writer(log_file);
  log_writer->append(bl);
  r = _flush(log_writer, true);
  ceph_assert(r == 0);
#ifdef HAVE_LIBAIO
  if (!cct->_conf->bluefs_sync_write) {
    list<aio_t> completed_ios;
    _claim_completed_aios(log_writer, &completed_ios);
    wait_for_aio(log_writer);
    completed_ios.clear();
  }
#endif
  flush_bdev();

  super.log_fnode = log_file->fnode;
  // rename device if needed
  if (log_dev != log_dev_new) {
    dout(10) << __func__ << " renaming log extents to " << log_dev_new << dendl;
    for (auto& p : super.log_fnode.extents) {
      p.bdev = log_dev_new;
    }
  }
  dout(10) << __func__ << " writing super, log fnode: " << super.log_fnode << dendl;

  ++super.version;
  _write_super(super_dev);
  flush_bdev();

  dout(10) << __func__ << " release old log extents " << old_extents << dendl;
  for (auto& r : old_extents) {
    pending_release[r.bdev].insert(r.offset, r.length);
  }
}

/*
 * 1. Allocate a new extent to continue the log, and then log an event
 * that jumps the log write position to the new extent.  At this point, the
 * old extent(s) won't be written to, and reflect everything to compact.
 * New events will be written to the new region that we'll keep.
 *
 * 2. While still holding the lock, encode a bufferlist that dumps all of the
 * in-memory fnodes and names.  This will become the new beginning of the
 * log.  The last event will jump to the log continuation extent from #1.
 *
 * 3. Queue a write to a new extent for the new beginnging of the log.
 *
 * 4. Drop lock and wait
 *
 * 5. Retake the lock.
 *
 * 6. Update the log_fnode to splice in the new beginning.
 *
 * 7. Write the new superblock.
 *
 * 8. Release the old log space.  Clean up.
 */
void BlueFS::_compact_log_async(std::unique_lock<ceph::mutex>& l)
{
  dout(10) << __func__ << dendl;
  File *log_file = log_writer->file.get();
  ceph_assert(!new_log);
  ceph_assert(!new_log_writer);

  // create a new log [writer] so that we know compaction is in progress
  // (see _should_compact_log)
  new_log = new File;
  new_log->fnode.ino = 0;   // so that _flush_range won't try to log the fnode

  // 0. wait for any racing flushes to complete.  (We do not want to block
  // in _flush_sync_log with jump_to set or else a racing thread might flush
  // our entries and our jump_to update won't be correct.)
  while (log_flushing) {
    dout(10) << __func__ << " log is currently flushing, waiting" << dendl;
    log_cond.wait(l);
  }

  // 1. allocate new log space and jump to it.
  old_log_jump_to = log_file->fnode.get_allocated();
  dout(10) << __func__ << " old_log_jump_to 0x" << std::hex << old_log_jump_to
           << " need 0x" << (old_log_jump_to + cct->_conf->bluefs_max_log_runway) << std::dec << dendl;
  int r = _allocate(log_file->fnode.prefer_bdev,
		    cct->_conf->bluefs_max_log_runway, &log_file->fnode);
  ceph_assert(r == 0);
  dout(10) << __func__ << " log extents " << log_file->fnode.extents << dendl;

  // update the log file change and log a jump to the offset where we want to
  // write the new entries
  log_t.op_file_update(log_file->fnode);
  log_t.op_jump(log_seq, old_log_jump_to);

  flush_bdev();  // FIXME?

  _flush_and_sync_log(l, 0, old_log_jump_to);

  // 2. prepare compacted log
  bluefs_transaction_t t;
  //avoid record two times in log_t and _compact_log_dump_metadata.
  log_t.clear();
  _compact_log_dump_metadata(&t, 0);

  // conservative estimate for final encoded size
  new_log_jump_to = round_up_to(t.op_bl.length() + super.block_size * 2,
                                cct->_conf->bluefs_alloc_size);
  t.op_jump(log_seq, new_log_jump_to);

  // allocate
  r = _allocate(BlueFS::BDEV_DB, new_log_jump_to,
                    &new_log->fnode);
  ceph_assert(r == 0);

  // we might have some more ops in log_t due to _allocate call
  t.claim_ops(log_t);

  bufferlist bl;
  encode(t, bl);
  _pad_bl(bl);

  dout(10) << __func__ << " new_log_jump_to 0x" << std::hex << new_log_jump_to
	   << std::dec << dendl;

  new_log_writer = _create_writer(new_log);
  new_log_writer->append(bl);

  // 3. flush
  r = _flush(new_log_writer, true);
  ceph_assert(r == 0);

  // 4. wait
  _flush_bdev_safely(new_log_writer);

  // 5. update our log fnode
  // discard first old_log_jump_to extents
  dout(10) << __func__ << " remove 0x" << std::hex << old_log_jump_to << std::dec
	   << " of " << log_file->fnode.extents << dendl;
  uint64_t discarded = 0;
  mempool::bluefs::vector<bluefs_extent_t> old_extents;
  while (discarded < old_log_jump_to) {
    ceph_assert(!log_file->fnode.extents.empty());
    bluefs_extent_t& e = log_file->fnode.extents.front();
    bluefs_extent_t temp = e;
    if (discarded + e.length <= old_log_jump_to) {
      dout(10) << __func__ << " remove old log extent " << e << dendl;
      discarded += e.length;
      log_file->fnode.pop_front_extent();
    } else {
      dout(10) << __func__ << " remove front of old log extent " << e << dendl;
      uint64_t drop = old_log_jump_to - discarded;
      temp.length = drop;
      e.offset += drop;
      e.length -= drop;
      discarded += drop;
      dout(10) << __func__ << "   kept " << e << " removed " << temp << dendl;
    }
    old_extents.push_back(temp);
  }
  auto from = log_file->fnode.extents.begin();
  auto to = log_file->fnode.extents.end();
  while (from != to) {
    new_log->fnode.append_extent(*from);
    ++from;
  }

  // clear the extents from old log file, they are added to new log
  log_file->fnode.clear_extents();
  // swap the log files. New log file is the log file now.
  new_log->fnode.swap_extents(log_file->fnode);

  log_writer->pos = log_writer->file->fnode.size =
    log_writer->pos - old_log_jump_to + new_log_jump_to;

  // 6. write the super block to reflect the changes
  dout(10) << __func__ << " writing super" << dendl;
  super.log_fnode = log_file->fnode;
  ++super.version;
  _write_super(BDEV_DB);

  lock.unlock();
  flush_bdev();
  lock.lock();

  // 7. release old space
  dout(10) << __func__ << " release old log extents " << old_extents << dendl;
  for (auto& r : old_extents) {
    pending_release[r.bdev].insert(r.offset, r.length);
  }

  // delete the new log, remove from the dirty files list
  _close_writer(new_log_writer);
  if (new_log->dirty_seq) {
    ceph_assert(dirty_files.count(new_log->dirty_seq));
    auto it = dirty_files[new_log->dirty_seq].iterator_to(*new_log);
    dirty_files[new_log->dirty_seq].erase(it);
  }
  new_log_writer = nullptr;
  new_log = nullptr;
  log_cond.notify_all();

  dout(10) << __func__ << " log extents " << log_file->fnode.extents << dendl;
  logger->inc(l_bluefs_log_compactions);
}

void BlueFS::_pad_bl(bufferlist& bl)
{
  uint64_t partial = bl.length() % super.block_size;
  if (partial) {
    dout(10) << __func__ << " padding with 0x" << std::hex
	     << super.block_size - partial << " zeros" << std::dec << dendl;
    bl.append_zero(super.block_size - partial);
  }
}

void BlueFS::flush_log()
{
  std::unique_lock l(lock);
  flush_bdev();
  _flush_and_sync_log(l);
}

int BlueFS::_flush_and_sync_log(std::unique_lock<ceph::mutex>& l,
				uint64_t want_seq,
				uint64_t jump_to)
{
  while (log_flushing) {
    dout(10) << __func__ << " want_seq " << want_seq
	     << " log is currently flushing, waiting" << dendl;
    ceph_assert(!jump_to);
    log_cond.wait(l);
  }
  if (want_seq && want_seq <= log_seq_stable) {
    dout(10) << __func__ << " want_seq " << want_seq << " <= log_seq_stable "
	     << log_seq_stable << ", done" << dendl;
    ceph_assert(!jump_to);
    return 0;
  }
  if (log_t.empty() && dirty_files.empty()) {
    dout(10) << __func__ << " want_seq " << want_seq
	     << " " << log_t << " not dirty, dirty_files empty, no-op" << dendl;
    ceph_assert(!jump_to);
    return 0;
  }

  vector<interval_set<uint64_t>> to_release(pending_release.size());
  to_release.swap(pending_release);

  uint64_t seq = log_t.seq = ++log_seq;
  ceph_assert(want_seq == 0 || want_seq <= seq);
  log_t.uuid = super.uuid;

  // log dirty files
  auto lsi = dirty_files.find(seq);
  if (lsi != dirty_files.end()) {
    dout(20) << __func__ << " " << lsi->second.size() << " dirty_files" << dendl;
    for (auto &f : lsi->second) {
      dout(20) << __func__ << "   op_file_update " << f.fnode << dendl;
      log_t.op_file_update(f.fnode);
    }
  }

  dout(10) << __func__ << " " << log_t << dendl;
  ceph_assert(!log_t.empty());

  // allocate some more space (before we run out)?
  int64_t runway = log_writer->file->fnode.get_allocated() -
    log_writer->get_effective_write_pos();
  if (runway < (int64_t)cct->_conf->bluefs_min_log_runway) {
    dout(10) << __func__ << " allocating more log runway (0x"
	     << std::hex << runway << std::dec  << " remaining)" << dendl;
    while (new_log_writer) {
      dout(10) << __func__ << " waiting for async compaction" << dendl;
      log_cond.wait(l);
    }
    int r = _allocate(log_writer->file->fnode.prefer_bdev,
		      cct->_conf->bluefs_max_log_runway,
		      &log_writer->file->fnode);
    ceph_assert(r == 0);
    log_t.op_file_update(log_writer->file->fnode);
  }

  bufferlist bl;
  bl.reserve(super.block_size);
  encode(log_t, bl);
  // pad to block boundary
  size_t realign = super.block_size - (bl.length() % super.block_size);
  if (realign && realign != super.block_size)
    bl.append_zero(realign);

  logger->inc(l_bluefs_logged_bytes, bl.length());

  log_writer->append(bl);

  log_t.clear();
  log_t.seq = 0;  // just so debug output is less confusing
  log_flushing = true;

  int r = _flush(log_writer, true);
  ceph_assert(r == 0);

  if (jump_to) {
    dout(10) << __func__ << " jumping log offset from 0x" << std::hex
	     << log_writer->pos << " -> 0x" << jump_to << std::dec << dendl;
    log_writer->pos = jump_to;
    log_writer->file->fnode.size = jump_to;
  }

  _flush_bdev_safely(log_writer);

  log_flushing = false;
  log_cond.notify_all();

  // clean dirty files
  if (seq > log_seq_stable) {
    log_seq_stable = seq;
    dout(20) << __func__ << " log_seq_stable " << log_seq_stable << dendl;

    auto p = dirty_files.begin();
    while (p != dirty_files.end()) {
      if (p->first > log_seq_stable) {
        dout(20) << __func__ << " done cleaning up dirty files" << dendl;
        break;
      }

      auto l = p->second.begin();
      while (l != p->second.end()) {
        File *file = &*l;
        ceph_assert(file->dirty_seq > 0);
        ceph_assert(file->dirty_seq <= log_seq_stable);
        dout(20) << __func__ << " cleaned file " << file->fnode << dendl;
        file->dirty_seq = 0;
        p->second.erase(l++);
      }

      ceph_assert(p->second.empty());
      dirty_files.erase(p++);
    }
  } else {
    dout(20) << __func__ << " log_seq_stable " << log_seq_stable
             << " already >= out seq " << seq
             << ", we lost a race against another log flush, done" << dendl;
  }

  for (unsigned i = 0; i < to_release.size(); ++i) {
    if (!to_release[i].empty()) {
      /* OK, now we have the guarantee alloc[i] won't be null. */
      int r = 0;
      if (discard_mode == BlockDevice::DISCARD_ASYNC) {
	r = bdev[i]->queue_discard(to_release[i]);
	if (r == 0)
	  continue;
      } else if (discard_mode == BlockDevice::DISCARD_SYNC) {
	for (auto p = to_release[i].begin(); p != to_release[i].end(); ++p) {
	  bdev[i]->discard(p.get_start(), p.get_len());
	}
      }
      alloc[i]->release(to_release[i]);
    }
  }

  _update_logger_stats();

  return 0;
}

int BlueFS::_flush_range(FileWriter *h, uint64_t offset, uint64_t length)
{
  dout(10) << __func__ << " " << h << " pos 0x" << std::hex << h->pos
	   << " 0x" << offset << "~" << length << std::dec
	   << " to " << h->file->fnode << dendl;
  ceph_assert(!h->file->deleted);
  ceph_assert(h->file->num_readers.load() == 0);

  h->buffer_appender.flush();

  bool buffered;
  if (h->file->fnode.ino == 1)
    buffered = false;
  else
    buffered = cct->_conf->bluefs_buffered_io;

  if (offset + length <= h->pos)
    return 0;
  if (offset < h->pos) {
    length -= h->pos - offset;
    offset = h->pos;
    dout(10) << " still need 0x"
             << std::hex << offset << "~" << length << std::dec
             << dendl;
  }
  ceph_assert(offset <= h->file->fnode.size);

  uint64_t allocated = h->file->fnode.get_allocated();

  // do not bother to dirty the file if we are overwriting
  // previously allocated extents.
  bool must_dirty = false;
  if (allocated < offset + length) {
    // we should never run out of log space here; see the min runway check
    // in _flush_and_sync_log.
    ceph_assert(h->file->fnode.ino != 1);
    int r = _allocate(h->file->fnode.prefer_bdev,
		      offset + length - allocated,
		      &h->file->fnode);
    if (r < 0) {
      derr << __func__ << " allocated: 0x" << std::hex << allocated
           << " offset: 0x" << offset << " length: 0x" << length << std::dec
           << dendl;
      ceph_abort_msg("bluefs enospc");
      return r;
    }
    if (cct->_conf->bluefs_preextend_wal_files &&
	h->writer_type == WRITER_WAL) {
      // NOTE: this *requires* that rocksdb also has log recycling
      // enabled and is therefore doing robust CRCs on the log
      // records.  otherwise, we will fail to reply the rocksdb log
      // properly due to garbage on the device.
      h->file->fnode.size = h->file->fnode.get_allocated();
      dout(10) << __func__ << " extending WAL size to 0x" << std::hex
	       << h->file->fnode.size << std::dec << " to include allocated"
	       << dendl;
    }
    must_dirty = true;
  }
  if (h->file->fnode.size < offset + length) {
    h->file->fnode.size = offset + length;
    if (h->file->fnode.ino > 1) {
      // we do not need to dirty the log file (or it's compacting
      // replacement) when the file size changes because replay is
      // smart enough to discover it on its own.
      must_dirty = true;
    }
  }
  if (must_dirty) {
    h->file->fnode.mtime = ceph_clock_now();
    ceph_assert(h->file->fnode.ino >= 1);
    if (h->file->dirty_seq == 0) {
      h->file->dirty_seq = log_seq + 1;
      dirty_files[h->file->dirty_seq].push_back(*h->file);
      dout(20) << __func__ << " dirty_seq = " << log_seq + 1
	       << " (was clean)" << dendl;
    } else {
      if (h->file->dirty_seq != log_seq + 1) {
        // need re-dirty, erase from list first
        ceph_assert(dirty_files.count(h->file->dirty_seq));
        auto it = dirty_files[h->file->dirty_seq].iterator_to(*h->file);
        dirty_files[h->file->dirty_seq].erase(it);
        h->file->dirty_seq = log_seq + 1;
        dirty_files[h->file->dirty_seq].push_back(*h->file);
        dout(20) << __func__ << " dirty_seq = " << log_seq + 1
                 << " (was " << h->file->dirty_seq << ")" << dendl;
      } else {
        dout(20) << __func__ << " dirty_seq = " << log_seq + 1
                 << " (unchanged, do nothing) " << dendl;
      }
    }
  }
  dout(20) << __func__ << " file now " << h->file->fnode << dendl;

  uint64_t x_off = 0;
  auto p = h->file->fnode.seek(offset, &x_off);
  ceph_assert(p != h->file->fnode.extents.end());
  dout(20) << __func__ << " in " << *p << " x_off 0x"
           << std::hex << x_off << std::dec << dendl;

  unsigned partial = x_off & ~super.block_mask();
  bufferlist bl;
  if (partial) {
    dout(20) << __func__ << " using partial tail 0x"
             << std::hex << partial << std::dec << dendl;
    ceph_assert(h->tail_block.length() == partial);
    bl.claim_append_piecewise(h->tail_block);
    x_off -= partial;
    offset -= partial;
    length += partial;
    dout(20) << __func__ << " waiting for previous aio to complete" << dendl;
    for (auto p : h->iocv) {
      if (p) {
	p->aio_wait();
      }
    }
  }
  if (length == partial + h->buffer.length()) {
    bl.claim_append_piecewise(h->buffer);
  } else {
    bufferlist t;
    h->buffer.splice(0, length, &t);
    bl.claim_append_piecewise(t);
    t.substr_of(h->buffer, length, h->buffer.length() - length);
    h->buffer.swap(t);
    dout(20) << " leaving 0x" << std::hex << h->buffer.length() << std::dec
             << " unflushed" << dendl;
  }
  ceph_assert(bl.length() == length);

  switch (h->writer_type) {
  case WRITER_WAL:
    logger->inc(l_bluefs_bytes_written_wal, length);
    break;
  case WRITER_SST:
    logger->inc(l_bluefs_bytes_written_sst, length);
    break;
  }

  dout(30) << "dump:\n";
  bl.hexdump(*_dout);
  *_dout << dendl;

  h->pos = offset + length;
  h->tail_block.clear();

  uint64_t bloff = 0;
  uint64_t bytes_written_slow = 0;
  while (length > 0) {
    uint64_t x_len = std::min(p->length - x_off, length);
    bufferlist t;
    t.substr_of(bl, bloff, x_len);
    unsigned tail = x_len & ~super.block_mask();
    if (tail) {
      size_t zlen = super.block_size - tail;
      dout(20) << __func__ << " caching tail of 0x"
               << std::hex << tail
	       << " and padding block with 0x" << zlen
	       << std::dec << dendl;
      h->tail_block.substr_of(bl, bl.length() - tail, tail);
      if (h->file->fnode.ino > 1) {
	// we are using the page_aligned_appender, and can safely use
	// the tail of the raw buffer.
	const bufferptr &last = t.back();
	if (last.unused_tail_length() < zlen) {
	  derr << " wtf, last is " << last << " from " << t << dendl;
	  ceph_assert(last.unused_tail_length() >= zlen);
	}
	bufferptr z = last;
	z.set_offset(last.offset() + last.length());
	z.set_length(zlen);
	z.zero();
	t.append(z, 0, zlen);
      } else {
	t.append_zero(zlen);
      }
    }
    if (cct->_conf->bluefs_sync_write) {
      bdev[p->bdev]->write(p->offset + x_off, t, buffered, h->write_hint);
    } else {
      bdev[p->bdev]->aio_write(p->offset + x_off, t, h->iocv[p->bdev], buffered, h->write_hint);
    }
    h->dirty_devs[p->bdev] = true;
    if (p->bdev == BDEV_SLOW) {
      bytes_written_slow += t.length();
    }

    bloff += x_len;
    length -= x_len;
    ++p;
    x_off = 0;
  }
  logger->inc(l_bluefs_bytes_written_slow, bytes_written_slow);
  for (unsigned i = 0; i < MAX_BDEV; ++i) {
    if (bdev[i]) {
      if (h->iocv[i] && h->iocv[i]->has_pending_aios()) {
        bdev[i]->aio_submit(h->iocv[i]);
      }
    }
  }
  dout(20) << __func__ << " h " << h << " pos now 0x"
           << std::hex << h->pos << std::dec << dendl;
  return 0;
}

#ifdef HAVE_LIBAIO
// we need to retire old completed aios so they don't stick around in
// memory indefinitely (along with their bufferlist refs).
void BlueFS::_claim_completed_aios(FileWriter *h, list<aio_t> *ls)
{
  for (auto p : h->iocv) {
    if (p) {
      ls->splice(ls->end(), p->running_aios);
    }
  }
  dout(10) << __func__ << " got " << ls->size() << " aios" << dendl;
}

void BlueFS::wait_for_aio(FileWriter *h)
{
  // NOTE: this is safe to call without a lock, as long as our reference is
  // stable.
  dout(10) << __func__ << " " << h << dendl;
  utime_t start = ceph_clock_now();
  for (auto p : h->iocv) {
    if (p) {
      p->aio_wait();
    }
  }
  dout(10) << __func__ << " " << h << " done in " << (ceph_clock_now() - start) << dendl;
}
#endif

int BlueFS::_flush(FileWriter *h, bool force)
{
  h->buffer_appender.flush();
  uint64_t length = h->buffer.length();
  uint64_t offset = h->pos;
  if (!force &&
      length < cct->_conf->bluefs_min_flush_size) {
    dout(10) << __func__ << " " << h << " ignoring, length " << length
	     << " < min_flush_size " << cct->_conf->bluefs_min_flush_size
	     << dendl;
    return 0;
  }
  if (length == 0) {
    dout(10) << __func__ << " " << h << " no dirty data on "
	     << h->file->fnode << dendl;
    return 0;
  }
  dout(10) << __func__ << " " << h << " 0x"
           << std::hex << offset << "~" << length << std::dec
	   << " to " << h->file->fnode << dendl;
  ceph_assert(h->pos <= h->file->fnode.size);
  return _flush_range(h, offset, length);
}

int BlueFS::_truncate(FileWriter *h, uint64_t offset)
{
  dout(10) << __func__ << " 0x" << std::hex << offset << std::dec
           << " file " << h->file->fnode << dendl;
  if (h->file->deleted) {
    dout(10) << __func__ << "  deleted, no-op" << dendl;
    return 0;
  }

  // we never truncate internal log files
  ceph_assert(h->file->fnode.ino > 1);

  h->buffer_appender.flush();

  // truncate off unflushed data?
  if (h->pos < offset &&
      h->pos + h->buffer.length() > offset) {
    bufferlist t;
    dout(20) << __func__ << " tossing out last " << offset - h->pos
	     << " unflushed bytes" << dendl;
    t.substr_of(h->buffer, 0, offset - h->pos);
    h->buffer.swap(t);
    ceph_abort_msg("actually this shouldn't happen");
  }
  if (h->buffer.length()) {
    int r = _flush(h, true);
    if (r < 0)
      return r;
  }
  if (offset == h->file->fnode.size) {
    return 0;  // no-op!
  }
  if (offset > h->file->fnode.size) {
    ceph_abort_msg("truncate up not supported");
  }
  ceph_assert(h->file->fnode.size >= offset);
  h->file->fnode.size = offset;
  log_t.op_file_update(h->file->fnode);
  return 0;
}

int BlueFS::_fsync(FileWriter *h, std::unique_lock<ceph::mutex>& l)
{
  dout(10) << __func__ << " " << h << " " << h->file->fnode << dendl;
  int r = _flush(h, true);
  if (r < 0)
     return r;
  uint64_t old_dirty_seq = h->file->dirty_seq;

  _flush_bdev_safely(h);

  if (old_dirty_seq) {
    uint64_t s = log_seq;
    dout(20) << __func__ << " file metadata was dirty (" << old_dirty_seq
	     << ") on " << h->file->fnode << ", flushing log" << dendl;
    _flush_and_sync_log(l, old_dirty_seq);
    ceph_assert(h->file->dirty_seq == 0 ||  // cleaned
	   h->file->dirty_seq > s);    // or redirtied by someone else
  }
  return 0;
}

void BlueFS::_flush_bdev_safely(FileWriter *h)
{
  std::array<bool, MAX_BDEV> flush_devs = h->dirty_devs;
  h->dirty_devs.fill(false);
#ifdef HAVE_LIBAIO
  if (!cct->_conf->bluefs_sync_write) {
    list<aio_t> completed_ios;
    _claim_completed_aios(h, &completed_ios);
    lock.unlock();
    wait_for_aio(h);
    completed_ios.clear();
    flush_bdev(flush_devs);
    lock.lock();
  } else
#endif
  {
    lock.unlock();
    flush_bdev(flush_devs);
    lock.lock();
  }
}

void BlueFS::flush_bdev(std::array<bool, MAX_BDEV>& dirty_bdevs)
{
  // NOTE: this is safe to call without a lock.
  dout(20) << __func__ << dendl;
  for (unsigned i = 0; i < MAX_BDEV; i++) {
    if (dirty_bdevs[i])
      bdev[i]->flush();
  }
}

void BlueFS::flush_bdev()
{
  // NOTE: this is safe to call without a lock.
  dout(20) << __func__ << dendl;
  for (auto p : bdev) {
    if (p)
      p->flush();
  }
}

int BlueFS::_expand_slow_device(uint64_t need, PExtentVector& extents)
{
  int r = -ENOSPC;
  if (slow_dev_expander) {
    auto min_alloc_size = cct->_conf->bluefs_alloc_size;
    int id = _get_slow_device_id();
    ceph_assert(id <= (int)alloc.size() && alloc[id]);
    need = std::max(need,
      slow_dev_expander->get_recommended_expansion_delta(
        alloc[id]->get_free(), block_all[id].size()));

    need = round_up_to(need, min_alloc_size);
    dout(10) << __func__ << " expanding slow device by 0x"
             << std::hex << need << std::dec
	     << dendl;
    r = slow_dev_expander->allocate_freespace(need, extents);
  }
  return r;
}

int BlueFS::_allocate_without_fallback(uint8_t id, uint64_t len,
		      PExtentVector* extents)
{
  dout(10) << __func__ << " len 0x" << std::hex << len << std::dec
           << " from " << (int)id << dendl;
  assert(id < alloc.size());
  uint64_t min_alloc_size = cct->_conf->bluefs_alloc_size;

  uint64_t left = round_up_to(len, min_alloc_size);

  if (!alloc[id]) {
    return -ENOENT;
  }
  extents->reserve(4);  // 4 should be (more than) enough for most allocations
  int64_t alloc_len = alloc[id]->allocate(left, min_alloc_size, 0, extents);
  if (alloc_len < (int64_t)left) {
    if (alloc_len != 0) {
      alloc[id]->release(*extents);
    }
    if (bdev[id])
      derr << __func__ << " failed to allocate 0x" << std::hex << left
	   << " on bdev " << (int)id
	   << ", free 0x" << alloc[id]->get_free() << std::dec << dendl;
    else
      derr << __func__ << " failed to allocate 0x" << std::hex << left
	   << " on bdev " << (int)id << ", dne" << std::dec << dendl;
    if (alloc[id])
      alloc[id]->dump();
    return -ENOSPC;
  }

  return 0;
}

int BlueFS::_allocate(uint8_t id, uint64_t len,
		      bluefs_fnode_t* node)
{
  dout(10) << __func__ << " len 0x" << std::hex << len << std::dec
           << " from " << (int)id << dendl;
  ceph_assert(id < alloc.size());
  uint64_t min_alloc_size = cct->_conf->bluefs_alloc_size;

  uint64_t left = round_up_to(len, min_alloc_size);
  int64_t alloc_len = 0;
  PExtentVector extents;
  
  uint64_t hint = 0;
  if (alloc[id]) {
    if (!node->extents.empty() && node->extents.back().bdev == id) {
      hint = node->extents.back().end();
    }   
    extents.reserve(4);  // 4 should be (more than) enough for most allocations
    alloc_len = alloc[id]->allocate(left, min_alloc_size, hint, &extents);
  }
  if (alloc_len < (int64_t)left) {
    if (alloc_len > 0) {
      alloc[id]->release(extents);
    }
    if (id != BDEV_SLOW) {
      if (bdev[id]) {
	dout(1) << __func__ << " failed to allocate 0x" << std::hex << left
		<< " on bdev " << (int)id
		<< ", free 0x" << alloc[id]->get_free()
		<< "; fallback to bdev " << (int)id + 1
		<< std::dec << dendl;
      }
      return _allocate(id + 1, len, node);
    }
    dout(1) << __func__ << " unable to allocate 0x" << std::hex << left
	    << " on bdev " << (int)id << ", free 0x"
	    << (alloc[id] ? alloc[id]->get_free() : (uint64_t)-1)
	    << "; fallback to slow device expander "
	    << std::dec << dendl;
    extents.clear();
    if (_expand_slow_device(left, extents) == 0) {
      id = _get_slow_device_id();
      for (auto& e : extents) {
	_add_block_extent(id, e.offset, e.length);
      }
      extents.clear();
      auto* last_alloc = alloc[id];
      ceph_assert(last_alloc);
      // try again
      alloc_len = last_alloc->allocate(left, min_alloc_size, hint, &extents);
      if (alloc_len < (int64_t)left) {
	if (alloc_len > 0) {
	  last_alloc->release(extents);
	}
	derr << __func__ << " failed to allocate 0x" << std::hex << left
	      << " on bdev " << (int)id
	      << ", free 0x" << last_alloc->get_free() << std::dec << dendl;
        return -ENOSPC;
      }
    } else {
      derr << __func__ << " failed to expand slow device to fit +0x"
	   << std::hex << left << std::dec
	   << dendl;
      return -ENOSPC;
    }
  } else {
    uint64_t total_allocated =
      block_all[id].size() - alloc[id]->get_free();
    if (max_bytes[id] < total_allocated) {
      logger->set(max_bytes_pcounters[id], total_allocated);
      max_bytes[id] = total_allocated;
    }
  }

  for (auto& p : extents) {
    node->append_extent(bluefs_extent_t(id, p.offset, p.length));
  }
   
  return 0;
}

int BlueFS::_preallocate(FileRef f, uint64_t off, uint64_t len)
{
  dout(10) << __func__ << " file " << f->fnode << " 0x"
	   << std::hex << off << "~" << len << std::dec << dendl;
  if (f->deleted) {
    dout(10) << __func__ << "  deleted, no-op" << dendl;
    return 0;
  }
  ceph_assert(f->fnode.ino > 1);
  uint64_t allocated = f->fnode.get_allocated();
  if (off + len > allocated) {
    uint64_t want = off + len - allocated;
    int r = _allocate(f->fnode.prefer_bdev, want, &f->fnode);
    if (r < 0)
      return r;
    log_t.op_file_update(f->fnode);
  }
  return 0;
}

void BlueFS::sync_metadata()
{
  std::unique_lock l(lock);
  if (log_t.empty()) {
    dout(10) << __func__ << " - no pending log events" << dendl;
  } else {
    dout(10) << __func__ << dendl;
    utime_t start = ceph_clock_now();
    flush_bdev(); // FIXME?
    _flush_and_sync_log(l);
    dout(10) << __func__ << " done in " << (ceph_clock_now() - start) << dendl;
  }

  if (_should_compact_log()) {
    if (cct->_conf->bluefs_compact_log_sync) {
      _compact_log_sync();
    } else {
      _compact_log_async(l);
    }
  }
}

int BlueFS::open_for_write(
  const string& dirname,
  const string& filename,
  FileWriter **h,
  bool overwrite)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << "/" << filename << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  DirRef dir;
  if (p == dir_map.end()) {
    // implicitly create the dir
    dout(20) << __func__ << "  dir " << dirname
	     << " does not exist" << dendl;
    return -ENOENT;
  } else {
    dir = p->second;
  }

  FileRef file;
  bool create = false;
  map<string,FileRef>::iterator q = dir->file_map.find(filename);
  if (q == dir->file_map.end()) {
    if (overwrite) {
      dout(20) << __func__ << " dir " << dirname << " (" << dir
	       << ") file " << filename
	       << " does not exist" << dendl;
      return -ENOENT;
    }
    file = new File;
    file->fnode.ino = ++ino_last;
    file_map[ino_last] = file;
    dir->file_map[filename] = file;
    ++file->refs;
    create = true;
  } else {
    // overwrite existing file?
    file = q->second;
    if (overwrite) {
      dout(20) << __func__ << " dir " << dirname << " (" << dir
	       << ") file " << filename
	       << " already exists, overwrite in place" << dendl;
    } else {
      dout(20) << __func__ << " dir " << dirname << " (" << dir
	       << ") file " << filename
	       << " already exists, truncate + overwrite" << dendl;
      file->fnode.size = 0;
      for (auto& p : file->fnode.extents) {
	pending_release[p.bdev].insert(p.offset, p.length);
      }

      file->fnode.clear_extents();
    }
  }
  ceph_assert(file->fnode.ino > 1);

  file->fnode.mtime = ceph_clock_now();
  file->fnode.prefer_bdev = BlueFS::BDEV_DB;
  if (dirname.length() > 5) {
    // the "db.slow" and "db.wal" directory names are hard-coded at
    // match up with bluestore.  the slow device is always the second
    // one (when a dedicated block.db device is present and used at
    // bdev 0).  the wal device is always last.
    if (boost::algorithm::ends_with(dirname, ".slow")) {
      file->fnode.prefer_bdev = BlueFS::BDEV_SLOW;
    } else if (boost::algorithm::ends_with(dirname, ".wal")) {
      file->fnode.prefer_bdev = BlueFS::BDEV_WAL;
    }
  }
  dout(20) << __func__ << " mapping " << dirname << "/" << filename
	   << " to bdev " << (int)file->fnode.prefer_bdev << dendl;

  log_t.op_file_update(file->fnode);
  if (create)
    log_t.op_dir_link(dirname, filename, file->fnode.ino);

  *h = _create_writer(file);

  if (boost::algorithm::ends_with(filename, ".log")) {
    (*h)->writer_type = BlueFS::WRITER_WAL;
    if (logger && !overwrite) {
      logger->inc(l_bluefs_files_written_wal);
    }
  } else if (boost::algorithm::ends_with(filename, ".sst")) {
    (*h)->writer_type = BlueFS::WRITER_SST;
    if (logger) {
      logger->inc(l_bluefs_files_written_sst);
    }
  }

  dout(10) << __func__ << " h " << *h << " on " << file->fnode << dendl;
  return 0;
}

BlueFS::FileWriter *BlueFS::_create_writer(FileRef f)
{
  FileWriter *w = new FileWriter(f);
  for (unsigned i = 0; i < MAX_BDEV; ++i) {
    if (bdev[i]) {
      w->iocv[i] = new IOContext(cct, NULL);
    }
  }
  return w;
}

void BlueFS::_close_writer(FileWriter *h)
{
  dout(10) << __func__ << " " << h << " type " << h->writer_type << dendl;
  for (unsigned i=0; i<MAX_BDEV; ++i) {
    if (bdev[i]) {
      if (h->iocv[i]) {
	h->iocv[i]->aio_wait();
	bdev[i]->queue_reap_ioc(h->iocv[i]);
      }
    }
  }
  delete h;
}

int BlueFS::open_for_read(
  const string& dirname,
  const string& filename,
  FileReader **h,
  bool random)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << "/" << filename
	   << (random ? " (random)":" (sequential)") << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef dir = p->second;

  map<string,FileRef>::iterator q = dir->file_map.find(filename);
  if (q == dir->file_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " (" << dir
	     << ") file " << filename
	     << " not found" << dendl;
    return -ENOENT;
  }
  File *file = q->second.get();

  *h = new FileReader(file, random ? 4096 : cct->_conf->bluefs_max_prefetch,
		      random, false);
  dout(10) << __func__ << " h " << *h << " on " << file->fnode << dendl;
  return 0;
}

int BlueFS::rename(
  const string& old_dirname, const string& old_filename,
  const string& new_dirname, const string& new_filename)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << old_dirname << "/" << old_filename
	   << " -> " << new_dirname << "/" << new_filename << dendl;
  map<string,DirRef>::iterator p = dir_map.find(old_dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << old_dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef old_dir = p->second;
  map<string,FileRef>::iterator q = old_dir->file_map.find(old_filename);
  if (q == old_dir->file_map.end()) {
    dout(20) << __func__ << " dir " << old_dirname << " (" << old_dir
	     << ") file " << old_filename
	     << " not found" << dendl;
    return -ENOENT;
  }
  FileRef file = q->second;

  p = dir_map.find(new_dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << new_dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef new_dir = p->second;
  q = new_dir->file_map.find(new_filename);
  if (q != new_dir->file_map.end()) {
    dout(20) << __func__ << " dir " << new_dirname << " (" << old_dir
	     << ") file " << new_filename
	     << " already exists, unlinking" << dendl;
    ceph_assert(q->second != file);
    log_t.op_dir_unlink(new_dirname, new_filename);
    _drop_link(q->second);
  }

  dout(10) << __func__ << " " << new_dirname << "/" << new_filename << " "
	   << " " << file->fnode << dendl;

  new_dir->file_map[new_filename] = file;
  old_dir->file_map.erase(old_filename);

  log_t.op_dir_link(new_dirname, new_filename, file->fnode.ino);
  log_t.op_dir_unlink(old_dirname, old_filename);
  return 0;
}

int BlueFS::mkdir(const string& dirname)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p != dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " exists" << dendl;
    return -EEXIST;
  }
  dir_map[dirname] = new Dir;
  log_t.op_dir_create(dirname);
  return 0;
}

int BlueFS::rmdir(const string& dirname)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " does not exist" << dendl;
    return -ENOENT;
  }
  DirRef dir = p->second;
  if (!dir->file_map.empty()) {
    dout(20) << __func__ << " dir " << dirname << " not empty" << dendl;
    return -ENOTEMPTY;
  }
  dir_map.erase(dirname);
  log_t.op_dir_remove(dirname);
  return 0;
}

bool BlueFS::dir_exists(const string& dirname)
{
  std::lock_guard l(lock);
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  bool exists = p != dir_map.end();
  dout(10) << __func__ << " " << dirname << " = " << (int)exists << dendl;
  return exists;
}

int BlueFS::stat(const string& dirname, const string& filename,
		 uint64_t *size, utime_t *mtime)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << "/" << filename << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef dir = p->second;
  map<string,FileRef>::iterator q = dir->file_map.find(filename);
  if (q == dir->file_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " (" << dir
	     << ") file " << filename
	     << " not found" << dendl;
    return -ENOENT;
  }
  File *file = q->second.get();
  dout(10) << __func__ << " " << dirname << "/" << filename
	   << " " << file->fnode << dendl;
  if (size)
    *size = file->fnode.size;
  if (mtime)
    *mtime = file->fnode.mtime;
  return 0;
}

int BlueFS::lock_file(const string& dirname, const string& filename,
		      FileLock **plock)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << "/" << filename << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef dir = p->second;
  map<string,FileRef>::iterator q = dir->file_map.find(filename);
  File *file;
  if (q == dir->file_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " (" << dir
	     << ") file " << filename
	     << " not found, creating" << dendl;
    file = new File;
    file->fnode.ino = ++ino_last;
    file->fnode.mtime = ceph_clock_now();
    file_map[ino_last] = file;
    dir->file_map[filename] = file;
    ++file->refs;
    log_t.op_file_update(file->fnode);
    log_t.op_dir_link(dirname, filename, file->fnode.ino);
  } else {
    file = q->second.get();
    if (file->locked) {
      dout(10) << __func__ << " already locked" << dendl;
      return -ENOLCK;
    }
  }
  file->locked = true;
  *plock = new FileLock(file);
  dout(10) << __func__ << " locked " << file->fnode
	   << " with " << *plock << dendl;
  return 0;
}

int BlueFS::unlock_file(FileLock *fl)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << fl << " on " << fl->file->fnode << dendl;
  ceph_assert(fl->file->locked);
  fl->file->locked = false;
  delete fl;
  return 0;
}

int BlueFS::readdir(const string& dirname, vector<string> *ls)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << dendl;
  if (dirname.empty()) {
    // list dirs
    ls->reserve(dir_map.size() + 2);
    for (auto& q : dir_map) {
      ls->push_back(q.first);
    }
  } else {
    // list files in dir
    map<string,DirRef>::iterator p = dir_map.find(dirname);
    if (p == dir_map.end()) {
      dout(20) << __func__ << " dir " << dirname << " not found" << dendl;
      return -ENOENT;
    }
    DirRef dir = p->second;
    ls->reserve(dir->file_map.size() + 2);
    for (auto& q : dir->file_map) {
      ls->push_back(q.first);
    }
  }
  ls->push_back(".");
  ls->push_back("..");
  return 0;
}

int BlueFS::unlink(const string& dirname, const string& filename)
{
  std::lock_guard l(lock);
  dout(10) << __func__ << " " << dirname << "/" << filename << dendl;
  map<string,DirRef>::iterator p = dir_map.find(dirname);
  if (p == dir_map.end()) {
    dout(20) << __func__ << " dir " << dirname << " not found" << dendl;
    return -ENOENT;
  }
  DirRef dir = p->second;
  map<string,FileRef>::iterator q = dir->file_map.find(filename);
  if (q == dir->file_map.end()) {
    dout(20) << __func__ << " file " << dirname << "/" << filename
	     << " not found" << dendl;
    return -ENOENT;
  }
  FileRef file = q->second;
  if (file->locked) {
    dout(20) << __func__ << " file " << dirname << "/" << filename
             << " is locked" << dendl;
    return -EBUSY;
  }
  dir->file_map.erase(filename);
  log_t.op_dir_unlink(dirname, filename);
  _drop_link(file);
  return 0;
}

bool BlueFS::wal_is_rotational()
{
  if (bdev[BDEV_WAL]) {
    return bdev[BDEV_WAL]->is_rotational();
  } else if (bdev[BDEV_DB]) {
    return bdev[BDEV_DB]->is_rotational();
  }
  return bdev[BDEV_SLOW]->is_rotational();
}
