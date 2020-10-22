// Copyright (c) 2018-Present Red Hat Inc.  All rights reserved.
//
// Copyright (c) 2011-2018, Facebook, Inc.  All rights reserved.
// This source code is licensed under both the GPLv2 and Apache 2.0 License
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "BinnedLRUCache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "common/pretty_binary.h"

#define dout_context cct
#define dout_subsys ceph_subsys_rocksdb
#undef dout_prefix
#define dout_prefix *_dout << "rocksdb: "

namespace rocksdb_cache {

BinnedLRUHandleTable::BinnedLRUHandleTable() : list_(nullptr), length_(0), elems_(0) {
  Resize();
}

BinnedLRUHandleTable::~BinnedLRUHandleTable() {
  ApplyToAllCacheEntries([](BinnedLRUHandle* h) {
    if (h->refs == 1) {
      h->Free();
    }
  });
  delete[] list_;
}

BinnedLRUHandle* BinnedLRUHandleTable::Lookup(const rocksdb::Slice& key, uint32_t hash) {
  return *FindPointer(key, hash);
}

BinnedLRUHandle* BinnedLRUHandleTable::Insert(BinnedLRUHandle* h) {
  BinnedLRUHandle** ptr = FindPointer(h->key(), h->hash);
  BinnedLRUHandle* old = *ptr;
  h->next_hash = (old == nullptr ? nullptr : old->next_hash);
  *ptr = h;
  if (old == nullptr) {
    ++elems_;
    if (elems_ > length_) {
      // Since each cache entry is fairly large, we aim for a small
      // average linked list length (<= 1).
      Resize();
    }
  }
  return old;
}

BinnedLRUHandle* BinnedLRUHandleTable::Remove(const rocksdb::Slice& key, uint32_t hash) {
  BinnedLRUHandle** ptr = FindPointer(key, hash);
  BinnedLRUHandle* result = *ptr;
  if (result != nullptr) {
    *ptr = result->next_hash;
    --elems_;
  }
  return result;
}

BinnedLRUHandle** BinnedLRUHandleTable::FindPointer(const rocksdb::Slice& key, uint32_t hash) {
  BinnedLRUHandle** ptr = &list_[hash & (length_ - 1)];
  while (*ptr != nullptr && ((*ptr)->hash != hash || key != (*ptr)->key())) {
    ptr = &(*ptr)->next_hash;
  }
  return ptr;
}

void BinnedLRUHandleTable::Resize() {
  uint32_t new_length = 16;
  while (new_length < elems_ * 1.5) {
    new_length *= 2;
  }
  BinnedLRUHandle** new_list = new BinnedLRUHandle*[new_length];
  memset(new_list, 0, sizeof(new_list[0]) * new_length);
  uint32_t count = 0;
  for (uint32_t i = 0; i < length_; i++) {
    BinnedLRUHandle* h = list_[i];
    while (h != nullptr) {
      BinnedLRUHandle* next = h->next_hash;
      uint32_t hash = h->hash;
      BinnedLRUHandle** ptr = &new_list[hash & (new_length - 1)];
      h->next_hash = *ptr;
      *ptr = h;
      h = next;
      count++;
    }
  }
  ceph_assert(elems_ == count);
  delete[] list_;
  list_ = new_list;
  length_ = new_length;
}

BinnedLRUCacheShard::BinnedLRUCacheShard(CephContext *c, size_t capacity, bool strict_capacity_limit,
					 double high_pri_pool_ratio)
    : cct(c),
      capacity_(0),
      high_pri_pool_usage_(0),
      strict_capacity_limit_(strict_capacity_limit),
      high_pri_pool_ratio_(high_pri_pool_ratio),
      high_pri_pool_capacity_(0),
      usage_(0),
      lru_usage_(0) {
  // Make empty circular linked list
  lru_.next = &lru_;
  lru_.prev = &lru_;
  lru_low_pri_ = &lru_;
  SetCapacity(capacity);
}

BinnedLRUCacheShard::~BinnedLRUCacheShard() {}

bool BinnedLRUCacheShard::Unref(BinnedLRUHandle* e) {
  ceph_assert(e->refs > 0);
  e->refs--;
  return e->refs == 0;
}

// Call deleter and free

void BinnedLRUCacheShard::EraseUnRefEntries() {
  ceph::autovector<BinnedLRUHandle*> last_reference_list;
  {
    std::lock_guard<std::mutex> l(mutex_);
    while (lru_.next != &lru_) {
      BinnedLRUHandle* old = lru_.next;
      ceph_assert(old->InCache());
      ceph_assert(old->refs ==
             1);  // LRU list contains elements which may be evicted
      LRU_Remove(old);
      table_.Remove(old->key(), old->hash);
      old->SetInCache(false);
      Unref(old);
      usage_ -= old->charge;
      last_reference_list.push_back(old);
    }
  }

  for (auto entry : last_reference_list) {
    entry->Free();
  }
}

void BinnedLRUCacheShard::ApplyToAllCacheEntries(void (*callback)(void*, size_t),
                                           bool thread_safe) {
  if (thread_safe) {
    mutex_.lock();
  }
  table_.ApplyToAllCacheEntries(
      [callback](BinnedLRUHandle* h) { callback(h->value, h->charge); });
  if (thread_safe) {
    mutex_.unlock();
  }
}

void BinnedLRUCacheShard::TEST_GetLRUList(BinnedLRUHandle** lru, BinnedLRUHandle** lru_low_pri) {
  *lru = &lru_;
  *lru_low_pri = lru_low_pri_;
}

size_t BinnedLRUCacheShard::TEST_GetLRUSize() {
  BinnedLRUHandle* lru_handle = lru_.next;
  size_t lru_size = 0;
  while (lru_handle != &lru_) {
    lru_size++;
    lru_handle = lru_handle->next;
  }
  return lru_size;
}

double BinnedLRUCacheShard::GetHighPriPoolRatio() const {
  std::lock_guard<std::mutex> l(mutex_);
  return high_pri_pool_ratio_;
}

size_t BinnedLRUCacheShard::GetHighPriPoolUsage() const {
  std::lock_guard<std::mutex> l(mutex_);
  return high_pri_pool_usage_;
}

void BinnedLRUCacheShard::add_stats(size_t& capacity,
				    size_t& high_pri_pool_usage,
				    size_t& usage,
				    size_t& lru_usage,
				    uint64_t& inserts_low,
				    uint64_t& inserts_high,
				    uint64_t& lookups,
				    uint64_t& lookup_hits_low,
				    uint64_t& lookup_hits_high,
				    uint64_t& erases,
				    uint64_t& erases_low,
				    uint64_t& erases_high,
				    uint64_t& evicts_low,
				    uint64_t& evicts_high
				    ) const {
  std::lock_guard<std::mutex> l(mutex_);
  capacity += capacity_;
  high_pri_pool_usage += high_pri_pool_usage_;
  usage += usage_;
  lru_usage += lru_usage_;
  inserts_low += this->inserts_low.load();
  inserts_high += this->inserts_high.load();
  lookups += this->lookups.load();
  lookup_hits_low += this->lookup_hits_low.load();
  lookup_hits_high += this->lookup_hits_high.load();
  erases += this->erases.load();
  erases_low += this->erases_low.load();
  erases_high += this->erases_high.load();
  evicts_low += this->evicts_low.load();
  evicts_high += this->evicts_high.load();
}

void BinnedLRUCacheShard::LRU_Remove(BinnedLRUHandle* e) {
  ceph_assert(e->next != nullptr);
  ceph_assert(e->prev != nullptr);
  if (lru_low_pri_ == e) {
    lru_low_pri_ = e->prev;
  }
  e->next->prev = e->prev;
  e->prev->next = e->next;
  e->prev = e->next = nullptr;
  lru_usage_ -= e->charge;
  if (e->InHighPriPool()) {
    ceph_assert(high_pri_pool_usage_ >= e->charge);
    high_pri_pool_usage_ -= e->charge;
  }
}

void BinnedLRUCacheShard::LRU_Insert(BinnedLRUHandle* e) {
  ceph_assert(e->next == nullptr);
  ceph_assert(e->prev == nullptr);
  if (high_pri_pool_ratio_ > 0 && e->IsHighPri()) {
    // Inset "e" to head of LRU list.
    e->next = &lru_;
    e->prev = lru_.prev;
    e->prev->next = e;
    e->next->prev = e;
    e->SetInHighPriPool(true);
    high_pri_pool_usage_ += e->charge;
    MaintainPoolSize();
  } else {
    // Insert "e" to the head of low-pri pool. Note that when
    // high_pri_pool_ratio is 0, head of low-pri pool is also head of LRU list.
    e->next = lru_low_pri_->next;
    e->prev = lru_low_pri_;
    e->prev->next = e;
    e->next->prev = e;
    e->SetInHighPriPool(false);
    lru_low_pri_ = e;
  }
  lru_usage_ += e->charge;
}

void BinnedLRUCacheShard::MaintainPoolSize() {
  while (high_pri_pool_usage_ > high_pri_pool_capacity_) {
    // Overflow last entry in high-pri pool to low-pri pool.
    lru_low_pri_ = lru_low_pri_->next;
    ceph_assert(lru_low_pri_ != &lru_);
    lru_low_pri_->SetInHighPriPool(false);
    high_pri_pool_usage_ -= lru_low_pri_->charge;
  }
}

void BinnedLRUCacheShard::EvictFromLRU(size_t charge,
                                 ceph::autovector<BinnedLRUHandle*>* deleted) {
  uint32_t high = 0;
  uint32_t low = 0;
  while (usage_ + charge > capacity_ && lru_.next != &lru_) {
    BinnedLRUHandle* old = lru_.next;
    ceph_assert(old->InCache());
    ceph_assert(old->refs == 1);  // LRU list contains elements which may be evicted
    LRU_Remove(old);
    table_.Remove(old->key(), old->hash);
    old->SetInCache(false);
    Unref(old);
    usage_ -= old->charge;
    deleted->push_back(old);
    if (old->InHighPriPool()) {
      high++;
    } else {
      low++;
    }
  }
  evicts_high += high;
  evicts_low += low;
}

void BinnedLRUCacheShard::SetCapacity(size_t capacity) {
  ceph::autovector<BinnedLRUHandle*> last_reference_list;
  {
    std::lock_guard<std::mutex> l(mutex_);
    capacity_ = capacity;
    high_pri_pool_capacity_ = capacity_ * high_pri_pool_ratio_;
    EvictFromLRU(0, &last_reference_list);
  }
  // we free the entries here outside of mutex for
  // performance reasons
  for (auto entry : last_reference_list) {
    entry->Free();
  }
}

void BinnedLRUCacheShard::SetStrictCapacityLimit(bool strict_capacity_limit) {
  std::lock_guard<std::mutex> l(mutex_);
  strict_capacity_limit_ = strict_capacity_limit;
}

rocksdb::Cache::Handle* BinnedLRUCacheShard::Lookup(const rocksdb::Slice& key, uint32_t hash) {
  std::lock_guard<std::mutex> l(mutex_);
  BinnedLRUHandle* e = table_.Lookup(key, hash);
  lookups++;
  if (e != nullptr) {
    ceph_assert(e->InCache());
    if (e->refs == 1) {
      LRU_Remove(e);
    }
    e->refs++;
    e->SetHit();
    if (e->InHighPriPool()) {
      lookup_hits_high++;
    } else {
      lookup_hits_low++;
    }
    e->touch = ceph::mono_clock::now();
  }
  return reinterpret_cast<rocksdb::Cache::Handle*>(e);
}

bool BinnedLRUCacheShard::Ref(rocksdb::Cache::Handle* h) {
  BinnedLRUHandle* handle = reinterpret_cast<BinnedLRUHandle*>(h);
  std::lock_guard<std::mutex> l(mutex_);
  if (handle->InCache() && handle->refs == 1) {
    LRU_Remove(handle);
  }
  handle->refs++;
  return true;
}

void BinnedLRUCacheShard::SetHighPriPoolRatio(double high_pri_pool_ratio) {
  std::lock_guard<std::mutex> l(mutex_);
  high_pri_pool_ratio_ = high_pri_pool_ratio;
  high_pri_pool_capacity_ = capacity_ * high_pri_pool_ratio_;
  MaintainPoolSize();
}

bool BinnedLRUCacheShard::Release(rocksdb::Cache::Handle* handle, bool force_erase) {
  if (handle == nullptr) {
    return false;
  }
  BinnedLRUHandle* e = reinterpret_cast<BinnedLRUHandle*>(handle);
  bool last_reference = false;
  {
    std::lock_guard<std::mutex> l(mutex_);
    last_reference = Unref(e);
    if (last_reference) {
      usage_ -= e->charge;
    }
    if (e->refs == 1 && e->InCache()) {
      // The item is still in cache, and nobody else holds a reference to it
      if (usage_ > capacity_ || force_erase) {
        // the cache is full
        // The LRU list must be empty since the cache is full
        ceph_assert(!(usage_ > capacity_) || lru_.next == &lru_);
        // take this opportunity and remove the item
        table_.Remove(e->key(), e->hash);
        e->SetInCache(false);
        Unref(e);
        usage_ -= e->charge;
        last_reference = true;
      } else {
        // put the item on the list to be potentially freed
        LRU_Insert(e);
      }
    }
  }

  // free outside of mutex
  if (last_reference) {
    e->Free();
  }
  return last_reference;
}

rocksdb::Status BinnedLRUCacheShard::Insert(const rocksdb::Slice& key, uint32_t hash, void* value,
                             size_t charge,
                             void (*deleter)(const rocksdb::Slice& key, void* value),
                             rocksdb::Cache::Handle** handle, rocksdb::Cache::Priority priority) {
  auto e = new BinnedLRUHandle();
  rocksdb::Status s;
  ceph::autovector<BinnedLRUHandle*> last_reference_list;

  e->value = value;
  e->deleter = deleter;
  e->charge = charge;
  e->key_length = key.size();
  e->key_data = new char[e->key_length];
  e->flags = 0;
  e->hash = hash;
  e->refs = (handle == nullptr
                 ? 1
                 : 2);  // One from BinnedLRUCache, one for the returned handle
  e->next = e->prev = nullptr;
  e->SetInCache(true);
  e->SetPriority(priority);
  std::copy_n(key.data(), e->key_length, e->key_data);
  e->touch = ceph::mono_clock::now();
  {
    std::lock_guard<std::mutex> l(mutex_);
    // Free the space following strict LRU policy until enough space
    // is freed or the lru list is empty
    EvictFromLRU(charge, &last_reference_list);

    if (usage_ - lru_usage_ + charge > capacity_ &&
        (strict_capacity_limit_ || handle == nullptr)) {
      if (handle == nullptr) {
        // Don't insert the entry but still return ok, as if the entry inserted
        // into cache and get evicted immediately.
        last_reference_list.push_back(e);
      } else {
        delete e;
        *handle = nullptr;
        s = rocksdb::Status::Incomplete("Insert failed due to LRU cache being full.");
      }
    } else {
      // insert into the cache
      // note that the cache might get larger than its capacity if not enough
      // space was freed
      BinnedLRUHandle* old = table_.Insert(e);
      usage_ += e->charge;
      if (old != nullptr) {
        old->SetInCache(false);
        if (Unref(old)) {
          usage_ -= old->charge;
          // old is on LRU because it's in cache and its reference count
          // was just 1 (Unref returned 0)
          LRU_Remove(old);
          last_reference_list.push_back(old);
        }
      }
      if (handle == nullptr) {
        LRU_Insert(e);
      } else {
        *handle = reinterpret_cast<rocksdb::Cache::Handle*>(e);
      }
      s = rocksdb::Status::OK();
      if (priority == rocksdb::Cache::Priority::HIGH) {
	inserts_high++;
      } else {
	inserts_low++;
      }
    }
  }

  // we free the entries here outside of mutex for
  // performance reasons
  for (auto entry : last_reference_list) {
    entry->Free();
  }

  return s;
}

void BinnedLRUCacheShard::Erase(const rocksdb::Slice& key, uint32_t hash) {
  BinnedLRUHandle* e;
  bool last_reference = false;
  {
    std::lock_guard<std::mutex> l(mutex_);
    erases++;
    e = table_.Remove(key, hash);
    if (e != nullptr) {
      last_reference = Unref(e);
      if (last_reference) {
        usage_ -= e->charge;
      }
      if (last_reference && e->InCache()) {
        LRU_Remove(e);
      }
      e->SetInCache(false);
      if (e->InHighPriPool()) {
	erases_high++;
      } else {
	erases_low++;
      }
    }
  }

  // mutex not held here
  // last_reference will only be true if e != nullptr
  if (last_reference) {
    e->Free();
  }
}

size_t BinnedLRUCacheShard::GetUsage() const {
  std::lock_guard<std::mutex> l(mutex_);
  return usage_;
}

size_t BinnedLRUCacheShard::GetPinnedUsage() const {
  std::lock_guard<std::mutex> l(mutex_);
  ceph_assert(usage_ >= lru_usage_);
  return usage_ - lru_usage_;
}

std::string BinnedLRUCacheShard::GetPrintableOptions() const {
  const int kBufferSize = 200;
  char buffer[kBufferSize];
  {
    std::lock_guard<std::mutex> l(mutex_);
    snprintf(buffer, kBufferSize, "    high_pri_pool_ratio: %.3lf\n",
             high_pri_pool_ratio_);
  }
  return std::string(buffer);
}

BinnedLRUCache::BinnedLRUCache(CephContext *c, 
                               size_t capacity, 
                               int num_shard_bits,
                               bool strict_capacity_limit, 
                               double high_pri_pool_ratio,
			       const std::string& name)
  : ShardedCache(capacity, num_shard_bits, strict_capacity_limit), cct(c) {
  num_shards_ = 1 << num_shard_bits;
  // TODO: Switch over to use mempool
  int rc = posix_memalign((void**) &shards_, 
                          CACHE_LINE_SIZE, 
                          sizeof(BinnedLRUCacheShard) * num_shards_);
  if (rc != 0) {
    throw std::bad_alloc();
  } 
  size_t per_shard = (capacity + (num_shards_ - 1)) / num_shards_;
  for (int i = 0; i < num_shards_; i++) {
    new (&shards_[i])
        BinnedLRUCacheShard(c, per_shard, strict_capacity_limit, high_pri_pool_ratio);
  }
  if (AdminSocket *admin_socket = cct->get_admin_socket(); admin_socket) {
    int r = admin_socket->register_command(
      "rocksdb cache stat name=cache,req=false,type=CephString name=shard,req=false,type=CephString",
      this,
      "<cache name> [<shard>]. Dump stats for specific shard. If not set, sum up for entire cache.",
      "cache",
      name);
    ceph_assert(r == 0);
    r = admin_socket->register_command(
      "rocksdb cache list name=cache,req=false,type=CephString name=shard,req=false,type=CephString",
      this,
      "<cache name> [<shard>]. List cached elements for specific shard, or all if not set.",
      "cache",
      name);
    ceph_assert(r == 0);
  }
}

BinnedLRUCache::~BinnedLRUCache() {
  for (int i = 0; i < num_shards_; i++) {
    shards_[i].~BinnedLRUCacheShard();
  }
  aligned_free(shards_);
  if (AdminSocket *admin_socket = cct->get_admin_socket(); admin_socket) {
    admin_socket->unregister_commands(this);
  }
}

int BinnedLRUCache::call(std::string_view command, const cmdmap_t& cmdmap,
			 Formatter *f, std::ostream& ss, bufferlist& out) {
  int r = 0;
  if (command == "rocksdb cache stat") {
    std::string shardstr;
    size_t capacity = 0;
    size_t high_pri_pool_usage = 0;
    size_t usage = 0;
    size_t lru_usage = 0;
    uint64_t inserts_low = 0;
    uint64_t inserts_high = 0;
    uint64_t lookups = 0;
    uint64_t lookup_hits_low = 0;
    uint64_t lookup_hits_high = 0;
    uint64_t erases = 0;
    uint64_t erases_low = 0;
    uint64_t erases_high = 0;
    uint64_t evicts_low = 0;
    uint64_t evicts_high = 0;
    bool one_shard = false;
    int shard_id = 0;
    if (!ceph::common::cmd_getval(cmdmap, "shard", shardstr)) {
      //shard not provided, calc total
      for (int i = 0; i < num_shards_; i++) {
	shards_[i].add_stats(capacity, high_pri_pool_usage, usage, lru_usage,
			     inserts_low, inserts_high, lookups, lookup_hits_low,
			     lookup_hits_high, erases, erases_low, erases_high,
			     evicts_low, evicts_high);
      }
    } else {
      std::string err;
      shard_id = strict_strtol(shardstr.c_str(), 0, &err);
      if (err.empty() && shard_id >= 0 && shard_id < num_shards_) {
	shards_[shard_id].add_stats(capacity, high_pri_pool_usage, usage, lru_usage,
				    inserts_low, inserts_high, lookups, lookup_hits_low,
				    lookup_hits_high, erases, erases_low, erases_high,
				    evicts_low, evicts_high);
	one_shard = true;
      } else {
	ss << "invalid shard (" << shardstr << "); valid range 0-" << to_string(num_shards_ - 1);
	r = -EINVAL;
      }
    }
    if (r == 0) {
      if (one_shard) {
	f->open_object_section("shard");
	f->dump_unsigned("id", shard_id);
      } else {
	f->open_object_section("all_shards_sum");
	f->dump_unsigned("num_shards", num_shards_);
      }
      f->dump_unsigned("capacity", capacity);
      f->dump_unsigned("high_pri_pool_usage", high_pri_pool_usage);
      f->dump_unsigned("usage", usage);
      f->dump_unsigned("lru_usage", lru_usage);
      f->dump_unsigned("inserts_low", inserts_low);
      f->dump_unsigned("inserts_high", inserts_high);
      f->dump_unsigned("lookups", lookups);
      f->dump_unsigned("lookup_hits_low", lookup_hits_low);
      f->dump_unsigned("lookup_hits_high", lookup_hits_high);
      f->dump_unsigned("erases", erases);
      f->dump_unsigned("erases_low", erases_low);
      f->dump_unsigned("erases_high", erases_high);
      f->dump_unsigned("evicts_low", evicts_low);
      f->dump_unsigned("evicts_high", evicts_high);
      f->close_section();
    }
  } else if (command == "rocksdb cache list") {
    std::string shardstr;
    int shard_id = 0;
    int shard_from = 0;
    int shard_to = num_shards_;
    if (ceph::common::cmd_getval(cmdmap, "shard", shardstr)) {
      std::string err;
      shard_id = strict_strtol(shardstr.c_str(), 0, &err);
      if (err.empty() && shard_id >= 0 && shard_id < num_shards_) {
	shard_from = shard_id;
	shard_to = shard_id + 1;
      } else {
	ss << "invalid shard (" << shardstr << "); valid range 0-" << to_string(num_shards_ - 1);
	r = -EINVAL;
      }
    }
    if (r == 0) {
      ceph::mono_clock::time_point now = ceph::mono_clock::now();
      f->open_object_section("lru_lists");
      for (int i = shard_from; i < shard_to; i++) {
	f->open_object_section("shard");
	f->dump_unsigned("id", i);
	std::lock_guard<std::mutex> l(shards_[i].mutex_);
	BinnedLRUHandle* start = &shards_[i].lru_;;
	BinnedLRUHandle* e = start->prev;
	bool in_low = false;
	while (e != start) {
	  if (e == shards_[i].lru_low_pri_) {
	    in_low = true;
	  }
	  if (in_low) {
	    f->open_object_section("low");
	  } else {
	    f->open_object_section("high");
	  }
	  f->dump_string("key", pretty_binary_string(std::string(e->key_data, e->key_length)));
	  f->dump_unsigned("charge", e->charge);
	  f->dump_unsigned("refs", e->refs);
	  f->dump_float("age", ceph::to_seconds<double>(now - e->touch));
	  f->close_section();
	  e = e->prev;
	}
	f->close_section();
      }
      f->close_section();
    }
  } else {
    ss << "Invalid command" << std::endl;
    r = -ENOSYS;
  }
  return r;
}

CacheShard* BinnedLRUCache::GetShard(int shard) {
  return reinterpret_cast<CacheShard*>(&shards_[shard]);
}

const CacheShard* BinnedLRUCache::GetShard(int shard) const {
  return reinterpret_cast<CacheShard*>(&shards_[shard]);
}

void* BinnedLRUCache::Value(Handle* handle) {
  return reinterpret_cast<const BinnedLRUHandle*>(handle)->value;
}

size_t BinnedLRUCache::GetCharge(Handle* handle) const {
  return reinterpret_cast<const BinnedLRUHandle*>(handle)->charge;
}

uint32_t BinnedLRUCache::GetHash(Handle* handle) const {
  return reinterpret_cast<const BinnedLRUHandle*>(handle)->hash;
}

void BinnedLRUCache::DisownData() {
// Do not drop data if compile with ASAN to suppress leak warning.
#ifndef __SANITIZE_ADDRESS__
  shards_ = nullptr;
#endif  // !__SANITIZE_ADDRESS__
}

size_t BinnedLRUCache::TEST_GetLRUSize() {
  size_t lru_size_of_all_shards = 0;
  for (int i = 0; i < num_shards_; i++) {
    lru_size_of_all_shards += shards_[i].TEST_GetLRUSize();
  }
  return lru_size_of_all_shards;
}

void BinnedLRUCache::SetHighPriPoolRatio(double high_pri_pool_ratio) {
  for (int i = 0; i < num_shards_; i++) {
    shards_[i].SetHighPriPoolRatio(high_pri_pool_ratio);
  }
}

double BinnedLRUCache::GetHighPriPoolRatio() const {
  double result = 0.0;
  if (num_shards_ > 0) {
    result = shards_[0].GetHighPriPoolRatio();
  }
  return result;
}

size_t BinnedLRUCache::GetHighPriPoolUsage() const {
  // We will not lock the cache when getting the usage from shards.
  size_t usage = 0;
  for (int s = 0; s < num_shards_; s++) {
    usage += shards_[s].GetHighPriPoolUsage();
  }
  return usage;
}

// PriCache

int64_t BinnedLRUCache::request_cache_bytes(PriorityCache::Priority pri, uint64_t total_cache) const
{
  int64_t assigned = get_cache_bytes(pri);
  int64_t request = 0;

  switch (pri) {
  // PRI0 is for rocksdb's high priority items (indexes/filters)
  case PriorityCache::Priority::PRI0:
    {
      request = GetHighPriPoolUsage();
      break;
    }
  // All other cache items are currently shoved into the PRI1 priority. 
  case PriorityCache::Priority::PRI1:
    {
      request = GetUsage();
      request -= GetHighPriPoolUsage();
      break;
    }
  default:
    break;
  }
  request = (request > assigned) ? request - assigned : 0;
  ldout(cct, 10) << __func__ << " Priority: " << static_cast<uint32_t>(pri)
                 << " Request: " << request << dendl;
  return request;
}

int64_t BinnedLRUCache::commit_cache_size(uint64_t total_bytes)
{
  size_t old_bytes = GetCapacity();
  int64_t new_bytes = PriorityCache::get_chunk(
      get_cache_bytes(), total_bytes);
  ldout(cct, 10) << __func__ << " old: " << old_bytes
                 << " new: " << new_bytes << dendl;
  SetCapacity((size_t) new_bytes);

  double ratio = 0;
  if (new_bytes > 0) {
    int64_t pri0_bytes = get_cache_bytes(PriorityCache::Priority::PRI0);
    // Add 10% of the "reserved" bytes so the ratio can't get stuck at 0 
    pri0_bytes += (new_bytes - get_cache_bytes()) / 10;
    ratio = (double) pri0_bytes / new_bytes;
  }
  ldout(cct, 10) << __func__ << " High Pri Pool Ratio set to " << ratio << dendl;
  SetHighPriPoolRatio(ratio);
  return new_bytes;
}

std::shared_ptr<rocksdb::Cache> NewBinnedLRUCache(
    CephContext *c, 
    size_t capacity,
    int num_shard_bits,
    bool strict_capacity_limit,
    double high_pri_pool_ratio,
    const std::string& name) {
  if (num_shard_bits >= 20) {
    return nullptr;  // the cache cannot be sharded into too many fine pieces
  }
  if (high_pri_pool_ratio < 0.0 || high_pri_pool_ratio > 1.0) {
    // invalid high_pri_pool_ratio
    return nullptr;
  }
  if (num_shard_bits < 0) {
    num_shard_bits = GetDefaultCacheShardBits(capacity);
  }
  return std::make_shared<BinnedLRUCache>(
    c, capacity, num_shard_bits, strict_capacity_limit, high_pri_pool_ratio, name);
}

}  // namespace rocksdb_cache
