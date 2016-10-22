// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 Allen Samuels <allen.samuels@sandisk.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "include/mempool.h"
#include "include/demangle.h"


// default to debug_mode off
bool mempool::debug_mode = false;

// --------------------------------------------------------------

mempool::pool_t& mempool::get_pool(mempool::pool_index_t ix)
{
  // We rely on this array being initialized before any invocation of
  // this function, even if it is called by ctors in other compilation
  // units that are being initialized before this compilation unit.
  static mempool::pool_t table[num_pools];
  return table[ix];
}

const char *mempool::get_pool_name(mempool::pool_index_t ix) {
#define P(x) #x,
  static const char *names[num_pools] = {
    DEFINE_MEMORY_POOLS_HELPER(P)
  };
#undef P
  return names[ix];
}

void mempool::dump(ceph::Formatter *f, size_t skip)
{
  for (size_t i = skip; i < num_pools; ++i) {
    const pool_t &pool = mempool::get_pool((pool_index_t)i);
    f->open_object_section(get_pool_name((pool_index_t)i));
    pool.dump(f);
    f->close_section();
  }
}

void mempool::set_debug_mode(bool d)
{
  debug_mode = d;
}

// --------------------------------------------------------------
// pool_t

size_t mempool::pool_t::sumup(std::atomic<ssize_t> shard_t::*pm) const {
  ssize_t result = 0;
  for (size_t i = 0; i < num_shards; ++i) {
    result += shard[i].*pm;
  }
  assert(result >= 0);
  return (size_t) result;
}

size_t mempool::pool_t::sumupdiff(std::atomic<ssize_t> shard_t::*pl, std::atomic<ssize_t> shard_t::*pr) const {
  ssize_t result = 0;
  for (size_t i = 0; i < num_shards; ++i) {
    result += shard[i].*pl - shard[i].*pr;
  }
  assert(result >= 0);
  return (size_t) result;
}

size_t mempool::pool_t::allocated_bytes() const { return sumup(&shard_t::bytes); }
size_t mempool::pool_t::free_bytes()      const { return sumup(&shard_t::free_bytes); }
size_t mempool::pool_t::inuse_bytes()     const { return sumupdiff(&shard_t::bytes,&shard_t::free_bytes); }
size_t mempool::pool_t::allocated_items() const { return sumup(&shard_t::items); }
size_t mempool::pool_t::free_items()      const { return sumup(&shard_t::free_items); }
size_t mempool::pool_t::inuse_items()     const { return sumupdiff(&shard_t::items,&shard_t::free_items); }
size_t mempool::pool_t::containers()      const { return sumup(&shard_t::containers); }
size_t mempool::pool_t::slabs()           const { return sumup(&shard_t::slabs); }

void mempool::pool_t::get_stats(
  stats_t *total,
  std::map<std::string, stats_t> *by_type) const
{
  for (size_t i = 0; i < num_shards; ++i) {
    total->items += shard[i].items;
    total->bytes += shard[i].bytes;
    total->free_items += shard[i].free_items;
    total->free_bytes += shard[i].free_bytes;
  }
  if (debug_mode) {
    std::unique_lock<std::mutex> shard_lock(lock);
    for (auto &p : type_map) {
      std::string n = ceph_demangle(p.second.type_name);
      stats_t &s = (*by_type)[n];
      s.bytes = p.second.items * p.second.item_size;
      s.items = p.second.items;
      s.free_items = p.second.free_items;
      s.free_bytes = p.second.free_items * p.second.item_size;
    }
  }
}

void mempool::pool_t::dump(ceph::Formatter *f) const
{
  stats_t total;
  std::map<std::string, stats_t> by_type;
  get_stats(&total, &by_type);
  f->dump_object("total", total);
  if (!by_type.empty()) {
    for (auto &i : by_type) {
      f->open_object_section(i.first.c_str());
      i.second.dump(f);
      f->close_section();
    }
  }
}
