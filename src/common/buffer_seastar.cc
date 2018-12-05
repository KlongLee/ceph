// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <seastar/core/sharded.hh>

#include "include/buffer_raw.h"
#include "buffer_seastar.h"

using temporary_buffer = seastar::temporary_buffer<char>;

namespace ceph::buffer {

class raw_seastar_foreign_ptr : public raw {
  seastar::foreign_ptr<temporary_buffer> ptr;
 public:
  raw_seastar_foreign_ptr(temporary_buffer&& buf)
    : raw(buf.get_write(), buf.size()), ptr(std::move(buf)) {}
  raw* clone_empty() override {
    return create(len);
  }
};

raw* create_foreign(temporary_buffer&& buf) {
  return new raw_seastar_foreign_ptr(std::move(buf));
}

class raw_seastar_local_ptr : public raw {
  temporary_buffer buf;
 public:
  raw_seastar_local_ptr(temporary_buffer&& buf)
    : raw(buf.get_write(), buf.size()), buf(std::move(buf)) {}
  raw* clone_empty() override {
    return create(len);
  }
};

raw* create(temporary_buffer&& buf) {
  return new raw_seastar_local_ptr(std::move(buf));
}

// buffer::ptr conversions

ptr::operator seastar::temporary_buffer<char>() &
{
  return {c_str(), _len, seastar::make_object_deleter(*this)};
}

ptr::operator seastar::temporary_buffer<char>() &&
{
  auto data = c_str();
  auto length = _len;
  return {data, length, seastar::make_object_deleter(std::move(*this))};
}

// buffer::list conversions

list::operator seastar::net::packet() &&
{
  seastar::net::packet p;
  p.reserve(_buffers.size());
  for (auto& ptr : _buffers) {
    // append each ptr as a temporary_buffer
    p = seastar::net::packet(std::move(p), std::move(ptr));
  }
  clear();
  return p;
}

} // namespace ceph::buffer

namespace {

using ceph::buffer::raw;
class raw_seastar_local_shared_ptr : public raw {
  temporary_buffer buf;
public:
  raw_seastar_local_shared_ptr(temporary_buffer& buf)
    : raw(buf.get_write(), buf.size()), buf(buf.share()) {}
  raw* clone_empty() override {
    return ceph::buffer::create(len);
  }
};
}

buffer::ptr seastar_buffer_iterator::get_ptr(size_t len)
{
  buffer::raw* r = new raw_seastar_local_shared_ptr{buf};
  buffer::ptr p{r};
  p.set_length(len);
  return p;
}

buffer::ptr const_seastar_buffer_iterator::get_ptr(size_t len)
{
  buffer::raw* r = buffer::copy(get_pos_add(len), len);
  return buffer::ptr{r};
}
