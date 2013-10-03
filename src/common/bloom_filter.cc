// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/types.h"
#include "common/bloom_filter.hpp"

void bloom_filter::encode(bufferlist& bl) const
{
  ENCODE_START(2, 2, bl);
  ::encode((uint64_t)salt_count_, bl);
  ::encode((uint64_t)inserted_element_count_, bl);
  ::encode((uint64_t)random_seed_, bl);
  bufferptr bp((const char*)bit_table_, table_size_);
  ::encode(bp, bl);
  ENCODE_FINISH(bl);
}

void bloom_filter::decode(bufferlist::iterator& p)
{
  DECODE_START(2, p);
  uint64_t v;
  ::decode(v, p);
  salt_count_ = v;
  ::decode(v, p);
  inserted_element_count_ = v;
  ::decode(v, p);
  random_seed_ = v;
  bufferlist t;
  ::decode(t, p);

  salt_.clear();
  generate_unique_salt();
  table_size_ = t.length();
  delete bit_table_;
  if (table_size_) {
    bit_table_ = new cell_type[table_size_];
    t.copy(0, table_size_, (char *)bit_table_);
  } else {
    bit_table_ = NULL;
  }

  DECODE_FINISH(p);
}

void bloom_filter::dump(Formatter *f) const
{
  f->dump_unsigned("salt_count", salt_count_);
  f->dump_unsigned("table_size", table_size_);
  f->dump_unsigned("insert_count", inserted_element_count_);
  f->dump_unsigned("random_seed", random_seed_);

  f->open_array_section("salt_table");
  for (std::vector<bloom_type>::const_iterator i = salt_.begin(); i != salt_.end(); ++i)
    f->dump_unsigned("salt", *i);
  f->close_section();

  f->open_array_section("bit_table");
  for (unsigned i = 0; i < table_size_; ++i)
    f->dump_unsigned("byte", (unsigned)bit_table_[i]);
  f->close_section();
}

void bloom_filter::generate_test_instances(list<bloom_filter*>& ls)
{
  ls.push_back(new bloom_filter(10, .5, 1));
  ls.push_back(new bloom_filter(10, .5, 1));
  ls.back()->insert("foo");
  ls.back()->insert("bar");
  ls.push_back(new bloom_filter(50, .5, 1));
  ls.back()->insert("foo");
  ls.back()->insert("bar");
  ls.back()->insert("baz");
  ls.back()->insert("boof");
  ls.back()->insert("boogggg");
}


void compressible_bloom_filter::encode(bufferlist& bl) const
{
  ENCODE_START(2, 2, bl);
  ::encode((uint64_t)salt_count_, bl);
  uint32_t s = size_list.size();
  ::encode(s, bl);
  for (vector<size_t>::const_iterator p = size_list.begin();
       p != size_list.end(); ++p)
    ::encode((uint64_t)*p, bl);
  ::encode((uint64_t)inserted_element_count_, bl);
  ::encode((uint64_t)random_seed_, bl);
  bufferptr bp((const char*)bit_table_, table_size_);
  ::encode(bp, bl);
  ENCODE_FINISH(bl);
}

void compressible_bloom_filter::decode(bufferlist::iterator& p)
{
  DECODE_START(2, p);
  uint64_t v;
  ::decode(v, p);
  salt_count_ = v;

  uint32_t s;
  ::decode(s, p);
  size_list.resize(s);
  for (unsigned i = 0; i < s; i++) {
    ::decode(v, p);
    size_list[i] = v;
  }

  ::decode(v, p);
  inserted_element_count_ = v;
  ::decode(v, p);
  random_seed_ = v;
  bufferlist t;
  ::decode(t, p);

  salt_.clear();
  generate_unique_salt();
  table_size_ = t.length();
  assert((!table_size_ && size_list.empty()) ||
	 table_size_ == size_list.back());
  delete bit_table_;
  if (table_size_) {
    bit_table_ = new cell_type[table_size_];
    t.copy(0, table_size_, (char *)bit_table_);
  } else {
    bit_table_ = NULL;
  }

  DECODE_FINISH(p);
}

void compressible_bloom_filter::dump(Formatter *f) const
{
  f->dump_unsigned("salt_count", salt_count_);
  f->dump_unsigned("insert_count", inserted_element_count_);
  f->dump_unsigned("random_seed", random_seed_);
  f->dump_unsigned("table_size", table_size_);
  f->open_array_section("table_sizes");
  for (vector<size_t>::const_iterator p = size_list.begin();
       p != size_list.end(); ++p)
    f->dump_unsigned("size", (uint64_t)*p);
  f->close_section();

  f->open_array_section("salt_table");
  for (std::vector<bloom_type>::const_iterator i = salt_.begin(); i != salt_.end(); ++i)
    f->dump_unsigned("salt", *i);
  f->close_section();

  f->open_array_section("bit_table");
  for (unsigned i = 0; i < table_size_; ++i)
    f->dump_unsigned("byte", (unsigned)bit_table_[i]);
  f->close_section();
}

void compressible_bloom_filter::generate_test_instances(list<compressible_bloom_filter*>& ls)
{
  ls.push_back(new compressible_bloom_filter(10, .5, 1));
  ls.push_back(new compressible_bloom_filter(10, .5, 1));
  ls.back()->insert("foo");
  ls.back()->insert("bar");
  ls.push_back(new compressible_bloom_filter(50, .5, 1));
  ls.back()->insert("foo");
  ls.back()->insert("bar");
  ls.back()->insert("baz");
  ls.back()->insert("boof");
  ls.back()->compress(20);
  ls.back()->insert("boogggg");
}
