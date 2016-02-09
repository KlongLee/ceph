// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_CLS_JOURNAL_TYPES_H
#define CEPH_CLS_JOURNAL_TYPES_H

#include "include/int_types.h"
#include "include/buffer_fwd.h"
#include "include/encoding.h"
#include <iosfwd>
#include <list>
#include <set>
#include <string>

namespace ceph {
class Formatter;
}

namespace cls {
namespace journal {

struct EntryPosition {
  uint64_t tag_tid;
  uint64_t entry_tid;

  EntryPosition() : tag_tid(0), entry_tid(0) {}
  EntryPosition(uint64_t _tag_tid, uint64_t _entry_tid)
    : tag_tid(_tag_tid), entry_tid(_entry_tid) {}

  inline bool operator==(const EntryPosition& rhs) const {
    return (tag_tid == rhs.tag_tid && entry_tid == rhs.entry_tid);
  }

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& iter);
  void dump(Formatter *f) const;

  inline bool operator<(const EntryPosition &rhs) const {
    if (tag_tid != rhs.tag_tid) {
      return tag_tid < rhs.tag_tid;
    }
    return entry_tid < rhs.entry_tid;
  }

  static void generate_test_instances(std::list<EntryPosition *> &o);
};

typedef std::list<EntryPosition> EntryPositions;

struct ObjectSetPosition {
  uint64_t object_number;
  EntryPositions entry_positions;

  ObjectSetPosition() : object_number(0) {}
  ObjectSetPosition(uint64_t _object_number,
                    const EntryPositions &_entry_positions)
    : object_number(_object_number), entry_positions(_entry_positions) {}

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& iter);
  void dump(Formatter *f) const;

  inline bool operator==(const ObjectSetPosition &rhs) const {
    return (object_number == rhs.object_number &&
            entry_positions == rhs.entry_positions);
  }

  static void generate_test_instances(std::list<ObjectSetPosition *> &o);
};

struct Client {
  std::string id;
  bufferlist data;
  ObjectSetPosition commit_position;

  Client() {}
  Client(const std::string& _id, const bufferlist &_data,
         const ObjectSetPosition &_commit_position = ObjectSetPosition())
    : id(_id), data(_data), commit_position(_commit_position) {}

  inline bool operator==(const Client &rhs) const {
    return (id == rhs.id &&
            data.contents_equal(rhs.data) &&
            commit_position == rhs.commit_position);
  }
  inline bool operator<(const Client &rhs) const {
    return (id < rhs.id);
  }

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& iter);
  void dump(Formatter *f) const;

  static void generate_test_instances(std::list<Client *> &o);
};

struct Tag {
  static const uint64_t TAG_CLASS_NEW = static_cast<uint64_t>(-1);

  uint64_t tid;
  uint64_t tag_class;
  bufferlist data;

  Tag() : tid(0), tag_class(0) {}
  Tag(uint64_t tid, uint64_t tag_class, const bufferlist &data)
    : tid(tid), tag_class(tag_class), data(data) {}

  inline bool operator==(const Tag &rhs) const {
    return (tid == rhs.tid &&
            tag_class == rhs.tag_class &&
            data.contents_equal(rhs.data));
  }
  inline bool operator<(const Tag &rhs) const {
    return (tid < rhs.tid);
  }

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& iter);
  void dump(Formatter *f) const;

  static void generate_test_instances(std::list<Tag *> &o);
};

WRITE_CLASS_ENCODER(EntryPosition);
WRITE_CLASS_ENCODER(ObjectSetPosition);
WRITE_CLASS_ENCODER(Client);
WRITE_CLASS_ENCODER(Tag);

std::ostream &operator<<(std::ostream &os,
                         const EntryPosition &entry_position);
std::ostream &operator<<(std::ostream &os,
                         const ObjectSetPosition &object_set_position);
std::ostream &operator<<(std::ostream &os,
			 const Client &client);
std::ostream &operator<<(std::ostream &os, const Tag &tag);

} // namespace journal
} // namespace cls

using cls::journal::encode;
using cls::journal::decode;

#endif // CEPH_CLS_JOURNAL_TYPES_H
