// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include "crimson/common/log.h"
#include "crimson/os/seastore/onode_manager/staged-fltree/value.h"

namespace crimson::os::seastore::onode {

class TestValue final : public Value {
 public:
  static constexpr auto HEADER_MAGIC = value_magic_t::TEST;
  using id_t = uint16_t;
  using magic_t = uint32_t;
  struct magic_packed_t {
    magic_t value;
  } __attribute__((packed));

 private:
  struct payload_t {
    id_t id;
  } __attribute__((packed));

  struct Replayable {
    static void set_id(NodeExtentMutable& payload_mut, id_t id) {
      auto p_payload = get_write(payload_mut);
      p_payload->id = id;
    }

    static void set_tail_magic(NodeExtentMutable& payload_mut, magic_t magic) {
      auto length = payload_mut.get_length();
      auto offset_magic = length - sizeof(magic_t);
      payload_mut.copy_in_relative(offset_magic, magic);
    }

   private:
    static payload_t* get_write(NodeExtentMutable& payload_mut) {
      return reinterpret_cast<payload_t*>(payload_mut.get_write());
    }
  };

 public:
  class Recorder final : public ValueDeltaRecorder {
    enum class delta_op_t : uint8_t {
      UPDATE_ID,
      UPDATE_TAIL_MAGIC,
    };

   public:
    Recorder(ceph::bufferlist& encoded)
      : ValueDeltaRecorder(encoded) {}
    ~Recorder() override = default;

    void encode_set_id(NodeExtentMutable& payload_mut, id_t id) {
      auto& encoded = get_encoded(payload_mut);
      ceph::encode(delta_op_t::UPDATE_ID, encoded);
      ceph::encode(id, encoded);
    }

    void encode_set_tail_magic(NodeExtentMutable& payload_mut, magic_t magic) {
      auto& encoded = get_encoded(payload_mut);
      ceph::encode(delta_op_t::UPDATE_TAIL_MAGIC, encoded);
      ceph::encode(magic, encoded);
    }

   protected:
    value_magic_t get_header_magic() const override {
      return HEADER_MAGIC;
    }

    void apply_value_delta(ceph::bufferlist::const_iterator& delta,
                           NodeExtentMutable& payload_mut,
                           laddr_t value_addr) override {
      delta_op_t op;
      try {
        ceph::decode(op, delta);
        switch (op) {
        case delta_op_t::UPDATE_ID: {
          logger().debug("OTree::TestValue::Replay: decoding UPDATE_ID ...");
          id_t id;
          ceph::decode(id, delta);
          logger().debug("OTree::TestValue::Replay: apply id={} ...", id);
          Replayable::set_id(payload_mut, id);
          break;
        }
        case delta_op_t::UPDATE_TAIL_MAGIC: {
          logger().debug("OTree::TestValue::Replay: decoding UPDATE_TAIL_MAGIC ...");
          magic_t magic;
          ceph::decode(magic, delta);
          logger().debug("OTree::TestValue::Replay: apply magic={} ...", magic);
          Replayable::set_tail_magic(payload_mut, magic);
          break;
        }
        default:
          logger().error("OTree::TestValue::Replay: got unknown op {} when replay {:#x}+{:#x}",
                         op, value_addr, payload_mut.get_length());
          ceph_abort();
        }
      } catch (buffer::error& e) {
        logger().error("OTree::TestValue::Replay: got decode error {} when replay {:#x}+{:#x}",
                       e, value_addr, payload_mut.get_length());
        ceph_abort();
      }
    }

   private:
    seastar::logger& logger() {
      return crimson::get_logger(ceph_subsys_test);
    }
  };

  TestValue(NodeExtentManager& nm, const ValueBuilder& vb, Ref<tree_cursor_t>& p_cursor)
    : Value(nm, vb, p_cursor) {}
  ~TestValue() override = default;

  id_t get_id() const {
    return read_payload<payload_t>()->id;
  }
  void set_id_replayable(Transaction& t, id_t id) {
    auto value_mutable = prepare_mutate_payload<payload_t, Recorder>(t);
    if (value_mutable.second) {
      value_mutable.second->encode_set_id(value_mutable.first, id);
    }
    Replayable::set_id(value_mutable.first, id);
  }

  magic_t get_tail_magic() const {
    auto p_payload = read_payload<payload_t>();
    auto offset_magic = get_payload_size() - sizeof(magic_t);
    auto p_magic = reinterpret_cast<const char*>(p_payload) + offset_magic;
    return reinterpret_cast<const magic_packed_t*>(p_magic)->value;
  }
  void set_tail_magic_replayable(Transaction& t, magic_t magic) {
    auto value_mutable = prepare_mutate_payload<payload_t, Recorder>(t);
    if (value_mutable.second) {
      value_mutable.second->encode_set_tail_magic(value_mutable.first, magic);
    }
    Replayable::set_tail_magic(value_mutable.first, magic);
  }
};

struct test_item_t {
  using ValueType = TestValue;

  value_size_t size;
  TestValue::id_t id;
  TestValue::magic_t magic;

  value_size_t get_payload_size() const {
    assert(size > sizeof(value_header_t));
    return {static_cast<value_size_t>(size - sizeof(value_header_t))};
  }

  void initialize(Transaction& t, TestValue& value) const {
    ceph_assert(value.get_payload_size() + sizeof(value_header_t) == size);
    value.set_id_replayable(t, id);
    value.set_tail_magic_replayable(t, magic);
  }

  void validate(TestValue& value) const {
    ceph_assert(value.get_payload_size() + sizeof(value_header_t) == size);
    ceph_assert(value.get_id() == id);
    ceph_assert(value.get_tail_magic() == magic);
  }

  static test_item_t create(std::size_t _size, std::size_t _id) {
    ceph_assert(_size <= std::numeric_limits<value_size_t>::max());
    ceph_assert(_size > sizeof(value_header_t));
    value_size_t size = _size;

    ceph_assert(_id <= std::numeric_limits<TestValue::id_t>::max());
    TestValue::id_t id = _id;

    return {size, id, (TestValue::magic_t)id * 137};
  }
};
inline std::ostream& operator<<(std::ostream& os, const test_item_t& item) {
  return os << "TestItem(#" << item.id << ", " << item.size << "B)";
}

}
