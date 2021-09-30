// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <limits>
#include <numeric>
#include <iostream>

#include "include/byteorder.h"
#include "include/denc.h"
#include "include/buffer.h"
#include "include/cmp.h"
#include "include/uuid.h"
#include "include/interval_set.h"

namespace crimson::os::seastore {

using depth_t = uint32_t;
using depth_le_t = ceph_le32;

inline depth_le_t init_depth_le(uint32_t i) {
  return ceph_le32(i);
}

using checksum_t = uint32_t;

// Immutable metadata for seastore to set at mkfs time
struct seastore_meta_t {
  uuid_d seastore_id;

  DENC(seastore_meta_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.seastore_id, p);
    DENC_FINISH(p);
  }
};

// identifies a specific physical device within seastore
using device_id_t = uint8_t;

constexpr uint16_t SEGMENT_ID_LEN_BITS = 24;

// order of device_id_t
constexpr uint16_t DEVICE_ID_LEN_BITS = 8;

// 1 bit to identify address type

// segment ids without a device id encapsulated
using device_segment_id_t = uint32_t;

constexpr device_id_t DEVICE_ID_MAX = 
  (std::numeric_limits<device_id_t>::max() >>
   (std::numeric_limits<device_id_t>::digits - DEVICE_ID_LEN_BITS + 1));
constexpr device_id_t DEVICE_ID_RECORD_RELATIVE = DEVICE_ID_MAX - 1;
constexpr device_id_t DEVICE_ID_BLOCK_RELATIVE = DEVICE_ID_MAX - 2;
constexpr device_id_t DEVICE_ID_DELAYED = DEVICE_ID_MAX - 3;
constexpr device_id_t DEVICE_ID_NULL = DEVICE_ID_MAX - 4;
constexpr device_id_t DEVICE_ID_FAKE = DEVICE_ID_MAX - 5;
constexpr device_id_t DEVICE_ID_ZERO = DEVICE_ID_MAX - 6;
constexpr device_id_t DEVICE_ID_MAX_VALID = DEVICE_ID_MAX - 7;

constexpr device_segment_id_t DEVICE_SEGMENT_ID_MAX =
  (1 << SEGMENT_ID_LEN_BITS) - 1;

// Identifies segment location on disk, see SegmentManager,
struct segment_id_t {
private:
  // internal segment id type of segment_id_t, basically
  // this is a unsigned int with the top "DEVICE_ID_LEN_BITS"
  // bits representing the id of the device on which the
  // segment resides
  using internal_segment_id_t = uint32_t;

  // mask for segment manager id
  static constexpr internal_segment_id_t SM_ID_MASK =
    0xF << (std::numeric_limits<internal_segment_id_t>::digits - DEVICE_ID_LEN_BITS);
  // default internal segment id
  static constexpr internal_segment_id_t DEFAULT_INTERNAL_SEG_ID =
    (std::numeric_limits<internal_segment_id_t>::max() >> 1) - 1;

  internal_segment_id_t segment = DEFAULT_INTERNAL_SEG_ID;

  constexpr segment_id_t(uint32_t encoded) : segment(encoded) {}

public:
  segment_id_t() = default;
  constexpr segment_id_t(device_id_t id, device_segment_id_t segment)
    : segment(make_internal(segment, id)) {}

  [[gnu::always_inline]]
  device_id_t device_id() const {
    return internal_to_device(segment);
  }

  [[gnu::always_inline]]
  constexpr device_segment_id_t device_segment_id() const {
    return internal_to_segment(segment);
  }

  bool operator==(const segment_id_t& other) const {
    return segment == other.segment;
  }
  bool operator!=(const segment_id_t& other) const {
    return segment != other.segment;
  }
  bool operator<(const segment_id_t& other) const {
    return segment < other.segment;
  }
  bool operator<=(const segment_id_t& other) const {
    return segment <= other.segment;
  }
  bool operator>(const segment_id_t& other) const {
    return segment > other.segment;
  }
  bool operator>=(const segment_id_t& other) const {
    return segment >= other.segment;
  }

  DENC(segment_id_t, v, p) {
    denc(v.segment, p);
  }
private:
  static constexpr unsigned segment_bits = (
    std::numeric_limits<internal_segment_id_t>::digits - DEVICE_ID_LEN_BITS
  );

  static inline device_id_t internal_to_device(internal_segment_id_t id) {
    return (static_cast<device_id_t>(id) & SM_ID_MASK) >> segment_bits;
  }

  constexpr static inline device_segment_id_t internal_to_segment(
    internal_segment_id_t id) {
    return id & (~SM_ID_MASK);
  }

  constexpr static inline internal_segment_id_t make_internal(
    device_segment_id_t id,
    device_id_t sm_id) {
    return static_cast<internal_segment_id_t>(id) |
      (static_cast<internal_segment_id_t>(sm_id) << segment_bits);
  }

  friend struct segment_id_le_t;
  friend struct seg_paddr_t;
  friend struct paddr_t;
  friend struct paddr_le_t;
};

// ondisk type of segment_id_t
struct __attribute((packed)) segment_id_le_t {
  ceph_le32 segment = ceph_le32(segment_id_t::DEFAULT_INTERNAL_SEG_ID);

  segment_id_le_t(const segment_id_t id) :
    segment(ceph_le32(id.segment)) {}

  operator segment_id_t() const {
    return segment_id_t(segment);
  }
};

constexpr segment_id_t MAX_SEG_ID = segment_id_t(
  DEVICE_ID_MAX,
  DEVICE_SEGMENT_ID_MAX
);
// for tests which generate fake paddrs
constexpr segment_id_t NULL_SEG_ID = segment_id_t(DEVICE_ID_NULL, 0);
constexpr segment_id_t FAKE_SEG_ID = segment_id_t(DEVICE_ID_FAKE, 0);

std::ostream &operator<<(std::ostream &out, const segment_id_t&);


std::ostream &segment_to_stream(std::ostream &, const segment_id_t &t);

// Offset within a segment on disk, see SegmentManager
// may be negative for relative offsets
using segment_off_t = int32_t;
constexpr segment_off_t NULL_SEG_OFF =
  std::numeric_limits<segment_off_t>::max();
constexpr segment_off_t MAX_SEG_OFF =
  std::numeric_limits<segment_off_t>::max();

std::ostream &offset_to_stream(std::ostream &, const segment_off_t &t);

/* Monotonically increasing segment seq, uniquely identifies
 * the incarnation of a segment */
using segment_seq_t = uint32_t;
static constexpr segment_seq_t NULL_SEG_SEQ =
  std::numeric_limits<segment_seq_t>::max();
static constexpr segment_seq_t MAX_SEG_SEQ =
  std::numeric_limits<segment_seq_t>::max();

// Offset of delta within a record
using record_delta_idx_t = uint32_t;
constexpr record_delta_idx_t NULL_DELTA_IDX =
  std::numeric_limits<record_delta_idx_t>::max();

/**
 * segment_map_t
 *
 * Compact templated mapping from a segment_id_t to a value type.
 */
template <typename T>
class segment_map_t {
public:
  segment_map_t() {
    // initializes top vector with 0 length vectors to indicate that they
    // are not yet present
    device_to_segments.resize(DEVICE_ID_MAX_VALID);
  }
  void add_device(device_id_t device, size_t segments, const T& init) {
    assert(device <= DEVICE_ID_MAX_VALID);
    assert(device_to_segments[device].size() == 0);
    device_to_segments[device].resize(segments, init);
    total_segments += segments;
  }
  void clear() {
    device_to_segments.clear();
    device_to_segments.resize(DEVICE_ID_MAX_VALID);
    total_segments = 0;
  }

  T& operator[](segment_id_t id) {
    assert(id.device_segment_id() < device_to_segments[id.device_id()].size());
    return device_to_segments[id.device_id()][id.device_segment_id()];
  }
  const T& operator[](segment_id_t id) const {
    assert(id.device_segment_id() < device_to_segments[id.device_id()].size());
    return device_to_segments[id.device_id()][id.device_segment_id()];
  }

  auto begin() {
    return iterator<false>::lower_bound(*this, 0, 0);
  }
  auto begin() const {
    return iterator<true>::lower_bound(*this, 0, 0);
  }

  auto end() {
    return iterator<false>::end_iterator(*this);
  }
  auto end() const {
    return iterator<true>::end_iterator(*this);
  }

  auto device_begin(device_id_t id) {
    auto ret = iterator<false>::lower_bound(*this, id, 0);
    assert(ret->first.device_id() == id);
    return ret;
  }
  auto device_end(device_id_t id) {
    return iterator<false>::lower_bound(*this, id + 1, 0);
  }

  size_t size() const {
    return total_segments;
  }

private:
  template <bool is_const = false>
  class iterator {
    /// points at set being iterated over
    std::conditional_t<
      is_const,
      const segment_map_t &,
      segment_map_t &> parent;

    /// points at current device, or DEVICE_ID_MAX_VALID if is_end()
    device_id_t device_id;

    /// segment at which we are pointing, 0 if is_end()
    device_segment_id_t device_segment_id;

    /// holds referent for operator* and operator-> when !is_end()
    std::optional<
      std::pair<
        const segment_id_t,
	std::conditional_t<is_const, const T&, T&>
	>> current;

    bool is_end() const {
      return device_id == DEVICE_ID_MAX_VALID;
    }

    void find_valid() {
      assert(!is_end());
      auto &device_vec = parent.device_to_segments[device_id];
      if (device_vec.size() == 0 ||
	  device_segment_id == device_vec.size()) {
	while (++device_id < DEVICE_ID_MAX_VALID &&
	       parent.device_to_segments[device_id].size() == 0);
	device_segment_id = 0;
      }
      if (is_end()) {
	current = std::nullopt;
      } else {
	current.emplace(
	  segment_id_t{device_id, device_segment_id},
	  parent.device_to_segments[device_id][device_segment_id]
	);
      }
    }

    iterator(
      decltype(parent) &parent,
      device_id_t device_id,
      device_segment_id_t device_segment_id)
      : parent(parent), device_id(device_id),
	device_segment_id(device_segment_id) {}

  public:
    static iterator lower_bound(
      decltype(parent) &parent,
      device_id_t device_id,
      device_segment_id_t device_segment_id) {
      if (device_id == DEVICE_ID_MAX_VALID) {
	return end_iterator(parent);
      } else {
	auto ret = iterator{parent, device_id, device_segment_id};
	ret.find_valid();
	return ret;
      }
    }

    static iterator end_iterator(
      decltype(parent) &parent) {
      return iterator{parent, DEVICE_ID_MAX_VALID, 0};
    }

    iterator<is_const>& operator++() {
      assert(!is_end());
      ++device_segment_id;
      find_valid();
      return *this;
    }

    bool operator==(iterator<is_const> rit) {
      return (device_id == rit.device_id &&
	      device_segment_id == rit.device_segment_id);
    }

    bool operator!=(iterator<is_const> rit) {
      return !(*this == rit);
    }

    template <bool c = is_const, std::enable_if_t<c, int> = 0>
    const std::pair<const segment_id_t, const T&> *operator->() {
      assert(!is_end());
      return &*current;
    }
    template <bool c = is_const, std::enable_if_t<!c, int> = 0>
    std::pair<const segment_id_t, T&> *operator->() {
      assert(!is_end());
      return &*current;
    }
    template <bool c = is_const, std::enable_if_t<c, int> = 0>
    const std::pair<const segment_id_t, const T&> &operator*() {
      assert(!is_end());
      return *current;
    }
    template <bool c = is_const, std::enable_if_t<!c, int> = 0>
    std::pair<const segment_id_t, T&> &operator*() {
      assert(!is_end());
      return *current;
    }
  };

  /**
   * device_to_segments
   *
   * device -> segment -> T mapping.  device_to_segments[d].size() > 0 iff
   * device <d> has been added.
   */
  std::vector<std::vector<T>> device_to_segments;

  /// total number of added segments
  size_t total_segments = 0;
};

static constexpr uint16_t BLK_ID_LEN_BITS = 36;
using device_block_id_t = uint64_t;
constexpr device_block_id_t DEVICE_BLOCK_ID_MAX =
  (static_cast<device_block_id_t>(1) << BLK_ID_LEN_BITS) - 1;

struct block_id_t {
private:
  using internal_block_id_t = uint64_t;

  static constexpr internal_block_id_t BLK_ID_MASK =
    static_cast<internal_block_id_t>(0xFFFFFFF) << BLK_ID_LEN_BITS;
  static constexpr internal_block_id_t DEFAULT_INTERNAL_BLK_ID =
    (std::numeric_limits<internal_block_id_t>::max() >>
    (std::numeric_limits<internal_block_id_t>::digits - BLK_ID_LEN_BITS))
    - 1;

  internal_block_id_t block = DEFAULT_INTERNAL_BLK_ID;

  constexpr block_id_t(uint64_t encoded) : block(encoded) {}
public:
  block_id_t() = default;
  constexpr block_id_t(device_id_t id, device_block_id_t block)
    : block(make_internal(block, id)) {}

  [[gnu::always_inline]]
  device_id_t device_id() const {
    return internal_to_device(block);
  }

  [[gnu::always_inline]]
  constexpr device_block_id_t device_block_id() const {
    return internal_to_block(block);
  }

  bool operator==(const block_id_t& other) const {
    return block == other.block;
  }
  bool operator!=(const block_id_t& other) const {
    return block != other.block;
  }
  bool operator<(const block_id_t& other) const {
    return block < other.block;
  }
  bool operator<=(const block_id_t& other) const {
    return block <= other.block;
  }
  bool operator>(const block_id_t& other) const {
    return block > other.block;
  }
  bool operator>=(const block_id_t& other) const {
    return block >= other.block;
  }

private:
  static constexpr unsigned block_id_bits = (
    BLK_ID_LEN_BITS
  );

  static inline device_id_t internal_to_device(internal_block_id_t id) {
    return (static_cast<device_id_t>(id) & BLK_ID_MASK) >> block_id_bits;
  }

  constexpr static inline device_block_id_t internal_to_block(
    internal_block_id_t id) {
    return id & (~BLK_ID_MASK);
  }

  constexpr static inline internal_block_id_t make_internal(
    device_block_id_t id,
    device_id_t d_id) {
    return static_cast<internal_block_id_t>(id) |
      (static_cast<internal_block_id_t>(d_id) << block_id_bits) |
      (static_cast<internal_block_id_t>(0x1) <<
      (BLK_ID_LEN_BITS + DEVICE_ID_LEN_BITS - 1));
  }

  friend struct blk_paddr_t;
  friend struct paddr_t;
  friend struct paddr_le_t;
};

constexpr block_id_t NULL_BLK_ID = block_id_t(DEVICE_ID_NULL, 0);
constexpr block_id_t FAKE_BLK_ID = block_id_t(DEVICE_ID_FAKE, 0);

using device_block_off_t = int32_t;
static constexpr uint16_t BLK_OFF_LEN_BITS = 20;
constexpr device_block_off_t BLK_OFF_MAX = 
  std::numeric_limits<device_block_off_t>::max() >>
  (std::numeric_limits<device_block_off_t>::digits - BLK_OFF_LEN_BITS);
constexpr device_block_off_t BLK_OFF_MIN =
  std::numeric_limits<device_block_off_t>::min() >>
  (std::numeric_limits<device_block_off_t>::digits - BLK_OFF_LEN_BITS);

struct block_off_t {
  using internal_block_off_t = int32_t;
  internal_block_off_t off = 0;
  constexpr void check_valid(const internal_block_off_t offset) const {
    assert(offset <= BLK_OFF_MAX);
    assert(offset >= BLK_OFF_MIN);   
  }
  [[gnu::always_inline]]
  constexpr device_block_off_t device_block_off() const {
    return off;
  }
  constexpr block_off_t(device_block_off_t offset) : off(offset) {
    check_valid(offset);
  }
  constexpr uint32_t get_raw_bits() const {
    uint32_t ret = off & 0x8FFFF;
    ret |= (off < 0 ? 1 << BLK_OFF_LEN_BITS : 0 << BLK_OFF_LEN_BITS);
    return ret;
  }
  bool operator==(const block_off_t& other) const {
    check_valid(other.off);
    return off == other.off;
  }
  bool operator!=(const block_off_t& other) const {
    check_valid(other.off);
    return off != other.off;
  }
  bool operator<(const block_off_t& other) const {
    check_valid(other.off);
    return off < other.off;
  }
  bool operator<=(const block_off_t& other) const {
    check_valid(other.off);
    return off <= other.off;
  }
  bool operator>(const block_off_t& other) const {
    check_valid(other.off);
    return off > other.off;
  }
  bool operator>=(const block_off_t& other) const {
    check_valid(other.off);
    return off >= other.off;
  }

  block_off_t operator-(block_off_t rhs) const {
    check_valid(rhs.off);
    block_off_t offset = block_off_t(off - rhs.off);
    check_valid(offset.off);
    return offset;
  }
  block_off_t operator+(block_off_t rhs) const {
    check_valid(rhs.off);
    block_off_t offset = block_off_t(off + rhs.off);
    check_valid(offset.off);
    return offset;
  }
  friend struct blk_paddr_t;
};

constexpr block_off_t NULL_BLK_OFF = block_off_t{BLK_OFF_MAX};
constexpr block_off_t MAX_BLK_OFF = block_off_t{BLK_OFF_MAX};

/**
 * paddr_t
 *
 * <segment, offset> offset on disk, see SegmentManager
 *
 * May be absolute, record_relative, or block_relative.
 *
 * Blocks get read independently of the surrounding record,
 * so paddrs embedded directly within a block need to refer
 * to other blocks within the same record by a block_relative
 * addr relative to the block's own offset.  By contrast,
 * deltas to existing blocks need to use record_relative
 * addrs relative to the first block of the record.
 *
 * Fresh extents during a transaction are refered to by
 * record_relative paddrs.
 */
constexpr uint16_t DEV_ADDR_LEN_BITS = 64 - DEVICE_ID_LEN_BITS;
static constexpr uint16_t SEG_OFF_LEN_BITS = 32;
enum class addr_types_t : uint8_t {
  SEGMENT = 0,
  RANDOM_BLOCK = 1
};
struct seg_paddr_t;
struct blk_paddr_t;
struct paddr_t {
protected:
  using common_addr_t = uint64_t;
  common_addr_t dev_addr;
private:
  constexpr paddr_t(segment_id_t seg, segment_off_t offset)
    : dev_addr((static_cast<common_addr_t>(seg.segment)
	<< SEG_OFF_LEN_BITS) | static_cast<uint32_t>(offset)) {}
  constexpr paddr_t(common_addr_t val) : dev_addr(val) {}
  constexpr paddr_t(block_id_t blk, block_off_t offset)
    : dev_addr((static_cast<common_addr_t>(blk.block)
	<< BLK_OFF_LEN_BITS) | static_cast<uint32_t>(offset.get_raw_bits())) {}
public:
  static constexpr paddr_t make_seg_paddr(
    segment_id_t seg, segment_off_t offset) {
    return paddr_t(seg, offset);
  }
  static constexpr paddr_t make_seg_paddr(
    device_id_t device,
    device_segment_id_t seg,
    segment_off_t offset) {
    return paddr_t(segment_id_t(device, seg), offset);
  }
  constexpr paddr_t() : paddr_t(NULL_SEG_ID, 0) {}
  static constexpr paddr_t make_blk_paddr(
    device_id_t device,
    device_block_id_t blk,
    block_off_t offset) {
    return paddr_t(block_id_t(device, blk), offset);
  }
  static constexpr paddr_t make_blk_paddr(
    block_id_t blk, block_off_t offset) {
    return paddr_t(blk, offset);
  }

  // use 1bit in device_id_t for address type
  void set_device_id(device_id_t id, addr_types_t type = addr_types_t::SEGMENT) {
    dev_addr &= static_cast<common_addr_t>(
      std::numeric_limits<device_segment_id_t>::max());
    dev_addr |= static_cast<common_addr_t>(id & 0x8) << DEV_ADDR_LEN_BITS;
    dev_addr |= static_cast<common_addr_t>(type)
      << (std::numeric_limits<common_addr_t>::digits - 1);
  }

  device_id_t get_device_id() const {
    return static_cast<device_id_t>(dev_addr >> DEV_ADDR_LEN_BITS);
  }
  addr_types_t get_addr_type() const {
    return (addr_types_t)((dev_addr
	    >> (std::numeric_limits<common_addr_t>::digits - 1)) & 1);
  }

  paddr_t add_offset(int32_t o) const;
  paddr_t add_relative(paddr_t o) const;
  paddr_t add_block_relative(paddr_t o) const;
  paddr_t add_record_relative(paddr_t o) const;
  paddr_t maybe_relative_to(paddr_t base) const;

  seg_paddr_t& as_seg_paddr();
  const seg_paddr_t& as_seg_paddr() const;
  blk_paddr_t& as_blk_paddr();
  const blk_paddr_t& as_blk_paddr() const;

  paddr_t operator-(paddr_t rhs) const;

  bool is_block_relative() const {
    return get_device_id() == DEVICE_ID_BLOCK_RELATIVE;
  }
  bool is_record_relative() const {
    return get_device_id() == DEVICE_ID_RECORD_RELATIVE;
  }
  bool is_relative() const {
    return is_block_relative() || is_record_relative();
  }
  /// Denotes special null addr
  bool is_null() const {
    return get_device_id() == DEVICE_ID_NULL;
  }
  /// Denotes special zero addr
  bool is_zero() const {
    return get_device_id() == DEVICE_ID_ZERO;
  }

  /**
   * is_real
   *
   * indicates whether addr reflects a physical location, absolute
   * or relative.  FAKE segments also count as real so as to reflect
   * the way in which unit tests use them.
   */
  bool is_real() const {
    return !is_zero() && !is_null();
  }

  DENC(paddr_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.dev_addr, p);
    DENC_FINISH(p);
  }
  friend struct paddr_le_t;
  friend struct seg_paddr_t;

  friend bool operator==(const paddr_t &, const paddr_t&);
  friend bool operator!=(const paddr_t &, const paddr_t&);
  friend bool operator<=(const paddr_t &, const paddr_t&);
  friend bool operator<(const paddr_t &, const paddr_t&);
  friend bool operator>=(const paddr_t &, const paddr_t&);
  friend bool operator>(const paddr_t &, const paddr_t&);
};
WRITE_EQ_OPERATORS_1(paddr_t, dev_addr);
WRITE_CMP_OPERATORS_1(paddr_t, dev_addr);

struct seg_paddr_t : public paddr_t {
  static constexpr uint64_t SEG_OFF_MASK = std::numeric_limits<uint32_t>::max();
  // mask for segment manager id
  static constexpr uint64_t SEG_ID_MASK =
    static_cast<common_addr_t>(0xFFFFFFFF) << SEG_OFF_LEN_BITS;

  seg_paddr_t(const seg_paddr_t&) = delete;
  seg_paddr_t(seg_paddr_t&) = delete;
  seg_paddr_t& operator=(const seg_paddr_t&) = delete;
  seg_paddr_t& operator=(seg_paddr_t&) = delete;
  segment_id_t get_segment_id() const {
    return segment_id_t((dev_addr & SEG_ID_MASK) >> SEG_OFF_LEN_BITS);
  }
  segment_off_t get_segment_off() const {
    return segment_off_t(dev_addr & SEG_OFF_MASK);
  }
  void set_segment_id(const segment_id_t id) {
    dev_addr &= static_cast<common_addr_t>(
      std::numeric_limits<device_segment_id_t>::max());
    dev_addr |= static_cast<common_addr_t>(id.segment) << SEG_OFF_LEN_BITS;
  }
  void set_segment_off(const segment_off_t off) {
    dev_addr &= static_cast<common_addr_t>(
      std::numeric_limits<device_segment_id_t>::max()) << SEG_OFF_LEN_BITS;
    dev_addr |= (uint32_t)off;
  }

  paddr_t add_offset(segment_off_t o) const {
    return paddr_t::make_seg_paddr(get_segment_id(), get_segment_off() + o);
  }

  paddr_t add_relative(paddr_t o) const {
    assert(o.is_relative());
    seg_paddr_t& s = o.as_seg_paddr();
    return paddr_t::make_seg_paddr(get_segment_id(),
	    get_segment_off() + s.get_segment_off());
  }

  paddr_t add_block_relative(paddr_t o) const {
    // special version mainly for documentation purposes
    assert(o.is_block_relative());
    return add_relative(o);
  }

  paddr_t add_record_relative(paddr_t o) const {
    // special version mainly for documentation purposes
    assert(o.is_record_relative());
    return add_relative(o);
  }

  /**
   * paddr_t::operator-
   *
   * Only defined for record_relative paddr_ts.  Yields a
   * block_relative address.
   */
  paddr_t operator-(paddr_t rhs) const {
    seg_paddr_t& r = rhs.as_seg_paddr();
    assert(rhs.is_relative() && is_relative());
    assert(r.get_segment_id() == get_segment_id());
    return paddr_t::make_seg_paddr(
      segment_id_t{DEVICE_ID_BLOCK_RELATIVE, 0},
      get_segment_off() - r.get_segment_off()
      );
  }

  /**
   * maybe_relative_to
   *
   * Helper for the case where an in-memory paddr_t may be
   * either block_relative or absolute (not record_relative).
   *
   * base must be either absolute or record_relative.
   */
  paddr_t maybe_relative_to(paddr_t base) const {
    assert(!base.is_block_relative());
    seg_paddr_t& s = base.as_seg_paddr();
    if (is_block_relative())
      return s.add_block_relative(*this);
    else
      return *this;
  }
};

struct blk_paddr_t : public paddr_t {
  static constexpr uint64_t BLK_OFF_MASK = std::numeric_limits<uint32_t>::max() >> 12;
  // mask for random block manager id
  static constexpr uint64_t BLK_ID_MASK =
    static_cast<common_addr_t>(0xFFFFFFFFFFF) << BLK_OFF_LEN_BITS;

  blk_paddr_t(const blk_paddr_t&) = delete;
  blk_paddr_t(blk_paddr_t&) = delete;
  blk_paddr_t& operator=(const blk_paddr_t&) = delete;
  blk_paddr_t& operator=(blk_paddr_t&) = delete;
  block_id_t get_block_id() const {
    return block_id_t((dev_addr & BLK_ID_MASK) >> BLK_OFF_LEN_BITS);
  }
  block_off_t get_block_off() const {
    return block_off_t(dev_addr & BLK_OFF_MASK);
  }
  void set_block_id(const block_id_t id) {
    dev_addr &= static_cast<common_addr_t>(
      std::numeric_limits<device_block_id_t>::max());
    dev_addr |= static_cast<common_addr_t>(id.block) << BLK_OFF_LEN_BITS;
  }
  void set_block_off(const block_off_t off) {
    dev_addr &= static_cast<common_addr_t>(
      std::numeric_limits<device_block_id_t>::max()) << BLK_OFF_LEN_BITS;
    dev_addr |= ((uint32_t)off.get_raw_bits() >> 12);
  }

  paddr_t add_offset(block_off_t o) const {
    return paddr_t::make_blk_paddr(get_block_id(), get_block_off() + o);
  }

  paddr_t add_relative(paddr_t o) const {
    assert(o.is_relative());
    blk_paddr_t& s = o.as_blk_paddr();
    return paddr_t::make_blk_paddr(get_block_id(),
	    get_block_off() + s.get_block_off());
  }

  paddr_t add_block_relative(paddr_t o) const {
    // special version mainly for documentation purposes
    assert(o.is_block_relative());
    return add_relative(o);
  }

  paddr_t add_record_relative(paddr_t o) const {
    // special version mainly for documentation purposes
    assert(o.is_record_relative());
    return add_relative(o);
  }

  /**
   * paddr_t::operator-
   *
   * Only defined for record_relative paddr_ts.  Yields a
   * block_relative address.
   */
  paddr_t operator-(paddr_t rhs) const {
    blk_paddr_t& r = rhs.as_blk_paddr();
    assert(rhs.is_relative() && is_relative());
    assert(r.get_block_id() == get_block_id());
    return paddr_t::make_blk_paddr(
      block_id_t{DEVICE_ID_BLOCK_RELATIVE, 0},
      get_block_off() - r.get_block_off()
      );
  }

  /**
   * maybe_relative_to
   *
   * Helper for the case where an in-memory paddr_t may be
   * either block_relative or absolute (not record_relative).
   *
   * base must be either absolute or record_relative.
   */
  paddr_t maybe_relative_to(paddr_t base) const {
    assert(!base.is_block_relative());
    blk_paddr_t& s = base.as_blk_paddr();
    if (is_block_relative())
      return s.add_block_relative(*this);
    else
      return *this;
  }
};

constexpr paddr_t P_ADDR_NULL = paddr_t{};
constexpr paddr_t P_ADDR_MIN = paddr_t::make_seg_paddr(segment_id_t(0, 0), 0);
constexpr paddr_t P_ADDR_MAX = paddr_t::make_seg_paddr(
  segment_id_t(DEVICE_ID_MAX, DEVICE_SEGMENT_ID_MAX),
  std::numeric_limits<segment_off_t>::max());
constexpr paddr_t P_ADDR_ZERO = paddr_t::make_seg_paddr(
  DEVICE_ID_ZERO, 0, 0);

constexpr paddr_t make_record_relative_paddr(segment_off_t off) {
  return paddr_t::make_seg_paddr(
    segment_id_t{DEVICE_ID_RECORD_RELATIVE, 0},
    off);
}
constexpr paddr_t make_block_relative_paddr(segment_off_t off) {
  return paddr_t::make_seg_paddr(
    segment_id_t{DEVICE_ID_BLOCK_RELATIVE, 0},
    off);
}
constexpr paddr_t make_fake_paddr(segment_off_t off) {
  return paddr_t::make_seg_paddr(FAKE_SEG_ID, off);
}
constexpr paddr_t delayed_temp_paddr(segment_off_t off) {
  return paddr_t::make_seg_paddr(
    segment_id_t{DEVICE_ID_DELAYED, 0},
    off);
}

constexpr paddr_t make_record_relative_paddr(block_off_t off) {
  return paddr_t::make_blk_paddr(
    block_id_t{DEVICE_ID_RECORD_RELATIVE, 0},
    off);
}
constexpr paddr_t make_block_relative_paddr(block_off_t off) {
  return paddr_t::make_blk_paddr(
    block_id_t{DEVICE_ID_BLOCK_RELATIVE, 0},
    off);
}
constexpr paddr_t delayed_temp_paddr(block_off_t off) {
  return paddr_t::make_blk_paddr(
    block_id_t{DEVICE_ID_DELAYED, 0},
    off);
}

struct __attribute((packed)) paddr_le_t {
  ceph_le64 dev_addr =
    ceph_le64(P_ADDR_NULL.dev_addr);

  paddr_le_t() = default;
  paddr_le_t(const paddr_t &addr) : dev_addr(ceph_le64(addr.dev_addr)) {}

  operator paddr_t() const {
    return paddr_t{dev_addr};
  }
};

std::ostream &operator<<(std::ostream &out, const paddr_t &rhs);

using objaddr_t = uint32_t;
constexpr objaddr_t OBJ_ADDR_MAX = std::numeric_limits<objaddr_t>::max();
constexpr objaddr_t OBJ_ADDR_NULL = OBJ_ADDR_MAX - 1;

enum class placement_hint_t {
  HOT = 0,   // Most of the metadata
  COLD,      // Object data
  REWRITE,   // Cold metadata and data (probably need further splits)
  NUM_HINTS  // Constant for number of hints
};

enum device_type_t {
  NONE = 0,
  SEGMENTED, // i.e. Hard_Disk, SATA_SSD, NAND_NVME
  RANDOM_BLOCK, // i.e. RANDOM_BD
  PMEM, // i.e. NVDIMM, PMEM
  NUM_TYPES
};

bool can_delay_allocation(device_type_t type);
device_type_t string_to_device_type(std::string type);
std::string device_type_to_string(device_type_t type);

/* Monotonically increasing identifier for the location of a
 * journal_record.
 */
struct journal_seq_t {
  segment_seq_t segment_seq = 0;
  paddr_t offset;

  journal_seq_t add_offset(segment_off_t o) const {
    return {segment_seq, offset.add_offset(o)};
  }

  DENC(journal_seq_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.segment_seq, p);
    denc(v.offset, p);
    DENC_FINISH(p);
  }
};
WRITE_CMP_OPERATORS_2(journal_seq_t, segment_seq, offset)
WRITE_EQ_OPERATORS_2(journal_seq_t, segment_seq, offset)
constexpr journal_seq_t JOURNAL_SEQ_MIN{
  0,
  paddr_t::make_seg_paddr(NULL_SEG_ID, 0)
};
constexpr journal_seq_t JOURNAL_SEQ_MAX{
  MAX_SEG_SEQ,
  P_ADDR_MAX
};

std::ostream &operator<<(std::ostream &out, const journal_seq_t &seq);

static constexpr journal_seq_t NO_DELTAS = journal_seq_t{
  NULL_SEG_SEQ,
  P_ADDR_NULL
};

// logical addr, see LBAManager, TransactionManager
using laddr_t = uint64_t;
constexpr laddr_t L_ADDR_MIN = std::numeric_limits<laddr_t>::min();
constexpr laddr_t L_ADDR_MAX = std::numeric_limits<laddr_t>::max();
constexpr laddr_t L_ADDR_NULL = std::numeric_limits<laddr_t>::max();
constexpr laddr_t L_ADDR_ROOT = std::numeric_limits<laddr_t>::max() - 1;
constexpr laddr_t L_ADDR_LBAT = std::numeric_limits<laddr_t>::max() - 2;

struct __attribute((packed)) laddr_le_t {
  ceph_le64 laddr = ceph_le64(L_ADDR_NULL);

  laddr_le_t() = default;
  laddr_le_t(const laddr_le_t &) = default;
  explicit laddr_le_t(const laddr_t &addr)
    : laddr(ceph_le64(addr)) {}

  operator laddr_t() const {
    return laddr_t(laddr);
  }
  laddr_le_t& operator=(laddr_t addr) {
    ceph_le64 val;
    val = addr;
    laddr = val;
    return *this;
  }
};

// logical offset, see LBAManager, TransactionManager
using extent_len_t = uint32_t;
constexpr extent_len_t EXTENT_LEN_MAX =
  std::numeric_limits<extent_len_t>::max();

using extent_len_le_t = ceph_le32;
inline extent_len_le_t init_extent_len_le(extent_len_t len) {
  return ceph_le32(len);
}

struct laddr_list_t : std::list<std::pair<laddr_t, extent_len_t>> {
  template <typename... T>
  laddr_list_t(T&&... args)
    : std::list<std::pair<laddr_t, extent_len_t>>(std::forward<T>(args)...) {}
};
struct paddr_list_t : std::list<std::pair<paddr_t, extent_len_t>> {
  template <typename... T>
  paddr_list_t(T&&... args)
    : std::list<std::pair<paddr_t, extent_len_t>>(std::forward<T>(args)...) {}
};

std::ostream &operator<<(std::ostream &out, const laddr_list_t &rhs);
std::ostream &operator<<(std::ostream &out, const paddr_list_t &rhs);

/* identifies type of extent, used for interpretting deltas, managing
 * writeback.
 *
 * Note that any new extent type needs to be added to
 * Cache::get_extent_by_type in cache.cc
 */
enum class extent_types_t : uint8_t {
  ROOT = 0,
  LADDR_INTERNAL = 1,
  LADDR_LEAF = 2,
  OMAP_INNER = 3,
  OMAP_LEAF = 4,
  ONODE_BLOCK_STAGED = 5,
  COLL_BLOCK = 6,
  OBJECT_DATA_BLOCK = 7,
  RETIRED_PLACEHOLDER = 8,
  RBM_ALLOC_INFO = 9,
  // Test Block Types
  TEST_BLOCK = 10,
  TEST_BLOCK_PHYSICAL = 11,
  // None and the number of valid extent_types_t
  NONE = 12,
};
constexpr auto EXTENT_TYPES_MAX = static_cast<uint8_t>(extent_types_t::NONE);

constexpr bool is_logical_type(extent_types_t type) {
  switch (type) {
  case extent_types_t::ROOT:
  case extent_types_t::LADDR_INTERNAL:
  case extent_types_t::LADDR_LEAF:
    return false;
  default:
    return true;
  }
}

std::ostream &operator<<(std::ostream &out, extent_types_t t);

/* description of a new physical extent */
struct extent_t {
  extent_types_t type;  ///< type of extent
  laddr_t addr;         ///< laddr of extent (L_ADDR_NULL for non-logical)
  ceph::bufferlist bl;  ///< payload, bl.length() == length, aligned
  paddr_t reserve_ool_paddr = P_ADDR_NULL;
};

using extent_version_t = uint32_t;
constexpr extent_version_t EXTENT_VERSION_NULL = 0;

/* description of a mutation to a physical extent */
struct delta_info_t {
  extent_types_t type = extent_types_t::NONE;  ///< delta type
  paddr_t paddr;                               ///< physical address
  laddr_t laddr = L_ADDR_NULL;                 ///< logical address
  uint32_t prev_crc = 0;
  uint32_t final_crc = 0;
  segment_off_t length = NULL_SEG_OFF;         ///< extent length
  extent_version_t pversion;                   ///< prior version
  ceph::bufferlist bl;                         ///< payload

  DENC(delta_info_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.type, p);
    denc(v.paddr, p);
    denc(v.laddr, p);
    denc(v.prev_crc, p);
    denc(v.final_crc, p);
    denc(v.length, p);
    denc(v.pversion, p);
    denc(v.bl, p);
    DENC_FINISH(p);
  }

  bool operator==(const delta_info_t &rhs) const {
    return (
      type == rhs.type &&
      paddr == rhs.paddr &&
      laddr == rhs.laddr &&
      prev_crc == rhs.prev_crc &&
      final_crc == rhs.final_crc &&
      length == rhs.length &&
      pversion == rhs.pversion &&
      bl == rhs.bl
    );
  }

  friend std::ostream &operator<<(std::ostream &lhs, const delta_info_t &rhs);
};

std::ostream &operator<<(std::ostream &lhs, const delta_info_t &rhs);

struct record_t {
  std::vector<extent_t> extents;
  std::vector<delta_info_t> deltas;

  std::size_t get_raw_data_size() const {
    auto extent_size = std::accumulate(
        extents.begin(), extents.end(), 0,
        [](uint64_t sum, auto& extent) {
          return sum + extent.bl.length();
        }
    );
    auto delta_size = std::accumulate(
        deltas.begin(), deltas.end(), 0,
        [](uint64_t sum, auto& delta) {
          return sum + delta.bl.length();
        }
    );
    return extent_size + delta_size;
  }
};

class object_data_t {
  laddr_t reserved_data_base = L_ADDR_NULL;
  extent_len_t reserved_data_len = 0;

  bool dirty = false;
public:
  object_data_t(
    laddr_t reserved_data_base,
    extent_len_t reserved_data_len)
    : reserved_data_base(reserved_data_base),
      reserved_data_len(reserved_data_len) {}

  laddr_t get_reserved_data_base() const {
    return reserved_data_base;
  }

  extent_len_t get_reserved_data_len() const {
    return reserved_data_len;
  }

  bool is_null() const {
    return reserved_data_base == L_ADDR_NULL;
  }

  bool must_update() const {
    return dirty;
  }

  void update_reserved(
    laddr_t base,
    extent_len_t len) {
    dirty = true;
    reserved_data_base = base;
    reserved_data_len = len;
  }

  void update_len(
    extent_len_t len) {
    dirty = true;
    reserved_data_len = len;
  }

  void clear() {
    dirty = true;
    reserved_data_base = L_ADDR_NULL;
    reserved_data_len = 0;
  }
};

struct __attribute__((packed)) object_data_le_t {
  laddr_le_t reserved_data_base = laddr_le_t(L_ADDR_NULL);
  extent_len_le_t reserved_data_len = init_extent_len_le(0);

  void update(const object_data_t &nroot) {
    reserved_data_base = nroot.get_reserved_data_base();
    reserved_data_len = init_extent_len_le(nroot.get_reserved_data_len());
  }

  object_data_t get() const {
    return object_data_t(
      reserved_data_base,
      reserved_data_len);
  }
};

struct omap_root_t {
  laddr_t addr = L_ADDR_NULL;
  depth_t depth = 0;
  laddr_t hint = L_ADDR_MIN;
  bool mutated = false;

  omap_root_t() = default;
  omap_root_t(laddr_t addr, depth_t depth, laddr_t addr_min)
    : addr(addr),
      depth(depth),
      hint(addr_min) {}

  omap_root_t(const omap_root_t &o) = default;
  omap_root_t(omap_root_t &&o) = default;
  omap_root_t &operator=(const omap_root_t &o) = default;
  omap_root_t &operator=(omap_root_t &&o) = default;

  bool is_null() const {
    return addr == L_ADDR_NULL;
  }

  bool must_update() const {
    return mutated;
  }
  
  void update(laddr_t _addr, depth_t _depth, laddr_t _hint) {
    mutated = true;
    addr = _addr;
    depth = _depth;
    hint = _hint;
  }
  
  laddr_t get_location() const {
    return addr;
  }

  depth_t get_depth() const {
    return depth;
  }

  laddr_t get_hint() const {
    return hint;
  }
};

class __attribute__((packed)) omap_root_le_t {
  laddr_le_t addr = laddr_le_t(L_ADDR_NULL);
  depth_le_t depth = init_depth_le(0);

public: 
  omap_root_le_t() = default;
  
  omap_root_le_t(laddr_t addr, depth_t depth)
    : addr(addr), depth(init_depth_le(depth)) {}

  omap_root_le_t(const omap_root_le_t &o) = default;
  omap_root_le_t(omap_root_le_t &&o) = default;
  omap_root_le_t &operator=(const omap_root_le_t &o) = default;
  omap_root_le_t &operator=(omap_root_le_t &&o) = default;
  
  void update(const omap_root_t &nroot) {
    addr = nroot.get_location();
    depth = init_depth_le(nroot.get_depth());
  }
  
  omap_root_t get(laddr_t hint) const {
    return omap_root_t(addr, depth, hint);
  }
};

/**
 * lba_root_t 
 */
class __attribute__((packed)) lba_root_t {
  paddr_le_t root_addr;
  depth_le_t depth = init_extent_len_le(0);
  
public:
  lba_root_t() = default;
  
  lba_root_t(paddr_t addr, depth_t depth)
    : root_addr(addr), depth(init_depth_le(depth)) {}

  lba_root_t(const lba_root_t &o) = default;
  lba_root_t(lba_root_t &&o) = default;
  lba_root_t &operator=(const lba_root_t &o) = default;
  lba_root_t &operator=(lba_root_t &&o) = default;
  
  paddr_t get_location() const {
    return root_addr;
  }

  void set_location(paddr_t location) {
    root_addr = location;
  }

  depth_t get_depth() const {
    return depth;
  }

  void set_depth(depth_t ndepth) {
    depth = ndepth;
  }

  void adjust_addrs_from_base(paddr_t base) {
    paddr_t _root_addr = root_addr;
    if (_root_addr.is_relative()) {
      root_addr = base.add_record_relative(_root_addr);
    }
  }
};

class coll_root_t {
  laddr_t addr = L_ADDR_NULL;
  extent_len_t size = 0;

  bool mutated = false;

public:
  coll_root_t() = default;
  coll_root_t(laddr_t addr, extent_len_t size) : addr(addr), size(size) {}

  coll_root_t(const coll_root_t &o) = default;
  coll_root_t(coll_root_t &&o) = default;
  coll_root_t &operator=(const coll_root_t &o) = default;
  coll_root_t &operator=(coll_root_t &&o) = default;
  
  bool must_update() const {
    return mutated;
  }
  
  void update(laddr_t _addr, extent_len_t _s) {
    mutated = true;
    addr = _addr;
    size = _s;
  }
  
  laddr_t get_location() const {
    return addr;
  }

  extent_len_t get_size() const {
    return size;
  }
};

/**
 * coll_root_le_t
 *
 * Information for locating CollectionManager information, to be embedded
 * in root block.
 */
class __attribute__((packed)) coll_root_le_t {
  laddr_le_t addr;
  extent_len_le_t size = init_extent_len_le(0);
  
public:
  coll_root_le_t() = default;
  
  coll_root_le_t(laddr_t laddr, segment_off_t size)
    : addr(laddr), size(init_extent_len_le(size)) {}


  coll_root_le_t(const coll_root_le_t &o) = default;
  coll_root_le_t(coll_root_le_t &&o) = default;
  coll_root_le_t &operator=(const coll_root_le_t &o) = default;
  coll_root_le_t &operator=(coll_root_le_t &&o) = default;
  
  void update(const coll_root_t &nroot) {
    addr = nroot.get_location();
    size = init_extent_len_le(nroot.get_size());
  }
  
  coll_root_t get() const {
    return coll_root_t(addr, size);
  }
};


/**
 * root_t
 *
 * Contains information required to find metadata roots.
 * TODO: generalize this to permit more than one lba_manager implementation
 */
struct __attribute__((packed)) root_t {
  using meta_t = std::map<std::string, std::string>;

  static constexpr int MAX_META_LENGTH = 1024;

  lba_root_t lba_root;
  laddr_le_t onode_root;
  coll_root_le_t collection_root;

  char meta[MAX_META_LENGTH];

  root_t() {
    set_meta(meta_t{});
  }

  void adjust_addrs_from_base(paddr_t base) {
    lba_root.adjust_addrs_from_base(base);
  }

  meta_t get_meta() {
    bufferlist bl;
    bl.append(ceph::buffer::create_static(MAX_META_LENGTH, meta));
    meta_t ret;
    auto iter = bl.cbegin();
    decode(ret, iter);
    return ret;
  }

  void set_meta(const meta_t &m) {
    ceph::bufferlist bl;
    encode(m, bl);
    ceph_assert(bl.length() < MAX_META_LENGTH);
    bl.rebuild();
    auto &bptr = bl.front();
    ::memset(meta, 0, MAX_META_LENGTH);
    ::memcpy(meta, bptr.c_str(), bl.length());
  }
};

// use absolute address
struct rbm_alloc_delta_t {
  enum class op_types_t : uint8_t {
    NONE = 0,
    SET = 1,
    CLEAR = 2
  };
  std::vector<std::pair<paddr_t, size_t>> alloc_blk_ranges;
  op_types_t op = op_types_t::NONE;

  rbm_alloc_delta_t() = default;

  DENC(rbm_alloc_delta_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.alloc_blk_ranges, p);
    denc(v.op, p);
    DENC_FINISH(p);
  }
};

struct extent_info_t {
  extent_types_t type = extent_types_t::NONE;
  laddr_t addr = L_ADDR_NULL;
  extent_len_t len = 0;
  paddr_t reserve_ool_paddr = P_ADDR_NULL;

  extent_info_t() = default;
  extent_info_t(const extent_t &et)
    : type(et.type), addr(et.addr), len(et.bl.length()),
      reserve_ool_paddr(et.reserve_ool_paddr) {}

  DENC(extent_info_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.type, p);
    denc(v.addr, p);
    denc(v.len, p);
    denc(v.reserve_ool_paddr, p);
    DENC_FINISH(p);
  }
};

using segment_nonce_t = uint32_t;

/**
 * Segment header
 *
 * Every segment contains and encode segment_header_t in the first block.
 * Our strategy for finding the journal replay point is:
 * 1) Find the segment with the highest journal_segment_seq
 * 2) Replay starting at record located at that segment's journal_tail
 */
struct segment_header_t {
  segment_seq_t journal_segment_seq;
  segment_id_t physical_segment_id; // debugging

  journal_seq_t journal_tail;
  segment_nonce_t segment_nonce;
  bool out_of_line;

  DENC(segment_header_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.journal_segment_seq, p);
    denc(v.physical_segment_id, p);
    denc(v.journal_tail, p);
    denc(v.segment_nonce, p);
    denc(v.out_of_line, p);
    DENC_FINISH(p);
  }
};
std::ostream &operator<<(std::ostream &out, const segment_header_t &header);

struct record_header_t {
  // Fixed portion
  extent_len_t  mdlength;       // block aligned, length of metadata
  extent_len_t  dlength;        // block aligned, length of data
  uint32_t deltas;              // number of deltas
  uint32_t extents;             // number of extents
  segment_nonce_t segment_nonce;// nonce of containing segment
  journal_seq_t committed_to;   // records prior to committed_to have been
                                // fully written, maybe in another segment.
  checksum_t data_crc;          // crc of data payload


  DENC(record_header_t, v, p) {
    DENC_START(1, 1, p);
    denc(v.mdlength, p);
    denc(v.dlength, p);
    denc(v.deltas, p);
    denc(v.extents, p);
    denc(v.segment_nonce, p);
    denc(v.committed_to, p);
    denc(v.data_crc, p);
    DENC_FINISH(p);
  }
};

std::ostream &operator<<(std::ostream &out, const extent_info_t &header);

struct record_size_t {
  extent_len_t raw_mdlength = 0;
  extent_len_t mdlength = 0;
  extent_len_t dlength = 0;
};

extent_len_t get_encoded_record_raw_mdlength(
  const record_t &record,
  size_t block_size);

/**
 * Return <mdlength, dlength> pair denoting length of
 * metadata and blocks respectively.
 */
record_size_t get_encoded_record_length(
  const record_t &record,
  size_t block_size);

ceph::bufferlist encode_record(
  record_size_t rsize,
  record_t &&record,
  size_t block_size,
  const journal_seq_t& committed_to,
  segment_nonce_t current_segment_nonce = 0);

/// scan segment for end incrementally
struct scan_valid_records_cursor {
  bool last_valid_header_found = false;
  journal_seq_t seq;
  journal_seq_t last_committed;

  struct found_record_t {
    paddr_t offset;
    record_header_t header;
    bufferlist mdbuffer;

    found_record_t(
      paddr_t offset,
      const record_header_t &header,
      const bufferlist &mdbuffer)
      : offset(offset), header(header), mdbuffer(mdbuffer) {}
  };
  std::deque<found_record_t> pending_records;

  bool is_complete() const {
    return last_valid_header_found && pending_records.empty();
  }

  segment_id_t get_segment_id() const {
    return seq.offset.as_seg_paddr().get_segment_id();
  }

  segment_off_t get_segment_offset() const {
    return seq.offset.as_seg_paddr().get_segment_off();
  }

  void increment(segment_off_t off) {
    auto& seg_addr = seq.offset.as_seg_paddr();
    seg_addr.set_segment_off(
      seg_addr.get_segment_off() + off);
  }

  scan_valid_records_cursor(
    journal_seq_t seq)
    : seq(seq) {}
};

inline const seg_paddr_t& paddr_t::as_seg_paddr() const {
  assert(get_addr_type() == addr_types_t::SEGMENT);
  return *static_cast<const seg_paddr_t*>(this);
}

inline seg_paddr_t& paddr_t::as_seg_paddr() {
  assert(get_addr_type() == addr_types_t::SEGMENT);
  return *static_cast<seg_paddr_t*>(this);
}

inline const blk_paddr_t& paddr_t::as_blk_paddr() const {
  assert(get_addr_type() == addr_types_t::RANDOM_BLOCK);
  return *static_cast<const blk_paddr_t*>(this);
}

inline blk_paddr_t& paddr_t::as_blk_paddr() {
  assert(get_addr_type() == addr_types_t::RANDOM_BLOCK);
  return *static_cast<blk_paddr_t*>(this);
}

inline paddr_t paddr_t::operator-(paddr_t rhs) const {
  if (get_addr_type() == addr_types_t::SEGMENT) {
    auto& seg_addr = as_seg_paddr();
    return seg_addr - rhs;
  }
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

#define PADDR_OPERATION(a_type, base, func)        \
  if (get_addr_type() == a_type) {                 \
    return static_cast<const base*>(this)->func;   \
  }

inline paddr_t paddr_t::add_offset(int32_t o) const {
  PADDR_OPERATION(addr_types_t::SEGMENT, seg_paddr_t, add_offset(o))
  PADDR_OPERATION(addr_types_t::RANDOM_BLOCK, blk_paddr_t, add_offset(o))
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

inline paddr_t paddr_t::add_relative(paddr_t o) const {
  PADDR_OPERATION(addr_types_t::SEGMENT, seg_paddr_t, add_relative(o))
  PADDR_OPERATION(addr_types_t::RANDOM_BLOCK, blk_paddr_t, add_relative(o))
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

inline paddr_t paddr_t::add_block_relative(paddr_t o) const {
  PADDR_OPERATION(addr_types_t::SEGMENT, seg_paddr_t, add_block_relative(o))
  PADDR_OPERATION(addr_types_t::RANDOM_BLOCK, blk_paddr_t, add_block_relative(o))
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

inline paddr_t paddr_t::add_record_relative(paddr_t o) const {
  PADDR_OPERATION(addr_types_t::SEGMENT, seg_paddr_t, add_record_relative(o))
  PADDR_OPERATION(addr_types_t::RANDOM_BLOCK, blk_paddr_t, add_record_relative(o))
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

inline paddr_t paddr_t::maybe_relative_to(paddr_t o) const {
  PADDR_OPERATION(addr_types_t::SEGMENT, seg_paddr_t, maybe_relative_to(o))
  PADDR_OPERATION(addr_types_t::RANDOM_BLOCK, blk_paddr_t, maybe_relative_to(o))
  ceph_assert(0 == "not supported type");
  return paddr_t{};
}

}

WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::seastore_meta_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::segment_id_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::paddr_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::journal_seq_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::delta_info_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::record_header_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::extent_info_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::segment_header_t)
WRITE_CLASS_DENC_BOUNDED(crimson::os::seastore::rbm_alloc_delta_t)

template<>
struct denc_traits<crimson::os::seastore::device_type_t> {
  static constexpr bool supported = true;
  static constexpr bool featured = false;
  static constexpr bool bounded = true;
  static constexpr bool need_contiguous = false;

  static void bound_encode(
    const crimson::os::seastore::device_type_t &o,
    size_t& p,
    uint64_t f=0) {
    p += sizeof(crimson::os::seastore::device_type_t);
  }
  template<class It>
  static std::enable_if_t<!is_const_iterator_v<It>>
  encode(
    const crimson::os::seastore::device_type_t &o,
    It& p,
    uint64_t f=0) {
    get_pos_add<crimson::os::seastore::device_type_t>(p) = o;
  }
  template<class It>
  static std::enable_if_t<is_const_iterator_v<It>>
  decode(
    crimson::os::seastore::device_type_t& o,
    It& p,
    uint64_t f=0) {
    o = get_pos_add<crimson::os::seastore::device_type_t>(p);
  }
  static void decode(
    crimson::os::seastore::device_type_t& o,
    ceph::buffer::list::const_iterator &p) {
    p.copy(sizeof(crimson::os::seastore::device_type_t),
           reinterpret_cast<char*>(&o));
  }
};
