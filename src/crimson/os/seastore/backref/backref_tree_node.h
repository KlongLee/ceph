// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include "crimson/os/seastore/btree/fixed_kv_node.h"

namespace crimson::os::seastore::backref {

using backref_node_meta_t = fixed_kv_node_meta_t<paddr_t>;
using backref_node_meta_le_t = fixed_kv_node_meta_le_t<paddr_t>;

/**
 * Layout (4k):
 *   checksum   :                              4b
 *   size       : uint32_t[1]                  4b
 *   meta       : backref_node_meta_le_t[3]    (1*24)b
 *   keys       : paddr_t[169]                 (169*8)b
 *   values     : laddr_t[169]                 (169*16)b
 *                                             = 4088
 */
constexpr size_t INTERNAL_NODE_CAPACITY = 169;

/**
 * Layout (4k):
 *   checksum   :                              4b
 *   size       : uint32_t[1]                  4b
 *   meta       : backref_node_meta_le_t[3]    (1*24)b
 *   keys       : paddr_t[127]                 (127*8)b
 *   values     : backref_map_val_t[127]       (127*24)b
 *                                             = 4096
 */
constexpr size_t LEAF_NODE_CAPACITY = 127;

using BackrefNode = FixedKVNode<paddr_t>;

struct backref_map_val_t {
  extent_len_t len = 0;	///< length of extents
  laddr_t laddr = L_ADDR_MIN; ///< logical address of extents
  extent_types_t type = extent_types_t::ROOT;

  backref_map_val_t() = default;
  backref_map_val_t(
    extent_len_t len,
    laddr_t laddr,
    extent_types_t type)
    : len(len), laddr(laddr), type(type) {}

  bool operator==(const backref_map_val_t& rhs) const noexcept {
    return len == rhs.len && laddr == rhs.laddr;
  }
};

std::ostream& operator<<(std::ostream &out, const backref_map_val_t& val);

struct backref_map_val_le_t {
  extent_len_le_t len = init_extent_len_le(0);
  laddr_le_t laddr = laddr_le_t(L_ADDR_MIN);
  extent_types_le_t type = 0;

  backref_map_val_le_t() = default;
  backref_map_val_le_t(const backref_map_val_le_t &) = default;
  explicit backref_map_val_le_t(const backref_map_val_t &val)
    : len(init_extent_len_le(val.len)),
      laddr(val.laddr),
      type(extent_types_le_t(val.type)) {}

  operator backref_map_val_t() const {
    return backref_map_val_t{len, laddr, (extent_types_t)type};
  }
};

class BackrefInternalNode
  : public FixedKVInternalNode<
      INTERNAL_NODE_CAPACITY,
      paddr_t, paddr_le_t,
      BACKREF_NODE_SIZE,
      BackrefInternalNode> {
public:
  template <typename... T>
  BackrefInternalNode(T&&... t) :
    FixedKVInternalNode(std::forward<T>(t)...) {}

  static constexpr extent_types_t TYPE = extent_types_t::BACKREF_INTERNAL;

  extent_types_t get_type() const final {
    return TYPE;
  }
};
using BackrefInternalNodeRef = BackrefInternalNode::Ref;

class BackrefLeafNode
  : public FixedKVLeafNode<
      LEAF_NODE_CAPACITY,
      paddr_t, paddr_le_t,
      backref_map_val_t, backref_map_val_le_t,
      BACKREF_NODE_SIZE,
      BackrefLeafNode,
      false> {
public:
  template <typename... T>
  BackrefLeafNode(T&&... t) :
    FixedKVLeafNode(std::forward<T>(t)...) {}

  static constexpr extent_types_t TYPE = extent_types_t::BACKREF_LEAF;

  extent_types_t get_type() const final  {
    return TYPE;
  }

  const_iterator insert(
    const_iterator iter,
    paddr_t key,
    backref_map_val_t val,
    LogicalCachedExtent*) final {
    journal_insert(
      iter,
      key,
      val,
      maybe_get_delta_buffer());
    return iter;
  }

  void update(
    const_iterator iter,
    backref_map_val_t val,
    LogicalCachedExtent*) final {
    return journal_update(
      iter,
      val,
      maybe_get_delta_buffer());
  }

  void remove(const_iterator iter) final {
    return journal_remove(
      iter,
      maybe_get_delta_buffer());
  }

  // backref leaf nodes don't have to resolve relative addresses
  void resolve_relative_addrs(paddr_t base) final {}

  void node_resolve_vals(iterator from, iterator to) const final {}

  void node_unresolve_vals(iterator from, iterator to) const final {}
};
using BackrefLeafNodeRef = BackrefLeafNode::Ref;

} // namespace crimson::os::seastore::backref

#if FMT_VERSION >= 90000
template <> struct fmt::formatter<crimson::os::seastore::backref::backref_map_val_t> : fmt::ostream_formatter {};
template <> struct fmt::formatter<crimson::os::seastore::backref::BackrefInternalNode> : fmt::ostream_formatter {};
template <> struct fmt::formatter<crimson::os::seastore::backref::BackrefLeafNode> : fmt::ostream_formatter {};
template <> struct fmt::formatter<crimson::os::seastore::backref::backref_node_meta_t> : fmt::ostream_formatter {};
#endif
