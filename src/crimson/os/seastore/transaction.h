// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <iostream>

#include <boost/intrusive/list.hpp>

#include "crimson/common/log.h"
#include "crimson/os/seastore/logging.h"
#include "crimson/os/seastore/ordering_handle.h"
#include "crimson/os/seastore/seastore_types.h"
#include "crimson/os/seastore/cached_extent.h"
#include "crimson/os/seastore/root_block.h"

namespace crimson::os::seastore {

class SeaStore;
class Transaction;

/**
 * Transaction
 *
 * Representation of in-progress mutation. Used exclusively through Cache methods.
 */
class Transaction {
public:
  using Ref = std::unique_ptr<Transaction>;
  using on_destruct_func_t = std::function<void(Transaction&)>;
  enum class get_extent_ret {
    PRESENT,
    ABSENT,
    RETIRED
  };
  get_extent_ret get_extent(paddr_t addr, CachedExtentRef *out) {
    LOG_PREFIX(Transaction::get_extent);
    if (retired_set.count(addr)) {
      return get_extent_ret::RETIRED;
    } else if (auto iter = write_set.find_offset(addr);
	iter != write_set.end()) {
      if (out)
	*out = CachedExtentRef(&*iter);
      TRACET("Found offset {} in write_set: {}", *this, addr, *iter);
      return get_extent_ret::PRESENT;
    } else if (
      auto iter = read_set.find(addr);
      iter != read_set.end()) {
      // placeholder in read-set should be in the retired-set
      // at the same time.
      assert(iter->ref->get_type() != extent_types_t::RETIRED_PLACEHOLDER);
      if (out)
	*out = iter->ref;
      TRACET("Found offset {} in read_set: {}", *this, addr, *(iter->ref));
      return get_extent_ret::PRESENT;
    } else {
      return get_extent_ret::ABSENT;
    }
  }

  void add_to_retired_set(CachedExtentRef ref) {
    ceph_assert(!is_weak());
    if (ref->is_initial_pending()) {
      ref->state = CachedExtent::extent_state_t::INVALID;
      write_set.erase(*ref);
    } else if (ref->is_mutation_pending()) {
      ref->state = CachedExtent::extent_state_t::INVALID;
      write_set.erase(*ref);
      assert(ref->prior_instance);
      retired_set.insert(ref->prior_instance);
      assert(read_set.count(ref->prior_instance->get_paddr()));
      ref->prior_instance.reset();
    } else {
      // && retired_set.count(ref->get_paddr()) == 0
      // If it's already in the set, insert here will be a noop,
      // which is what we want.
      retired_set.insert(ref);
    }
  }

  void add_to_read_set(CachedExtentRef ref) {
    if (is_weak()) return;

    auto [iter, inserted] = read_set.emplace(this, ref);
    ceph_assert(inserted);
  }

  void add_fresh_extent(
    CachedExtentRef ref,
    bool delayed = false) {
    LOG_PREFIX(Transaction::add_fresh_extent);
    ceph_assert(!is_weak());
    if (delayed) {
      assert(ref->is_logical());
      ref->set_paddr(delayed_temp_paddr(delayed_temp_offset));
      delayed_temp_offset += ref->get_length();
      delayed_alloc_list.emplace_back(ref->cast<LogicalCachedExtent>());
    } else {
      ref->set_paddr(make_record_relative_paddr(offset));
      offset += ref->get_length();
      inline_block_list.push_back(ref);
    }
    TRACET("adding {} to write_set", *this, *ref);
    write_set.insert(*ref);
  }

  void mark_delayed_extent_inline(LogicalCachedExtentRef& ref) {
    LOG_PREFIX(Transaction::mark_delayed_extent_inline);
    TRACET("removing {} from write_set", *this, *ref);
    write_set.erase(*ref);
    ref->set_paddr(make_record_relative_paddr(offset));
    offset += ref->get_length();
    inline_block_list.push_back(ref);
    TRACET("adding {} to write_set", *this, *ref);
    write_set.insert(*ref);
  }

  void mark_delayed_extent_ool(LogicalCachedExtentRef& ref, paddr_t final_addr) {
    LOG_PREFIX(Transaction::mark_delayed_extent_ool);
    TRACET("removing {} from write_set", *this, *ref);
    write_set.erase(*ref);
    ref->set_paddr(final_addr);
    assert(!ref->get_paddr().is_null());
    assert(!ref->is_inline());
    ool_block_list.push_back(ref);
    TRACET("adding {} to write_set", *this, *ref);
    write_set.insert(*ref);
  }

  void add_mutated_extent(CachedExtentRef ref) {
    LOG_PREFIX(Transaction::add_mutated_extent);
    ceph_assert(!is_weak());
    mutated_block_list.push_back(ref);
    TRACET("adding {} to write_set", *this, *ref);
    write_set.insert(*ref);
  }

  void replace_placeholder(CachedExtent& placeholder, CachedExtent& extent) {
    ceph_assert(!is_weak());

    assert(placeholder.get_type() == extent_types_t::RETIRED_PLACEHOLDER);
    assert(extent.get_type() != extent_types_t::RETIRED_PLACEHOLDER);
    assert(extent.get_type() != extent_types_t::ROOT);
    assert(extent.get_paddr() == placeholder.get_paddr());
    {
      auto where = read_set.find(placeholder.get_paddr());
      assert(where != read_set.end());
      assert(where->ref.get() == &placeholder);
      where = read_set.erase(where);
      read_set.emplace_hint(where, this, &extent);
    }
    {
      auto where = retired_set.find(&placeholder);
      assert(where != retired_set.end());
      assert(where->get() == &placeholder);
      where = retired_set.erase(where);
      retired_set.emplace_hint(where, &extent);
    }
  }

  void mark_segment_to_release(segment_id_t segment) {
    assert(to_release == NULL_SEG_ID);
    to_release = segment;
  }

  segment_id_t get_segment_to_release() const {
    return to_release;
  }

  auto& get_delayed_alloc_list() {
    return delayed_alloc_list;
  }

  const auto &get_mutated_block_list() {
    return mutated_block_list;
  }

  const auto &get_retired_set() {
    return retired_set;
  }

  template <typename F>
  auto for_each_fresh_block(F &&f) {
    std::for_each(ool_block_list.begin(), ool_block_list.end(), f);
    std::for_each(inline_block_list.begin(), inline_block_list.end(), f);
  }

  auto get_num_fresh_blocks() const {
    return inline_block_list.size() + ool_block_list.size();
  }

  enum class src_t : uint8_t {
    MUTATE = 0,
    READ, // including weak and non-weak read transactions
    CLEANER,
    MAX
  };
  static constexpr auto SRC_MAX = static_cast<std::size_t>(src_t::MAX);
  src_t get_src() const {
    return src;
  }

  bool is_weak() const {
    return weak;
  }

  void test_set_conflict() {
    conflicted = true;
  }

  bool is_conflicted() const {
    return conflicted;
  }

  auto &get_handle() {
    return handle;
  }

  Transaction(
    OrderingHandle &&handle,
    bool weak,
    src_t src,
    journal_seq_t initiated_after,
    on_destruct_func_t&& f
  ) : weak(weak),
      handle(std::move(handle)),
      on_destruct(std::move(f)),
      src(src)
  {}

  void invalidate_clear_write_set() {
    for (auto &&i: write_set) {
      i.state = CachedExtent::extent_state_t::INVALID;
    }
    write_set.clear();
  }

  ~Transaction() {
    on_destruct(*this);
    invalidate_clear_write_set();
  }

  friend class crimson::os::seastore::SeaStore;
  friend class TransactionConflictCondition;

  void reset_preserve_handle(journal_seq_t initiated_after) {
    root.reset();
    offset = 0;
    delayed_temp_offset = 0;
    read_set.clear();
    blocks_with_onode_fixing.clear();
    invalidate_clear_write_set();
    mutated_block_list.clear();
    delayed_alloc_list.clear();
    inline_block_list.clear();
    ool_block_list.clear();
    retired_set.clear();
    onode_tree_stats = {};
    lba_tree_stats = {};
    onode_tree_conflict_stats = {};
    to_release = NULL_SEG_ID;
    conflicted = false;
    if (!has_reset) {
      has_reset = true;
    }
  }

  bool did_reset() const {
    return has_reset;
  }

  struct tree_stats_t {
    uint64_t depth = 0;
    uint64_t num_inserts = 0;
    uint64_t num_erases = 0;

    bool is_clear() const {
      return (depth == 0 &&
              num_inserts == 0 &&
              num_erases == 0);
    }
  };
  tree_stats_t& get_onode_tree_stats() {
    return onode_tree_stats;
  }
  tree_stats_t& get_lba_tree_stats() {
    return lba_tree_stats;
  }

  struct onode_tree_conflict_stats_t {
    uint64_t marked_fixing = 0;

    static constexpr auto NOOP_LEVEL = std::numeric_limits<uint8_t>::max();
    uint8_t fixing_level = NOOP_LEVEL;

    uint64_t last_num_modify_when_fixing = 0;
    uint64_t num_modify = 0;
    uint64_t num_modify_with_fix = 0;

    // account stats
    void mark_modify() {
      ++num_modify;
    }

    void mark_fixing(uint8_t _level) {
      ceph_assert(num_modify != 0);
      if (marked_fixing == 0) {
        ceph_assert(fixing_level == NOOP_LEVEL);
        fixing_level = _level;
        if (last_num_modify_when_fixing != num_modify) {
          last_num_modify_when_fixing = num_modify;
          ++num_modify_with_fix;
        } else {
          // should already account num_modify_with_fix
        }
      } else {
        // nested
        ceph_assert(fixing_level <= _level);
      }
      ++marked_fixing;
    }

    void unmark_fixing() {
      ceph_assert(marked_fixing != 0);
      --marked_fixing;
      if (marked_fixing == 0) {
        fixing_level = NOOP_LEVEL;
      }
    }

    bool is_fixing() const {
      return marked_fixing != 0;
    }

    uint8_t get_fixing_level() const {
      ceph_assert(is_fixing());
      ceph_assert(fixing_level != NOOP_LEVEL);
      return fixing_level;
    }

    // get stats when commit
    uint64_t get_num_modify() const {
      return num_modify;
    }

    uint64_t get_num_modify_with_fix() const {
      return num_modify_with_fix;
    }
  };
  void onode_mark_extent_fixing(CachedExtentRef ext) {
    ceph_assert(ext->get_type() == extent_types_t::ONODE_BLOCK_STAGED);
    CachedExtentRef to_mark = ext;
    if (ext->prior_instance) {
      to_mark = ext->prior_instance;
    }
    auto [iter, inserted] = blocks_with_onode_fixing.emplace(this, to_mark);
    ceph_assert(inserted);
  }
  void onode_mark_modify() {
    onode_tree_conflict_stats.mark_modify();
  }
  void onode_mark_fixing(uint8_t level) {
    onode_tree_conflict_stats.mark_fixing(level);
  }
  void onode_unmark_fixing() {
    onode_tree_conflict_stats.unmark_fixing();
  }
  bool onode_is_fixing() const {
    return onode_tree_conflict_stats.is_fixing();
  }
  uint8_t onode_get_fixing_level() const {
    return onode_tree_conflict_stats.get_fixing_level();
  }
  uint64_t onode_get_num_modify() const {
    return onode_tree_conflict_stats.get_num_modify();
  }
  uint64_t onode_get_num_modify_with_fix() const {
    return onode_tree_conflict_stats.get_num_modify_with_fix();
  }
  bool onode_is_extent_fixing(CachedExtentRef ext) {
    ceph_assert(!ext->prior_instance);
    auto iter = blocks_with_onode_fixing.find(ext->get_paddr());
    if (iter != blocks_with_onode_fixing.end()) {
      return true;
    } else {
      return false;
    }
  }

private:
  friend class Cache;
  friend Ref make_test_transaction();

  /**
   * If set, *this may not be used to perform writes and will not provide
   * consistentency allowing operations using to avoid maintaining a read_set.
   */
  const bool weak;

  RootBlockRef root;        ///< ref to root if read or written by transaction

  segment_off_t offset = 0; ///< relative offset of next block
  segment_off_t delayed_temp_offset = 0;

  /**
   * read_set
   *
   * Holds a reference (with a refcount) to every extent read via *this.
   * Submitting a transaction mutating any contained extent/addr will
   * invalidate *this.
   */
  read_set_t<Transaction> read_set; ///< set of extents read by paddr

  read_set_t<Transaction> blocks_with_onode_fixing;

  /**
   * write_set
   *
   * Contains a reference (without a refcount) to every extent mutated
   * as part of *this.  No contained extent may be referenced outside
   * of *this.  Every contained extent will be in one of inline_block_list,
   * ool_block_list, mutated_block_list, or delayed_alloc_list.
   */
  ExtentIndex write_set;

  /// list of fresh blocks, holds refcounts, subset of write_set
  std::list<CachedExtentRef> inline_block_list;

  /// list of fresh blocks, holds refcounts, subset of write_set
  std::list<CachedExtentRef> ool_block_list;

  /// extents with delayed allocation, may become inline or ool
  std::list<LogicalCachedExtentRef> delayed_alloc_list;

  /// list of mutated blocks, holds refcounts, subset of write_set
  std::list<CachedExtentRef> mutated_block_list;

  /**
   * retire_set
   *
   * Set of extents retired by *this.
   */
  pextent_set_t retired_set;

  tree_stats_t onode_tree_stats;
  tree_stats_t lba_tree_stats;

  onode_tree_conflict_stats_t onode_tree_conflict_stats;

  ///< if != NULL_SEG_ID, release this segment after completion
  segment_id_t to_release = NULL_SEG_ID;

  bool conflicted = false;

  bool has_reset = false;

  OrderingHandle handle;

  on_destruct_func_t on_destruct;

  const src_t src;
};
using TransactionRef = Transaction::Ref;

inline std::ostream& operator<<(std::ostream& os,
                                const Transaction::src_t& src) {
  switch (src) {
  case Transaction::src_t::MUTATE:
    return os << "MUTATE";
  case Transaction::src_t::READ:
    return os << "READ";
  case Transaction::src_t::CLEANER:
    return os << "CLEANER";
  default:
    ceph_abort("impossible");
  }
}

/// Should only be used with dummy staged-fltree node extent manager
inline TransactionRef make_test_transaction() {
  return std::make_unique<Transaction>(
    get_dummy_ordering_handle(),
    false,
    Transaction::src_t::MUTATE,
    journal_seq_t{},
    [](Transaction&) {}
  );
}

struct TransactionConflictCondition {
  class transaction_conflict final : public std::exception {
  public:
    const char* what() const noexcept final {
      return "transaction conflict detected";
    }
  };

public:
  TransactionConflictCondition(Transaction &t) : t(t) {}

  template <typename Fut>
  std::pair<bool, std::optional<Fut>> may_interrupt() {
    if (t.conflicted) {
      return {
	true,
	seastar::futurize<Fut>::make_exception_future(
	  transaction_conflict())};
    } else {
      return {false, std::optional<Fut>()};
    }
  }

  template <typename T>
  static constexpr bool is_interruption_v =
    std::is_same_v<T, transaction_conflict>;


  static bool is_interruption(std::exception_ptr& eptr) {
    return *eptr.__cxa_exception_type() == typeid(transaction_conflict);
  }

private:
  Transaction &t;
};

using trans_intr = crimson::interruptible::interruptor<
  TransactionConflictCondition
  >;

template <typename E>
using trans_iertr =
  crimson::interruptible::interruptible_errorator<
    TransactionConflictCondition,
    E
  >;

template <typename F, typename... Args>
auto with_trans_intr(Transaction &t, F &&f, Args&&... args) {
  return trans_intr::with_interruption_to_error<crimson::ct_error::eagain>(
    std::move(f),
    TransactionConflictCondition(t),
    t,
    std::forward<Args>(args)...);
}

template <typename T>
using with_trans_ertr = typename T::base_ertr::template extend<crimson::ct_error::eagain>;

}
