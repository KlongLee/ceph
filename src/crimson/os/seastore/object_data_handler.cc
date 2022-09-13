// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <utility>
#include <functional>

#include "crimson/common/log.h"

#include "crimson/os/seastore/object_data_handler.h"

namespace {
  seastar::logger& logger() {
    return crimson::get_logger(ceph_subsys_seastore_odata);
  }
}

SET_SUBSYS(seastore_odata);

namespace crimson::os::seastore {
#define assert_aligned(x) ceph_assert(((x)%ctx.tm.get_block_size()) == 0)

using context_t = ObjectDataHandler::context_t;
using get_iertr = ObjectDataHandler::write_iertr;

auto read_pin(
  context_t ctx,
  LBAPinRef pin) {
  return ctx.tm.pin_to_extent<ObjectDataBlock>(
    ctx.t,
    std::move(pin)
  ).handle_error_interruptible(
    get_iertr::pass_further{},
    crimson::ct_error::assert_all{ "read_pin: invalid error" }
  );
}

/**
 * extent_to_write_t
 *
 * Encapsulates extents to be written out using do_insertions.
 * Indicates a zero/existing extent or a data extent based on whether
 * to_write is populate.
 * The meaning of existing_paddr is that the new extent to be
 * written is the part of exising extent on the disk. existing_paddr
 * must be absolute.
 */
struct extent_to_write_t {
  laddr_t addr = L_ADDR_NULL;
  extent_len_t len;
  std::optional<bufferlist> to_write;
  std::optional<paddr_t> existing_paddr = std::nullopt;

  extent_to_write_t() = default;
  extent_to_write_t(const extent_to_write_t &) = default;
  extent_to_write_t(extent_to_write_t &&) = default;

  extent_to_write_t(laddr_t addr, bufferlist to_write)
    : addr(addr), len(to_write.length()), to_write(to_write) {}

  extent_to_write_t(laddr_t addr, extent_len_t len)
    : addr(addr), len(len) {}

  extent_to_write_t(laddr_t addr, paddr_t existing_paddr, extent_len_t len)
    : addr(addr), len(len), to_write(std::nullopt), existing_paddr(existing_paddr) {}
};
using extent_to_write_list_t = std::list<extent_to_write_t>;

/**
 * append_extent_to_write
 *
 * Appends passed extent_to_write_t maintaining invariant that the
 * list may not contain consecutive zero elements by checking and
 * combining them.
 */
void append_extent_to_write(
  extent_to_write_list_t &to_write, extent_to_write_t &&to_append)
{
  assert(
    to_write.empty() ||
    (to_write.back().addr + to_write.back().len) == to_append.addr);
  if (to_write.empty() || to_write.back().to_write || to_append.to_write) {
    to_write.push_back(std::move(to_append));
  } else {
    to_write.back().len += to_append.len;
  }
}

/**
 * splice_extent_to_write
 *
 * splices passed extent_to_write_list_t maintaining invariant that the
 * list may not contain consecutive zero elements by checking and
 * combining them.
 */
void splice_extent_to_write(
  extent_to_write_list_t &to_write, extent_to_write_list_t &&to_splice)
{
  if (!to_splice.empty()) {
    append_extent_to_write(to_write, std::move(to_splice.front()));
    to_splice.pop_front();
    to_write.splice(to_write.end(), std::move(to_splice));
  }
}

/// Removes extents/mappings in pins
ObjectDataHandler::write_ret do_removals(
  context_t ctx,
  lba_pin_list_t &pins)
{
  return trans_intr::do_for_each(
    pins,
    [ctx](auto &pin) {
      LOG_PREFIX(object_data_handler.cc::do_removals);
      DEBUGT("decreasing ref: {}",
	     ctx.t,
	     pin->get_key());
      return ctx.tm.dec_ref(
	ctx.t,
	pin->get_key()
      ).si_then(
	[](auto){},
	ObjectDataHandler::write_iertr::pass_further{},
	crimson::ct_error::assert_all{
	  "object_data_handler::do_removals invalid error"
	}
      );
    });
}

/// Creates zero/data extents in to_write
ObjectDataHandler::write_ret do_insertions(
  context_t ctx,
  extent_to_write_list_t &to_write)
{
  return trans_intr::do_for_each(
    to_write,
    [ctx](auto &region) {
      LOG_PREFIX(object_data_handler.cc::do_insertions);
      if (region.to_write) {
	assert_aligned(region.addr);
	assert_aligned(region.len);
	ceph_assert(region.len == region.to_write->length());
	DEBUGT("allocating extent: {}~{}",
	       ctx.t,
	       region.addr,
	       region.len);
	return ctx.tm.alloc_extent<ObjectDataBlock>(
	  ctx.t,
	  region.addr,
	  region.len
	).si_then([&region](auto extent) {
	  if (extent->get_laddr() != region.addr) {
	    logger().debug(
	      "object_data_handler::do_insertions alloc got addr {},"
	      " should have been {}",
	      extent->get_laddr(),
	      region.addr);
	  }
	  ceph_assert(extent->get_laddr() == region.addr);
	  ceph_assert(extent->get_length() == region.len);
	  auto iter = region.to_write->cbegin();
	  iter.copy(region.len, extent->get_bptr().c_str());
	  return ObjectDataHandler::write_iertr::now();
	});
      } else if (!region.existing_paddr){
	DEBUGT("reserving: {}~{}",
	       ctx.t,
	       region.addr,
	       region.len);
	return ctx.tm.reserve_region(
	  ctx.t,
	  region.addr,
	  region.len
	).si_then([FNAME, ctx, &region](auto pin) {
	  ceph_assert(pin->get_length() == region.len);
	  if (pin->get_key() != region.addr) {
	    ERRORT(
	      "inconsistent laddr: pin: {} region {}",
	      ctx.t,
	      pin->get_key(),
	      region.addr);
	  }
	  ceph_assert(pin->get_key() == region.addr);
	  return ObjectDataHandler::write_iertr::now();
	});
      } else {
	DEBUGT("map existing extent: laddr {} len {} {}",
	       ctx.t, region.addr, region.len, *region.existing_paddr);
	return ctx.tm.map_existing_extent<ObjectDataBlock>(
	  ctx.t, region.addr, *region.existing_paddr, region.len
	).handle_error_interruptible(
	  TransactionManager::alloc_extent_iertr::pass_further{},
	  Device::read_ertr::assert_all{"ignore read error"}
	).si_then([FNAME, ctx, &region](auto extent) {
	  if (extent->get_laddr() != region.addr) {
	    ERRORT(
	      "inconsistent laddr: extent: {} region {}",
	      ctx.t,
	      extent->get_laddr(),
	      region.addr);
	  }
	  ceph_assert(extent->get_laddr() == region.addr);
	  return ObjectDataHandler::write_iertr::now();
	});
      }
    });
}

struct overwrite_plan_t {
  extent_len_t block_size;
  laddr_t pin_begin;
  laddr_t pin_end;
  paddr_t left_paddr;
  paddr_t right_paddr;
  laddr_t data_begin;
  laddr_t data_end;
  laddr_t aligned_begin;
  laddr_t aligned_end;
  extent_len_t data_size;
  extent_len_t write_size;
  bool split_left;
  bool split_right;
  friend std::ostream& operator<<(
    std::ostream& out,
    const overwrite_plan_t& overwrite_plan) {
    return out << "overwrite_plan_t(pin_begin=" << overwrite_plan.pin_begin
	       << ", pin_end=" << overwrite_plan.pin_end
	       << ", left_paddr=" << overwrite_plan.left_paddr
	       << ", right_paddr=" << overwrite_plan.right_paddr
	       << ", data_begin=" << overwrite_plan.data_begin
	       << ", data_end=" << overwrite_plan.data_end
	       << ", aligned_begin=" << overwrite_plan.aligned_begin
	       << ", aligned_end=" << overwrite_plan.aligned_end
	       << ", block_size=" << overwrite_plan.block_size
	       << ", data_size=" << overwrite_plan.data_size
	       << ", write_size=" << overwrite_plan.write_size << std::boolalpha
	       << ", split_left=" << overwrite_plan.split_left
	       << ", split_right=" << overwrite_plan.split_right << ")"
	       << std::noboolalpha;
  }
  overwrite_plan_t(laddr_t offset,
		   extent_len_t len,
		   const lba_pin_list_t& pins,
		   extent_len_t block_size) :
    block_size(block_size),
    pin_begin(pins.front()->get_key()),
    pin_end(pins.back()->get_key() + pins.back()->get_length()),
    left_paddr(pins.front()->get_val()),
    right_paddr(pins.back()->get_val()),
    data_begin(offset),
    data_end(offset + len),
    aligned_begin(p2align((uint64_t)data_begin, (uint64_t)block_size)),
    aligned_end(p2roundup((uint64_t)data_end, (uint64_t)block_size)),
    data_size(aligned_end - aligned_begin),
    write_size(pin_end - pin_begin),
    split_left(false),
    split_right(false) {}

  void validate() const {
    ceph_assert(pin_begin <= data_begin);
    ceph_assert(pin_end >= data_end);
    ceph_assert(aligned_begin % block_size == 0);
    ceph_assert(aligned_begin <= data_begin);
    ceph_assert(pin_begin <= aligned_begin);
    ceph_assert(aligned_end % block_size == 0);
    ceph_assert(aligned_end >= data_end);
    ceph_assert(pin_end >= aligned_end);
  }
  /*
   * When trying to modify a portion of an object data block, follow
   * the read-full-extent-then-merge-new-data strategy, if the write
   * amplification caused by it is not greater than
   * seastore_obj_data_write_amplification; otherwise, split the
   * original extent into at most three parts: origin-left, part-to-be-modified
   * and origin-right.
   *
   * all used variable are described as follows:
   * |<--------------------------------------write_size--------------------------------------->|
   *                 |<----------------------data_size----------------------->|
   *                                data_begin         data_end
   *                                ---------------------------(incoming data)
   *                 aligned_begin                                  aligned_end
   *                 ----------------------------------------------------------(incoming data's block-size-aligned range)
   * |<--left_size-->|                                                        |<--right_size-->|
   * pin_begin                                                                           pin_end
   * -------------------------------------(existing extent)   ----------------------------------(existing extent)
   * left_paddr                                               right_paddr
   *
   * pseudocode of splitting:
   *
   * if left_paddr/right_paddr is zero:
   *   prepend/append hole if data_offset/data_end is not aligned,
   *   reverse zero extent if necessary.
   *
   * if left_paddr/right_paddr is relative:
   *   merge pin_begin/pin_end to incoming data
   *
   * if left_paddr/right_paddr is absolute, split extent:
   *   while either left or right is not processed:
   *     if write/data_size > seastore_obj_data_write_amplification
   *       select a larger end according to left_size and right_size,
   *       split selected end.
   *       write_size -= left_size or right_size
   *     else
   *       merge the end that has not been processed
   */
  void split() {
    auto left_size = aligned_begin - pin_begin;
    auto right_size = pin_end - aligned_end;
    bool left_set = false;
    bool right_set = false;
    if (left_paddr.is_zero()) {
      write_size -= left_size;
      left_size = 0;
      left_set = true;
    } else if (left_paddr.is_relative() ||
	       left_paddr.is_delayed()) {
      data_size += left_size;
      left_size = 0;
      left_set = true;
    }
    if (right_paddr.is_zero()) {
      write_size -= right_size;
      right_size = 0;
      right_set = true;
    } else if (right_paddr.is_relative() ||
	       right_paddr.is_delayed()) {
      data_size += right_size;
      right_size = 0;
      right_set = true;
    }

    while (!(left_set && right_set)) {
      if (((double)write_size / (double)data_size) >
	  crimson::common::get_conf<double>("seastore_obj_data_write_amplification")) {
	if (left_size >= right_size && !left_set && left_size != 0) {
	  write_size -= left_size;
	  left_size = 0;
	  left_set = true;
	  split_left = true;
	} else if (!right_set && right_size != 0) {
	  write_size -= right_size;
	  right_size = 0;
	  right_set = true;
	  split_right = true;
	} else {
	  ceph_assert(0 == "impossible case");
	}
      } else {
	break;
      }
    }
    // fallback case, merge default
    if (!left_set) {
      split_left = false;
    }
    if (!right_set) {
      split_right = false;
    }
  }
};

overwrite_plan_t generate_overwrite_plan(
  laddr_t offset,
  extent_len_t len,
  const lba_pin_list_t& pins,
  extent_len_t block_size) {
  overwrite_plan_t plan(offset, len, pins, block_size);
  plan.validate();
  plan.split();
  return plan;
}

/**
 * split_pin_left
 *
 * Splits the passed pin returning aligned extent to be rewritten
 * to the left (if a zero extent), tail to be prepended to write
 * beginning at offset.  See below for details.
 */
using split_ret_bare = std::pair<
  std::optional<extent_to_write_t>,
  std::optional<bufferptr>>;
using split_ret = get_iertr::future<split_ret_bare>;
split_ret split_pin_left(context_t ctx, LBAPinRef &pin, const overwrite_plan_t &overwrite_plan)
{
  if (overwrite_plan.data_begin == overwrite_plan.pin_begin) {
    // Aligned, no tail and no extra extent
    return get_iertr::make_ready_future<split_ret_bare>(
      std::nullopt,
      std::nullopt);
  } else if (pin->get_val().is_zero()) {
    /* Zero extent unaligned, return largest aligned zero extent to
     * the left and the gap between aligned_offset and offset to prepend. */
    auto zero_extent_len = overwrite_plan.aligned_begin - overwrite_plan.pin_begin;
    assert_aligned(zero_extent_len);
    auto zero_prepend_len = overwrite_plan.data_begin - overwrite_plan.aligned_begin;
    return get_iertr::make_ready_future<split_ret_bare>(
      (zero_extent_len == 0
       ? std::nullopt
       : std::make_optional(extent_to_write_t(overwrite_plan.pin_begin, zero_extent_len))),
      (zero_prepend_len == 0
       ? std::nullopt
       : std::make_optional(
	 bufferptr(ceph::buffer::create(zero_prepend_len, 0))))
    );
  } else {
    if (!overwrite_plan.split_left) {
      // Data, return up to offset to prepend
      auto to_prepend = overwrite_plan.data_begin - overwrite_plan.pin_begin;
      return read_pin(ctx, pin->duplicate()
      ).si_then([to_prepend](auto extent) {
	return get_iertr::make_ready_future<split_ret_bare>(
	  std::nullopt,
	  (to_prepend == 0
	   ? std::nullopt
	   : std::make_optional(bufferptr(extent->get_bptr(), 0, to_prepend))));
      });
    } else {
      auto extent_len = overwrite_plan.aligned_begin - overwrite_plan.pin_begin;
      auto prepend_len = overwrite_plan.data_begin - overwrite_plan.aligned_begin;
      if (prepend_len == 0) {
	// block_size aligned, split
	return get_iertr::make_ready_future<split_ret_bare>(
	  (extent_len == 0
	   ? std::nullopt
	   : std::make_optional(extent_to_write_t(
	       overwrite_plan.pin_begin,
	       overwrite_plan.left_paddr,
	       extent_len))),
	  std::nullopt);
      } else {
	// not block_size aligned, split
	return read_pin(ctx, pin->duplicate()
	).si_then([prepend_len, extent_len, &overwrite_plan](auto extent) {
	  return get_iertr::make_ready_future<split_ret_bare>(
	    (extent_len == 0
	     ? std::nullopt
	     : std::make_optional(extent_to_write_t(
	         overwrite_plan.pin_begin,
		 overwrite_plan.left_paddr,
		 extent_len))),
	    std::make_optional(bufferptr(
	      extent->get_bptr(),
	      overwrite_plan.aligned_begin - overwrite_plan.pin_begin,
	      prepend_len)));
	});
      }
    }
  }
};

/// Reverse of split_pin_left
split_ret split_pin_right(context_t ctx, LBAPinRef &pin, const overwrite_plan_t &overwrite_plan)
{
  if (overwrite_plan.data_end == overwrite_plan.pin_end) {
    return get_iertr::make_ready_future<split_ret_bare>(
      std::nullopt,
      std::nullopt);
  } else if (pin->get_val().is_zero()) {
    auto zero_suffix_len = overwrite_plan.aligned_end - overwrite_plan.data_end;
    auto zero_extent_len = overwrite_plan.pin_end - overwrite_plan.aligned_end;
    assert_aligned(zero_extent_len);
    return get_iertr::make_ready_future<split_ret_bare>(
      (zero_extent_len == 0
       ? std::nullopt
       : std::make_optional(extent_to_write_t(overwrite_plan.aligned_end, zero_extent_len))),
      (zero_suffix_len == 0
       ? std::nullopt
       : std::make_optional(
         bufferptr(ceph::buffer::create(zero_suffix_len, 0))))
    );
  } else {
    auto last_pin_begin = pin->get_key();
    if (!overwrite_plan.split_right) {
      return read_pin(ctx, pin->duplicate()
      ).si_then([last_pin_begin, &overwrite_plan](auto extent) {
	auto to_append = overwrite_plan.pin_end - overwrite_plan.data_end;
        return get_iertr::make_ready_future<split_ret_bare>(
          std::nullopt,
	  (to_append == 0
	   ? std::nullopt
	   : std::make_optional(bufferptr(
	       extent->get_bptr(),
	       overwrite_plan.data_end - last_pin_begin,
	       to_append))));
      });
    } else {
      auto extent_len = overwrite_plan.pin_end - overwrite_plan.aligned_end;
      auto append_len = overwrite_plan.aligned_end - overwrite_plan.data_end;
      if (append_len == 0) {
        return get_iertr::make_ready_future<split_ret_bare>(
	  (extent_len == 0
	   ? std::nullopt
	   : std::make_optional(extent_to_write_t(
	       overwrite_plan.aligned_end,
	       overwrite_plan.right_paddr.add_offset(overwrite_plan.aligned_end - last_pin_begin),
	       extent_len))),
          std::nullopt);
      } else {
	return read_pin(ctx, pin->duplicate()
	).si_then([last_pin_begin, append_len, extent_len, &overwrite_plan](auto extent) {
	  return get_iertr::make_ready_future<split_ret_bare>(
	  (extent_len == 0
	   ? std::nullopt
	   : std::make_optional(extent_to_write_t(
	       overwrite_plan.aligned_end,
	       overwrite_plan.right_paddr.add_offset(overwrite_plan.aligned_end - last_pin_begin),
	       extent_len))),
	  std::make_optional(bufferptr(
	    extent->get_bptr(),
	    overwrite_plan.data_end - last_pin_begin,
	    append_len)));
	});
      }
    }
  }
};

template <typename F>
auto with_object_data(
  ObjectDataHandler::context_t ctx,
  F &&f)
{
  return seastar::do_with(
    ctx.onode.get_layout().object_data.get(),
    std::forward<F>(f),
    [ctx](auto &object_data, auto &f) {
      return std::invoke(f, object_data
      ).si_then([ctx, &object_data] {
	if (object_data.must_update()) {
	  ctx.onode.get_mutable_layout(ctx.t).object_data.update(object_data);
	}
	return seastar::now();
      });
    });
}

ObjectDataHandler::write_ret ObjectDataHandler::prepare_data_reservation(
  context_t ctx,
  object_data_t &object_data,
  extent_len_t size)
{
  LOG_PREFIX(ObjectDataHandler::prepare_data_reservation);
  ceph_assert(size <= max_object_size);
  if (!object_data.is_null()) {
    ceph_assert(object_data.get_reserved_data_len() == max_object_size);
    DEBUGT("reservation present: {}~{}",
           ctx.t,
           object_data.get_reserved_data_base(),
           object_data.get_reserved_data_len());
    return write_iertr::now();
  } else {
    DEBUGT("reserving: {}~{}",
           ctx.t,
           ctx.onode.get_data_hint(),
           max_object_size);
    return ctx.tm.reserve_region(
      ctx.t,
      ctx.onode.get_data_hint(),
      max_object_size
    ).si_then([max_object_size=max_object_size, &object_data](auto pin) {
      ceph_assert(pin->get_length() == max_object_size);
      object_data.update_reserved(
	pin->get_key(),
	pin->get_length());
      return write_iertr::now();
    });
  }
}

ObjectDataHandler::clear_ret ObjectDataHandler::trim_data_reservation(
  context_t ctx, object_data_t &object_data, extent_len_t size)
{
  ceph_assert(!object_data.is_null());
  ceph_assert(size <= object_data.get_reserved_data_len());
  return seastar::do_with(
    lba_pin_list_t(),
    extent_to_write_list_t(),
    [ctx, size, &object_data](auto &pins, auto &to_write) {
      LOG_PREFIX(ObjectDataHandler::trim_data_reservation);
      DEBUGT("object_data: {}~{}",
	     ctx.t,
	     object_data.get_reserved_data_base(),
	     object_data.get_reserved_data_len());
      return ctx.tm.get_pins(
	ctx.t,
	object_data.get_reserved_data_base() + size,
	object_data.get_reserved_data_len() - size
      ).si_then([ctx, size, &pins, &object_data, &to_write](auto _pins) {
	_pins.swap(pins);
	ceph_assert(pins.size());
	auto &pin = *pins.front();
	ceph_assert(pin.get_key() >= object_data.get_reserved_data_base());
	ceph_assert(
	  pin.get_key() <= object_data.get_reserved_data_base() + size);
	auto pin_offset = pin.get_key() -
	  object_data.get_reserved_data_base();
	if ((pin.get_key() == (object_data.get_reserved_data_base() + size)) ||
	  (pin.get_val().is_zero())) {
	  /* First pin is exactly at the boundary or is a zero pin.  Either way,
	   * remove all pins and add a single zero pin to the end. */
	  to_write.emplace_back(
	    pin.get_key(),
	    object_data.get_reserved_data_len() - pin_offset);
	  return clear_iertr::now();
	} else {
	  /* First pin overlaps the boundary and has data, read in extent
	   * and rewrite portion prior to size */
	  return read_pin(
	    ctx,
	    pin.duplicate()
	  ).si_then([ctx, size, pin_offset, &pin, &object_data, &to_write](
		     auto extent) {
	    bufferlist bl;
	    bl.append(
	      bufferptr(
		extent->get_bptr(),
		0,
		size - pin_offset
	      ));
	    bl.append_zero(p2roundup(size, ctx.tm.get_block_size()) - size);
	    to_write.emplace_back(
	      pin.get_key(),
	      bl);
	    to_write.emplace_back(
	      object_data.get_reserved_data_base() +
                p2roundup(size, ctx.tm.get_block_size()),
	      object_data.get_reserved_data_len() -
                p2roundup(size, ctx.tm.get_block_size()));
	    return clear_iertr::now();
	  });
	}
      }).si_then([ctx, &pins] {
	return do_removals(ctx, pins);
      }).si_then([ctx, &to_write] {
	return do_insertions(ctx, to_write);
      }).si_then([size, &object_data] {
	if (size == 0) {
	  object_data.clear();
	}
	return ObjectDataHandler::clear_iertr::now();
      });
    });
}

/**
 * get_zero_buffers
 *
 * Returns extent_to_write_t's reflecting a zero region extending
 * from offset~len with headptr optionally on the left and tailptr
 * optionally on the right.
 */
extent_to_write_list_t get_zero_buffers(
  const extent_len_t block_size,
  laddr_t offset, extent_len_t len,
  std::optional<bufferptr> &&headptr, std::optional<bufferptr> &&tailptr)
{
  auto zero_left = p2roundup(offset, (laddr_t)block_size);
  auto zero_right = p2align(offset + len, (laddr_t)block_size);
  auto left = headptr ? (offset - headptr->length()) : offset;
  auto right = tailptr ?
    (offset + len + tailptr->length()) :
    (offset + len);

  assert(
    (headptr && ((zero_left - left) ==
		 p2roundup(headptr->length(), block_size))) ^
    (!headptr && (zero_left == left)));
  assert(
    (tailptr && ((right - zero_right) ==
		 p2roundup(tailptr->length(), block_size))) ^
    (!tailptr && (right == zero_right)));

  assert(right > left);
  assert((left % block_size) == 0);
  assert((right % block_size) == 0);

  // zero region too small for a reserved section,
  // headptr and tailptr in same extent
  if (zero_right <= zero_left) {
    bufferlist bl;
    if (headptr) {
      bl.append(*headptr);
    }
    bl.append_zero(
      right - left - bl.length() - (tailptr ? tailptr->length() : 0));
    if (tailptr) {
      bl.append(*tailptr);
    }
    assert(bl.length() % block_size == 0);
    assert(bl.length() == (right - left));
    return {{left, bl}};
  } else {
    // reserved section between ends, headptr and tailptr in different extents
    extent_to_write_list_t ret;
    if (headptr) {
      bufferlist headbl;
      headbl.append(*headptr);
      headbl.append_zero(zero_left - left - headbl.length());
      assert(headbl.length() % block_size == 0);
      assert(headbl.length() > 0);
      ret.emplace_back(left, headbl);
    }
    // reserved zero region
    ret.emplace_back(zero_left, zero_right - zero_left);
    assert(ret.back().len % block_size == 0);
    assert(ret.back().len > 0);
    if (tailptr) {
      bufferlist tailbl;
      tailbl.append(*tailptr);
      tailbl.append_zero(right - zero_right - tailbl.length());
      assert(tailbl.length() % block_size == 0);
      assert(tailbl.length() > 0);
      ret.emplace_back(zero_right, tailbl);
    }
    return ret;
  }
}

/**
 * get_buffers
 *
 * Returns extent_to_write_t's from bl.
 *
 * TODO: probably add some kind of upper limit on extent size.
 */
extent_to_write_list_t get_buffers(laddr_t offset, bufferlist &bl)
{
  auto ret = extent_to_write_list_t();
  ret.emplace_back(offset, bl);
  return ret;
};

ObjectDataHandler::write_ret ObjectDataHandler::overwrite(
  context_t ctx,
  laddr_t _offset,
  extent_len_t len,
  std::optional<bufferlist> &&bl,
  lba_pin_list_t &&_pins)
{
  if (bl) {
    assert(bl->length() == len);
  }
  auto overwrite_plan =
    generate_overwrite_plan(_offset, len, _pins, ctx.tm.get_block_size());
  return seastar::do_with(
    _offset,
    std::move(bl),
    std::optional<bufferptr>(),
    std::move(_pins),
    extent_to_write_list_t(),
    overwrite_plan,
    [ctx, len](laddr_t &offset, auto &bl, auto &headptr,
	       auto &pins, auto &to_write, auto &overwrite_plan) {
      LOG_PREFIX(ObjectDataHandler::overwrite);
      DEBUGT("overwrite: {}~{}",
	     ctx.t,
	     offset,
	     len);
      ceph_assert(pins.size() >= 1);
      DEBUGT("overwrite: split overwrite_plan {}", ctx.t, overwrite_plan);

      return split_pin_left(
	ctx,
	pins.front(),
	overwrite_plan
      ).si_then([ctx, &headptr, &pins, &to_write, &overwrite_plan](
		 auto p) {
	auto &[left_extent, _headptr] = p;
	if (left_extent) {
	  ceph_assert(left_extent->addr == overwrite_plan.pin_begin);
	  append_extent_to_write(to_write, std::move(*left_extent));
	}
	if (_headptr) {
	  assert(_headptr->length() > 0);
	  headptr = std::move(_headptr);
	}
	return split_pin_right(
	  ctx,
	  pins.back(),
	  overwrite_plan);
      }).si_then([ctx, len, &offset, &bl, &headptr, &to_write,
		  &overwrite_plan](auto p) {
	auto &[right_extent, tailptr] = p;
	if (bl) {
	  bufferlist write_bl;
	  if (headptr) {
	    write_bl.append(*headptr);
	    offset -= headptr->length();
	    assert_aligned(offset);
	  }
	  write_bl.claim_append(*bl);
	  if (tailptr) {
	    write_bl.append(*tailptr);
	    assert_aligned(write_bl.length());
	  }
	  splice_extent_to_write(to_write, get_buffers(offset, write_bl));
	} else {
	  splice_extent_to_write(
	    to_write,
	    get_zero_buffers(
	      ctx.tm.get_block_size(),
	      offset,
	      len,
	      std::move(headptr),
	      std::move(tailptr)));
	}
	if (right_extent) {
	  ceph_assert((right_extent->addr  + right_extent->len) ==
		      overwrite_plan.pin_end);
	  append_extent_to_write(to_write, std::move(*right_extent));
	}
	assert(to_write.size());
	assert(overwrite_plan.pin_begin == to_write.front().addr);
	assert(overwrite_plan.pin_end ==
	       (to_write.back().addr + to_write.back().len));
	return write_iertr::now();
      }).si_then([ctx, &pins] {
	return do_removals(ctx, pins);
      }).si_then([ctx, &to_write] {
	return do_insertions(ctx, to_write);
      });
    });
}

ObjectDataHandler::zero_ret ObjectDataHandler::zero(
  context_t ctx,
  objaddr_t offset,
  extent_len_t len)
{
  return with_object_data(
    ctx,
    [this, ctx, offset, len](auto &object_data) {
      LOG_PREFIX(ObjectDataHandler::zero);
      DEBUGT("zero to {}~{}, object_data: {}~{}, is_null {}",
             ctx.t,
             offset,
             len,
             object_data.get_reserved_data_base(),
             object_data.get_reserved_data_len(),
             object_data.is_null());
      return prepare_data_reservation(
	ctx,
	object_data,
	p2roundup(offset + len, ctx.tm.get_block_size())
      ).si_then([this, ctx, offset, len, &object_data] {
	auto logical_offset = object_data.get_reserved_data_base() + offset;
	return ctx.tm.get_pins(
	  ctx.t,
	  logical_offset,
	  len
	).si_then([this, ctx, logical_offset, len](auto pins) {
	  return overwrite(
	    ctx, logical_offset, len,
	    std::nullopt, std::move(pins));
	});
      });
    });
}

ObjectDataHandler::write_ret ObjectDataHandler::write(
  context_t ctx,
  objaddr_t offset,
  const bufferlist &bl)
{
  return with_object_data(
    ctx,
    [this, ctx, offset, &bl](auto &object_data) {
      LOG_PREFIX(ObjectDataHandler::write);
      DEBUGT("writing to {}~{}, object_data: {}~{}, is_null {}",
             ctx.t,
             offset,
	     bl.length(),
	     object_data.get_reserved_data_base(),
	     object_data.get_reserved_data_len(),
             object_data.is_null());
      return prepare_data_reservation(
	ctx,
	object_data,
	p2roundup(offset + bl.length(), ctx.tm.get_block_size())
      ).si_then([this, ctx, offset, &object_data, &bl] {
	auto logical_offset = object_data.get_reserved_data_base() + offset;
	return ctx.tm.get_pins(
	  ctx.t,
	  logical_offset,
	  bl.length()
	).si_then([this, ctx,logical_offset, &bl](
		   auto pins) {
	  ceph_assert(!pins.empty());
	  return overwrite(
	    ctx, logical_offset, bl.length(),
	    bufferlist(bl), std::move(pins));
	});
      });
    });
}

ObjectDataHandler::read_ret ObjectDataHandler::read(
  context_t ctx,
  objaddr_t obj_offset,
  extent_len_t len)
{
  return seastar::do_with(
    bufferlist(),
    [ctx, obj_offset, len](auto &ret) {
      return with_object_data(
	ctx,
	[ctx, obj_offset, len, &ret](const auto &object_data) {
	  LOG_PREFIX(ObjectDataHandler::read);
	  DEBUGT("reading {}~{}",
		 ctx.t,
		 object_data.get_reserved_data_base(),
		 object_data.get_reserved_data_len());
	  /* Assumption: callers ensure that onode size is <= reserved
	   * size and that len is adjusted here prior to call */
	  ceph_assert(!object_data.is_null());
	  ceph_assert((obj_offset + len) <= object_data.get_reserved_data_len());
	  ceph_assert(len > 0);
	  laddr_t loffset =
	    object_data.get_reserved_data_base() + obj_offset;
	  return ctx.tm.get_pins(
	    ctx.t,
	    loffset,
	    len
	  ).si_then([ctx, loffset, len, &ret](auto _pins) {
	    // offset~len falls within reserved region and len > 0
	    ceph_assert(_pins.size() >= 1);
	    ceph_assert((*_pins.begin())->get_key() <= loffset);
	    return seastar::do_with(
	      std::move(_pins),
	      loffset,
	      [ctx, loffset, len, &ret](auto &pins, auto &current) {
		return trans_intr::do_for_each(
		  pins,
		  [ctx, loffset, len, &current, &ret](auto &pin)
		  -> read_iertr::future<> {
		    ceph_assert(current <= (loffset + len));
		    ceph_assert(
		      (loffset + len) > pin->get_key());
		    laddr_t end = std::min(
		      pin->get_key() + pin->get_length(),
		      loffset + len);
		    if (pin->get_val().is_zero()) {
		      ceph_assert(end > current); // See LBAManager::get_mappings
		      ret.append_zero(end - current);
		      current = end;
		      return seastar::now();
		    } else {
		      return ctx.tm.pin_to_extent<ObjectDataBlock>(
			ctx.t,
			std::move(pin)
		      ).si_then([&ret, &current, end](auto extent) {
			ceph_assert(
			  (extent->get_laddr() + extent->get_length()) >= end);
			ceph_assert(end > current);
			ret.append(
			  bufferptr(
			    extent->get_bptr(),
			    current - extent->get_laddr(),
			    end - current));
			current = end;
			return seastar::now();
		      }).handle_error_interruptible(
			read_iertr::pass_further{},
			crimson::ct_error::assert_all{
			  "ObjectDataHandler::read hit invalid error"
			}
		      );
		    }
		  });
	      });
	  });
	}).si_then([&ret] {
	  return std::move(ret);
	});
    });
}

ObjectDataHandler::fiemap_ret ObjectDataHandler::fiemap(
  context_t ctx,
  objaddr_t obj_offset,
  extent_len_t len)
{
  return seastar::do_with(
    std::map<uint64_t, uint64_t>(),
    [ctx, obj_offset, len](auto &ret) {
    return with_object_data(
      ctx,
      [ctx, obj_offset, len, &ret](const auto &object_data) {
      LOG_PREFIX(ObjectDataHandler::fiemap);
      DEBUGT(
	"{}~{}, reservation {}~{}",
        ctx.t,
        obj_offset,
        len,
        object_data.get_reserved_data_base(),
        object_data.get_reserved_data_len());
      /* Assumption: callers ensure that onode size is <= reserved
       * size and that len is adjusted here prior to call */
      ceph_assert(!object_data.is_null());
      ceph_assert((obj_offset + len) <= object_data.get_reserved_data_len());
      ceph_assert(len > 0);
      laddr_t loffset =
        object_data.get_reserved_data_base() + obj_offset;
      return ctx.tm.get_pins(
        ctx.t,
        loffset,
        len
      ).si_then([loffset, len, &object_data, &ret](auto &&pins) {
	ceph_assert(pins.size() >= 1);
        ceph_assert((*pins.begin())->get_key() <= loffset);
	for (auto &&i: pins) {
	  if (!(i->get_val().is_zero())) {
	    auto ret_left = std::max(i->get_key(), loffset);
	    auto ret_right = std::min(
	      i->get_key() + i->get_length(),
	      loffset + len);
	    assert(ret_right > ret_left);
	    ret.emplace(
	      std::make_pair(
		ret_left - object_data.get_reserved_data_base(),
		ret_right - ret_left
	      ));
	  }
	}
      });
    }).si_then([&ret] {
      return std::move(ret);
    });
  });
}

ObjectDataHandler::truncate_ret ObjectDataHandler::truncate(
  context_t ctx,
  objaddr_t offset)
{
  return with_object_data(
    ctx,
    [this, ctx, offset](auto &object_data) {
      LOG_PREFIX(ObjectDataHandler::truncate);
      DEBUGT("truncating {}~{} offset: {}",
	     ctx.t,
	     object_data.get_reserved_data_base(),
	     object_data.get_reserved_data_len(),
	     offset);
      if (offset < object_data.get_reserved_data_len()) {
	return trim_data_reservation(ctx, object_data, offset);
      } else if (offset > object_data.get_reserved_data_len()) {
	return prepare_data_reservation(
	  ctx,
	  object_data,
	  p2roundup(offset, ctx.tm.get_block_size()));
      } else {
	return truncate_iertr::now();
      }
    });
}

ObjectDataHandler::clear_ret ObjectDataHandler::clear(
  context_t ctx)
{
  return with_object_data(
    ctx,
    [this, ctx](auto &object_data) {
      LOG_PREFIX(ObjectDataHandler::clear);
      DEBUGT("clearing: {}~{}",
	     ctx.t,
	     object_data.get_reserved_data_base(),
	     object_data.get_reserved_data_len());
      return trim_data_reservation(ctx, object_data, 0);
    });
}

}
