// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <map>
#include <fmt/format.h>
#include <seastar/core/condition-variable.hh>
#include "crimson/osd/osd_operations/client_request.h"

namespace crimson::osd {

// when PG interval changes, we are supposed to interrupt all in-flight ops.
// but in the order in which the ops are interrupted are not determined
// because they are scheduled by the seastar scheduler, if we just interrupt
// them at seeing a different interval when moving to a new continuation. but
// we are supposed to replay the ops from the same client targeting the same
// PG in the exact order that they are received.
//
// the way how we address this problem is to set up a blocker which blocks an
// op until the preceding op is unblocked if the blocked one is issued in a new
// pg interval.
//
// here, the ops from the same client are grouped by PG, and then ordered by
// their id which is monotonically increasing and unique on per PG basis, so we
// can keep an op waiting in the case explained above.
class OpSequencer {
public:
  template <typename HandleT,
            typename FuncT,
            typename Result = std::invoke_result_t<FuncT>>
  seastar::futurize_t<Result>
  start_op(const ClientRequest& op,
           HandleT& handle,
           FuncT&& do_op) {
    const auto* const prev_op = &op.get_prev_op();
    auto have_green_light = seastar::make_ready_future<>();
    assert(prev_op->get_id() < op.get_id());
    if (last_issued == prev_op) {
      // starting a new op, let's advance the last_issued!
      last_issued = &op;
    }
    if (prev_op != last_unblocked) {
      // this implies that there are some blocked ops before me, so i have to
      // wait until they are unblocked.
      //
      // i should leave the current pipeline stage when waiting for the blocked
      // ones, so that the following ops can be queued up here. we cannot let
      // the seastar scheduler to determine the order of performing these ops,
      // once they are unblocked after the first op of the same pg interval is
      // scheduled.
      assert(prev_op->get_id() > last_unblocked->get_id());
      handle.exit();
      ::crimson::get_logger(ceph_subsys_osd).debug(
        "OpSequencer::start_op: {} waiting ({} > {})",
        op, prev_op->get_id(), last_unblocked->get_id());
      have_green_light = unblocked.wait([prev_op, this] {
        // wait until the previous op is unblocked
        return last_unblocked == prev_op;
      });
    }
    return have_green_light.then([&op, do_op=std::move(do_op), this]() mutable {
      auto result = seastar::futurize_invoke(std::move(do_op));
      // unblock the next one
      last_unblocked = &op;
      unblocked.broadcast();
      return result;
    });
  }
  const ClientRequest* get_last_issued() const {
    return last_issued;
  }
  void finish_op(const ClientRequest& op) {
    assert(op.get_id() > last_completed->get_id());
    last_completed = &op;
  }
  void maybe_reset(const ClientRequest& op) {
    const auto op_id = op.get_id();
    // pg interval changes, so we need to reenqueue the previously unblocked
    // ops by rewinding the "last_unblock" pointer
    if (op_id <= last_unblocked->get_id()) {
      ::crimson::get_logger(ceph_subsys_osd).debug(
        "OpSequencer::maybe_reset:{}  {} <= {}, resetting to {}",
        op, op_id, last_unblocked->get_id(), last_completed->get_id());
      last_unblocked = last_completed;
    }
  }
  void abort() {
    // all blocked ops should be canceled, likely due to the osd is not primary
    // anymore.
    unblocked.broken();
  }
private:
  //          /--- unblocked (in pg pipeline)
  //         |      /--- blocked
  //         V      V
  // |////|.....|.......| <--- last_issued
  //      ^     ^       ^
  //      |     |       \- prev_op
  //      |      \--- last_unblocked
  //      last_completed
  //
  // the id of last op which is issued
  const ClientRequest* last_issued = nullptr;
  // the id of last op which is unblocked
  const ClientRequest* last_unblocked = nullptr;
  // the id of last op which is completed
  const ClientRequest* last_completed = nullptr;
  seastar::condition_variable unblocked;

  friend fmt::formatter<OpSequencer>;
};


class OpSequencers {
public:
  OpSequencer& get(const spg_t& pgid) {
    return pg_ops.at(pgid);
  }
  OpSequencer& operator[](const spg_t& pgid) {
    // TODO: trim pg_ops if there are too many empty sequencers
    return pg_ops[pgid];
  }
private:
  std::map<spg_t, OpSequencer> pg_ops;
};
} // namespace crimson::osd

template <>
struct fmt::formatter<crimson::osd::OpSequencer> {
  // ignore the format string
  constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(const crimson::osd::OpSequencer& sequencer,
              FormatContext& ctx)
  {
    return fmt::format_to(ctx.out(),
                          "(last_completed={},last_unblocked={},last_issued={})",
                          sequencer.last_completed,
                          sequencer.last_unblocked,
                          sequencer.last_issued);
  }
};
