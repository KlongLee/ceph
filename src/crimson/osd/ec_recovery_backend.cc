// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 smarttab expandtab

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <seastar/core/future.hh>
#include <seastar/core/do_with.hh>

#include "crimson/osd/ec_backend.h"
#include "crimson/osd/ec_recovery_backend.h"
#include "crimson/osd/pg.h"
#include "crimson/osd/pg_backend.h"
#include "messages/MOSDPGPush.h"
#include "messages/MOSDPGPushReply.h"
#include "msg/Message.h"
#include "osd/osd_types_fmt.h"

namespace {
  seastar::logger& logger() {
    return crimson::get_logger(ceph_subsys_osd);
  }
}

ECRecoveryBackend::ECRecoveryBackend(
  crimson::osd::PG& pg,
  crimson::osd::ShardServices& shard_services,
  crimson::os::CollectionRef coll,
  ECBackend* backend)
: ::RecoveryBackend(pg, shard_services, coll, backend),
  ::ECCommon::RecoveryBackend(
    shard_services.get_cct(),
    coll->get_cid(),
    backend->ec_impl,
    backend->sinfo,
    backend->read_pipeline,
    backend->unstable_hashinfo_registry,
    &pg)
{}

RecoveryBackend::interruptible_future<>
ECRecoveryBackend::recover_object(
  const hobject_t& soid,
  eversion_t need)
{
  logger().debug("{}: {}, {}", __func__, soid, need);
  // always add_recovering(soid) before recover_object(soid)
  assert(is_recovering(soid));
  return pg.obc_loader.with_obc<RWState::RWREAD>(soid,
    [this, soid, need](auto head, auto obc) {
    logger().debug("recover_object: loaded obc: {}", obc->obs.oi.soid);
    auto& recovery_waiter = get_recovering(soid);
    recovery_waiter.obc = obc;
    recovery_waiter.obc->wait_recovery_read();
    //logger().info("{}: starting {}", __func__, rop);
    assert(!recovery_ops.count(soid));
    recovery_ops[soid] =
      ECCommon::RecoveryBackend::recover_object(soid, need, head, obc);
    assert(soid == recovery_ops[soid].hoid);
    RecoveryMessages m;
    continue_recovery_op(recovery_ops[soid], &m);
    dispatch_recovery_messages(m, 0/* FIXME: priority */);
    return seastar::now();
  }).handle_error_interruptible(
    crimson::osd::PG::load_obc_ertr::all_same_way([soid](auto& code) {
    // TODO: may need eio handling?
    logger().error("recover_object saw error code {}, ignoring object {}",
                   code, soid);
    return seastar::now();
  }));
}

void ECRecoveryBackend::commit_txn_send_replies(
  ceph::os::Transaction&& txn,
  std::map<int, MOSDPGPushReply*> replies)
{
  std::ignore = shard_services.get_store().do_transaction(
    ::RecoveryBackend::coll, std::move(txn)
  ).then([replies=std::move(replies), this]() mutable {
    if (auto msgit = replies.find(get_parent()->whoami_shard().osd);
        msgit != std::end(replies)) {
      std::ignore = handle_push_reply(Ref<MOSDPGPushReply>{msgit->second});
      replies.erase(msgit);
    }
    return seastar::do_for_each(replies, [this] (auto&& kv) {
      auto [osd, msg] = kv;
      return pg.get_shard_services().send_to_osd(
        osd,
        MessageURef{msg},
        pg.get_osdmap_epoch());
    });
  });
}

void ECRecoveryBackend::maybe_load_obc(
  const std::map<std::string, ceph::bufferlist, std::less<>>& raw_attrs,
  RecoveryOp &op)
{
  logger().debug("{}", __func__);
  ceph_assert(op.obc);
  // attrs only reference the origin bufferlist (decode from
  // ECSubReadReply message) whose size is much greater than attrs
  // in recovery. If obc cache it (get_obc maybe cache the attr),
  // this causes the whole origin bufferlist would not be free
  // until obc is evicted from obc cache. So rebuild the
  // bufferlist before cache it.
  for (std::map<std::string, ceph::bufferlist>::iterator it = op.xattrs.begin();
       it != op.xattrs.end();
       ++it) {
    it->second.rebuild();
  }
  // Need to remove ECUtil::get_hinfo_key() since it should not leak out
  // of the backend (see bug #12983)
  std::map<std::string, ceph::bufferlist, std::less<>> sanitized_attrs(op.xattrs);
  sanitized_attrs.erase(ECUtil::get_hinfo_key());
  //op.obc = get_parent()->get_obc(hoid, sanitized_attrs);

  op.obc->obs.oi.decode(op.xattrs.at(OI_ATTR));
  ceph_assert(op.obc->obs.oi.soid == op.hoid);

  auto ss_attr_iter = op.xattrs.find(SS_ATTR);
  if (ss_attr_iter != op.xattrs.end()) {
    if (!op.obc->ssc) {
      op.obc->ssc = new crimson::osd::SnapSetContext(
        op.hoid.get_snapdir());
    }
    try {
      op.obc->ssc->snapset = SnapSet(ss_attr_iter->second);
      op.obc->ssc->exists = true;
    } catch (const buffer::error&) {
      logger().warn("unable to decode SnapSet");
      ceph_abort_msg("undecodable SnapSet during recovery");
    }
  }
#if 0
  pull_info.recovery_info.oi = obc->obs.oi;
  if (pull_info.recovery_info.soid.snap &&
      pull_info.recovery_info.soid.snap < CEPH_NOSNAP) {
      recalc_subsets(pull_info.recovery_info,
                     pull_info.obc->ssc);
  }
  return crimson::osd::PG::load_obc_ertr::now();
#endif

  op.recovery_info.size = op.obc->obs.oi.size;
  op.recovery_info.oi = op.obc->obs.oi;
  ceph_assert(op.obc->is_loaded_and_valid());
  logger().debug("{}: filled obc. oi.size={}", __func__, op.obc->obs.oi.size);
}

RecoveryBackend::interruptible_future<>
ECRecoveryBackend::handle_push(
  Ref<MOSDPGPush> m)
{
  logger().debug("{}: {}", __func__, *m);
  RecoveryMessages rm;
  for (const auto& push_op : m->pushes) {
    handle_recovery_push(push_op, &rm, m->is_repair);
  }
  dispatch_recovery_messages(rm, m->get_priority());
  return seastar::now();
}

RecoveryBackend::interruptible_future<>
ECRecoveryBackend::handle_push_reply(
  Ref<MOSDPGPushReply> m)
{
  logger().debug("{}: {}", __func__, *m);
  RecoveryMessages rm;
  for (const auto& push_reply_op : m->replies) {
    handle_recovery_push_reply(push_reply_op, m->from, &rm);
  }
  dispatch_recovery_messages(rm, m->get_priority());
  return seastar::now();
}

RecoveryBackend::interruptible_future<>
ECRecoveryBackend::handle_recovery_op(
  Ref<MOSDFastDispatchOp> m,
  crimson::net::ConnectionXcoreRef conn)
{
  switch (m->get_header().type) {
  case MSG_OSD_PG_PUSH:
    return handle_push(boost::static_pointer_cast<MOSDPGPush>(m));
  case MSG_OSD_PG_PUSH_REPLY:
    return handle_push_reply(
      boost::static_pointer_cast<MOSDPGPushReply>(m));
  default:
    // delegate to parent class for handling backend-agnostic recovery ops.
    return ::RecoveryBackend::handle_recovery_op(std::move(m), conn);
  }
}
