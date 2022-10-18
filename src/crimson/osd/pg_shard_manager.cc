// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "crimson/osd/pg_shard_manager.h"
#include "crimson/osd/pg.h"

namespace {
  seastar::logger& logger() {
    return crimson::get_logger(ceph_subsys_osd);
  }
}

namespace crimson::osd {

seastar::future<> PGShardManager::start(
  const int whoami,
  crimson::net::Messenger &cluster_msgr,
  crimson::net::Messenger &public_msgr,
  crimson::mon::Client &monc,
  crimson::mgr::Client &mgrc,
  seastar::sharded<ShardStores> &shard_stores)
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return osd_singleton_state.start_single(
    whoami, std::ref(cluster_msgr), std::ref(public_msgr),
    std::ref(monc), std::ref(mgrc)
  ).then([this, whoami, &shard_stores] {
    ceph::mono_time startup_time = ceph::mono_clock::now();
    return shard_services.start(
      std::ref(osd_singleton_state),
      whoami,
      startup_time,
      osd_singleton_state.local().perf,
      osd_singleton_state.local().recoverystate_perf,
      std::ref(shard_stores));
  });
}

seastar::future<> PGShardManager::stop()
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.stop(
  ).then([this] {
    return osd_singleton_state.stop();
  });
}

seastar::future<> PGShardManager::load_pgs()
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.invoke_on_all(
    [this](auto &local_service) {
    return local_service.load_pgs();
  });
}

seastar::future<> PGShardManager::stop_pgs()
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.invoke_on_all([](auto &local_service) {
    return local_service.local_state.stop_pgs();
  });
}

seastar::future<std::map<pg_t, pg_stat_t>>
PGShardManager::get_pg_stats() const
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.map_reduce0(
    [](auto &local) {
      return local.local_state.get_pg_stats();
    },
    std::map<pg_t, pg_stat_t>(),
    [](auto &&left, auto &&right) {
      left.merge(std::move(right));
      return std::move(left);
    });
}

seastar::future<> PGShardManager::broadcast_map_to_pgs(epoch_t epoch)
{
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.invoke_on_all([epoch](auto &local_service) {
    return local_service.local_state.broadcast_map_to_pgs(
      local_service, epoch
    );
  }).then([this, epoch] {
    get_osd_singleton_state().osdmap_gate.got_map(epoch);
    return seastar::now();
  });
}

seastar::future<> PGShardManager::set_up_epoch(epoch_t e) {
  ceph_assert(seastar::this_shard_id() == PRIMARY_CORE);
  return shard_services.invoke_on_all(
    seastar::smp_submit_to_options{},
    [e](auto &local_service) {
      local_service.local_state.set_up_epoch(e);
      return seastar::now();
    });
}

}
