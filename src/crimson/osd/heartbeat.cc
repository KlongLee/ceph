#include "heartbeat.h"

#include <boost/range/join.hpp>

#include "messages/MOSDPing.h"
#include "messages/MOSDFailure.h"

#include "crimson/common/config_proxy.h"
#include "crimson/net/Connection.h"
#include "crimson/net/SocketMessenger.h"
#include "crimson/osd/osdmap_service.h"
#include "crimson/mon/MonClient.h"

#include "osd/OSDMap.h"

using ceph::common::local_conf;

namespace {
  seastar::logger& logger() {
    return ceph::get_logger(ceph_subsys_osd);
  }

  template<typename Message, typename... Args>
  Ref<Message> make_message(Args&&... args)
  {
    return {new Message{std::forward<Args>(args)...}, false};
  }
}

Heartbeat::Heartbeat(int whoami,
                     uint32_t nonce,
                     const OSDMapService& service,
                     ceph::mon::Client& monc)
  : front_msgr{new ceph::net::SocketMessenger{entity_name_t::OSD(whoami),
                                              "hb_front", nonce}},
    back_msgr{new ceph::net::SocketMessenger{entity_name_t::OSD(whoami),
                                             "hb_back", nonce}},
    service{service},
    monc{monc},
    timer{[this] {send_heartbeats();}}
{}

seastar::future<> Heartbeat::start(entity_addrvec_t front_addrs,
                                   entity_addrvec_t back_addrs)
{
  logger().info("heartbeat: start");
  // i only care about the address, so any unused port would work
  for (auto& addr : boost::join(front_addrs.v, back_addrs.v)) {
    addr.set_port(0);
  }
  front_msgr->try_bind(front_addrs,
                       local_conf()->ms_bind_port_min,
                       local_conf()->ms_bind_port_max);
  back_msgr->try_bind(front_addrs,
                      local_conf()->ms_bind_port_min,
                      local_conf()->ms_bind_port_max);
  return seastar::when_all_succeed(front_msgr->start(this),
                                   back_msgr->start(this)).then([this] {
    timer.arm_periodic(
      std::chrono::seconds(local_conf()->osd_heartbeat_interval));
  });
}

seastar::future<> Heartbeat::stop()
{
  return seastar::when_all_succeed(front_msgr->shutdown(),
                                   back_msgr->shutdown());
}

const entity_addrvec_t& Heartbeat::get_front_addrs() const
{
  return front_msgr->get_myaddrs();
}

const entity_addrvec_t& Heartbeat::get_back_addrs() const
{
  return back_msgr->get_myaddrs();
}

void Heartbeat::add_peer(osd_id_t peer)
{
  auto found = peers.find(peer);
  if (found == peers.end()) {
    logger().info("add_peer({})", peer);
    PeerInfo info;
    auto osdmap = service.get_map();
    // TODO: msgr v2
    info.con_front =
      front_msgr->connect(osdmap->get_hb_front_addrs(peer).legacy_addr(),
                          CEPH_ENTITY_TYPE_OSD);
    info.con_back =
      back_msgr->connect(osdmap->get_hb_back_addrs(peer).legacy_addr(),
                         CEPH_ENTITY_TYPE_OSD);
    peers.emplace(peer, std::move(info));
  }
}

seastar::future<> Heartbeat::remove_peer(osd_id_t peer)
{
  auto found = peers.find(peer);
  assert(found != peers.end());
  logger().info("remove_peer({})", peer);
  return seastar::when_all_succeed(found->second.con_front->close(),
                                   found->second.con_back->close()).then(
    [this, peer] {
      peers.erase(peer);
      return seastar::now();
    });
}

seastar::future<> Heartbeat::ms_dispatch(ceph::net::ConnectionRef conn,
                                         MessageRef m)
{
  logger().info("heartbeat: ms_dispatch {}", *m);
  switch (m->get_type()) {
  case CEPH_MSG_PING:
    return handle_osd_ping(conn, boost::static_pointer_cast<MOSDPing>(m));
  default:
    return seastar::now();
  }
}

seastar::future<> Heartbeat::handle_osd_ping(ceph::net::ConnectionRef conn,
                                             Ref<MOSDPing> m)
{
  switch (m->op) {
  case MOSDPing::PING:
    return handle_ping(conn, m);
  case MOSDPing::PING_REPLY:
    return handle_reply(conn, m);
  case MOSDPing::YOU_DIED:
    return handle_you_died();
  default:
    return seastar::now();
  }
}

seastar::future<> Heartbeat::handle_ping(ceph::net::ConnectionRef conn,
                                         Ref<MOSDPing> m)
{
  auto min_message = static_cast<uint32_t>(
    local_conf()->osd_heartbeat_min_size);
  auto reply =
    make_message<MOSDPing>(m->fsid,
                           service.get_map()->get_epoch(),
                           MOSDPing::PING_REPLY,
                           m->stamp,
                           min_message);
  return conn->send(reply);
}

seastar::future<> Heartbeat::handle_reply(ceph::net::ConnectionRef conn,
                                          Ref<MOSDPing> m)
{
  const osd_id_t from = m->get_source().num();
  auto found = peers.find(from);
  if (found == peers.end()) {
    // stale reply
    return seastar::now();
  }
  auto& peer = found->second;
  auto ping = peer.ping_history.find(m->stamp);
  if (ping == peer.ping_history.end()) {
    // old replies, deprecated by newly sent pings.
    return seastar::now();
  }
  const auto now = clock::now();
  auto& unacked = ping->second.unacknowledged;
  if (conn == peer.con_back) {
    peer.last_rx_back = now;
    unacked--;
  } else if (conn == peer.con_front) {
    peer.last_rx_front = now;
    unacked--;
  }
  if (unacked == 0) {
    peer.ping_history.erase(peer.ping_history.begin(), ++ping);
  }
  if (peer.is_healthy(now)) {
    // cancel false reports
    failure_queue.erase(from);
    if (auto pending = failure_pending.find(from);
        pending != failure_pending.end()) {
      return send_still_alive(from, pending->second.addrs);
    }
  }
  return seastar::now();
}

seastar::future<> Heartbeat::handle_you_died()
{
  // TODO: ask for newer osdmap
  return seastar::now();
}

seastar::future<> Heartbeat::send_heartbeats()
{
  using peers_item_t = typename peers_map_t::value_type;
  return seastar::parallel_for_each(peers,
    [this](peers_item_t& item) {
      const auto now = clock::now();
      const auto deadline =
        now + std::chrono::seconds(local_conf()->osd_heartbeat_grace);
      auto& [peer, info] = item;
      info.last_tx = now;
      if (clock::is_zero(info.first_tx)) {
        info.first_tx = now;
      }
      const utime_t sent_stamp{now};
      auto [reply, added] = info.ping_history.emplace(sent_stamp,
                                                      reply_t{deadline, 0});
      std::vector<ceph::net::ConnectionRef> conns{info.con_front,
                                                  info.con_back};
      return seastar::parallel_for_each(std::move(conns),
        [=] (auto con) {
          if (con) {
            auto min_message = static_cast<uint32_t>(
              local_conf()->osd_heartbeat_min_size);
            auto ping = make_message<MOSDPing>(monc.get_fsid(),
                                               service.get_map()->get_epoch(),
                                               MOSDPing::PING,
                                               sent_stamp,
                                               min_message);
            return con->send(ping).then([&reply] {
              reply->second.unacknowledged++;
              return seastar::now();
            });
          } else {
            return seastar::now();
          }
        });
    });
}

seastar::future<> Heartbeat::send_failures()
{
  using failure_item_t = typename failure_queue_t::value_type;
  return seastar::parallel_for_each(failure_queue,
    [this](failure_item_t& failure_item) {
      auto [osd, failed_since] = failure_item;
      if (failure_pending.count(osd)) {
        return seastar::now();
      }
      auto failed_for = chrono::duration_cast<chrono::seconds>(
        clock::now() - failed_since).count();
      auto osdmap = service.get_map();
      auto failure_report =
        make_message<MOSDFailure>(monc.get_fsid(),
                                  osd,
                                  osdmap->get_addrs(osd),
                                  static_cast<int>(failed_for),
                                  osdmap->get_epoch());
      failure_pending.emplace(osd, failure_info_t{failed_since,
                                                  osdmap->get_addrs(osd)});
      return monc.send_message(failure_report);
    }).then([this] {
      failure_queue.clear();
      return seastar::now();
    });
}

seastar::future<> Heartbeat::send_still_alive(osd_id_t osd,
                                              const entity_addrvec_t& addrs)
{
  auto still_alive = make_message<MOSDFailure>(monc.get_fsid(),
                                               osd,
                                               addrs,
                                               0,
                                               service.get_map()->get_epoch(),
                                               MOSDFailure::FLAG_ALIVE);
  return monc.send_message(still_alive).then([=] {
    failure_pending.erase(osd);
    return seastar::now();
  });
}

bool Heartbeat::PeerInfo::is_unhealthy(clock::time_point now) const
{
  if (ping_history.empty()) {
    // we haven't sent a ping yet or we have got all replies,
    // in either way we are safe and healthy for now
    return false;
  } else {
    auto oldest_ping = ping_history.begin();
    return now > oldest_ping->second.deadline;
  }
}

bool Heartbeat::PeerInfo::is_healthy(clock::time_point now) const
{
  if (con_front && clock::is_zero(last_rx_front)) {
    return false;
  }
  if (con_back && clock::is_zero(last_rx_back)) {
    return false;
  }
  // only declare to be healthy until we have received the first
  // replies from both front/back connections
  return !is_unhealthy(now);
}
