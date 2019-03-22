// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "Protocol.h"

#include "auth/Auth.h"

#include "crimson/common/log.h"
#include "Socket.h"
#include "SocketConnection.h"

namespace {
  seastar::logger& logger() {
    return ceph::get_logger(ceph_subsys_ms);
  }
}

namespace ceph::net {

Protocol::Protocol(int type,
                   Dispatcher& dispatcher,
                   SocketConnection& conn,
                   SocketMessenger& messenger)
  : proto_type(type),
    dispatcher(dispatcher),
    conn(conn),
    messenger(messenger)
{
  auth_meta = seastar::make_lw_shared<AuthConnectionMeta>();
}

Protocol::~Protocol()
{
  ceph_assert(pending_dispatch.is_closed());
}

bool Protocol::is_connected() const
{
  return write_state == write_state_t::open;
}

seastar::future<> Protocol::close()
{
  if (closed) {
    // already closing
    assert(close_ready.valid());
    return close_ready.get_future();
  }

  // unregister_conn() drops a reference, so hold another until completion
  auto cleanup = [conn_ref = conn.shared_from_this(), this] {
      logger().debug("{} closed!", conn);
    };

  trigger_close();

  // close_ready become valid only after state is state_t::closing
  assert(!close_ready.valid());

  if (socket) {
    close_ready = socket->close()
      .then([this] {
        return pending_dispatch.close();
      }).finally(std::move(cleanup));
  } else {
    close_ready = pending_dispatch.close().finally(std::move(cleanup));
  }

  closed = true;
  set_write_state(write_state_t::drop);

  return close_ready.get_future();
}

seastar::future<> Protocol::send(MessageRef msg)
{
  if (write_state != write_state_t::drop) {
    conn.out_q.push(std::move(msg));
    write_event();
  }
  return seastar::now();
}

seastar::future<> Protocol::keepalive()
{
  if (!m_keepalive) {
    m_keepalive = true;
    write_event();
  }
  return seastar::now();
}

void Protocol::notify_keepalive_ack()
{
  if (!m_keepalive_ack) {
    m_keepalive_ack = true;
    write_event();
  }
}

void Protocol::write_event()
{
  if (write_dispatching) {
    // already dispatching
    return;
  }
  write_dispatching = true;
  switch (write_state) {
   case write_state_t::open:
   case write_state_t::delay:
    seastar::with_gate(pending_dispatch, [this] {
      return seastar::repeat([this] {
        switch (write_state) {
         case write_state_t::open:
          return seastar::futurize_apply([this] {
            if (m_keepalive) {
              return do_keepalive()
              .then([this] { m_keepalive = false; });
            }
            return seastar::now();
          }).then([this] {
            if (m_keepalive_ack) {
              return do_keepalive_ack()
              .then([this] { m_keepalive_ack = false; });
            }
            return seastar::now();
          }).then([this] {
            if (!conn.out_q.empty()){
              MessageRef msg = conn.out_q.front();
              return write_message(msg)
              .then([this, msg] {
                if (msg == conn.out_q.front()) {
                  conn.out_q.pop();
                }
                return stop_t::no;
              });
            } else {
              return socket->flush()
              .then([this] {
                if (!conn.out_q.empty()) {
                  return stop_t::no;
                } else {
                  write_dispatching = false;
                  return stop_t::yes;
                }
              });
            }
          }).handle_exception([this] (std::exception_ptr eptr) {
            logger().warn("{} write_event fault: {}", conn, eptr);
            close();
            return stop_t::no;
          });
         case write_state_t::delay:
          // delay dispatching writes until open
          return state_changed.get_shared_future()
          .then([] { return stop_t::no; });
         case write_state_t::drop:
          write_dispatching = false;
          return seastar::make_ready_future<stop_t>(stop_t::yes);
         default:
          ceph_assert(false);
        }
      });
    });
    return;
   case write_state_t::drop:
    write_dispatching = false;
   default:
    ceph_assert(false);
  }
}

} // namespace ceph::net
