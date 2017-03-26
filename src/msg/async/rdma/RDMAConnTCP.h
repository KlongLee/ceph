// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 XSKY <haomai@xsky.com>
 *
 * Author: Haomai Wang <haomaiwang@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef CEPH_MSG_RDMA_CONNECTED_SOCKET_TCP_H
#define CEPH_MSG_RDMA_CONNECTED_SOCKET_TCP_H

#include "common/ceph_context.h"
#include "common/debug.h"
#include "common/errno.h"
#include "msg/async/Stack.h"
#include "Infiniband.h"
#include "RDMAConnectedSocketImpl.h"

class RDMAWorker;
class RDMADispatcher;

class RDMAConnTCP : public RDMAConnectedSocketImpl {
  class C_handle_connection : public EventCallback {
    RDMAConnTCP *cst;
    bool active;
   public:
    C_handle_connection(RDMAConnTCP *w): cst(w), active(true) {};
    void do_request(int fd) {
      if (active)
        cst->handle_connection();
    };
    void close() {
      active = false;
    };
  };

  class Disconnector : public RDMADisconnector {
    QueuePair *qp;

  public:
    Disconnector(QueuePair *qp) : qp(qp) {};

    virtual void disconnect() { qp->to_dead(); };

    virtual ostream &print(ostream &o) {
      return o << "TCP FIN: { qpn: " << *qp << "}";
    }
  };

  IBSYNMsg peer_msg;
  IBSYNMsg my_msg;
  EventCallbackRef con_handler;
  int tcp_fd = -1;

private:
  void handle_connection();
  int send_msg(CephContext *cct, int sd, IBSYNMsg& msg);
  int recv_msg(CephContext *cct, int sd, IBSYNMsg& msg);
  void wire_gid_to_gid(const char *wgid, union ibv_gid *gid);
  void gid_to_wire_gid(const union ibv_gid *gid, char wgid[]);

public:
  RDMAConnTCP(CephContext *cct, Infiniband* ib, RDMADispatcher* s,
                         RDMAWorker *w);
  virtual ~RDMAConnTCP();

  void set_accept_fd(int sd);

  virtual void cleanup() override;
  virtual int try_connect(const entity_addr_t&, const SocketOptions &opt) override;
  virtual int remote_qpn()override { return peer_msg.qpn; };
  virtual void fin() override;
  virtual int activate() override;

  virtual ostream &print(ostream &o) override;
};

class RDMAServerConnTCP : public RDMAServerSocketImpl {
  NetHandler net;
  int server_setup_socket;

public:
  RDMAServerConnTCP(CephContext *cct, Infiniband* i, RDMADispatcher *s, RDMAWorker *w, entity_addr_t& a);

  int listen(entity_addr_t &sa, const SocketOptions &opt);
  virtual int accept(ConnectedSocket *s, const SocketOptions &opts, entity_addr_t *out, Worker *w) override;
  virtual void abort_accept() override;
  virtual int fd() const override { return server_setup_socket; }
};

#endif
