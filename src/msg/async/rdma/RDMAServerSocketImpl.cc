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

#include "msg/async/net_handler.h"
#include "RDMAStack.h"
#include "Device.h"
#include "RDMAConnTCP.h"
#include "RDMAConnCM.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix *_dout << " RDMAServerSocketImpl "

RDMAServerSocketImpl *RDMAServerSocketImpl::factory(CephContext *cct,
						    Infiniband *ib,
						    RDMADispatcher *s,
						    RDMAWorker *w,
						    entity_addr_t& a)
{
  if (cct->_conf->ms_async_rdma_cm)
    return new RDMAServerConnCM(cct, ib, s, w, a);

  return new RDMAServerConnTCP(cct, ib, s, w, a);
}

RDMAServerSocketImpl::RDMAServerSocketImpl(CephContext *cct, Infiniband* i, RDMADispatcher *s, RDMAWorker *w, entity_addr_t& a)
  : cct(cct), infiniband(i), dispatcher(s), worker(w), sa(a)
{
}

RDMAServerConnTCP::RDMAServerConnTCP(CephContext *cct, Infiniband* i, RDMADispatcher *s, RDMAWorker *w, entity_addr_t& a)
  : RDMAServerSocketImpl(cct, i, s, w, a), net(cct), server_setup_socket(-1)
{
  ibdev = infiniband->get_device(cct->_conf->ms_async_rdma_device_name.c_str());
  ibport = cct->_conf->ms_async_rdma_port_num;

  assert(ibdev);
  assert(ibport > 0);

  ibdev->init(ibport);
}

int RDMAServerConnTCP::listen(entity_addr_t &sa, const SocketOptions &opt)
{
  int rc = 0;
  ldout(cct, 1) << __func__ << ":" << __LINE__ << " thread: " << pthread_self() << dendl;
  server_setup_socket = net.create_socket(sa.get_family(), true);
  if (server_setup_socket < 0) {
    rc = -errno;
    lderr(cct) << __func__ << " failed to create server socket: "
               << cpp_strerror(errno) << dendl;
    return rc;
  }

  rc = net.set_nonblock(server_setup_socket);
  if (rc < 0) {
    goto err;
  }

  rc = net.set_socket_options(server_setup_socket, opt.nodelay, opt.rcbuf_size);
  if (rc < 0) {
    goto err;
  }
  net.set_close_on_exec(server_setup_socket);

  rc = ::bind(server_setup_socket, sa.get_sockaddr(), sa.get_sockaddr_len());
  if (rc < 0) {
    rc = -errno;
    ldout(cct, 10) << __func__ << " unable to bind to " << sa.get_sockaddr()
                   << " on port " << sa.get_port() << ": " << cpp_strerror(errno) << dendl;
    goto err;
  }

  rc = ::listen(server_setup_socket, 128);
  if (rc < 0) {
    rc = -errno;
    lderr(cct) << __func__ << " unable to listen on " << sa << ": " << cpp_strerror(errno) << dendl;
    goto err;
  }

  ldout(cct, 20) << __func__ << " bind to " << sa.get_sockaddr() << " on port " << sa.get_port()  << dendl;
  return 0;

err:
  ::close(server_setup_socket);
  server_setup_socket = -1;
  return -errno;
}

int RDMAServerConnTCP::accept(ConnectedSocket *sock, const SocketOptions &opt, entity_addr_t *out, Worker *w)
{
  ldout(cct, 15) << __func__ << dendl;
  ldout(cct, 1) << __func__ << ":" << __LINE__ << " thread: " << pthread_self() << dendl;

  assert(sock);
  sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  int sd = ::accept(server_setup_socket, (sockaddr*)&ss, &slen);
  if (sd < 0) {
    return -errno;
  }

  net.set_close_on_exec(sd);
  int r = net.set_nonblock(sd);
  if (r < 0) {
    ::close(sd);
    return -errno;
  }

  r = net.set_socket_options(sd, opt.nodelay, opt.rcbuf_size);
  if (r < 0) {
    ::close(sd);
    return -errno;
  }

  assert(NULL != out); //out should not be NULL in accept connection

  out->set_sockaddr((sockaddr*)&ss);
  net.set_priority(sd, opt.priority, out->get_family());

  RDMAConnTCP* server;
  //Worker* w = dispatcher->get_stack()->get_worker();
  server = new RDMAConnTCP(cct, infiniband, dispatcher, dynamic_cast<RDMAWorker*>(w));
  server->set_accept_fd(sd);
  ldout(cct, 1) << __func__ << ":" << __LINE__ << " thread: " << pthread_self() << dendl;
  ldout(cct, 20) << __func__ << " accepted a new QP, tcp_fd: " << sd << dendl;
  std::unique_ptr<RDMAConnectedSocketImpl> csi(server);
  *sock = ConnectedSocket(std::move(csi));

  return 0;
}

void RDMAServerConnTCP::abort_accept()
{
  if (server_setup_socket >= 0)
    ::close(server_setup_socket);
}
