// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 XSky <haomai@xsky.com>
 *
 * Author: Haomai Wang <haomaiwang@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <gtest/gtest.h>

#include "acconfig.h"
#include "include/Context.h"
#include "common/ceph_argparse.h"
#include "global/global_init.h"

#include "msg/async/Event.h"
#include "msg/async/GenericSocket.h"

#if GTEST_HAS_PARAM_TEST

class TransportTest : public ::testing::TestWithParam<const char*> {
 public:
  EventCenter *center;
  std::unique_ptr<NetworkStack> transport;
  string addr;

  TransportTest() {}
  virtual void SetUp() {
    cerr << __func__ << " start set up " << GetParam() << std::endl;
    if (strncmp(GetParam(), "dpdk", 4)) {
      g_ceph_context->_conf->set_val("ms_dpdk_enable", "false");
      addr = "127.0.0.1:15000";
    } else {
      g_ceph_context->_conf->set_val("ms_dpdk_enable", "true");
      g_ceph_context->_conf->set_val("ms_dpdk_host_ipv4_addr", "172.16.218.199", false, false);
      g_ceph_context->_conf->set_val("ms_dpdk_gateway_ipv4_addr", "172.16.218.2", false, false);
      g_ceph_context->_conf->set_val("ms_dpdk_netmask_ipv4_addr", "255.255.255.0", false, false);
      addr = "172.16.218.199:15000";
    }
    g_ceph_context->_conf->apply_changes(nullptr);
    center = new EventCenter(g_ceph_context);
    center->init(1000);
    center->set_owner();
    transport = NetworkStack::create(g_ceph_context, GetParam(), center, 0);
    transport->initialize();
  }
  virtual void TearDown() {
    delete center;
    transport.reset();
  }
  string get_addr() const {
    return addr;
  }
};

class C_poll : public EventCallback {
  EventCenter *center;
  std::atomic<bool> wakeuped;
  static const int sleepus = 500;

 public:
  C_poll(EventCenter *c): center(c), wakeuped(false) {}
  void do_request(int r) {
    wakeuped = true;
  }
  void poll(int seconds) {
    while (!wakeuped)
      center->process_events(sleepus);
  }
};

TEST_P(TransportTest, SimpleTest) {
  entity_addr_t bind_addr, cli_addr;
  bind_addr.parse(get_addr().c_str());
  SocketOptions options;
  ServerSocket bind_socket;
  int r = transport->listen(bind_addr, options, &bind_socket);
  ASSERT_EQ(r, 0);
  ConnectedSocket cli_socket, srv_socket;
  r = transport->connect(bind_addr, options, &cli_socket);
  ASSERT_EQ(r, 0);

  {
    C_poll cb(center);
    center->create_file_event(bind_socket.fd(), EVENT_READABLE, &cb);
    cb.poll(5);
  }

  r = bind_socket.accept(&srv_socket, &cli_addr);
  ASSERT_EQ(r, 0);
  ASSERT_TRUE(srv_socket.fd() > 0);

  {
    C_poll cb(center);
    center->create_file_event(cli_socket.fd(), EVENT_READABLE, &cb);
    r = cli_socket.is_connected();
    if (r == 0) {
      cb.poll(5);
      r = cli_socket.is_connected();
    }
    ASSERT_EQ(r, 1);
  }

  struct msghdr msg;
  struct iovec msgvec[2];
  const char *message = "this is a new message";
  int len = strlen(message);
  memset(&msg, 0, sizeof(msg));
  msg.msg_iovlen = 1;
  msg.msg_iov = msgvec;
  msgvec[0].iov_base = (char*)message;
  msgvec[0].iov_len = len;
  r = cli_socket.sendmsg(msg, len, false);
  ASSERT_EQ(r, len);

  char buf[1024];
  {
    C_poll cb(center);
    center->create_file_event(srv_socket.fd(), EVENT_READABLE, &cb);
    r = srv_socket.read(buf, sizeof(buf));
    if (r == -EAGAIN) {
      cb.poll(5);
      r = srv_socket.read(buf, sizeof(buf));
    }
    ASSERT_EQ(r, len);
    ASSERT_EQ(0, memcmp(buf, message, len));
  }
}

INSTANTIATE_TEST_CASE_P(
  AsyncMessenger,
  TransportTest,
  ::testing::Values(
#ifdef HAVE_DPDK
    "dpdk",
#endif
    "posix"
  )
);

#else

// Google Test may not support value-parameterized tests with some
// compilers. If we use conditional compilation to compile out all
// code referring to the gtest_main library, MSVC linker will not link
// that library at all and consequently complain about missing entry
// point defined in that library (fatal error LNK1561: entry point
// must be defined). This dummy test keeps gtest_main linked in.
TEST(DummyTest, ValueParameterizedTestsAreNotSupportedOnThisPlatform) {}

#endif


int main(int argc, char **argv) {
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/*
 * Local Variables:
 * compile-command: "cd ../.. ; make ceph_test_async_transport &&
 *    ./ceph_test_async_transport
 *
 * End:
 */
