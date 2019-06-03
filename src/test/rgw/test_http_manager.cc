// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2015 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */
#include "rgw/rgw_rados.h"
#include "rgw/rgw_http_client.h"
#include "rgw/rgw_http_client_curl.h"
#include "global/global_init.h"
#include "common/ceph_argparse.h"
#include <curl/curl.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <thread>
#include <gtest/gtest.h>

TEST(HTTPManager, ReadTruncated)
{
  using tcp = boost::asio::ip::tcp;
  tcp::endpoint endpoint(tcp::v4(), 0);
  boost::asio::io_context ioctx;
  tcp::acceptor acceptor(ioctx);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint);
  acceptor.listen();

  std::thread server{[&] {
    tcp::socket socket{ioctx};
    acceptor.accept(socket);
    std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 1024\r\n"
        "\r\n"
        "short body";
    boost::asio::write(socket, boost::asio::buffer(response));
  }};
  const auto url = std::string{"http://127.0.0.1:"} + std::to_string(acceptor.local_endpoint().port());

  rgw::curl::setup_curl(boost::none);

  RGWHTTPClient client{g_ceph_context};
  EXPECT_EQ(-EINVAL, client.process("GET", url.c_str()));

  server.join();

  rgw::curl::cleanup_curl();
}

TEST(HTTPManager, SignalThread)
{
  auto cct = g_ceph_context;
  RGWHTTPManager http(cct);

  ASSERT_EQ(0, http.set_threaded());

  // default pipe buffer size according to man pipe
  constexpr size_t max_pipe_buffer_size = 65536;
  // each signal writes 4 bytes to the pipe
  constexpr size_t max_pipe_signals = max_pipe_buffer_size / sizeof(uint32_t);
  // add_request and unregister_request
  constexpr size_t pipe_signals_per_request = 2;
  // number of http requests to fill the pipe buffer
  constexpr size_t max_requests = max_pipe_signals / pipe_signals_per_request;

  // send one extra request to test that we don't deadlock
  constexpr size_t num_requests = max_requests + 1;

  for (size_t i = 0; i < num_requests; i++) {
    RGWHTTPClient client{cct};
    http.add_request(&client, "PUT", "http://127.0.0.1:80");
  }
}

int main(int argc, char** argv)
{
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
			 CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  curl_global_init(CURL_GLOBAL_ALL);
  ::testing::InitGoogleTest(&argc, argv);
  int r = RUN_ALL_TESTS();
  curl_global_cleanup();
  return r;
}
