// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef RGW_ASIO_CLIENT_H
#define RGW_ASIO_CLIENT_H

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include "include/ceph_assert.h"

#include "rgw_client_io.h"

namespace rgw {
namespace asio {

namespace beast = boost::beast;
using parser_type = beast::http::request_parser<beast::http::buffer_body>;

using response_type = beast::http::response<beast::http::buffer_body>;
using response_serializer_type = beast::http::response_serializer<
    beast::http::buffer_body>;

class ClientIO : public io::RestfulClient {
 protected:
  parser_type& parser;
  response_type response;
  response_serializer_type serializer;
 private:
  const bool is_ssl;
  using endpoint_type = boost::asio::ip::tcp::endpoint;
  endpoint_type local_endpoint;
  endpoint_type remote_endpoint;

  RGWEnv env;

 public:
  ClientIO(parser_type& parser, bool is_ssl,
           const endpoint_type& local_endpoint,
           const endpoint_type& remote_endpoint);
  ~ClientIO() override;

  int init_env(CephContext *cct) override;
  void flush() override {} // no buffering
  size_t send_status(int status, const char *status_name) override;
  size_t send_header(const std::string_view& name,
                     const std::string_view& value) override;
  size_t send_content_length(uint64_t len) override;
  size_t send_chunked_transfer_encoding() override;

  RGWEnv& get_env() noexcept override {
    return env;
  }
};

} // namespace asio
} // namespace rgw

#endif // RGW_ASIO_CLIENT_H
