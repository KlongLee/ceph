#include "rgw_redis_common.h"

#include <iostream>

#include "rgw_redis_scripts.h"

namespace rgw {
namespace redis {

using boost::redis::config;
using boost::redis::connection;

int load_lua_rgwlib(boost::asio::io_context& io, connection* conn, config* cfg,
                    optional_yield y) {
  conn->async_run(*cfg, {}, boost::asio::detached);

  boost::redis::request req;
  boost::redis::response<std::string> resp;
  boost::system::error_code ec;

  req.push("FUNCTION", "LOAD", "REPLACE", RGW_LUA_SCRIPT);
  rgw::redis::redis_exec(conn, ec, req, resp, y);

  if (ec) {
    std::cerr << "EC Message: " << ec.message() << std::endl;
    return ec.value();
  }
  if (std::get<0>(resp).value() != "rgwlib") return -EINVAL;

  return 0;
}

RedisWriteResponse do_redis_func(
    connection* conn, boost::redis::request& req,
    boost::redis::response<RedisWriteResponse>& resp, std::string func_name,
    optional_yield y) {
  try {
    boost::system::error_code ec;
    rgw::redis::redis_exec(conn, ec, req, resp, y);
    if (ec) {
      std::cerr << "RGW RedisLock:: " << func_name
                << "(): ERROR: " << ec.message() << std::endl;
      return RedisWriteResponse(-ec.value(), ec.message());
    }
    return RedisWriteResponse(std::get<0>(resp).value());

  } catch (const std::exception& e) {
    std::cerr << "RGW RedisLock:: " << func_name
              << "(): Exception: " << e.what() << std::endl;
    return RedisWriteResponse(-EINVAL, e.what());
  }
}

RedisReadResponse do_redis_func(connection* conn, boost::redis::request& req,
                                boost::redis::response<RedisReadResponse>& resp,
                                std::string func_name, optional_yield y) {
  try {
    boost::system::error_code ec;
    rgw::redis::redis_exec(conn, ec, req, resp, y);
    if (ec) {
      std::cerr << "RGW RedisLock:: " << func_name
                << "(): ERROR: " << ec.message() << std::endl;
      return RedisReadResponse(-ec.value(), ec.message());
    }
    return RedisReadResponse(std::get<0>(resp).value());

  } catch (const std::exception& e) {
    std::cerr << "RGW RedisLock:: " << func_name
              << "(): Exception: " << e.what() << std::endl;
    return RedisReadResponse(-EINVAL, e.what());
  }
}

}  // namespace redis
}  // namespace rgw
