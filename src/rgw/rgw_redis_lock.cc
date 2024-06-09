#include "rgw_redis_lock.h"

#include <boost/asio/detached.hpp>
#include <fstream>
#include <iostream>
#include <string>

#include "common/async/blocked_completion.h"
#include "common/dout.h"

namespace rgw {
namespace redislock {

struct initiate_exec {
  connection* conn;

  using executor_type = boost::redis::connection::executor_type;
  executor_type get_executor() const noexcept { return conn->get_executor(); }

  template <typename Handler, typename Response>
  void operator()(Handler handler, const boost::redis::request& req,
                  Response& resp) {
    auto h = boost::asio::consign(std::move(handler), conn);
    return boost::asio::dispatch(
        get_executor(), [c = conn, &req, &resp, h = std::move(h)]() mutable {
          return c->async_exec(req, resp, std::move(h));
        });
  }
};

template <typename Response, typename CompletionToken>
auto async_exec(connection* conn, const boost::redis::request& req,
                Response& resp, CompletionToken&& token) {
  return boost::asio::async_initiate<
      CompletionToken, void(boost::system::error_code, std::size_t)>(
      initiate_exec{conn}, token, req, resp);
}

template <typename T>
void redis_exec(connection* conn, boost::system::error_code& ec,
                boost::redis::request& req, boost::redis::response<T>& resp,
                optional_yield y) {
  if (y) {
    auto yield = y.get_yield_context();
    async_exec(conn, req, resp, yield[ec]);
  } else {
    async_exec(conn, req, resp, ceph::async::use_blocked[ec]);
  }
}

template <typename T>
int doRedisFunc(connection* conn, boost::redis::request& req,
                boost::redis::response<T>& resp, optional_yield y) {
  boost::system::error_code ec;
  redis_exec(conn, ec, req, resp, y);

  if (ec) {
    std::cerr << "EC Message: " << ec.message() << std::endl;
    return ec.value();
  }
  return std::get<0>(resp).value();
}

int initLock(boost::asio::io_context& io, connection* conn, config* cfg,
             optional_yield y) {
  conn->async_run(*cfg, {}, boost::asio::detached);

  // std::string filename = "../src/test/rgw/test_redis_lock.lua";
  // std::string luaScript = getLuaScript(filename);

  const std::string luaScript = R"(#!lua name=liblock_1_0_0

--- Linux Error codes
local lerrorCodes = {
    EPERM = 1,
    ENOENT = 2,
    EBUSY = 16,
    EEXIST = 17
}

--- Assert if the lock is held by the owner of the cookie
--- @param keys table A single element list - lock name
--- @param args table A single-element list - cookie 
--- @return number 0 if the lock is held by the owner of the cookie,
--- -lerrorCodes.EBUSY if the lock is held by another owner, 
--- -lerrorCodes.ENOENT if the lock does not exist
local function assert_lock(keys, args)
    local name = keys[1]
    local cookie = args[1]
    if redis.call('EXISTS', name) == 1 then
        local existing_cookie = redis.call('GET', name)
        if existing_cookie == cookie then
            return 0 -- success
        else
            return -lerrorCodes.EBUSY
        end
    end
    return -lerrorCodes.ENOENT
end

--- Acquire a lock on a resource.
--- It sets a key with a cookie value if the key does not exist.
--- If the key exists and the value is same as cookie, it extends the lock.
--- If the key exists and the value is different from cookie, it fails.  
---@param keys table A single element list - lock name
---@param args table A two-element list - cookie and timeout
---@return number 0 if the lock is acquired or extended
local function lock(keys, args)
    local name = keys[1]
    local cookie = args[1]
    local timeout = args[2]
    local lock_status = assert_lock(keys, args)
    if lock_status == 0 then
        redis.call('PEXPIRE', name, timeout)
        return 0
    elseif lock_status == -lerrorCodes.ENOENT then
        redis.call('SET', name, cookie, 'PX', timeout)
        return 0
    end
    return lock_status
end

--- Release the lock on a resource.
--- It deletes the key if the value matches the cookie.
---@param keys table A single element list - lock name
---@param args table A single-element list - cookie
local function unlock(keys, args)
    local name = keys[1]
    local cookie = args[1]
    local lock_status = assert_lock(keys, args)
    if lock_status == 0 then
        redis.call('DEL', name)
        return 0
    end
    return lock_status
end

--- Register the functions.
redis.register_function('lock', lock)
redis.register_function('unlock', unlock)
redis.register_function('assert_lock', assert_lock)
)";

  boost::redis::request req;
  boost::redis::response<std::string> resp;
  boost::system::error_code ec;
  req.push("FUNCTION", "LOAD", "REPLACE", luaScript);
  redis_exec(conn, ec, req, resp, y);

  if (ec) {
    std::cerr << "EC Message: " << ec.message() << std::endl;
    return ec.value();
  }
  if (std::get<0>(resp).value() != "liblock_1_0_0") return -EINVAL;

  return 0;
}

int lock(connection* conn, const std::string name, const std::string cookie,
         const int duration, optional_yield y) {
  boost::redis::request req;
  boost::redis::response<int> resp;

  std::string expiration_time = std::to_string(duration);
  req.push("FCALL", "lock", 1, name, cookie, expiration_time);
  return doRedisFunc(conn, req, resp, y);
}

int unlock(connection* conn, const std::string& name, const std::string& cookie,
           optional_yield y) {
  boost::redis::request req;
  boost::redis::response<int> resp;

  req.push("FCALL", "unlock", 1, name, cookie);
  return doRedisFunc(conn, req, resp, y);
}

int assert_locked(connection* conn, const std::string& name,
                  const std::string& cookie, optional_yield y) {
  boost::redis::request req;
  boost::redis::response<int> resp;

  req.push("FCALL", "assert_lock", 1, name, cookie);
  return doRedisFunc(conn, req, resp, y);
}

}  // namespace redislock
}  // namespace rgw
