// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-

#include "config_proxy.h"

namespace ceph::common {

ConfigProxy::ConfigProxy()
{
  if (seastar::engine().cpu_id() != 0) {
    return;
  }
  // set the initial value on CPU#0
  values.reset(seastar::make_lw_shared<ConfigValues>());
  // and the only copy of md_config_impl<> is allocated on CPU#0
  local_config.reset(new md_config_t{*values, obs_mgr, true});
}

seastar::future<> ConfigProxy::start()
{
  // populate values and config to all other shards
  if (!values) {
    return seastar::make_ready_future<>();
  }
  return container().invoke_on_others([this](auto& proxy) {
    return values.copy().then([config=local_config.get(),
			       &proxy](auto foreign_values) {
      proxy.values.reset();
      proxy.values = std::move(foreign_values);
      proxy.remote_config = config;
      return seastar::make_ready_future<>();
    });
  });
}

ConfigProxy::ShardedConfig ConfigProxy::sharded_conf;
}
