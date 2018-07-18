// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-

#pragma once

#include "lock_policy.h"

namespace ceph::internal {
template<LockPolicy lp> class md_config_obs_impl;
}

class md_config_t;
using md_config_obs_t =
  ceph::internal::md_config_obs_impl<ceph::internal::LockPolicy::MUTEX>;
class ConfigProxy;
