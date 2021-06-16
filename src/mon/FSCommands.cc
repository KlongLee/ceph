// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2017 Red Hat Ltd
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */


#include "OSDMonitor.h"

#include "FSCommands.h"
#include "MDSMonitor.h"
#include "MgrStatMonitor.h"
#include "mds/cephfs_features.h"

using TOPNSPC::common::cmd_getval;

using std::dec;
using std::hex;
using std::list;
using std::map;
using std::make_pair;
using std::ostream;
using std::ostringstream;
using std::pair;
using std::set;
using std::string;
using std::stringstream;
using std::to_string;
using std::vector;

using ceph::bufferlist;
using ceph::decode;
using ceph::encode;
using ceph::ErasureCodeInterfaceRef;
using ceph::ErasureCodeProfile;
using ceph::Formatter;
using ceph::JSONFormatter;
using ceph::make_message;
using ceph::mono_clock;
using ceph::mono_time;

class FlagSetHandler : public FileSystemCommandHandler
{
  public:
  FlagSetHandler()
    : FileSystemCommandHandler("fs flag set")
  {
  }

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    string flag_name;
    cmd_getval(cmdmap, "flag_name", flag_name);

    string flag_val;
    cmd_getval(cmdmap, "val", flag_val);

    bool sure = false;
    cmd_getval(cmdmap, "yes_i_really_mean_it", sure);

    if (flag_name == "enable_multiple") {
      bool flag_bool = false;
      int r = parse_bool(flag_val, &flag_bool, ss);
      if (r != 0) {
        ss << "Invalid boolean value '" << flag_val << "'";
        return r;
      }

      fsmap.set_enable_multiple(flag_bool);
      return 0;
    } else {
      ss << "Unknown flag '" << flag_name << "'";
      return -EINVAL;
    }
  }
};

class FailHandler : public FileSystemCommandHandler
{
  public:
  FailHandler()
    : FileSystemCommandHandler("fs fail")
  {
  }

  int handle(
      Monitor* mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream& ss) override
  {
    if (!mon->osdmon()->is_writeable()) {
      // not allowed to write yet, so retry when we can
      mon->osdmon()->wait_for_writeable(op, new PaxosService::C_RetryMessage(mon->mdsmon(), op));
      return -EAGAIN;
    }

    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);

    auto f = [](auto fs) {
      fs->mds_map.set_flag(CEPH_MDSMAP_NOT_JOINABLE);
    };
    fsmap.modify_filesystem(fs->fscid, std::move(f));

    std::vector<mds_gid_t> to_fail;
    for (const auto& p : fs->mds_map.get_mds_info()) {
      to_fail.push_back(p.first);
    }

    for (const auto& gid : to_fail) {
      mon->mdsmon()->fail_mds_gid(fsmap, gid);
    }
    if (!to_fail.empty()) {
      mon->osdmon()->propose_pending();
    }

    ss << fs_name;
    ss << " marked not joinable; MDS cannot join the cluster. All MDS ranks marked failed.";

    return 0;
  }
};

class FsNewHandler : public FileSystemCommandHandler
{
  public:
  explicit FsNewHandler(Paxos *paxos)
    : FileSystemCommandHandler("fs new"), m_paxos(paxos)
  {
  }

  bool batched_propose() override {
    return true;
  }

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    ceph_assert(m_paxos->is_plugged());

    string metadata_name;
    cmd_getval(cmdmap, "metadata", metadata_name);
    int64_t metadata = mon->osdmon()->osdmap.lookup_pg_pool_name(metadata_name);
    if (metadata < 0) {
      ss << "pool '" << metadata_name << "' does not exist";
      return -ENOENT;
    }

    string data_name;
    cmd_getval(cmdmap, "data", data_name);
    int64_t data = mon->osdmon()->osdmap.lookup_pg_pool_name(data_name);
    if (data < 0) {
      ss << "pool '" << data_name << "' does not exist";
      return -ENOENT;
    }
    if (data == 0) {
      ss << "pool '" << data_name << "' has id 0, which CephFS does not allow. Use another pool or recreate it to get a non-zero pool id.";
      return -EINVAL;
    }

    string fs_name;
    cmd_getval(cmdmap, "fs_name", fs_name);
    if (fs_name.empty()) {
        // Ensure fs name is not empty so that we can implement
        // commmands that refer to FS by name in future.
        ss << "Filesystem name may not be empty";
        return -EINVAL;
    }

    if (fsmap.get_filesystem(fs_name)) {
      auto fs = fsmap.get_filesystem(fs_name);
      if (*(fs->mds_map.get_data_pools().begin()) == data
          && fs->mds_map.get_metadata_pool() == metadata) {
        // Identical FS created already, this is a no-op
        ss << "filesystem '" << fs_name << "' already exists";
        return 0;
      } else {
        ss << "filesystem already exists with name '" << fs_name << "'";
        return -EINVAL;
      }
    }

    bool force = false;
    cmd_getval(cmdmap, "force", force);

    const pool_stat_t *stat = mon->mgrstatmon()->get_pool_stat(metadata);
    if (stat) {
      int64_t metadata_num_objects = stat->stats.sum.num_objects;
      if (!force && metadata_num_objects > 0) {
	ss << "pool '" << metadata_name
	   << "' already contains some objects. Use an empty pool instead.";
	return -EINVAL;
      }
    }

    if (fsmap.filesystem_count() > 0
        && !fsmap.get_enable_multiple()) {
      ss << "Creation of multiple filesystems is disabled.  To enable "
            "this experimental feature, use 'ceph fs flag set enable_multiple "
            "true'";
      return -EINVAL;
    }

    for (auto& fs : fsmap.get_filesystems()) {
      const std::vector<int64_t> &data_pools = fs->mds_map.get_data_pools();

      bool sure = false;
      cmd_getval(cmdmap,
                 "allow_dangerous_metadata_overlay", sure);

      if ((std::find(data_pools.begin(), data_pools.end(), data) != data_pools.end()
	   || fs->mds_map.get_metadata_pool() == metadata)
	  && !sure) {
	ss << "Filesystem '" << fs_name
	   << "' is already using one of the specified RADOS pools. This should ONLY be done in emergencies and after careful reading of the documentation. Pass --allow-dangerous-metadata-overlay to permit this.";
	return -EEXIST;
      }
    }

    pg_pool_t const *data_pool = mon->osdmon()->osdmap.get_pg_pool(data);
    ceph_assert(data_pool != NULL);  // Checked it existed above
    pg_pool_t const *metadata_pool = mon->osdmon()->osdmap.get_pg_pool(metadata);
    ceph_assert(metadata_pool != NULL);  // Checked it existed above

    int r = _check_pool(mon->osdmon()->osdmap, data, POOL_DATA_DEFAULT, force, &ss);
    if (r < 0) {
      return r;
    }

    r = _check_pool(mon->osdmon()->osdmap, metadata, POOL_METADATA, force, &ss);
    if (r < 0) {
      return r;
    }
    
    if (!mon->osdmon()->is_writeable()) {
      // not allowed to write yet, so retry when we can
      mon->osdmon()->wait_for_writeable(op, new PaxosService::C_RetryMessage(mon->mdsmon(), op));
      return -EAGAIN;
    }
    mon->osdmon()->do_application_enable(data,
					 pg_pool_t::APPLICATION_NAME_CEPHFS,
					 "data", fs_name, true);
    mon->osdmon()->do_application_enable(metadata,
					 pg_pool_t::APPLICATION_NAME_CEPHFS,
					 "metadata", fs_name, true);
    mon->osdmon()->do_set_pool_opt(metadata,
				   pool_opts_t::RECOVERY_PRIORITY,
				   static_cast<int64_t>(5));
    mon->osdmon()->do_set_pool_opt(metadata,
				   pool_opts_t::PG_NUM_MIN,
				   static_cast<int64_t>(16));
    mon->osdmon()->do_set_pool_opt(metadata,
				   pool_opts_t::PG_AUTOSCALE_BIAS,
				   static_cast<double>(4.0));
    mon->osdmon()->propose_pending();

    // All checks passed, go ahead and create.
    auto&& fs = fsmap.create_filesystem(fs_name, metadata, data,
        mon->get_quorum_con_features());

    ss << "new fs with metadata pool " << metadata << " and data pool " << data;

    // assign a standby to rank 0 to avoid health warnings
    auto info = fsmap.find_replacement_for({fs->fscid, 0});

    if (info) {
      mon->clog->info() << info->human_name() << " assigned to filesystem "
          << fs_name << " as rank 0";
      fsmap.promote(info->global_id, *fs, 0);
    }

    return 0;
  }

private:
  Paxos *m_paxos;
};

class SetHandler : public FileSystemCommandHandler
{
public:
  SetHandler()
    : FileSystemCommandHandler("fs set")
  {}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    string var;
    if (!cmd_getval(cmdmap, "var", var) || var.empty()) {
      ss << "Invalid variable";
      return -EINVAL;
    }
    string val;
    string interr;
    int64_t n = 0;
    if (!cmd_getval(cmdmap, "val", val)) {
      return -EINVAL;
    }
    // we got a string.  see if it contains an int.
    n = strict_strtoll(val.c_str(), 10, &interr);
    if (var == "max_mds") {
      // NOTE: see also "mds set_max_mds", which can modify the same field.
      if (interr.length()) {
        ss << interr;
	return -EINVAL;
      }

      if (n <= 0) {
        ss << "You must specify at least one MDS";
        return -EINVAL;
      }

      if (n > 1 && n > fs->mds_map.get_max_mds()) {
	if (fs->mds_map.was_snaps_ever_allowed() &&
	    !fs->mds_map.allows_multimds_snaps()) {
	  ss << "multi-active MDS is not allowed while there are snapshots possibly created by pre-mimic MDS";
	  return -EINVAL;
	}
      }
      if (n > MAX_MDS) {
        ss << "may not have more than " << MAX_MDS << " MDS ranks";
        return -EINVAL;
      }

      fsmap.modify_filesystem(
          fs->fscid,
          [n](std::shared_ptr<Filesystem> fs)
      {
	fs->mds_map.clear_flag(CEPH_MDSMAP_NOT_JOINABLE);
        fs->mds_map.set_max_mds(n);
      });
    } else if (var == "inline_data") {
      bool enable_inline = false;
      int r = parse_bool(val, &enable_inline, ss);
      if (r != 0) {
        return r;
      }

      if (enable_inline) {
        bool confirm = false;
        cmd_getval(cmdmap, "yes_i_really_really_mean_it", confirm);
	if (!confirm) {
	  ss << "Inline data support is deprecated and will be removed in a future release. "
	     << "Add --yes-i-really-really-mean-it if you are certain you want this enabled.";
	  return -EPERM;
	}
	ss << "inline data enabled";

        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
          fs->mds_map.set_inline_data_enabled(true);
        });

        // Update `compat`
        CompatSet c = fsmap.get_compat();
        c.incompat.insert(MDS_FEATURE_INCOMPAT_INLINE);
        fsmap.update_compat(c);
      } else {
	ss << "inline data disabled";
        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
          fs->mds_map.set_inline_data_enabled(false);
        });
      }
    } else if (var == "balancer") {
      if (val.empty()) {
        ss << "unsetting the metadata load balancer";
      } else {
        ss << "setting the metadata load balancer to " << val;
      }
      fsmap.modify_filesystem(
	fs->fscid,
	[val](std::shared_ptr<Filesystem> fs)
        {
          fs->mds_map.set_balancer(val);
        });
      return true;
    } else if (var == "max_file_size") {
      if (interr.length()) {
	ss << var << " requires an integer value";
	return -EINVAL;
      }
      if (n < CEPH_MIN_STRIPE_UNIT) {
	ss << var << " must at least " << CEPH_MIN_STRIPE_UNIT;
	return -ERANGE;
      }
      fsmap.modify_filesystem(
          fs->fscid,
          [n](std::shared_ptr<Filesystem> fs)
      {
        fs->mds_map.set_max_filesize(n);
      });
    } else if (var == "allow_new_snaps") {
      bool enable_snaps = false;
      int r = parse_bool(val, &enable_snaps, ss);
      if (r != 0) {
        return r;
      }

      if (!enable_snaps) {
        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
          fs->mds_map.clear_snaps_allowed();
        });
	ss << "disabled new snapshots";
      } else {
        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
          fs->mds_map.set_snaps_allowed();
        });
	ss << "enabled new snapshots";
      }
    } else if (var == "allow_multimds") {
        ss << "Multiple MDS is always enabled. Use the max_mds"
           << " parameter to control the number of active MDSs"
           << " allowed. This command is DEPRECATED and will be"
           << " REMOVED from future releases.";
    } else if (var == "allow_multimds_snaps") {
      bool enable = false;
      int r = parse_bool(val, &enable, ss);
      if (r != 0) {
        return r;
      }

      string confirm;
      if (!cmd_getval(cmdmap, "confirm", confirm) ||
	  confirm != "--yes-i-am-really-a-mds") {
	ss << "Warning! This command is for MDS only. Do not run it manually";
	return -EPERM;
      }

      if (enable) {
	ss << "enabled multimds with snapshot";
        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
	  fs->mds_map.set_multimds_snaps_allowed();
        });
      } else {
	ss << "disabled multimds with snapshot";
        fsmap.modify_filesystem(
            fs->fscid,
            [](std::shared_ptr<Filesystem> fs)
        {
	  fs->mds_map.clear_multimds_snaps_allowed();
        });
      }
    } else if (var == "allow_dirfrags") {
        ss << "Directory fragmentation is now permanently enabled."
           << " This command is DEPRECATED and will be REMOVED from future releases.";
    } else if (var == "down") {
      bool is_down = false;
      int r = parse_bool(val, &is_down, ss);
      if (r != 0) {
        return r;
      }

      ss << fs->mds_map.get_fs_name();

      fsmap.modify_filesystem(
          fs->fscid,
          [is_down](std::shared_ptr<Filesystem> fs)
      {
	if (is_down) {
          if (fs->mds_map.get_max_mds() > 0) {
	    fs->mds_map.set_old_max_mds();
	    fs->mds_map.set_max_mds(0);
          } /* else already down! */
	} else {
	  mds_rank_t oldmax = fs->mds_map.get_old_max_mds();
	  fs->mds_map.set_max_mds(oldmax ? oldmax : 1);
	}
      });

      if (is_down) {
	ss << " marked down. ";
      } else {
	ss << " marked up, max_mds = " << fs->mds_map.get_max_mds();
      }
    } else if (var == "cluster_down" || var == "joinable") {
      bool joinable = true;
      int r = parse_bool(val, &joinable, ss);
      if (r != 0) {
        return r;
      }
      if (var == "cluster_down") {
        joinable = !joinable;
      }

      ss << fs->mds_map.get_fs_name();

      fsmap.modify_filesystem(
          fs->fscid,
          [joinable](std::shared_ptr<Filesystem> fs)
      {
	if (joinable) {
	  fs->mds_map.clear_flag(CEPH_MDSMAP_NOT_JOINABLE);
	} else {
	  fs->mds_map.set_flag(CEPH_MDSMAP_NOT_JOINABLE);
	}
      });

      if (joinable) {
	ss << " marked joinable; MDS may join as newly active.";
      } else {
	ss << " marked not joinable; MDS cannot join as newly active.";
      }

      if (var == "cluster_down") {
        ss << " WARNING: cluster_down flag is deprecated and will be"
           << " removed in a future version. Please use \"joinable\".";
      }
    } else if (var == "standby_count_wanted") {
      if (interr.length()) {
       ss << var << " requires an integer value";
       return -EINVAL;
      }
      if (n < 0) {
       ss << var << " must be non-negative";
       return -ERANGE;
      }
      fsmap.modify_filesystem(
          fs->fscid,
          [n](std::shared_ptr<Filesystem> fs)
      {
        fs->mds_map.set_standby_count_wanted(n);
      });
    } else if (var == "session_timeout") {
      if (interr.length()) {
       ss << var << " requires an integer value";
       return -EINVAL;
      }
      if (n < 30) {
       ss << var << " must be at least 30s";
       return -ERANGE;
      }
      fsmap.modify_filesystem(
          fs->fscid,
          [n](std::shared_ptr<Filesystem> fs)
      {
        fs->mds_map.set_session_timeout((uint32_t)n);
      });
    } else if (var == "session_autoclose") {
      if (interr.length()) {
       ss << var << " requires an integer value";
       return -EINVAL;
      }
      if (n < 30) {
       ss << var << " must be at least 30s";
       return -ERANGE;
      }
      fsmap.modify_filesystem(
          fs->fscid,
          [n](std::shared_ptr<Filesystem> fs)
      {
        fs->mds_map.set_session_autoclose((uint32_t)n);
      });
    } else if (var == "allow_standby_replay") {
      bool allow = false;
      int r = parse_bool(val, &allow, ss);
      if (r != 0) {
        return r;
      }

      if (!allow) {
        if (!mon->osdmon()->is_writeable()) {
          // not allowed to write yet, so retry when we can
          mon->osdmon()->wait_for_writeable(op, new PaxosService::C_RetryMessage(mon->mdsmon(), op));
          return -EAGAIN;
        }
        std::vector<mds_gid_t> to_fail;
        for (const auto& [gid, info]: fs->mds_map.get_mds_info()) {
          if (info.state == MDSMap::STATE_STANDBY_REPLAY) {
            to_fail.push_back(gid);
          }
        }

        for (const auto& gid : to_fail) {
          mon->mdsmon()->fail_mds_gid(fsmap, gid);
        }
        if (!to_fail.empty()) {
          mon->osdmon()->propose_pending();
        }
      }

      auto f = [allow](auto& fs) {
        if (allow) {
          fs->mds_map.set_standby_replay_allowed();
        } else {
          fs->mds_map.clear_standby_replay_allowed();
        }
      };
      fsmap.modify_filesystem(fs->fscid, std::move(f));
    } else if (var == "min_compat_client") {
      auto vno = ceph_release_from_name(val.c_str());
      if (!vno) {
	ss << "version " << val << " is not recognized";
	return -EINVAL;
      }
      ss << "WARNING: setting min_compat_client is deprecated"
            " and may not do what you want.\n"
            "The oldest release to set is octopus.\n"
            "Please migrate to `ceph fs required_client_features ...`.";
      auto f = [vno](auto&& fs) {
        fs->mds_map.set_min_compat_client(vno);
      };
      fsmap.modify_filesystem(fs->fscid, std::move(f));
    } else {
      ss << "unknown variable " << var;
      return -EINVAL;
    }

    return 0;
  }
};

class RequiredClientFeaturesHandler : public FileSystemCommandHandler
{
  public:
    RequiredClientFeaturesHandler()
      : FileSystemCommandHandler("fs required_client_features")
    {
    }

    int handle(
	Monitor *mon,
	FSMap &fsmap,
	MonOpRequestRef op,
	const cmdmap_t& cmdmap,
	std::stringstream &ss) override
    {
      std::string fs_name;
      if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
	ss << "Missing filesystem name";
	return -EINVAL;
      }
      auto fs = fsmap.get_filesystem(fs_name);
      if (fs == nullptr) {
	ss << "Not found: '" << fs_name << "'";
	return -ENOENT;
      }
      string subop;
      if (!cmd_getval(cmdmap, "subop", subop) ||
	  (subop != "add" && subop != "rm")) {
	ss << "Must either add or rm a feature; " << subop << " is not recognized";
	return -EINVAL;
      }
      string val;
      if (!cmd_getval(cmdmap, "val", val) || val.empty()) {
	ss << "Missing feature id/name";
	return -EINVAL;
      }

      int feature = cephfs_feature_from_name(val);
      if (feature < 0) {
	string err;
	feature = strict_strtol(val.c_str(), 10, &err);
	if (err.length()) {
	  ss << "Invalid feature name: " << val;
	  return -EINVAL;
	}
	if (feature < 0 || feature > CEPHFS_FEATURE_MAX) {
	  ss << "Invalid feature id: " << feature;
	  return -EINVAL;
	}
      }

      if (subop == "add") {
	bool ret = false;
	fsmap.modify_filesystem(
	    fs->fscid,
	    [feature, &ret](auto&& fs)
	{
	  if (fs->mds_map.get_required_client_features().test(feature))
	    return;
	  fs->mds_map.add_required_client_feature(feature);
	  ret = true;
	});
	if (ret) {
	  ss << "added feature '" << cephfs_feature_name(feature) << "' to required_client_features";
	} else {
	  ss << "feature '" << cephfs_feature_name(feature) << "' is already set";
	}
      } else {
	bool ret = false;
	fsmap.modify_filesystem(
	    fs->fscid,
	    [feature, &ret](auto&& fs)
	{
          if (!fs->mds_map.get_required_client_features().test(feature))
            return;
          fs->mds_map.remove_required_client_feature(feature);
          ret = true;
	});
	if (ret) {
	  ss << "removed feature '" << cephfs_feature_name(feature) << "' from required_client_features";
	} else {
	  ss << "feature '" << cephfs_feature_name(feature) << "' is already unset";
	}
      }
      return 0;
   }
};


class AddDataPoolHandler : public FileSystemCommandHandler
{
  public:
  explicit AddDataPoolHandler(Paxos *paxos)
    : FileSystemCommandHandler("fs add_data_pool"), m_paxos(paxos)
  {}

  bool batched_propose() override {
    return true;
  }

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    ceph_assert(m_paxos->is_plugged());

    string poolname;
    cmd_getval(cmdmap, "pool", poolname);

    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name)
        || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    int64_t poolid = mon->osdmon()->osdmap.lookup_pg_pool_name(poolname);
    if (poolid < 0) {
      string err;
      poolid = strict_strtol(poolname.c_str(), 10, &err);
      if (err.length()) {
	ss << "pool '" << poolname << "' does not exist";
	return -ENOENT;
      }
    }

    int r = _check_pool(mon->osdmon()->osdmap, poolid, POOL_DATA_EXTRA, false, &ss);
    if (r != 0) {
      return r;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    // no-op when the data_pool already on fs
    if (fs->mds_map.is_data_pool(poolid)) {
      ss << "data pool " << poolid << " is already on fs " << fs_name;
      return 0;
    }

    if (!mon->osdmon()->is_writeable()) {
      // not allowed to write yet, so retry when we can
      mon->osdmon()->wait_for_writeable(op, new PaxosService::C_RetryMessage(mon->mdsmon(), op));
      return -EAGAIN;
    }
    mon->osdmon()->do_application_enable(poolid,
					 pg_pool_t::APPLICATION_NAME_CEPHFS,
					 "data", fs_name, true);
    mon->osdmon()->propose_pending();

    fsmap.modify_filesystem(
        fs->fscid,
        [poolid](std::shared_ptr<Filesystem> fs)
    {
      fs->mds_map.add_data_pool(poolid);
    });

    ss << "added data pool " << poolid << " to fsmap";

    return 0;
  }

private:
  Paxos *m_paxos;
};

class SetDefaultHandler : public FileSystemCommandHandler
{
  public:
  SetDefaultHandler()
    : FileSystemCommandHandler("fs set-default")
  {}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    std::string fs_name;
    cmd_getval(cmdmap, "fs_name", fs_name);
    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
        ss << "filesystem '" << fs_name << "' does not exist";
        return -ENOENT;
    }

    fsmap.set_legacy_client_fscid(fs->fscid);
    return 0;
  }
};

class RemoveFilesystemHandler : public FileSystemCommandHandler
{
  public:
  RemoveFilesystemHandler()
    : FileSystemCommandHandler("fs rm")
  {}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    /* We may need to blocklist ranks. */
    if (!mon->osdmon()->is_writeable()) {
      // not allowed to write yet, so retry when we can
      mon->osdmon()->wait_for_writeable(op, new PaxosService::C_RetryMessage(mon->mdsmon(), op));
      return -EAGAIN;
    }

    // Check caller has correctly named the FS to delete
    // (redundant while there is only one FS, but command
    //  syntax should apply to multi-FS future)
    string fs_name;
    cmd_getval(cmdmap, "fs_name", fs_name);
    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
        // Consider absence success to make deletes idempotent
        ss << "filesystem '" << fs_name << "' does not exist";
        return 0;
    }

    // Check that no MDS daemons are active
    if (fs->mds_map.get_num_up_mds() > 0) {
      ss << "all MDS daemons must be inactive/failed before removing filesystem. See `ceph fs fail`.";
      return -EINVAL;
    }

    // Check for confirmation flag
    bool sure = false;
    cmd_getval(cmdmap, "yes_i_really_mean_it", sure);
    if (!sure) {
      ss << "this is a DESTRUCTIVE operation and will make data in your filesystem permanently" \
            " inaccessible.  Add --yes-i-really-mean-it if you are sure you wish to continue.";
      return -EPERM;
    }

    if (fsmap.get_legacy_client_fscid() == fs->fscid) {
      fsmap.set_legacy_client_fscid(FS_CLUSTER_ID_NONE);
    }

    std::vector<mds_gid_t> to_fail;
    // There may be standby_replay daemons left here
    for (const auto &i : fs->mds_map.get_mds_info()) {
      ceph_assert(i.second.state == MDSMap::STATE_STANDBY_REPLAY);
      to_fail.push_back(i.first);
    }

    for (const auto &gid : to_fail) {
      // Standby replays don't write, so it isn't important to
      // wait for an osdmap propose here: ignore return value.
      mon->mdsmon()->fail_mds_gid(fsmap, gid);
    }
    if (!to_fail.empty()) {
      mon->osdmon()->propose_pending(); /* maybe new blocklists */
    }

    fsmap.erase_filesystem(fs->fscid);

    return 0;
  }
};

class ResetFilesystemHandler : public FileSystemCommandHandler
{
  public:
  ResetFilesystemHandler()
    : FileSystemCommandHandler("fs reset")
  {}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    string fs_name;
    cmd_getval(cmdmap, "fs_name", fs_name);
    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
        ss << "filesystem '" << fs_name << "' does not exist";
        // Unlike fs rm, we consider this case an error
        return -ENOENT;
    }

    // Check that no MDS daemons are active
    if (fs->mds_map.get_num_up_mds() > 0) {
      ss << "all MDS daemons must be inactive before resetting filesystem: set the cluster_down flag"
            " and use `ceph mds fail` to make this so";
      return -EINVAL;
    }

    // Check for confirmation flag
    bool sure = false;
    cmd_getval(cmdmap, "yes_i_really_mean_it", sure);
    if (!sure) {
      ss << "this is a potentially destructive operation, only for use by experts in disaster recovery.  "
        "Add --yes-i-really-mean-it if you are sure you wish to continue.";
      return -EPERM;
    }

    fsmap.reset_filesystem(fs->fscid);

    return 0;
  }
};

class RemoveDataPoolHandler : public FileSystemCommandHandler
{
  public:
  RemoveDataPoolHandler()
    : FileSystemCommandHandler("fs rm_data_pool")
  {}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    string poolname;
    cmd_getval(cmdmap, "pool", poolname);

    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name)
        || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    int64_t poolid = mon->osdmon()->osdmap.lookup_pg_pool_name(poolname);
    if (poolid < 0) {
      string err;
      poolid = strict_strtol(poolname.c_str(), 10, &err);
      if (err.length()) {
	ss << "pool '" << poolname << "' does not exist";
        return -ENOENT;
      } else if (poolid < 0) {
        ss << "invalid pool id '" << poolid << "'";
        return -EINVAL;
      }
    }

    ceph_assert(poolid >= 0);  // Checked by parsing code above

    auto fs = fsmap.get_filesystem(fs_name);
    if (fs->mds_map.get_first_data_pool() == poolid) {
      ss << "cannot remove default data pool";
      return -EINVAL;
    }

    int r = 0;
    fsmap.modify_filesystem(fs->fscid,
        [&r, poolid](std::shared_ptr<Filesystem> fs)
    {
      r = fs->mds_map.remove_data_pool(poolid);
    });
    if (r == -ENOENT) {
      // It was already removed, succeed in silence
      return 0;
    } else if (r == 0) {
      // We removed it, succeed
      ss << "removed data pool " << poolid << " from fsmap";
      return 0;
    } else {
      // Unexpected error, bubble up
      return r;
    }
  }
};

/**
 * For commands with an alternative prefix
 */
template<typename T>
class AliasHandler : public T
{
  std::string alias_prefix;

  public:
  explicit AliasHandler(const std::string &new_prefix)
    : T()
  {
    alias_prefix = new_prefix;
  }

  std::string const &get_prefix() const override {return alias_prefix;}

  int handle(
      Monitor *mon,
      FSMap& fsmap,
      MonOpRequestRef op,
      const cmdmap_t& cmdmap,
      std::stringstream &ss) override
  {
    return T::handle(mon, fsmap, op, cmdmap, ss);
  }
};

class MirrorHandlerEnable : public FileSystemCommandHandler
{
public:
  MirrorHandlerEnable()
    : FileSystemCommandHandler("fs mirror enable")
  {}

  int handle(Monitor *mon,
             FSMap &fsmap, MonOpRequestRef op,
             const cmdmap_t& cmdmap, std::stringstream &ss) override {
    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
      ss << "Filesystem '" << fs_name << "' not found";
      return -ENOENT;
    }

    if (fs->mirror_info.is_mirrored()) {
      return 0;
    }

    auto f = [](auto &&fs) {
               fs->mirror_info.enable_mirroring();
    };
    fsmap.modify_filesystem(fs->fscid, std::move(f));

    return 0;
  }
};

class MirrorHandlerDisable : public FileSystemCommandHandler
{
public:
  MirrorHandlerDisable()
    : FileSystemCommandHandler("fs mirror disable")
  {}

  int handle(Monitor *mon,
             FSMap &fsmap, MonOpRequestRef op,
             const cmdmap_t& cmdmap, std::stringstream &ss) override {
    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
      ss << "Filesystem '" << fs_name << "' not found";
      return -ENOENT;
    }

    if (!fs->mirror_info.is_mirrored()) {
      return 0;
    }

    auto f = [](auto &&fs) {
      fs->mirror_info.disable_mirroring();
    };
    fsmap.modify_filesystem(fs->fscid, std::move(f));

    return 0;
  }
};

class MirrorHandlerAddPeer : public FileSystemCommandHandler
{
public:
  MirrorHandlerAddPeer()
    : FileSystemCommandHandler("fs mirror peer_add")
  {}

  boost::optional<std::pair<string, string>>
  extract_remote_cluster_conf(const std::string &spec) {
    auto pos = spec.find("@");
    if (pos == std::string_view::npos) {
      return boost::optional<std::pair<string, string>>();
    }

    auto client = spec.substr(0, pos);
    auto cluster = spec.substr(pos+1);

    return std::make_pair(client, cluster);
  }

  bool peer_add(FSMap &fsmap, Filesystem::const_ref &&fs,
                const cmdmap_t &cmdmap, std::stringstream &ss) {
    string peer_uuid;
    string remote_spec;
    string remote_fs_name;
    cmd_getval(cmdmap, "uuid", peer_uuid);
    cmd_getval(cmdmap, "remote_cluster_spec", remote_spec);
    cmd_getval(cmdmap, "remote_fs_name", remote_fs_name);

    // verify (and extract) remote cluster specification
    auto remote_conf = extract_remote_cluster_conf(remote_spec);
    if (!remote_conf) {
      ss << "invalid remote cluster spec -- should be <client>@<cluster>";
      return false;
    }

    if (fs->mirror_info.has_peer(peer_uuid)) {
      ss << "peer already exists";
      return true;
    }
    if (fs->mirror_info.has_peer((*remote_conf).first, (*remote_conf).second,
                                 remote_fs_name)) {
      ss << "peer already exists";
      return true;
    }

    auto f = [peer_uuid, remote_conf, remote_fs_name](auto &&fs) {
               fs->mirror_info.peer_add(peer_uuid, (*remote_conf).first,
                                        (*remote_conf).second, remote_fs_name);
             };
    fsmap.modify_filesystem(fs->fscid, std::move(f));
    return true;
  }

  int handle(Monitor *mon,
             FSMap &fsmap, MonOpRequestRef op,
             const cmdmap_t& cmdmap, std::stringstream &ss) override {
    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
      ss << "Filesystem '" << fs_name << "' not found";
      return -ENOENT;
    }

    if (!fs->mirror_info.is_mirrored()) {
      ss << "Mirroring not enabled for filesystem '" << fs_name << "'";
      return -EINVAL;
    }

    auto res = peer_add(fsmap, std::move(fs), cmdmap, ss);
    if (!res) {
      return -EINVAL;
    }

    return 0;
  }
};

class MirrorHandlerRemovePeer : public FileSystemCommandHandler
{
public:
  MirrorHandlerRemovePeer()
    : FileSystemCommandHandler("fs mirror peer_remove")
  {}

  bool peer_remove(FSMap &fsmap, Filesystem::const_ref &&fs,
                   const cmdmap_t &cmdmap, std::stringstream &ss) {
    string peer_uuid;
    cmd_getval(cmdmap, "uuid", peer_uuid);

    if (!fs->mirror_info.has_peer(peer_uuid)) {
      ss << "cannot find peer with uuid: " << peer_uuid;
      return true;
    }

    auto f = [peer_uuid](auto &&fs) {
               fs->mirror_info.peer_remove(peer_uuid);
             };
    fsmap.modify_filesystem(fs->fscid, std::move(f));
    return true;
  }

  int handle(Monitor *mon,
             FSMap &fsmap, MonOpRequestRef op,
             const cmdmap_t& cmdmap, std::stringstream &ss) override {
    std::string fs_name;
    if (!cmd_getval(cmdmap, "fs_name", fs_name) || fs_name.empty()) {
      ss << "Missing filesystem name";
      return -EINVAL;
    }

    auto fs = fsmap.get_filesystem(fs_name);
    if (fs == nullptr) {
      ss << "Filesystem '" << fs_name << "' not found";
      return -ENOENT;
    }

    if (!fs->mirror_info.is_mirrored()) {
      ss << "Mirroring not enabled for filesystem '" << fs_name << "'";
      return -EINVAL;
    }

    auto res = peer_remove(fsmap, std::move(fs), cmdmap, ss);
    if (!res) {
      return -EINVAL;
    }

    return 0;
  }
};

std::list<std::shared_ptr<FileSystemCommandHandler> >
FileSystemCommandHandler::load(Paxos *paxos)
{
  std::list<std::shared_ptr<FileSystemCommandHandler> > handlers;

  handlers.push_back(std::make_shared<SetHandler>());
  handlers.push_back(std::make_shared<FailHandler>());
  handlers.push_back(std::make_shared<FlagSetHandler>());
  handlers.push_back(std::make_shared<RequiredClientFeaturesHandler>());
  handlers.push_back(std::make_shared<AddDataPoolHandler>(paxos));
  handlers.push_back(std::make_shared<RemoveDataPoolHandler>());
  handlers.push_back(std::make_shared<FsNewHandler>(paxos));
  handlers.push_back(std::make_shared<RemoveFilesystemHandler>());
  handlers.push_back(std::make_shared<ResetFilesystemHandler>());

  handlers.push_back(std::make_shared<SetDefaultHandler>());
  handlers.push_back(std::make_shared<AliasHandler<SetDefaultHandler> >(
        "fs set_default"));
  handlers.push_back(std::make_shared<MirrorHandlerEnable>());
  handlers.push_back(std::make_shared<MirrorHandlerDisable>());
  handlers.push_back(std::make_shared<MirrorHandlerAddPeer>());
  handlers.push_back(std::make_shared<MirrorHandlerRemovePeer>());

  return handlers;
}

int FileSystemCommandHandler::_check_pool(
    OSDMap &osd_map,
    const int64_t pool_id,
    int type,
    bool force,
    std::stringstream *ss) const
{
  ceph_assert(ss != NULL);

  const pg_pool_t *pool = osd_map.get_pg_pool(pool_id);
  if (!pool) {
    *ss << "pool id '" << pool_id << "' does not exist";
    return -ENOENT;
  }

  const string& pool_name = osd_map.get_pool_name(pool_id);

  if (pool->is_erasure()) {
    if (type == POOL_METADATA) {
      *ss << "pool '" << pool_name << "' (id '" << pool_id << "')"
         << " is an erasure-coded pool.  Use of erasure-coded pools"
         << " for CephFS metadata is not permitted";
      return -EINVAL;
    } else if (type == POOL_DATA_DEFAULT && !force) {
      *ss << "pool '" << pool_name << "' (id '" << pool_id << "')"
             " is an erasure-coded pool."
             " Use of an EC pool for the default data pool is discouraged;"
             " see the online CephFS documentation for more information."
             " Use --force to override.";
      return -EINVAL;
    } else if (!pool->allows_ecoverwrites()) {
      // non-overwriteable EC pools are only acceptable with a cache tier overlay
      if (!pool->has_tiers() || !pool->has_read_tier() || !pool->has_write_tier()) {
        *ss << "pool '" << pool_name << "' (id '" << pool_id << "')"
            << " is an erasure-coded pool, with no overwrite support";
        return -EINVAL;
      }

      // That cache tier overlay must be writeback, not readonly (it's the
      // write operations like modify+truncate we care about support for)
      const pg_pool_t *write_tier = osd_map.get_pg_pool(
          pool->write_tier);
      ceph_assert(write_tier != NULL);  // OSDMonitor shouldn't allow DNE tier
      if (write_tier->cache_mode == pg_pool_t::CACHEMODE_FORWARD
          || write_tier->cache_mode == pg_pool_t::CACHEMODE_READONLY) {
        *ss << "EC pool '" << pool_name << "' has a write tier ("
            << osd_map.get_pool_name(pool->write_tier)
            << ") that is configured "
               "to forward writes.  Use a cache mode such as 'writeback' for "
               "CephFS";
        return -EINVAL;
      }
    }
  }

  if (pool->is_tier()) {
    *ss << " pool '" << pool_name << "' (id '" << pool_id
      << "') is already in use as a cache tier.";
    return -EINVAL;
  }

  if (!force && !pool->application_metadata.empty() &&
      pool->application_metadata.count(
        pg_pool_t::APPLICATION_NAME_CEPHFS) == 0) {
    *ss << " pool '" << pool_name << "' (id '" << pool_id
        << "') has a non-CephFS application enabled.";
    return -EINVAL;
  }

  // Nothing special about this pool, so it is permissible
  return 0;
}

int FileSystemCommandHandler::is_op_allowed(
    const MonOpRequestRef& op, const FSMap& fsmap, const cmdmap_t& cmdmap,
    std::stringstream &ss) const
{
    string fs_name;
    cmd_getval(cmdmap, "fs_name", fs_name);

    // so that fsmap can filtered and the original copy is untouched.
    FSMap fsmap_copy = fsmap;
    fsmap_copy.filter(op->get_session()->get_allowed_fs_names());

    auto fs = fsmap_copy.get_filesystem(fs_name);
    if (fs == nullptr) {
      /* let "fs rm" handle idempotent case where file system does not exist */
      if (!(get_prefix() == "fs rm" && fsmap.get_filesystem(fs_name) == nullptr)) {
        ss << "Filesystem not found: '" << fs_name << "'";
        return -ENOENT;
      }
    }

    if (!op->get_session()->fs_name_capable(fs_name, MON_CAP_W)) {
      ss << "Permission denied: '" << fs_name << "'";
      return -EPERM;
    }

  return 1;
}
