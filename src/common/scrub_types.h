// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_SCRUB_TYPES_H
#define CEPH_SCRUB_TYPES_H

#include "include/rados/rados_types.hpp"
#include "common/hobject.h"
#include "osd/osd_types.h"


// wrappers around scrub types to offer the necessary bits other than
// the minimal set that the lirados requires
struct object_id_wrapper : public librados::object_id_t {
  object_id_wrapper(const hobject_t& hoid)
    : object_id_t{hoid.oid.name, hoid.nspace, hoid.get_key(), hoid.snap}
  {}
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bl);
};

WRITE_CLASS_ENCODER(object_id_wrapper)

inline void decode(librados::object_id_t& obj, bufferlist::iterator& bp) {
  reinterpret_cast<object_id_wrapper&>(obj).decode(bp);
}

struct osd_shard_wrapper : public librados::osd_shard_t {
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bp);
};

WRITE_CLASS_ENCODER(osd_shard_wrapper)

namespace librados {
  inline void decode(librados::osd_shard_t& shard, bufferlist::iterator& bp) {
    reinterpret_cast<osd_shard_wrapper&>(shard).decode(bp);
  }
}

struct shard_info_wrapper : public librados::shard_info_t {
public:
  shard_info_wrapper() = default;
  shard_info_wrapper(const ScrubMap::object& object) {
    set_object(object);
  }
  void set_object(const ScrubMap::object& object);
  void set_missing() {
    errors |= err_t::SHARD_MISSING;
  }
  void set_omap_digest_mismatch_oi() {
    errors |= err_t::OMAP_DIGEST_MISMATCH_OI;
  }
  void set_size_mismatch_oi() {
    errors |= err_t::SIZE_MISMATCH_OI;
  }
  void set_data_digest_mismatch_oi() {
    errors |= err_t::DATA_DIGEST_MISMATCH_OI;
  }
  void set_read_error() {
    errors |= err_t::SHARD_READ_ERR;
  }
  void set_stat_error() {
    errors |= err_t::SHARD_STAT_ERR;
  }
  void set_ec_hash_mismatch() {
    errors |= err_t::SHARD_EC_HASH_MISMATCH;
  }
  void set_ec_size_mismatch() {
    errors |= err_t::SHARD_EC_SIZE_MISMATCH;
  }
  void set_oi_attr_missing() {
    errors |= err_t::OI_ATTR_MISSING;
  }
  void set_oi_attr_corrupted() {
    errors |= err_t::OI_ATTR_CORRUPTED;
  }
  void set_ss_attr_missing() {
    errors |= err_t::SS_ATTR_MISSING;
  }
  void set_ss_attr_corrupted() {
    errors |= err_t::SS_ATTR_CORRUPTED;
  }
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bp);
};

WRITE_CLASS_ENCODER(shard_info_wrapper)

namespace librados {
  inline void decode(librados::shard_info_t& shard,
		     bufferlist::iterator& bp) {
    reinterpret_cast<shard_info_wrapper&>(shard).decode(bp);
  }
}

struct inconsistent_obj_wrapper : librados::inconsistent_obj_t {
  inconsistent_obj_wrapper(const hobject_t& hoid);

  void set_object_info_inconsistency() {
    errors |= obj_err_t::OBJECT_INFO_INCONSISTENCY;
  }
  void set_omap_digest_mismatch() {
    errors |= obj_err_t::OMAP_DIGEST_MISMATCH;
  }
  void set_data_digest_mismatch() {
    errors |= obj_err_t::DATA_DIGEST_MISMATCH;
  }
  void set_size_mismatch() {
    errors |= obj_err_t::SIZE_MISMATCH;
  }
  void set_attr_value_mismatch() {
    errors |= obj_err_t::ATTR_VALUE_MISMATCH;
  }
  void set_attr_name_mismatch() {
    errors |= obj_err_t::ATTR_NAME_MISMATCH;
  }
  void set_object_fiemap_inconsistency() {
    errors |= obj_err_t::OBJECT_FIEMAP_INCONSISTENCY;
  }
  void add_shard(const pg_shard_t& pgs, const shard_info_wrapper& shard);
  void set_auth_missing(const hobject_t& hoid,
                        const map<pg_shard_t, ScrubMap*>&,
			map<pg_shard_t, shard_info_wrapper>&,
			int &shallow_errors, int &deep_errors);
  void set_version(uint64_t ver) { version = ver; }
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bp);
};

WRITE_CLASS_ENCODER(inconsistent_obj_wrapper)

inline void decode(librados::inconsistent_obj_t& obj,
		   bufferlist::iterator& bp) {
  reinterpret_cast<inconsistent_obj_wrapper&>(obj).decode(bp);
}

struct inconsistent_snapset_wrapper : public librados::inconsistent_snapset_t {
  inconsistent_snapset_wrapper() = default;
  inconsistent_snapset_wrapper(const hobject_t& head);
  void set_headless();
  // soid claims that it is a head or a snapdir, but its SS_ATTR
  // is missing.
  void set_ss_attr_missing();
  void set_oi_attr_missing();
  void set_ss_attr_corrupted();
  void set_oi_attr_corrupted();
  // snapset with missing clone
  void set_clone_missing(snapid_t);
  // Clones that are there
  void set_clone(snapid_t);
  // the snapset is not consistent with itself
  void set_snapset_mismatch();
  // soid.snap inconsistent with snapset
  void set_head_mismatch();
  void set_size_mismatch();

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bp);
};

WRITE_CLASS_ENCODER(inconsistent_snapset_wrapper)

namespace librados {
  inline void decode(librados::inconsistent_snapset_t& snapset,
		     bufferlist::iterator& bp) {
    reinterpret_cast<inconsistent_snapset_wrapper&>(snapset).decode(bp);
  }
}

struct scrub_ls_arg_t {
  uint32_t interval;
  uint32_t get_snapsets;
  librados::object_id_t start_after;
  uint64_t max_return;
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bl);
};

WRITE_CLASS_ENCODER(scrub_ls_arg_t);

struct scrub_ls_result_t {
  epoch_t interval;
  std::vector<bufferlist> vals;
  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bl);
};

WRITE_CLASS_ENCODER(scrub_ls_result_t);

#endif
