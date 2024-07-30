// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2023 IBM, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */

#ifndef MON_NVMEOFGWMAP_H_
#define MON_NVMEOFGWMAP_H_
#include <map>
#include <iostream>
#include "include/encoding.h"
#include "include/utime.h"
#include "common/Formatter.h"
#include "common/ceph_releases.h"
#include "common/version.h"
#include "common/options.h"
#include "common/Clock.h"
#include "msg/Message.h"
#include "common/ceph_time.h"
#include "NVMeofGwTypes.h"

using ceph::coarse_mono_clock;
class Monitor;

/**
 * NVMeofGwMap
 *
 * Encapsulates state maintained by NVMeofMon
 *
 * Type Summary:
 * created_gw {NvmeGroupKey -> {NvmeGwID -> NvmeGwMonState}}
 * fsm_timers {NvmeGroupKey -> {NvmeGwID -> NvmeGwTimerState}}
 *
 * NvmeGwMonState:
 * - State for a single gateway within a group
 * - Each gateway has an associated NvmeAnaGrpId (NvmeGwMonState::ana_grp_id)
 *   which identifies the ana group associated with that gateway or, if the value
 *   is REDUNDANT_GW_ANA_GROUP, that the gateway is a designated failover target.
 * - NvmeGwMonState::sm_state indicates the status of each of the group's
 *   ana_group_id with respect to that gateway.
 *
 * Invariants:
 * - NvmeGwMonState::ana_grp_id for each gateway is either
 *   REDUNDANT_GW_ANA_GROUP_ID or is unique within the group.
 * - NvmeGwMonState::sm_state contains an entry matching the
 *   NvmeGwMonState::ana_grp_id for each gateway in the group
 *   with an NvmeGwMonState::ana_grp_id value other than
 *   REDUNDANT_GW_ANA_GROUP
 * - NvmeGwMonState::sm_state will list a given ana-group-id as active for no
 *   more than one gateway within the group -- see
 *   NVMeofGwMap::validate_gw_map.
 */
class NVMeofGwMap
{
public:
  Monitor *mon = NULL;

  // epoch is for Paxos synchronization  mechanizm
  epoch_t epoch = 0;
  bool delay_propose = false;

  std::map<NvmeGroupKey, NvmeGwMonStates>  created_gws;

  // map that handles timers started by all Gateway FSMs
  std::map<NvmeGroupKey, NvmeGwTimers> fsm_timers;

  void to_gmap(std::map<NvmeGroupKey, NvmeGwMonClientStates>& Gmap) const;

  int cfg_add_gw(const NvmeGwId &gw_id, const NvmeGroupKey& group_key);

  /**
   * cfg_delete_gw
   *
   * Remove gateway gw_id from group group_key
   * - Resets ana group failover/back to/from gw_id
   * - Clears NvmeAnaGrpId owned by gw_id from other gateways in the group
   *
   * @param [in] gw_id     id of gateway to add
   * @param [in] group_key key for group containing <gw_id>
   * @return -EINVAL if gw_id is not present in group, 0 otherwise
   */
  int cfg_delete_gw(const NvmeGwId &gw_id, const NvmeGroupKey& group_key);

  /**
   * process_gw_map_ka
   *
   * Notifies NVMeofGwMap of receipt of a keep-alive beacon from
   * gateway <gw_id> in group <group_key>.  Adds <group_key>/<gw_id>
   * to map if not already present.
   *
   * Caller must ensure that <group_key>/<gw_id> is already present
   * in the map.
   *
   * @param [in] gw_id          id of gateway to add
   * @param [in] group_key      key for group containing <gw_id>
   * @param [in] last_osd_epoch most recent OSDMap epoch seen by gw_id
   *                            prior to sending beacon.
   * @param [out] propose_pending set to true if map is mutated
   */
  void process_gw_map_ka(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    epoch_t& last_osd_epoch,  bool &propose_pending);

  /**
   * process_gw_map_gw_down
   *
   * Notifies NVMeofGwMap that <group_key>/<gw_id> is down, either due
   * to receipt of an MNVMeofGwBeacon specifying that the sender is
   * unavailable or due to NvmeofGwMon::tick noting that the grace period
   * has expired.  Initiates the process of failing over any NvmeAnaGrpId's
   * for which the gateway is currently responsible.
   *
   * Caller must ensure that <group_key>/<gw_id> is already present
   * in the map.
   *
   * @param [in] gw_id          id of gateway to add
   * @param [in] group_key      key for group containing <gw_id>
   * @param [out] propose_pending set to true if map is mutated
   * @return 0 on succes, -EINVAL if <group_key>/<gw_id> is not
   *         present in map.
   */
  int process_gw_map_gw_down(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    bool &propose_pending);
  void update_active_timers(bool &propose_pending);
  void handle_abandoned_ana_groups(bool &propose_pending);
  void handle_removed_subsystems(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    const std::vector<NvmeNqnId> &current_subsystems, bool &propose_pending);
  void start_timer(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId anagrpid, uint8_t value);
private:
  void add_grp_id(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    const NvmeAnaGrpId grpid);
  void remove_grp_id(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    const NvmeAnaGrpId grpid);
  void fsm_handle_gw_down(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    gw_states_per_group_t state, NvmeAnaGrpId grpid,  bool &map_modified);
  void fsm_handle_gw_delete(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    gw_states_per_group_t state, NvmeAnaGrpId grpid,  bool &map_modified);
  void fsm_handle_gw_alive(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeGwMonState & gw_state, gw_states_per_group_t state,
    NvmeAnaGrpId grpid, epoch_t& last_osd_epoch, bool &map_modified);
  void fsm_handle_to_expired(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId grpid,  bool &map_modified);

  void find_failover_candidate(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId grpid, bool &propose_pending);
  void find_failback_gw(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    bool &propose_pending);
  void set_failover_gw_for_ANA_group(
    const NvmeGwId &failed_gw_id, const NvmeGroupKey& group_key,
    const NvmeGwId &gw_id, NvmeAnaGrpId groupid);

  int get_timer(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId anagrpid);
  void cancel_timer(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId anagrpid);
  void validate_gw_map(
    const NvmeGroupKey& group_key);

public:
  int blocklist_gw(
    const NvmeGwId &gw_id, const NvmeGroupKey& group_key,
    NvmeAnaGrpId ANA_groupid, epoch_t &epoch, bool failover);

  void encode(ceph::buffer::list &bl) const {
    using ceph::encode;
    ENCODE_START(1, 1, bl);
    encode(epoch, bl);// global map epoch

    encode(created_gws, bl); //Encode created GWs
    encode(fsm_timers, bl);
    ENCODE_FINISH(bl);
  }

  void decode(ceph::buffer::list::const_iterator &bl) {
    using ceph::decode;
    DECODE_START(1, bl);
    decode(epoch, bl);

    decode(created_gws, bl);
    decode(fsm_timers, bl);
    DECODE_FINISH(bl);
  }
};

#include "NVMeofGwSerialize.h"

#endif /* SRC_MON_NVMEOFGWMAP_H_ */
