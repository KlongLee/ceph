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

#ifndef MON_NVMEOFGWTYPES_H_
#define MON_NVMEOFGWTYPES_H_
#include <string>
#include <iomanip>
#include <map>
#include <iostream>

using NvmeGwId      = std::string;
using NvmeGroupKey  = std::pair<std::string, std::string>;
using NvmeNqnId     = std::string;
using NvmeAnaGrpId  = uint32_t;


enum class gw_states_per_group_t {
    GW_IDLE_STATE = 0, //invalid state
    GW_STANDBY_STATE,
    GW_ACTIVE_STATE,
    GW_OWNER_WAIT_FAILBACK_PREPARED,
    GW_WAIT_FAILBACK_PREPARED,
    GW_WAIT_BLOCKLIST_CMPL
};

enum class gw_exported_states_per_group_t {
    GW_EXPORTED_OPTIMIZED_STATE = 0,
    GW_EXPORTED_INACCESSIBLE_STATE
};

enum class gw_availability_t {
    GW_CREATED = 0,
    GW_AVAILABLE,
    GW_UNAVAILABLE,
    GW_DELETED
};

#define MAX_SUPPORTED_ANA_GROUPS 16
#define REDUNDANT_GW_ANA_GROUP_ID 0xFF

typedef gw_states_per_group_t          SM_STATE         [MAX_SUPPORTED_ANA_GROUPS];

using ANA_STATE = std::vector<std::pair<gw_exported_states_per_group_t, epoch_t>>;

struct BeaconNamespace {
    NvmeAnaGrpId anagrpid;
    std::string  nonce;

    // Define the equality operator
    bool operator==(const BeaconNamespace& other) const {
        return anagrpid == other.anagrpid &&
               nonce == other.nonce;
    }
};

// Beacon Listener represents an NVME Subsystem listener,
// which generally does not have to use TCP/IP.
// It is derived from the SPDK listener JSON RPC representation.
// For more details, see https://spdk.io/doc/jsonrpc.html#rpc_nvmf_listen_address.
struct BeaconListener {
    std::string address_family; // IPv4 or IPv6
    std::string address;        //
    std::string svcid;          // port

    // Define the equality operator
    bool operator==(const BeaconListener& other) const {
        return address_family == other.address_family &&
               address == other.address &&
               svcid == other.svcid;
    }
};

struct BeaconSubsystem {
    NvmeNqnId nqn;
    std::list<BeaconListener>  listeners;
    std::list<BeaconNamespace> namespaces;

    // Define the equality operator
    bool operator==(const BeaconSubsystem& other) const {
        return nqn == other.nqn &&
               listeners == other.listeners &&
               namespaces == other.namespaces;
    }
};

using BeaconSubsystems = std::list<BeaconSubsystem>;

using NvmeNonceVector    = std::vector<std::string>;
using NvmeAnaNonceMap  = std::map <NvmeAnaGrpId, NvmeNonceVector>;

struct NvmeGwMonState {
    NvmeAnaGrpId       ana_grp_id;                    // ana-group-id allocated for this GW, GW owns this group-id
    gw_availability_t  availability;                  // in absence of  beacon  heartbeat messages it becomes inavailable
    bool               last_gw_map_epoch_valid;       // "true" if the last epoch seen by the gw-client is up-to-date
    bool               performed_full_startup;        // in order to identify gws that did not exit upon failover
    BeaconSubsystems   subsystems;                    // gateway susbsystem and their state machine states
    NvmeAnaNonceMap    nonce_map;
    SM_STATE           sm_state;                      // state machine states per ANA group
    struct{
       epoch_t     osd_epoch;
       bool        is_failover;
    }blocklist_data[MAX_SUPPORTED_ANA_GROUPS];

    NvmeGwMonState(): ana_grp_id(REDUNDANT_GW_ANA_GROUP_ID) {};

    NvmeGwMonState(NvmeAnaGrpId id): ana_grp_id(id), availability(gw_availability_t::GW_CREATED), last_gw_map_epoch_valid(false),
                                    performed_full_startup(false)
    {
        for (int i = 0; i < MAX_SUPPORTED_ANA_GROUPS; i++){
            sm_state[i] = gw_states_per_group_t::GW_STANDBY_STATE;
            blocklist_data[i].osd_epoch = 0;
            blocklist_data[i].is_failover = true;
        }
    };
    void set_unavailable_state(){
        availability = gw_availability_t::GW_UNAVAILABLE;
        performed_full_startup = false; // after setting this state the next time monitor sees GW, it expects it performed the full startup
    }
    void standby_state(NvmeAnaGrpId grpid) {
           sm_state[grpid]       = gw_states_per_group_t::GW_STANDBY_STATE;
    };
    void active_state(NvmeAnaGrpId grpid) {
           sm_state[grpid]       = gw_states_per_group_t::GW_ACTIVE_STATE;
           blocklist_data[grpid].osd_epoch = 0;
    };
};

struct NqnState {
    std::string   nqn;          // subsystem NQN
    ANA_STATE     ana_state;    // subsystem's ANA state

    // constructors
    NqnState(const std::string& _nqn, const ANA_STATE& _ana_state):
        nqn(_nqn), ana_state(_ana_state)  {}
    NqnState(const std::string& _nqn, const SM_STATE& sm_state, const NvmeGwMonState & gw_created) : nqn(_nqn)  {
        for (int i=0; i < MAX_SUPPORTED_ANA_GROUPS; i++){
            std::pair<gw_exported_states_per_group_t, epoch_t> state_pair;
            state_pair.first = (  sm_state[i] == gw_states_per_group_t::GW_ACTIVE_STATE
			       || sm_state[i] == gw_states_per_group_t::GW_WAIT_BLOCKLIST_CMPL)
                           ? gw_exported_states_per_group_t::GW_EXPORTED_OPTIMIZED_STATE
                           : gw_exported_states_per_group_t::GW_EXPORTED_INACCESSIBLE_STATE;
            state_pair.second = gw_created.blocklist_data[i].osd_epoch;
            ana_state.push_back(state_pair);
        }
    }
};

typedef std::map<NvmeNqnId, NqnState> GwSubsystems;

struct NvmeGwClientState {
    NvmeAnaGrpId              group_id;
    epoch_t                   gw_map_epoch;
    GwSubsystems              subsystems;
    gw_availability_t         availability;
    NvmeGwClientState(NvmeAnaGrpId id, epoch_t epoch, gw_availability_t available):
        group_id(id),
        gw_map_epoch(epoch),
        availability(available)
    {};

    NvmeGwClientState() : NvmeGwClientState(REDUNDANT_GW_ANA_GROUP_ID, 0, gw_availability_t::GW_UNAVAILABLE) {};
};

struct NvmeGwTimerState {
   struct{
      uint32_t     timer_started; // statemachine timer(timestamp) set in some state
      uint8_t      timer_value;
      std::chrono::system_clock::time_point end_time;
   } data[MAX_SUPPORTED_ANA_GROUPS];

    NvmeGwTimerState() {
        for (int i=0; i<MAX_SUPPORTED_ANA_GROUPS; i++){
            data[i].timer_started = 0;
            data[i].timer_value = 0;
        }
    };
};

using NvmeGwMonClientStates      = std::map<NvmeGwId, NvmeGwClientState>;
using NvmeGwTimers               = std::map<NvmeGwId, NvmeGwTimerState>;
using NvmeGwMonStates            = std::map<NvmeGwId, NvmeGwMonState>;

#endif /* SRC_MON_NVMEOFGWTYPES_H_ */
