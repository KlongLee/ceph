// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <cassert>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "PG.h"
#include "ScrubStore.h"
#include "scrub_machine_lstnr.h"
#include "scrubber_common.h"

class Callback;

namespace Scrub {
class ScrubMachine;
struct BuildMap;


/**
 * Reserving/freeing scrub resources at the replicas.
 *
 *  When constructed - sends reservation requests to the acting_set.
 *  A rejection triggers a "couldn't acquire the replicas' scrub resources" event.
 *  All previous requests, whether already granted or not, are explicitly released.
 *
 *  A note re performance: I've measured a few container alternatives for
 *  m_reserved_peers, with its specific usage pattern. Std::set is extremely slow, as
 *  expected. flat_set is only slightly better. Surprisingly - std::vector (with no
 *  sorting) is better than boost::small_vec. And for std::vector: no need to pre-reserve.
 */
class ReplicaReservations {
  using OrigSet = decltype(std::declval<PG>().get_actingset());

  PG* m_pg;
  PgScrubber* m_scrubber;
  OrigSet m_acting_set;
  OSDService* m_osds;
  std::vector<pg_shard_t> m_waited_for_peers;
  std::vector<pg_shard_t> m_reserved_peers;
  bool m_had_rejections{false};
  int m_pending{-1};

  void release_replica(pg_shard_t peer, epoch_t epoch);

  void send_all_done();	 ///< all reservations are granted

  /// notify the scrubber that we have failed to reserve replicas' resources
  void send_reject();

  void release_all();

 public:
  ReplicaReservations(PG* pg, PgScrubber* scrubber, pg_shard_t whoami);

  ~ReplicaReservations();

  void handle_reserve_grant(OpRequestRef op, pg_shard_t from);

  void handle_reserve_reject(OpRequestRef op, pg_shard_t from);
};

/**
 *  wraps the local OSD scrub resource reservation in an RAII wrapper
 */
class LocalReservation {
  PG* m_pg;
  OSDService* m_osds;
  bool m_holding_local_reservation{false};

 public:
  LocalReservation(PG* pg, OSDService* osds);
  ~LocalReservation();
  bool is_reserved() const { return m_holding_local_reservation; }
  void early_release();
};

/**
 *  wraps the OSD resource we are using when reserved as a replica by a scrubbing master.
 */
class ReservedByRemotePrimary {
  PG* m_pg;
  OSDService* m_osds;
  bool m_reserved_by_remote_primary{false};

 public:
  ReservedByRemotePrimary(PG* pg, OSDService* osds);
  ~ReservedByRemotePrimary();
  [[nodiscard]] bool is_reserved() const { return m_reserved_by_remote_primary; }
  void early_release();
};

/**
 * Once all replicas' scrub maps are received, we go on to compare the maps. That is -
 * unless we we have not yet completed building our own scrub map. MapsCollectionStatus
 * combines the status of waiting for both the local map and the replicas, without
 * resorting to adding dummy entries into a list.
 */
class MapsCollectionStatus {

  bool m_local_map_ready{false};
  std::vector<pg_shard_t> m_maps_awaited_for;

 public:
  [[nodiscard]] bool are_all_maps_available() const
  {
    return m_local_map_ready && m_maps_awaited_for.empty();
  }

  void mark_local_map_ready() { m_local_map_ready = true; }

  void mark_replica_map_request(pg_shard_t from_whom)
  {
    m_maps_awaited_for.push_back(from_whom);
  }

  /// \retval true if indeed waiting for this one. Otherwise: an error string
  auto mark_arriving_map(pg_shard_t from) -> std::tuple<bool, std::string_view>;

  std::vector<pg_shard_t> get_awaited() const { return m_maps_awaited_for; }

  void reset();

  std::string dump() const;

  friend ostream& operator<<(ostream& out, const MapsCollectionStatus& sf);
};


}  // namespace Scrub

/**
 * the scrub operation flags. Primary only.
 * Set at scrub start. Checked in multiple locations - mostly
 * at finish.
 */
struct scrub_flags_t {

  unsigned int priority{0};

  /**
   * set by queue_scrub() if either planned_scrub.auto_repair or
   * need_auto were set.
   * Tested at scrub end.
   */
  bool auto_repair{false};

  /// this flag indicates that we are scrubbing post repair to verify everything is fixed
  bool check_repair{false};

  /// checked at the end of the scrub, to possibly initiate a deep-scrub
  bool deep_scrub_on_error{false};  // RRR \todo handle the initialization of this one

  /**
   * the scrub session was originally marked 'must_scrub'. 'marked_must' is used
   * when determining sleep time for the scrubbing process. RRR not in original code
   */
  bool marked_must{false};

  /**
   * scrub must not be aborted.
   * Set for explicitly requested scrubs, and for scrubs originated by the pairing
   * process with the 'repair' flag set (in the RequestScrub event).
   *
   * RRR \todo clarify why different from 'marked_must'
   */
  bool required{false};
};

ostream& operator<<(ostream& out, const scrub_flags_t& sf);


/**
 * The part of PG-scrubbing code that isn't state-machine wiring.
 *
 * Why the separation? I wish to move to a different FSM implementation. Thus I
 * am forced to strongly decouple the state-machine implementation details from
 * the actual scrubbing code.
 */
class PgScrubber : public ScrubPgIF, public ScrubMachineListener {

 public:
  explicit PgScrubber(PG* pg);

  //  ------------------  the I/F exposed to the PG (ScrubPgIF) -------------

  /// are we waiting for resource reservation grants form our replicas?
  [[nodiscard]] bool is_reserving() const final;

  void send_start_scrub() final;

  void send_start_after_rec() final;

  void send_scrub_resched() final;

  void active_pushes_notification() final;

  void update_applied_notification(epoch_t epoch_queued) final;

  void send_scrub_unblock() final;

  void digest_update_notification() final;

  void send_replica_maps_ready() final;

  void send_replica_pushes_upd() final;

  void reset_epoch(epoch_t epoch_queued) final;

  /**
   *  we allow some number of preemptions of the scrub, which mean we do
   *  not block.  Then we start to block.  Once we start blocking, we do
   *  not stop until the scrub range is completed.
   */
  bool write_blocked_by_scrub(const hobject_t& soid) final;

  /// true if the given range intersects the scrub interval in any way
  bool range_intersects_scrub(const hobject_t& start, const hobject_t& end) final;

  void handle_scrub_reserve_request(OpRequestRef op) final;
  void handle_scrub_reserve_grant(OpRequestRef op, pg_shard_t from) final;
  void handle_scrub_reserve_reject(OpRequestRef op, pg_shard_t from) final;
  void handle_scrub_reserve_release(OpRequestRef op) final;
  void clear_scrub_reservations() final;  // PG::clear... fwds to here
  void unreserve_replicas() final;

  // managing scrub op registration

  bool is_scrub_registered() const final;

  void reg_next_scrub(requested_scrub_t& request_flags, bool is_explicit) final;

  void unreg_next_scrub() final;

  void scrub_requested(bool deep,
		       bool repair,
		       bool need_auto,
		       requested_scrub_t& req_flags) final;

  /**
   * Reserve local scrub resources (managed by the OSD)
   *
   * Fails if OSD's local-scrubs budget was exhausted
   * \retval 'true' if local resources reserved.
   */
  bool reserve_local() final;

  void handle_query_state(ceph::Formatter* f) final;

  void dump(ceph::Formatter* f) const override;

  // used if we are a replica

  void replica_scrub_op(OpRequestRef op) final;
  void replica_scrub(epoch_t epoch_queued) final;
  void replica_scrub_resched(epoch_t epoch_queued) final;

  /// the op priority, taken from the primary's request message
  Scrub::scrub_prio_t replica_op_priority() const final
  {
    return m_replica_request_priority;
  };

  unsigned int scrub_requeue_priority(Scrub::scrub_prio_t with_priority,
				      unsigned int suggested_priority) const final;
  /// the version that refers to m_flags.priority
  unsigned int scrub_requeue_priority(Scrub::scrub_prio_t with_priority) const final;

  void add_callback(Context* context) final { m_callbacks.push_back(context); }

  [[nodiscard]] bool are_callbacks_pending() const final  // used for an assert in PG.cc
  {
    return !m_callbacks.empty();
  }

  /// handle a message carrying a replica map
  void map_from_replica(OpRequestRef op) final;

  /**
   *  should we requeue blocked ops?
   *  Applicable to the PrimaryLogScrub derived class.
   */
  [[nodiscard]] virtual bool should_requeue_blocked_ops(
    eversion_t last_recovery_applied) const override
  {
    return false;
  }

  void scrub_clear_state(bool keep_repair_state = false) final;

  /**
   *  add to scrub statistics, but only if the soid is below the scrub start
   */
  virtual void add_stats_if_lower(const object_stat_sum_t& delta_stats,
				  const hobject_t& soid) override
  {
    ceph_assert(false);
  }

  void set_op_parameters(requested_scrub_t& request) final;

  void cleanup_store(ObjectStore::Transaction* t);

  // -------------------------------------------------------------------------------------------
  // the I/F used by the state-machine (i.e. the implementation of ScrubMachineListener)

  bool select_range() final;

  /// walk the log to find the latest update that affects our chunk
  eversion_t search_log_for_updates() const final;

  eversion_t get_last_update_applied() const final
  {
    return m_pg->recovery_state.get_last_update_applied();
  }

  void requeue_waiting() const final { m_pg->requeue_ops(m_pg->waiting_for_scrub); }

  int pending_active_pushes() const final { return m_pg->active_pushes; }

  void scrub_compare_maps() final;

  void on_init() final;
  void on_replica_init() final;
  void replica_handling_done() final;

  /// the version of 'scrub_clear_state()' that does not try to invoke FSM services
  /// (thus can be called from FSM reactions)
  void clear_pgscrub_state(bool keep_repair_state) final;

  void add_delayed_scheduling() final;

  /// \retval 'true' if a request was sent to at least one replica
  bool get_replicas_maps(bool replica_can_preempt) final;

  Scrub::FsmNext on_digest_updates() final;

  void send_replica_map(bool was_preempted) final;

  void send_remotes_reserved() final;
  void send_reservation_failure() final;

  /**
   *  does the PG have newer updates than what we (the scrubber) know?
   */
  [[nodiscard]] bool has_pg_marked_new_updates() const final;

  void set_subset_last_update(eversion_t e) final;

  void replica_update_start_epoch() final;

  void maps_compare_n_cleanup() final;

  Scrub::preemption_t* get_preemptor() final;

  int build_primary_map_chunk() final;

  int build_replica_map_chunk() final;

  void reserve_replicas() final;

  [[nodiscard]] bool was_epoch_changed() const final;

  void mark_local_map_ready() final;

  [[nodiscard]] bool are_all_maps_available() const final;

  std::string dump_awaited_maps() const final;

 protected:
  bool state_test(uint64_t m) const { return m_pg->state_test(m); }
  void state_set(uint64_t m) { m_pg->state_set(m); }
  void state_clear(uint64_t m) { m_pg->state_clear(m); }

  [[nodiscard]] bool is_primary() const { return m_pg->recovery_state.is_primary(); }

  virtual void _scrub_clear_state() {}

  utime_t m_scrub_reg_stamp;  ///< stamp we registered for

  ostream& show(ostream& out) const override;

 public:
  // -------------------------------------------------------------------------------------------

  friend ostream& operator<<(ostream& out, const PgScrubber& scrubber);

  static utime_t scrub_must_stamp() { return utime_t(1, 1); }  // -- work needed --

  virtual ~PgScrubber();  // must be defined separately, in the .cc file

  [[nodiscard]] bool is_scrub_active() const final;
  [[nodiscard]] bool is_chunky_scrub_active()
    const final;  // obsolete? only 'chunky' is supported here

 private:
  void reset_internal_state();

  void _scan_snaps(ScrubMap& smap);  // note that the (non-standard for a
				     // non-virtual) name of the function is searched
				     // for by the QA standalone tests. Do not modify.

  void clean_meta_map(ScrubMap& for_meta_scrub);

  void run_callbacks();

  [[nodiscard]] bool is_event_relevant(epoch_t queued) const;

  [[nodiscard]] bool should_abort_scrub(epoch_t queued) const;

  void send_epoch_changed();

  bool scrub_process_inconsistent();

  bool m_needs_sleep{true};  ///< should we sleep before being rescheduled? always
			     ///< 'true', unless we just got out of a sleep period


  // 'optional', as ReplicaReservations is 'RAII-designed' to guarantee un-reserving when
  //  deleted.
  std::optional<Scrub::ReplicaReservations> m_reservations;

  // 'optional', as LocalReservation is 'RAII-designed' to guarantee un-reserving when
  //  deleted.
  std::optional<Scrub::LocalReservation> m_local_osd_resource;

  // the 'remote' resource we, as a replica, grant our Primary when it is scrubbing
  std::optional<Scrub::ReservedByRemotePrimary> m_remote_osd_resource;

  void cleanup_on_finish();  // scrub_clear_state() as called for a Primary when
			     // Active->NotActive

  /// the part that actually finalizes a scrub
  void scrub_finish();

  utime_t m_sleep_started_at;

 protected:
  PG* const m_pg;

  /**
   * the derivative-specific scrub-finishing touches:
   */
  virtual void _scrub_finish() {}

  /**
   * Validate consistency of the object info and snap sets.
   */
  virtual void scrub_snapshot_metadata(ScrubMap& map, const missing_map_t& missing_digest)
  {}

  // common code used by build_primary_map_chunk() and build_replica_map_chunk():
  int build_scrub_map_chunk(ScrubMap& map,  // primary or replica?
			    ScrubMapBuilder& pos,
			    hobject_t start,
			    hobject_t end,
			    bool deep);

  std::unique_ptr<Scrub::ScrubMachine> m_fsm;
  const spg_t m_pg_id;	///< a local copy of m_pg->pg_id
  OSDService* const m_osds;
  const pg_shard_t m_pg_whoami;	 ///< a local copy of m_pg->pg_whoami;

  epoch_t m_epoch_start;  ///< epoch when scrubbing was first scheduled
  epoch_t m_epoch_queued;
  scrub_flags_t m_flags;  // RRR verify that only used by the primary

  bool m_active{false};

  eversion_t m_subset_last_update;

  std::unique_ptr<Scrub::Store> m_store;

  int num_digest_updates_pending{0};
  hobject_t m_start, m_end;  ///< note: half-closed: [start,end)

  /// Returns reference to current osdmap
  const OSDMapRef& get_osdmap() const;

  /// Returns epoch of current osdmap
  epoch_t get_osdmap_epoch() const { return get_osdmap()->get_epoch(); }

  CephContext* get_pg_cct() const { return m_pg->cct; }

  void send_start_replica();

  void send_sched_replica();

  // collected statistics
  int m_shallow_errors{0};
  int m_deep_errors{0};
  int m_fixed_count{0};

  /// Maps from objects with errors to missing peers
  HobjToShardSetMapping m_missing;

 private:
  /**
   * 'm_is_deep' - is the running scrub a deep one?
   *
   * Note that most of the code directly checks PG_STATE_DEEP_SCRUB, which is
   * primary-only (and is set earlier - when scheduling the scrub). 'm_is_deep' is
   * meaningful both for the primary and the replicas, and is used as a parameter when
   * building the scrub maps.
   */
  bool m_is_deep{false};

  inline static int fake_count{2};  // unit-tests. To be removed

  std::list<Context*> m_callbacks;

  void message_all_replicas(int32_t opcode, std::string_view op_text);

  hobject_t m_max_end;	///< Largest end that may have been sent to replicas
  ScrubMap m_primary_scrubmap;
  ScrubMapBuilder m_primary_scrubmap_pos;

  std::map<pg_shard_t, ScrubMap> m_received_maps;

  /// Cleaned std::map pending snap metadata scrub
  ScrubMap m_cleaned_meta_map;

  void _request_scrub_map(pg_shard_t replica,
			  eversion_t version,
			  hobject_t start,
			  hobject_t end,
			  bool deep,
			  bool allow_preemption);


  Scrub::MapsCollectionStatus m_maps_status;

  omap_stat_t m_omap_stats = (const struct omap_stat_t){0};

  /// Maps from objects with errors to inconsistent peers
  HobjToShardSetMapping m_inconsistent;

  /// Maps from object with errors to good peers
  std::map<hobject_t, std::list<std::pair<ScrubMap::object, pg_shard_t>>> m_authoritative;

  // ------------ members used if we are a replica

  epoch_t m_replica_epoch_start;
  epoch_t m_replica_min_epoch;	///< the min epoch needed to handle this message

  ScrubMapBuilder replica_scrubmap_pos;	 /// \todo document
  ScrubMap replica_scrubmap;		 /// \todo document
  /**
   * we mark the request priority as it arrived. It influences the queuing priority
   * when we wait for local updates
   */
  Scrub::scrub_prio_t m_replica_request_priority;

  /**
   *  Queue a XX event to be sent to the replica, to trigger a re-check of the
   * availability of the scrub map prepared by the backend.
   */
  void requeue_replica(Scrub::scrub_prio_t is_high_priority);

  /**
   * the 'preemption' "state-machine".
   * Note: originally implemented as an orthogonal sub-machine. As the states diagram is
   * extremely simple, the added complexity was not justified.
   */
  class preemption_data_t : public Scrub::preemption_t {
   public:
    preemption_data_t(PG* pg);	// the PG access is used for conf access (and logs)

    [[nodiscard]] bool is_preemptable() const final { return m_preemptable; }

    bool do_preempt() final
    {
      if (m_preempted || !m_preemptable)
	return false;

      std::lock_guard<std::mutex> lk{m_preemption_lock};
      if (!m_preemptable)
	return false;

      m_preempted = true;
      return true;
    }

    // same as 'do_preempt()' but w/o checks
    void replica_preempted() { m_preempted = true; }

    void enable_preemption()
    {
      if (are_preemptions_left()) {
	// std::lock_guard<std::mutex> lk{m_preemption_lock};
	if (!m_preempted)
	  m_preemptable = true;
      }
    }

    // used by a replica to set preemptability state according to the Primary's request
    void force_preemptability(bool is_allowed)
    {
      // no need to lock for a replica: std::lock_guard<std::mutex>
      // lk{m_preemption_lock};
      m_preempted = false;
      m_preemptable = is_allowed;
    }

    bool disable_and_test() final
    {
      std::lock_guard<std::mutex> lk{m_preemption_lock};
      m_preemptable = false;
      return m_preempted;
    }

    [[nodiscard]] bool was_preempted() const { return m_preempted; }

    size_t chunk_divisor() const { return m_size_divisor; }

    void reset();

    void adjust_parameters() final
    {
      std::lock_guard<std::mutex> lk{m_preemption_lock};

      if (m_preempted) {
	m_preempted = false;
	m_preemptable = adjust_left();
      } else {
	m_preemptable = are_preemptions_left();
      }
    }

   private:
    PG* m_pg;
    mutable std::mutex m_preemption_lock;
    bool m_preemptable{false};
    bool m_preempted{false};
    int m_left;
    size_t m_size_divisor{1};
    bool are_preemptions_left() const { return m_left > 0; }

    bool adjust_left()
    {
      if (m_left > 0) {
	--m_left;
	m_size_divisor *= 2;
      }
      return m_left > 0;
    }
  };

  preemption_data_t preemption_data;
};
