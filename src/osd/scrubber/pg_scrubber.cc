// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=2 sw=2 smarttab

#include "./pg_scrubber.h"  // '.' notation used to affect clang-format order

#include <cmath>
#include <cstddef>
#include <iostream>
#include <vector>

#include <fmt/ranges.h>

#include "debug.h"

#include "common/Clock.h"
#include "common/ceph_time.h"
#include "common/errno.h"
#include "messages/MOSDOp.h"
#include "messages/MOSDRepScrub.h"
#include "messages/MOSDRepScrubMap.h"
#include "messages/MOSDScrubReserve.h"
#include "osd/OSD.h"
#include "osd/PG.h"
#include "include/utime_fmt.h"
#include "osd/osd_types_fmt.h"
#include "osd/scrubber_common.h"

#include "ScrubStore.h"
#include "scrub_backend.h"
#include "scrub_machine.h"
#include "scrub_queue.h"

using std::list;
using std::pair;
using std::stringstream;
using std::vector;
using namespace Scrub;
using namespace std::chrono;
using namespace std::chrono_literals;
using namespace std::literals;

using schedule_result_t = Scrub::schedule_result_t;
using ScrubPGPreconds = Scrub::ScrubPGPreconds;
using ScrubPreconds = Scrub::ScrubPreconds;

#define dout_context (m_osds->cct)
#define dout_subsys ceph_subsys_osd
#undef dout_prefix
#define dout_prefix _prefix(_dout, this)

template <class T>
static ostream& _prefix(std::ostream* _dout, T* t)
{
  return t->gen_prefix(*_dout);
}

ostream& operator<<(ostream& out, const scrub_flags_t& sf)
{
  if (sf.auto_repair)
    out << " AUTO_REPAIR";
  if (sf.check_repair)
    out << " CHECK_REPAIR";
  if (sf.deep_scrub_on_error)
    out << " DEEP_SCRUB_ON_ERROR";
  if (sf.required)
    out << " REQ_SCRUB";

  return out;
}

/*
 * if the incoming message is from a previous interval, it must mean
 * PrimaryLogPG::on_change() was called when that interval ended. We can safely
 * discard the stale message.
 */
bool PgScrubber::check_interval(epoch_t epoch_to_verify)
{
  return epoch_to_verify >= m_pg->get_same_interval_since();
}

bool PgScrubber::is_message_relevant(epoch_t epoch_to_verify)
{
  if (!m_active) {
    // not scrubbing. We can assume that the scrub was already terminated, and
    // we can silently discard the incoming event.
    return false;
  }

  // is this a message from before we started this scrub?
  if (epoch_to_verify < m_epoch_start) {
    return false;
  }

  // has a new interval started?
  if (!check_interval(epoch_to_verify)) {
    // if this is a new interval, on_change() has already terminated that
    // old scrub.
    return false;
  }

  ceph_assert(is_primary());

  // were we instructed to abort?
  return verify_against_abort(epoch_to_verify);
}

/*
 * A note re the desired effect of the noscrub and nodeep-scrub flags on
 * the various scrub types:

 From docs.ceph.com (osd-internals/scrub):

 clang-format off

   Desired no-scrub flags & scrub type interactions:

   Periodic  type     |  none    |  no-scrub  | no-scrub+no-deep | no-deep
   ------------------------------------------------------------------------
   ------------------------------------------------------------------------
   periodic           |  shallow |  x         |  x               | shallow
   ------------------------------------------------------------------------
   periodic + t.f.deep|  deep    |  deep      |  x               | shallow
   ------------------------------------------------------------------------
   initiated          |  shallow |  shallow   |  shallow         | shallow
   ------------------------------------------------------------------------
   init. + t.f.deep   |  deep    |  deep      |  shallow         | shallow
   ------------------------------------------------------------------------
   initiated deep     |  deep    |  deep      |  deep            | deep
   ------------------------------------------------------------------------

   "periodic" - if !must_scrub && !must_deep_scrub;
   "initiated deep" - if must_scrub && must_deep_scrub;
   "initiated" - if must_scrub && !must_deep_scrub;

  clang-format on
 */
bool PgScrubber::verify_against_abort(epoch_t epoch_to_verify)
{
  if (!should_abort()) {
    return true;
  }

  dout(10) << fmt::format(
		  "{}: aborting. Incoming epoch: {} vs. last-aborted: {}",
		  __func__, epoch_to_verify, m_last_aborted)
	   << dendl;

  // if we were not aware of the abort before - kill the scrub.
  if (epoch_to_verify >= m_last_aborted) {
    at_scrub_failure(delay_cause_t::aborted);
    scrub_clear_state();
    m_last_aborted = std::max(epoch_to_verify, m_epoch_start);
  }
  return false;
}

bool PgScrubber::should_abort() const
{
  if (m_flags.required != !m_active_target->is_periodic()) {
    dout(1) << fmt::format(
		   "(possible bug) the required flag {} vs {}",
		   m_flags.required, m_active_target->is_periodic())
	    << dendl;
  }

  if (m_active_target->is_required()) {
    return false;  // not stopping 'required' scrubs for configuration changes
  }

  // note: deep scrubs are allowed even if 'no-scrub' is set (but not
  // 'no-deepscrub')
  if (m_is_deep) {
    if (get_osdmap()->test_flag(CEPH_OSDMAP_NODEEP_SCRUB) ||
	m_pg->pool.info.has_flag(pg_pool_t::FLAG_NODEEP_SCRUB)) {
      dout(10) << "nodeep_scrub set, aborting" << dendl;
      return true;
    }
  } else if (
      get_osdmap()->test_flag(CEPH_OSDMAP_NOSCRUB) ||
      m_pg->pool.info.has_flag(pg_pool_t::FLAG_NOSCRUB)) {
    dout(10) << "noscrub set, aborting" << dendl;
    return true;
  }

  return false;
}

//   initiating state-machine events --------------------------------

/*
 * a note re the checks performed before sending scrub-initiating messages:
 *
 * For those ('StartScrub', 'AfterRepairScrub') scrub-initiation messages that
 * possibly were in the queue while the PG changed state and became unavailable
 * for scrubbing:
 *
 * The check_interval() catches all major changes to the PG. As for the other
 * conditions we may check (and see is_message_relevant() above):
 *
 * - we are not 'active' yet, so must not check against is_active(), and:
 *
 * - the 'abort' flags were just verified (when the triggering message was
 * queued). As those are only modified in human speeds - they need not be
 * queried again.
 *
 * Some of the considerations above are also relevant to the replica-side
 * initiation
 * ('StartReplica' & 'StartReplicaNoWait').
 */

void PgScrubber::initiate_regular_scrub(epoch_t epoch_queued)
{
  dout(15) << __func__ << " epoch: " << epoch_queued << dendl;
  // we may have lost our Primary status while the message languished in the
  // queue
  if (check_interval(epoch_queued)) {
    dout(10) << "scrubber event -->> StartScrub epoch: " << epoch_queued
	     << dendl;
    reset_epoch(epoch_queued);
    m_fsm->process_event(StartScrub{});
    dout(10) << "scrubber event --<< StartScrub" << dendl;
  } else {
    clear_queued_or_active();  // also restarts snap trimming
  }
}

void PgScrubber::initiate_scrub_after_repair(epoch_t epoch_queued)
{
  dout(15) << __func__ << " epoch: " << epoch_queued << dendl;
  // we may have lost our Primary status while the message languished in the
  // queue
  if (check_interval(epoch_queued)) {
    dout(10) << "scrubber event -->> AfterRepairScrub epoch: " << epoch_queued
	     << dendl;
    reset_epoch(epoch_queued);
    m_fsm->process_event(AfterRepairScrub{});
    dout(10) << "scrubber event --<< AfterRepairScrub" << dendl;
  } else {
    clear_queued_or_active();  // also restarts snap trimming
  }
}

void PgScrubber::send_scrub_unblock(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(Unblocked{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_scrub_resched(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(InternalSchedScrub{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_start_replica(epoch_t epoch_queued,
				    Scrub::act_token_t token)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << " token: " << token << dendl;
  if (is_primary()) {
    // shouldn't happen. Ignore
    dout(1) << "got a replica scrub request while Primary!" << dendl;
    return;
  }

  if (check_interval(epoch_queued) && is_token_current(token)) {
    // save us some time by not waiting for updates if there are none
    // to wait for. Affects the transition from NotActive into either
    // ReplicaWaitUpdates or ActiveReplica.
    if (pending_active_pushes())
      m_fsm->process_event(StartReplica{});
    else
      m_fsm->process_event(StartReplicaNoWait{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_sched_replica(epoch_t epoch_queued,
				    Scrub::act_token_t token)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << " token: " << token << dendl;
  if (check_interval(epoch_queued) && is_token_current(token)) {
    m_fsm->process_event(SchedReplica{});  // retest for map availability
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::active_pushes_notification(epoch_t epoch_queued)
{
  // note: Primary only
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(ActivePushesUpd{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::update_applied_notification(epoch_t epoch_queued)
{
  // note: Primary only
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(UpdatesApplied{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::digest_update_notification(epoch_t epoch_queued)
{
  // note: Primary only
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(DigestUpdate{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_local_map_done(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(Scrub::IntLocalMapDone{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_replica_maps_ready(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(GotReplicas{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_replica_pushes_upd(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (check_interval(epoch_queued)) {
    m_fsm->process_event(ReplicaPushesUpd{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_remotes_reserved(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  // note: scrub is not active yet
  if (check_interval(epoch_queued)) {
    m_fsm->process_event(RemotesReserved{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_reservation_failure(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (check_interval(epoch_queued)) {  // do not check for 'active'!
    m_fsm->process_event(ReservationFailure{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_full_reset(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;

  m_fsm->process_event(Scrub::FullReset{});

  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_chunk_free(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (check_interval(epoch_queued)) {
    m_fsm->process_event(Scrub::SelectedChunkFree{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_chunk_busy(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (check_interval(epoch_queued)) {
    m_fsm->process_event(Scrub::ChunkIsBusy{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_get_next_chunk(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;
  if (is_message_relevant(epoch_queued)) {
    m_fsm->process_event(Scrub::NextChunk{});
  }
  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_scrub_is_finished(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;

  // can't check for "active"

  m_fsm->process_event(Scrub::ScrubFinished{});

  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

void PgScrubber::send_maps_compared(epoch_t epoch_queued)
{
  dout(10) << "scrubber event -->> " << __func__ << " epoch: " << epoch_queued
	   << dendl;

  m_fsm->process_event(Scrub::MapsCompared{});

  dout(10) << "scrubber event --<< " << __func__ << dendl;
}

// -----------------

bool PgScrubber::is_reserving() const
{
  return m_fsm->is_reserving();
}

void PgScrubber::reset_epoch(epoch_t epoch_queued)
{
  dout(10) << __func__ << " state deep? " << state_test(PG_STATE_DEEP_SCRUB)
	   << dendl;
  m_fsm->assert_not_active();

  m_epoch_start = epoch_queued;
  m_needs_sleep = true;
  ceph_assert(m_is_deep == state_test(PG_STATE_DEEP_SCRUB));
  update_op_mode_text();
}

unsigned int PgScrubber::scrub_requeue_priority(
  Scrub::scrub_prio_t with_priority) const
{
  unsigned int qu_priority = m_flags.priority;

  if (with_priority == Scrub::scrub_prio_t::high_priority) {
    qu_priority =
      std::max(qu_priority,
	       (unsigned int)m_pg->get_cct()->_conf->osd_client_op_priority);
  }
  return qu_priority;
}

unsigned int PgScrubber::scrub_requeue_priority(
  Scrub::scrub_prio_t with_priority,
  unsigned int suggested_priority) const
{
  if (with_priority == Scrub::scrub_prio_t::high_priority) {
    suggested_priority =
      std::max(suggested_priority,
	       (unsigned int)m_pg->get_cct()->_conf->osd_client_op_priority);
  }
  return suggested_priority;
}

// ///////////////////////////////////////////////////////////////////// //
// scrub-op registration handling

bool PgScrubber::is_scrub_registered() const
{
  return m_scrub_job && m_scrub_job->in_queue();
}

std::string_view PgScrubber::registration_state() const
{
  if (m_scrub_job) {
    return m_scrub_job->registration_state();
  }
  return "(no sched job)"sv;
}

void PgScrubber::rm_from_osd_scrubbing()
{
  if (m_scrub_job) {
    m_scrub_job->remove_from_osd_queue();
  }
}

void PgScrubber::on_primary_change(std::string_view caller)
{
  if (!m_scrub_job) {
    // we won't have a chance to see more logs from this function, thus:
    dout(5) << fmt::format(
		   "{}: (from {}) {}.Reg-state:{:.7}. No scrub-job!", __func__,
		   caller, (is_primary() ? "Primary" : "Replica/other"),
		   registration_state())
	    << dendl;
    return;
  }

  auto pre_reg = registration_state();

  // is there an interval change we should respond to?
  if (is_primary() && is_scrub_active()) {
    if (m_interval_start < m_pg->get_same_interval_since()) {
      dout(10) << fmt::format(
		      "{}: interval changed ({} -> {}). Aborting active scrub.",
		      __func__, m_interval_start,
		      m_pg->get_same_interval_since())
	       << dendl;
      scrub_clear_state();
    }
  }

  if (is_primary()) {
    auto applicable_conf =
	m_scrub_queue.populate_config_params(m_pg->get_pgpool().info.opts);

    m_scrub_job->init_and_queue_targets(
	m_pg->info, applicable_conf, m_scrub_queue.scrub_clock_now());
    dout(20) << fmt::format(
		    "{}: (from {}) {}.Reg-state:{:.7}. "
		    "New targets: <{}> - <{}>",
		    __func__, caller,
		    (is_primary() ? "Primary" : "Replica/other"),
		    registration_state(), m_scrub_job->shallow_target,
		    m_scrub_job->deep_target)
	     << dendl;

  } else {
    m_scrub_job->remove_from_osd_queue();
    m_after_repair_scrub_required = false;
  }

  dout(10) << fmt::format(
		  "{} (from {}): {}. <{:.5}> --> <{:.5}> ({})", __func__,
		  caller, (is_primary() ? "Primary" : "Replica/other"), pre_reg,
		  registration_state(), *m_scrub_job)
	   << dendl;
}

void PgScrubber::on_maybe_registration_change()
{
  dout(10) << fmt::format(
		  "{}: {} Reg:{}", __func__,
		  (is_primary() ? " Primary " : " Replica/other "),
		  registration_state())
	   << dendl;
  on_primary_change(__func__);
  dout(15) << __func__ << " done " << registration_state() << dendl;
}

scrub_level_t PgScrubber::scrub_requested(
    scrub_level_t scrub_level,
    scrub_type_t scrub_type)
{
  auto now_is = m_scrub_queue.scrub_clock_now();
  const bool deep_requested = (scrub_level == scrub_level_t::deep) ||
			      (scrub_type == scrub_type_t::do_repair);
  dout(5) << fmt::format(
		 "{}: {} {} scrub requested. Prev stamp: {}. Registered? {}",
		 __func__,
		 (scrub_type == scrub_type_t::do_repair ? " repair-scrub "
							: " not-repair "),
		 (deep_requested ? "Deep" : "Shallow"),
		 m_scrub_job->get_sched_time(now_is), registration_state())
	  << dendl;

  auto deduced_level =
      deep_requested ? scrub_level_t::deep : scrub_level_t::shallow;
  m_scrub_job->operator_forced_targets(deduced_level, scrub_type, now_is);
  return deduced_level;
}

void PgScrubber::recovery_completed()
{
  dout(15) << fmt::format("{}: is scrub required? {}", __func__,
                          m_after_repair_scrub_required)
           << dendl;
  if (m_after_repair_scrub_required) {
    m_after_repair_scrub_required = false;
    m_scrub_job->mark_for_after_repair();
  }
}

void PgScrubber::recalc_schedule([[maybe_unused]] epoch_t epoch_queued)
{
  auto applicable_conf = m_osds->get_scrub_services().populate_config_params(
      m_pg->get_pgpool().info.opts);

  m_scrub_job->on_periods_change(
      m_pg->info, applicable_conf, m_scrub_queue.scrub_clock_now());
}

void PgScrubber::at_scrub_failure(delay_cause_t issue)
{
  // assuming we can still depend on the 'scrubbing' flag being set;
  // Also on Queued&Active.

  // if there is a 'next' target - it might have higher priority than
  // what was just run. Let's merge the two.
  ceph_assert(m_active_target);
  m_scrub_job->on_abort(std::move(*m_active_target), issue, ceph_clock_now());
  m_active_target.reset();
}


bool PgScrubber::reserve_local()
{
  // try to create the reservation object (which translates into asking the
  // OSD for the local scrub resource). If failing - undo it immediately

  m_local_osd_resource.emplace(m_osds);
  if (m_local_osd_resource->is_reserved()) {
    dout(15) << __func__ << ": local resources reserved" << dendl;
    return true;
  }

  dout(10) << __func__ << ": failed to reserve local scrub resources" << dendl;
  m_local_osd_resource.reset();
  return false;
}


/**
 * A note re the possible error values:
 * As it happens - we do not care about the exact error value. Thus, the
 * returned schedule_result_t is now reduced to a simple 'scrub_initiated' /
 * 'no PG to scrub' / a general failure.
 */
schedule_result_t PgScrubber::start_scrubbing(
    utime_t scrub_clock_now,
    scrub_level_t lvl,
    const ScrubPGPreconds& pg_cond,
    const ScrubPreconds& preconds)
{
  m_depenalize_timer.reset();

  auto& trgt = m_scrub_job->get_target(lvl);
  dout(10) << fmt::format(
		  "{}: pg[{}] {} {} target: {}", __func__, m_pg_id,
		  (m_pg->is_active() ? "<active>" : "<not-active>"),
		  (m_pg->is_clean() ? "<clean>" : "<not-clean>"), trgt)
	   << dendl;

  // mark our target as not-in-queue. If any error is encountered - that
  // target must be requeued!
  trgt.clear_queued();

  ceph_assert(!is_queued_or_active());
  ceph_assert(!trgt.is_off());

  // a few checks. If failed - we will requeue the (modified) target
  auto failure_code = [&]() -> std::optional<Scrub::schedule_result_t> {
    if (preconds.only_deadlined && trgt.is_periodic() &&
	!trgt.over_deadline(scrub_clock_now)) {
      dout(15) << fmt::format(
		      "not scheduling scrub for pg[{}] due to {}", m_pg_id,
		      (preconds.time_permit ? "high load"
					    : "time not permitting"))
	       << dendl;
      trgt.delay_on_wrong_time(scrub_clock_now);
      return schedule_result_t::failure;
    }

    if (state_test(PG_STATE_SNAPTRIM) || state_test(PG_STATE_SNAPTRIM_WAIT)) {
      // note that the trimmer checks scrub status when setting 'snaptrim_wait'
      // (on the transition from NotTrimming to Trimming/WaitReservation),
      // i.e. some time before setting 'snaptrim'.
      dout(10) << __func__ << ": cannot scrub while snap-trimming" << dendl;
      trgt.delay_on_pg_state(scrub_clock_now);
      return schedule_result_t::failure;
    }

    // analyze the combination of the requested scrub flags, the osd/pool
    // configuration and the PG status to determine whether we should scrub now.
    auto validation_err = validate_scrub_mode(scrub_clock_now, trgt, pg_cond);
    if (validation_err) {
      // the stars do not align for starting a scrub for this PG at this time
      // (due to configuration or priority issues).
      // The reason was already reported by the callee.
      dout(10) << __func__ << ": failed to initiate a scrub" << dendl;
      return validation_err.value();
    }

    // try to reserve the local OSD resources. If failing: no harm. We will
    // be retried by the OSD later on.
    if (!reserve_local()) {
      dout(10) << __func__ << ": failed to reserve locally" << dendl;
      trgt.delay_on_no_local_resrc(scrub_clock_now);
      return schedule_result_t::failure;
    }
    return std::nullopt;
  }();

  // upon failure: we have already modified the NB of the target. Just push it
  // back to the queue
  if (failure_code.has_value()) {
    m_scrub_job->requeue_entry(lvl);
    return failure_code.value();
  }

  // we are now committed to scrubbing this PG
  set_op_parameters(trgt, pg_cond);
  m_scrub_job->scrubbing = true;

  dout(10) << __func__ << ": queueing" << dendl;
  m_osds->queue_for_scrub(m_pg, Scrub::scrub_prio_t::low_priority);
  return schedule_result_t::scrub_initiated;
}


/*
 * We are presented with the specific scheduling target that was chosen by the
 * OSD - i.e., we have a specific PG to scrub and the presumed type of scrub
 * (remember that each PG has two entries - deep and shallow - in the scrubbing
 * queue.
 *
 * Are we prevented from going on with this specific level of scrub?
 * If so, we will return a 'failure' result, and will modify the target's
 * 'not before'. The caller will requeue.
 */
std::optional<Scrub::schedule_result_t> PgScrubber::validate_scrub_mode(
    utime_t scrub_clock_now,
    Scrub::SchedTarget& trgt,
    const Scrub::ScrubPGPreconds& pg_cond)
{
  using schedule_result_t = Scrub::schedule_result_t;
  if (trgt.is_required()) {
    // 'initiated' scrubs
    dout(10) << __func__ << ": initiated (\"must\") scrub" << dendl;

    if (trgt.is_shallow() && pg_cond.has_deep_errors) {
      m_osds->clog->error() << fmt::format(
	  "osd.{} pg {} Regular scrub request, deep-scrub details will be lost",
	  m_osds->whoami, m_pg_id);
    }
    // but we will honor the request
    return std::nullopt;  // no error
  }

  // --------  a periodic scrub

  // if a shallow target:
  if (trgt.is_shallow()) {
    if (!pg_cond.allow_shallow) {
      // can't scrub at all
      dout(10) << __func__ << ": shallow not allowed" << dendl;
      trgt.delay_on_level_not_allowed(scrub_clock_now);
      return schedule_result_t::failure;
    }

    return std::nullopt;  // no error;
  }

  // A deep target:
  if (!pg_cond.allow_deep) {
    dout(10) << __func__ << ": deep not allowed" << dendl;
    trgt.delay_on_level_not_allowed(scrub_clock_now);
    return schedule_result_t::failure;
  }
  return std::nullopt;
}

// ----------------------------------------------------------------------------

bool PgScrubber::has_pg_marked_new_updates() const
{
  auto last_applied = m_pg->recovery_state.get_last_update_applied();
  dout(10) << __func__ << " recovery last: " << last_applied
	   << " vs. scrub's: " << m_subset_last_update << dendl;

  return last_applied >= m_subset_last_update;
}

void PgScrubber::set_subset_last_update(eversion_t e)
{
  m_subset_last_update = e;
  dout(15) << __func__ << " last-update: " << e << dendl;
}

void PgScrubber::on_applied_when_primary(const eversion_t& applied_version)
{
  // we are only interested in updates if we are the Primary, and in state
  // WaitLastUpdate
  if (m_fsm->is_accepting_updates() &&
      (applied_version >= m_subset_last_update)) {
    m_osds->queue_scrub_applied_update(m_pg, m_pg->is_scrub_blocking_ops());
    dout(15) << __func__ << " update: " << applied_version
	     << " vs. required: " << m_subset_last_update << dendl;
  }
}

/*
 * The selected range is set directly into 'm_start' and 'm_end'
 * setting:
 * - m_subset_last_update
 * - m_max_end
 * - end
 * - start
 */
bool PgScrubber::select_range()
{
  m_be->new_chunk();

  /* get the start and end of our scrub chunk
   *
   * Our scrub chunk has an important restriction we're going to need to
   * respect. We can't let head be start or end.
   * Using a half-open interval means that if end == head,
   * we'd scrub/lock head and the clone right next to head in different
   * chunks which would allow us to miss clones created between
   * scrubbing that chunk and scrubbing the chunk including head.
   * This isn't true for any of the other clones since clones can
   * only be created "just to the left of" head.  There is one exception
   * to this: promotion of clones which always happens to the left of the
   * left-most clone, but promote_object checks the scrubber in that
   * case, so it should be ok.  Also, it's ok to "miss" clones at the
   * left end of the range if we are a tier because they may legitimately
   * not exist (see _scrub).
   */
  int min_idx = static_cast<int>(
    std::max<int64_t>(3,
		      m_pg->get_cct()->_conf->osd_scrub_chunk_min /
			(int)preemption_data.chunk_divisor()));

  int max_idx = static_cast<int>(
    std::max<int64_t>(min_idx,
		      m_pg->get_cct()->_conf->osd_scrub_chunk_max /
			(int)preemption_data.chunk_divisor()));

  dout(10) << __func__ << " Min: " << min_idx << " Max: " << max_idx
	   << " Div: " << preemption_data.chunk_divisor() << dendl;

  hobject_t start = m_start;
  hobject_t candidate_end;
  std::vector<hobject_t> objects;
  int ret = m_pg->get_pgbackend()->objects_list_partial(start,
							min_idx,
							max_idx,
							&objects,
							&candidate_end);
  ceph_assert(ret >= 0);

  if (!objects.empty()) {

    hobject_t back = objects.back();
    while (candidate_end.is_head() && candidate_end == back.get_head()) {
      candidate_end = back;
      objects.pop_back();
      if (objects.empty()) {
	ceph_assert(0 ==
		    "Somehow we got more than 2 objects which"
		    "have the same head but are not clones");
      }
      back = objects.back();
    }

    if (candidate_end.is_head()) {
      ceph_assert(candidate_end != back.get_head());
      candidate_end = candidate_end.get_object_boundary();
    }

  } else {
    ceph_assert(candidate_end.is_max());
  }

  // is that range free for us? if not - we will be rescheduled later by whoever
  // triggered us this time

  if (!m_pg->_range_available_for_scrub(m_start, candidate_end)) {
    // we'll be requeued by whatever made us unavailable for scrub
    dout(10) << __func__ << ": scrub blocked somewhere in range "
	     << "[" << m_start << ", " << candidate_end << ")" << dendl;
    return false;
  }

  m_end = candidate_end;
  if (m_end > m_max_end)
    m_max_end = m_end;

  dout(15) << __func__ << " range selected: " << m_start << " //// " << m_end
	   << " //// " << m_max_end << dendl;

  // debug: be 'blocked' if told so by the 'pg scrub_debug block' asok command
  if (m_debug_blockrange > 0) {
    m_debug_blockrange--;
    return false;
  }
  return true;
}

void PgScrubber::select_range_n_notify()
{
  if (select_range()) {
    // the next chunk to handle is not blocked
    dout(20) << __func__ << ": selection OK" << dendl;
    m_osds->queue_scrub_chunk_free(m_pg, Scrub::scrub_prio_t::low_priority);

  } else {
    // we will wait for the objects range to become available for scrubbing
    dout(10) << __func__ << ": selected chunk is busy" << dendl;
    m_osds->queue_scrub_chunk_busy(m_pg, Scrub::scrub_prio_t::low_priority);
  }
}

bool PgScrubber::write_blocked_by_scrub(const hobject_t& soid)
{
  if (soid < m_start || soid >= m_end) {
    return false;
  }

  dout(20) << __func__ << " " << soid << " can preempt? "
	   << preemption_data.is_preemptable() << " already preempted? "
	   << preemption_data.was_preempted() << dendl;

  if (preemption_data.was_preempted()) {
    // otherwise - write requests arriving while 'already preempted' is set
    // but 'preemptable' is not - will not be allowed to continue, and will
    // not be requeued on time.
    return false;
  }

  if (preemption_data.is_preemptable()) {

    dout(10) << __func__ << " " << soid << " preempted" << dendl;

    // signal the preemption
    preemption_data.do_preempt();
    m_end = m_start;  // free the range we were scrubbing

    return false;
  }
  return true;
}

bool PgScrubber::range_intersects_scrub(const hobject_t& start,
					const hobject_t& end)
{
  // does [start, end] intersect [scrubber.start, scrubber.m_max_end)
  return (start < m_max_end && end >= m_start);
}

Scrub::BlockedRangeWarning PgScrubber::acquire_blocked_alarm()
{
  int grace = get_pg_cct()->_conf->osd_blocked_scrub_grace_period;
  if (grace == 0) {
    // we will not be sending any alarms re the blocked object
    dout(10)
      << __func__
      << ": blocked-alarm disabled ('osd_blocked_scrub_grace_period' set to 0)"
      << dendl;
    return nullptr;
  }
  ceph::timespan grace_period{m_debug_blockrange ? 4s : seconds{grace}};
  dout(20) << fmt::format(": timeout:{}",
			  std::chrono::duration_cast<seconds>(grace_period))
	   << dendl;
  return std::make_unique<blocked_range_t>(m_osds,
					   grace_period,
					   *this,
					   m_pg_id);
}

/**
 *  if we are required to sleep:
 *	arrange a callback sometimes later.
 *	be sure to be able to identify a stale callback.
 *  Otherwise: perform a requeue (i.e. - rescheduling thru the OSD queue)
 *    anyway.
 */
void PgScrubber::add_delayed_scheduling()
{
  m_end = m_start;  // not blocking any range now

  const milliseconds sleep_time{
      m_needs_sleep
	  ? m_osds->get_scrub_services().required_sleep_time(m_flags.required)
	  : 0ms};
  dout(15) << fmt::format(
		  "{} sleep: {}ms. needed? {}", __func__, sleep_time.count(),
		  m_needs_sleep)
	   << dendl;

  if (sleep_time.count()) {
    // schedule a transition for some 'sleep_time' ms in the future

    m_needs_sleep = false;
    m_sleep_started_at = m_scrub_queue.scrub_clock_now();

    // the following log line is used by osd-scrub-test.sh
    dout(20) << __func__ << " scrub state is PendingTimer, sleeping" << dendl;

    // the 'delayer' for crimson is different. Will be factored out.

    spg_t pgid = m_pg->get_pgid();
    auto callbk = new LambdaContext([osds = m_osds, pgid, scrbr = this](
					[[maybe_unused]] int r) mutable {
      PGRef pg = osds->osd->lookup_lock_pg(pgid);
      if (!pg) {
	lgeneric_subdout(g_ceph_context, osd, 10)
	    << "scrub_requeue_callback: Could not find "
	    << "PG " << pgid << " can't complete scrub requeue after sleep"
	    << dendl;
	return;
      }
      scrbr->m_needs_sleep = true;
      lgeneric_dout(scrbr->get_pg_cct(), 7)
	  << "scrub_requeue_callback: slept for "
	  << ceph_clock_now() - scrbr->m_sleep_started_at
	  << ", re-queuing scrub" << dendl;

      scrbr->m_sleep_started_at = utime_t{};
      osds->queue_for_scrub_resched(&(*pg), Scrub::scrub_prio_t::low_priority);
      pg->unlock();
    });

    std::lock_guard l(m_osds->sleep_lock);
    m_osds->sleep_timer.add_event_after(sleep_time.count() / 1000.0f, callbk);

  } else {
    // just a requeue
    m_osds->queue_for_scrub_resched(m_pg, Scrub::scrub_prio_t::high_priority);
  }
}

eversion_t PgScrubber::search_log_for_updates() const
{
  auto& projected = m_pg->projected_log.log;
  auto pi = find_if(projected.crbegin(),
		    projected.crend(),
		    [this](const auto& e) -> bool {
		      return e.soid >= m_start && e.soid < m_end;
		    });

  if (pi != projected.crend())
    return pi->version;

  // there was no relevant update entry in the log

  auto& log = m_pg->recovery_state.get_pg_log().get_log().log;
  auto p = find_if(log.crbegin(), log.crend(), [this](const auto& e) -> bool {
    return e.soid >= m_start && e.soid < m_end;
  });

  if (p == log.crend())
    return eversion_t{};
  else
    return p->version;
}

void PgScrubber::get_replicas_maps(bool replica_can_preempt)
{
  dout(10) << __func__ << " started in epoch/interval: " << m_epoch_start << "/"
	   << m_interval_start << " pg same_interval_since: "
	   << m_pg->info.history.same_interval_since << dendl;

  m_primary_scrubmap_pos.reset();

  // ask replicas to scan and send maps
  for (const auto& i : m_pg->get_actingset()) {

    if (i == m_pg_whoami)
      continue;

    m_maps_status.mark_replica_map_request(i);
    _request_scrub_map(i,
		       m_subset_last_update,
		       m_start,
		       m_end,
		       m_is_deep,
		       replica_can_preempt);
  }

  dout(10) << __func__ << " awaiting" << m_maps_status << dendl;
}

bool PgScrubber::was_epoch_changed() const
{
  // for crimson we have m_pg->get_info().history.same_interval_since
  dout(10) << __func__ << " epoch_start: " << m_interval_start
	   << " from pg: " << m_pg->get_history().same_interval_since << dendl;

  return m_interval_start < m_pg->get_history().same_interval_since;
}

void PgScrubber::mark_local_map_ready()
{
  m_maps_status.mark_local_map_ready();
}

bool PgScrubber::are_all_maps_available() const
{
  return m_maps_status.are_all_maps_available();
}

std::string PgScrubber::dump_awaited_maps() const
{
  return m_maps_status.dump();
}

void PgScrubber::update_op_mode_text()
{
  auto visible_repair = state_test(PG_STATE_REPAIR);
  m_mode_desc =
    (visible_repair ? "repair" : (m_is_deep ? "deep-scrub" : "scrub"));

  dout(10) << __func__
	   << ": repair: visible: " << (visible_repair ? "true" : "false")
	   << ", internal: " << (m_is_repair ? "true" : "false")
	   << ". Displayed: " << m_mode_desc << dendl;
}

void PgScrubber::_request_scrub_map(pg_shard_t replica,
				    eversion_t version,
				    hobject_t start,
				    hobject_t end,
				    bool deep,
				    bool allow_preemption)
{
  ceph_assert(replica != m_pg_whoami);
  dout(10) << __func__ << " scrubmap from osd." << replica
	   << (deep ? " deep" : " shallow") << dendl;

  auto repscrubop = new MOSDRepScrub(spg_t(m_pg->info.pgid.pgid, replica.shard),
				     version,
				     get_osdmap_epoch(),
				     m_pg->get_last_peering_reset(),
				     start,
				     end,
				     deep,
				     allow_preemption,
				     m_flags.priority,
				     m_pg->ops_blocked_by_scrub());

  // default priority. We want the replica-scrub processed prior to any recovery
  // or client io messages (we are holding a lock!)
  m_osds->send_message_osd_cluster(replica.osd, repscrubop, get_osdmap_epoch());
}

void PgScrubber::cleanup_store(ObjectStore::Transaction* t)
{
  if (!m_store)
    return;

  struct OnComplete : Context {
    std::unique_ptr<Scrub::Store> store;
    explicit OnComplete(std::unique_ptr<Scrub::Store>&& store)
	: store(std::move(store))
    {}
    void finish(int) override {}
  };
  m_store->cleanup(t);
  t->register_on_complete(new OnComplete(std::move(m_store)));
  ceph_assert(!m_store);
}

void PgScrubber::on_init()
{
  // going upwards from 'inactive'
  ceph_assert(!is_scrub_active());
  m_pg->reset_objects_scrubbed();
  preemption_data.reset();
  m_pg->publish_stats_to_osd();
  m_interval_start = m_pg->get_history().same_interval_since;

  dout(10) << __func__ << " start same_interval:" << m_interval_start << dendl;

  m_be = std::make_unique<ScrubBackend>(
    *this,
    *m_pg,
    m_pg_whoami,
    m_is_repair,
    m_is_deep ? scrub_level_t::deep : scrub_level_t::shallow,
    m_pg->get_actingset());

  //  create a new store
  {
    ObjectStore::Transaction t;
    cleanup_store(&t);
    m_store.reset(
      Scrub::Store::create(m_pg->osd->store, &t, m_pg->info.pgid, m_pg->coll));
    m_pg->osd->store->queue_transaction(m_pg->ch, std::move(t), nullptr);
  }

  m_start = m_pg->info.pgid.pgid.get_hobj_start();
  m_active = true;
  ++m_sessions_counter;
  m_pg->publish_stats_to_osd();
}


void PgScrubber::on_repl_reservation_failure()
{
  const seconds penalty_period =
      seconds{m_pg->get_cct()->_conf.get_val<int64_t>(
	  "osd_scrub_busy_replicas_penalty")};
  dout(10) << fmt::format(
		  "{}: penalty period: {}s", __func__, penalty_period.count())
	   << dendl;

  if (m_scrub_job->on_reservation_failure(
	  penalty_period, std::move(*m_active_target))) {


    utime_t now_is = m_scrub_queue.scrub_clock_now();
    m_depenalize_timer = std::make_unique<depenalize_timer_t>(
	m_osds, this, now_is + utime_t{penalty_period});
  }

  m_active_target.reset();
  clear_pgscrub_state();
}

PgScrubber::depenalize_timer_t::depenalize_timer_t(
    OSDService* osds,
    PgScrubber* scrbr,
    utime_t timeout)
    : m_osds{osds}
    , m_scrbr{*scrbr}
{
  m_depenalize_cb = new LambdaContext(
      [this, scrbr = scrbr, pgid = scrbr->m_pg_id]([[maybe_unused]] int r) {
	if (!m_depenalize_cb) {
	  // already cancelled
	  return;
	}
	lgeneric_dout(g_ceph_context, 7)
	    << "depenalize_timer_t: callback activated" << dendl;

	// send an event to the scrubber to handle the timeout
	PGRef pg = m_osds->osd->lookup_lock_pg(pgid);
	if (!pg) {
	  lgeneric_subdout(g_ceph_context, osd, 10)
	      << "depenalize_timer_t: Could not find PG " << pgid << dendl;
	  m_depenalize_cb = nullptr;
	  return;
	}
	m_depenalize_cb = nullptr;
	lgeneric_dout(g_ceph_context, 10)
	    << fmt::format("depenalize_timer_t: un-penalizing {}", pgid)
	    << dendl;

	scrbr->m_scrub_job->un_penalize();
	pg->unlock();
      });

  std::lock_guard l(m_osds->sleep_lock);
  // add_event_after() deletes the callback if failing to add (and returns
  // nullptr)
  m_depenalize_cb =
      m_osds->sleep_timer.add_event_after(timeout, m_depenalize_cb);
}

PgScrubber::depenalize_timer_t::~depenalize_timer_t()
{
  if (m_depenalize_cb) {
    std::lock_guard l(m_osds->sleep_lock);
    m_osds->sleep_timer.cancel_event(m_depenalize_cb);
  }
}


void PgScrubber::on_replica_init()
{
  dout(10) << __func__ << " called with 'active' "
	   << (m_active ? "set" : "cleared") << dendl;
  if (!m_active) {
    m_be = std::make_unique<ScrubBackend>(
      *this, *m_pg, m_pg_whoami, m_is_repair,
      m_is_deep ? scrub_level_t::deep : scrub_level_t::shallow);
    m_active = true;
    ++m_sessions_counter;
  }
}

int PgScrubber::build_primary_map_chunk()
{
  epoch_t map_building_since = m_pg->get_osdmap_epoch();
  dout(20) << __func__ << ": initiated at epoch " << map_building_since
	   << dendl;

  auto ret = build_scrub_map_chunk(m_be->get_primary_scrubmap(),
				   m_primary_scrubmap_pos,
				   m_start,
				   m_end,
				   m_is_deep);

  if (ret == -EINPROGRESS) {
    // reschedule another round of asking the backend to collect the scrub data
    m_osds->queue_for_scrub_resched(m_pg, Scrub::scrub_prio_t::low_priority);
  }
  return ret;
}


int PgScrubber::build_replica_map_chunk()
{
  dout(10) << __func__ << " interval start: " << m_interval_start
	   << " current token: " << m_current_token
	   << " epoch: " << m_epoch_start << " deep: " << m_is_deep << dendl;

  ceph_assert(m_be);

  auto ret = build_scrub_map_chunk(replica_scrubmap,
				   replica_scrubmap_pos,
				   m_start,
				   m_end,
				   m_is_deep);

  switch (ret) {

    case -EINPROGRESS:
      // must wait for the backend to finish. No external event source.
      // (note: previous version used low priority here. Now switched to using
      // the priority of the original message)
      m_osds->queue_for_rep_scrub_resched(m_pg,
					  m_replica_request_priority,
					  m_flags.priority,
					  m_current_token);
      break;

    case 0: {
      // finished!

      auto required_fixes = m_be->replica_clean_meta(replica_scrubmap,
						     m_end.is_max(),
						     m_start,
						     get_snap_mapper_accessor());
      // actuate snap-mapper changes:
      apply_snap_mapper_fixes(required_fixes);

      // the local map has been created. Send it to the primary.
      // Note: once the message reaches the Primary, it may ask us for another
      // chunk - and we better be done with the current scrub. Thus - the
      // preparation of the reply message is separate, and we clear the scrub
      // state before actually sending it.

      auto reply = prep_replica_map_msg(PreemptionNoted::no_preemption);
      replica_handling_done();
      dout(15) << __func__ << " chunk map sent " << dendl;
      send_replica_map(reply);
    } break;

    default:
      // negative retval: build_scrub_map_chunk() signalled an error
      // Pre-Pacific code ignored this option, treating it as a success.
      // \todo Add an error flag in the returning message.
      dout(1) << "Error! Aborting. ActiveReplica::react(SchedReplica) Ret: "
	      << ret << dendl;
      replica_handling_done();
      // only in debug mode for now:
      assert(false && "backend error");
      break;
  };

  return ret;
}

int PgScrubber::build_scrub_map_chunk(ScrubMap& map,
				      ScrubMapBuilder& pos,
				      hobject_t start,
				      hobject_t end,
				      bool deep)
{
  dout(10) << __func__ << " [" << start << "," << end << ") "
	   << " pos " << pos << " Deep: " << deep << dendl;

  // start
  while (pos.empty()) {

    pos.deep = deep;
    map.valid_through = m_pg->info.last_update;

    // objects
    vector<ghobject_t> rollback_obs;
    pos.ret = m_pg->get_pgbackend()->objects_list_range(start,
							end,
							&pos.ls,
							&rollback_obs);
    dout(10) << __func__ << " while pos empty " << pos.ret << dendl;
    if (pos.ret < 0) {
      dout(5) << "objects_list_range error: " << pos.ret << dendl;
      return pos.ret;
    }
    dout(10) << __func__ << " pos.ls.empty()? " << (pos.ls.empty() ? "+" : "-")
	     << dendl;
    if (pos.ls.empty()) {
      break;
    }
    m_pg->_scan_rollback_obs(rollback_obs);
    pos.pos = 0;
    return -EINPROGRESS;
  }

  // scan objects
  while (!pos.done()) {

    int r = m_pg->get_pgbackend()->be_scan_list(map, pos);
    dout(30) << __func__ << " BE returned " << r << dendl;
    if (r == -EINPROGRESS) {
      dout(20) << __func__ << " in progress" << dendl;
      return r;
    }
  }

  // finish
  dout(20) << __func__ << " finishing" << dendl;
  ceph_assert(pos.done());
  repair_oinfo_oid(map);

  dout(20) << __func__ << " done, got " << map.objects.size() << " items"
	   << dendl;
  return 0;
}

/// \todo consider moving repair_oinfo_oid() back to the backend
void PgScrubber::repair_oinfo_oid(ScrubMap& smap)
{
  for (auto i = smap.objects.rbegin(); i != smap.objects.rend(); ++i) {

    const hobject_t& hoid = i->first;
    ScrubMap::object& o = i->second;

    if (o.attrs.find(OI_ATTR) == o.attrs.end()) {
      continue;
    }
    bufferlist bl;
    bl.push_back(o.attrs[OI_ATTR]);
    object_info_t oi;
    try {
      oi.decode(bl);
    } catch (...) {
      continue;
    }

    if (oi.soid != hoid) {
      ObjectStore::Transaction t;
      OSDriver::OSTransaction _t(m_pg->osdriver.get_transaction(&t));

      m_osds->clog->error()
        << "osd." << m_pg_whoami << " found object info error on pg " << m_pg_id
        << " oid " << hoid << " oid in object info: " << oi.soid
        << "...repaired";
      // Fix object info
      oi.soid = hoid;
      bl.clear();
      encode(oi,
             bl,
             m_pg->get_osdmap()->get_features(CEPH_ENTITY_TYPE_OSD, nullptr));

      bufferptr bp(bl.c_str(), bl.length());
      o.attrs[OI_ATTR] = bp;

      t.setattr(m_pg->coll, ghobject_t(hoid), OI_ATTR, bl);
      int r = m_pg->osd->store->queue_transaction(m_pg->ch, std::move(t));
      if (r != 0) {
        derr << __func__ << ": queue_transaction got " << cpp_strerror(r)
             << dendl;
      }
    }
  }
}


void PgScrubber::run_callbacks()
{
  std::list<Context*> to_run;
  to_run.swap(m_callbacks);

  for (auto& tr : to_run) {
    tr->complete(0);
  }
}

void PgScrubber::persist_scrub_results(inconsistent_objs_t&& all_errors)
{
  dout(10) << __func__ << " " << all_errors.size() << " errors" << dendl;

  for (auto& e : all_errors) {
    std::visit([this](auto& e) { m_store->add_error(m_pg->pool.id, e); }, e);
  }

  ObjectStore::Transaction t;
  m_store->flush(&t);
  m_osds->store->queue_transaction(m_pg->ch, std::move(t), nullptr);
}

void PgScrubber::apply_snap_mapper_fixes(
  const std::vector<snap_mapper_fix_t>& fix_list)
{
  dout(15) << __func__ << " " << fix_list.size() << " fixes" << dendl;

  if (fix_list.empty()) {
    return;
  }

  ObjectStore::Transaction t;
  OSDriver::OSTransaction t_drv(m_pg->osdriver.get_transaction(&t));

  for (auto& [fix_op, hoid, snaps, bogus_snaps] : fix_list) {

    if (fix_op != snap_mapper_op_t::add) {

      // must remove the existing snap-set before inserting the correct one
      if (auto r = m_pg->snap_mapper.remove_oid(hoid, &t_drv); r < 0) {

	derr << __func__ << ": remove_oid returned " << cpp_strerror(r)
	     << dendl;
	if (fix_op == snap_mapper_op_t::update) {
	  // for inconsistent snapmapper objects (i.e. for
	  // snap_mapper_op_t::inconsistent), we don't fret if we can't remove
	  // the old entries
	  ceph_abort();
	}
      }

      m_osds->clog->error() << fmt::format(
	"osd.{} found snap mapper error on pg {} oid {} snaps in mapper: {}, "
	"oi: "
	"{} ...repaired",
	m_pg_whoami,
	m_pg_id,
	hoid,
	bogus_snaps,
	snaps);

    } else {

      m_osds->clog->error() << fmt::format(
	"osd.{} found snap mapper error on pg {} oid {} snaps missing in "
	"mapper, should be: {} ...repaired",
	m_pg_whoami,
	m_pg_id,
	hoid,
	snaps);
    }

    // now - insert the correct snap-set
    m_pg->snap_mapper.add_oid(hoid, snaps, &t_drv);
  }

  // wait for repair to apply to avoid confusing other bits of the system.
  {
    dout(15) << __func__ << " wait on repair!" << dendl;

    ceph::condition_variable my_cond;
    ceph::mutex my_lock = ceph::make_mutex("PG::_scan_snaps my_lock");
    int e = 0;
    bool done{false};

    t.register_on_applied_sync(new C_SafeCond(my_lock, my_cond, &done, &e));

    if (e = m_pg->osd->store->queue_transaction(m_pg->ch, std::move(t));
	e != 0) {
      derr << __func__ << ": queue_transaction got " << cpp_strerror(e)
	   << dendl;
    } else {
      std::unique_lock l{my_lock};
      my_cond.wait(l, [&done] { return done; });
      ceph_assert(m_pg->osd->store);  // RRR why?
    }
    dout(15) << __func__ << " wait on repair - done" << dendl;
  }
}

void PgScrubber::maps_compare_n_cleanup()
{
  m_pg->add_objects_scrubbed_count(m_be->get_primary_scrubmap().objects.size());

  auto required_fixes =
    m_be->scrub_compare_maps(m_end.is_max(), get_snap_mapper_accessor());
  if (!required_fixes.inconsistent_objs.empty()) {
    if (state_test(PG_STATE_REPAIR)) {
      dout(10) << __func__ << ": discarding scrub results (repairing)" << dendl;
    } else {
      // perform the ordered scrub-store I/O:
      persist_scrub_results(std::move(required_fixes.inconsistent_objs));
    }
  }

  // actuate snap-mapper changes:
  apply_snap_mapper_fixes(required_fixes.snap_fix_list);

  auto chunk_err_counts = m_be->get_error_counts();
  m_shallow_errors += chunk_err_counts.shallow_errors;
  m_deep_errors += chunk_err_counts.deep_errors;

  m_start = m_end;
  run_callbacks();
  requeue_waiting();
  m_osds->queue_scrub_maps_compared(m_pg, Scrub::scrub_prio_t::low_priority);
}

Scrub::preemption_t& PgScrubber::get_preemptor()
{
  return preemption_data;
}

/*
 * Process note: called for the arriving "give me your map, replica!" request.
 * Unlike the original implementation, we do not requeue the Op waiting for
 * updates. Instead - we trigger the FSM.
 */
void PgScrubber::replica_scrub_op(OpRequestRef op)
{
  op->mark_started();
  auto msg = op->get_req<MOSDRepScrub>();
  dout(10) << __func__ << " pg:" << m_pg->pg_id
	   << " Msg: map_epoch:" << msg->map_epoch
	   << " min_epoch:" << msg->min_epoch << " deep?" << msg->deep << dendl;

  // are we still processing a previous scrub-map request without noticing that
  // the interval changed? won't see it here, but rather at the reservation
  // stage.

  if (msg->map_epoch < m_pg->info.history.same_interval_since) {
    dout(10) << "replica_scrub_op discarding old replica_scrub from "
	     << msg->map_epoch << " < "
	     << m_pg->info.history.same_interval_since << dendl;

    // is there a general sync issue? are we holding a stale reservation?
    // not checking now - assuming we will actively react to interval change.

    return;
  }

  if (is_queued_or_active()) {
    // this is bug!
    // Somehow, we have received a new scrub request from our Primary, before
    // having finished with the previous one. Did we go through an interval
    // change without reseting the FSM? Possible responses:
    // - crashing (the original assert_not_active() implemented that one), or
    // - trying to recover:
    //  - (logging enough information to debug this scenario)
    //  - reset the FSM.
    m_osds->clog->warn() << fmt::format(
      "{}: error: a second scrub-op received while handling the previous one",
      __func__);

    scrub_clear_state();
    m_osds->clog->warn() << fmt::format(
      "{}: after a reset. Now handling the new OP",
      __func__);
  }
  // make sure the FSM is at NotActive
  m_fsm->assert_not_active();

  replica_scrubmap = ScrubMap{};
  replica_scrubmap_pos = ScrubMapBuilder{};

  m_replica_min_epoch = msg->min_epoch;
  m_start = msg->start;
  m_end = msg->end;
  m_max_end = msg->end;
  m_is_deep = msg->deep;
  m_interval_start = m_pg->info.history.same_interval_since;
  m_replica_request_priority = msg->high_priority
				 ? Scrub::scrub_prio_t::high_priority
				 : Scrub::scrub_prio_t::low_priority;
  m_flags.priority = msg->priority ? msg->priority : m_pg->get_scrub_priority();

  preemption_data.reset();
  preemption_data.force_preemptability(msg->allow_preemption);

  replica_scrubmap_pos.reset();	 // needed? RRR

  set_queued_or_active();
  m_osds->queue_for_rep_scrub(m_pg,
			      m_replica_request_priority,
			      m_flags.priority,
			      m_current_token);
}

void PgScrubber::set_op_parameters(
    Scrub::SchedTarget& trgt,
    const Scrub::ScrubPGPreconds& pg_cond)
{
  dout(10) << fmt::format("{}: {}: conditions: {}", __func__, trgt, pg_cond)
	   << dendl;

  // we are now committed to scrubbing this pg. The 'scheduling target' being
  // passed here is the one we have chosen to scrub. It will be moved into
  // m_active_target (as it contains relevant info about the current scrub),
  // and a new target object will be created in the ScrubJob, to be used for
  // scheduling the next scrub of this level.
  set_queued_or_active();
  m_active_target = m_scrub_job->get_moved_target(trgt.level());
  // remove our sister target from the queue
  m_scrub_job->dequeue_entry(ScrubJob::the_other_level(trgt.level()));

  // write down the epoch of starting a new scrub. Will be used
  // to discard stale messages from previous aborted scrubs.
  m_epoch_start = m_pg->get_osdmap_epoch();

  m_flags.check_repair = trgt.urgency() == urgency_t::after_repair;
  bool can_auto_repair =
      trgt.is_deep() && trgt.is_periodic() && pg_cond.can_autorepair;
  if (can_auto_repair) {
    // maintaining an existing log line
    dout(20) << __func__ << ": auto repair with deep scrubbing" << dendl;
  }

  m_flags.auto_repair = can_auto_repair || trgt.get_auto_repair();

  if (trgt.is_periodic()) {
    // lower urgency
    m_flags.required = false;
    m_flags.priority = m_pg->get_scrub_priority();
  } else {
    // 'required' scrubs
    m_flags.required = true;
    m_flags.priority = get_pg_cct()->_conf->osd_requested_scrub_priority;
  }

  // 'deep-on-error' is set for periodic shallow scrubs, if allowed
  // by the environment
  if (trgt.is_shallow() && pg_cond.can_autorepair && trgt.is_periodic()) {
    m_flags.deep_scrub_on_error = true;
    dout(10) << fmt::format(
		    "{}: auto repair with scrubbing, rescrub if errors found",
		    __func__)
	     << dendl;
  }

  state_set(PG_STATE_SCRUBBING);

  // will we be deep-scrubbing?
  if (trgt.is_deep()) {
    state_set(PG_STATE_DEEP_SCRUB);
    m_is_deep = true;
  } else {
    m_is_deep = false;
  }

  // m_is_repair is set for either 'must_repair' or 'repair-on-the-go' (i.e.
  // deep-scrub with the auto_repair configuration flag set). m_is_repair value
  // determines the scrubber behavior.
  //
  // PG_STATE_REPAIR, on the other hand, is only used for status reports (inc.
  // the PG status as appearing in the logs).
  m_is_repair = trgt.get_do_repair() || m_flags.auto_repair;
  if (trgt.get_do_repair()) {
    state_set(PG_STATE_REPAIR);
    update_op_mode_text();
  }

  // the publishing here is required for tests synchronization
  m_pg->publish_stats_to_osd();
}


ScrubMachineListener::MsgAndEpoch PgScrubber::prep_replica_map_msg(
  PreemptionNoted was_preempted)
{
  dout(10) << __func__ << " min epoch:" << m_replica_min_epoch << dendl;

  auto reply = make_message<MOSDRepScrubMap>(
    spg_t(m_pg->info.pgid.pgid, m_pg->get_primary().shard),
    m_replica_min_epoch,
    m_pg_whoami);

  reply->preempted = (was_preempted == PreemptionNoted::preempted);
  ::encode(replica_scrubmap, reply->get_data());

  return ScrubMachineListener::MsgAndEpoch{reply, m_replica_min_epoch};
}

void PgScrubber::send_replica_map(const MsgAndEpoch& preprepared)
{
  m_pg->send_cluster_message(m_pg->get_primary().osd,
			     preprepared.m_msg,
			     preprepared.m_epoch,
			     false);
}

void PgScrubber::send_preempted_replica()
{
  auto reply = make_message<MOSDRepScrubMap>(
    spg_t{m_pg->info.pgid.pgid, m_pg->get_primary().shard},
    m_replica_min_epoch,
    m_pg_whoami);

  reply->preempted = true;
  ::encode(replica_scrubmap,
	   reply->get_data());	// skipping this crashes the scrubber
  m_pg->send_cluster_message(m_pg->get_primary().osd,
			     reply,
			     m_replica_min_epoch,
			     false);
}

/*
 *  - if the replica lets us know it was interrupted, we mark the chunk as
 *     interrupted. The state-machine will react to that when all replica maps
 *     are received.
 *  - when all maps are received, we signal the FSM with the GotReplicas event
 *    (see scrub_send_replmaps_ready()). Note that due to the no-reentrancy
 *     limitations of the FSM, we do not 'process' the event directly. Instead -
 *     it is queued for the OSD to handle.
 */
void PgScrubber::map_from_replica(OpRequestRef op)
{
  auto m = op->get_req<MOSDRepScrubMap>();
  dout(15) << __func__ << " " << *m << dendl;

  if (m->map_epoch < m_pg->info.history.same_interval_since) {
    dout(10) << __func__ << " discarding old from " << m->map_epoch << " < "
	     << m_pg->info.history.same_interval_since << dendl;
    return;
  }

  // note: we check for active() before map_from_replica() is called. Thus, we
  // know m_be is initialized
  m_be->decode_received_map(m->from, *m);

  auto [is_ok, err_txt] = m_maps_status.mark_arriving_map(m->from);
  if (!is_ok) {
    // previously an unexpected map was triggering an assert. Now, as scrubs can
    // be aborted at any time, the chances of this happening have increased, and
    // aborting is not justified
    dout(1) << __func__ << err_txt << " from OSD " << m->from << dendl;
    return;
  }

  if (m->preempted) {
    dout(10) << __func__ << " replica was preempted, setting flag" << dendl;
    preemption_data.do_preempt();
  }

  if (m_maps_status.are_all_maps_available()) {
    dout(15) << __func__ << " all repl-maps available" << dendl;
    m_osds->queue_scrub_got_repl_maps(m_pg, m_pg->is_scrub_blocking_ops());
  }
}

void PgScrubber::handle_scrub_reserve_request(OpRequestRef op)
{
  dout(10) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();
  auto request_ep = op->get_req<MOSDScrubReserve>()->get_map_epoch();
  dout(20) << fmt::format("{}: request_ep:{} recovery:{}",
			  __func__,
			  request_ep,
			  m_osds->is_recovery_active())
	   << dendl;

  /*
   *  if we are currently holding a reservation, then:
   *  either (1) we, the scrubber, did not yet notice an interval change. The
   *  remembered reservation epoch is from before our interval, and we can
   *  silently discard the reservation (no message is required).
   *  or:
   *
   *  (2) the interval hasn't changed, but the same Primary that (we think)
   *  holds the lock just sent us a new request. Note that we know it's the
   *  same Primary, as otherwise the interval would have changed.
   *
   *  Ostensibly we can discard & redo the reservation. But then we
   *  will be temporarily releasing the OSD resource - and might not be able
   *  to grab it again. Thus, we simply treat this as a successful new request
   *  (but mark the fact that if there is a previous request from the primary
   *  to scrub a specific chunk - that request is now defunct).
   */

  if (m_remote_osd_resource.has_value() && m_remote_osd_resource->is_stale()) {
    // we are holding a stale reservation from a past epoch
    m_remote_osd_resource.reset();
    dout(10) << __func__ << " cleared existing stale reservation" << dendl;
  }

  if (request_ep < m_pg->get_same_interval_since()) {
    // will not ack stale requests
    dout(10) << fmt::format("{}: stale reservation (request ep{} < {}) denied",
			    __func__,
			    request_ep,
			    m_pg->get_same_interval_since())
	     << dendl;
    return;
  }

  bool granted{false};
  if (m_remote_osd_resource.has_value()) {

    dout(10) << __func__ << " already reserved. Reassigned." << dendl;

    /*
     * it might well be that we did not yet finish handling the latest scrub-op
     * from our primary. This happens, for example, if 'noscrub' was set via a
     * command, then reset. The primary in this scenario will remain in the
     * same interval, but we do need to reset our internal state (otherwise -
     * the first renewed 'give me your scrub map' from the primary will see us
     * in active state, crashing the OSD).
     */
    advance_token();
    granted = true;

  } else if (m_pg->cct->_conf->osd_scrub_during_recovery ||
	     !m_osds->is_recovery_active()) {
    m_remote_osd_resource.emplace(this, m_pg, m_osds, request_ep);
    // OSD resources allocated?
    granted = m_remote_osd_resource->is_reserved();
    if (!granted) {
      // just forget it
      m_remote_osd_resource.reset();
      dout(20) << __func__ << ": failed to reserve remotely" << dendl;
    }
  } else {
    dout(10) << __func__ << ": recovery is active; not granting" << dendl;
  }

  dout(10) << __func__ << " reserved? " << (granted ? "yes" : "no") << dendl;

  Message* reply = new MOSDScrubReserve(
    spg_t(m_pg->info.pgid.pgid, m_pg->get_primary().shard),
    request_ep,
    granted ? MOSDScrubReserve::GRANT : MOSDScrubReserve::REJECT,
    m_pg_whoami);

  m_osds->send_message_osd_cluster(reply, op->get_req()->get_connection());
}

void PgScrubber::handle_scrub_reserve_grant(OpRequestRef op, pg_shard_t from)
{
  dout(10) << __func__ << " " << *op->get_req() << dendl;
  {
    if (m_debug_deny_replica) {
      // debug/UT code
      dout(10) << fmt::format("{}: debug_deny_replica set - denying", __func__)
	       << dendl;
      m_debug_deny_replica = false;
      m_reservations->release_replica(from, m_pg->get_osdmap_epoch());
      handle_scrub_reserve_reject(op, from);
      return;
    }
  }
  op->mark_started();

  if (m_reservations.has_value()) {
    m_reservations->handle_reserve_grant(op, from);
  } else {
    dout(20) << __func__ << ": late/unsolicited reservation grant from osd "
	     << from << " (" << op << ")" << dendl;
  }
}

void PgScrubber::handle_scrub_reserve_reject(OpRequestRef op, pg_shard_t from)
{
  dout(10) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();

  if (m_reservations.has_value()) {
    // there is an active reservation process. No action is required otherwise.
    m_reservations->handle_reserve_reject(op, from);
  }
}

void PgScrubber::handle_scrub_reserve_release(OpRequestRef op)
{
  dout(10) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();

  /*
   * this specific scrub session has terminated. All incoming events carrying
   *  the old tag will be discarded.
   */
  advance_token();
  m_remote_osd_resource.reset();
}

void PgScrubber::discard_replica_reservations()
{
  dout(10) << __func__ << dendl;
  if (m_reservations.has_value()) {
    m_reservations->discard_all();
  }
}

void PgScrubber::clear_scrub_reservations()
{
  dout(10) << __func__ << dendl;
  m_reservations.reset();	  // the remote reservations
  m_local_osd_resource.reset();	  // the local reservation
  m_remote_osd_resource.reset();  // we as replica reserved for a Primary
}

void PgScrubber::message_all_replicas(int32_t opcode, std::string_view op_text)
{
  ceph_assert(m_pg->recovery_state.get_backfill_targets().empty());

  std::vector<pair<int, Message*>> messages;
  messages.reserve(m_pg->get_actingset().size());

  epoch_t epch = get_osdmap_epoch();

  for (auto& p : m_pg->get_actingset()) {

    if (p == m_pg_whoami)
      continue;

    dout(10) << "scrub requesting " << op_text << " from osd." << p
	     << " Epoch: " << epch << dendl;
    Message* m = new MOSDScrubReserve(spg_t(m_pg->info.pgid.pgid, p.shard),
				      epch,
				      opcode,
				      m_pg_whoami);
    messages.push_back(std::make_pair(p.osd, m));
  }

  if (!messages.empty()) {
    m_osds->send_message_osd_cluster(messages, epch);
  }
}

void PgScrubber::unreserve_replicas()
{
  dout(10) << __func__ << dendl;
  m_reservations.reset();
}

void PgScrubber::set_reserving_now()
{
  m_osds->get_scrub_services().set_reserving_now();
}

void PgScrubber::clear_reserving_now()
{
  m_osds->get_scrub_services().clear_reserving_now();
}

void PgScrubber::set_queued_or_active()
{
  m_queued_or_active = true;
}

void PgScrubber::clear_queued_or_active()
{
  if (m_queued_or_active) {
    m_queued_or_active = false;
    // and just in case snap trimming was blocked by the aborted scrub
    m_pg->snap_trimmer_scrub_complete();
  }
}

bool PgScrubber::is_queued_or_active() const
{
  return m_queued_or_active;
}

void PgScrubber::set_scrub_blocked(utime_t since)
{
  ceph_assert(!m_scrub_job->blocked);
  // we are called from a time-triggered lambda,
  // thus - not under PG-lock
  PGRef pg = m_osds->osd->lookup_lock_pg(m_pg_id);
  ceph_assert(pg); // 'this' here should not exist if the PG was removed
  m_osds->get_scrub_services().mark_pg_scrub_blocked(m_pg_id);
  m_scrub_job->blocked_since = since;
  m_scrub_job->blocked = true;
  m_pg->publish_stats_to_osd();
  pg->unlock();
}

void PgScrubber::err_cnt_to_clog() const
{
  stringstream oss;
  oss << m_pg->info.pgid.pgid << " " << m_mode_desc << " ";
  int total_errors = m_shallow_errors + m_deep_errors;
  if (total_errors)
    oss << total_errors << " errors";
  else
    oss << "ok";
  if (!m_is_deep && m_pg->info.stats.stats.sum.num_deep_scrub_errors)
    oss << " ( " << m_pg->info.stats.stats.sum.num_deep_scrub_errors
	<< " remaining deep scrub error details lost)";
  if (m_is_repair)
    oss << ", " << m_fixed_count << " fixed";
  if (total_errors)
    m_osds->clog->error(oss);
  else
    m_osds->clog->debug(oss);
}

void PgScrubber::clear_scrub_blocked()
{
  ceph_assert(m_scrub_job->blocked);
  m_osds->get_scrub_services().clear_pg_scrub_blocked(m_pg_id);
  m_scrub_job->blocked = false;
  m_pg->publish_stats_to_osd();
}

/*
 * note: only called for the Primary.
 */
void PgScrubber::scrub_finish()
{
  dout(10) << fmt::format(
		  "{}: flags at start:{} pg-state:{}", __func__, m_flags,
		  (state_test(PG_STATE_REPAIR) ? "repair" : "no-repair"))
	   << dendl;
  ceph_assert(m_pg->is_locked());
  ceph_assert(is_queued_or_active());

  // if the repair request comes from auto-repair and large number of errors,
  // we would like to cancel auto-repair
  if (m_is_repair && m_flags.auto_repair &&
      m_be->authoritative_peers_count() >
	  static_cast<int>(
	      m_pg->cct->_conf->osd_scrub_auto_repair_num_errors)) {

    dout(10) << __func__ << ": undoing the repair" << dendl;
    state_clear(PG_STATE_REPAIR);  // not expected to be set, anyway
    m_is_repair = false;
    update_op_mode_text();
  }

  m_be->update_repair_status(m_is_repair);

  // if a regular scrub had errors within the limit, do a deep scrub to auto
  // repair
  bool do_auto_scrub = false;
  if (m_flags.deep_scrub_on_error && m_be->authoritative_peers_count() &&
      m_be->authoritative_peers_count() <=
	  static_cast<int>(
	      m_pg->cct->_conf->osd_scrub_auto_repair_num_errors)) {
    ceph_assert(!m_is_deep);
    do_auto_scrub = true;
    dout(15) << __func__ << ": Try to auto repair after scrub errors" << dendl;
  }

  m_flags.deep_scrub_on_error = false;

  // type-specific finish (can tally more errors)
  _scrub_finish();

  /// \todo fix the relevant scrub test so that we would not need the extra log
  /// line here (even if the following 'if' is false)

  if (m_be->authoritative_peers_count()) {

    auto err_msg = fmt::format(
	"{} {} {} missing, {} inconsistent objects", m_pg->info.pgid,
	m_mode_desc, m_be->m_missing.size(), m_be->m_inconsistent.size());

    dout(2) << err_msg << dendl;
    m_osds->clog->error() << fmt::to_string(err_msg);
  }

  // note that the PG_STATE_REPAIR might have changed above
  if (m_be->authoritative_peers_count() && m_is_repair) {

    state_clear(PG_STATE_CLEAN);
    // we know we have a problem, so it's OK to set the user-visible flag
    // even if we only reached here via auto-repair
    state_set(PG_STATE_REPAIR);
    update_op_mode_text();
    m_be->update_repair_status(true);
    m_fixed_count += m_be->scrub_process_inconsistent();
  }

  bool has_error = (m_be->authoritative_peers_count() > 0) && m_is_repair;
  err_cnt_to_clog();

  // Since we don't know which errors were fixed, we can only clear them
  // when every one has been fixed.
  if (m_is_repair) {
    dout(15) << fmt::format(
		    "{}: {} errors. {} errors fixed", __func__,
		    m_shallow_errors + m_deep_errors, m_fixed_count)
	     << dendl;
    if (m_fixed_count == m_shallow_errors + m_deep_errors) {

      ceph_assert(m_is_deep);
      m_shallow_errors = 0;
      m_deep_errors = 0;
      dout(20) << __func__ << " All may be fixed" << dendl;

    } else if (has_error) {

      // Deep scrub in order to get corrected error counts
      dout(10) << fmt::format(
		      "{}: the repair will be followed by a deep-scrub",
		      __func__)
	       << dendl;
      m_after_repair_scrub_required = true;
    } else if (m_shallow_errors || m_deep_errors) {

      // We have errors but nothing can be fixed, so there is no repair
      // possible.
      state_set(PG_STATE_FAILED_REPAIR);
      dout(10) << __func__ << " " << (m_shallow_errors + m_deep_errors)
	       << " error(s) present with no repair possible" << dendl;
    }
  }

  {
    // finish up
    ObjectStore::Transaction t;
    m_pg->recovery_state.update_stats(
	[this](auto& history, auto& stats) {
	  dout(10) << "m_pg->recovery_state.update_stats() errors:"
		   << m_shallow_errors << "/" << m_deep_errors << " deep? "
		   << m_is_deep << dendl;
	  utime_t now = ceph_clock_now();
	  history.last_scrub = m_pg->recovery_state.get_info().last_update;
	  history.last_scrub_stamp = now;
	  if (m_is_deep) {
	    history.last_deep_scrub =
		m_pg->recovery_state.get_info().last_update;
	    history.last_deep_scrub_stamp = now;
	  }

	  if (m_is_deep) {
	    if ((m_shallow_errors == 0) && (m_deep_errors == 0)) {
	      history.last_clean_scrub_stamp = now;
	    }
	    stats.stats.sum.num_shallow_scrub_errors = m_shallow_errors;
	    stats.stats.sum.num_deep_scrub_errors = m_deep_errors;
	    auto omap_stats = m_be->this_scrub_omapstats();
	    stats.stats.sum.num_large_omap_objects =
		omap_stats.large_omap_objects;
	    stats.stats.sum.num_omap_bytes = omap_stats.omap_bytes;
	    stats.stats.sum.num_omap_keys = omap_stats.omap_keys;
	    dout(19) << "scrub_finish shard " << m_pg_whoami
		     << " num_omap_bytes = " << stats.stats.sum.num_omap_bytes
		     << " num_omap_keys = " << stats.stats.sum.num_omap_keys
		     << dendl;
	  } else {
	    stats.stats.sum.num_shallow_scrub_errors = m_shallow_errors;
	    // XXX: last_clean_scrub_stamp doesn't mean the pg is not
	    // inconsistent because of deep-scrub errors
	    if (m_shallow_errors == 0) {
	      history.last_clean_scrub_stamp = now;
	    }
	  }

	  stats.stats.sum.num_scrub_errors =
	      stats.stats.sum.num_shallow_scrub_errors +
	      stats.stats.sum.num_deep_scrub_errors;

	  if (m_flags.check_repair) {
	    m_flags.check_repair = false;
	    if (m_pg->info.stats.stats.sum.num_scrub_errors) {
	      state_set(PG_STATE_FAILED_REPAIR);
	      dout(10) << "scrub_finish "
		       << m_pg->info.stats.stats.sum.num_scrub_errors
		       << " error(s) still present after re-scrub" << dendl;
	    }
	  }
	  return true;
	},
	&t);
    int tr = m_osds->store->queue_transaction(m_pg->ch, std::move(t), nullptr);
    ceph_assert(tr == 0);
  }

  if (has_error) {
    m_pg->queue_peering_event(
	PGPeeringEventRef(std::make_shared<PGPeeringEvent>(
	    get_osdmap_epoch(), get_osdmap_epoch(),
	    PeeringState::DoRecovery())));
  } else {
    m_is_repair = false;
    state_clear(PG_STATE_REPAIR);
    update_op_mode_text();
  }

  cleanup_on_finish();

  if (do_auto_scrub) {
    m_scrub_job->mark_for_rescrubbing();
  }

  auto applicable_conf = m_osds->get_scrub_services().populate_config_params(
      m_pg->get_pgpool().info.opts);
  /// \todo the ceph_clock_now() should be replaced by the mockable ScrubQueue
  /// clock
  m_scrub_job->at_scrub_completion(
      m_pg->get_pg_info(ScrubberPasskey()), applicable_conf, ceph_clock_now());

  // m_active & queued-or-active are both cleared now

  if (m_pg->is_active() && m_pg->is_primary()) {
    m_pg->recovery_state.share_pg_info();
  }
}

void PgScrubber::on_digest_updates()
{
  dout(10) << __func__ << " #pending: " << num_digest_updates_pending << " "
	   << (m_end.is_max() ? " <last chunk>" : " <mid chunk>")
	   << (is_queued_or_active() ? "" : " ** not marked as scrubbing **")
	   << dendl;

  if (num_digest_updates_pending > 0) {
    // do nothing for now. We will be called again when new updates arrive
    return;
  }

  // got all updates, and finished with this chunk. Any more?
  if (m_end.is_max()) {
    m_osds->queue_scrub_is_finished(m_pg);
  } else {
    // go get a new chunk (via "requeue")
    preemption_data.reset();
    m_osds->queue_scrub_next_chunk(m_pg, m_pg->is_scrub_blocking_ops());
  }
}

// handling Asok's "scrub" & "deep_scrub" commands

namespace {
void asok_response_section(
    ceph::Formatter* f,
    bool is_periodic,
    scrub_level_t scrub_level
    /*const char* section_value*/)
{
  f->open_object_section("result");
  f->dump_bool("deep", (scrub_level == scrub_level_t::deep));
  f->dump_bool("must", !is_periodic);
  f->close_section();
}
}  // namespace

// when asked to force a "periodic" scrub by faking the timestamps
void PgScrubber::on_operator_periodic_cmd(
    ceph::Formatter* f,
    scrub_level_t scrub_level,
    int64_t offset)
{
  auto cnf = m_scrub_queue.populate_config_params(m_pg->get_pgpool().info.opts);
  dout(10) << fmt::format(
		  "{}: {} (cmd offset:{}) conf:{}", __func__,
		  (scrub_level == scrub_level_t::deep ? "deep" : "shallow"), offset,
		  cnf)
	   << dendl;

  // move the relevant time-stamp backwards - enough to trigger a scrub

  utime_t now_is = m_scrub_queue.scrub_clock_now();
  utime_t stamp = now_is;

  if (offset > 0) {
    stamp -= offset;
  } else {
    double max_iv =
	(scrub_level == scrub_level_t::deep)
	    ? 2 * cnf.max_deep
	    : (cnf.max_shallow ? *cnf.max_shallow : cnf.shallow_interval);
    dout(20) << fmt::format(
		    "{}: stamp:{} ms:{}/{}/{}", __func__, stamp,
		    (cnf.max_shallow ? "ms+" : "ms-"),
		    (cnf.max_shallow ? *cnf.max_shallow : -999.99),
		    cnf.shallow_interval)
	     << dendl;
    stamp -= max_iv;
  }
  stamp -= 100.0;  // for good measure

  dout(10) << fmt::format("{}: stamp:{} ", __func__, stamp) << dendl;
  asok_response_section(f, true, scrub_level);

  if (scrub_level == scrub_level_t::deep) {
    m_pg->set_last_deep_scrub_stamp(stamp);
    m_pg->set_last_scrub_stamp(stamp);
  } else {
    m_pg->set_last_scrub_stamp(stamp);
  }

  // use the newly-updated set of timestamps to schedule a scrub
  m_scrub_job->operator_periodic_targets(
      scrub_level, stamp, m_pg->get_pg_info(ScrubberPasskey()), cnf, now_is);
}

// when asked to force a high-priority scrub
void PgScrubber::on_operator_forced_scrub(
    ceph::Formatter* f,
    scrub_level_t scrub_level)
{
  auto deep_req = scrub_requested(scrub_level, scrub_type_t::not_repair);
  asok_response_section(f, false, deep_req);
}

void PgScrubber::dump_scrubber(ceph::Formatter* f) const
{
  f->open_object_section("scrubber");

  if (m_active) {
    f->dump_bool("active", true);
    dump_active_scrubber(f, state_test(PG_STATE_DEEP_SCRUB));
  } else {
    f->dump_bool("active", false);
    auto now_is = m_scrub_queue.scrub_clock_now();
    auto& closest = m_scrub_job->closest_target(now_is);
    f->dump_bool("must_scrub", closest.is_required());
    f->dump_stream("scrub_reg_stamp") << m_scrub_job->get_sched_time(now_is);

    auto sched_state = m_scrub_job->scheduling_state();
    m_scrub_job->dump(f);
    f->dump_string("schedule", sched_state);
  }

  if (m_publish_sessions) {
    // an ever-increasing number used by tests
    f->dump_int("test_sequence", m_sessions_counter);
  }

  f->close_section();
}

void PgScrubber::dump_active_scrubber(ceph::Formatter* f, bool is_deep) const
{
  f->dump_stream("epoch_start") << m_interval_start;
  f->dump_stream("start") << m_start;
  f->dump_stream("end") << m_end;
  f->dump_stream("max_end") << m_max_end;
  f->dump_stream("subset_last_update") << m_subset_last_update;
  // note that m_is_deep will be set some time after PG_STATE_DEEP_SCRUB is
  // asserted. Thus, using the latter.
  f->dump_bool("deep", is_deep);

  // dump the scrub-type flags
  f->dump_bool("req_scrub", m_flags.required);
  f->dump_bool("auto_repair", m_flags.auto_repair);
  f->dump_bool("check_repair", m_flags.check_repair);
  f->dump_bool("deep_scrub_on_error", m_flags.deep_scrub_on_error);
  f->dump_unsigned("priority", m_flags.priority);

  f->dump_int("shallow_errors", m_shallow_errors);
  f->dump_int("deep_errors", m_deep_errors);
  f->dump_int("fixed", m_fixed_count);
  {
    f->open_array_section("waiting_on_whom");
    for (const auto& p : m_maps_status.get_awaited()) {
      f->dump_stream("shard") << p;
    }
    f->close_section();
  }
  if (m_scrub_job->blocked) {
    f->dump_string("schedule", "blocked");
  } else {
    f->dump_string("schedule", "scrubbing");
  }
}

pg_scrubbing_status_t PgScrubber::get_schedule() const
{
  if (!m_scrub_job) {
    return pg_scrubbing_status_t{};
  }
  dout(25) << fmt::format(
		"{}: active:{} blocked:{}", __func__, m_active,
		m_scrub_job->blocked)
	   << dendl;

  auto now_is = m_scrub_queue.scrub_clock_now();

  if (m_active) {
    // report current scrub info, including updated duration
    if (m_scrub_job->blocked) {
      // a bug. An object is held locked.
      int32_t blocked_for =
	(now_is - m_scrub_job->blocked_since).sec();
      return pg_scrubbing_status_t{
	utime_t{},
	blocked_for,
	pg_scrub_sched_status_t::blocked,
	true,  // active
	(m_is_deep ? scrub_level_t::deep : scrub_level_t::shallow),
	!m_flags.required};

    } else {
      int32_t duration = (now_is - scrub_begin_stamp).sec();
      return pg_scrubbing_status_t{
	utime_t{},
	duration,
	pg_scrub_sched_status_t::active,
	true,  // active
	(m_is_deep ? scrub_level_t::deep : scrub_level_t::shallow),
	!m_flags.required /* is periodic? */};
    }
  }

  if (!m_scrub_job->in_queue()) {
    return pg_scrubbing_status_t{
      utime_t{},
      0,
      pg_scrub_sched_status_t::not_queued,
      false,
      scrub_level_t::shallow,
      false};
  }

  // not active (i.e. - not scrubbing just now). Report the information
  // gleaned from the nearest scheduling target.
  SchedTarget& closest = m_scrub_job->closest_target(now_is);
  auto sched_time = closest.sched_time();

  // are we ripe for scrubbing?
  if (closest.is_ripe(now_is)) {
    // we are waiting for our turn at the OSD.
    return pg_scrubbing_status_t{
      sched_time,
      0, // no relevant value for 'duration'
      pg_scrub_sched_status_t::queued,
      false, // not scrubbing at this time
      closest.level(),
      closest.is_periodic()};
  }

  // were we already delayed once (or more)?
  if (closest.was_delayed()) {
    return pg_scrubbing_status_t{
      sched_time,
      0, // no relevant value for 'duration'
      pg_scrub_sched_status_t::delayed,
      false, // not scrubbing at this time
      closest.level(),
      closest.is_periodic()};
  }
  return pg_scrubbing_status_t{
    sched_time,
    0,
    pg_scrub_sched_status_t::scheduled,
    false,
    closest.level(),
    closest.is_periodic()};
}

PgScrubber::~PgScrubber()
{
  m_depenalize_timer.reset();

  if (m_scrub_job) {
    // make sure the OSD won't try to scrub this one just now
    m_scrub_job->remove_from_osd_queue();
    m_scrub_job.reset();
  }
}

PgScrubber::PgScrubber(PG* pg, ScrubQueue& osd_scrubq)
    : m_pg{pg}
    , m_pg_id{pg->pg_id}
    , m_osds{m_pg->osd}
    , m_scrub_queue{osd_scrubq}
    , m_pg_whoami{pg->pg_whoami}
    , preemption_data{pg}
{
  m_fsm = std::make_unique<ScrubMachine>(m_pg, this);
  m_fsm->initiate();

  m_scrub_job = std::make_unique<Scrub::ScrubJob>(
      m_scrub_queue, m_osds->cct, m_pg->pg_id, m_osds->get_nodeid());
}

void PgScrubber::set_scrub_begin_time()
{
  scrub_begin_stamp = m_scrub_queue.scrub_clock_now();
  m_osds->clog->debug() << fmt::format(
    "{} {} starts",
    m_pg->info.pgid.pgid,
    m_mode_desc);
}

void PgScrubber::set_scrub_duration()
{
  utime_t stamp = m_scrub_queue.scrub_clock_now();
  utime_t duration = stamp - scrub_begin_stamp;
  m_pg->recovery_state.update_stats([=](auto& history, auto& stats) {
    stats.last_scrub_duration = ceill(duration.to_msec() / 1000.0);
    stats.scrub_duration = double(duration);
    return true;
  });
}

void PgScrubber::reserve_replicas()
{
  dout(10) << __func__ << dendl;
  m_reservations.emplace(
    m_pg, m_pg_whoami, m_scrub_job.get(), m_pg->get_cct()->_conf);
}

// note: only called for successful scrubs
void PgScrubber::cleanup_on_finish()
{
  dout(10) << __func__ << dendl;
  ceph_assert(m_pg->is_locked());

  state_clear(PG_STATE_SCRUBBING);
  state_clear(PG_STATE_DEEP_SCRUB);
  m_scrub_job->consec_aborts = 0;
  m_pg->publish_stats_to_osd();

  clear_scrub_reservations();
  m_pg->publish_stats_to_osd();

  requeue_waiting();

  reset_internal_state();
  m_pg->publish_stats_to_osd();
  m_flags = scrub_flags_t{};

  // type-specific state clear
  _scrub_clear_state();
}

// uses process_event(), so must be invoked externally
void PgScrubber::scrub_clear_state()
{
  dout(10) << __func__ << dendl;

  clear_pgscrub_state();
  m_fsm->process_event(FullReset{});
}

/*
 * note: does not access the state-machine
 */
void PgScrubber::clear_pgscrub_state()
{
  dout(10) << __func__ << dendl;
  ceph_assert(m_pg->is_locked());

  state_clear(PG_STATE_SCRUBBING);
  state_clear(PG_STATE_DEEP_SCRUB);

  state_clear(PG_STATE_REPAIR);

  clear_scrub_reservations();
  m_pg->publish_stats_to_osd();

  requeue_waiting();

  reset_internal_state();
  m_flags = scrub_flags_t{};

  // type-specific state clear
  _scrub_clear_state();
  m_pg->publish_stats_to_osd();
}

void PgScrubber::replica_handling_done()
{
  dout(10) << __func__ << dendl;

  state_clear(PG_STATE_SCRUBBING);
  state_clear(PG_STATE_DEEP_SCRUB);

  reset_internal_state();
}

/*
 * note: performs run_callbacks()
 * note: reservations-related variables are not reset here
 */
void PgScrubber::reset_internal_state()
{
  dout(10) << __func__ << dendl;

  preemption_data.reset();
  m_maps_status.reset();

  m_start = hobject_t{};
  m_end = hobject_t{};
  m_max_end = hobject_t{};
  m_subset_last_update = eversion_t{};
  m_shallow_errors = 0;
  m_deep_errors = 0;
  m_fixed_count = 0;

  run_callbacks();

  num_digest_updates_pending = 0;
  m_primary_scrubmap_pos.reset();
  replica_scrubmap = ScrubMap{};
  replica_scrubmap_pos.reset();
  m_needs_sleep = true;
  m_sleep_started_at = utime_t{};

  m_active = false;
  m_scrub_job->scrubbing = false;
  m_active_target.reset();
  clear_queued_or_active();
  ++m_sessions_counter;
  m_be.reset();
}

// note that only applicable to the Replica:
void PgScrubber::advance_token()
{
  dout(10) << __func__ << " was: " << m_current_token << dendl;
  m_current_token++;

  // when advance_token() is called, it is assumed that no scrubbing takes
  // place. We will, though, verify that. And if we are actually still handling
  // a stale request - both our internal state and the FSM state will be
  // cleared.
  replica_handling_done();
  m_fsm->process_event(FullReset{});
}

bool PgScrubber::is_token_current(Scrub::act_token_t received_token)
{
  if (received_token == 0 || received_token == m_current_token) {
    return true;
  }
  dout(5) << __func__ << " obsolete token (" << received_token << " vs current "
	  << m_current_token << dendl;

  return false;
}

const OSDMapRef& PgScrubber::get_osdmap() const
{
  return m_pg->get_osdmap();
}

LoggerSinkSet& PgScrubber::get_logger() const { return *m_osds->clog.get(); }

ostream &operator<<(ostream &out, const PgScrubber &scrubber) {
  return out << scrubber.m_flags;
}

std::ostream& PgScrubber::gen_prefix(std::ostream& out) const
{
  if (m_pg) {
    return m_pg->gen_prefix(out) << "scrubber<" << m_fsm_state_name << ">: ";
  } else {
    return out << " scrubber [" << m_pg_id << "]: ";
  }
}

void PgScrubber::log_cluster_warning(const std::string& warning) const
{
  m_osds->clog->do_log(CLOG_WARN, warning);
}

// 'show_concise()' is only used when calling operator<< thru the ScrubPgIF
// interface - i.e. only by the PG
ostream& PgScrubber::show_concise(ostream& out) const
{
  // desired outcome:
  // if active:
  //   (shallow|deep,urgency[,mandatory][,auto-rpr][,chk-rpr][,deep-on-error])
  // if not:
  //   either nothing (if only periodic scrubs are scheduled)
  //   or [next scrub: effective-lvl, urgency, rpr,

  if (m_active && is_primary()) {
    if (m_active_target) {
      return out << fmt::format(
		 "({},{}{:4.4}{})", m_is_deep ? "deep" : "shallow",
		 (m_scrub_job->blocked ? "-*blocked*" : ""),
		 (*m_active_target).urgency(), m_flags);
    } else {
      return out << fmt::format(
		 "({},{}{}-inac)", m_is_deep ? "deep" : "shallow",
		 (m_scrub_job->blocked ? "-*blocked*" : ""), m_flags);
    }
  }

  auto now_is = m_scrub_queue.scrub_clock_now();
  auto& nscrub = m_scrub_job->closest_target(now_is);
  if (nscrub.is_periodic()) {
    // no interesting flags to be reported
    return out;
  }

  return out << fmt::format(
	     " [next-scrub:{},{:4.4}{}{}]", (nscrub.is_deep() ? "dp" : "sh"),
	     nscrub.urgency(), (nscrub.get_do_repair() ? ",rpr" : ""),
	     (nscrub.get_auto_repair() ? ",auto" : ""));
}

int PgScrubber::asok_debug(
    std::string_view prefix,
    std::string_view cmd,
    std::string_view param,
    Formatter* f,
    std::stringstream& ss)
{
  dout(10) << fmt::format(
		  "asok_debug: prefix={}, cmd={}, param={}", prefix, cmd, param)
	   << dendl;

  if (cmd == "block") {
    // 'm_debug_blockrange' causes the next 'select_range' to report a blocked
    // object
    m_debug_blockrange = 10;  // >1, so that will trigger fast state reports

  } else if (cmd == "unblock") {
    // send an 'unblock' event, as if a blocked range was freed
    m_debug_blockrange = 0;
    m_fsm->process_event(Unblocked{});

  } else if ((cmd == "set") || (cmd == "unset")) {

    if (param == "sessions") {
      // set/reset the inclusion of the scrub sessions counter in 'query' output
      m_publish_sessions = (cmd == "set");

    } else if (param == "block") {
      if (cmd == "set") {
	// set a flag that will cause the next 'select_range' to report a
	// blocked object
	m_debug_blockrange = 10;  // >1, so that will trigger fast state reports
      } else {
	// send an 'unblock' event, as if a blocked range was freed
	m_debug_blockrange = 0;
	m_fsm->process_event(Unblocked{});
      }
    } else if (param == "deny") {
      // arrange to have the next replica scrub reservation request denied
      m_debug_deny_replica = true;
    }
    f->open_object_section("result");
    f->dump_bool("success", true);
    f->close_section();
  }

  return 0;
}

/*
 * Note: under PG lock
 */
void PgScrubber::update_scrub_stats(ceph::coarse_real_clock::time_point now_is)
{
  using clock = ceph::coarse_real_clock;
  using namespace std::chrono;

  const seconds period_active = seconds(m_pg->get_cct()->_conf.get_val<int64_t>(
      "osd_stats_update_period_scrubbing"));
  if (!period_active.count()) {
    // a way for the operator to disable these stats updates
    return;
  }
  auto base_inactive_upd = seconds(m_pg->get_cct()->_conf.get_val<int64_t>(
      "osd_stats_update_period_not_scrubbing"));
  // a period set to < 5 seconds means we are running a test. In that case -
  // do not "randomize" the period based on the PG ID
  const seconds period_inactive =
      (base_inactive_upd > 5s)
	  ? base_inactive_upd + seconds(m_pg_id.pgid.m_seed % 30)
	  : base_inactive_upd;

  // determine the required update period, based on our current state
  auto period{period_inactive};
  if (m_active) {
    period = m_debug_blockrange ? 2s : period_active;
  }

  /// \todo use the date library (either the one included in Arrow or directly)
  /// to get the formatting of the time_points.

  if (g_conf()->subsys.should_gather<ceph_subsys_osd, 20>()) {
    // will only create the debug strings if required
    char buf[50];
    auto printable_last = fmt::localtime(clock::to_time_t(m_last_stat_upd));
    strftime(buf, sizeof(buf), "%Y-%m-%dT%T", &printable_last);
    dout(20) << fmt::format(
		    "{}: period: {}/{}-> {} last:{}", __func__, period_active,
		    period_inactive, period, buf)
	     << dendl;
  }

  if (now_is - m_last_stat_upd > period) {
    m_pg->publish_stats_to_osd();
    m_last_stat_upd = now_is;
  }
}


// ///////////////////// preemption_data_t //////////////////////////////////

PgScrubber::preemption_data_t::preemption_data_t(PG* pg) : m_pg{pg}
{
  m_left = static_cast<int>(
    m_pg->get_cct()->_conf.get_val<uint64_t>("osd_scrub_max_preemptions"));
}

void PgScrubber::preemption_data_t::reset()
{
  std::lock_guard<ceph::mutex> lk{m_preemption_lock};

  m_preemptable = false;
  m_preempted = false;
  m_left = static_cast<int>(
    m_pg->cct->_conf.get_val<uint64_t>("osd_scrub_max_preemptions"));
  m_size_divisor = 1;
}


// ///////////////////// ReplicaReservations //////////////////////////////////
namespace Scrub {

void ReplicaReservations::release_replica(pg_shard_t peer, epoch_t epoch)
{
  auto m = new MOSDScrubReserve(spg_t(m_pg_info.pgid.pgid, peer.shard),
				epoch,
				MOSDScrubReserve::RELEASE,
				m_pg->pg_whoami);
  m_osds->send_message_osd_cluster(peer.osd, m, epoch);
}

ReplicaReservations::ReplicaReservations(
    PG* pg,
    pg_shard_t whoami,
    Scrub::ScrubJob* scrubjob,
    const ConfigProxy& conf)
    : m_pg{pg}
    , m_acting_set{pg->get_actingset()}
    , m_osds{m_pg->get_pg_osd(ScrubberPasskey())}
    , m_pending{static_cast<int>(m_acting_set.size()) - 1}
    , m_pg_info{m_pg->get_pg_info(ScrubberPasskey())}
    , m_scrub_job{scrubjob}
    , m_conf{conf}
{
  epoch_t epoch = m_pg->get_osdmap_epoch();
  m_log_msg_prefix = fmt::format(
      "osd.{} ep: {} scrubber::ReplicaReservations pg[{}]: ", m_osds->whoami,
      epoch, pg->pg_id);
  m_timeout = conf.get_val<std::chrono::milliseconds>(
      "osd_scrub_slow_reservation_response");

  if (m_pending <= 0) {
    // A special case of no replicas.
    // just signal the scrub state-machine to continue
    send_all_done();

  } else {
    // start a timer to handle the case of no replies
    m_no_reply = make_unique<ReplicaReservations::no_reply_t>(
	m_osds, m_conf, *this, m_log_msg_prefix);

    // send the reservation requests
    for (auto p : m_acting_set) {
      if (p == whoami)
	continue;
      auto m = new MOSDScrubReserve(
	  spg_t(m_pg_info.pgid.pgid, p.shard), epoch, MOSDScrubReserve::REQUEST,
	  m_pg->pg_whoami);
      m_osds->send_message_osd_cluster(p.osd, m, epoch);
      m_waited_for_peers.push_back(p);
      dout(10) << __func__ << ": reserve " << p.osd << dendl;
    }
  }
}

void ReplicaReservations::send_all_done()
{
  // stop any pending timeout timer
  m_no_reply.reset();
  m_osds->queue_for_scrub_granted(m_pg, scrub_prio_t::low_priority);
}

void ReplicaReservations::send_reject()
{
  // stop any pending timeout timer
  m_no_reply.reset();
  m_osds->queue_for_scrub_denied(m_pg, scrub_prio_t::low_priority);
}

void ReplicaReservations::discard_all()
{
  dout(10) << __func__ << ": " << m_reserved_peers << dendl;

  m_no_reply.reset();
  m_had_rejections = true;  // preventing late-coming responses from triggering
			    // events
  m_reserved_peers.clear();
  m_waited_for_peers.clear();
}

/*
 * The following holds when update_latecomers() is called:
 * - we are still waiting for replies from some of the replicas;
 * - we might have already set a timer. If so, we should restart it.
 * - we might have received responses from 50% of the replicas.
 */
std::optional<ReplicaReservations::tpoint_t>
ReplicaReservations::update_latecomers(tpoint_t now_is)
{
  if (m_reserved_peers.size() > m_waited_for_peers.size()) {
    // at least half of the replicas have already responded. Time we flag
    // latecomers.
    return now_is + m_timeout;
  } else {
    return std::nullopt;
  }
}

ReplicaReservations::~ReplicaReservations()
{
  m_had_rejections = true;  // preventing late-coming responses from triggering
			    // events

  // stop any pending timeout timer
  m_no_reply.reset();

  // send un-reserve messages to all reserved replicas. We do not wait for
  // answer (there wouldn't be one). Other incoming messages will be discarded
  // on the way, by our owner.
  epoch_t epoch = m_pg->get_osdmap_epoch();

  for (auto& p : m_reserved_peers) {
    release_replica(p, epoch);
  }
  m_reserved_peers.clear();

  // note: the release will follow on the heels of the request. When tried
  // otherwise, grants that followed a reject arrived after the whole scrub
  // machine-state was reset, causing leaked reservations.
  for (auto& p : m_waited_for_peers) {
    release_replica(p, epoch);
  }
  m_waited_for_peers.clear();
}

/**
 *  @ATTN we would not reach here if the ReplicaReservation object managed by
 * the scrubber was reset.
 */
void ReplicaReservations::handle_reserve_grant(OpRequestRef op, pg_shard_t from)
{
  dout(10) << __func__ << ": granted by " << from << dendl;
  op->mark_started();

  {
    // reduce the amount of extra release messages. Not a must, but the log is
    // cleaner
    auto w = find(m_waited_for_peers.begin(), m_waited_for_peers.end(), from);
    if (w != m_waited_for_peers.end())
      m_waited_for_peers.erase(w);
  }

  // are we forced to reject the reservation?
  if (m_had_rejections) {

    dout(10) << __func__ << ": rejecting late-coming reservation from " << from
	     << dendl;
    release_replica(from, m_pg->get_osdmap_epoch());

  } else if (std::find(m_reserved_peers.begin(),
		       m_reserved_peers.end(),
		       from) != m_reserved_peers.end()) {

    dout(10) << __func__ << ": already had osd." << from << " reserved"
	     << dendl;

  } else {

    dout(10) << __func__ << ": osd." << from << " scrub reserve = success"
	     << dendl;
    m_reserved_peers.push_back(from);

    // was this response late?
    auto now_is = clock::now();
    if (m_timeout_point && (now_is > *m_timeout_point)) {
      m_osds->clog->warn() << fmt::format(
	"osd.{} scrubber pg[{}]: late reservation from osd.{}",
	m_osds->whoami,
	m_pg->pg_id,
	from);
      m_timeout_point.reset();
    } else {
      // possibly set a timer to warn about late-coming reservations
      m_timeout_point = update_latecomers(now_is);
    }

    if (--m_pending == 0) {
      send_all_done();
    }
  }
}

void ReplicaReservations::handle_reserve_reject(OpRequestRef op,
						pg_shard_t from)
{
  dout(10) << __func__ << ": rejected by " << from << dendl;
  dout(15) << __func__ << ": " << *op->get_req() << dendl;
  op->mark_started();

  {
    // reduce the amount of extra release messages. Not a must, but the log is
    // cleaner
    auto w = find(m_waited_for_peers.begin(), m_waited_for_peers.end(), from);
    if (w != m_waited_for_peers.end())
      m_waited_for_peers.erase(w);
  }

  if (m_had_rejections) {

    // our failure was already handled when the first rejection arrived
    dout(15) << __func__ << ": ignoring late-coming rejection from " << from
	     << dendl;

  } else if (std::find(m_reserved_peers.begin(),
		       m_reserved_peers.end(),
		       from) != m_reserved_peers.end()) {

    dout(10) << __func__ << ": already had osd." << from << " reserved"
	     << dendl;

  } else {

    dout(10) << __func__ << ": osd." << from << " scrub reserve = fail"
	     << dendl;
    m_had_rejections = true;  // preventing any additional notifications
    send_reject();
  }
}

void ReplicaReservations::handle_no_reply_timeout()
{
  dout(1) << fmt::format(
	       "{}: timeout! no reply from {}", __func__, m_waited_for_peers)
	  << dendl;

  m_had_rejections = true;  // preventing any additional notifications
  send_reject();
}

std::ostream& ReplicaReservations::gen_prefix(std::ostream& out) const
{
  return out << m_log_msg_prefix;
}

ReplicaReservations::no_reply_t::no_reply_t(
    OSDService* osds,
    const ConfigProxy& conf,
    ReplicaReservations& parent,
    std::string_view log_prfx)
    : m_osds{osds}
    , m_parent{parent}
    , m_log_prfx{log_prfx}
{
  auto now_is = clock::now();
  auto timeout = conf.get_val<milliseconds>("osd_scrub_reservation_timeout");

  m_abort_callback = new LambdaContext(
      [this, now_is, pgid = m_parent.m_pg->pg_id]([[maybe_unused]] int r) {
	// behave as if a REJECT was received
	if (!m_abort_callback) {
	  // already cancelled
	  return;
	}
	m_abort_callback = nullptr;
	m_osds->clog->warn() << fmt::format(
	    "{} timeout on replica reservations (since {})", m_log_prfx,
	    now_is);
	PGRef pg = m_osds->osd->lookup_lock_pg(pgid);
	if (!pg) {
	  lgeneric_subdout(g_ceph_context, osd, 10)
	      << "scrub_noreply_callback: Could not find PG " << pgid << dendl;
	  return;
	}
	m_parent.handle_no_reply_timeout();
	pg->unlock();
      });

  std::lock_guard l(m_osds->sleep_lock);
  // add_event_after() deletes the callback if failing to add (and returns
  // nullptr)
  m_abort_callback =
      m_osds->sleep_timer.add_event_after(timeout, m_abort_callback);
}

ReplicaReservations::no_reply_t::~no_reply_t()
{
  std::lock_guard l(m_osds->sleep_lock);
  if (m_abort_callback) {
    m_osds->sleep_timer.cancel_event(m_abort_callback);
  }
}

// ///////////////////// LocalReservation //////////////////////////////////

// note: no dout()s in LocalReservation functions. Client logs interactions.
LocalReservation::LocalReservation(OSDService* osds) : m_osds{osds}
{
  if (m_osds->get_scrub_services().resource_bookkeeper().inc_scrubs_local()) {
    // a failure is signalled by not having m_holding_local_reservation set
    m_holding_local_reservation = true;
  }
}

LocalReservation::~LocalReservation()
{
  if (m_holding_local_reservation) {
    m_holding_local_reservation = false;
    m_osds->get_scrub_services().resource_bookkeeper().dec_scrubs_local();
  }
}

// ///////////////////// ReservedByRemotePrimary ///////////////////////////////

ReservedByRemotePrimary::ReservedByRemotePrimary(
    const PgScrubber* scrubber,
    PG* pg,
    OSDService* osds,
    epoch_t epoch)
    : m_scrubber{scrubber}
    , m_pg{pg}
    , m_osds{osds}
    , m_reserved_at{epoch}
{
  if (!m_osds->get_scrub_services().resource_bookkeeper().inc_scrubs_remote()) {
    dout(10) << __func__ << ": failed to reserve at Primary request" << dendl;
    // the failure is signalled by not having m_reserved_by_remote_primary set
    return;
  }

  dout(20) << __func__ << ": scrub resources reserved at Primary request"
	   << dendl;
  m_reserved_by_remote_primary = true;
}

bool ReservedByRemotePrimary::is_stale() const
{
  return m_reserved_at < m_pg->get_same_interval_since();
}

ReservedByRemotePrimary::~ReservedByRemotePrimary()
{
  if (m_reserved_by_remote_primary) {
    m_reserved_by_remote_primary = false;
    m_osds->get_scrub_services().resource_bookkeeper().dec_scrubs_remote();
  }
}

std::ostream& ReservedByRemotePrimary::gen_prefix(std::ostream& out) const
{
  return m_scrubber->gen_prefix(out);
}

// ///////////////////// MapsCollectionStatus ////////////////////////////////

auto MapsCollectionStatus::mark_arriving_map(pg_shard_t from)
  -> std::tuple<bool, std::string_view>
{
  auto fe =
    std::find(m_maps_awaited_for.begin(), m_maps_awaited_for.end(), from);
  if (fe != m_maps_awaited_for.end()) {
    // we are indeed waiting for a map from this replica
    m_maps_awaited_for.erase(fe);
    return std::tuple{true, ""sv};
  } else {
    return std::tuple{false, " unsolicited scrub-map"sv};
  }
}

void MapsCollectionStatus::reset()
{
  *this = MapsCollectionStatus{};
}

std::string MapsCollectionStatus::dump() const
{
  std::string all;
  for (const auto& rp : m_maps_awaited_for) {
    all.append(rp.get_osd() + " "s);
  }
  return all;
}

ostream& operator<<(ostream& out, const MapsCollectionStatus& sf)
{
  out << " [ ";
  for (const auto& rp : sf.m_maps_awaited_for) {
    out << rp.get_osd() << " ";
  }
  if (!sf.m_local_map_ready) {
    out << " local ";
  }
  return out << " ] ";
}

// ///////////////////// blocked_range_t ///////////////////////////////

blocked_range_t::blocked_range_t(OSDService* osds,
				 ceph::timespan waittime,
				 ScrubMachineListener& scrubber,
				 spg_t pg_id)
    : m_osds{osds}
    , m_scrubber{scrubber}
    , m_pgid{pg_id}
{
  auto now_is = std::chrono::system_clock::now();
  m_callbk = new LambdaContext([this, now_is]([[maybe_unused]] int r) {
    std::time_t now_c = std::chrono::system_clock::to_time_t(now_is);
    char buf[50];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::localtime(&now_c));
    lgeneric_subdout(g_ceph_context, osd, 10)
      << "PgScrubber: " << m_pgid
      << " blocked on an object for too long (since " << buf << ")" << dendl;
    m_osds->clog->warn() << "osd." << m_osds->whoami
			 << " PgScrubber: " << m_pgid
			 << " blocked on an object for too long (since " << buf
			 << ")";

    m_warning_issued = true;
    m_scrubber.set_scrub_blocked(utime_t{now_c,0});
    return;
  });

  std::lock_guard l(m_osds->sleep_lock);
  m_osds->sleep_timer.add_event_after(waittime, m_callbk);
}

blocked_range_t::~blocked_range_t()
{
  if (m_warning_issued) {
    m_scrubber.clear_scrub_blocked();
  }
  std::lock_guard l(m_osds->sleep_lock);
  m_osds->sleep_timer.cancel_event(m_callbk);
}

}  // namespace Scrub
