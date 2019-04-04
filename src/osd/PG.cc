// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "PG.h"
// #include "msg/Messenger.h"
#include "messages/MOSDRepScrub.h"
// #include "common/cmdparse.h"
// #include "common/ceph_context.h"

#include "common/errno.h"
#include "common/config.h"
#include "OSD.h"
#include "OpRequest.h"
#include "ScrubStore.h"
#include "Session.h"

#include "common/Timer.h"
#include "common/perf_counters.h"

#include "messages/MOSDOp.h"
#include "messages/MOSDPGNotify.h"
// #include "messages/MOSDPGLog.h"
#include "messages/MOSDPGInfo.h"
#include "messages/MOSDPGTrim.h"
#include "messages/MOSDPGScan.h"
#include "messages/MOSDPGBackfill.h"
#include "messages/MOSDPGBackfillRemove.h"
#include "messages/MBackfillReserve.h"
#include "messages/MRecoveryReserve.h"
#include "messages/MOSDPGPush.h"
#include "messages/MOSDPGPushReply.h"
#include "messages/MOSDPGPull.h"
#include "messages/MOSDECSubOpWrite.h"
#include "messages/MOSDECSubOpWriteReply.h"
#include "messages/MOSDECSubOpRead.h"
#include "messages/MOSDECSubOpReadReply.h"
#include "messages/MOSDPGUpdateLogMissing.h"
#include "messages/MOSDPGUpdateLogMissingReply.h"
#include "messages/MOSDBackoff.h"
#include "messages/MOSDScrubReserve.h"
#include "messages/MOSDRepOp.h"
#include "messages/MOSDRepOpReply.h"
#include "messages/MOSDRepScrubMap.h"
#include "messages/MOSDPGRecoveryDelete.h"
#include "messages/MOSDPGRecoveryDeleteReply.h"

#include "common/BackTrace.h"
#include "common/EventTrace.h"

#ifdef WITH_LTTNG
#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "tracing/pg.h"
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_DEFINE
#else
#define tracepoint(...)
#endif

#include <sstream>

#define dout_context cct
#define dout_subsys ceph_subsys_osd
#undef dout_prefix
#define dout_prefix _prefix(_dout, this)

// prefix pgmeta_oid keys with _ so that PGLog::read_log_and_missing() can
// easily skip them
const string infover_key("_infover");
const string info_key("_info");
const string biginfo_key("_biginfo");
const string epoch_key("_epoch");
const string fastinfo_key("_fastinfo");

template <class T>
static ostream& _prefix(std::ostream *_dout, T *t)
{
  return t->gen_prefix(*_dout);
}

void PG::get(const char* tag)
{
  int after = ++ref;
  lgeneric_subdout(cct, refs, 5) << "PG::get " << this << " "
				 << "tag " << (tag ? tag : "(none") << " "
				 << (after - 1) << " -> " << after << dendl;
#ifdef PG_DEBUG_REFS
  std::lock_guard l(_ref_id_lock);
  _tag_counts[tag]++;
#endif
}

void PG::put(const char* tag)
{
#ifdef PG_DEBUG_REFS
  {
    std::lock_guard l(_ref_id_lock);
    auto tag_counts_entry = _tag_counts.find(tag);
    ceph_assert(tag_counts_entry != _tag_counts.end());
    --tag_counts_entry->second;
    if (tag_counts_entry->second == 0) {
      _tag_counts.erase(tag_counts_entry);
    }
  }
#endif
  auto local_cct = cct;
  int after = --ref;
  lgeneric_subdout(local_cct, refs, 5) << "PG::put " << this << " "
				       << "tag " << (tag ? tag : "(none") << " "
				       << (after + 1) << " -> " << after
				       << dendl;
  if (after == 0)
    delete this;
}

#ifdef PG_DEBUG_REFS
uint64_t PG::get_with_id()
{
  ref++;
  std::lock_guard l(_ref_id_lock);
  uint64_t id = ++_ref_id;
  BackTrace bt(0);
  stringstream ss;
  bt.print(ss);
  lgeneric_subdout(cct, refs, 5) << "PG::get " << this << " " << info.pgid
				 << " got id " << id << " "
				 << (ref - 1) << " -> " << ref
				 << dendl;
  ceph_assert(!_live_ids.count(id));
  _live_ids.insert(make_pair(id, ss.str()));
  return id;
}

void PG::put_with_id(uint64_t id)
{
  int newref = --ref;
  lgeneric_subdout(cct, refs, 5) << "PG::put " << this << " " << info.pgid
				 << " put id " << id << " "
				 << (newref + 1) << " -> " << newref
				 << dendl;
  {
    std::lock_guard l(_ref_id_lock);
    ceph_assert(_live_ids.count(id));
    _live_ids.erase(id);
  }
  if (newref)
    delete this;
}

void PG::dump_live_ids()
{
  std::lock_guard l(_ref_id_lock);
  dout(0) << "\t" << __func__ << ": " << info.pgid << " live ids:" << dendl;
  for (map<uint64_t, string>::iterator i = _live_ids.begin();
       i != _live_ids.end();
       ++i) {
    dout(0) << "\t\tid: " << *i << dendl;
  }
  dout(0) << "\t" << __func__ << ": " << info.pgid << " live tags:" << dendl;
  for (map<string, uint64_t>::iterator i = _tag_counts.begin();
       i != _tag_counts.end();
       ++i) {
    dout(0) << "\t\tid: " << *i << dendl;
  }
}
#endif

PG::PG(OSDService *o, OSDMapRef curmap,
       const PGPool &_pool, spg_t p) :
  recovery_state(
    cct,
    p,
    _pool,
    curmap,
    this,
    this),
  primary(recovery_state.primary),
  pg_whoami(recovery_state.pg_whoami),
  up_primary(recovery_state.up_primary),
  upset(recovery_state.upset),
  actingset(recovery_state.actingset),
  acting_recovery_backfill(recovery_state.acting_recovery_backfill),
  dirty_info(recovery_state.dirty_info),
  dirty_big_info(recovery_state.dirty_big_info),
  info(recovery_state.info),
  past_intervals(recovery_state.past_intervals),
  pg_log(recovery_state.pg_log),
  last_peering_reset(recovery_state.last_peering_reset),
  last_update_ondisk(recovery_state.last_update_ondisk),
  last_complete_ondisk(recovery_state.last_complete_ondisk),
  last_update_applied(recovery_state.last_update_applied),
  last_rollback_info_trimmed_to_applied(recovery_state.last_rollback_info_trimmed_to_applied),
  peer_info(recovery_state.peer_info),
  peer_missing(recovery_state.peer_missing),
  peer_log_requested(recovery_state.peer_log_requested),
  peer_missing_requested(recovery_state.peer_missing_requested),
  peer_last_complete_ondisk(recovery_state.peer_last_complete_ondisk),
  min_last_complete_ondisk(recovery_state.min_last_complete_ondisk),
  pg_trim_to(recovery_state.pg_trim_to),
  backfill_targets(recovery_state.backfill_targets),
  async_recovery_targets(recovery_state.async_recovery_targets),
  might_have_unfound(recovery_state.might_have_unfound),
  deleting(recovery_state.deleting),
  deleted(recovery_state.deleted),
  missing_loc(recovery_state.missing_loc),
  pg_id(p),
  coll(p),
  osd(o),
  cct(o->cct),
  pool(recovery_state.get_pool()),
  osdriver(osd->store, coll_t(), OSD::make_snapmapper_oid()),
  snap_mapper(
    cct,
    &osdriver,
    p.ps(),
    p.get_split_bits(_pool.info.get_pg_num()),
    _pool.id,
    p.shard),
  trace_endpoint("0.0.0.0", 0, "PG"),
  info_struct_v(0),
  pgmeta_oid(p.make_pgmeta_oid()),
  stat_queue_item(this),
  scrub_queued(false),
  recovery_queued(false),
  recovery_ops_active(0),
  heartbeat_peer_lock("PG::heartbeat_peer_lock"),
  backfill_reserving(false),
  pg_stats_publish_lock("PG::pg_stats_publish_lock"),
  pg_stats_publish_valid(false),
  finish_sync_event(NULL),
  backoff_lock("PG::backoff_lock"),
  scrub_after_recovery(false),
  active_pushes(0)
{
#ifdef PG_DEBUG_REFS
  osd->add_pgid(p, this);
#endif
#ifdef WITH_BLKIN
  std::stringstream ss;
  ss << "PG " << info.pgid;
  trace_endpoint.copy_name(ss.str());
#endif
}

PG::~PG()
{
#ifdef PG_DEBUG_REFS
  osd->remove_pgid(info.pgid, this);
#endif
}

void PG::lock(bool no_lockdep) const
{
  _lock.Lock(no_lockdep);
  // if we have unrecorded dirty state with the lock dropped, there is a bug
  ceph_assert(!dirty_info);
  ceph_assert(!dirty_big_info);

  dout(30) << "lock" << dendl;
}

std::ostream& PG::gen_prefix(std::ostream& out) const
{
  OSDMapRef mapref = recovery_state.get_osdmap();
  if (_lock.is_locked_by_me()) {
    out << "osd." << osd->whoami
	<< " pg_epoch: " << (mapref ? mapref->get_epoch():0)
	<< " " << *this << " ";
  } else {
    out << "osd." << osd->whoami
	<< " pg_epoch: " << (mapref ? mapref->get_epoch():0)
	<< " pg[" << pg_id.pgid << "(unlocked)] ";
  }
  return out;
}

PerfCounters &PG::get_peering_perf() {
  return *(osd->recoverystate_perf);
}

PerfCounters &PG::get_perf_logger() {
  return *(osd->logger);
}

void PG::log_state_enter(const char *state) {
  osd->pg_recovery_stats.log_enter(state);
}

void PG::log_state_exit(
  const char *state_name, utime_t enter_time,
  uint64_t events, utime_t event_dur) {
  osd->pg_recovery_stats.log_exit(
    state_name, ceph_clock_now() - enter_time, events, event_dur);
}
  
/********* PG **********/

void PG::remove_snap_mapped_object(
  ObjectStore::Transaction &t, const hobject_t &soid)
{
  t.remove(
    coll,
    ghobject_t(soid, ghobject_t::NO_GEN, pg_whoami.shard));
  clear_object_snap_mapping(&t, soid);
}

void PG::clear_object_snap_mapping(
  ObjectStore::Transaction *t, const hobject_t &soid)
{
  OSDriver::OSTransaction _t(osdriver.get_transaction(t));
  if (soid.snap < CEPH_MAXSNAP) {
    int r = snap_mapper.remove_oid(
      soid,
      &_t);
    if (!(r == 0 || r == -ENOENT)) {
      derr << __func__ << ": remove_oid returned " << cpp_strerror(r) << dendl;
      ceph_abort();
    }
  }
}

void PG::update_object_snap_mapping(
  ObjectStore::Transaction *t, const hobject_t &soid, const set<snapid_t> &snaps)
{
  OSDriver::OSTransaction _t(osdriver.get_transaction(t));
  ceph_assert(soid.snap < CEPH_MAXSNAP);
  int r = snap_mapper.remove_oid(
    soid,
    &_t);
  if (!(r == 0 || r == -ENOENT)) {
    derr << __func__ << ": remove_oid returned " << cpp_strerror(r) << dendl;
    ceph_abort();
  }
  snap_mapper.add_oid(
    soid,
    snaps,
    &_t);
}

/******* PG ***********/
void PG::clear_primary_state()
{
  last_update_ondisk = eversion_t();

  projected_log = PGLog::IndexedLog();

  snap_trimq.clear();
  finish_sync_event = 0;  // so that _finish_recovery doesn't go off in another thread
  release_pg_backoffs();

  scrubber.reserved_peers.clear();
  scrub_after_recovery = false;

  agent_clear();
}

PG::Scrubber::Scrubber()
 : reserved(false), reserve_failed(false),
   epoch_start(0),
   active(false),
   shallow_errors(0), deep_errors(0), fixed(0),
   must_scrub(false), must_deep_scrub(false), must_repair(false),
   auto_repair(false),
   check_repair(false),
   deep_scrub_on_error(false),
   num_digest_updates_pending(0),
   state(INACTIVE),
   deep(false)
{}

PG::Scrubber::~Scrubber() {}

bool PG::op_has_sufficient_caps(OpRequestRef& op)
{
  // only check MOSDOp
  if (op->get_req()->get_type() != CEPH_MSG_OSD_OP)
    return true;

  const MOSDOp *req = static_cast<const MOSDOp*>(op->get_req());

  auto priv = req->get_connection()->get_priv();
  auto session = static_cast<Session*>(priv.get());
  if (!session) {
    dout(0) << "op_has_sufficient_caps: no session for op " << *req << dendl;
    return false;
  }
  OSDCap& caps = session->caps;
  priv.reset();

  const string &key = req->get_hobj().get_key().empty() ?
    req->get_oid().name :
    req->get_hobj().get_key();

  bool cap = caps.is_capable(pool.name, req->get_hobj().nspace,
			     pool.info.application_metadata,
			     key,
			     op->need_read_cap(),
			     op->need_write_cap(),
			     op->classes(),
			     session->get_peer_socket_addr());

  dout(20) << "op_has_sufficient_caps "
           << "session=" << session
           << " pool=" << pool.id << " (" << pool.name
           << " " << req->get_hobj().nspace
	   << ")"
	   << " pool_app_metadata=" << pool.info.application_metadata
	   << " need_read_cap=" << op->need_read_cap()
	   << " need_write_cap=" << op->need_write_cap()
	   << " classes=" << op->classes()
	   << " -> " << (cap ? "yes" : "NO")
	   << dendl;
  return cap;
}

bool PG::requeue_scrub(bool high_priority)
{
  ceph_assert(is_locked());
  if (scrub_queued) {
    dout(10) << __func__ << ": already queued" << dendl;
    return false;
  } else {
    dout(10) << __func__ << ": queueing" << dendl;
    scrub_queued = true;
    osd->queue_for_scrub(this, high_priority);
    return true;
  }
}

void PG::queue_recovery()
{
  if (!is_primary() || !is_peered()) {
    dout(10) << "queue_recovery -- not primary or not peered " << dendl;
    ceph_assert(!recovery_queued);
  } else if (recovery_queued) {
    dout(10) << "queue_recovery -- already queued" << dendl;
  } else {
    dout(10) << "queue_recovery -- queuing" << dendl;
    recovery_queued = true;
    osd->queue_for_recovery(this);
  }
}

bool PG::queue_scrub()
{
  ceph_assert(is_locked());
  if (is_scrubbing()) {
    return false;
  }
  // An interrupted recovery repair could leave this set.
  state_clear(PG_STATE_REPAIR);
  scrubber.priority = scrubber.must_scrub ?
         cct->_conf->osd_requested_scrub_priority : get_scrub_priority();
  scrubber.must_scrub = false;
  state_set(PG_STATE_SCRUBBING);
  if (scrubber.must_deep_scrub) {
    state_set(PG_STATE_DEEP_SCRUB);
    scrubber.must_deep_scrub = false;
  }
  if (scrubber.must_repair || scrubber.auto_repair) {
    state_set(PG_STATE_REPAIR);
    scrubber.must_repair = false;
  }
  requeue_scrub();
  return true;
}

unsigned PG::get_scrub_priority()
{
  // a higher value -> a higher priority
  int64_t pool_scrub_priority = 0;
  pool.info.opts.get(pool_opts_t::SCRUB_PRIORITY, &pool_scrub_priority);
  return pool_scrub_priority > 0 ? pool_scrub_priority : cct->_conf->osd_scrub_priority;
}

Context *PG::finish_recovery()
{
  dout(10) << "finish_recovery" << dendl;
  ceph_assert(info.last_complete == info.last_update);

  clear_recovery_state();

  /*
   * sync all this before purging strays.  but don't block!
   */
  finish_sync_event = new C_PG_FinishRecovery(this);
  return finish_sync_event;
}

void PG::_finish_recovery(Context *c)
{
  lock();
  // When recovery is initiated by a repair, that flag is left on
  state_clear(PG_STATE_REPAIR);
  if (deleting) {
    unlock();
    return;
  }
  if (c == finish_sync_event) {
    dout(10) << "_finish_recovery" << dendl;
    finish_sync_event = 0;
    recovery_state.purge_strays();

    publish_stats_to_osd();

    if (scrub_after_recovery) {
      dout(10) << "_finish_recovery requeueing for scrub" << dendl;
      scrub_after_recovery = false;
      scrubber.must_deep_scrub = true;
      scrubber.check_repair = true;
      queue_scrub();
    }
  } else {
    dout(10) << "_finish_recovery -- stale" << dendl;
  }
  unlock();
}

void PG::start_recovery_op(const hobject_t& soid)
{
  dout(10) << "start_recovery_op " << soid
#ifdef DEBUG_RECOVERY_OIDS
	   << " (" << recovering_oids << ")"
#endif
	   << dendl;
  ceph_assert(recovery_ops_active >= 0);
  recovery_ops_active++;
#ifdef DEBUG_RECOVERY_OIDS
  recovering_oids.insert(soid);
#endif
  osd->start_recovery_op(this, soid);
}

void PG::finish_recovery_op(const hobject_t& soid, bool dequeue)
{
  dout(10) << "finish_recovery_op " << soid
#ifdef DEBUG_RECOVERY_OIDS
	   << " (" << recovering_oids << ")" 
#endif
	   << dendl;
  ceph_assert(recovery_ops_active > 0);
  recovery_ops_active--;
#ifdef DEBUG_RECOVERY_OIDS
  ceph_assert(recovering_oids.count(soid));
  recovering_oids.erase(recovering_oids.find(soid));
#endif
  osd->finish_recovery_op(this, soid, dequeue);

  if (!dequeue) {
    queue_recovery();
  }
}

void PG::split_into(pg_t child_pgid, PG *child, unsigned split_bits)
{
  recovery_state.split_into(child_pgid, &child->recovery_state, split_bits);

  child->update_snap_mapper_bits(split_bits);

  child->snap_trimq = snap_trimq;

  _split_into(child_pgid, child, split_bits);

  // release all backoffs for simplicity
  release_backoffs(hobject_t(), hobject_t::get_max());
}

void PG::start_split_stats(const set<spg_t>& childpgs, vector<object_stat_sum_t> *out)
{
  recovery_state.start_split_stats(childpgs, out);
}

void PG::finish_split_stats(const object_stat_sum_t& stats, ObjectStore::Transaction *t)
{
  recovery_state.finish_split_stats(stats, t);
}

void PG::merge_from(map<spg_t,PGRef>& sources, PeeringCtx *rctx,
		    unsigned split_bits,
		    const pg_merge_meta_t& last_pg_merge_meta)
{
  dout(10) << __func__ << " from " << sources << " split_bits " << split_bits
	   << dendl;
  map<spg_t, PeeringState*> source_ps;
  for (auto &&source : sources) {
    source_ps.emplace(source.first, &source.second->recovery_state);
  }
  recovery_state.merge_from(source_ps, rctx, split_bits, last_pg_merge_meta);

  for (auto& i : sources) {
    auto& source = i.second;
    // wipe out source's pgmeta
    rctx->transaction->remove(source->coll, source->pgmeta_oid);

    // merge (and destroy source collection)
    rctx->transaction->merge_collection(source->coll, coll, split_bits);
  }

  // merge_collection does this, but maybe all of our sources were missing.
  rctx->transaction->collection_set_bits(coll, split_bits);

  snap_mapper.update_bits(split_bits);
}

void PG::add_backoff(SessionRef s, const hobject_t& begin, const hobject_t& end)
{
  ConnectionRef con = s->con;
  if (!con)   // OSD::ms_handle_reset clears s->con without a lock
    return;
  BackoffRef b(s->have_backoff(info.pgid, begin));
  if (b) {
    derr << __func__ << " already have backoff for " << s << " begin " << begin
	 << " " << *b << dendl;
    ceph_abort();
  }
  std::lock_guard l(backoff_lock);
  {
    b = new Backoff(info.pgid, this, s, ++s->backoff_seq, begin, end);
    backoffs[begin].insert(b);
    s->add_backoff(b);
    dout(10) << __func__ << " session " << s << " added " << *b << dendl;
  }
  con->send_message(
    new MOSDBackoff(
      info.pgid,
      get_osdmap_epoch(),
      CEPH_OSD_BACKOFF_OP_BLOCK,
      b->id,
      begin,
      end));
}

void PG::release_backoffs(const hobject_t& begin, const hobject_t& end)
{
  dout(10) << __func__ << " [" << begin << "," << end << ")" << dendl;
  vector<BackoffRef> bv;
  {
    std::lock_guard l(backoff_lock);
    auto p = backoffs.lower_bound(begin);
    while (p != backoffs.end()) {
      int r = cmp(p->first, end);
      dout(20) << __func__ << " ? " << r << " " << p->first
	       << " " << p->second << dendl;
      // note: must still examine begin=end=p->first case
      if (r > 0 || (r == 0 && begin < end)) {
	break;
      }
      dout(20) << __func__ << " checking " << p->first
	       << " " << p->second << dendl;
      auto q = p->second.begin();
      while (q != p->second.end()) {
	dout(20) << __func__ << " checking  " << *q << dendl;
	int r = cmp((*q)->begin, begin);
	if (r == 0 || (r > 0 && (*q)->end < end)) {
	  bv.push_back(*q);
	  q = p->second.erase(q);
	} else {
	  ++q;
	}
      }
      if (p->second.empty()) {
	p = backoffs.erase(p);
      } else {
	++p;
      }
    }
  }
  for (auto b : bv) {
    std::lock_guard l(b->lock);
    dout(10) << __func__ << " " << *b << dendl;
    if (b->session) {
      ceph_assert(b->pg == this);
      ConnectionRef con = b->session->con;
      if (con) {   // OSD::ms_handle_reset clears s->con without a lock
	con->send_message(
	  new MOSDBackoff(
	    info.pgid,
	    get_osdmap_epoch(),
	    CEPH_OSD_BACKOFF_OP_UNBLOCK,
	    b->id,
	    b->begin,
	    b->end));
      }
      if (b->is_new()) {
	b->state = Backoff::STATE_DELETING;
      } else {
	b->session->rm_backoff(b);
	b->session.reset();
      }
      b->pg.reset();
    }
  }
}

void PG::clear_backoffs()
{
  dout(10) << __func__ << " " << dendl;
  map<hobject_t,set<BackoffRef>> ls;
  {
    std::lock_guard l(backoff_lock);
    ls.swap(backoffs);
  }
  for (auto& p : ls) {
    for (auto& b : p.second) {
      std::lock_guard l(b->lock);
      dout(10) << __func__ << " " << *b << dendl;
      if (b->session) {
	ceph_assert(b->pg == this);
	if (b->is_new()) {
	  b->state = Backoff::STATE_DELETING;
	} else {
	  b->session->rm_backoff(b);
	  b->session.reset();
	}
	b->pg.reset();
      }
    }
  }
}

// called by Session::clear_backoffs()
void PG::rm_backoff(BackoffRef b)
{
  dout(10) << __func__ << " " << *b << dendl;
  std::lock_guard l(backoff_lock);
  ceph_assert(b->lock.is_locked_by_me());
  ceph_assert(b->pg == this);
  auto p = backoffs.find(b->begin);
  // may race with release_backoffs()
  if (p != backoffs.end()) {
    auto q = p->second.find(b);
    if (q != p->second.end()) {
      p->second.erase(q);
      if (p->second.empty()) {
	backoffs.erase(p);
      }
    }
  }
}

void PG::clear_recovery_state() 
{
  dout(10) << "clear_recovery_state" << dendl;

  pg_log.reset_recovery_pointers();
  finish_sync_event = 0;

  hobject_t soid;
  while (recovery_ops_active > 0) {
#ifdef DEBUG_RECOVERY_OIDS
    soid = *recovering_oids.begin();
#endif
    finish_recovery_op(soid, true);
  }

  async_recovery_targets.clear();
  backfill_targets.clear();
  backfill_info.clear();
  peer_backfill_info.clear();
  waiting_on_backfill.clear();
  _clear_recovery_state();  // pg impl specific hook
}

void PG::cancel_recovery()
{
  dout(10) << "cancel_recovery" << dendl;
  clear_recovery_state();
}

void PG::set_probe_targets(const set<pg_shard_t> &probe_set)
{
  std::lock_guard l(heartbeat_peer_lock);
  probe_targets.clear();
  for (set<pg_shard_t>::iterator i = probe_set.begin();
       i != probe_set.end();
       ++i) {
    probe_targets.insert(i->osd);
  }
}

void PG::send_cluster_message(
  int target, Message *m,
  epoch_t epoch, bool share_map_update=false)
{
  ConnectionRef con = osd->get_con_osd_cluster(
    target, get_osdmap_epoch());
  if (!con)
    return;

  if (share_map_update) {
    osd->share_map_peer(target, con.get(), get_osdmap());
  }
  osd->send_message_osd_cluster(m, con.get());
}

void PG::clear_probe_targets()
{
  std::lock_guard l(heartbeat_peer_lock);
  probe_targets.clear();
}

void PG::update_heartbeat_peers(set<int> new_peers)
{
  bool need_update = false;
  heartbeat_peer_lock.Lock();
  if (new_peers == heartbeat_peers) {
    dout(10) << "update_heartbeat_peers " << heartbeat_peers << " unchanged" << dendl;
  } else {
    dout(10) << "update_heartbeat_peers " << heartbeat_peers << " -> " << new_peers << dendl;
    heartbeat_peers.swap(new_peers);
    need_update = true;
  }
  heartbeat_peer_lock.Unlock();

  if (need_update)
    osd->need_heartbeat_peer_update();
}


bool PG::check_in_progress_op(
  const osd_reqid_t &r,
  eversion_t *version,
  version_t *user_version,
  int *return_code) const
{
  return (
    projected_log.get_request(r, version, user_version, return_code) ||
    pg_log.get_log().get_request(r, version, user_version, return_code));
}

void PG::publish_stats_to_osd()
{
  if (!is_primary())
    return;

  pg_stats_publish_lock.Lock();

  auto stats = recovery_state.prepare_stats_for_publish(
    pg_stats_publish_valid,
    pg_stats_publish,
    unstable_stats);
  if (stats) {
    pg_stats_publish = stats.value();
    pg_stats_publish_valid = true;
  }

  pg_stats_publish_lock.Unlock();
}

void PG::clear_publish_stats()
{
  dout(15) << "clear_stats" << dendl;
  pg_stats_publish_lock.Lock();
  pg_stats_publish_valid = false;
  pg_stats_publish_lock.Unlock();
}

/**
 * initialize a newly instantiated pg
 *
 * Initialize PG state, as when a PG is initially created, or when it
 * is first instantiated on the current node.
 *
 * @param role our role/rank
 * @param newup up set
 * @param newacting acting set
 * @param history pg history
 * @param pi past_intervals
 * @param backfill true if info should be marked as backfill
 * @param t transaction to write out our new state in
 */
void PG::init(
  int role,
  const vector<int>& newup, int new_up_primary,
  const vector<int>& newacting, int new_acting_primary,
  const pg_history_t& history,
  const PastIntervals& pi,
  bool backfill,
  ObjectStore::Transaction *t)
{
  recovery_state.init(
    role, newup, new_up_primary, newacting,
    new_acting_primary, history, pi, backfill, t);
}

void PG::shutdown()
{
  ch->flush();
  lock();
  on_shutdown();
  unlock();
}

#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

void PG::upgrade(ObjectStore *store)
{
  dout(0) << __func__ << " " << info_struct_v << " -> " << latest_struct_v
	  << dendl;
  ceph_assert(info_struct_v <= 10);
  ObjectStore::Transaction t;

  // <do upgrade steps here>

  // finished upgrade!
  ceph_assert(info_struct_v == 10);

  // update infover_key
  if (info_struct_v < latest_struct_v) {
    map<string,bufferlist> v;
    __u8 ver = latest_struct_v;
    encode(ver, v[infover_key]);
    t.omap_setkeys(coll, pgmeta_oid, v);
  }

  dirty_info = true;
  dirty_big_info = true;
  write_if_dirty(t);

  ObjectStore::CollectionHandle ch = store->open_collection(coll);
  int r = store->queue_transaction(ch, std::move(t));
  if (r != 0) {
    derr << __func__ << ": queue_transaction returned "
	 << cpp_strerror(r) << dendl;
    ceph_abort();
  }
  ceph_assert(r == 0);

  C_SaferCond waiter;
  if (!ch->flush_commit(&waiter)) {
    waiter.wait();
  }
}

#pragma GCC diagnostic pop
#pragma GCC diagnostic warning "-Wpragmas"

int PG::_prepare_write_info(CephContext* cct,
			    map<string,bufferlist> *km,
			    epoch_t epoch,
			    pg_info_t &info,
			    pg_info_t &last_written_info,
			    PastIntervals &past_intervals,
			    bool dirty_big_info,
			    bool dirty_epoch,
			    bool try_fast_info,
			    PerfCounters *logger)
{
  if (dirty_epoch) {
    encode(epoch, (*km)[epoch_key]);
  }

  if (logger)
    logger->inc(l_osd_pg_info);

  // try to do info efficiently?
  if (!dirty_big_info && try_fast_info &&
      info.last_update > last_written_info.last_update) {
    pg_fast_info_t fast;
    fast.populate_from(info);
    bool did = fast.try_apply_to(&last_written_info);
    ceph_assert(did);  // we verified last_update increased above
    if (info == last_written_info) {
      encode(fast, (*km)[fastinfo_key]);
      if (logger)
	logger->inc(l_osd_pg_fastinfo);
      return 0;
    }
    generic_dout(30) << __func__ << " fastinfo failed, info:\n";
    {
      JSONFormatter jf(true);
      jf.dump_object("info", info);
      jf.flush(*_dout);
    }
    {
      *_dout << "\nlast_written_info:\n";
      JSONFormatter jf(true);
      jf.dump_object("last_written_info", last_written_info);
      jf.flush(*_dout);
    }
    *_dout << dendl;
  }

  last_written_info = info;

  // info.  store purged_snaps separately.
  interval_set<snapid_t> purged_snaps;
  purged_snaps.swap(info.purged_snaps);
  encode(info, (*km)[info_key]);
  purged_snaps.swap(info.purged_snaps);

  if (dirty_big_info) {
    // potentially big stuff
    bufferlist& bigbl = (*km)[biginfo_key];
    encode(past_intervals, bigbl);
    encode(info.purged_snaps, bigbl);
    //dout(20) << "write_info bigbl " << bigbl.length() << dendl;
    if (logger)
      logger->inc(l_osd_pg_biginfo);
  }

  return 0;
}

void PG::_create(ObjectStore::Transaction& t, spg_t pgid, int bits)
{
  coll_t coll(pgid);
  t.create_collection(coll, bits);
}

void PG::_init(ObjectStore::Transaction& t, spg_t pgid, const pg_pool_t *pool)
{
  coll_t coll(pgid);

  if (pool) {
    // Give a hint to the PG collection
    bufferlist hint;
    uint32_t pg_num = pool->get_pg_num();
    uint64_t expected_num_objects_pg = pool->expected_num_objects / pg_num;
    encode(pg_num, hint);
    encode(expected_num_objects_pg, hint);
    uint32_t hint_type = ObjectStore::Transaction::COLL_HINT_EXPECTED_NUM_OBJECTS;
    t.collection_hint(coll, hint_type, hint);
  }

  ghobject_t pgmeta_oid(pgid.make_pgmeta_oid());
  t.touch(coll, pgmeta_oid);
  map<string,bufferlist> values;
  __u8 struct_v = latest_struct_v;
  encode(struct_v, values[infover_key]);
  t.omap_setkeys(coll, pgmeta_oid, values);
}

void PG::prepare_write(
  pg_info_t &info,
  pg_info_t &last_written_info,
  PastIntervals &past_intervals,
  PGLog &pglog,
  bool dirty_info,
  bool dirty_big_info,
  bool need_write_epoch,
  ObjectStore::Transaction &t)
{
  info.stats.stats.add(unstable_stats);
  unstable_stats.clear();
  map<string,bufferlist> km;
  if (dirty_big_info || dirty_info) {
    int ret = _prepare_write_info(
      cct,
      &km,
      get_osdmap_epoch(),
      info,
      last_written_info,
      past_intervals,
      dirty_big_info,
      need_write_epoch,
      cct->_conf->osd_fast_info,
      osd->logger);
    ceph_assert(ret == 0);
  }
  pglog.write_log_and_missing(
    t, &km, coll, pgmeta_oid, pool.info.require_rollback());
  if (!km.empty())
    t.omap_setkeys(coll, pgmeta_oid, km);
}

#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

bool PG::_has_removal_flag(ObjectStore *store,
			   spg_t pgid)
{
  coll_t coll(pgid);
  ghobject_t pgmeta_oid(pgid.make_pgmeta_oid());

  // first try new way
  set<string> keys;
  keys.insert("_remove");
  map<string,bufferlist> values;
  auto ch = store->open_collection(coll);
  ceph_assert(ch);
  if (store->omap_get_values(ch, pgmeta_oid, keys, &values) == 0 &&
      values.size() == 1)
    return true;

  return false;
}

int PG::peek_map_epoch(ObjectStore *store,
		       spg_t pgid,
		       epoch_t *pepoch)
{
  coll_t coll(pgid);
  ghobject_t legacy_infos_oid(OSD::make_infos_oid());
  ghobject_t pgmeta_oid(pgid.make_pgmeta_oid());
  epoch_t cur_epoch = 0;

  // validate collection name
  ceph_assert(coll.is_pg());

  // try for v8
  set<string> keys;
  keys.insert(infover_key);
  keys.insert(epoch_key);
  map<string,bufferlist> values;
  auto ch = store->open_collection(coll);
  ceph_assert(ch);
  int r = store->omap_get_values(ch, pgmeta_oid, keys, &values);
  if (r == 0) {
    ceph_assert(values.size() == 2);

    // sanity check version
    auto bp = values[infover_key].cbegin();
    __u8 struct_v = 0;
    decode(struct_v, bp);
    ceph_assert(struct_v >= 8);

    // get epoch
    bp = values[epoch_key].begin();
    decode(cur_epoch, bp);
  } else {
    // probably bug 10617; see OSD::load_pgs()
    return -1;
  }

  *pepoch = cur_epoch;
  return 0;
}

#pragma GCC diagnostic pop
#pragma GCC diagnostic warning "-Wpragmas"

void PG::add_log_entry(const pg_log_entry_t& e, bool applied)
{
  // raise last_complete only if we were previously up to date
  if (info.last_complete == info.last_update)
    info.last_complete = e.version;
  
  // raise last_update.
  ceph_assert(e.version > info.last_update);
  info.last_update = e.version;

  // raise user_version, if it increased (it may have not get bumped
  // by all logged updates)
  if (e.user_version > info.last_user_version)
    info.last_user_version = e.user_version;

  // log mutation
  pg_log.add(e, applied);
  dout(10) << "add_log_entry " << e << dendl;
}


void PG::append_log(
  const vector<pg_log_entry_t>& logv,
  eversion_t trim_to,
  eversion_t roll_forward_to,
  ObjectStore::Transaction &t,
  bool transaction_applied,
  bool async)
{
  if (transaction_applied)
    update_snap_map(logv, t);

  /* The primary has sent an info updating the history, but it may not
   * have arrived yet.  We want to make sure that we cannot remember this
   * write without remembering that it happened in an interval which went
   * active in epoch history.last_epoch_started.
   */
  if (info.last_epoch_started != info.history.last_epoch_started) {
    info.history.last_epoch_started = info.last_epoch_started;
  }
  if (info.last_interval_started != info.history.last_interval_started) {
    info.history.last_interval_started = info.last_interval_started;
  }
  dout(10) << "append_log " << pg_log.get_log() << " " << logv << dendl;

  PGLogEntryHandler handler{this, &t};
  if (!transaction_applied) {
     /* We must be a backfill or async recovery peer, so it's ok if we apply
      * out-of-turn since we won't be considered when
      * determining a min possible last_update.
      *
      * We skip_rollforward() here, which advances the crt, without
      * doing an actual rollforward. This avoids cleaning up entries
      * from the backend and we do not end up in a situation, where the
      * object is deleted before we can _merge_object_divergent_entries().
      */
    pg_log.skip_rollforward();
  }

  for (vector<pg_log_entry_t>::const_iterator p = logv.begin();
       p != logv.end();
       ++p) {
    add_log_entry(*p, transaction_applied);

    /* We don't want to leave the rollforward artifacts around
     * here past last_backfill.  It's ok for the same reason as
     * above */
    if (transaction_applied &&
	p->soid > info.last_backfill) {
      pg_log.roll_forward(&handler);
    }
  }
  auto last = logv.rbegin();
  if (is_primary() && last != logv.rend()) {
    projected_log.skip_can_rollback_to_to_head();
    projected_log.trim(cct, last->version, nullptr, nullptr, nullptr);
  }

  if (transaction_applied && roll_forward_to > pg_log.get_can_rollback_to()) {
    pg_log.roll_forward_to(
      roll_forward_to,
      &handler);
    last_rollback_info_trimmed_to_applied = roll_forward_to;
  }

  dout(10) << __func__ << " approx pg log length =  "
           << pg_log.get_log().approx_size() << dendl;
  dout(10) << __func__ << " transaction_applied = "
           << transaction_applied << dendl;
  if (!transaction_applied || async)
    dout(10) << __func__ << " " << pg_whoami
             << " is async_recovery or backfill target" << dendl;
  pg_log.trim(trim_to, info, transaction_applied, async);

  // update the local pg, pg log
  dirty_info = true;
  write_if_dirty(t);
}

bool PG::check_log_for_corruption(ObjectStore *store)
{
  /// TODO: this method needs to work with the omap log
  return true;
}

//! Get the name we're going to save our corrupt page log as
std::string PG::get_corrupt_pg_log_name() const
{
  const int MAX_BUF = 512;
  char buf[MAX_BUF];
  struct tm tm_buf;
  time_t my_time(time(NULL));
  const struct tm *t = localtime_r(&my_time, &tm_buf);
  int ret = strftime(buf, sizeof(buf), "corrupt_log_%Y-%m-%d_%k:%M_", t);
  if (ret == 0) {
    dout(0) << "strftime failed" << dendl;
    return "corrupt_log_unknown_time";
  }
  string out(buf);
  out += stringify(info.pgid);
  return out;
}

int PG::read_info(
  ObjectStore *store, spg_t pgid, const coll_t &coll,
  pg_info_t &info, PastIntervals &past_intervals,
  __u8 &struct_v)
{
  set<string> keys;
  keys.insert(infover_key);
  keys.insert(info_key);
  keys.insert(biginfo_key);
  keys.insert(fastinfo_key);
  ghobject_t pgmeta_oid(pgid.make_pgmeta_oid());
  map<string,bufferlist> values;
  auto ch = store->open_collection(coll);
  ceph_assert(ch);
  int r = store->omap_get_values(ch, pgmeta_oid, keys, &values);
  ceph_assert(r == 0);
  ceph_assert(values.size() == 3 ||
	 values.size() == 4);

  auto p = values[infover_key].cbegin();
  decode(struct_v, p);
  ceph_assert(struct_v >= 10);

  p = values[info_key].begin();
  decode(info, p);

  p = values[biginfo_key].begin();
  decode(past_intervals, p);
  decode(info.purged_snaps, p);

  p = values[fastinfo_key].begin();
  if (!p.end()) {
    pg_fast_info_t fast;
    decode(fast, p);
    fast.try_apply_to(&info);
  }
  return 0;
}

void PG::read_state(ObjectStore *store)
{
  PastIntervals past_intervals_from_disk;
  pg_info_t info_from_disk;
  int r = read_info(
    store,
    pg_id,
    coll,
    info_from_disk,
    past_intervals_from_disk,
    info_struct_v);
  ceph_assert(r >= 0);

  if (info_struct_v < compat_struct_v) {
    derr << "PG needs upgrade, but on-disk data is too old; upgrade to"
	 << " an older version first." << dendl;
    ceph_abort_msg("PG too old to upgrade");
  }

  recovery_state.last_written_info = info;

  recovery_state.init_from_disk_state(
    std::move(info_from_disk),
    std::move(past_intervals_from_disk),
    [this, store] (PGLog &pglog) {
      ostringstream oss;
      pglog.read_log_and_missing(
	store,
	ch,
	pgmeta_oid,
	info,
	oss,
	cct->_conf->osd_ignore_stale_divergent_priors,
	cct->_conf->osd_debug_verify_missing_on_start);

      if (oss.tellp())
	osd->clog->error() << oss.str();
    });

  if (info_struct_v < latest_struct_v) {
    upgrade(store);
  }

  // initialize current mapping
  {
    int primary, up_primary;
    vector<int> acting, up;
    get_osdmap()->pg_to_up_acting_osds(
      pg_id.pgid, &up, &up_primary, &acting, &primary);
    recovery_state.init_primary_up_acting(
      up,
      acting,
      up_primary,
      primary);
    int rr = OSDMap::calc_pg_role(osd->whoami, acting);
    if (pool.info.is_replicated() || rr == pg_whoami.shard)
      recovery_state.set_role(rr);
    else
      recovery_state.set_role(-1);
  }

  PG::PeeringCtx rctx(0, 0, 0, new ObjectStore::Transaction);
  handle_initialize(&rctx);
  // note: we don't activate here because we know the OSD will advance maps
  // during boot.
  write_if_dirty(*rctx.transaction);
  store->queue_transaction(ch, std::move(*rctx.transaction));
  delete rctx.transaction;
}

void PG::update_snap_map(
  const vector<pg_log_entry_t> &log_entries,
  ObjectStore::Transaction &t)
{
  for (vector<pg_log_entry_t>::const_iterator i = log_entries.begin();
       i != log_entries.end();
       ++i) {
    OSDriver::OSTransaction _t(osdriver.get_transaction(&t));
    if (i->soid.snap < CEPH_MAXSNAP) {
      if (i->is_delete()) {
	int r = snap_mapper.remove_oid(
	  i->soid,
	  &_t);
	if (r != 0)
	  derr << __func__ << " remove_oid " << i->soid << " failed with " << r << dendl;
        // On removal tolerate missing key corruption
        ceph_assert(r == 0 || r == -ENOENT);
      } else if (i->is_update()) {
	ceph_assert(i->snaps.length() > 0);
	vector<snapid_t> snaps;
	bufferlist snapbl = i->snaps;
	auto p = snapbl.cbegin();
	try {
	  decode(snaps, p);
	} catch (...) {
	  derr << __func__ << " decode snaps failure on " << *i << dendl;
	  snaps.clear();
	}
	set<snapid_t> _snaps(snaps.begin(), snaps.end());

	if (i->is_clone() || i->is_promote()) {
	  snap_mapper.add_oid(
	    i->soid,
	    _snaps,
	    &_t);
	} else if (i->is_modify()) {
	  int r = snap_mapper.update_snaps(
	    i->soid,
	    _snaps,
	    0,
	    &_t);
	  ceph_assert(r == 0);
	} else {
	  ceph_assert(i->is_clean());
	}
      }
    }
  }
}

/**
 * filter trimming|trimmed snaps out of snapcontext
 */
void PG::filter_snapc(vector<snapid_t> &snaps)
{
  // nothing needs to trim, we can return immediately
  if (snap_trimq.empty() && info.purged_snaps.empty())
    return;

  bool filtering = false;
  vector<snapid_t> newsnaps;
  for (vector<snapid_t>::iterator p = snaps.begin();
       p != snaps.end();
       ++p) {
    if (snap_trimq.contains(*p) || info.purged_snaps.contains(*p)) {
      if (!filtering) {
	// start building a new vector with what we've seen so far
	dout(10) << "filter_snapc filtering " << snaps << dendl;
	newsnaps.insert(newsnaps.begin(), snaps.begin(), p);
	filtering = true;
      }
      dout(20) << "filter_snapc  removing trimq|purged snap " << *p << dendl;
    } else {
      if (filtering)
	newsnaps.push_back(*p);  // continue building new vector
    }
  }
  if (filtering) {
    snaps.swap(newsnaps);
    dout(10) << "filter_snapc  result " << snaps << dendl;
  }
}

void PG::requeue_object_waiters(map<hobject_t, list<OpRequestRef>>& m)
{
  for (map<hobject_t, list<OpRequestRef>>::iterator it = m.begin();
       it != m.end();
       ++it)
    requeue_ops(it->second);
  m.clear();
}

void PG::requeue_op(OpRequestRef op)
{
  auto p = waiting_for_map.find(op->get_source());
  if (p != waiting_for_map.end()) {
    dout(20) << __func__ << " " << op << " (waiting_for_map " << p->first << ")"
	     << dendl;
    p->second.push_front(op);
  } else {
    dout(20) << __func__ << " " << op << dendl;
    osd->enqueue_front(
      OpQueueItem(
        unique_ptr<OpQueueItem::OpQueueable>(new PGOpItem(info.pgid, op)),
	op->get_req()->get_cost(),
	op->get_req()->get_priority(),
	op->get_req()->get_recv_stamp(),
	op->get_req()->get_source().num(),
	get_osdmap_epoch()));
  }
}

void PG::requeue_ops(list<OpRequestRef> &ls)
{
  for (list<OpRequestRef>::reverse_iterator i = ls.rbegin();
       i != ls.rend();
       ++i) {
    requeue_op(*i);
  }
  ls.clear();
}

void PG::requeue_map_waiters()
{
  epoch_t epoch = get_osdmap_epoch();
  auto p = waiting_for_map.begin();
  while (p != waiting_for_map.end()) {
    if (epoch < p->second.front()->min_epoch) {
      dout(20) << __func__ << " " << p->first << " front op "
	       << p->second.front() << " must still wait, doing nothing"
	       << dendl;
      ++p;
    } else {
      dout(20) << __func__ << " " << p->first << " " << p->second << dendl;
      for (auto q = p->second.rbegin(); q != p->second.rend(); ++q) {
	auto req = *q;
	osd->enqueue_front(OpQueueItem(
          unique_ptr<OpQueueItem::OpQueueable>(new PGOpItem(info.pgid, req)),
	  req->get_req()->get_cost(),
	  req->get_req()->get_priority(),
	  req->get_req()->get_recv_stamp(),
	  req->get_req()->get_source().num(),
	  epoch));
      }
      p = waiting_for_map.erase(p);
    }
  }
}


// ==========================================================================================
// SCRUB

/*
 * when holding pg and sched_scrub_lock, then the states are:
 *   scheduling:
 *     scrubber.reserved = true
 *     scrub_rserved_peers includes whoami
 *     osd->scrub_pending++
 *   scheduling, replica declined:
 *     scrubber.reserved = true
 *     scrubber.reserved_peers includes -1
 *     osd->scrub_pending++
 *   pending:
 *     scrubber.reserved = true
 *     scrubber.reserved_peers.size() == acting.size();
 *     pg on scrub_wq
 *     osd->scrub_pending++
 *   scrubbing:
 *     scrubber.reserved = false;
 *     scrubber.reserved_peers empty
 *     osd->scrubber.active++
 */

// returns true if a scrub has been newly kicked off
bool PG::sched_scrub()
{
  bool nodeep_scrub = false;
  ceph_assert(is_locked());
  if (!(is_primary() && is_active() && is_clean() && !is_scrubbing())) {
    return false;
  }

  double deep_scrub_interval = 0;
  pool.info.opts.get(pool_opts_t::DEEP_SCRUB_INTERVAL, &deep_scrub_interval);
  if (deep_scrub_interval <= 0) {
    deep_scrub_interval = cct->_conf->osd_deep_scrub_interval;
  }
  bool time_for_deep = ceph_clock_now() >=
    info.history.last_deep_scrub_stamp + deep_scrub_interval;

  bool deep_coin_flip = false;
  // Only add random deep scrubs when NOT user initiated scrub
  if (!scrubber.must_scrub)
      deep_coin_flip = (rand() % 100) < cct->_conf->osd_deep_scrub_randomize_ratio * 100;
  dout(20) << __func__ << ": time_for_deep=" << time_for_deep << " deep_coin_flip=" << deep_coin_flip << dendl;

  time_for_deep = (time_for_deep || deep_coin_flip);

  //NODEEP_SCRUB so ignore time initiated deep-scrub
  if (get_osdmap()->test_flag(CEPH_OSDMAP_NODEEP_SCRUB) ||
      pool.info.has_flag(pg_pool_t::FLAG_NODEEP_SCRUB)) {
    time_for_deep = false;
    nodeep_scrub = true;
  }

  if (!scrubber.must_scrub) {
    ceph_assert(!scrubber.must_deep_scrub);

    //NOSCRUB so skip regular scrubs
    if ((get_osdmap()->test_flag(CEPH_OSDMAP_NOSCRUB) ||
	 pool.info.has_flag(pg_pool_t::FLAG_NOSCRUB)) && !time_for_deep) {
      if (scrubber.reserved) {
        // cancel scrub if it is still in scheduling,
        // so pgs from other pools where scrub are still legal
        // have a chance to go ahead with scrubbing.
        clear_scrub_reserved();
        scrub_unreserve_replicas();
      }
      return false;
    }
  }

  // Clear these in case user issues the scrub/repair command during
  // the scheduling of the scrub/repair (e.g. request reservation)
  scrubber.deep_scrub_on_error = false;
  scrubber.auto_repair = false;
  if (cct->_conf->osd_scrub_auto_repair
      && get_pgbackend()->auto_repair_supported()
      // respect the command from user, and not do auto-repair
      && !scrubber.must_repair
      && !scrubber.must_scrub
      && !scrubber.must_deep_scrub) {
    if (time_for_deep) {
      dout(20) << __func__ << ": auto repair with deep scrubbing" << dendl;
      scrubber.auto_repair = true;
    } else {
      dout(20) << __func__ << ": auto repair with scrubbing, rescrub if errors found" << dendl;
      scrubber.deep_scrub_on_error = true;
    }
  }

  bool ret = true;
  if (!scrubber.reserved) {
    ceph_assert(scrubber.reserved_peers.empty());
    if ((cct->_conf->osd_scrub_during_recovery || !osd->is_recovery_active()) &&
         osd->inc_scrubs_pending()) {
      dout(20) << __func__ << ": reserved locally, reserving replicas" << dendl;
      scrubber.reserved = true;
      scrubber.reserved_peers.insert(pg_whoami);
      scrub_reserve_replicas();
    } else {
      dout(20) << __func__ << ": failed to reserve locally" << dendl;
      ret = false;
    }
  }
  if (scrubber.reserved) {
    if (scrubber.reserve_failed) {
      dout(20) << "sched_scrub: failed, a peer declined" << dendl;
      clear_scrub_reserved();
      scrub_unreserve_replicas();
      ret = false;
    } else if (scrubber.reserved_peers.size() ==
	       recovery_state.get_acting().size()) {
      dout(20) << "sched_scrub: success, reserved self and replicas" << dendl;
      if (time_for_deep) {
	dout(10) << "sched_scrub: scrub will be deep" << dendl;
	state_set(PG_STATE_DEEP_SCRUB);
      } else if (!scrubber.must_deep_scrub && info.stats.stats.sum.num_deep_scrub_errors) {
	if (!nodeep_scrub) {
	  osd->clog->info() << "osd." << osd->whoami
			    << " pg " << info.pgid
			    << " Deep scrub errors, upgrading scrub to deep-scrub";
	  state_set(PG_STATE_DEEP_SCRUB);
	} else if (!scrubber.must_scrub) {
	  osd->clog->error() << "osd." << osd->whoami
			     << " pg " << info.pgid
			     << " Regular scrub skipped due to deep-scrub errors and nodeep-scrub set";
	  clear_scrub_reserved();
	  scrub_unreserve_replicas();
	  return false;
	} else {
	  osd->clog->error() << "osd." << osd->whoami
			     << " pg " << info.pgid
			     << " Regular scrub request, deep-scrub details will be lost";
	}
      }
      queue_scrub();
    } else {
      // none declined, since scrubber.reserved is set
      dout(20) << "sched_scrub: reserved " << scrubber.reserved_peers << ", waiting for replicas" << dendl;
    }
  }

  return ret;
}

void PG::reg_next_scrub()
{
  if (!is_primary())
    return;

  utime_t reg_stamp;
  bool must = false;
  if (scrubber.must_scrub) {
    // Set the smallest time that isn't utime_t()
    reg_stamp = utime_t(0,1);
    must = true;
  } else if (info.stats.stats_invalid && cct->_conf->osd_scrub_invalid_stats) {
    reg_stamp = ceph_clock_now();
    must = true;
  } else {
    reg_stamp = info.history.last_scrub_stamp;
  }
  // note down the sched_time, so we can locate this scrub, and remove it
  // later on.
  double scrub_min_interval = 0, scrub_max_interval = 0;
  pool.info.opts.get(pool_opts_t::SCRUB_MIN_INTERVAL, &scrub_min_interval);
  pool.info.opts.get(pool_opts_t::SCRUB_MAX_INTERVAL, &scrub_max_interval);
  ceph_assert(scrubber.scrub_reg_stamp == utime_t());
  scrubber.scrub_reg_stamp = osd->reg_pg_scrub(info.pgid,
					       reg_stamp,
					       scrub_min_interval,
					       scrub_max_interval,
					       must);
  dout(10) << __func__ << " pg " << pg_id << " register next scrub, scrub time "
      << scrubber.scrub_reg_stamp << ", must = " << (int)must << dendl;
  scrub_registered = true;
}

void PG::unreg_next_scrub()
{
  if (scrub_registered) {
    osd->unreg_pg_scrub(info.pgid, scrubber.scrub_reg_stamp);
    scrubber.scrub_reg_stamp = utime_t();
    scrub_registered = false;
  }
}

void PG::on_info_history_change()
{
  unreg_next_scrub();
  reg_next_scrub();
}

void PG::scrub_requested(bool deep, bool repair)
{
  unreg_next_scrub();
  scrubber.must_scrub = true;
  scrubber.must_deep_scrub = deep || repair;
  scrubber.must_repair = repair;
  reg_next_scrub();
}

void PG::clear_ready_to_merge() {
  osd->clear_ready_to_merge(this);
}

void PG::queue_want_pg_temp(const vector<int> &wanted) {
  osd->queue_want_pg_temp(get_pgid().pgid, wanted);
}

void PG::clear_want_pg_temp() {
  osd->remove_want_pg_temp(get_pgid().pgid);
}

void PG::on_role_change() {
  requeue_ops(waiting_for_peered);
  plpg_on_role_change();
}

void PG::on_new_interval() {
  scrub_queued = false;
  projected_last_update = eversion_t();
  cancel_recovery();
  plpg_on_new_interval();
}

epoch_t PG::oldest_stored_osdmap() {
  return osd->get_superblock().oldest_map;
}

LogChannel &PG::get_clog() {
  return *(osd->clog);
}

void PG::schedule_event_after(
  PGPeeringEventRef event,
  float delay) {
  std::lock_guard lock(osd->recovery_request_lock);
  osd->recovery_request_timer.add_event_after(
    delay,
    new QueuePeeringEvt(
      this,
      std::move(event)));
}

void PG::request_local_background_io_reservation(
  unsigned priority,
  PGPeeringEventRef on_grant,
  PGPeeringEventRef on_preempt) {
  osd->local_reserver.request_reservation(
    pg_id,
    on_grant ? new QueuePeeringEvt(
      this, on_grant) : nullptr,
    priority,
    on_preempt ? new QueuePeeringEvt(
      this, on_preempt) : nullptr);
}

void PG::update_local_background_io_priority(
  unsigned priority) {
  osd->local_reserver.update_priority(
    pg_id,
    priority);
}

void PG::cancel_local_background_io_reservation() {
  osd->local_reserver.cancel_reservation(
    pg_id);
}

void PG::request_remote_recovery_reservation(
  unsigned priority,
  PGPeeringEventRef on_grant,
  PGPeeringEventRef on_preempt) {
  osd->remote_reserver.request_reservation(
    pg_id,
    on_grant ? new QueuePeeringEvt(
      this, on_grant) : nullptr,
    priority,
    on_preempt ? new QueuePeeringEvt(
      this, on_preempt) : nullptr);
}

void PG::cancel_remote_recovery_reservation() {
  osd->remote_reserver.cancel_reservation(
    pg_id);
}

void PG::schedule_event_on_commit(
  ObjectStore::Transaction &t,
  PGPeeringEventRef on_commit)
{
  t.register_on_commit(new QueuePeeringEvt(this, on_commit));
}

void PG::on_active_exit()
{
  backfill_reserving = false;
  agent_stop();
}

void PG::on_active_advmap(const OSDMapRef &osdmap)
{
  if (osdmap->require_osd_release >= CEPH_RELEASE_MIMIC) {
    const auto& new_removed_snaps = osdmap->get_new_removed_snaps();
    auto i = new_removed_snaps.find(get_pgid().pool());
    if (i != new_removed_snaps.end()) {
      bool bad = false;
      for (auto j : i->second) {
	if (snap_trimq.intersects(j.first, j.second)) {
	  decltype(snap_trimq) added, overlap;
	  added.insert(j.first, j.second);
	  overlap.intersection_of(snap_trimq, added);
	  if (recovery_state.get_last_require_osd_release() < CEPH_RELEASE_MIMIC) {
	    derr << __func__ << " removed_snaps already contains "
		 << overlap << ", but this is the first mimic+ osdmap,"
		 << " so it's expected" << dendl;
	  } else {
	    derr << __func__ << " removed_snaps already contains "
		 << overlap << dendl;
	    bad = true;
	  }
	  snap_trimq.union_of(added);
	} else {
	  snap_trimq.insert(j.first, j.second);
	}
      }
      if (recovery_state.get_last_require_osd_release() < CEPH_RELEASE_MIMIC) {
	// at upgrade, we report *all* previously removed snaps as removed in
	// the first mimic epoch.  remove the ones we previously divined were
	// removed (and subsequently purged) from the trimq.
	derr << __func__ << " first mimic map, filtering purged_snaps"
	     << " from new removed_snaps" << dendl;
	snap_trimq.subtract(recovery_state.get_info().purged_snaps);
      }
      dout(10) << __func__ << " new removed_snaps " << i->second
	       << ", snap_trimq now " << snap_trimq << dendl;
      ceph_assert(!bad || !cct->_conf->osd_debug_verify_cached_snaps);
    }

    const auto& new_purged_snaps = osdmap->get_new_purged_snaps();
    auto j = new_purged_snaps.find(get_pgid().pgid.pool());
    if (j != new_purged_snaps.end()) {
      bool bad = false;
      for (auto k : j->second) {
	if (!recovery_state.get_info().purged_snaps.contains(k.first, k.second)) {
	  interval_set<snapid_t> rm, overlap;
	  rm.insert(k.first, k.second);
	  overlap.intersection_of(recovery_state.get_info().purged_snaps, rm);
	  derr << __func__ << " purged_snaps does not contain "
	       << rm << ", only " << overlap << dendl;
	  recovery_state.adjust_purged_snaps(
	    [&overlap](auto &purged_snaps) {
	      purged_snaps.subtract(overlap);
	    });
	  // This can currently happen in the normal (if unlikely) course of
	  // events.  Because adding snaps to purged_snaps does not increase
	  // the pg version or add a pg log entry, we don't reliably propagate
	  // purged_snaps additions to other OSDs.
	  // One example:
	  //  - purge S
	  //  - primary and replicas update purged_snaps
	  //  - no object updates
	  //  - pg mapping changes, new primary on different node
	  //  - new primary pg version == eversion_t(), so info is not
	  //    propagated.
	  //bad = true;
	} else {
	  recovery_state.adjust_purged_snaps(
	    [&k](auto &purged_snaps) {
	      purged_snaps.erase(k.first, k.second);
	    });
	}
      }
      dout(10) << __func__ << " new purged_snaps " << j->second
	       << ", now " << recovery_state.get_info().purged_snaps << dendl;
      ceph_assert(!bad || !cct->_conf->osd_debug_verify_cached_snaps);
    }
  } else if (!pool.newly_removed_snaps.empty()) {
    snap_trimq.union_of(pool.newly_removed_snaps);
    dout(10) << " snap_trimq now " << snap_trimq << dendl;
  }
}

void PG::on_active_actmap()
{
  if (cct->_conf->osd_check_for_log_corruption)
    check_log_for_corruption(osd->store);


  if (recovery_state.is_active()) {
    dout(10) << "Active: kicking snap trim" << dendl;
    kick_snap_trim();
  }

  if (recovery_state.is_peered() &&
      !recovery_state.is_clean() &&
      !recovery_state.get_osdmap()->test_flag(CEPH_OSDMAP_NOBACKFILL) &&
      (!recovery_state.get_osdmap()->test_flag(CEPH_OSDMAP_NOREBALANCE) ||
       recovery_state.is_degraded())) {
    queue_recovery();
  }
}

void PG::on_backfill_reserved()
{
  backfill_reserving = false;
  queue_recovery();
}

void PG::on_backfill_canceled()
{
  if (!waiting_on_backfill.empty()) {
    waiting_on_backfill.clear();
    finish_recovery_op(hobject_t::get_max());
  }
}

void PG::on_recovery_reserved()
{
  queue_recovery();
}

void PG::set_not_ready_to_merge_target(pg_t pgid, pg_t src)
{
  osd->set_not_ready_to_merge_target(pgid, src);
}

void PG::set_not_ready_to_merge_source(pg_t pgid)
{
  osd->set_not_ready_to_merge_source(pgid);
}

void PG::set_ready_to_merge_target(eversion_t lu, epoch_t les, epoch_t lec)
{
  osd->set_ready_to_merge_target(this, lu, les, lec);
}

void PG::set_ready_to_merge_source(eversion_t lu)
{
  osd->set_ready_to_merge_source(this, lu);
}

void PG::send_pg_created(pg_t pgid)
{
  osd->send_pg_created(pgid);
}

void PG::on_activate_committed()
{
  if (!is_primary()) {
    // waiters
    if (recovery_state.needs_flush() == 0) {
      requeue_ops(waiting_for_peered);
    } else if (!waiting_for_peered.empty()) {
      dout(10) << __func__ << " flushes in progress, moving "
	       << waiting_for_peered.size() << " items to waiting_for_flush"
	       << dendl;
      ceph_assert(waiting_for_flush.empty());
      waiting_for_flush.swap(waiting_for_peered);
    }
  }
}

void PG::do_replica_scrub_map(OpRequestRef op)
{
  const MOSDRepScrubMap *m = static_cast<const MOSDRepScrubMap*>(op->get_req());
  dout(7) << __func__ << " " << *m << dendl;
  if (m->map_epoch < info.history.same_interval_since) {
    dout(10) << __func__ << " discarding old from "
	     << m->map_epoch << " < " << info.history.same_interval_since
	     << dendl;
    return;
  }
  if (!scrubber.is_chunky_scrub_active()) {
    dout(10) << __func__ << " scrub isn't active" << dendl;
    return;
  }

  op->mark_started();

  auto p = const_cast<bufferlist&>(m->get_data()).cbegin();
  scrubber.received_maps[m->from].decode(p, info.pgid.pool());
  dout(10) << "map version is "
	   << scrubber.received_maps[m->from].valid_through
	   << dendl;

  dout(10) << __func__ << " waiting_on_whom was " << scrubber.waiting_on_whom
	   << dendl;
  ceph_assert(scrubber.waiting_on_whom.count(m->from));
  scrubber.waiting_on_whom.erase(m->from);
  if (m->preempted) {
    dout(10) << __func__ << " replica was preempted, setting flag" << dendl;
    scrub_preempted = true;
  }
  if (scrubber.waiting_on_whom.empty()) {
    requeue_scrub(ops_blocked_by_scrub());
  }
}

// send scrub v3 messages (chunky scrub)
void PG::_request_scrub_map(
  pg_shard_t replica, eversion_t version,
  hobject_t start, hobject_t end,
  bool deep,
  bool allow_preemption)
{
  ceph_assert(replica != pg_whoami);
  dout(10) << "scrub  requesting scrubmap from osd." << replica
	   << " deep " << (int)deep << dendl;
  MOSDRepScrub *repscrubop = new MOSDRepScrub(
    spg_t(info.pgid.pgid, replica.shard), version,
    get_osdmap_epoch(),
    get_last_peering_reset(),
    start, end, deep,
    allow_preemption,
    scrubber.priority,
    ops_blocked_by_scrub());
  // default priority, we want the rep scrub processed prior to any recovery
  // or client io messages (we are holding a lock!)
  osd->send_message_osd_cluster(
    replica.osd, repscrubop, get_osdmap_epoch());
}

void PG::handle_scrub_reserve_request(OpRequestRef op)
{
  dout(7) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();
  if (scrubber.reserved) {
    dout(10) << __func__ << " ignoring reserve request: Already reserved"
	     << dendl;
    return;
  }
  if ((cct->_conf->osd_scrub_during_recovery || !osd->is_recovery_active()) &&
      osd->inc_scrubs_pending()) {
    scrubber.reserved = true;
  } else {
    dout(20) << __func__ << ": failed to reserve remotely" << dendl;
    scrubber.reserved = false;
  }
  const MOSDScrubReserve *m =
    static_cast<const MOSDScrubReserve*>(op->get_req());
  Message *reply = new MOSDScrubReserve(
    spg_t(info.pgid.pgid, primary.shard),
    m->map_epoch,
    scrubber.reserved ? MOSDScrubReserve::GRANT : MOSDScrubReserve::REJECT,
    pg_whoami);
  osd->send_message_osd_cluster(reply, op->get_req()->get_connection());
}

void PG::handle_scrub_reserve_grant(OpRequestRef op, pg_shard_t from)
{
  dout(7) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();
  if (!scrubber.reserved) {
    dout(10) << "ignoring obsolete scrub reserve reply" << dendl;
    return;
  }
  if (scrubber.reserved_peers.find(from) != scrubber.reserved_peers.end()) {
    dout(10) << " already had osd." << from << " reserved" << dendl;
  } else {
    dout(10) << " osd." << from << " scrub reserve = success" << dendl;
    scrubber.reserved_peers.insert(from);
    sched_scrub();
  }
}

void PG::handle_scrub_reserve_reject(OpRequestRef op, pg_shard_t from)
{
  dout(7) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();
  if (!scrubber.reserved) {
    dout(10) << "ignoring obsolete scrub reserve reply" << dendl;
    return;
  }
  if (scrubber.reserved_peers.find(from) != scrubber.reserved_peers.end()) {
    dout(10) << " already had osd." << from << " reserved" << dendl;
  } else {
    /* One decline stops this pg from being scheduled for scrubbing. */
    dout(10) << " osd." << from << " scrub reserve = fail" << dendl;
    scrubber.reserve_failed = true;
    sched_scrub();
  }
}

void PG::handle_scrub_reserve_release(OpRequestRef op)
{
  dout(7) << __func__ << " " << *op->get_req() << dendl;
  op->mark_started();
  clear_scrub_reserved();
}

// Compute pending backfill data
static int64_t pending_backfill(CephContext *cct, int64_t bf_bytes, int64_t local_bytes)
{
  lgeneric_dout(cct, 20) << __func__ << " Adjust local usage "
			 << (local_bytes >> 10) << "KiB"
			 << " primary usage " << (bf_bytes >> 10)
			 << "KiB" << dendl;

  return std::max((int64_t)0, bf_bytes - local_bytes);
}


// We can zero the value of primary num_bytes as just an atomic.
// However, setting above zero reserves space for backfill and requires
// the OSDService::stat_lock which protects all OSD usage
bool PG::try_reserve_recovery_space(
  int64_t primary_bytes, int64_t local_bytes) {
  // Use tentative_bacfill_full() to make sure enough
  // space is available to handle target bytes from primary.

  // TODO: If we passed num_objects from primary we could account for
  // an estimate of the metadata overhead.

  // TODO: If we had compressed_allocated and compressed_original from primary
  // we could compute compression ratio and adjust accordingly.

  // XXX: There is no way to get omap overhead and this would only apply
  // to whatever possibly different partition that is storing the database.

  // update_osd_stat() from heartbeat will do this on a new
  // statfs using ps->primary_bytes.
  uint64_t pending_adjustment = 0;
  if (primary_bytes) {
    // For erasure coded pool overestimate by a full stripe per object
    // because we don't know how each objected rounded to the nearest stripe
    if (pool.info.is_erasure()) {
      primary_bytes /= (int)get_pgbackend()->get_ec_data_chunk_count();
      primary_bytes += get_pgbackend()->get_ec_stripe_chunk_size() *
	info.stats.stats.sum.num_objects;
      local_bytes /= (int)get_pgbackend()->get_ec_data_chunk_count();
      local_bytes += get_pgbackend()->get_ec_stripe_chunk_size() *
	info.stats.stats.sum.num_objects;
    }
    pending_adjustment = pending_backfill(
      cct,
      primary_bytes,
      local_bytes);
    dout(10) << __func__ << " primary_bytes " << (primary_bytes >> 10)
	     << "KiB"
	     << " local " << (local_bytes >> 10) << "KiB"
	     << " pending_adjustments " << (pending_adjustment >> 10) << "KiB"
	     << dendl;
  }

  // This lock protects not only the stats OSDService but also setting the
  // pg primary_bytes.  That's why we don't immediately unlock
  Mutex::Locker l(osd->stat_lock);
  osd_stat_t cur_stat = osd->osd_stat;
  if (cct->_conf->osd_debug_reject_backfill_probability > 0 &&
      (rand()%1000 < (cct->_conf->osd_debug_reject_backfill_probability*1000.0))) {
    dout(10) << "backfill reservation rejected: failure injection"
	     << dendl;
    return false;
  } else if (!cct->_conf->osd_debug_skip_full_check_in_backfill_reservation &&
      osd->tentative_backfill_full(this, pending_adjustment, cur_stat)) {
    dout(10) << "backfill reservation rejected: backfill full"
	     << dendl;
    return false;
  } else {
    // Don't reserve space if skipped reservation check, this is used
    // to test the other backfill full check AND in case a corruption
    // of num_bytes requires ignoring that value and trying the
    // backfill anyway.
    if (primary_bytes &&
	!cct->_conf->osd_debug_skip_full_check_in_backfill_reservation) {
      primary_num_bytes.store(primary_bytes);
      local_num_bytes.store(local_bytes);
    } else {
      unreserve_recovery_space();
    }
    return true;
  }
}

void PG::unreserve_recovery_space() {
  primary_num_bytes.store(0);
  local_num_bytes.store(0);
  return;
}

void PG::clear_scrub_reserved()
{
  scrubber.reserved_peers.clear();
  scrubber.reserve_failed = false;

  if (scrubber.reserved) {
    scrubber.reserved = false;
    osd->dec_scrubs_pending();
  }
}

void PG::scrub_reserve_replicas()
{
  ceph_assert(backfill_targets.empty());
  for (set<pg_shard_t>::iterator i = acting_recovery_backfill.begin();
       i != acting_recovery_backfill.end();
       ++i) {
    if (*i == pg_whoami) continue;
    dout(10) << "scrub requesting reserve from osd." << *i << dendl;
    osd->send_message_osd_cluster(
      i->osd,
      new MOSDScrubReserve(spg_t(info.pgid.pgid, i->shard),
			   get_osdmap_epoch(),
			   MOSDScrubReserve::REQUEST, pg_whoami),
      get_osdmap_epoch());
  }
}

void PG::scrub_unreserve_replicas()
{
  ceph_assert(backfill_targets.empty());
  for (set<pg_shard_t>::iterator i = acting_recovery_backfill.begin();
       i != acting_recovery_backfill.end();
       ++i) {
    if (*i == pg_whoami) continue;
    dout(10) << "scrub requesting unreserve from osd." << *i << dendl;
    osd->send_message_osd_cluster(
      i->osd,
      new MOSDScrubReserve(spg_t(info.pgid.pgid, i->shard),
			   get_osdmap_epoch(),
			   MOSDScrubReserve::RELEASE, pg_whoami),
      get_osdmap_epoch());
  }
}

void PG::_scan_rollback_obs(const vector<ghobject_t> &rollback_obs)
{
  ObjectStore::Transaction t;
  eversion_t trimmed_to = last_rollback_info_trimmed_to_applied;
  for (vector<ghobject_t>::const_iterator i = rollback_obs.begin();
       i != rollback_obs.end();
       ++i) {
    if (i->generation < trimmed_to.version) {
      dout(10) << __func__ << "osd." << osd->whoami
	       << " pg " << info.pgid
	       << " found obsolete rollback obj "
	       << *i << " generation < trimmed_to "
	       << trimmed_to
	       << "...repaired" << dendl;
      t.remove(coll, *i);
    }
  }
  if (!t.empty()) {
    derr << __func__ << ": queueing trans to clean up obsolete rollback objs"
	 << dendl;
    osd->store->queue_transaction(ch, std::move(t), NULL);
  }
}

void PG::_scan_snaps(ScrubMap &smap) 
{
  hobject_t head;
  SnapSet snapset;

  // Test qa/standalone/scrub/osd-scrub-snaps.sh uses this message to verify 
  // caller using clean_meta_map(), and it works properly.
  dout(20) << __func__ << " start" << dendl;

  for (map<hobject_t, ScrubMap::object>::reverse_iterator i = smap.objects.rbegin();
       i != smap.objects.rend();
       ++i) {
    const hobject_t &hoid = i->first;
    ScrubMap::object &o = i->second;

    dout(20) << __func__ << " " << hoid << dendl;

    ceph_assert(!hoid.is_snapdir());
    if (hoid.is_head()) {
      // parse the SnapSet
      bufferlist bl;
      if (o.attrs.find(SS_ATTR) == o.attrs.end()) {
	continue;
      }
      bl.push_back(o.attrs[SS_ATTR]);
      auto p = bl.cbegin();
      try {
	decode(snapset, p);
      } catch(...) {
	continue;
      }
      head = hoid.get_head();
      continue;
    }
    if (hoid.snap < CEPH_MAXSNAP) {
      // check and if necessary fix snap_mapper
      if (hoid.get_head() != head) {
	derr << __func__ << " no head for " << hoid << " (have " << head << ")"
	     << dendl;
	continue;
      }
      set<snapid_t> obj_snaps;
      auto p = snapset.clone_snaps.find(hoid.snap);
      if (p == snapset.clone_snaps.end()) {
	derr << __func__ << " no clone_snaps for " << hoid << " in " << snapset
	     << dendl;
	continue;
      }
      obj_snaps.insert(p->second.begin(), p->second.end());
      set<snapid_t> cur_snaps;
      int r = snap_mapper.get_snaps(hoid, &cur_snaps);
      if (r != 0 && r != -ENOENT) {
	derr << __func__ << ": get_snaps returned " << cpp_strerror(r) << dendl;
	ceph_abort();
      }
      if (r == -ENOENT || cur_snaps != obj_snaps) {
	ObjectStore::Transaction t;
	OSDriver::OSTransaction _t(osdriver.get_transaction(&t));
	if (r == 0) {
	  r = snap_mapper.remove_oid(hoid, &_t);
	  if (r != 0) {
	    derr << __func__ << ": remove_oid returned " << cpp_strerror(r)
		 << dendl;
	    ceph_abort();
	  }
	  osd->clog->error() << "osd." << osd->whoami
			    << " found snap mapper error on pg "
			    << info.pgid
			    << " oid " << hoid << " snaps in mapper: "
			    << cur_snaps << ", oi: "
			    << obj_snaps
			    << "...repaired";
	} else {
	  osd->clog->error() << "osd." << osd->whoami
			    << " found snap mapper error on pg "
			    << info.pgid
			    << " oid " << hoid << " snaps missing in mapper"
			    << ", should be: "
			    << obj_snaps
			     << " was " << cur_snaps << " r " << r
			    << "...repaired";
	}
	snap_mapper.add_oid(hoid, obj_snaps, &_t);

	// wait for repair to apply to avoid confusing other bits of the system.
	{
	  Cond my_cond;
	  Mutex my_lock("PG::_scan_snaps my_lock");
	  int r = 0;
	  bool done;
	  t.register_on_applied_sync(
	    new C_SafeCond(&my_lock, &my_cond, &done, &r));
	  r = osd->store->queue_transaction(ch, std::move(t));
	  if (r != 0) {
	    derr << __func__ << ": queue_transaction got " << cpp_strerror(r)
		 << dendl;
	  } else {
	    my_lock.Lock();
	    while (!done)
	      my_cond.Wait(my_lock);
	    my_lock.Unlock();
	  }
	}
      }
    }
  }
}

void PG::_repair_oinfo_oid(ScrubMap &smap)
{
  for (map<hobject_t, ScrubMap::object>::reverse_iterator i = smap.objects.rbegin();
       i != smap.objects.rend();
       ++i) {
    const hobject_t &hoid = i->first;
    ScrubMap::object &o = i->second;

    bufferlist bl;
    if (o.attrs.find(OI_ATTR) == o.attrs.end()) {
      continue;
    }
    bl.push_back(o.attrs[OI_ATTR]);
    object_info_t oi;
    try {
      oi.decode(bl);
    } catch(...) {
      continue;
    }
    if (oi.soid != hoid) {
      ObjectStore::Transaction t;
      OSDriver::OSTransaction _t(osdriver.get_transaction(&t));
      osd->clog->error() << "osd." << osd->whoami
			    << " found object info error on pg "
			    << info.pgid
			    << " oid " << hoid << " oid in object info: "
			    << oi.soid
			    << "...repaired";
      // Fix object info
      oi.soid = hoid;
      bl.clear();
      encode(oi, bl, get_osdmap()->get_features(CEPH_ENTITY_TYPE_OSD, nullptr));

      bufferptr bp(bl.c_str(), bl.length());
      o.attrs[OI_ATTR] = bp;

      t.setattr(coll, ghobject_t(hoid), OI_ATTR, bl);
      int r = osd->store->queue_transaction(ch, std::move(t));
      if (r != 0) {
	derr << __func__ << ": queue_transaction got " << cpp_strerror(r)
	     << dendl;
      }
    }
  }
}
int PG::build_scrub_map_chunk(
  ScrubMap &map,
  ScrubMapBuilder &pos,
  hobject_t start,
  hobject_t end,
  bool deep,
  ThreadPool::TPHandle &handle)
{
  dout(10) << __func__ << " [" << start << "," << end << ") "
	   << " pos " << pos
	   << dendl;

  // start
  while (pos.empty()) {
    pos.deep = deep;
    map.valid_through = info.last_update;

    // objects
    vector<ghobject_t> rollback_obs;
    pos.ret = get_pgbackend()->objects_list_range(
      start,
      end,
      &pos.ls,
      &rollback_obs);
    if (pos.ret < 0) {
      dout(5) << "objects_list_range error: " << pos.ret << dendl;
      return pos.ret;
    }
    if (pos.ls.empty()) {
      break;
    }
    _scan_rollback_obs(rollback_obs);
    pos.pos = 0;
    return -EINPROGRESS;
  }

  // scan objects
  while (!pos.done()) {
    int r = get_pgbackend()->be_scan_list(map, pos);
    if (r == -EINPROGRESS) {
      return r;
    }
  }

  // finish
  dout(20) << __func__ << " finishing" << dendl;
  ceph_assert(pos.done());
  _repair_oinfo_oid(map);
  if (!is_primary()) {
    ScrubMap for_meta_scrub;
    // In case we restarted smaller chunk, clear old data
    scrubber.cleaned_meta_map.clear_from(scrubber.start);
    scrubber.cleaned_meta_map.insert(map);
    scrubber.clean_meta_map(for_meta_scrub);
    _scan_snaps(for_meta_scrub);
  }

  dout(20) << __func__ << " done, got " << map.objects.size() << " items"
	   << dendl;
  return 0;
}

void PG::Scrubber::cleanup_store(ObjectStore::Transaction *t) {
  if (!store)
    return;
  struct OnComplete : Context {
    std::unique_ptr<Scrub::Store> store;
    explicit OnComplete(
      std::unique_ptr<Scrub::Store> &&store)
      : store(std::move(store)) {}
    void finish(int) override {}
  };
  store->cleanup(t);
  t->register_on_complete(new OnComplete(std::move(store)));
  ceph_assert(!store);
}

void PG::repair_object(
  const hobject_t& soid, list<pair<ScrubMap::object, pg_shard_t> > *ok_peers,
  pg_shard_t bad_peer)
{
  list<pg_shard_t> op_shards;
  for (auto i : *ok_peers) {
    op_shards.push_back(i.second);
  }
  dout(10) << "repair_object " << soid << " bad_peer osd."
	   << bad_peer << " ok_peers osd.{" << op_shards << "}" << dendl;
  ScrubMap::object &po = ok_peers->back().first;
  eversion_t v;
  bufferlist bv;
  bv.push_back(po.attrs[OI_ATTR]);
  object_info_t oi;
  try {
    auto bliter = bv.cbegin();
    decode(oi, bliter);
  } catch (...) {
    dout(0) << __func__ << ": Need version of replica, bad object_info_t: " << soid << dendl;
    ceph_abort();
  }
  if (bad_peer != primary) {
    peer_missing[bad_peer].add(soid, oi.version, eversion_t(), false);
  } else {
    // We should only be scrubbing if the PG is clean.
    ceph_assert(waiting_for_unreadable_object.empty());

    pg_log.missing_add(soid, oi.version, eversion_t());

    pg_log.set_last_requested(0);
    dout(10) << __func__ << ": primary = " << primary << dendl;
  }

  if (is_ec_pg() || bad_peer == primary) {
    // we'd better collect all shard for EC pg, and prepare good peers as the
    // source of pull in the case of replicated pg.
    missing_loc.add_missing(soid, oi.version, eversion_t());
    list<pair<ScrubMap::object, pg_shard_t> >::iterator i;
    for (i = ok_peers->begin();
	i != ok_peers->end();
	++i)
      missing_loc.add_location(soid, i->second);
  }
}

/* replica_scrub
 *
 * Wait for last_update_applied to match msg->scrub_to as above. Wait
 * for pushes to complete in case of recent recovery. Build a single
 * scrubmap of objects that are in the range [msg->start, msg->end).
 */
void PG::replica_scrub(
  OpRequestRef op,
  ThreadPool::TPHandle &handle)
{
  const MOSDRepScrub *msg = static_cast<const MOSDRepScrub *>(op->get_req());
  ceph_assert(!scrubber.active_rep_scrub);
  dout(7) << "replica_scrub" << dendl;

  if (msg->map_epoch < info.history.same_interval_since) {
    dout(10) << "replica_scrub discarding old replica_scrub from "
	     << msg->map_epoch << " < " << info.history.same_interval_since 
	     << dendl;
    return;
  }

  ceph_assert(msg->chunky);
  if (active_pushes > 0) {
    dout(10) << "waiting for active pushes to finish" << dendl;
    scrubber.active_rep_scrub = op;
    return;
  }

  scrubber.state = Scrubber::BUILD_MAP_REPLICA;
  scrubber.replica_scrub_start = msg->min_epoch;
  scrubber.start = msg->start;
  scrubber.end = msg->end;
  scrubber.max_end = msg->end;
  scrubber.deep = msg->deep;
  scrubber.epoch_start = info.history.same_interval_since;
  if (msg->priority) {
    scrubber.priority = msg->priority;
  } else {
    scrubber.priority = get_scrub_priority();
  }

  scrub_can_preempt = msg->allow_preemption;
  scrub_preempted = false;
  scrubber.replica_scrubmap_pos.reset();

  requeue_scrub(msg->high_priority);
}

/* Scrub:
 * PG_STATE_SCRUBBING is set when the scrub is queued
 * 
 * scrub will be chunky if all OSDs in PG support chunky scrub
 * scrub will fail if OSDs are too old.
 */
void PG::scrub(epoch_t queued, ThreadPool::TPHandle &handle)
{
  if (cct->_conf->osd_scrub_sleep > 0 &&
      (scrubber.state == PG::Scrubber::NEW_CHUNK ||
       scrubber.state == PG::Scrubber::INACTIVE) &&
       scrubber.needs_sleep) {
    ceph_assert(!scrubber.sleeping);
    dout(20) << __func__ << " state is INACTIVE|NEW_CHUNK, sleeping" << dendl;

    // Do an async sleep so we don't block the op queue
    OSDService *osds = osd;
    spg_t pgid = get_pgid();
    int state = scrubber.state;
    auto scrub_requeue_callback =
        new FunctionContext([osds, pgid, state](int r) {
          PGRef pg = osds->osd->lookup_lock_pg(pgid);
          if (pg == nullptr) {
            lgeneric_dout(osds->osd->cct, 20)
                << "scrub_requeue_callback: Could not find "
                << "PG " << pgid << " can't complete scrub requeue after sleep"
                << dendl;
            return;
          }
          pg->scrubber.sleeping = false;
          pg->scrubber.needs_sleep = false;
          lgeneric_dout(pg->cct, 20)
              << "scrub_requeue_callback: slept for "
              << ceph_clock_now() - pg->scrubber.sleep_start
              << ", re-queuing scrub with state " << state << dendl;
          pg->scrub_queued = false;
          pg->requeue_scrub();
          pg->scrubber.sleep_start = utime_t();
          pg->unlock();
        });
    std::lock_guard l(osd->sleep_lock);
    osd->sleep_timer.add_event_after(cct->_conf->osd_scrub_sleep,
                                           scrub_requeue_callback);
    scrubber.sleeping = true;
    scrubber.sleep_start = ceph_clock_now();
    return;
  }
  if (pg_has_reset_since(queued)) {
    return;
  }
  ceph_assert(scrub_queued);
  scrub_queued = false;
  scrubber.needs_sleep = true;

  // for the replica
  if (!is_primary() &&
      scrubber.state == PG::Scrubber::BUILD_MAP_REPLICA) {
    chunky_scrub(handle);
    return;
  }

  if (!is_primary() || !is_active() || !is_clean() || !is_scrubbing()) {
    dout(10) << "scrub -- not primary or active or not clean" << dendl;
    state_clear(PG_STATE_SCRUBBING);
    state_clear(PG_STATE_REPAIR);
    state_clear(PG_STATE_DEEP_SCRUB);
    publish_stats_to_osd();
    return;
  }

  if (!scrubber.active) {
    ceph_assert(backfill_targets.empty());

    scrubber.deep = state_test(PG_STATE_DEEP_SCRUB);

    dout(10) << "starting a new chunky scrub" << dendl;
  }

  chunky_scrub(handle);
}

/*
 * Chunky scrub scrubs objects one chunk at a time with writes blocked for that
 * chunk.
 *
 * The object store is partitioned into chunks which end on hash boundaries. For
 * each chunk, the following logic is performed:
 *
 *  (1) Block writes on the chunk
 *  (2) Request maps from replicas
 *  (3) Wait for pushes to be applied (after recovery)
 *  (4) Wait for writes to flush on the chunk
 *  (5) Wait for maps from replicas
 *  (6) Compare / repair all scrub maps
 *  (7) Wait for digest updates to apply
 *
 * This logic is encoded in the mostly linear state machine:
 *
 *           +------------------+
 *  _________v__________        |
 * |                    |       |
 * |      INACTIVE      |       |
 * |____________________|       |
 *           |                  |
 *           |   +----------+   |
 *  _________v___v______    |   |
 * |                    |   |   |
 * |      NEW_CHUNK     |   |   |
 * |____________________|   |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |     WAIT_PUSHES    |   |   |
 * |____________________|   |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |  WAIT_LAST_UPDATE  |   |   |
 * |____________________|   |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |      BUILD_MAP     |   |   |
 * |____________________|   |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |    WAIT_REPLICAS   |   |   |
 * |____________________|   |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |    COMPARE_MAPS    |   |   |
 * |____________________|   |   |
 *           |              |   |
 *           |              |   |
 *  _________v__________    |   |
 * |                    |   |   |
 * |WAIT_DIGEST_UPDATES |   |   |
 * |____________________|   |   |
 *           |   |          |   |
 *           |   +----------+   |
 *  _________v__________        |
 * |                    |       |
 * |       FINISH       |       |
 * |____________________|       |
 *           |                  |
 *           +------------------+
 *
 * The primary determines the last update from the subset by walking the log. If
 * it sees a log entry pertaining to a file in the chunk, it tells the replicas
 * to wait until that update is applied before building a scrub map. Both the
 * primary and replicas will wait for any active pushes to be applied.
 *
 * In contrast to classic_scrub, chunky_scrub is entirely handled by scrub_wq.
 *
 * scrubber.state encodes the current state of the scrub (refer to state diagram
 * for details).
 */
void PG::chunky_scrub(ThreadPool::TPHandle &handle)
{
  // check for map changes
  if (scrubber.is_chunky_scrub_active()) {
    if (scrubber.epoch_start != info.history.same_interval_since) {
      dout(10) << "scrub  pg changed, aborting" << dendl;
      scrub_clear_state();
      scrub_unreserve_replicas();
      return;
    }
  }

  bool done = false;
  int ret;

  while (!done) {
    dout(20) << "scrub state " << Scrubber::state_string(scrubber.state)
	     << " [" << scrubber.start << "," << scrubber.end << ")"
	     << " max_end " << scrubber.max_end << dendl;

    switch (scrubber.state) {
      case PG::Scrubber::INACTIVE:
        dout(10) << "scrub start" << dendl;
	ceph_assert(is_primary());

        publish_stats_to_osd();
        scrubber.epoch_start = info.history.same_interval_since;
        scrubber.active = true;

	osd->inc_scrubs_active(scrubber.reserved);
	if (scrubber.reserved) {
	  scrubber.reserved = false;
	  scrubber.reserved_peers.clear();
	}

	{
	  ObjectStore::Transaction t;
	  scrubber.cleanup_store(&t);
	  scrubber.store.reset(Scrub::Store::create(osd->store, &t,
						    info.pgid, coll));
	  osd->store->queue_transaction(ch, std::move(t), nullptr);
	}

        // Don't include temporary objects when scrubbing
        scrubber.start = info.pgid.pgid.get_hobj_start();
        scrubber.state = PG::Scrubber::NEW_CHUNK;

	{
	  bool repair = state_test(PG_STATE_REPAIR);
	  bool deep_scrub = state_test(PG_STATE_DEEP_SCRUB);
	  const char *mode = (repair ? "repair": (deep_scrub ? "deep-scrub" : "scrub"));
	  stringstream oss;
	  oss << info.pgid.pgid << " " << mode << " starts" << std::endl;
	  osd->clog->debug(oss);
	}

	scrubber.preempt_left = cct->_conf.get_val<uint64_t>(
	  "osd_scrub_max_preemptions");
	scrubber.preempt_divisor = 1;
        break;

      case PG::Scrubber::NEW_CHUNK:
        scrubber.primary_scrubmap = ScrubMap();
        scrubber.received_maps.clear();

	// begin (possible) preemption window
	if (scrub_preempted) {
	  scrubber.preempt_left--;
	  scrubber.preempt_divisor *= 2;
	  dout(10) << __func__ << " preempted, " << scrubber.preempt_left
		   << " left" << dendl;
	  scrub_preempted = false;
	}
	scrub_can_preempt = scrubber.preempt_left > 0;

        {
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
	  int min = std::max<int64_t>(3, cct->_conf->osd_scrub_chunk_min /
				      scrubber.preempt_divisor);
	  int max = std::max<int64_t>(min, cct->_conf->osd_scrub_chunk_max /
                                      scrubber.preempt_divisor);
          hobject_t start = scrubber.start;
	  hobject_t candidate_end;
	  vector<hobject_t> objects;
	  ret = get_pgbackend()->objects_list_partial(
	    start,
	    min,
	    max,
	    &objects,
	    &candidate_end);
	  ceph_assert(ret >= 0);

	  if (!objects.empty()) {
	    hobject_t back = objects.back();
	    while (candidate_end.is_head() &&
		   candidate_end == back.get_head()) {
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

	  if (!_range_available_for_scrub(scrubber.start, candidate_end)) {
	    // we'll be requeued by whatever made us unavailable for scrub
	    dout(10) << __func__ << ": scrub blocked somewhere in range "
		     << "[" << scrubber.start << ", " << candidate_end << ")"
		     << dendl;
	    done = true;
	    break;
	  }
	  scrubber.end = candidate_end;
	  if (scrubber.end > scrubber.max_end)
	    scrubber.max_end = scrubber.end;
        }

        // walk the log to find the latest update that affects our chunk
        scrubber.subset_last_update = eversion_t();
	for (auto p = projected_log.log.rbegin();
	     p != projected_log.log.rend();
	     ++p) {
          if (p->soid >= scrubber.start &&
	      p->soid < scrubber.end) {
            scrubber.subset_last_update = p->version;
            break;
	  }
	}
	if (scrubber.subset_last_update == eversion_t()) {
	  for (list<pg_log_entry_t>::const_reverse_iterator p =
		 pg_log.get_log().log.rbegin();
	       p != pg_log.get_log().log.rend();
	       ++p) {
	    if (p->soid >= scrubber.start &&
		p->soid < scrubber.end) {
	      scrubber.subset_last_update = p->version;
	      break;
	    }
	  }
	}

        scrubber.state = PG::Scrubber::WAIT_PUSHES;
        break;

      case PG::Scrubber::WAIT_PUSHES:
        if (active_pushes == 0) {
          scrubber.state = PG::Scrubber::WAIT_LAST_UPDATE;
        } else {
          dout(15) << "wait for pushes to apply" << dendl;
          done = true;
        }
        break;

      case PG::Scrubber::WAIT_LAST_UPDATE:
        if (last_update_applied < scrubber.subset_last_update) {
          // will be requeued by op_applied
          dout(15) << "wait for EC read/modify/writes to queue" << dendl;
          done = true;
	  break;
	}

        // ask replicas to scan
        scrubber.waiting_on_whom.insert(pg_whoami);

        // request maps from replicas
	for (set<pg_shard_t>::iterator i = acting_recovery_backfill.begin();
	     i != acting_recovery_backfill.end();
	     ++i) {
	  if (*i == pg_whoami) continue;
          _request_scrub_map(*i, scrubber.subset_last_update,
                             scrubber.start, scrubber.end, scrubber.deep,
			     scrubber.preempt_left > 0);
          scrubber.waiting_on_whom.insert(*i);
        }
	dout(10) << __func__ << " waiting_on_whom " << scrubber.waiting_on_whom
		 << dendl;

	scrubber.state = PG::Scrubber::BUILD_MAP;
	scrubber.primary_scrubmap_pos.reset();
        break;

      case PG::Scrubber::BUILD_MAP:
        ceph_assert(last_update_applied >= scrubber.subset_last_update);

        // build my own scrub map
	if (scrub_preempted) {
	  dout(10) << __func__ << " preempted" << dendl;
	  scrubber.state = PG::Scrubber::BUILD_MAP_DONE;
	  break;
	}
	ret = build_scrub_map_chunk(
	  scrubber.primary_scrubmap,
	  scrubber.primary_scrubmap_pos,
	  scrubber.start, scrubber.end,
	  scrubber.deep,
	  handle);
	if (ret == -EINPROGRESS) {
	  requeue_scrub();
	  done = true;
	  break;
	}
	scrubber.state = PG::Scrubber::BUILD_MAP_DONE;
	break;

      case PG::Scrubber::BUILD_MAP_DONE:
	if (scrubber.primary_scrubmap_pos.ret < 0) {
	  dout(5) << "error: " << scrubber.primary_scrubmap_pos.ret
		  << ", aborting" << dendl;
          scrub_clear_state();
          scrub_unreserve_replicas();
          return;
        }
	dout(10) << __func__ << " waiting_on_whom was "
		 << scrubber.waiting_on_whom << dendl;
	ceph_assert(scrubber.waiting_on_whom.count(pg_whoami));
        scrubber.waiting_on_whom.erase(pg_whoami);

        scrubber.state = PG::Scrubber::WAIT_REPLICAS;
        break;

      case PG::Scrubber::WAIT_REPLICAS:
        if (!scrubber.waiting_on_whom.empty()) {
          // will be requeued by sub_op_scrub_map
          dout(10) << "wait for replicas to build scrub map" << dendl;
          done = true;
	  break;
	}
	// end (possible) preemption window
	scrub_can_preempt = false;
	if (scrub_preempted) {
	  dout(10) << __func__ << " preempted, restarting chunk" << dendl;
	  scrubber.state = PG::Scrubber::NEW_CHUNK;
	} else {
          scrubber.state = PG::Scrubber::COMPARE_MAPS;
        }
        break;

      case PG::Scrubber::COMPARE_MAPS:
        ceph_assert(last_update_applied >= scrubber.subset_last_update);
        ceph_assert(scrubber.waiting_on_whom.empty());

        scrub_compare_maps();
	scrubber.start = scrubber.end;
	scrubber.run_callbacks();

        // requeue the writes from the chunk that just finished
        requeue_ops(waiting_for_scrub);

	scrubber.state = PG::Scrubber::WAIT_DIGEST_UPDATES;

	// fall-thru

      case PG::Scrubber::WAIT_DIGEST_UPDATES:
	if (scrubber.num_digest_updates_pending) {
	  dout(10) << __func__ << " waiting on "
		   << scrubber.num_digest_updates_pending
		   << " digest updates" << dendl;
	  done = true;
	  break;
	}

	scrubber.preempt_left = cct->_conf.get_val<uint64_t>(
	  "osd_scrub_max_preemptions");
	scrubber.preempt_divisor = 1;

	if (!(scrubber.end.is_max())) {
	  scrubber.state = PG::Scrubber::NEW_CHUNK;
	  requeue_scrub();
          done = true;
        } else {
          scrubber.state = PG::Scrubber::FINISH;
        }

	break;

      case PG::Scrubber::FINISH:
        scrub_finish();
        scrubber.state = PG::Scrubber::INACTIVE;
        done = true;

	if (!snap_trimq.empty()) {
	  dout(10) << "scrub finished, requeuing snap_trimmer" << dendl;
	  snap_trimmer_scrub_complete();
	}

        break;

      case PG::Scrubber::BUILD_MAP_REPLICA:
        // build my own scrub map
	if (scrub_preempted) {
	  dout(10) << __func__ << " preempted" << dendl;
	  ret = 0;
	} else {
	  ret = build_scrub_map_chunk(
	    scrubber.replica_scrubmap,
	    scrubber.replica_scrubmap_pos,
	    scrubber.start, scrubber.end,
	    scrubber.deep,
	    handle);
	}
	if (ret == -EINPROGRESS) {
	  requeue_scrub();
	  done = true;
	  break;
	}
	// reply
	{
	  MOSDRepScrubMap *reply = new MOSDRepScrubMap(
	    spg_t(info.pgid.pgid, get_primary().shard),
	    scrubber.replica_scrub_start,
	    pg_whoami);
	  reply->preempted = scrub_preempted;
	  ::encode(scrubber.replica_scrubmap, reply->get_data());
	  osd->send_message_osd_cluster(
	    get_primary().osd, reply,
	    scrubber.replica_scrub_start);
	}
	scrub_preempted = false;
	scrub_can_preempt = false;
	scrubber.state = PG::Scrubber::INACTIVE;
	scrubber.replica_scrubmap = ScrubMap();
	scrubber.replica_scrubmap_pos = ScrubMapBuilder();
	scrubber.start = hobject_t();
	scrubber.end = hobject_t();
	scrubber.max_end = hobject_t();
	done = true;
	break;

      default:
        ceph_abort();
    }
  }
  dout(20) << "scrub final state " << Scrubber::state_string(scrubber.state)
	   << " [" << scrubber.start << "," << scrubber.end << ")"
	   << " max_end " << scrubber.max_end << dendl;
}

bool PG::write_blocked_by_scrub(const hobject_t& soid)
{
  if (soid < scrubber.start || soid >= scrubber.end) {
    return false;
  }
  if (scrub_can_preempt) {
    if (!scrub_preempted) {
      dout(10) << __func__ << " " << soid << " preempted" << dendl;
      scrub_preempted = true;
    } else {
      dout(10) << __func__ << " " << soid << " already preempted" << dendl;
    }
    return false;
  }
  return true;
}

bool PG::range_intersects_scrub(const hobject_t &start, const hobject_t& end)
{
  // does [start, end] intersect [scrubber.start, scrubber.max_end)
  return (start < scrubber.max_end &&
	  end >= scrubber.start);
}

void PG::scrub_clear_state(bool has_error)
{
  ceph_assert(is_locked());
  state_clear(PG_STATE_SCRUBBING);
  if (!has_error)
    state_clear(PG_STATE_REPAIR);
  state_clear(PG_STATE_DEEP_SCRUB);
  publish_stats_to_osd();

  // active -> nothing.
  if (scrubber.active)
    osd->dec_scrubs_active();

  requeue_ops(waiting_for_scrub);

  scrubber.reset();

  // type-specific state clear
  _scrub_clear_state();
}

void PG::scrub_compare_maps() 
{
  dout(10) << __func__ << " has maps, analyzing" << dendl;

  // construct authoritative scrub map for type specific scrubbing
  scrubber.cleaned_meta_map.insert(scrubber.primary_scrubmap);
  map<hobject_t,
      pair<boost::optional<uint32_t>,
           boost::optional<uint32_t>>> missing_digest;

  map<pg_shard_t, ScrubMap *> maps;
  maps[pg_whoami] = &scrubber.primary_scrubmap;

  for (const auto& i : acting_recovery_backfill) {
    if (i == pg_whoami) continue;
    dout(2) << __func__ << " replica " << i << " has "
            << scrubber.received_maps[i].objects.size()
            << " items" << dendl;
    maps[i] = &scrubber.received_maps[i];
  }

  set<hobject_t> master_set;

  // Construct master set
  for (const auto map : maps) {
    for (const auto i : map.second->objects) {
      master_set.insert(i.first);
    }
  }

  stringstream ss;
  get_pgbackend()->be_omap_checks(maps, master_set,
                                  scrubber.omap_stats, ss);

  if (!ss.str().empty()) {
    osd->clog->warn(ss);
  }

  if (recovery_state.get_acting().size() > 1) {
    dout(10) << __func__ << "  comparing replica scrub maps" << dendl;

    // Map from object with errors to good peer
    map<hobject_t, list<pg_shard_t>> authoritative;

    dout(2) << __func__ << get_primary() << " has "
	    << scrubber.primary_scrubmap.objects.size() << " items" << dendl;

    ss.str("");
    ss.clear();

    get_pgbackend()->be_compare_scrubmaps(
      maps,
      master_set,
      state_test(PG_STATE_REPAIR),
      scrubber.missing,
      scrubber.inconsistent,
      authoritative,
      missing_digest,
      scrubber.shallow_errors,
      scrubber.deep_errors,
      scrubber.store.get(),
      info.pgid, recovery_state.get_acting(),
      ss);
    dout(2) << ss.str() << dendl;

    if (!ss.str().empty()) {
      osd->clog->error(ss);
    }

    for (map<hobject_t, list<pg_shard_t>>::iterator i = authoritative.begin();
	 i != authoritative.end();
	 ++i) {
      list<pair<ScrubMap::object, pg_shard_t> > good_peers;
      for (list<pg_shard_t>::const_iterator j = i->second.begin();
	   j != i->second.end();
	   ++j) {
	good_peers.emplace_back(maps[*j]->objects[i->first], *j);
      }
      scrubber.authoritative.emplace(i->first, good_peers);
    }

    for (map<hobject_t, list<pg_shard_t>>::iterator i = authoritative.begin();
	 i != authoritative.end();
	 ++i) {
      scrubber.cleaned_meta_map.objects.erase(i->first);
      scrubber.cleaned_meta_map.objects.insert(
	*(maps[i->second.back()]->objects.find(i->first))
	);
    }
  }

  ScrubMap for_meta_scrub;
  scrubber.clean_meta_map(for_meta_scrub);

  // ok, do the pg-type specific scrubbing
  scrub_snapshot_metadata(for_meta_scrub, missing_digest);
  // Called here on the primary can use an authoritative map if it isn't the primary
  _scan_snaps(for_meta_scrub);
  if (!scrubber.store->empty()) {
    if (state_test(PG_STATE_REPAIR)) {
      dout(10) << __func__ << ": discarding scrub results" << dendl;
      scrubber.store->flush(nullptr);
    } else {
      dout(10) << __func__ << ": updating scrub object" << dendl;
      ObjectStore::Transaction t;
      scrubber.store->flush(&t);
      osd->store->queue_transaction(ch, std::move(t), nullptr);
    }
  }
}

bool PG::scrub_process_inconsistent()
{
  dout(10) << __func__ << ": checking authoritative" << dendl;
  bool repair = state_test(PG_STATE_REPAIR);
  bool deep_scrub = state_test(PG_STATE_DEEP_SCRUB);
  const char *mode = (repair ? "repair": (deep_scrub ? "deep-scrub" : "scrub"));
  
  // authoriative only store objects which missing or inconsistent.
  if (!scrubber.authoritative.empty()) {
    stringstream ss;
    ss << info.pgid << " " << mode << " "
       << scrubber.missing.size() << " missing, "
       << scrubber.inconsistent.size() << " inconsistent objects";
    dout(2) << ss.str() << dendl;
    osd->clog->error(ss);
    if (repair) {
      state_clear(PG_STATE_CLEAN);
      for (map<hobject_t, list<pair<ScrubMap::object, pg_shard_t> >>::iterator i =
	     scrubber.authoritative.begin();
	   i != scrubber.authoritative.end();
	   ++i) {
	set<pg_shard_t>::iterator j;

	auto missing_entry = scrubber.missing.find(i->first);
	if (missing_entry != scrubber.missing.end()) {
	  for (j = missing_entry->second.begin();
	       j != missing_entry->second.end();
	       ++j) {
	    repair_object(
	      i->first,
	      &(i->second),
	      *j);
	    ++scrubber.fixed;
	  }
	}
	if (scrubber.inconsistent.count(i->first)) {
	  for (j = scrubber.inconsistent[i->first].begin(); 
	       j != scrubber.inconsistent[i->first].end(); 
	       ++j) {
	    repair_object(i->first, 
	      &(i->second),
	      *j);
	    ++scrubber.fixed;
	  }
	}
      }
    }
  }
  return (!scrubber.authoritative.empty() && repair);
}

bool PG::ops_blocked_by_scrub() const {
  return (waiting_for_scrub.size() != 0);
}

// the part that actually finalizes a scrub
void PG::scrub_finish() 
{
  dout(20) << __func__ << dendl;
  bool repair = state_test(PG_STATE_REPAIR);
  bool do_deep_scrub = false;
  // if the repair request comes from auto-repair and large number of errors,
  // we would like to cancel auto-repair
  if (repair && scrubber.auto_repair
      && scrubber.authoritative.size() > cct->_conf->osd_scrub_auto_repair_num_errors) {
    state_clear(PG_STATE_REPAIR);
    repair = false;
  }
  bool deep_scrub = state_test(PG_STATE_DEEP_SCRUB);
  const char *mode = (repair ? "repair": (deep_scrub ? "deep-scrub" : "scrub"));

  // if a regular scrub had errors within the limit, do a deep scrub to auto repair.
  if (scrubber.deep_scrub_on_error
      && scrubber.authoritative.size() <= cct->_conf->osd_scrub_auto_repair_num_errors) {
    ceph_assert(!deep_scrub);
    scrubber.deep_scrub_on_error = false;
    do_deep_scrub = true;
    dout(20) << __func__ << " Try to auto repair after scrub errors" << dendl;
  }

  // type-specific finish (can tally more errors)
  _scrub_finish();

  bool has_error = scrub_process_inconsistent();

  {
    stringstream oss;
    oss << info.pgid.pgid << " " << mode << " ";
    int total_errors = scrubber.shallow_errors + scrubber.deep_errors;
    if (total_errors)
      oss << total_errors << " errors";
    else
      oss << "ok";
    if (!deep_scrub && info.stats.stats.sum.num_deep_scrub_errors)
      oss << " ( " << info.stats.stats.sum.num_deep_scrub_errors
          << " remaining deep scrub error details lost)";
    if (repair)
      oss << ", " << scrubber.fixed << " fixed";
    if (total_errors)
      osd->clog->error(oss);
    else
      osd->clog->debug(oss);
  }

  // Since we don't know which errors were fixed, we can only clear them
  // when every one has been fixed.
  if (repair) {
    if (scrubber.fixed == scrubber.shallow_errors + scrubber.deep_errors) {
      ceph_assert(deep_scrub);
      scrubber.shallow_errors = scrubber.deep_errors = 0;
      dout(20) << __func__ << " All may be fixed" << dendl;
    } else if (has_error) {
      // Deep scrub in order to get corrected error counts
      scrub_after_recovery = true;
      dout(20) << __func__ << " Set scrub_after_recovery" << dendl;
    } else if (scrubber.shallow_errors || scrubber.deep_errors) {
      // We have errors but nothing can be fixed, so there is no repair
      // possible.
      state_set(PG_STATE_FAILED_REPAIR);
      dout(10) << __func__ << " " << (scrubber.shallow_errors + scrubber.deep_errors)
	       << " error(s) present with no repair possible" << dendl;
    }
  }

  {
    // finish up
    ObjectStore::Transaction t;
    recovery_state.update_stats(
      [this, do_deep_scrub, deep_scrub](auto &history, auto &stats) {
	utime_t now = ceph_clock_now();
	history.last_scrub = recovery_state.get_info().last_update;
	history.last_scrub_stamp = now;
	if (scrubber.deep) {
	  history.last_deep_scrub = recovery_state.get_info().last_update;
	  history.last_deep_scrub_stamp = now;
	}

	if (deep_scrub) {
	  if ((scrubber.shallow_errors == 0) && (scrubber.deep_errors == 0))
	    history.last_clean_scrub_stamp = now;
	  stats.stats.sum.num_shallow_scrub_errors = scrubber.shallow_errors;
	  stats.stats.sum.num_deep_scrub_errors = scrubber.deep_errors;
	  stats.stats.sum.num_large_omap_objects = scrubber.omap_stats.large_omap_objects;
	  stats.stats.sum.num_omap_bytes = scrubber.omap_stats.omap_bytes;
	  stats.stats.sum.num_omap_keys = scrubber.omap_stats.omap_keys;
	  dout(25) << __func__ << " shard " << pg_whoami << " num_omap_bytes = "
		   << stats.stats.sum.num_omap_bytes << " num_omap_keys = "
		   << stats.stats.sum.num_omap_keys << dendl;
	} else {
	  stats.stats.sum.num_shallow_scrub_errors = scrubber.shallow_errors;
	  // XXX: last_clean_scrub_stamp doesn't mean the pg is not inconsistent
	  // because of deep-scrub errors
	  if (scrubber.shallow_errors == 0)
	    history.last_clean_scrub_stamp = now;
	}
	stats.stats.sum.num_scrub_errors =
	  stats.stats.sum.num_shallow_scrub_errors +
	  stats.stats.sum.num_deep_scrub_errors;
	if (scrubber.check_repair) {
	  scrubber.check_repair = false;
	  if (info.stats.stats.sum.num_scrub_errors) {
	    state_set(PG_STATE_FAILED_REPAIR);
	    dout(10) << __func__ << " " << info.stats.stats.sum.num_scrub_errors
		     << " error(s) still present after re-scrub" << dendl;
	  }
	}
	if (do_deep_scrub) {
	  // XXX: Auto scrub won't activate if must_scrub is set, but
	  // setting the scrub stamps affects what users see.
	  utime_t stamp = utime_t(0,1);
	  set_last_scrub_stamp(stamp, history, stats);
	  set_last_deep_scrub_stamp(stamp, history, stats);
	}
	return true;
      },
      &t);
    int tr = osd->store->queue_transaction(ch, std::move(t), NULL);
    ceph_assert(tr == 0);
  }

  if (has_error) {
    queue_peering_event(
      PGPeeringEventRef(
	std::make_shared<PGPeeringEvent>(
	  get_osdmap_epoch(),
	  get_osdmap_epoch(),
	  PeeringState::DoRecovery())));
  }

  scrub_clear_state(has_error);
  scrub_unreserve_replicas();

  if (is_active() && is_primary()) {
    recovery_state.share_pg_info();
  }
}

bool PG::append_log_entries_update_missing(
  const mempool::osd_pglog::list<pg_log_entry_t> &entries,
  ObjectStore::Transaction &t, boost::optional<eversion_t> trim_to,
  boost::optional<eversion_t> roll_forward_to)
{
  ceph_assert(!entries.empty());
  ceph_assert(entries.begin()->version > info.last_update);

  PGLogEntryHandler rollbacker{this, &t};
  bool invalidate_stats =
    pg_log.append_new_log_entries(info.last_backfill,
				  info.last_backfill_bitwise,
				  entries,
				  &rollbacker);

  if (roll_forward_to && entries.rbegin()->soid > info.last_backfill) {
    pg_log.roll_forward(&rollbacker);
  }
  if (roll_forward_to && *roll_forward_to > pg_log.get_can_rollback_to()) {
    pg_log.roll_forward_to(*roll_forward_to, &rollbacker);
    last_rollback_info_trimmed_to_applied = *roll_forward_to;
  }

  info.last_update = pg_log.get_head();

  if (pg_log.get_missing().num_missing() == 0) {
    // advance last_complete since nothing else is missing!
    info.last_complete = info.last_update;
  }
  info.stats.stats_invalid = info.stats.stats_invalid || invalidate_stats;

  dout(20) << __func__ << " trim_to bool = " << bool(trim_to) << " trim_to = " << (trim_to ? *trim_to : eversion_t()) << dendl;
  if (trim_to)
    pg_log.trim(*trim_to, info);
  dirty_info = true;
  write_if_dirty(t);
  return invalidate_stats;
}


void PG::merge_new_log_entries(
  const mempool::osd_pglog::list<pg_log_entry_t> &entries,
  ObjectStore::Transaction &t,
  boost::optional<eversion_t> trim_to,
  boost::optional<eversion_t> roll_forward_to)
{
  dout(10) << __func__ << " " << entries << dendl;
  ceph_assert(is_primary());

  bool rebuild_missing = append_log_entries_update_missing(entries, t, trim_to, roll_forward_to);
  for (set<pg_shard_t>::const_iterator i = acting_recovery_backfill.begin();
       i != acting_recovery_backfill.end();
       ++i) {
    pg_shard_t peer(*i);
    if (peer == pg_whoami) continue;
    ceph_assert(peer_missing.count(peer));
    ceph_assert(peer_info.count(peer));
    pg_missing_t& pmissing(peer_missing[peer]);
    dout(20) << __func__ << " peer_missing for " << peer << " = " << pmissing << dendl;
    pg_info_t& pinfo(peer_info[peer]);
    bool invalidate_stats = PGLog::append_log_entries_update_missing(
      pinfo.last_backfill,
      info.last_backfill_bitwise,
      entries,
      true,
      NULL,
      pmissing,
      NULL,
      this);
    pinfo.last_update = info.last_update;
    pinfo.stats.stats_invalid = pinfo.stats.stats_invalid || invalidate_stats;
    rebuild_missing = rebuild_missing || invalidate_stats;
  }

  if (!rebuild_missing) {
    return;
  }

  for (auto &&i: entries) {
    missing_loc.rebuild(
      i.soid,
      pg_whoami,
      acting_recovery_backfill,
      info,
      pg_log.get_missing(),
      peer_missing,
      peer_info);
  }
}

bool PG::old_peering_msg(epoch_t reply_epoch, epoch_t query_epoch)
{
  if (last_peering_reset > reply_epoch ||
      last_peering_reset > query_epoch) {
    dout(10) << "old_peering_msg reply_epoch " << reply_epoch << " query_epoch " << query_epoch
	     << " last_peering_reset " << last_peering_reset
	     << dendl;
    return true;
  }
  return false;
}

struct FlushState {
  PGRef pg;
  epoch_t epoch;
  FlushState(PG *pg, epoch_t epoch) : pg(pg), epoch(epoch) {}
  ~FlushState() {
    pg->lock();
    if (!pg->pg_has_reset_since(epoch)) {
      pg->recovery_state.complete_flush();
    }
    pg->unlock();
  }
};
typedef std::shared_ptr<FlushState> FlushStateRef;

void PG::start_flush_on_transaction(ObjectStore::Transaction *t)
{
  // flush in progress ops
  FlushStateRef flush_trigger (std::make_shared<FlushState>(
                               this, get_osdmap_epoch()));
  t->register_on_applied(new ContainerContext<FlushStateRef>(flush_trigger));
  t->register_on_commit(new ContainerContext<FlushStateRef>(flush_trigger));
}

bool PG::try_flush_or_schedule_async()
{
  
  Context *c = new QueuePeeringEvt(
    this, get_osdmap_epoch(), PeeringState::IntervalFlush());
  if (!ch->flush_commit(c)) {
    return false;
  } else {
    delete c;
    return true;
  }
}

ostream& operator<<(ostream& out, const PG& pg)
{
  out << pg.recovery_state;
  if (pg.scrubber.must_repair)
    out << " MUST_REPAIR";
  if (pg.scrubber.auto_repair)
    out << " AUTO_REPAIR";
  if (pg.scrubber.check_repair)
    out << " CHECK_REPAIR";
  if (pg.scrubber.deep_scrub_on_error)
    out << " DEEP_SCRUB_ON_ERROR";
  if (pg.scrubber.must_deep_scrub)
    out << " MUST_DEEP_SCRUB";
  if (pg.scrubber.must_scrub)
    out << " MUST_SCRUB";

  if (pg.recovery_ops_active)
    out << " rops=" << pg.recovery_ops_active;

  //out << " (" << pg.pg_log.get_tail() << "," << pg.pg_log.get_head() << "]";
  if (pg.recovery_state.have_missing()) {
    out << " m=" << pg.recovery_state.get_num_missing();
    if (pg.is_primary()) {
      uint64_t unfound = pg.recovery_state.get_num_unfound();
      if (unfound)
	out << " u=" << unfound;
    }
  }
  if (!pg.is_clean()) {
    out << " mbc=" << pg.recovery_state.get_missing_by_count();
  }
  if (!pg.snap_trimq.empty()) {
    out << " trimq=";
    // only show a count if the set is large
    if (pg.snap_trimq.num_intervals() > 16) {
      out << pg.snap_trimq.size();
    } else {
      out << pg.snap_trimq;
    }
  }
  if (!pg.recovery_state.get_info().purged_snaps.empty()) {
    out << " ps="; // snap trim queue / purged snaps
    if (pg.recovery_state.get_info().purged_snaps.num_intervals() > 16) {
      out << pg.recovery_state.get_info().purged_snaps.size();
    } else {
      out << pg.recovery_state.get_info().purged_snaps;
    }
  }

  out << "]";


  return out;
}

bool PG::can_discard_op(OpRequestRef& op)
{
  const MOSDOp *m = static_cast<const MOSDOp*>(op->get_req());
  if (cct->_conf->osd_discard_disconnected_ops && OSD::op_is_discardable(m)) {
    dout(20) << " discard " << *m << dendl;
    return true;
  }

  if (m->get_map_epoch() < info.history.same_primary_since) {
    dout(7) << " changed after " << m->get_map_epoch()
	    << ", dropping " << *m << dendl;
    return true;
  }

  if (m->get_connection()->has_feature(CEPH_FEATURE_RESEND_ON_SPLIT)) {
    // >= luminous client
    if (m->get_connection()->has_feature(CEPH_FEATURE_SERVER_NAUTILUS)) {
      // >= nautilus client
      if (m->get_map_epoch() < pool.info.get_last_force_op_resend()) {
	dout(7) << __func__ << " sent before last_force_op_resend "
		<< pool.info.last_force_op_resend
		<< ", dropping" << *m << dendl;
	return true;
      }
    } else {
      // == < nautilus client (luminous or mimic)
      if (m->get_map_epoch() < pool.info.get_last_force_op_resend_prenautilus()) {
	dout(7) << __func__ << " sent before last_force_op_resend_prenautilus "
		<< pool.info.last_force_op_resend_prenautilus
		<< ", dropping" << *m << dendl;
	return true;
      }
    }
    if (m->get_map_epoch() < info.history.last_epoch_split) {
      dout(7) << __func__ << " pg split in "
	      << info.history.last_epoch_split << ", dropping" << dendl;
      return true;
    }
  } else if (m->get_connection()->has_feature(CEPH_FEATURE_OSD_POOLRESEND)) {
    // < luminous client
    if (m->get_map_epoch() < pool.info.get_last_force_op_resend_preluminous()) {
      dout(7) << __func__ << " sent before last_force_op_resend_preluminous "
	      << pool.info.last_force_op_resend_preluminous
	      << ", dropping" << *m << dendl;
      return true;
    }
  }

  return false;
}

template<typename T, int MSGTYPE>
bool PG::can_discard_replica_op(OpRequestRef& op)
{
  const T *m = static_cast<const T *>(op->get_req());
  ceph_assert(m->get_type() == MSGTYPE);

  int from = m->get_source().num();

  // if a repop is replied after a replica goes down in a new osdmap, and
  // before the pg advances to this new osdmap, the repop replies before this
  // repop can be discarded by that replica OSD, because the primary resets the
  // connection to it when handling the new osdmap marking it down, and also
  // resets the messenger sesssion when the replica reconnects. to avoid the
  // out-of-order replies, the messages from that replica should be discarded.
  OSDMapRef next_map = osd->get_next_osdmap();
  if (next_map->is_down(from))
    return true;
  /* Mostly, this overlaps with the old_peering_msg
   * condition.  An important exception is pushes
   * sent by replicas not in the acting set, since
   * if such a replica goes down it does not cause
   * a new interval. */
  if (next_map->get_down_at(from) >= m->map_epoch)
    return true;

  // same pg?
  //  if pg changes _at all_, we reset and repeer!
  if (old_peering_msg(m->map_epoch, m->map_epoch)) {
    dout(10) << "can_discard_replica_op pg changed " << info.history
	     << " after " << m->map_epoch
	     << ", dropping" << dendl;
    return true;
  }
  return false;
}

bool PG::can_discard_scan(OpRequestRef op)
{
  const MOSDPGScan *m = static_cast<const MOSDPGScan *>(op->get_req());
  ceph_assert(m->get_type() == MSG_OSD_PG_SCAN);

  if (old_peering_msg(m->map_epoch, m->query_epoch)) {
    dout(10) << " got old scan, ignoring" << dendl;
    return true;
  }
  return false;
}

bool PG::can_discard_backfill(OpRequestRef op)
{
  const MOSDPGBackfill *m = static_cast<const MOSDPGBackfill *>(op->get_req());
  ceph_assert(m->get_type() == MSG_OSD_PG_BACKFILL);

  if (old_peering_msg(m->map_epoch, m->query_epoch)) {
    dout(10) << " got old backfill, ignoring" << dendl;
    return true;
  }

  return false;

}

bool PG::can_discard_request(OpRequestRef& op)
{
  switch (op->get_req()->get_type()) {
  case CEPH_MSG_OSD_OP:
    return can_discard_op(op);
  case CEPH_MSG_OSD_BACKOFF:
    return false; // never discard
  case MSG_OSD_REPOP:
    return can_discard_replica_op<MOSDRepOp, MSG_OSD_REPOP>(op);
  case MSG_OSD_PG_PUSH:
    return can_discard_replica_op<MOSDPGPush, MSG_OSD_PG_PUSH>(op);
  case MSG_OSD_PG_PULL:
    return can_discard_replica_op<MOSDPGPull, MSG_OSD_PG_PULL>(op);
  case MSG_OSD_PG_PUSH_REPLY:
    return can_discard_replica_op<MOSDPGPushReply, MSG_OSD_PG_PUSH_REPLY>(op);
  case MSG_OSD_REPOPREPLY:
    return can_discard_replica_op<MOSDRepOpReply, MSG_OSD_REPOPREPLY>(op);
  case MSG_OSD_PG_RECOVERY_DELETE:
    return can_discard_replica_op<MOSDPGRecoveryDelete, MSG_OSD_PG_RECOVERY_DELETE>(op);

  case MSG_OSD_PG_RECOVERY_DELETE_REPLY:
    return can_discard_replica_op<MOSDPGRecoveryDeleteReply, MSG_OSD_PG_RECOVERY_DELETE_REPLY>(op);

  case MSG_OSD_EC_WRITE:
    return can_discard_replica_op<MOSDECSubOpWrite, MSG_OSD_EC_WRITE>(op);
  case MSG_OSD_EC_WRITE_REPLY:
    return can_discard_replica_op<MOSDECSubOpWriteReply, MSG_OSD_EC_WRITE_REPLY>(op);
  case MSG_OSD_EC_READ:
    return can_discard_replica_op<MOSDECSubOpRead, MSG_OSD_EC_READ>(op);
  case MSG_OSD_EC_READ_REPLY:
    return can_discard_replica_op<MOSDECSubOpReadReply, MSG_OSD_EC_READ_REPLY>(op);
  case MSG_OSD_REP_SCRUB:
    return can_discard_replica_op<MOSDRepScrub, MSG_OSD_REP_SCRUB>(op);
  case MSG_OSD_SCRUB_RESERVE:
    return can_discard_replica_op<MOSDScrubReserve, MSG_OSD_SCRUB_RESERVE>(op);
  case MSG_OSD_REP_SCRUBMAP:
    return can_discard_replica_op<MOSDRepScrubMap, MSG_OSD_REP_SCRUBMAP>(op);
  case MSG_OSD_PG_UPDATE_LOG_MISSING:
    return can_discard_replica_op<
      MOSDPGUpdateLogMissing, MSG_OSD_PG_UPDATE_LOG_MISSING>(op);
  case MSG_OSD_PG_UPDATE_LOG_MISSING_REPLY:
    return can_discard_replica_op<
      MOSDPGUpdateLogMissingReply, MSG_OSD_PG_UPDATE_LOG_MISSING_REPLY>(op);

  case MSG_OSD_PG_SCAN:
    return can_discard_scan(op);
  case MSG_OSD_PG_BACKFILL:
    return can_discard_backfill(op);
  case MSG_OSD_PG_BACKFILL_REMOVE:
    return can_discard_replica_op<MOSDPGBackfillRemove,
				  MSG_OSD_PG_BACKFILL_REMOVE>(op);
  }
  return true;
}

void PG::do_peering_event(PGPeeringEventRef evt, PeeringCtx *rctx)
{
  dout(10) << __func__ << ": " << evt->get_desc() << dendl;
  ceph_assert(have_same_or_newer_map(evt->get_epoch_sent()));
  if (old_peering_evt(evt)) {
    dout(10) << "discard old " << evt->get_desc() << dendl;
  } else {
    recovery_state.handle_event(evt, rctx);
  }
  // write_if_dirty regardless of path above to ensure we capture any work
  // done by OSD::advance_pg().
  write_if_dirty(*rctx->transaction);
}

void PG::queue_peering_event(PGPeeringEventRef evt)
{
  if (old_peering_evt(evt))
    return;
  osd->osd->enqueue_peering_evt(info.pgid, evt);
}

void PG::queue_null(epoch_t msg_epoch,
		    epoch_t query_epoch)
{
  dout(10) << "null" << dendl;
  queue_peering_event(
    PGPeeringEventRef(std::make_shared<PGPeeringEvent>(msg_epoch, query_epoch,
					 NullEvt())));
}

void PG::find_unfound(epoch_t queued, PeeringCtx *rctx)
{
  /*
    * if we couldn't start any recovery ops and things are still
    * unfound, see if we can discover more missing object locations.
    * It may be that our initial locations were bad and we errored
    * out while trying to pull.
    */
  recovery_state.discover_all_missing(*rctx->query_map);
  if (rctx->query_map->empty()) {
    string action;
    if (state_test(PG_STATE_BACKFILLING)) {
      auto evt = PGPeeringEventRef(
	new PGPeeringEvent(
	  queued,
	  queued,
	  PeeringState::UnfoundBackfill()));
      queue_peering_event(evt);
      action = "in backfill";
    } else if (state_test(PG_STATE_RECOVERING)) {
      auto evt = PGPeeringEventRef(
	new PGPeeringEvent(
	  queued,
	  queued,
	  PeeringState::UnfoundRecovery()));
      queue_peering_event(evt);
      action = "in recovery";
    } else {
      action = "already out of recovery/backfill";
    }
    dout(10) << __func__ << ": no luck, giving up on this pg for now (" << action << ")" << dendl;
  } else {
    dout(10) << __func__ << ": no luck, giving up on this pg for now (queue_recovery)" << dendl;
    queue_recovery();
  }
}

void PG::handle_advance_map(
  OSDMapRef osdmap, OSDMapRef lastmap,
  vector<int>& newup, int up_primary,
  vector<int>& newacting, int acting_primary,
  PeeringCtx *rctx)
{
  dout(10) << __func__ << ": " << osdmap->get_epoch() << dendl;
  osd_shard->update_pg_epoch(pg_slot, osdmap->get_epoch());
  recovery_state.advance_map(
    osdmap,
    lastmap,
    newup,
    up_primary,
    newacting,
    acting_primary,
    rctx);
}

void PG::handle_activate_map(PeeringCtx *rctx)
{
  dout(10) << __func__ << ": " << get_osdmap()->get_epoch()
	   << dendl;
  recovery_state.activate_map(rctx);

  requeue_map_waiters();
}

void PG::handle_initialize(PeeringCtx *rctx)
{
  dout(10) << __func__ << dendl;
  PeeringState::Initialize evt;
  recovery_state.handle_event(evt, rctx);
}

void PG::handle_query_state(Formatter *f)
{
  dout(10) << "handle_query_state" << dendl;
  PeeringState::QueryState q(f);
  recovery_state.handle_event(q, 0);

  if (is_primary() && is_active()) {
    f->open_object_section("scrub");
    f->dump_stream("scrubber.epoch_start") << scrubber.epoch_start;
    f->dump_bool("scrubber.active", scrubber.active);
    f->dump_string("scrubber.state", PG::Scrubber::state_string(scrubber.state));
    f->dump_stream("scrubber.start") << scrubber.start;
    f->dump_stream("scrubber.end") << scrubber.end;
    f->dump_stream("scrubber.max_end") << scrubber.max_end;
    f->dump_stream("scrubber.subset_last_update") << scrubber.subset_last_update;
    f->dump_bool("scrubber.deep", scrubber.deep);
    {
      f->open_array_section("scrubber.waiting_on_whom");
      for (set<pg_shard_t>::iterator p = scrubber.waiting_on_whom.begin();
	   p != scrubber.waiting_on_whom.end();
	   ++p) {
	f->dump_stream("shard") << *p;
      }
      f->close_section();
    }
    f->close_section();
  }
}

void PG::on_pool_change()
{
  auto r = osd->store->set_collection_opts(ch, pool.info.opts);
  if(r < 0 && r != -EOPNOTSUPP) {
    derr << __func__ << " set_collection_opts returns error:" << r << dendl;
  }
  plpg_on_pool_change();
}

void PG::C_DeleteMore::complete(int r) {
  ceph_assert(r == 0);
  pg->lock();
  if (!pg->pg_has_reset_since(epoch)) {
    pg->osd->queue_for_pg_delete(pg->get_pgid(), epoch);
  }
  pg->unlock();
  delete this;
}

void PG::do_delete_work(ObjectStore::Transaction *t)
{
  dout(10) << __func__ << dendl;

  {
    float osd_delete_sleep = osd->osd->get_osd_delete_sleep();
    if (osd_delete_sleep > 0 && delete_needs_sleep) {
      epoch_t e = get_osdmap()->get_epoch();
      PGRef pgref(this);
      auto delete_requeue_callback = new FunctionContext([this, pgref, e](int r) {
        dout(20) << __func__ << " wake up at "
                 << ceph_clock_now()
	         << ", re-queuing delete" << dendl;
        lock();
        delete_needs_sleep = false;
        if (!pg_has_reset_since(e)) {
          osd->queue_for_pg_delete(get_pgid(), e);
        }
        unlock();
      });

      utime_t delete_schedule_time = ceph_clock_now();
      delete_schedule_time += osd_delete_sleep;
      Mutex::Locker l(osd->sleep_lock);
      osd->sleep_timer.add_event_at(delete_schedule_time,
	                                        delete_requeue_callback);
      dout(20) << __func__ << " Delete scheduled at " << delete_schedule_time << dendl;
      return;
    }
  }

  delete_needs_sleep = true;

  vector<ghobject_t> olist;
  int max = std::min(osd->store->get_ideal_list_max(),
		     (int)cct->_conf->osd_target_transaction_size);
  ghobject_t next;
  osd->store->collection_list(
    ch,
    next,
    ghobject_t::get_max(),
    max,
    &olist,
    &next);
  dout(20) << __func__ << " " << olist << dendl;

  OSDriver::OSTransaction _t(osdriver.get_transaction(t));
  int64_t num = 0;
  for (auto& oid : olist) {
    if (oid.is_pgmeta()) {
      continue;
    }
    int r = snap_mapper.remove_oid(oid.hobj, &_t);
    if (r != 0 && r != -ENOENT) {
      ceph_abort();
    }
    t->remove(coll, oid);
    ++num;
  }
  if (num) {
    dout(20) << __func__ << " deleting " << num << " objects" << dendl;
    Context *fin = new C_DeleteMore(this, get_osdmap_epoch());
    t->register_on_commit(fin);
  } else {
    dout(20) << __func__ << " finished" << dendl;
    if (cct->_conf->osd_inject_failure_on_pg_removal) {
      _exit(1);
    }

    // final flush here to ensure completions drop refs.  Of particular concern
    // are the SnapMapper ContainerContexts.
    {
      PGRef pgref(this);
      PGLog::clear_info_log(info.pgid, t);
      t->remove_collection(coll);
      t->register_on_commit(new ContainerContext<PGRef>(pgref));
      t->register_on_applied(new ContainerContext<PGRef>(pgref));
      osd->store->queue_transaction(ch, std::move(*t));
    }
    ch->flush();

    if (!osd->try_finish_pg_delete(this, pool.info.get_pg_num())) {
      dout(1) << __func__ << " raced with merge, reinstantiating" << dendl;
      ch = osd->store->create_new_collection(coll);
      _create(*t,
	      info.pgid,
	      info.pgid.get_split_bits(pool.info.get_pg_num()));
      _init(*t, info.pgid, &pool.info);
      recovery_state.reset_last_persisted();
      dirty_info = true;
      dirty_big_info = true;
    } else {
      deleted = true;

      // cancel reserver here, since the PG is about to get deleted and the
      // exit() methods don't run when that happens.
      osd->local_reserver.cancel_reservation(info.pgid);

      osd->logger->dec(l_osd_pg_removing);
    }
  }
}

int PG::pg_stat_adjust(osd_stat_t *ns)
{
  osd_stat_t &new_stat = *ns;
  if (is_primary()) {
    return 0;
  }
  // Adjust the kb_used by adding pending backfill data
  uint64_t reserved_num_bytes = get_reserved_num_bytes();

  // For now we don't consider projected space gains here
  // I suggest we have an optional 2 pass backfill that frees up
  // space in a first pass.  This could be triggered when at nearfull
  // or near to backfillfull.
  if (reserved_num_bytes > 0) {
    // TODO: Handle compression by adjusting by the PGs average
    // compression precentage.
    dout(20) << __func__ << " reserved_num_bytes " << (reserved_num_bytes >> 10) << "KiB"
             << " Before kb_used " << new_stat.statfs.kb_used() << "KiB" << dendl;
    if (new_stat.statfs.available > reserved_num_bytes)
      new_stat.statfs.available -= reserved_num_bytes;
    else
      new_stat.statfs.available = 0;
    dout(20) << __func__ << " After kb_used " << new_stat.statfs.kb_used() << "KiB" << dendl;
    return 1;
  }
  return 0;
}

ostream& operator<<(ostream& out, const PG::BackfillInterval& bi)
{
  out << "BackfillInfo(" << bi.begin << "-" << bi.end
      << " " << bi.objects.size() << " objects";
  if (!bi.objects.empty())
    out << " " << bi.objects;
  out << ")";
  return out;
}

void PG::dump_pgstate_history(Formatter *f)
{
  lock();
  recovery_state.dump_history(f);
  unlock();
}

void PG::dump_missing(Formatter *f)
{
  for (auto& i : pg_log.get_missing().get_items()) {
    f->open_object_section("object");
    f->dump_object("oid", i.first);
    f->dump_object("missing_info", i.second);
    if (missing_loc.needs_recovery(i.first)) {
      f->dump_bool("unfound", missing_loc.is_unfound(i.first));
      f->open_array_section("locations");
      for (auto l : missing_loc.get_locations(i.first)) {
	f->dump_object("shard", l);
      }
      f->close_section();
    }
    f->close_section();
  }
}

void PG::get_pg_stats(std::function<void(const pg_stat_t&, epoch_t lec)> f)
{
  pg_stats_publish_lock.Lock();
  if (pg_stats_publish_valid) {
    f(pg_stats_publish, pg_stats_publish.get_effective_last_epoch_clean());
  }
  pg_stats_publish_lock.Unlock();
}

void PG::with_heartbeat_peers(std::function<void(int)> f)
{
  heartbeat_peer_lock.Lock();
  for (auto p : heartbeat_peers) {
    f(p);
  }
  for (auto p : probe_targets) {
    f(p);
  }
  heartbeat_peer_lock.Unlock();
}
