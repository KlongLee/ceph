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

#ifndef CEPH_MDS_SERVER_H
#define CEPH_MDS_SERVER_H

#include <string_view>

#include <common/DecayCounter.h>

#include "MDSRank.h"
#include "Mutation.h"

class OSDMap;
class PerfCounters;
class LogEvent;
class EMetaBlob;
class EUpdate;
class MMDSSlaveRequest;
struct SnapInfo;
class MClientRequest;
class MClientReply;
class MDLog;

enum {
  l_mdss_first = 1000,
  l_mdss_dispatch_client_request,
  l_mdss_dispatch_slave_request,
  l_mdss_handle_client_request,
  l_mdss_handle_client_session,
  l_mdss_handle_slave_request,
  l_mdss_req_create_latency,
  l_mdss_req_getattr_latency,
  l_mdss_req_getfilelock_latency,
  l_mdss_req_link_latency,
  l_mdss_req_lookup_latency,
  l_mdss_req_lookuphash_latency,
  l_mdss_req_lookupino_latency,
  l_mdss_req_lookupname_latency,
  l_mdss_req_lookupparent_latency,
  l_mdss_req_lookupsnap_latency,
  l_mdss_req_lssnap_latency,
  l_mdss_req_mkdir_latency,
  l_mdss_req_mknod_latency,
  l_mdss_req_mksnap_latency,
  l_mdss_req_open_latency,
  l_mdss_req_readdir_latency,
  l_mdss_req_rename_latency,
  l_mdss_req_renamesnap_latency,
  l_mdss_req_rmdir_latency,
  l_mdss_req_rmsnap_latency,
  l_mdss_req_rmxattr_latency,
  l_mdss_req_setattr_latency,
  l_mdss_req_setdirlayout_latency,
  l_mdss_req_setfilelock_latency,
  l_mdss_req_setlayout_latency,
  l_mdss_req_setxattr_latency,
  l_mdss_req_symlink_latency,
  l_mdss_req_unlink_latency,
  l_mdss_cap_revoke_eviction,
  l_mdss_last,
};

class Server {
public:
  using clock = ceph::coarse_mono_clock;
  using time = ceph::coarse_mono_time;

private:
  MDSRank *mds;
  MDCache *mdcache;
  MDLog *mdlog;
  PerfCounters *logger;

  // OSDMap full status, used to generate ENOSPC on some operations
  bool is_full;

  // State for while in reconnect
  MDSInternalContext *reconnect_done;
  int failed_reconnects;
  bool reconnect_evicting;  // true if I am waiting for evictions to complete
                            // before proceeding to reconnect_gather_finish
  utime_t  reconnect_start;
  set<client_t> client_reconnect_gather;  // clients i need a reconnect msg from.

  feature_bitset_t supported_features;
  feature_bitset_t required_client_features;

  double cap_revoke_eviction_timeout = 0;

  friend class MDSContinuation;
  friend class ServerContext;
  friend class ServerLogContext;

public:
  bool terminating_sessions;

  explicit Server(MDSRank *m);
  ~Server() {
    g_ceph_context->get_perfcounters_collection()->remove(logger);
    delete logger;
    delete reconnect_done;
  }

  void create_logger();

  // message handler
  void dispatch(Message *m);

  void handle_osd_map();

  // -- sessions and recovery --
  bool waiting_for_reconnect(client_t c) const;
  void dump_reconnect_status(Formatter *f) const;

  void handle_client_session(class MClientSession *m);
  void _session_logged(Session *session, uint64_t state_seq, 
		       bool open, version_t pv, interval_set<inodeno_t>& inos,version_t piv);
  version_t prepare_force_open_sessions(map<client_t,entity_inst_t> &cm,
					map<client_t,client_metadata_t>& cmm,
					map<client_t,pair<Session*,uint64_t> >& smap);
  void finish_force_open_sessions(const map<client_t,pair<Session*,uint64_t> >& smap,
				  bool dec_import=true);
  void flush_client_sessions(set<client_t>& client_set, MDSGatherBuilder& gather);
  void finish_flush_session(Session *session, version_t seq);
  void terminate_sessions();
  void find_idle_sessions();
  void kill_session(Session *session, Context *on_safe);
  size_t apply_blacklist(const std::set<entity_addr_t> &blacklist);
  void journal_close_session(Session *session, int state, Context *on_safe);
  void reconnect_clients(MDSInternalContext *reconnect_done_);
  void handle_client_reconnect(class MClientReconnect *m);
  void infer_supported_features(Session *session, client_metadata_t& client_metadata);
  void update_required_client_features();

  //void process_reconnect_cap(CInode *in, int from, ceph_mds_cap_reconnect& capinfo);
  void reconnect_gather_finish();
  void reconnect_tick();
  void recover_filelocks(CInode *in, bufferlist locks, int64_t client);

  enum RecallFlags {
    NONE = 0,
    STEADY = (1<<0),
    ENFORCE_MAX = (1<<1),
  };
  std::pair<bool, uint64_t> recall_client_state(MDSGatherBuilder* gather, enum RecallFlags=RecallFlags::NONE);
  void force_clients_readonly();

  // -- requests --
  void handle_client_request(MClientRequest *m);

  void journal_and_reply(MDRequestRef& mdr, CInode *tracei, CDentry *tracedn,
			 LogEvent *le, MDSLogContextBase *fin);
  void submit_mdlog_entry(LogEvent *le, MDSLogContextBase *fin,
                          MDRequestRef& mdr, const char *evt);
  void dispatch_client_request(MDRequestRef& mdr);
  void perf_gather_op_latency(const MClientRequest* req, utime_t lat);
  void early_reply(MDRequestRef& mdr, CInode *tracei, CDentry *tracedn);
  void respond_to_request(MDRequestRef& mdr, int r = 0);
  void set_trace_dist(Session *session, MClientReply *reply, CInode *in, CDentry *dn,
		      snapid_t snapid,
		      int num_dentries_wanted,
		      MDRequestRef& mdr);

  void encode_empty_dirstat(bufferlist& bl);
  void encode_infinite_lease(bufferlist& bl);
  void encode_null_lease(bufferlist& bl);

  void handle_slave_request(MMDSSlaveRequest *m);
  void handle_slave_request_reply(MMDSSlaveRequest *m);
  void dispatch_slave_request(MDRequestRef& mdr);
  void handle_slave_auth_pin(MDRequestRef& mdr);
  void handle_slave_auth_pin_ack(MDRequestRef& mdr, MMDSSlaveRequest *ack);

  // some helpers
  bool check_fragment_space(MDRequestRef& mdr, CDir *in);
  bool check_access(MDRequestRef& mdr, CInode *in, unsigned mask);
  bool _check_access(Session *session, CInode *in, unsigned mask, int caller_uid, int caller_gid, int setattr_uid, int setattr_gid);
  CDir *validate_dentry_dir(MDRequestRef& mdr, CInode *diri, std::string_view dname);
  CDir *traverse_to_auth_dir(MDRequestRef& mdr, vector<CDentry*> &trace, filepath refpath);
  CDentry *prepare_null_dentry(MDRequestRef& mdr, CDir *dir, std::string_view dname, bool okexist=false);
  CDentry *prepare_stray_dentry(MDRequestRef& mdr, CInode *in);
  CInode* prepare_new_inode(MDRequestRef& mdr, CDir *dir, inodeno_t useino, unsigned mode,
			    file_layout_t *layout=NULL);
  void journal_allocated_inos(MDRequestRef& mdr, EMetaBlob *blob);
  void apply_allocated_inos(MDRequestRef& mdr, Session *session);

  CInode* rdlock_path_pin_ref(MDRequestRef& mdr, int n, set<SimpleLock*>& rdlocks, bool want_auth,
			      bool no_want_auth=false,
			      file_layout_t **layout=NULL,
			      bool no_lookup=false);
  CDentry* rdlock_path_xlock_dentry(MDRequestRef& mdr, int n,
                                    set<SimpleLock*>& rdlocks,
                                    set<SimpleLock*>& wrlocks,
				    set<SimpleLock*>& xlocks, bool okexist,
				    bool mustexist, bool alwaysxlock,
				    file_layout_t **layout=NULL);

  CDir* try_open_auth_dirfrag(CInode *diri, frag_t fg, MDRequestRef& mdr);


  // requests on existing inodes.
  void handle_client_getattr(MDRequestRef& mdr, bool is_lookup);
  void handle_client_lookup_ino(MDRequestRef& mdr,
				bool want_parent, bool want_dentry);
  void _lookup_snap_ino(MDRequestRef& mdr);
  void _lookup_ino_2(MDRequestRef& mdr, int r);
  void handle_client_readdir(MDRequestRef& mdr);
  void handle_client_file_setlock(MDRequestRef& mdr);
  void handle_client_file_readlock(MDRequestRef& mdr);

  void handle_client_setattr(MDRequestRef& mdr);
  void handle_client_setlayout(MDRequestRef& mdr);
  void handle_client_setdirlayout(MDRequestRef& mdr);

  int parse_quota_vxattr(string name, string value, quota_info_t *quota);
  void create_quota_realm(CInode *in);
  int parse_layout_vxattr(string name, string value, const OSDMap& osdmap,
			  file_layout_t *layout, bool validate=true);
  int check_layout_vxattr(MDRequestRef& mdr,
                          string name,
                          string value,
                          file_layout_t *layout);
  void handle_set_vxattr(MDRequestRef& mdr, CInode *cur,
			 file_layout_t *dir_layout,
			 set<SimpleLock*> rdlocks,
			 set<SimpleLock*> wrlocks,
			 set<SimpleLock*> xlocks);
  void handle_remove_vxattr(MDRequestRef& mdr, CInode *cur,
			    file_layout_t *dir_layout,
			    set<SimpleLock*> rdlocks,
			    set<SimpleLock*> wrlocks,
			    set<SimpleLock*> xlocks);
  void handle_client_setxattr(MDRequestRef& mdr);
  void handle_client_removexattr(MDRequestRef& mdr);

  void handle_client_fsync(MDRequestRef& mdr);

  // open
  void handle_client_open(MDRequestRef& mdr);
  void handle_client_openc(MDRequestRef& mdr);  // O_CREAT variant.
  void do_open_truncate(MDRequestRef& mdr, int cmode);  // O_TRUNC variant.

  // namespace changes
  void handle_client_mknod(MDRequestRef& mdr);
  void handle_client_mkdir(MDRequestRef& mdr);
  void handle_client_symlink(MDRequestRef& mdr);

  // link
  void handle_client_link(MDRequestRef& mdr);
  void _link_local(MDRequestRef& mdr, CDentry *dn, CInode *targeti);
  void _link_local_finish(MDRequestRef& mdr, CDentry *dn, CInode *targeti,
			  version_t, version_t, bool);

  void _link_remote(MDRequestRef& mdr, bool inc, CDentry *dn, CInode *targeti);
  void _link_remote_finish(MDRequestRef& mdr, bool inc, CDentry *dn, CInode *targeti,
			   version_t);

  void handle_slave_link_prep(MDRequestRef& mdr);
  void _logged_slave_link(MDRequestRef& mdr, CInode *targeti, bool adjust_realm);
  void _commit_slave_link(MDRequestRef& mdr, int r, CInode *targeti);
  void _committed_slave(MDRequestRef& mdr);  // use for rename, too
  void handle_slave_link_prep_ack(MDRequestRef& mdr, MMDSSlaveRequest *m);
  void do_link_rollback(bufferlist &rbl, mds_rank_t master, MDRequestRef& mdr);
  void _link_rollback_finish(MutationRef& mut, MDRequestRef& mdr,
			     map<client_t,MClientSnap*>& split);

  // unlink
  void handle_client_unlink(MDRequestRef& mdr);
  bool _dir_is_nonempty_unlocked(MDRequestRef& mdr, CInode *rmdiri);
  bool _dir_is_nonempty(MDRequestRef& mdr, CInode *rmdiri);
  void _unlink_local(MDRequestRef& mdr, CDentry *dn, CDentry *straydn);
  void _unlink_local_finish(MDRequestRef& mdr,
			    CDentry *dn, CDentry *straydn,
			    version_t);
  bool _rmdir_prepare_witness(MDRequestRef& mdr, mds_rank_t who, vector<CDentry*>& trace, CDentry *straydn);
  void handle_slave_rmdir_prep(MDRequestRef& mdr);
  void _logged_slave_rmdir(MDRequestRef& mdr, CDentry *srcdn, CDentry *straydn);
  void _commit_slave_rmdir(MDRequestRef& mdr, int r, CDentry *straydn);
  void handle_slave_rmdir_prep_ack(MDRequestRef& mdr, MMDSSlaveRequest *ack);
  void do_rmdir_rollback(bufferlist &rbl, mds_rank_t master, MDRequestRef& mdr);
  void _rmdir_rollback_finish(MDRequestRef& mdr, metareqid_t reqid, CDentry *dn, CDentry *straydn);

  // rename
  void handle_client_rename(MDRequestRef& mdr);
  void _rename_finish(MDRequestRef& mdr,
		      CDentry *srcdn, CDentry *destdn, CDentry *straydn);

  void handle_client_lssnap(MDRequestRef& mdr);
  void handle_client_mksnap(MDRequestRef& mdr);
  void _mksnap_finish(MDRequestRef& mdr, CInode *diri, SnapInfo &info);
  void handle_client_rmsnap(MDRequestRef& mdr);
  void _rmsnap_finish(MDRequestRef& mdr, CInode *diri, snapid_t snapid);
  void handle_client_renamesnap(MDRequestRef& mdr);
  void _renamesnap_finish(MDRequestRef& mdr, CInode *diri, snapid_t snapid);


  // helpers
  bool _rename_prepare_witness(MDRequestRef& mdr, mds_rank_t who, set<mds_rank_t> &witnesse,
			       vector<CDentry*>& srctrace, vector<CDentry*>& dsttrace, CDentry *straydn);
  version_t _rename_prepare_import(MDRequestRef& mdr, CDentry *srcdn, bufferlist *client_map_bl);
  bool _need_force_journal(CInode *diri, bool empty);
  void _rename_prepare(MDRequestRef& mdr,
		       EMetaBlob *metablob, bufferlist *client_map_bl,
		       CDentry *srcdn, CDentry *destdn, CDentry *straydn);
  /* set not_journaling=true if you're going to discard the results --
   * this bypasses the asserts to make sure we're journaling the right
   * things on the right nodes */
  void _rename_apply(MDRequestRef& mdr, CDentry *srcdn, CDentry *destdn, CDentry *straydn);

  // slaving
  void handle_slave_rename_prep(MDRequestRef& mdr);
  void handle_slave_rename_prep_ack(MDRequestRef& mdr, MMDSSlaveRequest *m);
  void handle_slave_rename_notify_ack(MDRequestRef& mdr, MMDSSlaveRequest *m);
  void _slave_rename_sessions_flushed(MDRequestRef& mdr);
  void _logged_slave_rename(MDRequestRef& mdr, CDentry *srcdn, CDentry *destdn, CDentry *straydn);
  void _commit_slave_rename(MDRequestRef& mdr, int r, CDentry *srcdn, CDentry *destdn, CDentry *straydn);
  void do_rename_rollback(bufferlist &rbl, mds_rank_t master, MDRequestRef& mdr, bool finish_mdr=false);
  void _rename_rollback_finish(MutationRef& mut, MDRequestRef& mdr, CDentry *srcdn, version_t srcdnpv,
			       CDentry *destdn, CDentry *staydn, map<client_t,MClientSnap*> splits[2],
			       bool finish_mdr);

  void evict_cap_revoke_non_responders();
  void handle_conf_change(const struct md_config_t *conf,
                          const std::set <std::string> &changed);

private:
  void reply_client_request(MDRequestRef& mdr, MClientReply *reply);
  void flush_session(Session *session, MDSGatherBuilder *gather);

  DecayCounter recall_counter;
  time last_recall_state;
};

#endif
