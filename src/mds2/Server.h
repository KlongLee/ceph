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
#include "CObject.h"

class MDSRank;
class MDCache;
class Locker;
class Session;
class SimpleLock;
class MClientRequest;
class MClientReply;
class MClientReconnect;
class MClientSession;
class LogEvent;

struct MDRequestImpl;
typedef ceph::shared_ptr<MDRequestImpl> MDRequestRef;

class Server {
public:
  MDSRank* const mds;
  MDCache* const &mdcache;
  Locker* const &locker;

protected:
  Session *get_session(Message *m);
public:
  Server(MDSRank *_mds);

  void dispatch(Message *m);
  void dispatch_client_request(MDRequestRef& mdr);
  void handle_client_reconnect(MClientReconnect *m);
  void handle_client_session(MClientSession *m);
  void handle_client_request(MClientRequest *m);

protected:
  void encode_null_lease(bufferlist& bl);
  void encode_empty_dirstat(bufferlist& bl);
  void lock_objects_for_trace(CInode *in, CDentry *dn, MDRequestRef& mdr);
  void set_trace_dist(Session *session, MClientReply *reply,
		      CInode *in, CDentry *dn, MDRequestRef& mdr);
  void respond_to_request(MDRequestRef& mdr, int r);
  void reply_client_request(MDRequestRef& mdr, MClientReply *reply);
  void early_reply(MDRequestRef& mdr);

  void journal_and_reply(MDRequestRef& mdr, int tracei, int tracedn,
		  	 LogEvent *le, MDSInternalContextBase *fin);

  CInodeRef prepare_new_inode(MDRequestRef& mdr, CDentryRef& dn, inodeno_t useino,
			      unsigned mode, file_layout_t *layout=NULL);
  CDentryRef prepare_stray_dentry(MDRequestRef& mdr, CInode *in);

  int rdlock_path_pin_ref(MDRequestRef& mdr, int n,
			  set<SimpleLock*> &rdlocks,
			  bool is_lookup);
  int rdlock_path_xlock_dentry(MDRequestRef& mdr, int n,
			       set<SimpleLock*>& rdlocks,
			       set<SimpleLock*>& wrlocks,
			       set<SimpleLock*>& xlocks,
			       bool okexist, bool mustexist);
  bool directory_is_nonempty(CInodeRef& diri);

  void handle_client_getattr(MDRequestRef& mdr, bool is_lookup);
  void handle_client_setattr(MDRequestRef& mdr);
  void handle_client_mknod(MDRequestRef& mdr);
  void handle_client_symlink(MDRequestRef& mdr);
  void handle_client_mkdir(MDRequestRef& mdr);
  void handle_client_readdir(MDRequestRef& mdr);
  void handle_client_unlink(MDRequestRef& mdr);
  void handle_client_link(MDRequestRef& mdr);
  void handle_client_rename(MDRequestRef& mdr);
  void do_open_truncate(MDRequestRef& mdr, int cmode);
  void handle_client_open(MDRequestRef& mdr);
  void handle_client_openc(MDRequestRef& mdr);

  void __inode_update_finish(MDRequestRef& mdr, bool truncate_smaller);
  void __mknod_finish(MDRequestRef& mdr);
  void __unlink_finish(MDRequestRef& mdr, version_t dnpv);
  void __link_finish(MDRequestRef& mdr, version_t dnpv);
  void __rename_finish(MDRequestRef& mdr, version_t srcdn_pv, version_t destdn_pv);
  friend class C_MDS_inode_update_finish;
  friend class C_MDS_mknod_finish;
  friend class C_MDS_unlink_finish;
  friend class C_MDS_link_finish;
  friend class C_MDS_rename_finish;
};

#endif
