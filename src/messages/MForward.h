// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2010 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 * Client requests often need to get forwarded from some monitor
 * to the leader. This class encapsulates the original message
 * along with the client's caps so the leader can do proper permissions
 * checking.
 */

#ifndef CEPH_MFORWARD_H
#define CEPH_MFORWARD_H

#include "msg/Message.h"
#include "mon/MonCap.h"
#include "include/encoding.h"

struct MForward : public Message {
  uint64_t tid;
  PaxosServiceMessage *msg;
  entity_inst_t client;
  MonCap client_caps;
  uint64_t conn_features;

  static const int HEAD_VERSION = 2;
  static const int COMPAT_VERSION = 0;

  MForward() : Message(MSG_FORWARD, HEAD_VERSION, COMPAT_VERSION),
               tid(0), msg(NULL), conn_features(0) {}
  //the message needs to have caps filled in!
  MForward(uint64_t t, PaxosServiceMessage *m) :
    Message(MSG_FORWARD, HEAD_VERSION, COMPAT_VERSION),
    tid(t), msg(m) {
    client = m->get_source_inst();
    client_caps = m->get_session()->caps;
    conn_features = m->get_connection()->get_features();
  }
  MForward(uint64_t t, PaxosServiceMessage *m, const MonCap& caps) :
    Message(MSG_FORWARD, HEAD_VERSION, COMPAT_VERSION),
    tid(t), msg(m), client_caps(caps) {
    client = m->get_source_inst();
    conn_features = m->get_connection()->get_features();
  }
private:
  ~MForward() {
    if (msg) msg->put();
  }

public:
  void encode_payload(uint64_t features) {
    ::encode(tid, payload);
    ::encode(client, payload);
    ::encode(client_caps, payload, features);
    encode_message(msg, features, payload);
    ::encode(conn_features, payload);
  }

  void decode_payload() {
    bufferlist::iterator p = payload.begin();
    ::decode(tid, p);
    ::decode(client, p);
    ::decode(client_caps, p);
    msg = (PaxosServiceMessage *)decode_message(NULL, p);
    if (header.version >= 2) {
      ::decode(conn_features, p);
    } else {
      conn_features = 0;
    }

  }

  const char *get_type_name() const { return "forward"; }
  void print(ostream& o) const {
    if (msg)
      o << "forward(" << *msg << " caps " << client_caps
        << " conn_features " << conn_features << ") to leader";
    else o << "forward(??? ) to leader";
  }
};
  
#endif
