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

#ifndef CEPH_MDS_ESUBTREEMAP_H
#define CEPH_MDS_ESUBTREEMAP_H

#include "../LogEvent.h"
#include "EMetaBlob.h"

class ESubtreeMap : public LogEvent {
public:
  EMetaBlob metablob;
  map<dirfrag_t, vector<dirfrag_t> > subtrees;
  set<dirfrag_t> ambiguous_subtrees;
  uint64_t expire_pos;

  ESubtreeMap() : LogEvent(EVENT_SUBTREEMAP), expire_pos(0) { }
  
  void print(ostream& out) {
    out << "ESubtreeMap " << subtrees.size() << " subtrees " 
	<< ", " << ambiguous_subtrees.size() << " ambiguous "
	<< metablob;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(5, 5, bl);
    ::encode(stamp, bl);
    ::encode(metablob, bl);
    ::encode(subtrees, bl);
    ::encode(ambiguous_subtrees, bl);
    ::encode(expire_pos, bl);
    ENCODE_FINISH(bl);
  } 
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(5, 5, 5, bl);
    if (struct_v >= 2)
      ::decode(stamp, bl);
    ::decode(metablob, bl);
    ::decode(subtrees, bl);
    if (struct_v >= 4)
      ::decode(ambiguous_subtrees, bl);
    if (struct_v >= 3)
      ::decode(expire_pos, bl);
    DECODE_FINISH(bl);
  }

  void replay(MDS *mds);
};

#endif
