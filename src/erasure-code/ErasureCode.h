// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph distributed storage system
 *
 * Copyright (C) 2014 Cloudwatt <libre.licensing@cloudwatt.com>
 *
 * Author: Loic Dachary <loic@dachary.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 * 
 */

#ifndef CEPH_ERASURE_CODE_H
#define CEPH_ERASURE_CODE_H

/*! @file ErasureCode.h
    @brief Base class for erasure code plugins implementors

 */ 

#include "ErasureCodeInterface.h"

namespace ceph {

  class ErasureCode : public ErasureCodeInterface {
  public:
    virtual ~ErasureCode() {}

    int encode_prepare(const bufferlist &raw, bufferlist *prepared) const;

    virtual int encode(const set<int> &want_to_encode,
                       const bufferlist &in,
                       map<int, bufferlist> *encoded);

    virtual int encode_chunks(const set<int> &want_to_encode,
                              map<int, bufferlist> *encoded);

    virtual int decode(const set<int> &want_to_read,
                       const map<int, bufferlist> &chunks,
                       map<int, bufferlist> *decoded);

    virtual int decode_chunks(const set<int> &want_to_read,
                              const map<int, bufferlist> &chunks,
                              map<int, bufferlist> *decoded);

  };
}

#endif
