// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 * Copyright (C) 2013, 2014 Cloudwatt <libre.licensing@cloudwatt.com>
 * Copyright (C) 2014 Red Hat <contact@redhat.com>
 *
 * Author: Takanori Nakao <nakao.takanori@jp.fujitsu.com>
 * Author: Takeshi Miyamae <miyamae.takeshi@jp.fujitsu.com>
 * Author: Loic Dachary <loic@dachary.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 */

#ifndef CEPH_ERASURE_CODE_SHEC_H
#define CEPH_ERASURE_CODE_SHEC_H

#include "common/Mutex.h"
#include "erasure-code/ErasureCode.h"
#include "ErasureCodeShecTableCache.h"
#include <list>

#define DEFAULT_RULESET_ROOT "default"
#define DEFAULT_RULESET_FAILURE_DOMAIN "host"

class ErasureCodeShec : public ErasureCode {

public:
  enum {
    MULTIPLE = 0,
    SINGLE = 1
  };

  ErasureCodeShecTableCache &tcache;
  int k;
  int DEFAULT_K;
  int m;
  int DEFAULT_M;
  int c;
  int DEFAULT_C;
  int w;
  int DEFAULT_W;
  int technique;
  string ruleset_root;
  string ruleset_failure_domain;
  int *matrix;

  ErasureCodeShec(const int _technique,
		  ErasureCodeShecTableCache &_tcache) :
    tcache(_tcache),
    k(0),
    DEFAULT_K(4),
    m(0),
    DEFAULT_M(3),
    c(0),
    DEFAULT_C(2),
    w(0),
    DEFAULT_W(8),
    technique(_technique),
    ruleset_root(DEFAULT_RULESET_ROOT),
    ruleset_failure_domain(DEFAULT_RULESET_FAILURE_DOMAIN),
    matrix(0)
  {}

  ~ErasureCodeShec() override {}

  int create_ruleset(const string &name,
			     CrushWrapper &crush,
			     ostream *ss) const override;

  unsigned int get_chunk_count() const override {
    return k + m;
  }

  unsigned int get_data_chunk_count() const override {
    return k;
  }

  unsigned int get_chunk_size(unsigned int object_size) const override;

  int minimum_to_decode(const set<int> &want_to_read,
				const set<int> &available_chunks,
				set<int> *minimum) override;

  int minimum_to_decode_with_cost(const set<int> &want_to_read,
					  const map<int, int> &available,
					  set<int> *minimum) override;

  int encode(const set<int> &want_to_encode,
		     const bufferlist &in,
		     map<int, bufferlist> *encoded) override;
  int encode_chunks(const set<int> &want_to_encode,
			    map<int, bufferlist> *encoded) override;

  int decode(const set<int> &want_to_read,
		     const map<int, bufferlist> &chunks,
		     map<int, bufferlist> *decoded) override;
  int decode_chunks(const set<int> &want_to_read,
			    const map<int, bufferlist> &chunks,
			    map<int, bufferlist> *decoded) override;

  int init(ErasureCodeProfile &profile, ostream *ss) override;
  virtual void shec_encode(char **data,
			   char **coding,
			   int blocksize) = 0;
  virtual int shec_decode(int *erasures,
			  int *avails,
			  char **data,
			  char **coding,
			  int blocksize) = 0;
  virtual unsigned get_alignment() const = 0;
  virtual void prepare() = 0;

  virtual int shec_matrix_decode(int *erased, int *avails,
                                 char **data_ptrs, char **coding_ptrs, int size);
  virtual int* shec_reedsolomon_coding_matrix(int is_single);

private:
  virtual int parse(const ErasureCodeProfile &profile) = 0;

  virtual double shec_calc_recovery_efficiency1(int k, int m1, int m2, int c1, int c2)
  // http://tracker.ceph.com/issues/12936 shec fails i386 make check
#if defined(__i386__) && defined(__GNUC__)
    __attribute__((optimize(0)))
#endif    
    ;
  virtual int shec_make_decoding_matrix(bool prepare,
                                        int *want, int *avails,
                                        int *decoding_matrix,
                                        int *dm_row, int *dm_column,
                                        int *minimum);
};

class ErasureCodeShecReedSolomonVandermonde : public ErasureCodeShec {
public:

  ErasureCodeShecReedSolomonVandermonde(ErasureCodeShecTableCache &_tcache,
					int technique = MULTIPLE) :
    ErasureCodeShec(technique, _tcache)
  {}

  ~ErasureCodeShecReedSolomonVandermonde() override {
  }

  void shec_encode(char **data,
			   char **coding,
			   int blocksize) override;
  int shec_decode(int *erasures,
			  int *avails,
			  char **data,
			  char **coding,
			  int blocksize) override;
  unsigned get_alignment() const override;
  void prepare() override;
private:
  int parse(const ErasureCodeProfile &profile) override;
};

#endif
