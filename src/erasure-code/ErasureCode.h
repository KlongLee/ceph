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
    static const unsigned SIMD_ALIGN;

    std::vector<int> chunk_mapping;
    ErasureCodeProfile _profile;

    ~ErasureCode() override {}

    int init(ErasureCodeProfile &profile, std::ostream *ss) override {
      _profile = profile;
      return 0;
    }

    const ErasureCodeProfile &get_profile() const override {
      return _profile;
    }

    int sanity_check_k(int k, std::ostream *ss);

    unsigned int get_coding_chunk_count() const override {
      return get_chunk_count() - get_data_chunk_count();
    }

    int minimum_to_decode(const std::set<int> &want_to_read,
                                  const std::set<int> &available_chunks,
                                  std::set<int> *minimum) override;

    int minimum_to_decode_with_cost(const std::set<int> &want_to_read,
                                            const std::map<int, int> &available,
                                            std::set<int> *minimum) override;

    int encode_prepare(const bufferlist &raw,
                       std::map<int, bufferlist> &encoded) const;

    int encode(const std::set<int> &want_to_encode,
                       const bufferlist &in,
                       std::map<int, bufferlist> *encoded) override;

    int encode_chunks(const std::set<int> &want_to_encode,
                              std::map<int, bufferlist> *encoded) override;

    int decode(const std::set<int> &want_to_read,
                       const std::map<int, bufferlist> &chunks,
                       std::map<int, bufferlist> *decoded) override;

    int decode_chunks(const std::set<int> &want_to_read,
                              const std::map<int, bufferlist> &chunks,
                              std::map<int, bufferlist> *decoded) override;

    const std::vector<int> &get_chunk_mapping() const override;

    int to_mapping(const ErasureCodeProfile &profile,
		   std::ostream *ss);

    static int to_int(const std::string &name,
		      ErasureCodeProfile &profile,
		      int *value,
		      int default_value,
		      std::ostream *ss);

    static int to_bool(const std::string &name,
		       ErasureCodeProfile &profile,
		       bool *value,
		       const std::string &default_value,
		       std::ostream *ss);

    static int to_string(const std::string &name,
			 ErasureCodeProfile &profile,
			 std::string *value,
			 const std::string &default_value,
			 std::ostream *ss);

    int decode_concat(const std::map<int, bufferlist> &chunks,
			      bufferlist *decoded) override;

  protected:
    int parse(const ErasureCodeProfile &profile,
	      std::ostream *ss);

  private:
    int chunk_index(unsigned int i) const;
  };
}

#endif
