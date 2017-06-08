// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph distributed storage system
 *
 * Copyright (C) 2013, 2014 Cloudwatt <libre.licensing@cloudwatt.com>
 * Copyright (C) 2014 Red Hat <contact@redhat.com>
 *
 * Author: Loic Dachary <loic@dachary.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 * 
 */

#ifndef CEPH_ERASURE_CODE_JERASURE_H
#define CEPH_ERASURE_CODE_JERASURE_H

#include "erasure-code/ErasureCode.h"

#define DEFAULT_RULESET_ROOT "default"
#define DEFAULT_RULESET_FAILURE_DOMAIN "host"

class ErasureCodeJerasure : public ErasureCode {
public:
  int k;
  static constexpr int DEFAULT_K = 2;
  int m;
  static constexpr int DEFAULT_M = 1;
  int w;
  static constexpr int DEFAULT_W = 8;
  const char *technique;
  std::string ruleset_root;
  std::string ruleset_failure_domain;
  bool per_chunk_alignment;

  explicit ErasureCodeJerasure(const char *_technique) :
    k(0),
    m(0),
    w(0),
    technique(_technique),
    ruleset_root(DEFAULT_RULESET_ROOT),
    ruleset_failure_domain(DEFAULT_RULESET_FAILURE_DOMAIN),
    per_chunk_alignment(false)
  {}

  ~ErasureCodeJerasure() override {}
  
  int create_ruleset(const std::string &name,
			     CrushWrapper &crush,
			     std::ostream *ss) const override;

  unsigned int get_chunk_count() const override {
    return k + m;
  }

  unsigned int get_data_chunk_count() const override {
    return k;
  }

  unsigned int get_chunk_size(unsigned int object_size) const override;

  int encode_chunks(const std::set<int> &want_to_encode,
			    std::map<int, bufferlist> *encoded) override;

  int decode_chunks(const std::set<int> &want_to_read,
			    const std::map<int, bufferlist> &chunks,
			    std::map<int, bufferlist> *decoded) override;

  int init(ErasureCodeProfile &profile, std::ostream *ss) override;

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) = 0;
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) = 0;
  virtual unsigned get_alignment() const = 0;
  virtual void prepare() = 0;
  static bool is_prime(int value);
protected:
  virtual int parse(ErasureCodeProfile &profile, std::ostream *ss);
};

class ErasureCodeJerasureReedSolomonVandermonde : public ErasureCodeJerasure {
public:
  int *matrix;

  static constexpr int DEFAULT_K = 7;
  static constexpr int DEFAULT_M = 3;
  static constexpr int DEFAULT_W = 8;

  ErasureCodeJerasureReedSolomonVandermonde() :
    ErasureCodeJerasure("reed_sol_van"),
    matrix(0)
  {}
  ~ErasureCodeJerasureReedSolomonVandermonde() override {
    if (matrix)
      free(matrix);
  }

  void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) override;
  int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) override;
  unsigned get_alignment() const override;
  void prepare() override;
private:
  int parse(ErasureCodeProfile &profile, std::ostream *ss) override;
};

class ErasureCodeJerasureReedSolomonRAID6 : public ErasureCodeJerasure {
public:
  int *matrix;
  static constexpr int DEFAULT_K = 7;
  static constexpr int DEFAULT_M = 1;
  static constexpr int DEFAULT_W = 8;

  ErasureCodeJerasureReedSolomonRAID6() :
    ErasureCodeJerasure("reed_sol_r6_op"),
    matrix(0)
  {
  }
  ~ErasureCodeJerasureReedSolomonRAID6() override {
    if (matrix)
      free(matrix);
  }

  void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) override;
  int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) override;
  unsigned get_alignment() const override;
  void prepare() override;
private:
  int parse(ErasureCodeProfile &profile, std::ostream *ss) override;
};

class ErasureCodeJerasureCauchy : public ErasureCodeJerasure {
public:
  int *bitmatrix;
  int **schedule;
  int packetsize;

  static constexpr int DEFAULT_K = 7;
  static constexpr int DEFAULT_M = 3;
  static constexpr int DEFAULT_W = 8;

  explicit ErasureCodeJerasureCauchy(const char *technique) :
    ErasureCodeJerasure(technique),
    bitmatrix(0),
    schedule(0),
    packetsize(0)
  {}
  ~ErasureCodeJerasureCauchy() override {
    if (bitmatrix)
      free(bitmatrix);
    if (schedule)
      free(schedule);
  }

  void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) override;
  int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) override;
  unsigned get_alignment() const override;
  void prepare_schedule(int *matrix);
private:
  int parse(ErasureCodeProfile &profile, std::ostream *ss) override;
};

class ErasureCodeJerasureCauchyOrig : public ErasureCodeJerasureCauchy {
public:
  ErasureCodeJerasureCauchyOrig() :
    ErasureCodeJerasureCauchy("cauchy_orig")
  {}

  void prepare() override;
};

class ErasureCodeJerasureCauchyGood : public ErasureCodeJerasureCauchy {
public:
  ErasureCodeJerasureCauchyGood() :
    ErasureCodeJerasureCauchy("cauchy_good")
  {}

  void prepare() override;
};

class ErasureCodeJerasureLiberation : public ErasureCodeJerasure {
public:
  int *bitmatrix;
  int **schedule;
  int packetsize;
  static constexpr int DEFAULT_K = 2;
  static constexpr int DEFAULT_M = 2;
  static constexpr int DEFAULT_W = 7;

  explicit ErasureCodeJerasureLiberation(const char *technique = "liberation") :
    ErasureCodeJerasure(technique),
    bitmatrix(0),
    schedule(0),
    packetsize(0)
  {
  }
  ~ErasureCodeJerasureLiberation() override;

  void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) override;
  int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) override;
  unsigned get_alignment() const override;
  virtual bool check_k(std::ostream *ss) const;
  virtual bool check_w(std::ostream *ss) const;
  virtual bool check_packetsize_set(std::ostream *ss) const;
  virtual bool check_packetsize(std::ostream *ss) const;
  virtual int revert_to_default(ErasureCodeProfile &profile,
				std::ostream *ss);
  void prepare() override;
private:
  int parse(ErasureCodeProfile &profile, std::ostream *ss) override;
};

class ErasureCodeJerasureBlaumRoth : public ErasureCodeJerasureLiberation {
public:
  ErasureCodeJerasureBlaumRoth() :
    ErasureCodeJerasureLiberation("blaum_roth")
  {
  }

  bool check_w(std::ostream *ss) const override;
  void prepare() override;
};

class ErasureCodeJerasureLiber8tion : public ErasureCodeJerasureLiberation {
public:
  static constexpr int DEFAULT_K = 2;
  static constexpr int DEFAULT_M = 2;
  static constexpr int DEFAULT_W = 8;
  ErasureCodeJerasureLiber8tion() :
    ErasureCodeJerasureLiberation("liber8tion")
  {}

  void prepare() override;
private:
  int parse(ErasureCodeProfile &profile, std::ostream *ss) override;
};

#endif
