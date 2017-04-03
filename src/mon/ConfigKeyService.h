// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 Inktank, Inc
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */
#ifndef CEPH_MON_CONFIG_KEY_SERVICE_H
#define CEPH_MON_CONFIG_KEY_SERVICE_H

#include "mon/QuorumService.h"

class Paxos;
class Monitor;
namespace ceph {
class Formatter;
}

class ConfigKeyService : public QuorumService
{
  Paxos *paxos;

  int store_get(const string &key, bufferlist &bl);
  void store_put(const string &key, bufferlist &bl, Context *cb = NULL);
  void store_delete(const string &key, Context *cb = NULL);
  void store_list(stringstream &ss);
  bool store_exists(const string &key);

  static const string STORE_PREFIX;

protected:
  void service_shutdown() override { }

public:
  ConfigKeyService(Monitor *m, Paxos *p) :
    QuorumService(m),
    paxos(p)
  { }
  ~ConfigKeyService() override { }


  /**
   * @defgroup ConfigKeyService_Inherited_h Inherited abstract methods
   * @{
   */
  void init() override { }
  void get_health(Formatter *f,
                  list<pair<health_status_t,string> >& summary,
                  list<pair<health_status_t,string> > *detail) override { }
  bool service_dispatch(MonOpRequestRef op) override;

  void start_epoch() override { }
  void finish_epoch() override { }
  void cleanup() override { }
  void service_tick() override { }

  int get_type() override {
    return QuorumService::SERVICE_CONFIG_KEY;
  }

  string get_name() const override {
    return "config_key";
  }
  virtual void get_store_prefixes(set<string>& s);
  /**
   * @} // ConfigKeyService_Inherited_h
   */
};

#endif // CEPH_MON_CONFIG_KEY_SERVICE_H
