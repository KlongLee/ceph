// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <boost/optional.hpp>

#include "ConfigMap.h"
#include "mon/PaxosService.h"

class ConfigMonitor : public PaxosService
{
  version_t version = 0;
  ConfigMap config_map;
  map<string,boost::optional<bufferlist>> pending;

public:
  ConfigMonitor(Monitor *m, Paxos *p, const string& service_name);

  void init() override;

  void load_config();

  bool preprocess_query(MonOpRequestRef op) override;
  bool prepare_update(MonOpRequestRef op) override;

  void create_initial() override;
  void update_from_paxos(bool *need_bootstrap) override;
  void create_pending() override;
  void encode_pending(MonitorDBStore::TransactionRef t) override;
  version_t get_trim_to() const override;

  void encode_full(MonitorDBStore::TransactionRef t) override { }

  void tick() override;

  bool refresh_config(Session *s);
  void send_config(Session *s);
  void check_sub(Subscription *sub);
};
