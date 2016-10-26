/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 CERN (Switzerland)
 *
 * Author: Andreas-Joachim Peters <Andreas.Joachim.Peters@cern.ch>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 */


/**
 * @file   ErasureCodePluginIsa.cc
 *
 * @brief  Erasure Code Plug-in class wrapping the INTEL ISA-L library
 *
 * The factory plug-in class allows to call individual encoding techniques.
 * The INTEL ISA-L library provides two pre-defined encoding matrices
 * (cauchy, reed_sol_van = default).
 */

// -----------------------------------------------------------------------------
#include "ceph_ver.h"
#include "common/debug.h"
#include "erasure-code/ErasureCodePlugin.h"
#include "ErasureCodeIsa.h"
// -----------------------------------------------------------------------------

class ErasureCodePluginIsa : public ErasureCodePlugin {
public:
  ErasureCodeIsaTableCache tcache;

  ErasureCodePluginIsa(CephContext* cct) : ErasureCodePlugin(cct)
  {}

  virtual int factory(ErasureCodeProfile &profile,
                      ErasureCodeInterfaceRef *erasure_code,
                      ostream *ss)
  {
    ErasureCodeIsa *interface;
    std::string t;
    if (profile.find("technique") == profile.end())
      profile["technique"] = "reed_sol_van";
    t = profile.find("technique")->second;
    if ((t == "reed_sol_van")) {
      interface = new ErasureCodeIsaDefault(tcache,
                                            ErasureCodeIsaDefault::kVandermonde);
    } else {
      if ((t == "cauchy")) {
        interface = new ErasureCodeIsaDefault(tcache,
                                              ErasureCodeIsaDefault::kCauchy);
      } else {
        *ss << "technique=" << t << " is not a valid coding technique. "
          << " Choose one of the following: "
          << "reed_sol_van,"
          << "cauchy" << std::endl;
        return -ENOENT;
      }
    }

    int r = interface->init(profile, ss);
    if (r) {
      delete interface;
      return r;
    }
    *erasure_code = ErasureCodeInterfaceRef(interface);
    return 0;
  }
};

// -----------------------------------------------------------------------------

const char *__ceph_plugin_version()
{
  return CEPH_GIT_NICE_VER;
}

// -----------------------------------------------------------------------------

int __ceph_plugin_init(CephContext *cct,
                       const std::string& type,
                       const std::string& name)
{
  PluginRegistry *instance = cct->get_plugin_registry();

  return instance->add(type, name, new ErasureCodePluginIsa(cct));
}
