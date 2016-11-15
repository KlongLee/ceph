// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 Haomai Wang <haomaiwang@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 *
 */

#include "Compressor.h"
#include "CompressionPlugin.h"
#include "common/dout.h"

const char * Compressor::get_comp_alg_name(int a) {
  switch (a) {
    case COMP_ALG_NONE: return "none";
    case COMP_ALG_SNAPPY: return "snappy";
    case COMP_ALG_ZLIB: return "zlib";
    default: return "???";
  }
}

boost::optional<Compressor::CompressionAlgorithm> Compressor::get_comp_alg_type(const std::string &s) {
  if (s == "snappy")
    return COMP_ALG_SNAPPY;
  if (s == "zlib")
    return COMP_ALG_ZLIB;
  if (s == "")
    return COMP_ALG_NONE;

  return boost::optional<CompressionAlgorithm>();
}

const char *Compressor::get_comp_mode_name(int m) {
  switch (m) {
    case COMP_NONE: return "none";
    case COMP_PASSIVE: return "passive";
    case COMP_AGGRESSIVE: return "aggressive";
    case COMP_FORCE: return "force";
    default: return "???";
  }
}
boost::optional<Compressor::CompressionMode> Compressor::get_comp_mode_type(const std::string &s) {
  if (s == "force")
    return COMP_FORCE;
  if (s == "aggressive")
    return COMP_AGGRESSIVE;
  if (s == "passive")
    return COMP_PASSIVE;
  if (s == "none")
    return COMP_NONE;
  return boost::optional<CompressionMode>();
}

CompressorRef Compressor::create(CephContext *cct, const std::string &type)
{
  CompressorRef cs_impl = NULL;
  std::stringstream ss;
  PluginRegistry *reg = cct->get_plugin_registry();
  CompressionPlugin *factory = dynamic_cast<CompressionPlugin*>(reg->get_with_load("compressor", type));
  if (factory == NULL) {
    lderr(cct) << __func__ << " cannot load compressor of type " << type << dendl;
    return NULL;
  }
  int err = factory->factory(&cs_impl, &ss);
  if (err)
    lderr(cct) << __func__ << " factory return error " << err << dendl;
  return cs_impl;
}

CompressorRef Compressor::create(CephContext *cct, int alg)
{
  if (alg < 0 || alg >= COMP_ALG_LAST) {
    lderr(cct) << __func__ << " invalid algorithm value:" << alg << dendl;
    return CompressorRef();
  }
  std::string type_name = get_comp_alg_name(alg);
  return create(cct, type_name);
}
