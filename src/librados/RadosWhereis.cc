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

// -----------------------------------------------------------------------------
#include "librados/IoCtxImpl.h"
#include "include/rados/librados.hpp"
#include "common/Formatter.h"
#include "RadosWhereis.h"
#include <string>
#include <iostream>
#include <boost/asio.hpp>

// -----------------------------------------------------------------------------

/**
 * @file RadosWhereis.cc
 *
 * @brief Class providing a function to retrieve a vector of locations
 *
 * The 'locate' function fills a vector storing the IP, OSD- & PG-Seeds for
 * a given object in a given IO context (pool).
 */



// -----------------------------------------------------------------------------
void
librados::whereis::resolve()
{
  // translate ip's using boost asio
  boost::asio::ip::address ipa = boost::asio::ip::address::from_string(IpString);    
  boost::asio::ip::tcp::endpoint ep;
  ep.address(ipa);
  
  boost::asio::io_service io_service;
  boost::asio::ip::tcp::resolver resolver(io_service);
  
  boost::asio::ip::tcp::resolver::iterator itr = resolver.resolve(ep);
  boost::asio::ip::tcp::resolver::iterator end;
  
  for (int i = 1; itr != end; itr++, i++) 
    HostNames.push_back(itr->host_name());
}

// -----------------------------------------------------------------------------
void
librados::whereis::dump(bool showhost, void* ext_formatter ) const
{
  Formatter* formatter = static_cast<Formatter*> (ext_formatter);

  formatter->open_object_section("whereis");
  formatter->dump_int("osd-id", OsdID);
  formatter->dump_int("pg-seed", PgSeed);
  formatter->dump_string("ip", IpString);
  formatter->dump_string("state", OsdState);
  if (showhost) {
    std::vector<std::string>::const_iterator it;
    for (it=HostNames.begin(); it!=HostNames.end(); ++it) {
      formatter->open_array_section("host");
      formatter->dump_string("name",it->c_str());
      formatter->close_section();
    }
  }
  formatter->close_section();
}

// -----------------------------------------------------------------------------
bool
librados::RadosWhereis::whereis(const std::string &oname,
                               whereis_vector_t &locations
                               )
{
  librados::IoCtxImpl *ctx = io.io_ctx_impl;
  object_t oid(oname.c_str());

  // retrieve OSD map
  const OSDMap* osdmap = ctx->objecter->get_osdmap_read();
  // check if given pool is defined in the OSD map
  int64_t pool = ctx->poolid;
  if (!osdmap->have_pg_pool(pool)) {
    if (osdmap)
      ctx->objecter->put_osdmap_read();
    return false;
  }

  object_locator_t loc(pool);
  pg_t raw_pgid = osdmap->object_locator_to_pg(oid, loc);
  pg_t pgid = osdmap->raw_pg_to_pg(raw_pgid);

  vector<int> acting;
  osdmap->pg_to_acting_osds(pgid, acting);

  // fill and translate all given locations into a location vector
  for (size_t i = 0; i < acting.size(); i++) {
    std::stringstream hostaddr;
    entity_addr_t addr = osdmap->get_addr(acting[i]);
    hostaddr << addr.ss_addr();
    std::string host = hostaddr.str().c_str();
    host.erase(host.rfind(":"));

    whereis_t new_location;
    new_location.IpString = host;
    new_location.OsdID = acting[i];
    new_location.PgSeed = pgid.ps();

    if ( (osdmap->get_state(acting[i]) & CEPH_OSD_UP) && 
         (osdmap->get_weight(acting[i])) )
      new_location.OsdState="active";
    else
      new_location.OsdState="inactive";

    locations.push_back(new_location);
  }

  ctx->objecter->put_osdmap_read();
  return true;
}


bool
librados::Rados::whereis(IoCtx &ioctx, const std::string &oid, whereis_vector_t &locations)
{
  RadosWhereis locator(ioctx);
  return locator.whereis(oid,locations);
}

std::string
librados::Rados::dump_whereis(whereis_t &location, bool reversedns, void* formatter)
{
  if (reversedns)
    location.resolve();
  
  if (formatter) {
    location.dump(reversedns,formatter);
    return "";
  } else {
    JSONFormatter tmp_formatter(true);
    location.dump(reversedns, (dynamic_cast<void *>(&tmp_formatter)));
    std::stringstream s;
    tmp_formatter.flush(s);
    return s.str().c_str();
  }
}
