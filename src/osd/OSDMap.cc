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

#include "OSDMap.h"

#include "common/config.h"
#include "common/Formatter.h"
#include "include/ceph_features.h"

#include "common/code_environment.h"

#define dout_subsys ceph_subsys_osd

// ----------------------------------
// osd_info_t

void osd_info_t::dump(Formatter *f) const
{
  f->dump_int("last_clean_begin", last_clean_begin);
  f->dump_int("last_clean_end", last_clean_end);
  f->dump_int("up_from", up_from);
  f->dump_int("up_thru", up_thru);
  f->dump_int("down_at", down_at);
  f->dump_int("lost_at", lost_at);
}

void osd_info_t::encode(bufferlist& bl) const
{
  __u8 struct_v = 1;
  ::encode(struct_v, bl);
  ::encode(last_clean_begin, bl);
  ::encode(last_clean_end, bl);
  ::encode(up_from, bl);
  ::encode(up_thru, bl);
  ::encode(down_at, bl);
  ::encode(lost_at, bl);
}

void osd_info_t::decode(bufferlist::iterator& bl)
{
  __u8 struct_v;
  ::decode(struct_v, bl);
  ::decode(last_clean_begin, bl);
  ::decode(last_clean_end, bl);
  ::decode(up_from, bl);
  ::decode(up_thru, bl);
  ::decode(down_at, bl);
  ::decode(lost_at, bl);
}

void osd_info_t::generate_test_instances(list<osd_info_t*>& o)
{
  o.push_back(new osd_info_t);
  o.push_back(new osd_info_t);
  o.back()->last_clean_begin = 1;
  o.back()->last_clean_end = 2;
  o.back()->up_from = 30;
  o.back()->up_thru = 40;
  o.back()->down_at = 5;
  o.back()->lost_at = 6;
}

ostream& operator<<(ostream& out, const osd_info_t& info)
{
  out << "up_from " << info.up_from
      << " up_thru " << info.up_thru
      << " down_at " << info.down_at
      << " last_clean_interval [" << info.last_clean_begin << "," << info.last_clean_end << ")";
  if (info.lost_at)
    out << " lost_at " << info.lost_at;
  return out;
}


// ----------------------------------
// OSDMap::Incremental

int OSDMap::Incremental::get_net_marked_out(const OSDMap *previous) const
{
  int n = 0;
  for (map<int32_t,uint32_t>::const_iterator p = new_weight.begin();
       p != new_weight.end();
       ++p) {
    if (p->second == CEPH_OSD_OUT && !previous->is_out(p->first))
      n++;  // marked out
    if (p->second != CEPH_OSD_OUT && previous->is_out(p->first))
      n--;  // marked in
  }
  return n;
}

int OSDMap::Incremental::get_net_marked_down(const OSDMap *previous) const
{
  int n = 0;
  for (map<int32_t,uint8_t>::const_iterator p = new_state.begin();
       p != new_state.end();
       ++p) {
    if (p->second & CEPH_OSD_UP) {
      if (previous->is_up(p->first))
	n++;  // marked down
      else
	n--;  // marked up
    }
  }
  return n;
}

int OSDMap::Incremental::identify_osd(uuid_d u) const
{
  for (map<int32_t,uuid_d>::const_iterator p = new_uuid.begin();
       p != new_uuid.end();
       ++p)
    if (p->second == u)
      return p->first;
  return -1;
}

void OSDMap::Incremental::encode_client_old(bufferlist& bl) const
{
  __u16 v = 5;
  ::encode(v, bl);
  ::encode(fsid, bl);
  ::encode(epoch, bl);
  ::encode(modified, bl);
  int32_t new_t = new_pool_max;
  ::encode(new_t, bl);
  ::encode(new_flags, bl);
  ::encode(fullmap, bl);
  ::encode(crush, bl);

  ::encode(new_max_osd, bl);
  // for ::encode(new_pools, bl);
  __u32 n = new_pools.size();
  ::encode(n, bl);
  for (map<int64_t,pg_pool_t>::const_iterator p = new_pools.begin();
       p != new_pools.end();
       ++p) {
    n = p->first;
    ::encode(n, bl);
    ::encode(p->second, bl, 0);
  }
  // for ::encode(new_pool_names, bl);
  n = new_pool_names.size();
  ::encode(n, bl);
  for (map<int64_t, string>::const_iterator p = new_pool_names.begin(); p != new_pool_names.end(); ++p) {
    n = p->first;
    ::encode(n, bl);
    ::encode(p->second, bl);
  }
  // for ::encode(old_pools, bl);
  n = old_pools.size();
  ::encode(n, bl);
  for (set<int64_t>::iterator p = old_pools.begin(); p != old_pools.end(); ++p) {
    n = *p;
    ::encode(n, bl);
  }
  ::encode(new_up_client, bl);
  ::encode(new_state, bl);
  ::encode(new_weight, bl);
  // for ::encode(new_pg_temp, bl);
  n = new_pg_temp.size();
  ::encode(n, bl);
  for (map<pg_t,vector<int32_t> >::const_iterator p = new_pg_temp.begin();
       p != new_pg_temp.end();
       ++p) {
    old_pg_t opg = p->first.get_old_pg();
    ::encode(opg, bl);
    ::encode(p->second, bl);
  }
}

void OSDMap::Incremental::encode(bufferlist& bl, uint64_t features) const
{
  if ((features & CEPH_FEATURE_PGID64) == 0) {
    encode_client_old(bl);
    return;
  }

  // base
  __u16 v = 6;
  ::encode(v, bl);
  ::encode(fsid, bl);
  ::encode(epoch, bl);
  ::encode(modified, bl);
  ::encode(new_pool_max, bl);
  ::encode(new_flags, bl);
  ::encode(fullmap, bl);
  ::encode(crush, bl);

  ::encode(new_max_osd, bl);
  ::encode(new_pools, bl, features);
  ::encode(new_pool_names, bl);
  ::encode(old_pools, bl);
  ::encode(new_up_client, bl);
  ::encode(new_state, bl);
  ::encode(new_weight, bl);
  ::encode(new_pg_temp, bl);

  // extended
  __u16 ev = 8;
  ::encode(ev, bl);
  ::encode(new_hb_up, bl);
  ::encode(new_up_thru, bl);
  ::encode(new_last_clean_interval, bl);
  ::encode(new_lost, bl);
  ::encode(new_blacklist, bl);
  ::encode(old_blacklist, bl);
  ::encode(new_up_internal, bl);
  ::encode(cluster_snapshot, bl);
  ::encode(new_uuid, bl);
}

void OSDMap::Incremental::decode(bufferlist::iterator &p)
{
  __u32 n, t;
  // base
  __u16 v;
  ::decode(v, p);
  ::decode(fsid, p);
  ::decode(epoch, p);
  ::decode(modified, p);
  if (v == 4 || v == 5) {
    ::decode(n, p);
    new_pool_max = n;
  } else if (v >= 6)
    ::decode(new_pool_max, p);
  ::decode(new_flags, p);
  ::decode(fullmap, p);
  ::decode(crush, p);

  ::decode(new_max_osd, p);
  if (v < 6) {
    new_pools.clear();
    ::decode(n, p);
    while (n--) {
      ::decode(t, p);
      ::decode(new_pools[t], p);
    }
  } else {
    ::decode(new_pools, p);
  }
  if (v == 5) {
    new_pool_names.clear();
    ::decode(n, p);
    while (n--) {
      ::decode(t, p);
      ::decode(new_pool_names[t], p);
    }
  } else if (v >= 6) {
    ::decode(new_pool_names, p);
  }
  if (v < 6) {
    old_pools.clear();
    ::decode(n, p);
    while (n--) {
      ::decode(t, p);
      old_pools.insert(t);
    }
  } else {
    ::decode(old_pools, p);
  }
  ::decode(new_up_client, p);
  ::decode(new_state, p);
  ::decode(new_weight, p);

  if (v < 6) {
    new_pg_temp.clear();
    ::decode(n, p);
    while (n--) {
      old_pg_t opg;
      ::decode_raw(opg, p);
      ::decode(new_pg_temp[pg_t(opg)], p);
    }
  } else {
    ::decode(new_pg_temp, p);
  }

  // decode short map, too.
  if (v == 5 && p.end())
    return;

  // extended
  __u16 ev = 0;
  if (v >= 5)
    ::decode(ev, p);
  ::decode(new_hb_up, p);
  if (v < 5)
    ::decode(new_pool_names, p);
  ::decode(new_up_thru, p);
  ::decode(new_last_clean_interval, p);
  ::decode(new_lost, p);
  ::decode(new_blacklist, p);
  ::decode(old_blacklist, p);
  if (ev >= 6)
    ::decode(new_up_internal, p);
  if (ev >= 7)
    ::decode(cluster_snapshot, p);
  if (ev >= 8)
    ::decode(new_uuid, p);
}

void OSDMap::Incremental::dump(Formatter *f) const
{
  f->dump_int("epoch", epoch);
  f->dump_stream("fsid") << fsid;
  f->dump_stream("modified") << modified;
  f->dump_int("new_pool_max", new_pool_max);
  f->dump_int("new_flags", new_flags);

  if (fullmap.length()) {
    f->open_object_section("full_map");
    OSDMap full;
    bufferlist fbl = fullmap;  // kludge around constness.
    bufferlist::iterator p = fbl.begin();
    full.decode(p);
    full.dump(f);
    f->close_section();
  }
  if (crush.length()) {
    f->open_object_section("crush");
    CrushWrapper c;
    bufferlist tbl = crush;  // kludge around constness.
    bufferlist::iterator p = tbl.begin();
    c.decode(p);
    c.dump(f);
    f->close_section();
  }

  f->dump_int("new_max_osd", new_max_osd);

  f->open_array_section("new_pools");
  for (map<int64_t,pg_pool_t>::const_iterator p = new_pools.begin(); p != new_pools.end(); ++p) {
    f->open_object_section("pool");
    f->dump_int("pool", p->first);
    f->dump_string("name", new_pool_names.find(p->first)->second);
    p->second.dump(f);
    f->close_section();
  }
  f->close_section();
  f->open_array_section("old_pools");
  for (set<int64_t>::const_iterator p = old_pools.begin(); p != old_pools.end(); ++p)
    f->dump_int("pool", *p);
  f->close_section();

  f->open_array_section("new_up_osds");
  for (map<int32_t,entity_addr_t>::const_iterator p = new_up_client.begin(); p != new_up_client.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_stream("public_addr") << p->second;
    f->dump_stream("cluster_addr") << new_up_internal.find(p->first)->second;
    f->dump_stream("heartbeat_addr") << new_hb_up.find(p->first)->second;
    f->close_section();
  }
  f->close_section();

  f->open_array_section("new_weight");
  for (map<int32_t,uint32_t>::const_iterator p = new_weight.begin(); p != new_weight.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_int("weight", p->second);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("osd_state_xor");
  for (map<int32_t,uint8_t>::const_iterator p = new_state.begin(); p != new_state.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    set<string> st;
    calc_state_set(new_state.find(p->first)->second, st);
    f->open_array_section("state_xor");
    for (set<string>::iterator p = st.begin(); p != st.end(); ++p)
      f->dump_string("state", *p);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("new_pg_temp");
  for (map<pg_t,vector<int> >::const_iterator p = new_pg_temp.begin();
       p != new_pg_temp.end();
       p++) {
    f->open_object_section("pg");
    f->dump_stream("pgid") << p->first;
    f->open_array_section("osds");
    for (vector<int>::const_iterator q = p->second.begin(); q != p->second.end(); ++q)
      f->dump_int("osd", *q);
    f->close_section();
    f->close_section();    
  }
  f->close_section();

  f->open_array_section("new_up_thru");
  for (map<int32_t,uint32_t>::const_iterator p = new_up_thru.begin(); p != new_up_thru.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_int("up_thru", p->second);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("new_lost");
  for (map<int32_t,uint32_t>::const_iterator p = new_lost.begin(); p != new_lost.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_int("epoch_lost", p->second);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("new_last_clean_interval");
  for (map<int32_t,pair<epoch_t,epoch_t> >::const_iterator p = new_last_clean_interval.begin();
       p != new_last_clean_interval.end();
       ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_int("first", p->second.first);
    f->dump_int("last", p->second.second);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("new_blacklist");
  for (map<entity_addr_t,utime_t>::const_iterator p = new_blacklist.begin();
       p != new_blacklist.end();
       p++) {
    stringstream ss;
    ss << p->first;
    f->dump_stream(ss.str().c_str()) << p->second;
  }
  f->close_section();
  f->open_array_section("old_blacklist");
  for (vector<entity_addr_t>::const_iterator p = old_blacklist.begin(); p != old_blacklist.end(); ++p)
    f->dump_stream("addr") << *p;
  f->close_section();

  if (cluster_snapshot.size())
    f->dump_string("cluster_snapshot", cluster_snapshot);

  f->open_array_section("new_uuid");
  for (map<int32_t,uuid_d>::const_iterator p = new_uuid.begin(); p != new_uuid.end(); ++p) {
    f->open_object_section("osd");
    f->dump_int("osd", p->first);
    f->dump_stream("uuid") << p->second;
    f->close_section();
  }
  f->close_section();
}

void OSDMap::Incremental::generate_test_instances(list<Incremental*>& o)
{
  o.push_back(new Incremental);
}

// ----------------------------------
// OSDMap

void OSDMap::set_epoch(epoch_t e)
{
  epoch = e;
  for (map<int64_t,pg_pool_t>::iterator p = pools.begin();
       p != pools.end();
       p++)
    p->second.last_change = e;
}

bool OSDMap::is_blacklisted(const entity_addr_t& a) const
{
  if (blacklist.empty())
    return false;

  // this specific instance?
  if (blacklist.count(a))
    return true;

  // is entire ip blacklisted?
  entity_addr_t b = a;
  b.set_port(0);
  b.set_nonce(0);
  return blacklist.count(b);
}

void OSDMap::set_max_osd(int m)
{
  int o = max_osd;
  max_osd = m;
  osd_state.resize(m);
  osd_weight.resize(m);
  for (; o<max_osd; o++) {
    osd_state[o] = 0;
    osd_weight[o] = CEPH_OSD_OUT;
  }
  osd_info.resize(m);
  osd_addrs->client_addr.resize(m);
  osd_addrs->cluster_addr.resize(m);
  osd_addrs->hb_addr.resize(m);
  osd_uuid->resize(m);

  calc_num_osds();
}

int OSDMap::calc_num_osds()
{
  num_osd = 0;
  for (int i=0; i<max_osd; i++)
    if (osd_state[i] & CEPH_OSD_EXISTS)
      num_osd++;
  return num_osd;
}

void OSDMap::get_all_osds(set<int32_t>& ls) const
{
  for (int i=0; i<max_osd; i++)
    if (exists(i))
      ls.insert(i);
}

int OSDMap::get_num_up_osds() const
{
  int n = 0;
  for (int i=0; i<max_osd; i++)
    if (osd_state[i] & CEPH_OSD_EXISTS &&
	osd_state[i] & CEPH_OSD_UP) n++;
  return n;
}

int OSDMap::get_num_in_osds() const
{
  int n = 0;
  for (int i=0; i<max_osd; i++)
    if (osd_state[i] & CEPH_OSD_EXISTS &&
	get_weight(i) != CEPH_OSD_OUT) n++;
  return n;
}

void OSDMap::calc_state_set(int state, set<string>& st)
{
  unsigned t = state;
  for (unsigned s = 1; t; s <<= 1) {
    if (t & s) {
      t &= ~s;
      st.insert(ceph_osd_state_name(s));
    }
  }
}

void OSDMap::adjust_osd_weights(const map<int,double>& weights, Incremental& inc) const
{
  float max = 0;
  for (map<int,double>::const_iterator p = weights.begin();
       p != weights.end(); ++p) {
    if (p->second > max)
      max = p->second;
  }

  for (map<int,double>::const_iterator p = weights.begin();
       p != weights.end(); ++p) {
    inc.new_weight[p->first] = (unsigned)((p->second / max) * CEPH_OSD_IN);
  }
}

int OSDMap::identify_osd(const entity_addr_t& addr) const
{
  for (int i=0; i<max_osd; i++)
    if (exists(i) && (get_addr(i) == addr || get_cluster_addr(i) == addr))
      return i;
  return -1;
}

int OSDMap::identify_osd(const uuid_d& u) const
{
  for (int i=0; i<max_osd; i++)
    if (exists(i) && get_uuid(i) == u)
      return i;
  return -1;
}

bool OSDMap::find_osd_on_ip(const entity_addr_t& ip) const
{
  for (int i=0; i<max_osd; i++)
    if (exists(i) && (get_addr(i).is_same_host(ip) || get_cluster_addr(i).is_same_host(ip)))
      return i;
  return -1;
}

void OSDMap::dedup(const OSDMap *o, OSDMap *n)
{
  if (o->epoch == n->epoch)
    return;

  int diff = 0;

  // do addrs match?
  if (o->max_osd != n->max_osd)
    diff++;
  for (int i = 0; i < o->max_osd && i < n->max_osd; i++) {
    if ( n->osd_addrs->client_addr[i] &&  o->osd_addrs->client_addr[i] &&
	*n->osd_addrs->client_addr[i] == *o->osd_addrs->client_addr[i])
      n->osd_addrs->client_addr[i] = o->osd_addrs->client_addr[i];
    else
      diff++;
    if ( n->osd_addrs->cluster_addr[i] &&  o->osd_addrs->cluster_addr[i] &&
	*n->osd_addrs->cluster_addr[i] == *o->osd_addrs->cluster_addr[i])
      n->osd_addrs->cluster_addr[i] = o->osd_addrs->cluster_addr[i];
    else
      diff++;
    if ( n->osd_addrs->hb_addr[i] &&  o->osd_addrs->hb_addr[i] &&
	*n->osd_addrs->hb_addr[i] == *o->osd_addrs->hb_addr[i])
      n->osd_addrs->hb_addr[i] = o->osd_addrs->hb_addr[i];
    else
      diff++;
  }
  if (diff == 0) {
    // zoinks, no differences at all!
    n->osd_addrs = o->osd_addrs;
  }

  // does crush match?
  bufferlist oc, nc;
  ::encode(*o->crush, oc);
  ::encode(*n->crush, nc);
  if (oc.contents_equal(nc)) {
    n->crush = o->crush;
  }

  // does pg_temp match?
  if (o->pg_temp->size() == n->pg_temp->size()) {
    if (*o->pg_temp == *n->pg_temp)
      n->pg_temp = o->pg_temp;
  }

  // do uuids match?
  if (o->osd_uuid->size() == n->osd_uuid->size() &&
      *o->osd_uuid == *n->osd_uuid)
    n->osd_uuid = o->osd_uuid;
}

int OSDMap::apply_incremental(Incremental &inc)
{
  if (inc.epoch == 1)
    fsid = inc.fsid;
  else if (inc.fsid != fsid)
    return -EINVAL;
  
  assert(inc.epoch == epoch+1);
  epoch++;
  modified = inc.modified;

  // full map?
  if (inc.fullmap.length()) {
    decode(inc.fullmap);
    return 0;
  }

  // nope, incremental.
  if (inc.new_flags >= 0)
    flags = inc.new_flags;

  if (inc.new_max_osd >= 0)
    set_max_osd(inc.new_max_osd);

  if (inc.new_pool_max != -1)
    pool_max = inc.new_pool_max;

  for (set<int64_t>::iterator p = inc.old_pools.begin();
       p != inc.old_pools.end();
       p++) {
    pools.erase(*p);
    name_pool.erase(pool_name[*p]);
    pool_name.erase(*p);
  }
  for (map<int64_t,pg_pool_t>::iterator p = inc.new_pools.begin();
       p != inc.new_pools.end();
       p++) {
    pools[p->first] = p->second;
    pools[p->first].last_change = epoch;
  }
  for (map<int64_t,string>::iterator p = inc.new_pool_names.begin();
       p != inc.new_pool_names.end();
       p++) {
    pool_name[p->first] = p->second;
    name_pool[p->second] = p->first;
  }

  for (map<int32_t,uint32_t>::iterator i = inc.new_weight.begin();
       i != inc.new_weight.end();
       i++) {
    set_weight(i->first, i->second);

    // if we are marking in, clear the AUTOOUT and NEW bits.
    if (i->second)
      osd_state[i->first] &= ~(CEPH_OSD_AUTOOUT | CEPH_OSD_NEW);
  }

  // up/down
  for (map<int32_t,uint8_t>::iterator i = inc.new_state.begin();
       i != inc.new_state.end();
       i++) {
    int s = i->second ? i->second : CEPH_OSD_UP;
    if ((osd_state[i->first] & CEPH_OSD_UP) &&
	(s & CEPH_OSD_UP)) {
      osd_info[i->first].down_at = epoch;
    }
    if ((osd_state[i->first] & CEPH_OSD_EXISTS) &&
	(s & CEPH_OSD_EXISTS))
      (*osd_uuid)[i->first] = uuid_d();
    osd_state[i->first] ^= s;
  }
  for (map<int32_t,entity_addr_t>::iterator i = inc.new_up_client.begin();
       i != inc.new_up_client.end();
       i++) {
    osd_state[i->first] |= CEPH_OSD_EXISTS | CEPH_OSD_UP;
    osd_addrs->client_addr[i->first].reset(new entity_addr_t(i->second));
    if (inc.new_hb_up.empty())
      osd_addrs->hb_addr[i->first].reset(new entity_addr_t(i->second)); //this is a backward-compatibility hack
    else
      osd_addrs->hb_addr[i->first].reset(new entity_addr_t(inc.new_hb_up[i->first]));
    osd_info[i->first].up_from = epoch;
  }
  for (map<int32_t,entity_addr_t>::iterator i = inc.new_up_internal.begin();
       i != inc.new_up_internal.end();
       i++)
    osd_addrs->cluster_addr[i->first].reset(new entity_addr_t(i->second));

  // info
  for (map<int32_t,epoch_t>::iterator i = inc.new_up_thru.begin();
       i != inc.new_up_thru.end();
       i++)
    osd_info[i->first].up_thru = i->second;
  for (map<int32_t,pair<epoch_t,epoch_t> >::iterator i = inc.new_last_clean_interval.begin();
       i != inc.new_last_clean_interval.end();
       i++) {
    osd_info[i->first].last_clean_begin = i->second.first;
    osd_info[i->first].last_clean_end = i->second.second;
  }
  for (map<int32_t,epoch_t>::iterator p = inc.new_lost.begin(); p != inc.new_lost.end(); p++)
    osd_info[p->first].lost_at = p->second;

  // uuid
  for (map<int32_t,uuid_d>::iterator p = inc.new_uuid.begin(); p != inc.new_uuid.end(); ++p) 
    (*osd_uuid)[p->first] = p->second;

  // pg rebuild
  for (map<pg_t, vector<int> >::iterator p = inc.new_pg_temp.begin(); p != inc.new_pg_temp.end(); p++) {
    if (p->second.empty())
      pg_temp->erase(p->first);
    else
      (*pg_temp)[p->first] = p->second;
  }

  // blacklist
  for (map<entity_addr_t,utime_t>::iterator p = inc.new_blacklist.begin();
       p != inc.new_blacklist.end();
       p++)
    blacklist[p->first] = p->second;
  for (vector<entity_addr_t>::iterator p = inc.old_blacklist.begin();
       p != inc.old_blacklist.end();
       p++)
    blacklist.erase(*p);

  // cluster snapshot?
  if (inc.cluster_snapshot.length()) {
    cluster_snapshot = inc.cluster_snapshot;
    cluster_snapshot_epoch = inc.epoch;
  } else {
    cluster_snapshot.clear();
    cluster_snapshot_epoch = 0;
  }

  // do new crush map last (after up/down stuff)
  if (inc.crush.length()) {
    bufferlist::iterator blp = inc.crush.begin();
    crush.reset(new CrushWrapper);
    crush->decode(blp);
  }

  calc_num_osds();
  return 0;
}


// mapping
int OSDMap::object_locator_to_pg(const object_t& oid, const object_locator_t& loc, pg_t &pg) const
{
  // calculate ps (placement seed)
  const pg_pool_t *pool = get_pg_pool(loc.get_pool());
  if (!pool)
    return -ENOENT;
  ps_t ps;
  if (loc.key.length())
    ps = ceph_str_hash(pool->object_hash, loc.key.c_str(), loc.key.length());
  else
    ps = ceph_str_hash(pool->object_hash, oid.name.c_str(), oid.name.length());
  pg = pg_t(ps, loc.get_pool(), -1);
  return 0;
}

ceph_object_layout OSDMap::make_object_layout(object_t oid, int pg_pool) const
{
  object_locator_t loc(pg_pool);

  ceph_object_layout ol;
  pg_t pgid = object_locator_to_pg(oid, loc);
  ol.ol_pgid = pgid.get_old_pg().v;
  ol.ol_stripe_unit = 0;
  return ol;
}

void OSDMap::_remove_nonexistent_osds(vector<int>& osds) const
{
  unsigned removed = 0;
  for (unsigned i = 0; i < osds.size(); i++) {
    if (!exists(osds[i])) {
      removed++;
      continue;
    }
    if (removed) {
      osds[i - removed] = osds[i];
    }
  }
  if (removed)
    osds.resize(osds.size() - removed);
}

int OSDMap::_pg_to_osds(const pg_pool_t& pool, pg_t pg, vector<int>& osds) const
{
  // map to osds[]
  ps_t pps = pool.raw_pg_to_pps(pg);  // placement ps
  unsigned size = pool.get_size();

  // what crush rule?
  int ruleno = crush->find_rule(pool.get_crush_ruleset(), pool.get_type(), size);
  if (ruleno >= 0)
    crush->do_rule(ruleno, pps, osds, size, osd_weight);

  _remove_nonexistent_osds(osds);

  return osds.size();
}

// pg -> (up osd list)
void OSDMap::_raw_to_up_osds(pg_t pg, vector<int>& raw, vector<int>& up) const
{
  up.clear();
  for (unsigned i=0; i<raw.size(); i++) {
    if (!exists(raw[i]) || is_down(raw[i])) 
      continue;
    up.push_back(raw[i]);
  }
}
  
bool OSDMap::_raw_to_temp_osds(const pg_pool_t& pool, pg_t pg, vector<int>& raw, vector<int>& temp) const
{
  pg = pool.raw_pg_to_pg(pg);
  map<pg_t,vector<int> >::const_iterator p = pg_temp->find(pg);
  if (p != pg_temp->end()) {
    temp.clear();
    for (unsigned i=0; i<p->second.size(); i++) {
      if (!exists(p->second[i]) || is_down(p->second[i]))
	continue;
      temp.push_back(p->second[i]);
    }
    return true;
  }
  return false;
}

int OSDMap::pg_to_osds(pg_t pg, vector<int>& raw) const
{
  const pg_pool_t *pool = get_pg_pool(pg.pool());
  if (!pool)
    return 0;
  return _pg_to_osds(*pool, pg, raw);
}

int OSDMap::pg_to_acting_osds(pg_t pg, vector<int>& acting) const
{
  const pg_pool_t *pool = get_pg_pool(pg.pool());
  if (!pool)
    return 0;
  vector<int> raw;
  _pg_to_osds(*pool, pg, raw);
  if (!_raw_to_temp_osds(*pool, pg, raw, acting))
    _raw_to_up_osds(pg, raw, acting);
  return acting.size();
}

void OSDMap::pg_to_raw_up(pg_t pg, vector<int>& up)
{
  const pg_pool_t *pool = get_pg_pool(pg.pool());
  if (!pool)
    return;
  vector<int> raw;
  _pg_to_osds(*pool, pg, raw);
  _raw_to_up_osds(pg, raw, up);
}
  
void OSDMap::pg_to_up_acting_osds(pg_t pg, vector<int>& up, vector<int>& acting) const
{
  const pg_pool_t *pool = get_pg_pool(pg.pool());
  if (!pool)
    return;
  vector<int> raw;
  _pg_to_osds(*pool, pg, raw);
  _raw_to_up_osds(pg, raw, up);
  if (!_raw_to_temp_osds(*pool, pg, raw, acting))
    acting = up;
}

int OSDMap::calc_pg_rank(int osd, vector<int>& acting, int nrep)
{
  if (!nrep)
    nrep = acting.size();
  for (int i=0; i<nrep; i++) 
    if (acting[i] == osd)
      return i;
  return -1;
}

int OSDMap::calc_pg_role(int osd, vector<int>& acting, int nrep)
{
  if (!nrep)
    nrep = acting.size();
  return calc_pg_rank(osd, acting, nrep);
}


// serialize, unserialize
void OSDMap::encode_client_old(bufferlist& bl) const
{
  __u16 v = 5;
  ::encode(v, bl);

  // base
  ::encode(fsid, bl);
  ::encode(epoch, bl);
  ::encode(created, bl);
  ::encode(modified, bl);

  // for ::encode(pools, bl);
  __u32 n = pools.size();
  ::encode(n, bl);
  for (map<int64_t,pg_pool_t>::const_iterator p = pools.begin();
       p != pools.end();
       ++p) {
    n = p->first;
    ::encode(n, bl);
    ::encode(p->second, bl, 0);
  }
  // for ::encode(pool_name, bl);
  n = pool_name.size();
  ::encode(n, bl);
  for (map<int64_t, string>::const_iterator p = pool_name.begin();
       p != pool_name.end();
       ++p) {
    n = p->first;
    ::encode(n, bl);
    ::encode(p->second, bl);
  }
  // for ::encode(pool_max, bl);
  n = pool_max;
  ::encode(n, bl);

  ::encode(flags, bl);

  ::encode(max_osd, bl);
  ::encode(osd_state, bl);
  ::encode(osd_weight, bl);
  ::encode(osd_addrs->client_addr, bl);

  // for ::encode(pg_temp, bl);
  n = pg_temp->size();
  ::encode(n, bl);
  for (map<pg_t,vector<int32_t> >::const_iterator p = pg_temp->begin();
       p != pg_temp->end();
       ++p) {
    old_pg_t opg = p->first.get_old_pg();
    ::encode(opg, bl);
    ::encode(p->second, bl);
  }

  // crush
  bufferlist cbl;
  crush->encode(cbl);
  ::encode(cbl, bl);
}

void OSDMap::encode(bufferlist& bl, uint64_t features) const
{
  if ((features & CEPH_FEATURE_PGID64) == 0) {
    encode_client_old(bl);
    return;
  }

  __u16 v = 6;
  ::encode(v, bl);

  // base
  ::encode(fsid, bl);
  ::encode(epoch, bl);
  ::encode(created, bl);
  ::encode(modified, bl);

  ::encode(pools, bl, features);
  ::encode(pool_name, bl);
  ::encode(pool_max, bl);

  ::encode(flags, bl);

  ::encode(max_osd, bl);
  ::encode(osd_state, bl);
  ::encode(osd_weight, bl);
  ::encode(osd_addrs->client_addr, bl);

  ::encode(*pg_temp, bl);

  // crush
  bufferlist cbl;
  crush->encode(cbl);
  ::encode(cbl, bl);

  // extended
  __u16 ev = 8;
  ::encode(ev, bl);
  ::encode(osd_addrs->hb_addr, bl);
  ::encode(osd_info, bl);
  ::encode(blacklist, bl);
  ::encode(osd_addrs->cluster_addr, bl);
  ::encode(cluster_snapshot_epoch, bl);
  ::encode(cluster_snapshot, bl);
  ::encode(*osd_uuid, bl);
}

void OSDMap::decode(bufferlist& bl)
{
  bufferlist::iterator p = bl.begin();
  decode(p);
}

void OSDMap::decode(bufferlist::iterator& p)
{
  __u32 n, t;
  __u16 v;
  ::decode(v, p);

  // base
  ::decode(fsid, p);
  ::decode(epoch, p);
  ::decode(created, p);
  ::decode(modified, p);

  if (v < 6) {
    if (v < 4) {
      int32_t max_pools = 0;
      ::decode(max_pools, p);
      pool_max = max_pools;
    }
    pools.clear();
    ::decode(n, p);
    while (n--) {
      ::decode(t, p);
      ::decode(pools[t], p);
    }
    if (v == 4) {
      ::decode(n, p);
      pool_max = n;
    } else if (v == 5) {
      pool_name.clear();
      ::decode(n, p);
      while (n--) {
	::decode(t, p);
	::decode(pool_name[t], p);
      }
      ::decode(n, p);
      pool_max = n;
    }
  } else {
    ::decode(pools, p);
    ::decode(pool_name, p);
    ::decode(pool_max, p);
  }
  // kludge around some old bug that zeroed out pool_max (#2307)
  if (pools.size() && pool_max < pools.rbegin()->first) {
    pool_max = pools.rbegin()->first;
  }

  ::decode(flags, p);

  ::decode(max_osd, p);
  ::decode(osd_state, p);
  ::decode(osd_weight, p);
  ::decode(osd_addrs->client_addr, p);
  if (v <= 5) {
    pg_temp->clear();
    ::decode(n, p);
    while (n--) {
      old_pg_t opg;
      ::decode_raw(opg, p);
      ::decode((*pg_temp)[pg_t(opg)], p);
    }
  } else {
    ::decode(*pg_temp, p);
  }

  // crush
  bufferlist cbl;
  ::decode(cbl, p);
  bufferlist::iterator cblp = cbl.begin();
  crush->decode(cblp);

  // extended
  __u16 ev = 0;
  if (v >= 5)
    ::decode(ev, p);
  ::decode(osd_addrs->hb_addr, p);
  ::decode(osd_info, p);
  if (v < 5)
    ::decode(pool_name, p);

  ::decode(blacklist, p);
  if (ev >= 6)
    ::decode(osd_addrs->cluster_addr, p);
  else
    osd_addrs->cluster_addr.resize(osd_addrs->client_addr.size());

  if (ev >= 7) {
    ::decode(cluster_snapshot_epoch, p);
    ::decode(cluster_snapshot, p);
  }

  if (ev >= 8) {
    ::decode(*osd_uuid, p);
  } else {
    osd_uuid->resize(max_osd);
  }

  // index pool names
  name_pool.clear();
  for (map<int64_t,string>::iterator i = pool_name.begin(); i != pool_name.end(); i++)
    name_pool[i->second] = i->first;

  calc_num_osds();
}



void OSDMap::dump_json(ostream& out) const
{
  JSONFormatter jsf(true);
  jsf.open_object_section("osdmap");
  dump(&jsf);
  jsf.close_section();
  jsf.flush(out);
}

void OSDMap::dump(Formatter *f) const
{
  f->dump_int("epoch", get_epoch());
  f->dump_stream("fsid") << get_fsid();
  f->dump_stream("created") << get_created();
  f->dump_stream("modified") << get_modified();
  f->dump_string("flags", get_flag_string());
  f->dump_string("cluster_snapshot", get_cluster_snapshot());
  f->dump_int("pool_max", get_pool_max());
  f->dump_int("max_osd", get_max_osd());

  f->open_array_section("pools");
  for (map<int64_t,pg_pool_t>::const_iterator p = pools.begin(); p != pools.end(); ++p) {
    f->open_object_section("pool");
    f->dump_int("pool", p->first);
    p->second.dump(f);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("osds");
  for (int i=0; i<get_max_osd(); i++)
    if (exists(i)) {
      f->open_object_section("osd_info");
      f->dump_int("osd", i);
      f->dump_stream("uuid") << get_uuid(i);
      f->dump_int("up", is_up(i));
      f->dump_int("in", is_in(i));
      get_info(i).dump(f);
      f->dump_stream("public_addr") << get_addr(i);
      f->dump_stream("cluster_addr") << get_cluster_addr(i);
      f->dump_stream("heartbeat_addr") << get_hb_addr(i);

      set<string> st;
      get_state(i, st);
      f->open_array_section("state");
      for (set<string>::iterator p = st.begin(); p != st.end(); ++p)
	f->dump_string("state", *p);
      f->close_section();

      f->close_section();
    }
  f->close_section();

  f->open_array_section("pg_temp");
  for (map<pg_t,vector<int> >::const_iterator p = pg_temp->begin();
       p != pg_temp->end();
       p++) {
    f->open_array_section("osds");
    for (vector<int>::const_iterator q = p->second.begin(); q != p->second.end(); ++q)
      f->dump_int("osd", *q);
    f->close_section();
  }
  f->close_section();

  f->open_array_section("blacklist");
  for (hash_map<entity_addr_t,utime_t>::const_iterator p = blacklist.begin();
       p != blacklist.end();
       p++) {
    stringstream ss;
    ss << p->first;
    f->dump_stream(ss.str().c_str()) << p->second;
  }
  f->close_section();
}

void OSDMap::generate_test_instances(list<OSDMap*>& o)
{
  o.push_back(new OSDMap);

  CephContext *cct = new CephContext(CODE_ENVIRONMENT_UTILITY);
  o.push_back(new OSDMap);
  uuid_d fsid;
  o.back()->build_simple(cct, 1, fsid, 16, 7, 8);
  o.back()->created = o.back()->modified = utime_t(1, 2);  // fix timestamp
  delete cct;
}

string OSDMap::get_flag_string(unsigned f)
{
  string s;
  if ( f& CEPH_OSDMAP_NEARFULL)
    s += ",nearfull";
  if (f & CEPH_OSDMAP_FULL)
    s += ",full";
  if (f & CEPH_OSDMAP_PAUSERD)
    s += ",pauserd";
  if (f & CEPH_OSDMAP_PAUSEWR)
    s += ",pausewr";
  if (f & CEPH_OSDMAP_PAUSEREC)
    s += ",pauserec";
  if (f & CEPH_OSDMAP_NOUP)
    s += ",no-up";
  if (f & CEPH_OSDMAP_NODOWN)
    s += ",no-down";
  if (f & CEPH_OSDMAP_NOOUT)
    s += ",no-out";
  if (f & CEPH_OSDMAP_NOIN)
    s += ",no-in";
  if (s.length())
    s = s.erase(0, 1);
  return s;
}

string OSDMap::get_flag_string() const
{
  return get_flag_string(flags);
}

struct qi {
  int item;
  int depth;
  float weight;
  qi() {}
  qi(int i, int d, float w) : item(i), depth(d), weight(w) {}
};

void OSDMap::print(ostream& out) const
{
  out << "epoch " << get_epoch() << "\n"
      << "fsid " << get_fsid() << "\n"
      << "created " << get_created() << "\n"
      << "modifed " << get_modified() << "\n";

  out << "flags " << get_flag_string() << "\n";
  if (get_cluster_snapshot().length())
    out << "cluster_snapshot " << get_cluster_snapshot() << "\n";
  out << "\n";

  for (map<int64_t,pg_pool_t>::const_iterator p = pools.begin(); p != pools.end(); ++p) {
    std::string name("<unknown>");
    map<int64_t,string>::const_iterator pni = pool_name.find(p->first);
    if (pni != pool_name.end())
      name = pni->second;
    out << "pool " << p->first
	<< " '" << name
	<< "' " << p->second << "\n";
    for (map<snapid_t,pool_snap_info_t>::const_iterator q = p->second.snaps.begin();
	 q != p->second.snaps.end();
	 q++)
      out << "\tsnap " << q->second.snapid << " '" << q->second.name << "' " << q->second.stamp << "\n";
    if (!p->second.removed_snaps.empty())
      out << "\tremoved_snaps " << p->second.removed_snaps << "\n";
  }
  out << std::endl;

  out << "max_osd " << get_max_osd() << "\n";
  for (int i=0; i<get_max_osd(); i++) {
    if (exists(i)) {
      out << "osd." << i;
      out << (is_up(i) ? " up  ":" down");
      out << (is_in(i) ? " in ":" out");
      out << " weight " << get_weightf(i);
      const osd_info_t& info(get_info(i));
      out << " " << info;
      out << " " << get_addr(i) << " " << get_cluster_addr(i) << " " << get_hb_addr(i);
      set<string> st;
      get_state(i, st);
      out << " " << st;
      if (!get_uuid(i).is_zero())
	out << " " << get_uuid(i);
      out << "\n";
    }
  }
  out << std::endl;

  for (map<pg_t,vector<int> >::const_iterator p = pg_temp->begin();
       p != pg_temp->end();
       p++)
    out << "pg_temp " << p->first << " " << p->second << "\n";

  for (hash_map<entity_addr_t,utime_t>::const_iterator p = blacklist.begin();
       p != blacklist.end();
       p++)
    out << "blacklist " << p->first << " expires " << p->second << "\n";

  // ignore pg_swap_primary
}

void OSDMap::print_osd_line(int cur, ostream& out) const
{
  out << "osd." << cur << "\t";
  if (!exists(cur))
    out << "DNE\t\t";
  else {
    if (is_up(cur))
      out << "up\t";
    else
      out << "down\t";
    out << (exists(cur) ? get_weightf(cur):0) << "\t";
  }
}

void OSDMap::print_tree(ostream& out) const
{
  out << "# id\tweight\ttype name\tup/down\treweight\n";
  set<int> touched;
  set<int> roots;
  crush->find_roots(roots);
  for (set<int>::iterator p = roots.begin(); p != roots.end(); p++) {
    list<qi> q;
    q.push_back(qi(*p, 0, crush->get_bucket_weight(*p) / (float)0x10000));
    while (!q.empty()) {
      int cur = q.front().item;
      int depth = q.front().depth;
      float weight = q.front().weight;
      q.pop_front();

      out << cur << "\t" << weight << "\t";
      for (int k=0; k<depth; k++)
	out << "\t";

      if (cur >= 0) {
	print_osd_line(cur, out);
	out << "\n";
	touched.insert(cur);
	continue;
      }

      int type = crush->get_bucket_type(cur);
      out << crush->get_type_name(type) << " " << crush->get_item_name(cur) << "\n";

      // queue bucket contents...
      int s = crush->get_bucket_size(cur);
      for (int k=s-1; k>=0; k--)
	q.push_front(qi(crush->get_bucket_item(cur, k), depth+1,
			(float)crush->get_bucket_item_weight(cur, k) / (float)0x10000));
    }
  }

  set<int> stray;
  for (int i=0; i<max_osd; i++)
    if (exists(i) && touched.count(i) == 0)
      stray.insert(i);

  if (!stray.empty()) {
    out << "\n";
    for (set<int>::iterator p = stray.begin(); p != stray.end(); ++p) {
      out << *p << "\t0\t";
      print_osd_line(*p, out);
      out << "\n";
    }
  }

}

void OSDMap::print_summary(ostream& out) const
{
  out << "e" << get_epoch() << ": "
      << get_num_osds() << " osds: "
      << get_num_up_osds() << " up, "
      << get_num_in_osds() << " in";
  if (test_flag(CEPH_OSDMAP_FULL))
    out << " full";
  else if (test_flag(CEPH_OSDMAP_NEARFULL))
    out << " nearfull";
}

void OSDMap::build_simple(CephContext *cct, epoch_t e, uuid_d &fsid,
			  int nosd, int pg_bits, int pgp_bits)
{
  ldout(cct, 10) << "build_simple on " << num_osd
		 << " osds with " << pg_bits << " pg bits per osd, "
		 << dendl;
  epoch = e;
  set_fsid(fsid);
  created = modified = ceph_clock_now(cct);

  set_max_osd(nosd);

  // pgp_num <= pg_num
  if (pgp_bits > pg_bits)
    pgp_bits = pg_bits;

  // crush map
  map<int, const char*> rulesets;
  rulesets[CEPH_DATA_RULE] = "data";
  rulesets[CEPH_METADATA_RULE] = "metadata";
  rulesets[CEPH_RBD_RULE] = "rbd";

  int poolbase = nosd ? nosd : 1;

  for (map<int,const char*>::iterator p = rulesets.begin(); p != rulesets.end(); p++) {
    int64_t pool = ++pool_max;
    pools[pool].type = pg_pool_t::TYPE_REP;
    pools[pool].size = cct->_conf->osd_pool_default_size;
    pools[pool].crush_ruleset = p->first;
    pools[pool].object_hash = CEPH_STR_HASH_RJENKINS;
    pools[pool].set_pg_num(poolbase << pg_bits);
    pools[pool].set_pgp_num(poolbase << pgp_bits);
    pools[pool].last_change = epoch;
    if (p->first == CEPH_DATA_RULE)
      pools[pool].crash_replay_interval = cct->_conf->osd_default_data_pool_replay_window;
    pool_name[pool] = p->second;
    name_pool[p->second] = pool;
  }

  build_simple_crush_map(cct, *crush, rulesets, nosd);

  for (int i=0; i<nosd; i++) {
    set_state(i, 0);
    set_weight(i, CEPH_OSD_OUT);
  }
}


void OSDMap::build_simple_crush_map(CephContext *cct, CrushWrapper& crush,
				    map<int, const char*>& rulesets, int nosd)
{
  const md_config_t *conf = cct->_conf;

  crush.create();

  crush.set_type_name(0, "osd");
  crush.set_type_name(1, "host");
  crush.set_type_name(2, "rack");
  crush.set_type_name(3, "row");
  crush.set_type_name(4, "room");
  crush.set_type_name(5, "datacenter");
  crush.set_type_name(6, "pool");

  // root
  int rootid = crush.add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_DEFAULT, 6 /* pool */, 0, NULL, NULL);
  crush.set_item_name(rootid, "default");

  for (int o=0; o<nosd; o++) {
    map<string,string> loc;
    loc["host"] = "localhost";
    loc["rack"] = "localrack";
    loc["pool"] = "default";
    ldout(cct, 10) << " adding osd." << o << " at " << loc << dendl;
    char name[8];
    sprintf(name, "osd.%d", o);
    crush.insert_item(cct, o, 1.0, name, loc);
  }

  // rules
  int minrep = conf->osd_min_rep;
  int maxrep = conf->osd_max_rep;
  assert(maxrep >= minrep);
  for (map<int,const char*>::iterator p = rulesets.begin(); p != rulesets.end(); p++) {
    int ruleset = p->first;
    crush_rule *rule = crush_make_rule(3, ruleset, pg_pool_t::TYPE_REP, minrep, maxrep);
    assert(rule);
    crush_rule_set_step(rule, 0, CRUSH_RULE_TAKE, rootid, 0);
    // just spread across osds
    crush_rule_set_step(rule, 1, CRUSH_RULE_CHOOSE_FIRSTN, CRUSH_CHOOSE_N, 0);
    crush_rule_set_step(rule, 2, CRUSH_RULE_EMIT, 0, 0);
    int rno = crush_add_rule(crush.crush, rule, -1);
    crush.set_rule_name(rno, p->second);
  }

  crush.finalize();
}

void OSDMap::build_simple_from_conf(CephContext *cct, epoch_t e, uuid_d &fsid,
				    int pg_bits, int pgp_bits)
{
  ldout(cct, 10) << "build_simple_from_conf with "
		 << pg_bits << " pg bits per osd, "
		 << dendl;
  epoch = e;
  set_fsid(fsid);
  created = modified = ceph_clock_now(cct);

  const md_config_t *conf = cct->_conf;

  // count osds
  int maxosd = 0;

  vector<string> sections;
  conf->get_all_sections(sections);
  for (vector<string>::iterator i = sections.begin(); i != sections.end(); ++i) {
    if (i->find("osd.") != 0)
      continue;

    const char *begin = i->c_str() + 4;
    char *end = (char*)begin;
    int o = strtol(begin, &end, 10);
    if (*end != '\0')
      continue;

    if (o > maxosd)
      maxosd = o;
  }

  set_max_osd(maxosd + 1);

  // pgp_num <= pg_num
  if (pgp_bits > pg_bits)
    pgp_bits = pg_bits;

  // crush map
  map<int, const char*> rulesets;
  rulesets[CEPH_DATA_RULE] = "data";
  rulesets[CEPH_METADATA_RULE] = "metadata";
  rulesets[CEPH_RBD_RULE] = "rbd";

  for (map<int,const char*>::iterator p = rulesets.begin(); p != rulesets.end(); p++) {
    int64_t pool = ++pool_max;
    pools[pool].type = pg_pool_t::TYPE_REP;
    pools[pool].size = cct->_conf->osd_pool_default_size;
    pools[pool].crush_ruleset = p->first;
    pools[pool].object_hash = CEPH_STR_HASH_RJENKINS;
    pools[pool].set_pg_num((maxosd + 1) << pg_bits);
    pools[pool].set_pgp_num((maxosd + 1) << pgp_bits);
    pools[pool].last_change = epoch;
    if (p->first == CEPH_DATA_RULE)
      pools[pool].crash_replay_interval = cct->_conf->osd_default_data_pool_replay_window;
    pool_name[pool] = p->second;
    name_pool[p->second] = pool;
  }

  build_simple_crush_map_from_conf(cct, *crush, rulesets);

  for (int i=0; i<=maxosd; i++) {
    set_state(i, 0);
    set_weight(i, CEPH_OSD_OUT);
  }
}

void OSDMap::build_simple_crush_map_from_conf(CephContext *cct, CrushWrapper& crush,
					      map<int, const char*>& rulesets)
{
  const md_config_t *conf = cct->_conf;

  crush.create();

  crush.set_type_name(0, "osd");
  crush.set_type_name(1, "host");
  crush.set_type_name(2, "rack");
  crush.set_type_name(3, "row");
  crush.set_type_name(4, "room");
  crush.set_type_name(5, "datacenter");
  crush.set_type_name(6, "pool");

  set<string> hosts, racks;

  // root
  int rootid = crush.add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_DEFAULT, 6 /* pool */, 0, NULL, NULL);
  crush.set_item_name(rootid, "default");

  // add osds
  vector<string> sections;
  conf->get_all_sections(sections);
  for (vector<string>::iterator i = sections.begin(); i != sections.end(); ++i) {
    if (i->find("osd.") != 0)
      continue;

    const char *begin = i->c_str() + 4;
    char *end = (char*)begin;
    int o = strtol(begin, &end, 10);
    if (*end != '\0')
      continue;

    string host, rack, row, room, dc, pool;
    vector<string> sections;
    sections.push_back("osd");
    sections.push_back(*i);
    conf->get_val_from_conf_file(sections, "host", host, false);
    conf->get_val_from_conf_file(sections, "rack", rack, false);
    conf->get_val_from_conf_file(sections, "row", row, false);
    conf->get_val_from_conf_file(sections, "room", room, false);
    conf->get_val_from_conf_file(sections, "datacenter", dc, false);
    conf->get_val_from_conf_file(sections, "pool", pool, false);

    if (host.length() == 0)
      host = "unknownhost";
    if (rack.length() == 0)
      rack = "unknownrack";

    hosts.insert(host);
    racks.insert(rack);

    map<string,string> loc;
    loc["host"] = host;
    loc["rack"] = rack;
    if (row.size())
      loc["row"] = row;
    if (room.size())
      loc["room"] = room;
    if (dc.size())
      loc["datacenter"] = dc;
    loc["pool"] = "default";

    ldout(cct, 5) << " adding osd." << o << " at " << loc << dendl;
    crush.insert_item(cct, o, 1.0, *i, loc);
  }

  // rules
  int minrep = conf->osd_min_rep;
  int maxrep = conf->osd_max_rep;
  for (map<int,const char*>::iterator p = rulesets.begin(); p != rulesets.end(); p++) {
    int ruleset = p->first;
    crush_rule *rule = crush_make_rule(3, ruleset, pg_pool_t::TYPE_REP, minrep, maxrep);
    assert(rule);
    crush_rule_set_step(rule, 0, CRUSH_RULE_TAKE, rootid, 0);

    if (racks.size() > 3) {
      // spread replicas across hosts
      crush_rule_set_step(rule, 1, CRUSH_RULE_CHOOSE_LEAF_FIRSTN, CRUSH_CHOOSE_N, 2);
    } else if (hosts.size() > 1) {
      // spread replicas across hosts
      crush_rule_set_step(rule, 1, CRUSH_RULE_CHOOSE_LEAF_FIRSTN, CRUSH_CHOOSE_N, 1);
    } else {
      // just spread across osds
      crush_rule_set_step(rule, 1, CRUSH_RULE_CHOOSE_FIRSTN, CRUSH_CHOOSE_N, 0);
    }
    crush_rule_set_step(rule, 2, CRUSH_RULE_EMIT, 0, 0);
    int rno = crush_add_rule(crush.crush, rule, -1);
    crush.set_rule_name(rno, p->second);
  }

  crush.finalize();
}


