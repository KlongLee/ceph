// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2012 Inktank
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "common/pick_address.h"
#include "include/ipaddr.h"
#include "include/str_list.h"
#include "common/ceph_context.h"
#ifndef WITH_SEASTAR
#include "common/config.h"
#include "common/config_obs.h"
#endif
#include "common/debug.h"
#include "common/errno.h"
#include "common/numa.h"

#include <netdb.h>

#define dout_subsys ceph_subsys_

const struct sockaddr *find_ip_in_subnet_list(
  CephContext *cct,
  const struct ifaddrs *ifa,
  unsigned ipv,
  const std::string &networks,
  const std::string &interfaces,
  const std::string &excl_interfaces,
  const std::string &excl_interface_prefixes,
  int numa_node)
{
  std::list<string> nets;
  get_str_list(networks, nets);
  std::list<string> ifs;
  get_str_list(interfaces, ifs);
  std::list<string> excl_ifs;
  get_str_list(excl_interfaces, excl_ifs);
  std::list<string> excl_if_prefixes;
  get_str_list(excl_interface_prefixes, excl_if_prefixes);

  // filter interfaces by name
  const struct ifaddrs *filtered_0 = nullptr;
  struct ifaddrs *tmp_head_0 = nullptr;
  const struct ifaddrs *filtered = nullptr;
  for (const struct ifaddrs *p = ifa; p; p = p->ifa_next) {
    bool excluded = false;
    for (auto& s : excl_ifs) {
      if (strcmp(s.c_str(), p->ifa_name) == 0) {
        excluded = true;
        break;
      }
    }
    if (excluded) continue;
    for (auto& s : excl_if_prefixes) {
     if (strncmp(s.c_str(), p->ifa_name, s.length()) == 0) {
       excluded = true;
       break;
     }
    }
    if (excluded) continue;
    struct ifaddrs *n = new ifaddrs;
    memcpy(n, p, sizeof(*p));
    n->ifa_next = tmp_head_0;
    tmp_head_0 = n;
  }
  filtered_0 = tmp_head_0;
  if (ifs.empty()) {
    filtered = filtered_0;
  } else {
    if (nets.empty()) {
      lderr(cct) << "interface names specified but not network names" << dendl;
      exit(1);
    }
    const struct ifaddrs *t = filtered_0;
    struct ifaddrs *head = 0;
    while (t) {
      bool match = false;
      for (auto& i : ifs) {
	if (strcmp(i.c_str(), t->ifa_name) == 0) {
	  match = true;
	  break;
	}
      }
      if (match) {
	struct ifaddrs *n = new ifaddrs;
	memcpy(n, t, sizeof(*t));
	n->ifa_next = head;
	head = n;
      }
      t = t->ifa_next;
    }
    if (!head) {
      lderr(cct) << "no interfaces matching " << ifs << dendl;
      exit(1);
    }
    filtered = head;
  }

  struct sockaddr *r = nullptr;
  for (auto& s : nets) {
    struct sockaddr_storage net;
    unsigned int prefix_len;

    if (!parse_network(s.c_str(), &net, &prefix_len)) {
      lderr(cct) << "unable to parse network: " << s << dendl;
      exit(1);
    }

    switch (net.ss_family) {
    case AF_INET:
      if (!(ipv & CEPH_PICK_ADDRESS_IPV4)) {
	continue;
      }
      break;
    case AF_INET6:
      if (!(ipv & CEPH_PICK_ADDRESS_IPV6)) {
	continue;
      }
      break;
    }

    const struct ifaddrs *found = find_ip_in_subnet(
      filtered,
      (struct sockaddr *) &net, prefix_len, numa_node);
    if (found) {
      r = found->ifa_addr;
      break;
    }
  }

  if (filtered != filtered_0) {
    while (filtered) {
      struct ifaddrs *t = filtered->ifa_next;
      delete filtered;
      filtered = t;
    }
  }
  while (filtered_0) {
    struct ifaddrs *t = filtered_0->ifa_next;
    delete filtered_0;
    filtered_0 = t;
  }

  return r;
}

#ifndef WITH_SEASTAR
// observe this change
struct Observer : public md_config_obs_t {
  const char *keys[2];
  explicit Observer(const char *c) {
    keys[0] = c;
    keys[1] = NULL;
  }

  const char** get_tracked_conf_keys() const override {
    return (const char **)keys;
  }
  void handle_conf_change(const ConfigProxy& conf,
			  const std::set <std::string> &changed) override {
    // do nothing.
  }
};

static void fill_in_one_address(CephContext *cct,
				const struct ifaddrs *ifa,
				const string networks,
				const string interfaces,
				const char *conf_var,
				const string& excluded_ifs,
				const string& excluded_if_prefixes,
				int numa_node = -1)
{
  const struct sockaddr *found = find_ip_in_subnet_list(
    cct,
    ifa,
    CEPH_PICK_ADDRESS_IPV4|CEPH_PICK_ADDRESS_IPV6,
    networks,
    interfaces,
    excluded_ifs,
    excluded_if_prefixes,
    numa_node);
  if (!found) {
    lderr(cct) << "unable to find any IP address in networks '" << networks
	       << "' interfaces '" << interfaces << "'" << dendl;
    exit(1);
  }

  char buf[INET6_ADDRSTRLEN];
  int err;

  err = getnameinfo(found,
		    (found->sa_family == AF_INET)
		    ? sizeof(struct sockaddr_in)
		    : sizeof(struct sockaddr_in6),

		    buf, sizeof(buf),
		    nullptr, 0,
		    NI_NUMERICHOST);
  if (err != 0) {
    lderr(cct) << "unable to convert chosen address to string: " << gai_strerror(err) << dendl;
    exit(1);
  }

  Observer obs(conf_var);

  cct->_conf.add_observer(&obs);

  cct->_conf.set_val_or_die(conf_var, buf);
  cct->_conf.apply_changes(nullptr);

  cct->_conf.remove_observer(&obs);
}

void pick_addresses(CephContext *cct, int needs)
{
  struct ifaddrs *ifa;
  int r = getifaddrs(&ifa);
  auto public_addr = cct->_conf.get_val<entity_addr_t>("public_addr");
  auto public_network = cct->_conf.get_val<std::string>("public_network");
  auto public_network_interface =
    cct->_conf.get_val<std::string>("public_network_interface");
  auto cluster_addr = cct->_conf.get_val<entity_addr_t>("cluster_addr");
  auto cluster_network = cct->_conf.get_val<std::string>("cluster_network");
  auto cluster_network_interface =
    cct->_conf.get_val<std::string>("cluster_network_interface");
  auto excluded_network_interfaces =
    cct->_conf.get_val<std::string>("excluded_network_interfaces");
  auto excluded_network_interface_prefixes =
    cct->_conf.get_val<std::string>("excluded_network_interface_prefixes");

  if (r < 0) {
    string err = cpp_strerror(errno);
    lderr(cct) << "unable to fetch interfaces and addresses: " << err << dendl;
    exit(1);
  }

  if ((needs & CEPH_PICK_ADDRESS_PUBLIC) &&
    public_addr.is_blank_ip() && !public_network.empty()) {
    fill_in_one_address(cct, ifa, public_network, public_network_interface,
                        "public_addr",
                        excluded_network_interfaces,
                        excluded_network_interface_prefixes);
  }

  if ((needs & CEPH_PICK_ADDRESS_CLUSTER) && cluster_addr.is_blank_ip()) {
    if (!cluster_network.empty()) {
      fill_in_one_address(cct, ifa, cluster_network, cluster_network_interface,
                          "cluster_addr",
                          excluded_network_interfaces,
                          excluded_network_interface_prefixes);
    } else {
      if (!public_network.empty()) {
        lderr(cct) << "Public network was set, but cluster network was not set " << dendl;
        lderr(cct) << "    Using public network also for cluster network" << dendl;
        fill_in_one_address(cct, ifa, public_network, public_network_interface,
                            "cluster_addr",
                            excluded_network_interfaces,
                            excluded_network_interface_prefixes);
      }
    }
  }

  freeifaddrs(ifa);
}
#endif	// !WITH_SEASTAR

static int fill_in_one_address(
  CephContext *cct,
  const struct ifaddrs *ifa,
  unsigned ipv,
  const string networks,
  const string interfaces,
  const string& excluded_ifs,
  const string& excluded_if_prefixes,
  entity_addrvec_t *addrs,
  int numa_node = -1)
{
  const struct sockaddr *found = find_ip_in_subnet_list(cct, ifa, ipv, networks,
    interfaces, excluded_ifs, excluded_if_prefixes,
    numa_node);
  if (!found) {
    std::string ip_type = "";
    if ((ipv & CEPH_PICK_ADDRESS_IPV4) && (ipv & CEPH_PICK_ADDRESS_IPV6)) {
      ip_type = "IPv4 or IPv6";
    } else if (ipv & CEPH_PICK_ADDRESS_IPV4) {
      ip_type = "IPv4";
    } else {
      ip_type = "IPv6";
    }
    lderr(cct) << "unable to find any " << ip_type << " address in networks '"
               << networks << "' interfaces '" << interfaces << "'" << dendl;
    return -1;
  }

  char buf[INET6_ADDRSTRLEN];
  int err;

  err = getnameinfo(found,
		    (found->sa_family == AF_INET)
		    ? sizeof(struct sockaddr_in)
		    : sizeof(struct sockaddr_in6),

		    buf, sizeof(buf),
		    nullptr, 0,
		    NI_NUMERICHOST);
  if (err != 0) {
    lderr(cct) << "unable to convert chosen address to string: " << gai_strerror(err) << dendl;
    return -1;
  }

  entity_addr_t addr;
  const char *end = 0;
  bool r = addr.parse(buf, &end);
  if (!r) {
    return -1;
  }
  addrs->v.push_back(addr);
  return 0;
}

int pick_addresses(
  CephContext *cct,
  unsigned flags,
  struct ifaddrs *ifa,
  entity_addrvec_t *addrs,
  int preferred_numa_node)
{
  addrs->v.clear();

  unsigned addrt = (flags & (CEPH_PICK_ADDRESS_PUBLIC |
			     CEPH_PICK_ADDRESS_CLUSTER));
  if (addrt == 0 ||
      addrt == (CEPH_PICK_ADDRESS_PUBLIC |
		CEPH_PICK_ADDRESS_CLUSTER)) {
    return -EINVAL;
  }
  unsigned msgrv = flags & (CEPH_PICK_ADDRESS_MSGR1 |
			    CEPH_PICK_ADDRESS_MSGR2);
  if (msgrv == 0) {
    if (cct->_conf.get_val<bool>("ms_bind_msgr1")) {
      msgrv |= CEPH_PICK_ADDRESS_MSGR1;
    }
    if (cct->_conf.get_val<bool>("ms_bind_msgr2")) {
      msgrv |= CEPH_PICK_ADDRESS_MSGR2;
    }
    if (msgrv == 0) {
      return -EINVAL;
    }
  }
  unsigned ipv = flags & (CEPH_PICK_ADDRESS_IPV4 |
			  CEPH_PICK_ADDRESS_IPV6);
  if (ipv == 0) {
    if (cct->_conf.get_val<bool>("ms_bind_ipv4")) {
      ipv |= CEPH_PICK_ADDRESS_IPV4;
    }
    if (cct->_conf.get_val<bool>("ms_bind_ipv6")) {
      ipv |= CEPH_PICK_ADDRESS_IPV6;
    }
    if (ipv == 0) {
      return -EINVAL;
    }
    if (cct->_conf.get_val<bool>("ms_bind_prefer_ipv4")) {
      flags |= CEPH_PICK_ADDRESS_PREFER_IPV4;
    } else {
      flags &= ~CEPH_PICK_ADDRESS_PREFER_IPV4;
    }
  }

  entity_addr_t addr;
  string networks;
  string interfaces;
  if (addrt & CEPH_PICK_ADDRESS_PUBLIC) {
    addr = cct->_conf.get_val<entity_addr_t>("public_addr");
    networks = cct->_conf.get_val<std::string>("public_network");
    interfaces =
      cct->_conf.get_val<std::string>("public_network_interface");
  } else {
    addr = cct->_conf.get_val<entity_addr_t>("cluster_addr");
    networks = cct->_conf.get_val<std::string>("cluster_network");
    interfaces =
      cct->_conf.get_val<std::string>("cluster_network_interface");
    if (networks.empty()) {
      lderr(cct) << "Falling back to public interface" << dendl;
      // fall back to public_ network and interface if cluster is not set
      networks = cct->_conf.get_val<std::string>("public_network");
      interfaces =
	cct->_conf.get_val<std::string>("public_network_interface");
    }
  }
  auto excluded_network_interfaces =
    cct->_conf.get_val<std::string>("excluded_network_interfaces");
  auto excluded_network_interface_prefixes =
    cct->_conf.get_val<std::string>("excluded_network_interface_prefixes");
  if (addr.is_blank_ip() &&
      !networks.empty()) {
    int ipv4_r = !(ipv & CEPH_PICK_ADDRESS_IPV4) ? 0 : -1;
    int ipv6_r = !(ipv & CEPH_PICK_ADDRESS_IPV6) ? 0 : -1;
    // first try on preferred numa node (if >= 0), then anywhere.
    while (true) {
      // note: pass in ipv to filter the matching addresses
      if ((ipv & CEPH_PICK_ADDRESS_IPV4) &&
	  (flags & CEPH_PICK_ADDRESS_PREFER_IPV4)) {
	ipv4_r = fill_in_one_address(cct, ifa, CEPH_PICK_ADDRESS_IPV4,
                                     networks, interfaces,
                                     excluded_network_interfaces,
                                     excluded_network_interface_prefixes,
                                     addrs,
                                     preferred_numa_node);
      }
      if (ipv & CEPH_PICK_ADDRESS_IPV6) {
	ipv6_r = fill_in_one_address(cct, ifa, CEPH_PICK_ADDRESS_IPV6,
                                     networks, interfaces,
                                     excluded_network_interfaces,
                                     excluded_network_interface_prefixes,
                                     addrs,
                                     preferred_numa_node);
      }
      if ((ipv & CEPH_PICK_ADDRESS_IPV4) &&
	  !(flags & CEPH_PICK_ADDRESS_PREFER_IPV4)) {
	ipv4_r = fill_in_one_address(cct, ifa, CEPH_PICK_ADDRESS_IPV4,
                                     networks, interfaces,
                                     excluded_network_interfaces,
                                     excluded_network_interface_prefixes,
                                     addrs,
                                     preferred_numa_node);
      }
      if (ipv4_r >= 0 && ipv6_r >= 0) {
	break;
      }
      if (preferred_numa_node < 0) {
	return ipv4_r >= 0 && ipv6_r >= 0 ? 0 : -1;
      }
      preferred_numa_node = -1;      // try any numa node
    }
  }

  // note: we may have a blank addr here

  // ipv4 and/or ipv6?
  if (addrs->v.empty()) {
    addr.set_type(entity_addr_t::TYPE_MSGR2);
    if ((ipv & CEPH_PICK_ADDRESS_IPV4) &&
	(flags & CEPH_PICK_ADDRESS_PREFER_IPV4)) {
      addr.set_family(AF_INET);
      addrs->v.push_back(addr);
    }
    if (ipv & CEPH_PICK_ADDRESS_IPV6) {
      addr.set_family(AF_INET6);
      addrs->v.push_back(addr);
    }
    if ((ipv & CEPH_PICK_ADDRESS_IPV4) &&
	!(flags & CEPH_PICK_ADDRESS_PREFER_IPV4)) {
      addr.set_family(AF_INET);
      addrs->v.push_back(addr);
    }
  }

  // msgr2 or legacy or both?
  if (msgrv == (CEPH_PICK_ADDRESS_MSGR1 | CEPH_PICK_ADDRESS_MSGR2)) {
    vector<entity_addr_t> v;
    v.swap(addrs->v);
    for (auto a : v) {
      a.set_type(entity_addr_t::TYPE_MSGR2);
      if (flags & CEPH_PICK_ADDRESS_DEFAULT_MON_PORTS) {
	a.set_port(CEPH_MON_PORT_IANA);
      }
      addrs->v.push_back(a);
      a.set_type(entity_addr_t::TYPE_LEGACY);
      if (flags & CEPH_PICK_ADDRESS_DEFAULT_MON_PORTS) {
	a.set_port(CEPH_MON_PORT_LEGACY);
      }
      addrs->v.push_back(a);
    }
  } else if (msgrv == CEPH_PICK_ADDRESS_MSGR1) {
    for (auto& a : addrs->v) {
      a.set_type(entity_addr_t::TYPE_LEGACY);
    }
  } else {
    for (auto& a : addrs->v) {
      a.set_type(entity_addr_t::TYPE_MSGR2);
    }
  }

  return 0;
}

int pick_addresses(
  CephContext *cct,
  unsigned flags,
  entity_addrvec_t *addrs,
  int preferred_numa_node)
{
  struct ifaddrs *ifa;
  int r = getifaddrs(&ifa);
  if (r < 0) {
    r = -errno;
    string err = cpp_strerror(r);
    lderr(cct) << "unable to fetch interfaces and addresses: "
	       <<  cpp_strerror(r) << dendl;
    return r;
  }
  r = pick_addresses(cct, flags, ifa, addrs, preferred_numa_node);
  freeifaddrs(ifa);
  return r;
}

std::string pick_iface(CephContext *cct, const struct sockaddr_storage &network)
{
  struct ifaddrs *ifa;
  int r = getifaddrs(&ifa);
  if (r < 0) {
    string err = cpp_strerror(errno);
    lderr(cct) << "unable to fetch interfaces and addresses: " << err << dendl;
    return {};
  }

  const unsigned int prefix_len = max(sizeof(in_addr::s_addr), sizeof(in6_addr::s6_addr)) * CHAR_BIT;
  const struct ifaddrs *found = find_ip_in_subnet(
    ifa,
    (const struct sockaddr *) &network, prefix_len);

  std::string result;
  if (found) {
    result = found->ifa_name;
  }

  freeifaddrs(ifa);

  return result;
}


bool have_local_addr(CephContext *cct, const list<entity_addr_t>& ls, entity_addr_t *match)
{
  struct ifaddrs *ifa;
  int r = getifaddrs(&ifa);
  if (r < 0) {
    lderr(cct) << "unable to fetch interfaces and addresses: " << cpp_strerror(errno) << dendl;
    exit(1);
  }

  bool found = false;
  for (struct ifaddrs *addrs = ifa; addrs != nullptr; addrs = addrs->ifa_next) {
    if (addrs->ifa_addr) {
      entity_addr_t a;
      a.set_sockaddr(addrs->ifa_addr);
      for (auto& p : ls) {
        if (a.is_same_host(p)) {
          *match = p;
          found = true;
          goto out;
        }
      }
    }
  }

 out:
  freeifaddrs(ifa);
  return found;
}

int get_iface_numa_node(
  const std::string& iface,
  int *node)
{
  string fn = std::string("/sys/class/net/") + iface + "/device/numa_node";

  int r = 0;
  char buf[1024];
  char *endptr = 0;
  int fd = ::open(fn.c_str(), O_RDONLY);
  if (fd < 0) {
    return -errno;
  }
  r = safe_read(fd, &buf, sizeof(buf));
  if (r < 0) {
    goto out;
  }
  buf[r] = 0;
  while (r > 0 && ::isspace(buf[--r])) {
    buf[r] = 0;
  }
  *node = strtoll(buf, &endptr, 10);
  if (endptr != buf + strlen(buf)) {
    r = -EINVAL;
    goto out;
  }
  r = 0;
 out:
  ::close(fd);
  return r;
}
