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

#ifndef CEPH_MSG_TYPES_H
#define CEPH_MSG_TYPES_H

#include <netinet/in.h>

#include "include/types.h"
#include "include/blobhash.h"
#include "include/encoding.h"

namespace ceph {
  class Formatter;
}

extern ostream& operator<<(ostream& out, const sockaddr_storage &ss);
extern ostream& operator<<(ostream& out, const sockaddr *sa);

class entity_name_t {
public:
  __u8 _type;
  int64_t _num;

public:
  static const int TYPE_MON = CEPH_ENTITY_TYPE_MON;
  static const int TYPE_MDS = CEPH_ENTITY_TYPE_MDS;
  static const int TYPE_OSD = CEPH_ENTITY_TYPE_OSD;
  static const int TYPE_CLIENT = CEPH_ENTITY_TYPE_CLIENT;

  static const int64_t NEW = -1;

  // cons
  entity_name_t() : _type(0), _num(0) { }
  entity_name_t(int t, int64_t n) : _type(t), _num(n) { }
  explicit entity_name_t(const ceph_entity_name &n) : 
    _type(n.type), _num(n.num) { }

  // static cons
  static entity_name_t MON(int64_t i=NEW) { return entity_name_t(TYPE_MON, i); }
  static entity_name_t MDS(int64_t i=NEW) { return entity_name_t(TYPE_MDS, i); }
  static entity_name_t OSD(int64_t i=NEW) { return entity_name_t(TYPE_OSD, i); }
  static entity_name_t CLIENT(int64_t i=NEW) { return entity_name_t(TYPE_CLIENT, i); }
  
  int64_t num() const { return _num; }
  int type() const { return _type; }
  const char *type_str() const {
    return ceph_entity_type_name(type());
  }

  bool is_new() const { return num() < 0; }

  bool is_client() const { return type() == TYPE_CLIENT; }
  bool is_mds() const { return type() == TYPE_MDS; }
  bool is_osd() const { return type() == TYPE_OSD; }
  bool is_mon() const { return type() == TYPE_MON; }

  operator ceph_entity_name() const {
    ceph_entity_name n = { _type, init_le64(_num) };
    return n;
  }

  bool parse(const string& s) {
    const char *start = s.c_str();
    char *end;
    bool got = parse(start, &end);
    return got && end == start + s.length();
  }
  bool parse(const char *start, char **end) {
    if (strstr(start, "mon.") == start) {
      _type = TYPE_MON;
      start += 4;
    } else if (strstr(start, "osd.") == start) {
      _type = TYPE_OSD;
      start += 4;
    } else if (strstr(start, "mds.") == start) {
      _type = TYPE_MDS;
      start += 4;
    } else if (strstr(start, "client.") == start) {
      _type = TYPE_CLIENT;
      start += 7;
    } else {
      return false;
    }
    if (isspace(*start))
      return false;
    _num = strtoll(start, end, 10);
    if (*end == NULL || *end == start)
      return false;
    return true;
  }

  void encode(bufferlist& bl) const {
    ::encode(_type, bl);
    ::encode(_num, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(_type, bl);
    ::decode(_num, bl);
  }
  void dump(Formatter *f) const;

  static void generate_test_instances(list<entity_name_t*>& o);
};
WRITE_CLASS_ENCODER(entity_name_t)

inline bool operator== (const entity_name_t& l, const entity_name_t& r) { 
  return (l.type() == r.type()) && (l.num() == r.num()); }
inline bool operator!= (const entity_name_t& l, const entity_name_t& r) { 
  return (l.type() != r.type()) || (l.num() != r.num()); }
inline bool operator< (const entity_name_t& l, const entity_name_t& r) { 
  return (l.type() < r.type()) || (l.type() == r.type() && l.num() < r.num()); }

inline std::ostream& operator<<(std::ostream& out, const entity_name_t& addr) {
  //if (addr.is_namer()) return out << "namer";
  if (addr.is_new() || addr.num() < 0)
    return out << addr.type_str() << ".?";
  else
    return out << addr.type_str() << '.' << addr.num();
}
inline std::ostream& operator<<(std::ostream& out, const ceph_entity_name& addr) {
  return out << *(const entity_name_t*)&addr;
}

namespace std {
  template<> struct hash< entity_name_t >
  {
    size_t operator()( const entity_name_t &m ) const
    {
      return rjhash32(m.type() ^ m.num());
    }
  };
} // namespace std



/*
 * an entity's network address.
 * includes a random value that prevents it from being reused.
 * thus identifies a particular process instance.
 * ipv4 for now.
 */

#if defined(__linux__) || defined(DARWIN) || defined(__FreeBSD__)
/*
 * encode sockaddr.ss_family as network byte order 
 */
static inline void encode(const sockaddr_storage& a, bufferlist& bl) {
  struct sockaddr_storage ss = a;
#if defined(DARWIN) || defined(__FreeBSD__)
  unsigned short *ss_family = reinterpret_cast<unsigned short*>(&ss);
  *ss_family = htons(a.ss_family);
#else
  ss.ss_family = htons(ss.ss_family);
#endif
  ::encode_raw(ss, bl);
}
static inline void decode(sockaddr_storage& a, bufferlist::iterator& bl) {
  ::decode_raw(a, bl);
#if defined(DARWIN) || defined(__FreeBSD__)
  unsigned short *ss_family = reinterpret_cast<unsigned short *>(&a);
  a.ss_family = ntohs(*ss_family);
  a.ss_len = 0;
#else
  a.ss_family = ntohs(a.ss_family);
#endif
}
#endif

// define a wire format for sockaddr that matches Linux's.
struct ceph_sockaddr_storage {
  __le16 ss_family;
  __u8 __ss_padding[128 - sizeof(__le16)];

  void encode(bufferlist& bl) const {
    struct ceph_sockaddr_storage ss = *this;
    ss.ss_family = htons(ss.ss_family);
    ::encode_raw(ss, bl);
  }

  void decode(bufferlist::iterator& bl) {
    struct ceph_sockaddr_storage ss;
    ::decode_raw(ss, bl);
    ss.ss_family = ntohs(ss.ss_family);
    *this = ss;
  }
} __attribute__ ((__packed__));

WRITE_CLASS_ENCODER(ceph_sockaddr_storage)

struct entity_addr_t {
  __u32 type;
  __u32 nonce;
  union {
    sockaddr sa;
    sockaddr_in sin;
    sockaddr_in6 sin6;
  } u;

  entity_addr_t() : type(0), nonce(0) { 
    memset(&u, 0, sizeof(u));
  }
  explicit entity_addr_t(const ceph_entity_addr &o) {
    type = o.type;
    nonce = o.nonce;
    memcpy(&u, &o.in_addr, sizeof(u));
#if !defined(__FreeBSD__)
    u.sa.sa_family = ntohs(u.sa.sa_family);
#endif
  }

  __u32 get_nonce() const { return nonce; }
  void set_nonce(__u32 n) { nonce = n; }

  int get_family() const {
    return u.sa.sa_family;
  }
  void set_family(int f) {
    u.sa.sa_family = f;
  }

  sockaddr_in &in4_addr() {
    return u.sin;
  }
  const sockaddr_in &in4_addr() const{
    return u.sin;
  }
  sockaddr_in6 &in6_addr(){
    return u.sin6;
  }
  const sockaddr_in6 &in6_addr() const{
    return u.sin6;
  }
  const sockaddr *get_sockaddr() const {
    return &u.sa;
  }
  size_t get_sockaddr_len() const {
    switch (u.sa.sa_family) {
    case AF_INET:
      return sizeof(u.sin);
      break;
    case AF_INET6:
      return sizeof(u.sin6);
      break;
    }
    return sizeof(u);
  }
  bool set_sockaddr(const struct sockaddr *sa)
  {
    switch (sa->sa_family) {
    case AF_INET:
      memcpy(&u.sin, sa, sizeof(u.sin));
      break;
    case AF_INET6:
      memcpy(&u.sin6, sa, sizeof(u.sin6));
      break;
    default:
      return false;
    }
    return true;
  }

  sockaddr_storage get_sockaddr_storage() const {
    sockaddr_storage ss;
    memcpy(&ss, &u, sizeof(u));
    memset((char*)&ss + sizeof(u), 0, sizeof(ss) - sizeof(u));
    return ss;
  }

  void set_in4_quad(int pos, int val) {
    u.sin.sin_family = AF_INET;
    unsigned char *ipq = (unsigned char*)&u.sin.sin_addr.s_addr;
    ipq[pos] = val;
  }
  void set_port(int port) {
    switch (u.sa.sa_family) {
    case AF_INET:
      u.sin.sin_port = htons(port);
      break;
    case AF_INET6:
      u.sin6.sin6_port = htons(port);
      break;
    default:
      assert(0);
    }
  }
  int get_port() const {
    switch (u.sa.sa_family) {
    case AF_INET:
      return ntohs(u.sin.sin_port);
      break;
    case AF_INET6:
      return ntohs(u.sin6.sin6_port);
      break;
    }
    return 0;
  }

  operator ceph_entity_addr() const {
    ceph_entity_addr a;
    a.type = 0;
    a.nonce = nonce;
    a.in_addr = get_sockaddr_storage();
#if !defined(__FreeBSD__)
    a.in_addr.ss_family = htons(a.in_addr.ss_family);
#endif
    return a;
  }

  bool probably_equals(const entity_addr_t &o) const {
    if (get_port() != o.get_port())
      return false;
    if (get_nonce() != o.get_nonce())
      return false;
    if (is_blank_ip() || o.is_blank_ip())
      return true;
    if (memcmp(&u, &o.u, sizeof(u)) == 0)
      return true;
    return false;
  }
  
  bool is_same_host(const entity_addr_t &o) const {
    if (u.sa.sa_family != o.u.sa.sa_family)
      return false;
    if (u.sa.sa_family == AF_INET)
      return u.sin.sin_addr.s_addr == o.u.sin.sin_addr.s_addr;
    if (u.sa.sa_family == AF_INET6)
      return memcmp(u.sin6.sin6_addr.s6_addr,
		    o.u.sin6.sin6_addr.s6_addr,
		    sizeof(u.sin6.sin6_addr.s6_addr)) == 0;
    return false;
  }

  bool is_blank_ip() const {
    switch (u.sa.sa_family) {
    case AF_INET:
      return u.sin.sin_addr.s_addr == INADDR_ANY;
    case AF_INET6:
      return memcmp(&u.sin6.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0;
    default:
      return true;
    }
  }

  bool is_ip() const {
    switch (u.sa.sa_family) {
    case AF_INET:
    case AF_INET6:
      return true;
    default:
      return false;
    }
  }

  bool parse(const char *s, const char **end = 0);

  // Right now, these only deal with sockaddr_storage that have only family and content.
  // Apparently on BSD there is also an ss_len that we need to handle; this requires
  // broader study


  void encode(bufferlist& bl) const {
    ::encode(type, bl);
    ::encode(nonce, bl);
    sockaddr_storage ss = get_sockaddr_storage();
#if defined(__linux__) || defined(DARWIN) || defined(__FreeBSD__)
    ::encode(ss, bl);
#else
    ceph_sockaddr_storage wireaddr;
    ::memset(&wireaddr, '\0', sizeof(wireaddr));
    unsigned copysize = MIN(sizeof(wireaddr), sizeof(ss));
    // ceph_sockaddr_storage is in host byte order
    ::memcpy(&wireaddr, &ss, copysize);
    ::encode(wireaddr, bl);
#endif
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(type, bl);
    ::decode(nonce, bl);
    sockaddr_storage ss;
#if defined(__linux__) || defined(DARWIN) || defined(__FreeBSD__)
    ::decode(ss, bl);
#else
    ceph_sockaddr_storage wireaddr;
    ::memset(&wireaddr, '\0', sizeof(wireaddr));
    ::decode(wireaddr, bl);
    unsigned copysize = MIN(sizeof(wireaddr), sizeof(ss));
    ::memcpy(&ss, &wireaddr, copysize);
#endif
    set_sockaddr((sockaddr*)&ss);
  }

  void dump(Formatter *f) const;

  static void generate_test_instances(list<entity_addr_t*>& o);
};
WRITE_CLASS_ENCODER(entity_addr_t)

inline ostream& operator<<(ostream& out, const entity_addr_t &addr)
{
  return out << addr.get_sockaddr() << '/' << addr.nonce;
}

inline bool operator==(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) == 0; }
inline bool operator!=(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) != 0; }
inline bool operator<(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) < 0; }
inline bool operator<=(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) <= 0; }
inline bool operator>(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) > 0; }
inline bool operator>=(const entity_addr_t& a, const entity_addr_t& b) { return memcmp(&a, &b, sizeof(a)) >= 0; }

namespace std {
  template<> struct hash< entity_addr_t >
  {
    size_t operator()( const entity_addr_t& x ) const
    {
      static blobhash H;
      return H((const char*)&x, sizeof(x));
    }
  };
} // namespace std


/*
 * a particular entity instance
 */
struct entity_inst_t {
  entity_name_t name;
  entity_addr_t addr;
  entity_inst_t() {}
  entity_inst_t(entity_name_t n, const entity_addr_t& a) : name(n), addr(a) {}
  // cppcheck-suppress noExplicitConstructor
  entity_inst_t(const ceph_entity_inst& i) : name(i.name), addr(i.addr) { }
  entity_inst_t(const ceph_entity_name& n, const ceph_entity_addr &a) : name(n), addr(a) {}
  operator ceph_entity_inst() {
    ceph_entity_inst i = {name, addr};
    return i;
  }

  void encode(bufferlist& bl) const {
    ::encode(name, bl);
    ::encode(addr, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(name, bl);
    ::decode(addr, bl);
  }
};
WRITE_CLASS_ENCODER(entity_inst_t)


inline bool operator==(const entity_inst_t& a, const entity_inst_t& b) { 
  return a.name == b.name && a.addr == b.addr;
}
inline bool operator!=(const entity_inst_t& a, const entity_inst_t& b) { 
  return a.name != b.name || a.addr != b.addr;
}
inline bool operator<(const entity_inst_t& a, const entity_inst_t& b) { 
  return a.name < b.name || (a.name == b.name && a.addr < b.addr);
}
inline bool operator<=(const entity_inst_t& a, const entity_inst_t& b) {
  return a.name < b.name || (a.name == b.name && a.addr <= b.addr);
}
inline bool operator>(const entity_inst_t& a, const entity_inst_t& b) { return b < a; }
inline bool operator>=(const entity_inst_t& a, const entity_inst_t& b) { return b <= a; }

namespace std {
  template<> struct hash< entity_inst_t >
  {
    size_t operator()( const entity_inst_t& x ) const
    {
      static hash< entity_name_t > H;
      static hash< entity_addr_t > I;
      return H(x.name) ^ I(x.addr);
    }
  };
} // namespace std


inline ostream& operator<<(ostream& out, const entity_inst_t &i)
{
  return out << i.name << " " << i.addr;
}
inline ostream& operator<<(ostream& out, const ceph_entity_inst &i)
{
  entity_inst_t n = i;
  return out << n;
}





#endif
