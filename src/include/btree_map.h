// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_INCLUDE_BTREE_MAP_H
#define CEPH_INCLUDE_BTREE_MAP_H

#include "include/cpp-btree/btree.h"
#include "include/cpp-btree/btree_map.h"
#include "include/assert.h"   // cpp-btree uses system assert, blech
#include "include/encoding.h"

template<class T, class U>
inline void encode(const btree::btree_map<T,U>& m, bufferlist& bl)
{
  __u32 n = (__u32)(m.size());
  encode(n, bl);
  for (typename btree::btree_map<T,U>::const_iterator p = m.begin(); p != m.end(); ++p) {
    encode(p->first, bl);
    encode(p->second, bl);
  }
}
template<class T, class U>
inline void encode(const btree::btree_map<T,U>& m, bufferlist& bl, uint64_t features)
{
  __u32 n = (__u32)(m.size());
  encode(n, bl);
  for (typename btree::btree_map<T,U>::const_iterator p = m.begin(); p != m.end(); ++p) {
    encode(p->first, bl, features);
    encode(p->second, bl, features);
  }
}
template<class T, class U>
inline void decode(btree::btree_map<T,U>& m, bufferlist::const_iterator& p)
{
  __u32 n;
  decode(n, p);
  m.clear();
  while (n--) {
    T k;
    decode(k, p);
    decode(m[k], p);
  }
}
template<class T, class U>
inline void encode_nohead(const btree::btree_map<T,U>& m, bufferlist& bl)
{
  for (typename btree::btree_map<T,U>::const_iterator p = m.begin(); p != m.end(); ++p) {
    encode(p->first, bl);
    encode(p->second, bl);
  }
}
template<class T, class U>
inline void decode_nohead(int n, btree::btree_map<T,U>& m, bufferlist::const_iterator& p)
{
  m.clear();
  while (n--) {
    T k;
    decode(k, p);
    decode(m[k], p);
  }
}

#endif
