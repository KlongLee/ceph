#ifndef CEPH_CLS_LOCK_TYPES_H
#define CEPH_CLS_LOCK_TYPES_H

#include "include/types.h"
#include "include/utime.h"

/* lock flags */
#define LOCK_FLAG_RENEW 0x1        /* idempotent lock acquire */

enum ClsLockType {
  LOCK_NONE      = 0,
  LOCK_EXCLUSIVE = 1,
  LOCK_SHARED    = 2,
};

static inline const char *cls_lock_type_str(ClsLockType type)
{
    switch (type) {
      case LOCK_NONE:
	return "none";
      case LOCK_EXCLUSIVE:
	return "exclusive";
      case LOCK_SHARED:
	return "shared";
      default:
	return "<unknown>";
    }
}

struct cls_lock_id_t {
  entity_name_t locker;
  string cookie;

  cls_lock_id_t() {}
  cls_lock_id_t(entity_name_t& _n, const string& _c) : locker(_n), cookie(_c) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(locker, bl);
    ::encode(cookie, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
    ::decode(locker, bl);
    ::decode(cookie, bl);
    DECODE_FINISH(bl);
  }

  bool operator<(const cls_lock_id_t& rhs) const {
    if (locker == rhs.locker)
      return cookie.compare(rhs.cookie) < 0;
    if (locker < rhs.locker)
      return true;
    return false;
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<cls_lock_id_t*>& o);
};
WRITE_CLASS_ENCODER(cls_lock_id_t)

struct cls_lock_locker_info_t
{
  utime_t duration;
  entity_addr_t addr;
  string description;

  cls_lock_locker_info_t() {}
  cls_lock_locker_info_t(const utime_t& _e, const entity_addr_t& _a,
			 const string& _d) :  duration(_e), addr(_a), description(_d) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(duration, bl);
    ::encode(addr, bl);
    ::encode(description, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
    ::decode(duration, bl);
    ::decode(addr, bl);
    ::decode(description, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<cls_lock_locker_info_t *>& o);
};
WRITE_CLASS_ENCODER(cls_lock_locker_info_t)

#endif
