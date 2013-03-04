#ifndef CEPH_RGW_METADATA_H
#define CEPH_RGW_METADATA_H

#include <string>

#include "include/types.h"
#include "rgw_common.h"

class RGWRados;


class RGWMetadataHandler {
public:
  virtual ~RGWMetadataHandler() {}
  virtual string get_type() = 0;

  virtual int get(RGWRados *store, string& key, string& entry, Formatter *f) = 0;
  virtual int update(RGWRados *store, string& entry, bufferlist& bl) = 0;

  virtual int list_keys_init(RGWRados *store, void **phandle) = 0;
  virtual int list_keys_next(void *handle, int max, list<string>& keys, bool *truncated) = 0;
  virtual void list_keys_complete(void *handle) = 0;
};


class RGWMetadataManager {
  map<string, RGWMetadataHandler *> handlers;
  RGWRados *store;

  void parse_metadata_key(const string& metadata_key, string& type, string& entry);

  int find_handler(const string& metadata_key, RGWMetadataHandler **handler, string& entry);

public:
  RGWMetadataManager(RGWRados *_store) : store(_store) {}
  ~RGWMetadataManager();

  int register_handler(RGWMetadataHandler *handler);

  int get(string& metadata_key, Formatter *f);
  int update(string& metadata_key, bufferlist& bl);

  int list_keys_init(string& section, void **phandle);
  int list_keys_next(void *handle, int max, list<string>& keys, bool *truncated);
  void list_keys_complete(void *handle);
};

#endif
