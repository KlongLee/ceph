#ifndef CEPH_RGW_REST_CLIENT_H
#define CEPH_RGW_REST_CLIENT_H

#include <list>

#include "rgw_http_client.h"

class RGWRESTClient : public RGWHTTPClient {
  CephContext *cct;

protected:
  int status;

  string url;

  map<string, string> out_headers;
  list<pair<string, string> > params;
public:
  RGWRESTClient(CephContext *_cct, string& _url, list<pair<string, string> > *_headers,
                list<pair<string, string> > *_params) : cct(_cct), status(0), url(_url) {
    if (_headers)
      headers = *_headers;

    if (_params)
      params = *_params;
  }

  int read_header(void *ptr, size_t len);

  int execute(RGWAccessKey& key, const char *method, const char *resource);
};


#endif

