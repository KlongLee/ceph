#include "include/types.h"

#include <string.h>
#include <iostream>

#include "rgw_multi.h"

using namespace std;

#define dout_subsys ceph_subsys_rgw

bool RGWMultiPart::xml_end(const char *el)
{
  RGWMultiPartNumber *num_obj = (RGWMultiPartNumber *)find_first("PartNumber");
  RGWMultiETag *etag_obj = (RGWMultiETag *)find_first("ETag");

  if (!num_obj || !etag_obj)
    return false;

  string s = num_obj->get_data();
  if (s.empty())
    return false;

  num = atoi(s.c_str());

  s = etag_obj->get_data();
  etag = s;

  return true;
}

bool RGWMultiCompleteUpload::xml_end(const char *el) {
  XMLObjIter iter = find("Part");
  RGWMultiPart *part = (RGWMultiPart *)iter.get_next();
  while (part) {
    int num = part->get_num();
    string etag = part->get_etag();
    parts[num] = etag;
    part = (RGWMultiPart *)iter.get_next();
  }
  return true;
}


XMLObj *RGWMultiXMLParser::alloc_obj(const char *el) {
  XMLObj *obj = NULL;
  if (strcmp(el, "CompleteMultipartUpload") == 0) {
    obj = new RGWMultiCompleteUpload();
  } else if (strcmp(el, "Part") == 0) {
    obj = new RGWMultiPart();
  } else if (strcmp(el, "PartNumber") == 0) {
    obj = new RGWMultiPartNumber();
  } else if (strcmp(el, "ETag") == 0) {
    obj = new RGWMultiETag();
  }

  return obj;
}

