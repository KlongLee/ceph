// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <map>
#include <string>

#include <common/errno.h>
#include <boost/algorithm/string.hpp>

#include "rgw_tag.h"
#include "rgw_common.h"

bool RGWObjTags::add_tag(const string&key, const string& val){
  return tag_map.emplace(std::make_pair(key,val)).second;
}

bool RGWObjTags::emplace_tag(std::string&& key, std::string&& val){
  return tag_map.emplace(std::move(key), std::move(val)).second;
}

int RGWObjTags::check_and_add_tag(const string&key, const string& val){
  if (tag_map.size() == max_obj_tags ||
      key.size() > max_tag_key_size ||
      val.size() > max_tag_val_size ||
      key.size() == 0){
    return -ERR_INVALID_TAG;
  }

  // if we get a conflicting key, either the XML is malformed or the user
  // supplied an invalid string
  if (!add_tag(key,val))
    return -EINVAL;

  return 0;
}

int RGWObjTags::set_from_string(const string& input){
  int ret=0;
  vector <string> kvs;
  boost::split(kvs, input, boost::is_any_of("&"));
  for (const auto& kv: kvs){
    auto p = kv.find("=");
    string key,val;
    if (p != string::npos) {
      ret = check_and_add_tag(url_decode(kv.substr(0,p)),
                              url_decode(kv.substr(p+1)));
    } else {
      ret = check_and_add_tag(url_decode(kv));
    }

    if (ret < 0)
      return ret;
  }
  return ret;
}
