// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */
#include <string.h>

#include <iostream>
#include <map>

#include "include/types.h"

#include "rgw_cors_s3.h"
#include "rgw_user.h"

#define dout_subsys ceph_subsys_rgw

using namespace std;

void RGWCORSRule_S3::to_xml(ostream& out){
  out << "<CORSRule>";
  /*ID if present*/
  if(id.length() > 0){
    out << "<ID>" << id << "</ID>";
  }
  /*AllowedMethods*/
  if(allowed_methods & RGW_CORS_GET)
    out << "<AllowedMethod>GET</AllowedMethod>";
  if(allowed_methods & RGW_CORS_PUT)
    out << "<AllowedMethod>PUT</AllowedMethod>";
  if(allowed_methods & RGW_CORS_DELETE)
    out << "<AllowedMethod>DELETE</AllowedMethod>";
  if(allowed_methods & RGW_CORS_HEAD)
    out << "<AllowedMethod>HEAD</AllowedMethod>";
  if(allowed_methods & RGW_CORS_POST)
    out << "<AllowedMethod>POST</AllowedMethod>";
  /*AllowedOrigins*/
  for(set<string>::iterator it = allowed_origins.begin(); 
      it != allowed_origins.end(); 
      it++){
    string host, proto, in = *it;
    parse_host_name(in, host, proto);
    if(proto.length() == 0)
      proto = "http://";
    out << "<AllowedOrigin>" << proto << "www." << host << "</AllowedOrigin>";
  }
  /*AllowedHeader*/
  for(set<string>::iterator it = allowed_hdrs.begin(); 
      it != allowed_hdrs.end(); it++){
    out << "<AllowedHeader>" << *it << "</AllowedHeader>";
  }
  /*MaxAgeSeconds*/
  if(max_age != CORS_MAX_AGE_INVALID){
    out << "<MaxAgeSeconds>" << max_age << "</MaxAgeSeconds>";
  }
  /*ExposeHeader*/
  for(list<string>::iterator it = exposable_hdrs.begin(); 
      it != exposable_hdrs.end(); it++){
    out << "<ExposeHeader>" << *it << "</ExposeHeader>";
  }
  out << "</CORSRule>";
}

bool RGWCORSRule_S3::xml_end(const char *el){
  XMLObjIter iter = find("AllowedMethod");
  XMLObj *obj;
  /*Check all the allowedmethods*/
  obj = iter.get_next();
  if(obj){
    for( ; obj; obj = iter.get_next()) {
      const char *s = obj->get_data().c_str();
      dout(10) << "RGWCORSRule::xml_end, el : " << el << ", data : " << s << dendl;
      if(strcasecmp(s, "GET") == 0){
        allowed_methods |= RGW_CORS_GET;
      }else if(strcasecmp(s, "POST") == 0){
        allowed_methods |= RGW_CORS_POST;
      }else if(strcasecmp(s, "DELETE") == 0){
        allowed_methods |= RGW_CORS_DELETE;
      }else if(strcasecmp(s, "HEAD") == 0){
        allowed_methods |= RGW_CORS_HEAD;
      }else if(strcasecmp(s, "PUT") == 0){
        allowed_methods |= RGW_CORS_PUT;
      }else 
        return false;
    }
  } 
  /*Check the id's len, it should be less than 255*/
  XMLObj *xml_id = find_first("ID");
  if(xml_id != NULL){
    string data = xml_id->get_data();
    if(data.length() > 255){
      dout(0) << "RGWCORSRule has id of length greater than 255" << dendl;
      return false;
    }
    dout(10) << "RGWCORRule id : " << data << dendl;  
    id = data;
  }
  /*Check if there is atleast one AllowedOrigin*/
  iter = find("AllowedOrigin");
  if(!(obj = iter.get_next())){
    dout(0) << "RGWCORSRule does not have even one AllowedOrigin" << dendl;
    return false;
  }
  for( ; obj; obj = iter.get_next()){
    dout(10) << "RGWCORSRule - origin : " << obj->get_data() << dendl;
    /*Just take the hostname*/
    string s = obj->get_data(), host, proto;
    parse_host_name(s, host, proto);
    allowed_origins.insert(allowed_origins.end(), proto+host);
  }
  /*Check of max_age*/
  iter = find("MaxAgeSeconds");
  if((obj = iter.get_next())){
    char *end = NULL;
    max_age = strtol(obj->get_data().c_str(), &end, 10);
    if (max_age == LONG_MAX)
      max_age = CORS_MAX_AGE_INVALID;
    dout(10) << "RGWCORSRule : max_age : " << max_age << dendl;
  }
  /*Check and update ExposeHeader*/
  iter = find("ExposeHeader");
  if((obj = iter.get_next())){
    for(; obj; obj = iter.get_next()){
      dout(10) << "RGWCORSRule - exp_hdr : " << obj->get_data() << dendl;
      exposable_hdrs.push_back(obj->get_data());
    }
  }
  /*Check and update AllowedHeader*/
  iter = find("AllowedHeader");
  if((obj = iter.get_next())){
    for(; obj; obj = iter.get_next()){
      dout(10) << "RGWCORSRule - allowed_hdr : " << obj->get_data() << dendl;
      allowed_hdrs.insert(allowed_hdrs.end(), obj->get_data());
    }
  }
  return true;
}

void RGWCORSConfiguration_S3::to_xml(ostream& out){
  out << "<CORSConfiguration>";
  for(list<RGWCORSRule>::iterator it = rules.begin();
      it != rules.end(); it++){
    (static_cast<RGWCORSRule_S3 &>(*it)).to_xml(out);
  }
  out << "</CORSConfiguration>";
}

bool RGWCORSConfiguration_S3::xml_end(const char *el){
  XMLObjIter iter = find("CORSRule");
  RGWCORSRule_S3 *obj;
  if(!(obj = (RGWCORSRule_S3 *)iter.get_next())){
    dout(0) << "CORSConfiguration should have atleast one CORSRule" << dendl;
    return false;
  }
  for(; obj; obj = (RGWCORSRule_S3 *)iter.get_next()){
    rules.insert(rules.end(), *obj);
  }
  return true;
}

class CORSRuleID_S3 : public XMLObj {
  public:
    CORSRuleID_S3(){}
    ~CORSRuleID_S3(){}
};

class CORSRuleAllowedOrigin_S3 : public XMLObj {
  public:
    CORSRuleAllowedOrigin_S3(){}
    ~CORSRuleAllowedOrigin_S3(){}
};

class CORSRuleAllowedMethod_S3 : public XMLObj {
  public:
    CORSRuleAllowedMethod_S3(){}
    ~CORSRuleAllowedMethod_S3(){}
};

class CORSRuleAllowedHeader_S3 : public XMLObj {
  public:
    CORSRuleAllowedHeader_S3(){}
    ~CORSRuleAllowedHeader_S3(){}
};

class CORSRuleMaxAgeSeconds_S3 : public XMLObj {
  public:
    CORSRuleMaxAgeSeconds_S3(){}
    ~CORSRuleMaxAgeSeconds_S3(){}
};

class CORSRuleExposeHeader_S3 : public XMLObj {
  public:
    CORSRuleExposeHeader_S3(){}
    ~CORSRuleExposeHeader_S3(){}
};

XMLObj *RGWCORSXMLParser_S3::alloc_obj(const char *el){
  if(strcmp(el, "CORSConfiguration") == 0) return new RGWCORSConfiguration_S3;
  if(strcmp(el, "CORSRule") == 0) return new RGWCORSRule_S3;
  if(strcmp(el, "ID") == 0) return new CORSRuleID_S3;
  if(strcmp(el, "AllowedOrigin") == 0) return new CORSRuleAllowedOrigin_S3;
  if(strcmp(el, "AllowedMethod") == 0) return new CORSRuleAllowedMethod_S3;
  if(strcmp(el, "AllowedHeader") == 0) return new CORSRuleAllowedHeader_S3;
  if(strcmp(el, "MaxAgeSeconds") == 0) return new CORSRuleMaxAgeSeconds_S3;
  if(strcmp(el, "ExposeHeader")  == 0) return new CORSRuleExposeHeader_S3;
  return NULL;
}

