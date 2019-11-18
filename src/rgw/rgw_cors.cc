// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

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

#include <boost/algorithm/string.hpp>

#include "include/types.h"
#include "common/debug.h"
#include "common/str_util.h"
#include "common/Formatter.h"
#include "common/str_util.h"

#include "rgw_cors.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

void RGWCORSRule::dump_origins() {
  unsigned num_origins = allowed_origins.size();
  dout(10) << "Allowed origins : " << num_origins << dendl;
  for(set<string>::iterator it = allowed_origins.begin();
      it != allowed_origins.end(); 
      ++it) {
    dout(10) << *it << "," << dendl;
  }
}

void RGWCORSRule::erase_origin_if_present(string& origin, bool *rule_empty) {
  set<string>::iterator it = allowed_origins.find(origin);
  if (!rule_empty)
    return;
  *rule_empty = false;
  if (it != allowed_origins.end()) {
    dout(10) << "Found origin " << origin << ", set size:" << 
        allowed_origins.size() << dendl;
    allowed_origins.erase(it);
    *rule_empty = (allowed_origins.empty());
  }
}

/*
 * make attrs look-like-this
 * does not convert underscores or dashes
 *
 * Per CORS specification, section 3:
 * ===
 * "Converting a string to ASCII lowercase" means replacing all characters in the
 * range U+0041 LATIN CAPITAL LETTER A to U+005A LATIN CAPITAL LETTER Z with
 * the corresponding characters in the range U+0061 LATIN SMALL LETTER A to
 * U+007A LATIN SMALL LETTER Z).
 * ===
 *
 * @todo When UTF-8 is allowed in HTTP headers, this function will need to change
 */
static std::string lowercase_http_attr(std::string_view orig)
{
  return ceph::transform(orig, [](char c) { return char(std::tolower(c)); });
}


static bool is_string_in_set(const set<string, std::less<>>& s,
			     std::string_view h)
{
  if ((s.find("*") != s.end()) ||
      (s.find(h) != s.end())) {
    return true;
  }
  /* The header can be Content-*-type, or Content-* */
  for(auto it = s.begin(); it != s.end(); ++it) {
    size_t off;
    if ((off = (*it).find("*"))!=string::npos) {
      std::deque<string> ssplit;
      unsigned flen = 0;

      ceph::substr_insert((*it), std::back_inserter(ssplit), "* \t");
      if (off != 0) {
        string sl = ssplit.front();
        flen = sl.length();
        dout(10) << "Finding " << sl << ", in " << h << ", at offset 0" << dendl;
        if (!boost::algorithm::starts_with(h,sl))
          continue;
        ssplit.pop_front();
      }
      if (off != ((*it).length() - 1)) {
        string sl = ssplit.front();
        dout(10) << "Finding " << sl << ", in " << h
          << ", at offset not less than " << flen << dendl;
        if (h.size() < sl.size() ||
	    h.compare((h.size() - sl.size()), sl.size(), sl) != 0)
          continue;
        ssplit.pop_front();
      }
      if (!ssplit.empty())
        continue;
      return true;
    }
  }
  return false;
}

bool RGWCORSRule::has_wildcard_origin() {
  if (allowed_origins.find("*") != allowed_origins.end())
    return true;

  return false;
}

bool RGWCORSRule::is_origin_present(std::string_view o)
{
  return is_string_in_set(allowed_origins, o);
}

bool RGWCORSRule::is_header_allowed(std::string_view h) {
  if (lowercase_allowed_hdrs.empty()) {
    for (auto iter = allowed_hdrs.begin(); iter != allowed_hdrs.end(); ++iter) {
      lowercase_allowed_hdrs.insert(lowercase_http_attr(*iter));
    }
  }
  return is_string_in_set(lowercase_allowed_hdrs, lowercase_http_attr(h));
}

void RGWCORSRule::format_exp_headers(string& s) {
  s = "";
  for(auto it = exposable_hdrs.begin();
      it != exposable_hdrs.end(); ++it) {
      if (s.length() > 0)
        s.append(",");
      s.append((*it));
  }
}

RGWCORSRule* RGWCORSConfiguration::host_name_rule(std::string_view origin)
{
  for(auto it_r = rules.begin(); it_r != rules.end(); ++it_r) {
    RGWCORSRule& r = (*it_r);
    if (r.is_origin_present(origin))
      return &r;
  }
  return nullptr;
}

void RGWCORSConfiguration::erase_host_name_rule(string& origin) {
  bool rule_empty;
  unsigned loop = 0;
  /*Erase the host name from that rule*/
  dout(10) << "Num of rules : " << rules.size() << dendl;
  for(list<RGWCORSRule>::iterator it_r = rules.begin(); 
      it_r != rules.end(); ++it_r, loop++) {
    RGWCORSRule& r = (*it_r);
    r.erase_origin_if_present(origin, &rule_empty);
    dout(10) << "Origin:" << origin << ", rule num:" 
      << loop << ", emptying now:" << rule_empty << dendl;
    if (rule_empty) {
      rules.erase(it_r);
      break;
    }
  }
}

void RGWCORSConfiguration::dump() {
  unsigned loop = 1;
  unsigned num_rules = rules.size();
  dout(10) << "Number of rules: " << num_rules << dendl;
  for(list<RGWCORSRule>::iterator it = rules.begin();
      it!= rules.end(); ++it, loop++) {
    dout(10) << " <<<<<<< Rule " << loop << " >>>>>>> " << dendl;
    (*it).dump_origins();
  }
}
