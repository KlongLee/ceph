// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <string.h>

#include <iostream>
#include <map>

#include "include/types.h"

#include "rgw_user.h"
#include "rgw_lc_s3.h"


#define dout_subsys ceph_subsys_rgw

static bool check_date(const string& _date)
{
  boost::optional<ceph::real_time> date = ceph::from_iso_8601(_date);
  if (boost::none == date) {
    return false;
  }
  struct timespec time = ceph::real_clock::to_timespec(*date);
  if (time.tv_sec % (24*60*60) || time.tv_nsec) {
    return false;
  }
  return true;
}

void LCExpiration_S3::dump_xml(Formatter *f) const {
  if (dm_expiration) {
    encode_xml("ExpiredObjectDeleteMarker", "true", f);
  } else if (!days.empty()) {
    encode_xml("Days", days, f);
  } else {
    encode_xml("Date", date, f);
  }
}

void LCExpiration_S3::decode_xml(XMLObj *obj)
{
  bool has_days = RGWXMLDecoder::decode_xml("Days", days, obj);
  bool has_date = RGWXMLDecoder::decode_xml("Date", date, obj);
  string dm;
  bool has_dm = RGWXMLDecoder::decode_xml("ExpiredObjectDeleteMarker", dm, obj);

  int num = !!has_days + !!has_date + !!has_dm;

  if (num != 1) {
    throw RGWXMLDecoder::err("bad Expiration section");
  }

  if (has_date && !check_date(date)) {
    //We need return xml error according to S3
    throw RGWXMLDecoder::err("bad date in Date section");
  }

  if (has_dm) {
    dm_expiration = (dm == "true");
  }
}

void LCNoncurExpiration_S3::decode_xml(XMLObj *obj)
{
  RGWXMLDecoder::decode_xml("NoncurrentDays", days, obj, true);
}

void LCNoncurExpiration_S3::dump_xml(Formatter *f) const
{
  encode_xml("NoncurrentDays", days, f);
}

void LCMPExpiration_S3::decode_xml(XMLObj *obj)
{
  RGWXMLDecoder::decode_xml("DaysAfterInitiation", days, obj, true);
}

void LCMPExpiration_S3::dump_xml(Formatter *f) const
{
  encode_xml("DaysAfterInitiation", days, f);
}

void RGWLifecycleConfiguration_S3::decode_xml(XMLObj *obj)
{
  if (!cct) {
    throw RGWXMLDecoder::err("ERROR: RGWLifecycleConfiguration_S3 can't be decoded without cct initialized");
  }
  vector<LCRule_S3> rules;

  RGWXMLDecoder::decode_xml("Rule", rules, obj, true);

  for (auto& rule : rules) {
    if (rule.get_id().empty()) {
      string id;

      // S3 generates a 48 bit random ID, maybe we could generate shorter IDs
      static constexpr auto LC_ID_LENGTH = 48;

      gen_rand_alphanumeric_lower(cct, &id, LC_ID_LENGTH);
      rule.set_id(id);
    }

    add_rule(rule);
  }

  if (cct->_conf->rgw_lc_max_rules < rule_map.size()) {
    stringstream ss;
    ss << "Warn: The lifecycle config has too many rules, rule number is:" 
      << rule_map.size() << ", max number is:" << cct->_conf->rgw_lc_max_rules;
    throw RGWXMLDecoder::err(ss.str());
  }
}

void LCFilter_S3::dump_xml(Formatter *f) const
{
  if (has_prefix()) {
    encode_xml("Prefix", prefix, f);
  }
  bool multi = has_multi_condition();
  if (multi) {
    f->open_array_section("And");
  }
  if (has_tags()) {
    const auto& tagset_s3 = static_cast<const RGWObjTagSet_S3 &>(obj_tags);
    tagset_s3.dump_xml(f);
  }
  if (multi) {
    f->close_section();
  }
}

void LCFilter_S3::decode_xml(XMLObj *obj)
{
  XMLObj *o = obj->find_first("And");
  bool single_cond = false;
  int num_conditions = 0;
  // If there is an AND condition, every tag is a child of and
  // else we only support single conditions and return false if we see multiple

  if (o == nullptr){
    o = obj;
    single_cond = true;
  }

  RGWXMLDecoder::decode_xml("Prefix", prefix, o);
  if (!prefix.empty())
    num_conditions++;
  auto tags_iter = o->find("Tag");
  obj_tags.clear();
  while (auto tag_xml =tags_iter.get_next()){
    std::string _key,_val;
    RGWXMLDecoder::decode_xml("Key", _key, tag_xml);
    RGWXMLDecoder::decode_xml("Value", _val, tag_xml);
    obj_tags.emplace_tag(std::move(_key), std::move(_val));
    num_conditions++;
  }

  if (single_cond && num_conditions > 1) {
    throw RGWXMLDecoder::err("Bad filter: badly formed multiple conditions");
  }
}

void LCTransition_S3::decode_xml(XMLObj *obj)
{
  bool has_days = RGWXMLDecoder::decode_xml("Days", days, obj);
  bool has_date = RGWXMLDecoder::decode_xml("Date", date, obj);
  if ((has_days && has_date) || (!has_days && !has_date)) {
    throw RGWXMLDecoder::err("bad Transition section");
  }

  if (has_date && !check_date(date)) {
    //We need return xml error according to S3
    throw RGWXMLDecoder::err("bad Date in Transition section");
  }

  if (!RGWXMLDecoder::decode_xml("StorageClass", storage_class, obj)) {
    throw RGWXMLDecoder::err("missing StorageClass in Transition section");
  }
}

void LCTransition_S3::dump_xml(Formatter *f) const {
  if (!days.empty()) {
    encode_xml("Days", days, f);
  } else {
    encode_xml("Date", date, f);
  }
  encode_xml("StorageClass", storage_class, f);
}

void LCNoncurTransition_S3::decode_xml(XMLObj *obj)
{
  if (!RGWXMLDecoder::decode_xml("NoncurrentDays", days, obj)) {
    throw RGWXMLDecoder::err("missing NoncurrentDays in NoncurrentVersionTransition section");
  }
  if (!RGWXMLDecoder::decode_xml("StorageClass", storage_class, obj)) {
    throw RGWXMLDecoder::err("missing StorageClass in NoncurrentVersionTransition section");
  }
}

void LCNoncurTransition_S3::dump_xml(Formatter *f) const
{
  encode_xml("NoncurrentDays", days, f);
  encode_xml("StorageClass", storage_class, f);
}

void LCRule_S3::decode_xml(XMLObj *obj)
{
  id.clear();
  prefix.clear();
  status.clear();
  dm_expiration = false;

  RGWXMLDecoder::decode_xml("ID", id, obj);

  LCFilter_S3 filter_s3;
  if (!RGWXMLDecoder::decode_xml("Filter", filter_s3, obj)) {
    // Ideally the following code should be deprecated and we should return
    // False here, The new S3 LC configuration xml spec. makes Filter mandatory
    // and Prefix optional. However older clients including boto2 still generate
    // xml according to the older spec, where Prefix existed outside of Filter
    // and S3 itself seems to be sloppy on enforcing the mandatory Filter
    // argument. A day will come when S3 enforces their own xml-spec, but it is
    // not this day

    if (!RGWXMLDecoder::decode_xml("Prefix", prefix, obj)) {
      throw RGWXMLDecoder::err("missing Prefix in Filter");
    }
  }
  filter = (LCFilter)filter_s3;

  if (!RGWXMLDecoder::decode_xml("Status", status, obj)) {
    throw RGWXMLDecoder::err("missing Status in Filter");
  }
  if (status.compare("Enabled") != 0 && status.compare("Disabled") != 0 &&
      status.compare("Purge_Enabled") != 0) {
    throw RGWXMLDecoder::err("bad Status in Filter");
  }

  LCExpiration_S3 s3_expiration;
  LCNoncurExpiration_S3 s3_noncur_expiration;
  LCMPExpiration_S3 s3_mp_expiration;
  LCFilter_S3 s3_filter;

  bool has_expiration = RGWXMLDecoder::decode_xml("Expiration", s3_expiration, obj);
  bool has_noncur_expiration = RGWXMLDecoder::decode_xml("NoncurrentVersionExpiration", s3_noncur_expiration, obj);
  bool has_mp_expiration = RGWXMLDecoder::decode_xml("AbortIncompleteMultipartUpload", s3_mp_expiration, obj);

  vector<LCTransition_S3> transitions;
  vector<LCNoncurTransition_S3> noncur_transitions;

  bool has_transition = RGWXMLDecoder::decode_xml("Transition", transitions, obj);
  bool has_noncur_transition = RGWXMLDecoder::decode_xml("NoncurrentVersionTransition", noncur_transitions, obj);

  if (!has_expiration &&
      !has_noncur_expiration &&
      !has_mp_expiration &&
      !has_transition &&
      !has_noncur_transition) {
    throw RGWXMLDecoder::err("bad Rule");
  }

  if (has_expiration) {
    if (s3_expiration.has_days() ||
        s3_expiration.has_date()) {
      expiration = s3_expiration;
    } else {
      dm_expiration = s3_expiration.get_dm_expiration();
    }
  }
  if (has_noncur_expiration) {
    noncur_expiration = s3_noncur_expiration;
  }
  if (has_mp_expiration) {
    mp_expiration = s3_mp_expiration;
  }
  for (auto& t : transitions) {
    if (!add_transition(t)) {
      throw RGWXMLDecoder::err("Failed to add transition");
    }
  }
  for (auto& t : noncur_transitions) {
    if (!add_noncur_transition(t)) {
      throw RGWXMLDecoder::err("Failed to add non-current version transition");
    }
  }
}

void LCRule_S3::dump_xml(Formatter *f) const {
  encode_xml("ID", id, f);
  // In case of an empty filter and an empty Prefix, we defer to Prefix.
  if (!filter.empty()) {
    const LCFilter_S3& lc_filter = static_cast<const LCFilter_S3&>(filter);
    encode_xml("Filter", lc_filter, f);
  } else {
    encode_xml("Prefix", prefix, f);
  }
  encode_xml("Status", status, f);
  if (!expiration.empty() || dm_expiration) {
    LCExpiration_S3 expir(expiration.get_days_str(), expiration.get_date(), dm_expiration);
    encode_xml("Expiration", expir, f);
  }
  if (!noncur_expiration.empty()) {
    const LCNoncurExpiration_S3& noncur_expir = static_cast<const LCNoncurExpiration_S3&>(noncur_expiration);
    encode_xml("NoncurrentVersionExpiration", noncur_expir, f);
  }
  if (!mp_expiration.empty()) {
    const LCMPExpiration_S3& mp_expir = static_cast<const LCMPExpiration_S3&>(mp_expiration);
    encode_xml("AbortIncompleteMultipartUpload", mp_expir, f);
  }
  if (!transitions.empty()) {
    for (auto &elem : transitions) {
      const LCTransition_S3& tran = static_cast<const LCTransition_S3&>(elem.second);
      encode_xml("Transition", tran, f);
    }
  }
  if (!noncur_transitions.empty()) {
    for (auto &elem : noncur_transitions) {
      const LCNoncurTransition_S3& noncur_tran = static_cast<const LCNoncurTransition_S3&>(elem.second);
      encode_xml("NoncurrentVersionTransition", noncur_tran, f);
    }
  }
}

int RGWLifecycleConfiguration_S3::validate()
{
  multimap<string, LCRule>::iterator iter;
  multimap<string, LCRule> duplicate_finder;

  /*
    * Validate the rules for the following conditions:
    * 1. Basic sanity checking of each LCRule
    * 2. Check for duplicate IDs in case of multiple rules
    * (Duplicate prefixes are still fine. We don't check for them)
    */
  for (iter = rule_map.begin(); iter != rule_map.end(); ++iter) {
    LCRule& rule = iter->second;
    if (!rule.valid()) {
      return -EINVAL;
    } else {
      if (duplicate_finder.find(iter->first) == duplicate_finder.end())
        duplicate_finder.insert(make_pair(iter->first, iter->second));
      else
        return -EINVAL;
    }
  }
  return 0;
}


void RGWLifecycleConfiguration_S3::dump_xml(Formatter *f) const
{
  for (auto iter = rule_map.begin(); iter != rule_map.end(); ++iter) {
    const LCRule_S3& rule = static_cast<const LCRule_S3&>(iter->second);
    encode_xml("Rule", rule, f);
  }
}

