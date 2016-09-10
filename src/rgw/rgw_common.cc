// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>

#include "json_spirit/json_spirit.h"
#include "common/ceph_json.h"

#include "rgw_common.h"
#include "rgw_acl.h"
#include "rgw_string.h"

#include "common/ceph_crypto.h"
#include "common/armor.h"
#include "common/errno.h"
#include "common/Clock.h"
#include "common/Formatter.h"
#include "common/perf_counters.h"
#include "common/centile.h"
#include "common/strtol.h"
#include "include/str_list.h"
#include "auth/Crypto.h"

#include <sstream>
#include "common/Timer.h"

#define dout_subsys ceph_subsys_rgw

void setup_perf_timers(CephContext *cct, int update, int reset);
void update_percentile_perf(CephContext *cct);

PerfCounters *perfcounter = NULL;
PerfCounters *percentile_perfcounter = NULL;
int percentile_get_first, percentile_put_first;
vector<double> percentiles;
vector<unsigned int> object_sizes;
Mutex *lat_reset_lock, *lat_perf_update_lock;
SafeTimer *lat_reset_timer, *lat_perf_update_timer;

const uint32_t RGWBucketInfo::NUM_SHARDS_BLIND_BUCKET(UINT32_MAX);

centile::CentileCollection *get_lat_centile;
centile::CentileCollection *put_lat_centile;

int rgw_perf_start(CephContext *cct)
{
  PerfCountersBuilder plb(cct, cct->_conf->name.to_str(), l_rgw_first, l_rgw_last);

  plb.add_u64_counter(l_rgw_req, "req");
  plb.add_u64_counter(l_rgw_failed_req, "failed_req");

  plb.add_u64_counter(l_rgw_get, "get");
  plb.add_u64_counter(l_rgw_get_b, "get_b");
  plb.add_time_avg(l_rgw_get_lat, "get_initial_lat");
  plb.add_u64_counter(l_rgw_put, "put");
  plb.add_u64_counter(l_rgw_put_b, "put_b");
  plb.add_time_avg(l_rgw_put_lat, "put_initial_lat");

  plb.add_u64(l_rgw_qlen, "qlen");
  plb.add_u64(l_rgw_qactive, "qactive");

  plb.add_u64_counter(l_rgw_cache_hit, "cache_hit");
  plb.add_u64_counter(l_rgw_cache_miss, "cache_miss");

  plb.add_u64_counter(l_rgw_keystone_token_cache_hit, "keystone_token_cache_hit");
  plb.add_u64_counter(l_rgw_keystone_token_cache_miss, "keystone_token_cache_miss");

  plb.add_u64_counter(l_rgw_http_1xx_count, "http_1xx_count");
  plb.add_u64_counter(l_rgw_http_2xx_count, "http_2xx_count");
  plb.add_u64_counter(l_rgw_http_3xx_count, "http_3xx_count");
  plb.add_u64_counter(l_rgw_http_4xx_count, "http_4xx_count");
  plb.add_u64_counter(l_rgw_http_5xx_count, "http_5xx_count");
  plb.add_u64_counter(l_rgw_http_NULL_count, "http_NULL_count");

  perfcounter = plb.create_perf_counters();
  cct->get_perfcounters_collection()->add(perfcounter);
  return percentile_perf_start(cct);
}

void rgw_perf_stop(CephContext *cct)
{
  assert(perfcounter);
  cct->get_perfcounters_collection()->remove(perfcounter);
  delete perfcounter;
  percentile_perf_stop(cct);
}


int percentile_perf_start(CephContext *cct)
{
  int p_starti, p_endi, p_inci, p_updatei, p_reseti, index = 1;
  percentile_get_first = 16000;

  vector<string> sections;
  cct->_conf->get_my_sections(sections);

  string percentiles_conf_val, object_sizes_conf_val, p_start, p_end, p_inc, p_update, p_reset;

  cct->_conf->get_val_from_conf_file(sections, "rgw percentile buckets", percentiles_conf_val, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw object size buckets", object_sizes_conf_val, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw latency bucket duration start", p_start, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw latency bucket duration count", p_end, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw latency bucket duration increment", p_inc, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw latency bucket update", p_update, false);
  cct->_conf->get_val_from_conf_file(sections, "rgw latency bucket reset", p_reset, false);

  stringstream ss;
  string item;

  if(percentiles_conf_val.size() > 0) {
    ss.str(percentiles_conf_val);
    while (getline(ss, item, ',')) {
      percentiles.push_back(std::atof(item.c_str()));
    }
  }
  if(object_sizes_conf_val.size() > 0) {
    ss.clear();
    ss.str("");
    item = "";
    ss.str(object_sizes_conf_val);
    while (getline(ss, item, ',')) {
      object_sizes.push_back(std::atoi(item.c_str()));
    }
  }

  if(percentiles.empty()) {
    percentiles.push_back(0.99);
  }
  if(object_sizes.empty()) {
    object_sizes.push_back(1);
  }
  if(p_start.size() > 0) {
    p_starti = atoi(p_start.c_str());
  } else {
    p_starti = cct->_conf->rgw_latency_bucket_duration_start;
  }
  if(p_end.size() > 0) {
    p_endi = atoi(p_end.c_str()) * atoi(p_inc.c_str());
  } else {
    p_endi = cct->_conf->rgw_latency_bucket_duration_count * cct->_conf->rgw_latency_bucket_duration_increment;
  }
  if(p_inc.size() > 0) {
    p_inci = atoi(p_inc.c_str());
  } else {
    p_inci = cct->_conf->rgw_latency_bucket_duration_increment;
  }
  if(p_update.size() > 0) {
    p_updatei = atoi(p_update.c_str());
  } else {
    p_updatei = cct->_conf->rgw_latency_bucket_update;
  }
  if(p_reset.size() > 0) {
    p_reseti = atoi(p_reset.c_str());
  } else {
    p_reseti = cct->_conf->rgw_latency_bucket_reset;
  }

  percentile_put_first = percentile_get_first + (percentiles.size() * object_sizes.size());
  int percentile_last = percentile_get_first + (2 * (percentiles.size() * object_sizes.size())) + 1;
  PerfCountersBuilder plb(cct, "percentiles", percentile_get_first, percentile_last);

  get_lat_centile = new centile::CentileCollection(p_starti, p_endi, p_inci, object_sizes);
  put_lat_centile = new centile::CentileCollection(p_starti, p_endi, p_inci, object_sizes);

  for(vector<unsigned int>::iterator object_size_it = object_sizes.begin(); object_size_it != object_sizes.end(); object_size_it++) {
    for(vector<double>::iterator percentile_it = percentiles.begin(); percentile_it != percentiles.end(); percentile_it++) {
      std::ostringstream ostr;
      ostr << *object_size_it;
      std::string object_size = ostr.str();
      ostr.clear();
      ostr.str("");
      ostr << *percentile_it;
      std::string percentile = ostr.str();
      string str = string("get_objectSize_") + object_size + "_percentile_" + percentile;
      char *cstrget = new char[str.length()+1];
      strcpy(cstrget, str.c_str());
      plb.add_u64_counter(percentile_get_first + index, cstrget);

      str = string("put_objectsize_") + object_size + "_percentile_" + percentile;
      char *cstrput = new char[str.length()+1];
      strcpy(cstrput, str.c_str());
      plb.add_u64_counter(percentile_put_first + index, cstrput);
      index++;
    }
  }

  percentile_perfcounter = plb.create_perf_counters();
  cct->get_perfcounters_collection()->add(percentile_perfcounter);
  setup_perf_timers(cct, p_updatei, p_reseti);
  return 0;
}

void percentile_perf_stop(CephContext *cct)
{
  assert(percentile_perfcounter);
  cct->get_perfcounters_collection()->remove(percentile_perfcounter);
  delete percentile_perfcounter;
  delete get_lat_centile;
  delete put_lat_centile;
}

/* Updating all the percentiles for all the object sizes*/
void update_percentile_perf(CephContext *cct) {
  int index = 1;
  for(vector<unsigned int>::iterator object_size_it = object_sizes.begin(); object_size_it != object_sizes.end(); object_size_it++) {
    for(vector<double>::iterator percentile_it = percentiles.begin(); percentile_it != percentiles.end(); percentile_it++) {
      percentile_perfcounter->set(percentile_get_first + index, get_lat_centile->get_percentile(cct, *object_size_it, *percentile_it));
      percentile_perfcounter->set(percentile_put_first + index, put_lat_centile->get_percentile(cct, *object_size_it, *percentile_it));
      index++;
    }
  }
}

class C_lat_perf_update_timeout : public Context {
public:
  C_lat_perf_update_timeout(CephContext *cct_) : cct(cct_) {}
  void finish(int r) {
    update_percentile_perf(cct);
    lat_perf_update_timer->add_event_after(20, new C_lat_perf_update_timeout(cct));
  }
private:
  CephContext *cct;
};

class C_lat_reset_timeout : public Context {
public:
  C_lat_reset_timeout() {}
  void finish(int r) {
    get_lat_centile->reset();
    put_lat_centile->reset();
    lat_reset_timer->add_event_after(60, new C_lat_reset_timeout);
  }
};

/* Starting the update and reset percentile counters.*/
void setup_perf_timers(CephContext *cct, int update, int reset) {
  lat_perf_update_lock = new Mutex("lat_perf_update_lock");
  lat_perf_update_timer = new SafeTimer(cct, *lat_perf_update_lock);
  lat_perf_update_timer->init();
  lat_perf_update_lock->Lock();
  lat_perf_update_timer->add_event_after(update, new C_lat_perf_update_timeout(cct));
  lat_perf_update_lock->Unlock();

  lat_reset_lock = new Mutex("lat_reset_lock");
  lat_reset_timer = new SafeTimer(cct, *lat_reset_lock);
  lat_reset_timer->init();
  lat_reset_lock->Lock();
  lat_reset_timer->add_event_after(reset, new C_lat_reset_timeout);
  lat_reset_lock->Unlock();
}


using namespace ceph::crypto;

rgw_err::
rgw_err()
{
  clear();
}

rgw_err::
rgw_err(int http, const std::string& s3)
    : http_ret(http), ret(0), s3_code(s3)
{
}

void rgw_err::
clear()
{
  http_ret = 200;
  ret = 0;
  s3_code.clear();
}

bool rgw_err::
is_clear() const
{
  return (http_ret == 200);
}

bool rgw_err::
is_err() const
{
  return !(http_ret >= 200 && http_ret <= 399);
}


req_info::req_info(CephContext *cct, class RGWEnv *e) : env(e) {
  method = env->get("REQUEST_METHOD", "");
  script_uri = env->get("SCRIPT_URI", cct->_conf->rgw_script_uri.c_str());
  request_uri = env->get("REQUEST_URI", cct->_conf->rgw_request_uri.c_str());
  int pos = request_uri.find('?');
  if (pos >= 0) {
    request_params = request_uri.substr(pos + 1);
    request_uri = request_uri.substr(0, pos);
  } else {
    request_params = env->get("QUERY_STRING", "");
  }
  host = env->get("HTTP_HOST", "");

  // strip off any trailing :port from host (added by CrossFTP and maybe others)
  size_t colon_offset = host.find_last_of(':');
  if (colon_offset != string::npos) {
    bool all_digits = true;
    for (unsigned i = colon_offset + 1; i < host.size(); ++i) {
      if (!isdigit(host[i])) {
	all_digits = false;
	break;
      }
    }
    if (all_digits) {
      host.resize(colon_offset);
    }
  }
}

void req_info::rebuild_from(req_info& src)
{
  method = src.method;
  script_uri = src.script_uri;
  if (src.effective_uri.empty()) {
    request_uri = src.request_uri;
  } else {
    request_uri = src.effective_uri;
  }
  effective_uri.clear();
  host = src.host;

  x_meta_map = src.x_meta_map;
  x_meta_map.erase("x-amz-date");
}


req_state::req_state(CephContext *_cct, class RGWEnv *e) : cct(_cct), cio(NULL), op(OP_UNKNOWN),
							   has_acl_header(false),
                                                           os_auth_token(NULL), info(_cct, e)
{
  enable_ops_log = e->conf->enable_ops_log;
  enable_usage_log = e->conf->enable_usage_log;
  defer_to_bucket_acls = e->conf->defer_to_bucket_acls;
  content_started = false;
  format = 0;
  formatter = NULL;
  bucket_acl = NULL;
  object_acl = NULL;
  expect_cont = false;

  header_ended = false;
  obj_size = 0;
  prot_flags = 0;

  system_request = false;

  os_auth_token = NULL;
  time = ceph_clock_now(cct);
  perm_mask = 0;
  content_length = 0;
  bucket_exists = false;
  has_bad_meta = false;
  length = NULL;
  copy_source = NULL;
  http_auth = NULL;
  local_source = false;

  obj_ctx = NULL;
}

req_state::~req_state() {
  delete formatter;
  delete bucket_acl;
  delete object_acl;
}

struct str_len {
  const char *str;
  int len;
};

#define STR_LEN_ENTRY(s) { s, sizeof(s) - 1 }

struct str_len meta_prefixes[] = { STR_LEN_ENTRY("HTTP_X_AMZ"),
                                   STR_LEN_ENTRY("HTTP_X_GOOG"),
                                   STR_LEN_ENTRY("HTTP_X_DHO"),
                                   STR_LEN_ENTRY("HTTP_X_RGW"),
                                   STR_LEN_ENTRY("HTTP_X_OBJECT"),
                                   STR_LEN_ENTRY("HTTP_X_CONTAINER"),
                                   {NULL, 0} };


void req_info::init_meta_info(bool *found_bad_meta)
{
  x_meta_map.clear();

  map<string, string, ltstr_nocase>& m = env->get_map();
  map<string, string, ltstr_nocase>::iterator iter;
  for (iter = m.begin(); iter != m.end(); ++iter) {
    const char *prefix;
    const string& header_name = iter->first;
    const string& val = iter->second;
    for (int prefix_num = 0; (prefix = meta_prefixes[prefix_num].str) != NULL; prefix_num++) {
      int len = meta_prefixes[prefix_num].len;
      const char *p = header_name.c_str();
      if (strncmp(p, prefix, len) == 0) {
        dout(10) << "meta>> " << p << dendl;
        const char *name = p+len; /* skip the prefix */
        int name_len = header_name.size() - len;

        if (found_bad_meta && strncmp(name, "_META_", name_len) == 0)
          *found_bad_meta = true;

        char name_low[meta_prefixes[0].len + name_len + 1];
        snprintf(name_low, meta_prefixes[0].len - 5 + name_len + 1, "%s%s", meta_prefixes[0].str + 5 /* skip HTTP_ */, name); // normalize meta prefix
        int j;
        for (j = 0; name_low[j]; j++) {
          if (name_low[j] != '_')
            name_low[j] = tolower(name_low[j]);
          else
            name_low[j] = '-';
        }
        name_low[j] = 0;

        map<string, string>::iterator iter;
        iter = x_meta_map.find(name_low);
        if (iter != x_meta_map.end()) {
          string old = iter->second;
          int pos = old.find_last_not_of(" \t"); /* get rid of any whitespaces after the value */
          old = old.substr(0, pos + 1);
          old.append(",");
          old.append(val);
          x_meta_map[name_low] = old;
        } else {
          x_meta_map[name_low] = val;
        }
      }
    }
  }
  for (iter = x_meta_map.begin(); iter != x_meta_map.end(); ++iter) {
    dout(10) << "x>> " << iter->first << ":" << iter->second << dendl;
  }
}

std::ostream& operator<<(std::ostream& oss, const rgw_err &err)
{
  oss << "rgw_err(http_ret=" << err.http_ret << ", s3='" << err.s3_code << "') ";
  return oss;
}

string rgw_string_unquote(const string& s)
{
  if (s[0] != '"' || s.size() < 2)
    return s;

  int len;
  for (len = s.size(); len > 2; --len) {
    if (s[len - 1] != ' ')
      break;
  }

  if (s[len-1] != '"')
    return s;

  return s.substr(1, len - 2);
}

static void trim_whitespace(const string& src, string& dst)
{
  const char *spacestr = " \t\n\r\f\v";
  int start = src.find_first_not_of(spacestr);
  if (start < 0)
    return;

  int end = src.find_last_not_of(spacestr);
  dst = src.substr(start, end - start + 1);
}

static bool check_str_end(const char *s)
{
  if (!s)
    return false;

  while (*s) {
    if (!isspace(*s))
      return false;
    s++;
  }
  return true;
}

static bool check_gmt_end(const char *s)
{
  if (!s || !*s)
    return false;

  while (isspace(*s)) {
    ++s;
  }

  /* check for correct timezone */
  if ((strncmp(s, "GMT", 3) != 0) &&
      (strncmp(s, "UTC", 3) != 0)) {
    return false;
  }

  return true;
}

static bool parse_rfc850(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_gmt_end(strptime(s, "%A, %d-%b-%y %H:%M:%S ", t));
}

static bool parse_asctime(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_str_end(strptime(s, "%a %b %d %H:%M:%S %Y", t));
}

static bool parse_rfc1123(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_gmt_end(strptime(s, "%a, %d %b %Y %H:%M:%S ", t));
}

static bool parse_rfc1123_alt(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_str_end(strptime(s, "%a, %d %b %Y %H:%M:%S %z", t));
}

bool parse_rfc2616(const char *s, struct tm *t)
{
  return parse_rfc850(s, t) || parse_asctime(s, t) || parse_rfc1123(s, t) || parse_rfc1123_alt(s,t);
}

bool parse_iso8601(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  const char *p = strptime(s, "%Y-%m-%dT%T", t);
  if (!p) {
    dout(0) << "parse_iso8601 failed" << dendl;
    return false;
  }
  string str;
  trim_whitespace(p, str);
  int len = str.size();

  if (len == 1 && str[0] == 'Z')
    return true;

  if (str[0] != '.' ||
      str[len - 1] != 'Z')
    return false;

  uint32_t ms;
  int r = stringtoul(str.substr(1, len - 2), &ms);
  if (r < 0)
    return false;

  return true;
}

int parse_key_value(string& in_str, const char *delim, string& key, string& val)
{
  if (delim == NULL)
    return -EINVAL;

  int pos = in_str.find(delim);
  if (pos < 0)
    return -EINVAL;

  trim_whitespace(in_str.substr(0, pos), key);
  pos++;

  trim_whitespace(in_str.substr(pos), val);

  return 0;
}

int parse_key_value(string& in_str, string& key, string& val)
{
  return parse_key_value(in_str, "=", key,val);
}

int parse_time(const char *time_str, time_t *time)
{
  struct tm tm;

  if (!parse_rfc2616(time_str, &tm))
    return -EINVAL;

  *time = timegm(&tm);

  return 0;
}

/*
 * calculate the sha1 value of a given msg and key
 */
void calc_hmac_sha1(const char *key, int key_len,
                    const char *msg, int msg_len, char *dest)
/* destination should be CEPH_CRYPTO_HMACSHA1_DIGESTSIZE bytes long */
{
  HMACSHA1 hmac((const unsigned char *)key, key_len);
  hmac.Update((const unsigned char *)msg, msg_len);
  hmac.Final((unsigned char *)dest);
  
  char hex_str[(CEPH_CRYPTO_HMACSHA1_DIGESTSIZE * 2) + 1];
  buf_to_hex((unsigned char *)dest, CEPH_CRYPTO_HMACSHA1_DIGESTSIZE, hex_str);
}

int gen_rand_base64(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  char buf[size];
  char tmp_dest[size + 4]; /* so that there's space for the extra '=' characters, and some */
  int ret;

  ret = get_random_bytes(buf, sizeof(buf));
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  ret = ceph_armor(tmp_dest, &tmp_dest[sizeof(tmp_dest)],
		   (const char *)buf, ((const char *)buf) + ((size - 1) * 3 + 4 - 1) / 4);
  if (ret < 0) {
    lderr(cct) << "ceph_armor failed" << dendl;
    return ret;
  }
  tmp_dest[ret] = '\0';
  memcpy(dest, tmp_dest, size);
  dest[size] = '\0';

  return 0;
}

static const char alphanum_upper_table[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int gen_rand_alphanumeric_upper(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  int ret = get_random_bytes(dest, size);
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_upper_table[pos % (sizeof(alphanum_upper_table) - 1)];
  }
  dest[i] = '\0';

  return 0;
}

static const char alphanum_lower_table[]="0123456789abcdefghijklmnopqrstuvwxyz";

int gen_rand_alphanumeric_lower(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  int ret = get_random_bytes(dest, size);
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_lower_table[pos % (sizeof(alphanum_lower_table) - 1)];
  }
  dest[i] = '\0';

  return 0;
}

int gen_rand_alphanumeric_lower(CephContext *cct, string *str, int length)
{
  char buf[length + 1];
  int ret = gen_rand_alphanumeric_lower(cct, buf, sizeof(buf));
  if (ret < 0) {
    return ret;
  }
  *str = buf;
  return 0;
}

// this is basically a modified base64 charset, url friendly
static const char alphanum_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int gen_rand_alphanumeric(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  int ret = get_random_bytes(dest, size);
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_table[pos & 63];
  }
  dest[i] = '\0';

  return 0;
}

static const char alphanum_no_underscore_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.";

int gen_rand_alphanumeric_no_underscore(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  int ret = get_random_bytes(dest, size);
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_no_underscore_table[pos & 63];
  }
  dest[i] = '\0';

  return 0;
}

static const char alphanum_plain_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

int gen_rand_alphanumeric_plain(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  int ret = get_random_bytes(dest, size);
  if (ret < 0) {
    lderr(cct) << "cannot get random bytes: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_plain_table[pos % (sizeof(alphanum_plain_table) - 1)];
  }
  dest[i] = '\0';

  return 0;
}

int NameVal::parse()
{
  int delim_pos = str.find('=');
  int ret = 0;

  if (delim_pos < 0) {
    name = str;
    val = "";
    ret = 1;
  } else {
    name = str.substr(0, delim_pos);
    val = str.substr(delim_pos + 1);
  }

  return ret; 
}

int RGWHTTPArgs::parse()
{
  int pos = 0;
  bool end = false;
  bool admin_subresource_added = false; 
  if (str[pos] == '?') pos++;

  while (!end) {
    int fpos = str.find('&', pos);
    if (fpos  < pos) {
       end = true;
       fpos = str.size(); 
    }
    string substr, nameval;
    substr = str.substr(pos, fpos - pos);
    url_decode(substr, nameval, true);
    NameVal nv(nameval);
    int ret = nv.parse();
    if (ret >= 0) {
      string& name = nv.get_name();
      string& val = nv.get_val();

      if (name.compare(0, sizeof(RGW_SYS_PARAM_PREFIX) - 1, RGW_SYS_PARAM_PREFIX) == 0) {
        sys_val_map[name] = val;
      } else {
        val_map[name] = val;
      }

      if ((name.compare("acl") == 0) ||
          (name.compare("cors") == 0) ||
          (name.compare("location") == 0) ||
          (name.compare("logging") == 0) ||
          (name.compare("delete") == 0) ||
          (name.compare("uploads") == 0) ||
          (name.compare("partNumber") == 0) ||
          (name.compare("uploadId") == 0) ||
          (name.compare("versionId") == 0) ||
          (name.compare("versions") == 0) ||
          (name.compare("versioning") == 0) ||
          (name.compare("torrent") == 0)) {
        sub_resources[name] = val;
      } else if (name[0] == 'r') { // root of all evil
        if ((name.compare("response-content-type") == 0) ||
           (name.compare("response-content-language") == 0) ||
           (name.compare("response-expires") == 0) ||
           (name.compare("response-cache-control") == 0) ||
           (name.compare("response-content-disposition") == 0) ||
           (name.compare("response-content-encoding") == 0)) {
          sub_resources[name] = val;
          has_resp_modifier = true;
        }
      } else if  ((name.compare("subuser") == 0) ||
          (name.compare("key") == 0) ||
          (name.compare("caps") == 0) ||
          (name.compare("index") == 0) ||
          (name.compare("policy") == 0) ||
          (name.compare("quota") == 0) ||
          (name.compare("object") == 0)) {

        if (!admin_subresource_added) {
          sub_resources[name] = "";
          admin_subresource_added = true;
        }
      }
    }

    pos = fpos + 1;  
  }

  return 0;
}

string& RGWHTTPArgs::get(const string& name, bool *exists)
{
  map<string, string>::iterator iter;
  iter = val_map.find(name);
  bool e = (iter != val_map.end());
  if (exists)
    *exists = e;
  if (e)
    return iter->second;
  return empty_str;
}

string& RGWHTTPArgs::get(const char *name, bool *exists)
{
  string s(name);
  return get(s, exists);
}


int RGWHTTPArgs::get_bool(const string& name, bool *val, bool *exists)
{
  map<string, string>::iterator iter;
  iter = val_map.find(name);
  bool e = (iter != val_map.end());
  if (exists)
    *exists = e;

  if (e) {
    const char *s = iter->second.c_str();

    if (strcasecmp(s, "false") == 0) {
      *val = false;
    } else if (strcasecmp(s, "true") == 0) {
      *val = true;
    } else {
      return -EINVAL;
    }
  }

  return 0;
}

int RGWHTTPArgs::get_bool(const char *name, bool *val, bool *exists)
{
  string s(name);
  return get_bool(s, val, exists);
}

void RGWHTTPArgs::get_bool(const char *name, bool *val, bool def_val)
{
  bool exists = false;
  if ((get_bool(name, val, &exists) < 0) ||
      !exists) {
    *val = def_val;
  }
}

bool verify_bucket_permission(struct req_state *s, int perm)
{
  if (!s->bucket_acl)
    return false;

  if ((perm & (int)s->perm_mask) != perm)
    return false;

  return s->bucket_acl->verify_permission(s->user.user_id, perm, perm);
}

static inline bool check_deferred_bucket_acl(struct req_state *s, uint8_t deferred_check, int perm)
{
  return (s->defer_to_bucket_acls == deferred_check && verify_bucket_permission(s, perm));
}

bool verify_object_permission(struct req_state *s, RGWAccessControlPolicy *bucket_acl, RGWAccessControlPolicy *object_acl, int perm)
{
  if (check_deferred_bucket_acl(s, RGW_DEFER_TO_BUCKET_ACLS_RECURSE, perm) ||
      check_deferred_bucket_acl(s, RGW_DEFER_TO_BUCKET_ACLS_FULL_CONTROL, RGW_PERM_FULL_CONTROL)) {
    return true;
  }

  if (!object_acl)
    return false;

  bool ret = object_acl->verify_permission(s->user.user_id, s->perm_mask, perm);
  if (ret)
    return true;

  if (!s->cct->_conf->rgw_enforce_swift_acls)
    return ret;

  if ((perm & (int)s->perm_mask) != perm)
    return false;

  int swift_perm = 0;
  if (perm & (RGW_PERM_READ | RGW_PERM_READ_ACP))
    swift_perm |= RGW_PERM_READ_OBJS;
  if (perm & RGW_PERM_WRITE)
    swift_perm |= RGW_PERM_WRITE_OBJS;

  if (!swift_perm)
    return false;
  /* we already verified the user mask above, so we pass swift_perm as the mask here,
     otherwise the mask might not cover the swift permissions bits */
  return bucket_acl->verify_permission(s->user.user_id, swift_perm, swift_perm);
}

bool verify_object_permission(struct req_state *s, int perm)
{
  return verify_object_permission(s, s->bucket_acl, s->object_acl, perm);
}

class HexTable
{
  char table[256];

public:
  HexTable() {
    memset(table, -1, sizeof(table));
    int i;
    for (i = '0'; i<='9'; i++)
      table[i] = i - '0';
    for (i = 'A'; i<='F'; i++)
      table[i] = i - 'A' + 0xa;
    for (i = 'a'; i<='f'; i++)
      table[i] = i - 'a' + 0xa;
  }

  char to_num(char c) {
    return table[(int)c];
  }
};

static char hex_to_num(char c)
{
  static HexTable hex_table;
  return hex_table.to_num(c);
}

bool url_decode(string& src_str, string& dest_str, bool in_query)
{
  const char *src = src_str.c_str();
  char dest[src_str.size() + 1];
  int pos = 0;
  char c;

  while (*src) {
    if (*src != '%') {
      if (!in_query || *src != '+') {
        if (*src == '?') in_query = true;
        dest[pos++] = *src++;
      } else {
        dest[pos++] = ' ';
        ++src;
      }
    } else {
      src++;
      if (!*src)
        break;
      char c1 = hex_to_num(*src++);
      if (!*src)
        break;
      c = c1 << 4;
      if (c1 < 0)
        return false;
      c1 = hex_to_num(*src++);
      if (c1 < 0)
        return false;
      c |= c1;
      dest[pos++] = c;
    }
  }
  dest[pos] = 0;
  dest_str = dest;

  return true;
}

static void escape_char(char c, string& dst)
{
  char buf[16];
  snprintf(buf, sizeof(buf), "%%%.2X", (int)(unsigned char)c);
  dst.append(buf);
}

static bool char_needs_url_encoding(char c)
{
  if (c <= 0x20 || c >= 0x7f)
    return true;

  switch (c) {
    case 0x22:
    case 0x23:
    case 0x25:
    case 0x26:
    case 0x2B:
    case 0x2C:
    case 0x2F:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3E:
    case 0x3D:
    case 0x3F:
    case 0x40:
    case 0x5B:
    case 0x5D:
    case 0x5C:
    case 0x5E:
    case 0x60:
    case 0x7B:
    case 0x7D:
      return true;
  }
  return false;
}

void url_encode(const string& src, string& dst)
{
  const char *p = src.c_str();
  for (unsigned i = 0; i < src.size(); i++, p++) {
    if (char_needs_url_encoding(*p)) {
      escape_char(*p, dst);
      continue;
    }

    dst.append(p, 1);
  }
}

string rgw_trim_whitespace(const string& src)
{
  if (src.empty()) {
    return string();
  }

  int start = 0;
  for (; start != (int)src.size(); start++) {
    if (!isspace(src[start]))
      break;
  }

  int end = src.size() - 1;
  if (end < start) {
    return string();
  }

  for (; end > start; end--) {
    if (!isspace(src[end]))
      break;
  }

  return src.substr(start, end - start + 1);
}

string rgw_trim_quotes(const string& val)
{
  string s = rgw_trim_whitespace(val);
  if (s.size() < 2)
    return s;

  int start = 0;
  int end = s.size() - 1;
  int quotes_count = 0;

  if (s[start] == '"') {
    start++;
    quotes_count++;
  }
  if (s[end] == '"') {
    end--;
    quotes_count++;
  }
  if (quotes_count == 2) {
    return s.substr(start, end - start + 1);
  }
  return s;
}

struct rgw_name_to_flag {
  const char *type_name;
  uint32_t flag;
};

static int parse_list_of_flags(struct rgw_name_to_flag *mapping,
                               const string& str, uint32_t *perm)
{
  list<string> strs;
  get_str_list(str, strs);
  list<string>::iterator iter;
  uint32_t v = 0;
  for (iter = strs.begin(); iter != strs.end(); ++iter) {
    string& s = *iter;
    for (int i = 0; mapping[i].type_name; i++) {
      if (s.compare(mapping[i].type_name) == 0)
        v |= mapping[i].flag;
    }
  }

  *perm = v;
  return 0;
}

static struct rgw_name_to_flag cap_names[] = { {"*",     RGW_CAP_ALL},
                  {"read",  RGW_CAP_READ},
		  {"write", RGW_CAP_WRITE},
		  {NULL, 0} };

int RGWUserCaps::parse_cap_perm(const string& str, uint32_t *perm)
{
  return parse_list_of_flags(cap_names, str, perm);
}

int RGWUserCaps::get_cap(const string& cap, string& type, uint32_t *pperm)
{
  int pos = cap.find('=');
  if (pos >= 0) {
    trim_whitespace(cap.substr(0, pos), type);
  }

  if (type.size() == 0)
    return -EINVAL;

  string cap_perm;
  uint32_t perm = 0;
  if (pos < (int)cap.size() - 1) {
    cap_perm = cap.substr(pos + 1);
    int r = RGWUserCaps::parse_cap_perm(cap_perm, &perm);
    if (r < 0)
      return r;
  }

  *pperm = perm;

  return 0;
}

int RGWUserCaps::add_cap(const string& cap)
{
  uint32_t perm;
  string type;

  int r = get_cap(cap, type, &perm);
  if (r < 0)
    return r;

  caps[type] |= perm;

  return 0;
}

int RGWUserCaps::remove_cap(const string& cap)
{
  uint32_t perm;
  string type;

  int r = get_cap(cap, type, &perm);
  if (r < 0)
    return r;

  map<string, uint32_t>::iterator iter = caps.find(type);
  if (iter == caps.end())
    return 0;

  uint32_t& old_perm = iter->second;
  old_perm &= ~perm;
  if (!old_perm)
    caps.erase(iter);

  return 0;
}

int RGWUserCaps::add_from_string(const string& str)
{
  int start = 0;
  do {
    int end = str.find(';', start);
    if (end < 0)
      end = str.size();

    int r = add_cap(str.substr(start, end - start));
    if (r < 0)
      return r;

    start = end + 1;
  } while (start < (int)str.size());

  return 0;
}

int RGWUserCaps::remove_from_string(const string& str)
{
  int start = 0;
  do {
    int end = str.find(';', start);
    if (end < 0)
      end = str.size();

    int r = remove_cap(str.substr(start, end - start));
    if (r < 0)
      return r;

    start = end + 1;
  } while (start < (int)str.size());

  return 0;
}

void RGWUserCaps::dump(Formatter *f) const
{
  dump(f, "caps");
}

void RGWUserCaps::dump(Formatter *f, const char *name) const
{
  f->open_array_section(name);
  map<string, uint32_t>::const_iterator iter;
  for (iter = caps.begin(); iter != caps.end(); ++iter)
  {
    f->open_object_section("cap");
    f->dump_string("type", iter->first);
    uint32_t perm = iter->second;
    string perm_str;
    for (int i=0; cap_names[i].type_name; i++) {
      if ((perm & cap_names[i].flag) == cap_names[i].flag) {
	if (perm_str.size())
	  perm_str.append(", ");

	perm_str.append(cap_names[i].type_name);
	perm &= ~cap_names[i].flag;
      }
    }
    if (perm_str.empty())
      perm_str = "<none>";

    f->dump_string("perm", perm_str);
    f->close_section();
  }

  f->close_section();
}

struct RGWUserCap {
  string type;
  uint32_t perm;

  void decode_json(JSONObj *obj) {
    JSONDecoder::decode_json("type", type, obj);
    string perm_str;
    JSONDecoder::decode_json("perm", perm_str, obj);
    if (RGWUserCaps::parse_cap_perm(perm_str, &perm) < 0) {
      throw JSONDecoder::err("failed to parse permissions");
    }
  }
};

void RGWUserCaps::decode_json(JSONObj *obj)
{
  list<RGWUserCap> caps_list;
  decode_json_obj(caps_list, obj);

  list<RGWUserCap>::iterator iter;
  for (iter = caps_list.begin(); iter != caps_list.end(); ++iter) {
    RGWUserCap& cap = *iter;
    caps[cap.type] = cap.perm;
  }
}

int RGWUserCaps::check_cap(const string& cap, uint32_t perm)
{
  map<string, uint32_t>::iterator iter = caps.find(cap);

  if ((iter == caps.end()) ||
      (iter->second & perm) != perm) {
    return -EPERM;
  }

  return 0;
}


static struct rgw_name_to_flag op_type_mapping[] = { {"*",  RGW_OP_TYPE_ALL},
                  {"read",  RGW_OP_TYPE_READ},
		  {"write", RGW_OP_TYPE_WRITE},
		  {"delete", RGW_OP_TYPE_DELETE},
		  {NULL, 0} };


int rgw_parse_op_type_list(const string& str, uint32_t *perm)
{
  return parse_list_of_flags(op_type_mapping, str, perm);
}

