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

#include "common/ceph_json.h"
#include "common/strtol.h"
#include "rgw_rest.h"
#include "rgw_op.h"
#include "rgw_rest_s3.h"
#include "rgw_rest_log.h"
#include "rgw_client_io.h"
#include "rgw_sync.h"
#include "rgw_data_sync.h"
#include "rgw_common.h"
#include "rgw_zone.h"
#include "rgw_mdlog.h"

#include "services/svc_zone.h"
#include "services/svc_mdlog.h"
#include "services/svc_bilog_rados.h"

#include "common/errno.h"
#include "include/ceph_assert.h"

#define dout_context g_ceph_context
#define LOG_CLASS_LIST_MAX_ENTRIES (1000)
#define dout_subsys ceph_subsys_rgw

void RGWOp_MDLog_List::execute(optional_yield y) {
  string   period = s->info.args.get("period");
  string   shard = s->info.args.get("id");
  string   max_entries_str = s->info.args.get("max-entries");
  string   marker = s->info.args.get("marker"),
           err;
  unsigned shard_id, max_entries = LOG_CLASS_LIST_MAX_ENTRIES;

  if (s->info.args.exists("start-time") ||
      s->info.args.exists("end-time")) {
    dout(5) << "start-time and end-time are no longer accepted" << dendl;
    op_ret = -EINVAL;
    return;
  }

  shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (!max_entries_str.empty()) {
    max_entries = (unsigned)strict_strtol(max_entries_str.c_str(), 10, &err);
    if (!err.empty()) {
      dout(5) << "Error parsing max-entries " << max_entries_str << dendl;
      op_ret = -EINVAL;
      return;
    }
    if (max_entries > LOG_CLASS_LIST_MAX_ENTRIES) {
      max_entries = LOG_CLASS_LIST_MAX_ENTRIES;
    }
  }

  if (period.empty()) {
    ldout(s->cct, 5) << "Missing period id trying to use current" << dendl;
    period = store->svc()->zone->get_current_period_id();
    if (period.empty()) {
      ldout(s->cct, 5) << "Missing period id" << dendl;
      op_ret = -EINVAL;
      return;
    }
  }

  RGWMetadataLog meta_log{s->cct, store->svc()->zone, store->svc()->cls, period};

  op_ret = meta_log.list_entries(shard_id, max_entries, marker, entries,
                                   &last_marker, &truncated);
}

void RGWOp_MDLog_List::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret < 0)
    return;

  s->formatter->open_object_section("log_entries");
  s->formatter->dump_string("marker", last_marker);
  s->formatter->dump_bool("truncated", truncated);
  {
    s->formatter->open_array_section("entries");
    for (const auto& entry : entries) {
      store->ctl()->meta.mgr->dump_log_entry(entry, s->formatter);
      flusher.flush();
    }
    s->formatter->close_section();
  }
  s->formatter->close_section();
  flusher.flush();
}

void RGWOp_MDLog_Info::execute(optional_yield y) {
  num_objects = s->cct->_conf->rgw_md_log_max_shards;
  period = store->svc()->mdlog->read_oldest_log_period(y);
  op_ret = period.get_error();
}

void RGWOp_MDLog_Info::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  s->formatter->open_object_section("mdlog");
  s->formatter->dump_unsigned("num_objects", num_objects);
  if (period) {
    s->formatter->dump_string("period", period.get_period().get_id());
    s->formatter->dump_unsigned("realm_epoch", period.get_epoch());
  }
  s->formatter->close_section();
  flusher.flush();
}

void RGWOp_MDLog_ShardInfo::execute(optional_yield y) {
  string period = s->info.args.get("period");
  string shard = s->info.args.get("id");
  string err;

  unsigned shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (period.empty()) {
    ldout(s->cct, 5) << "Missing period id trying to use current" << dendl;
    period = store->svc()->zone->get_current_period_id();

    if (period.empty()) {
      ldout(s->cct, 5) << "Missing period id" << dendl;
      op_ret = -EINVAL;
      return;
    }
  }
  RGWMetadataLog meta_log{s->cct, store->svc()->zone, store->svc()->cls, period};

  op_ret = meta_log.get_info(shard_id, &info);
}

void RGWOp_MDLog_ShardInfo::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  encode_json("info", info, s->formatter);
  flusher.flush();
}

void RGWOp_MDLog_Delete::execute(optional_yield y) {
  string   marker = s->info.args.get("marker"),
           period = s->info.args.get("period"),
           shard = s->info.args.get("id"),
           err;
  unsigned shard_id;


  if (s->info.args.exists("start-time") ||
      s->info.args.exists("end-time")) {
    dout(5) << "start-time and end-time are no longer accepted" << dendl;
    op_ret = -EINVAL;
  }

  if (s->info.args.exists("start-marker")) {
    dout(5) << "start-marker is no longer accepted" << dendl;
    op_ret = -EINVAL;
  }

  if (s->info.args.exists("end-marker")) {
    if (!s->info.args.exists("marker")) {
      marker = s->info.args.get("end-marker");
    } else {
      dout(5) << "end-marker and marker cannot both be provided" << dendl;
      op_ret = -EINVAL;
    }
  }

  op_ret = 0;

  shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (marker.empty()) { /* bounding end */
    op_ret = -EINVAL;
    return;
  }

  if (period.empty()) {
    ldout(s->cct, 5) << "Missing period id trying to use current" << dendl;
    period = store->svc()->zone->get_current_period_id();

    if (period.empty()) {
      ldout(s->cct, 5) << "Missing period id" << dendl;
      op_ret = -EINVAL;
      return;
    }
  }
  RGWMetadataLog meta_log{s->cct, store->svc()->zone, store->svc()->cls, period};

  op_ret = meta_log.trim(shard_id, marker);
}

void RGWOp_MDLog_Lock::execute(optional_yield y) {
  string period, shard_id_str, duration_str, locker_id, zone_id;
  unsigned shard_id;

  op_ret = 0;

  period       = s->info.args.get("period");
  shard_id_str = s->info.args.get("id");
  duration_str = s->info.args.get("length");
  locker_id    = s->info.args.get("locker-id");
  zone_id      = s->info.args.get("zone-id");

  if (period.empty()) {
    ldout(s->cct, 5) << "Missing period id trying to use current" << dendl;
    period = store->svc()->zone->get_current_period_id();
  }

  if (period.empty() ||
      shard_id_str.empty() ||
      (duration_str.empty()) ||
      locker_id.empty() ||
      zone_id.empty()) {
    dout(5) << "Error invalid parameter list" << dendl;
    op_ret = -EINVAL;
    return;
  }

  string err;
  shard_id = (unsigned)strict_strtol(shard_id_str.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id param " << shard_id_str << dendl;
    op_ret = -EINVAL;
    return;
  }

  RGWMetadataLog meta_log{s->cct, store->svc()->zone, store->svc()->cls, period};
  unsigned dur;
  dur = (unsigned)strict_strtol(duration_str.c_str(), 10, &err);
  if (!err.empty() || dur <= 0) {
    dout(5) << "invalid length param " << duration_str << dendl;
    op_ret = -EINVAL;
    return;
  }
  op_ret = meta_log.lock_exclusive(shard_id, make_timespan(dur), zone_id,
				     locker_id);
  if (op_ret == -EBUSY)
    op_ret = -ERR_LOCKED;
}

void RGWOp_MDLog_Unlock::execute(optional_yield y) {
  string period, shard_id_str, locker_id, zone_id;
  unsigned shard_id;

  op_ret = 0;

  period       = s->info.args.get("period");
  shard_id_str = s->info.args.get("id");
  locker_id    = s->info.args.get("locker-id");
  zone_id      = s->info.args.get("zone-id");

  if (period.empty()) {
    ldout(s->cct, 5) << "Missing period id trying to use current" << dendl;
    period = store->svc()->zone->get_current_period_id();
  }

  if (period.empty() ||
      shard_id_str.empty() ||
      locker_id.empty() ||
      zone_id.empty()) {
    dout(5) << "Error invalid parameter list" << dendl;
    op_ret = -EINVAL;
    return;
  }

  string err;
  shard_id = (unsigned)strict_strtol(shard_id_str.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id param " << shard_id_str << dendl;
    op_ret = -EINVAL;
    return;
  }

  RGWMetadataLog meta_log{s->cct, store->svc()->zone, store->svc()->cls, period};
  op_ret = meta_log.unlock(shard_id, zone_id, locker_id);
}

void RGWOp_MDLog_Notify::execute(optional_yield y) {
#define LARGE_ENOUGH_BUF (128 * 1024)

  int r = 0;
  bufferlist data;
  std::tie(r, data) = rgw_rest_read_all_input(s, LARGE_ENOUGH_BUF);
  if (r < 0) {
    op_ret = r;
    return;
  }

  char* buf = data.c_str();
  ldout(s->cct, 20) << __func__ << "(): read data: " << buf << dendl;

  JSONParser p;
  r = p.parse(buf, data.length());
  if (r < 0) {
    ldout(s->cct, 0) << "ERROR: failed to parse JSON" << dendl;
    op_ret = r;
    return;
  }

  set<int> updated_shards;
  try {
    decode_json_obj(updated_shards, &p);
  } catch (JSONDecoder::err& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode JSON" << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (store->ctx()->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
    for (set<int>::iterator iter = updated_shards.begin(); iter != updated_shards.end(); ++iter) {
      ldout(s->cct, 20) << __func__ << "(): updated shard=" << *iter << dendl;
    }
  }

  store->getRados()->wakeup_meta_sync_shards(updated_shards);

  op_ret = 0;
}

void RGWOp_BILog_List::execute(optional_yield y) {
  string tenant_name = s->info.args.get("tenant"),
         bucket_name = s->info.args.get("bucket"),
         marker = s->info.args.get("marker"),
         max_entries_str = s->info.args.get("max-entries"),
         bucket_instance = s->info.args.get("bucket-instance");
  RGWBucketInfo bucket_info;
  unsigned max_entries;

  if (bucket_name.empty() && bucket_instance.empty()) {
    dout(5) << "ERROR: neither bucket nor bucket instance specified" << dendl;
    op_ret = -EINVAL;
    return;
  }

  int shard_id;
  string bn;
  op_ret = rgw_bucket_parse_bucket_instance(bucket_instance, &bn, &bucket_instance, &shard_id);
  if (op_ret < 0) {
    return;
  }

  if (!bucket_instance.empty()) {
    rgw_bucket b(rgw_bucket_key(tenant_name, bn, bucket_instance));
    op_ret = store->getRados()->get_bucket_instance_info(*s->sysobj_ctx, b, bucket_info, NULL, NULL, s->yield);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket instance info for bucket instance id=" << bucket_instance << dendl;
      return;
    }
  } else { /* !bucket_name.empty() */
    op_ret = store->getRados()->get_bucket_info(store->svc(), tenant_name, bucket_name, bucket_info, NULL, s->yield, NULL);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket info for bucket=" << bucket_name << dendl;
      return;
    }
  }

  bool truncated;
  unsigned count = 0;
  string err;

  max_entries = (unsigned)strict_strtol(max_entries_str.c_str(), 10, &err);
  if (!err.empty())
    max_entries = LOG_CLASS_LIST_MAX_ENTRIES;

  send_response();
  do {
    list<rgw_bi_log_entry> entries;
    int ret = store->svc()->bilog_rados->log_list(bucket_info, shard_id,
                                               marker, max_entries - count, 
                                               entries, &truncated);
    if (ret < 0) {
      ldpp_dout(s, 5) << "ERROR: list_bi_log_entries()" << dendl;
      return;
    }

    count += entries.size();

    send_response(entries, marker);
  } while (truncated && count < max_entries);

  send_response_end();
}

void RGWOp_BILog_List::send_response() {
  if (sent_header)
    return;

  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  sent_header = true;

  if (op_ret < 0)
    return;

  s->formatter->open_array_section("entries");
}

void RGWOp_BILog_List::send_response(list<rgw_bi_log_entry>& entries, string& marker)
{
  for (list<rgw_bi_log_entry>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
    rgw_bi_log_entry& entry = *iter;
    encode_json("entry", entry, s->formatter);

    marker = entry.id;
    flusher.flush();
  }
}

void RGWOp_BILog_List::send_response_end() {
  s->formatter->close_section();
  flusher.flush();
}
      
void RGWOp_BILog_Info::execute(optional_yield y) {
  string tenant_name = s->info.args.get("tenant"),
         bucket_name = s->info.args.get("bucket"),
         bucket_instance = s->info.args.get("bucket-instance");
  RGWBucketInfo bucket_info;

  if (bucket_name.empty() && bucket_instance.empty()) {
    ldpp_dout(s, 5) << "ERROR: neither bucket nor bucket instance specified" << dendl;
    op_ret = -EINVAL;
    return;
  }

  int shard_id;
  string bn;
  op_ret = rgw_bucket_parse_bucket_instance(bucket_instance, &bn, &bucket_instance, &shard_id);
  if (op_ret < 0) {
    return;
  }

  if (!bucket_instance.empty()) {
    rgw_bucket b(rgw_bucket_key(tenant_name, bn, bucket_instance));
    op_ret = store->getRados()->get_bucket_instance_info(*s->sysobj_ctx, b, bucket_info, NULL, NULL, s->yield);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket instance info for bucket instance id=" << bucket_instance << dendl;
      return;
    }
  } else { /* !bucket_name.empty() */
    op_ret = store->getRados()->get_bucket_info(store->svc(), tenant_name, bucket_name, bucket_info, NULL, s->yield, NULL);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket info for bucket=" << bucket_name << dendl;
      return;
    }
  }
  map<RGWObjCategory, RGWStorageStats> stats;
  int ret =  store->getRados()->get_bucket_stats(bucket_info, shard_id, &bucket_ver, &master_ver, stats, &max_marker, &syncstopped);
  if (ret < 0 && ret != -ENOENT) {
    op_ret = ret;
    return;
  }
}

void RGWOp_BILog_Info::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret < 0)
    return;

  s->formatter->open_object_section("info");
  encode_json("bucket_ver", bucket_ver, s->formatter);
  encode_json("master_ver", master_ver, s->formatter);
  encode_json("max_marker", max_marker, s->formatter);
  encode_json("syncstopped", syncstopped, s->formatter);
  s->formatter->close_section();

  flusher.flush();
}

void RGWOp_BILog_Delete::execute(optional_yield y) {
  string tenant_name = s->info.args.get("tenant"),
         bucket_name = s->info.args.get("bucket"),
         start_marker = s->info.args.get("start-marker"),
         end_marker = s->info.args.get("end-marker"),
         bucket_instance = s->info.args.get("bucket-instance");

  RGWBucketInfo bucket_info;

  op_ret = 0;
  if ((bucket_name.empty() && bucket_instance.empty()) ||
      end_marker.empty()) {
    ldpp_dout(s, 5) << "ERROR: one of bucket and bucket instance, and also end-marker is mandatory" << dendl;
    op_ret = -EINVAL;
    return;
  }

  int shard_id;
  string bn;
  op_ret = rgw_bucket_parse_bucket_instance(bucket_instance, &bn, &bucket_instance, &shard_id);
  if (op_ret < 0) {
    return;
  }

  if (!bucket_instance.empty()) {
    rgw_bucket b(rgw_bucket_key(tenant_name, bn, bucket_instance));
    op_ret = store->getRados()->get_bucket_instance_info(*s->sysobj_ctx, b, bucket_info, NULL, NULL, s->yield);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket instance info for bucket instance id=" << bucket_instance << dendl;
      return;
    }
  } else { /* !bucket_name.empty() */
    op_ret = store->getRados()->get_bucket_info(store->svc(), tenant_name, bucket_name, bucket_info, NULL, s->yield, NULL);
    if (op_ret < 0) {
      ldpp_dout(s, 5) << "could not get bucket info for bucket=" << bucket_name << dendl;
      return;
    }
  }
  op_ret = store->svc()->bilog_rados->log_trim(bucket_info, shard_id, start_marker, end_marker);
  if (op_ret < 0) {
    ldpp_dout(s, 5) << "ERROR: trim_bi_log_entries() " << dendl;
  }
  return;
}

void RGWOp_DATALog_List::execute(optional_yield y) {
  string   shard = s->info.args.get("id");

  string   max_entries_str = s->info.args.get("max-entries"),
           marker = s->info.args.get("marker"),
           err;
  unsigned shard_id, max_entries = LOG_CLASS_LIST_MAX_ENTRIES;

  if (s->info.args.exists("start-time") ||
      s->info.args.exists("end-time")) {
    dout(5) << "start-time and end-time are no longer accepted" << dendl;
    op_ret = -EINVAL;
  }

  s->info.args.get_bool("extra-info", &extra_info, false);

  shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (!max_entries_str.empty()) {
    max_entries = (unsigned)strict_strtol(max_entries_str.c_str(), 10, &err);
    if (!err.empty()) {
      dout(5) << "Error parsing max-entries " << max_entries_str << dendl;
      op_ret = -EINVAL;
      return;
    }
    if (max_entries > LOG_CLASS_LIST_MAX_ENTRIES) {
      max_entries = LOG_CLASS_LIST_MAX_ENTRIES;
    }
  }

  // Note that last_marker is updated to be the marker of the last
  // entry listed
  op_ret = store->svc()->datalog_rados->list_entries(shard_id,
						     max_entries, entries,
						     marker, &last_marker,
						     &truncated);
}

void RGWOp_DATALog_List::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret < 0)
    return;

  s->formatter->open_object_section("log_entries");
  s->formatter->dump_string("marker", last_marker);
  s->formatter->dump_bool("truncated", truncated);
  {
    s->formatter->open_array_section("entries");
    for (const auto& entry : entries) {
      if (!extra_info) {
        encode_json("entry", entry.entry, s->formatter);
      } else {
        encode_json("entry", entry, s->formatter);
      }
      flusher.flush();
    }
    s->formatter->close_section();
  }
  s->formatter->close_section();
  flusher.flush();
}


void RGWOp_DATALog_Info::execute(optional_yield y) {
  num_objects = s->cct->_conf->rgw_data_log_num_shards;
  op_ret = 0;
}

void RGWOp_DATALog_Info::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  s->formatter->open_object_section("num_objects");
  s->formatter->dump_unsigned("num_objects", num_objects);
  s->formatter->close_section();
  flusher.flush();
}

void RGWOp_DATALog_ShardInfo::execute(optional_yield y) {
  string shard = s->info.args.get("id");
  string err;

  unsigned shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }

  op_ret = store->svc()->datalog_rados->get_info(shard_id, &info);
}

void RGWOp_DATALog_ShardInfo::send_response() {
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  encode_json("info", info, s->formatter);
  flusher.flush();
}

void RGWOp_DATALog_Notify::execute(optional_yield y) {
  string  source_zone = s->info.args.get("source-zone");
#define LARGE_ENOUGH_BUF (128 * 1024)

  int r = 0;
  bufferlist data;
  std::tie(r, data) = rgw_rest_read_all_input(s, LARGE_ENOUGH_BUF);
  if (r < 0) {
    op_ret = r;
    return;
  }

  char* buf = data.c_str();
  ldout(s->cct, 20) << __func__ << "(): read data: " << buf << dendl;

  JSONParser p;
  r = p.parse(buf, data.length());
  if (r < 0) {
    ldout(s->cct, 0) << "ERROR: failed to parse JSON" << dendl;
    op_ret = r;
    return;
  }

  map<int, set<string> > updated_shards;
  try {
    decode_json_obj(updated_shards, &p);
  } catch (JSONDecoder::err& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode JSON" << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (store->ctx()->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
    for (map<int, set<string> >::iterator iter = updated_shards.begin(); iter != updated_shards.end(); ++iter) {
      ldout(s->cct, 20) << __func__ << "(): updated shard=" << iter->first << dendl;
      set<string>& keys = iter->second;
      for (set<string>::iterator kiter = keys.begin(); kiter != keys.end(); ++kiter) {
      ldout(s->cct, 20) << __func__ << "(): modified key=" << *kiter << dendl;
      }
    }
  }

  store->getRados()->wakeup_data_sync_shards(source_zone, updated_shards);

  op_ret = 0;
}

void RGWOp_DATALog_Delete::execute(optional_yield y) {
  string   marker = s->info.args.get("marker"),
           shard = s->info.args.get("id"),
           err;
  unsigned shard_id;

  op_ret = 0;

  if (s->info.args.exists("start-time") ||
      s->info.args.exists("end-time")) {
    dout(5) << "start-time and end-time are no longer accepted" << dendl;
    op_ret = -EINVAL;
  }

  if (s->info.args.exists("start-marker")) {
    dout(5) << "start-marker is no longer accepted" << dendl;
    op_ret = -EINVAL;
  }

  if (s->info.args.exists("end-marker")) {
    if (!s->info.args.exists("marker")) {
      marker = s->info.args.get("end-marker");
    } else {
      dout(5) << "end-marker and marker cannot both be provided" << dendl;
      op_ret = -EINVAL;
    }
  }

  shard_id = (unsigned)strict_strtol(shard.c_str(), 10, &err);
  if (!err.empty()) {
    dout(5) << "Error parsing shard_id " << shard << dendl;
    op_ret = -EINVAL;
    return;
  }
  if (marker.empty()) { /* bounding end */
    op_ret = -EINVAL;
    return;
  }

  op_ret = store->svc()->datalog_rados->trim_entries(shard_id, marker);
}

// not in header to avoid pulling in rgw_sync.h
class RGWOp_MDLog_Status : public RGWRESTOp {
  rgw_meta_sync_status status;
public:
  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("mdlog", RGW_CAP_READ);
  }
  int verify_permission(optional_yield) override {
    return check_caps(s->user->get_caps());
  }
  void execute(optional_yield y) override;
  void send_response() override;
  const char* name() const override { return "get_metadata_log_status"; }
};

void RGWOp_MDLog_Status::execute(optional_yield y)
{
  auto sync = store->getRados()->get_meta_sync_manager();
  if (sync == nullptr) {
    ldout(s->cct, 1) << "no sync manager" << dendl;
    op_ret = -ENOENT;
    return;
  }
  op_ret = sync->read_sync_status(&status);
}

void RGWOp_MDLog_Status::send_response()
{
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret >= 0) {
    encode_json("status", status, s->formatter);
  }
  flusher.flush();
}

// not in header to avoid pulling in rgw_data_sync.h
class RGWOp_BILog_Status : public RGWRESTOp {
  std::vector<rgw_bucket_shard_sync_info> status;
public:
  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("bilog", RGW_CAP_READ);
  }
  int verify_permission(optional_yield y) override {
    return check_caps(s->user->get_caps());
  }
  void execute(optional_yield y) override;
  void send_response() override;
  const char* name() const override { return "get_bucket_index_log_status"; }
};

void RGWOp_BILog_Status::execute(optional_yield y)
{
  const auto options = s->info.args.get("options");
  bool merge = (options == "merge");
  const auto source_zone = s->info.args.get("source-zone");
  const auto source_key = s->info.args.get("source-bucket");
  auto key = s->info.args.get("bucket");
  if (key.empty()) {
    key = source_key;
  }
  if (key.empty()) {
    ldpp_dout(s, 4) << "no 'bucket' provided" << dendl;
    op_ret = -EINVAL;
    return;
  }

  rgw_bucket bucket;
  int shard_id{-1}; // unused
  op_ret = rgw_bucket_parse_bucket_key(s->cct, key, &bucket, &shard_id);
  if (op_ret < 0) {
    ldpp_dout(s, 4) << "invalid 'bucket' provided" << dendl;
    op_ret = -EINVAL;
    return;
  }

  // read the bucket instance info for num_shards
  auto ctx = store->svc()->sysobj->init_obj_ctx();
  RGWBucketInfo info;
  op_ret = store->getRados()->get_bucket_instance_info(ctx, bucket, info, nullptr, nullptr, s->yield);
  if (op_ret < 0) {
    ldpp_dout(s, 4) << "failed to read bucket info: " << cpp_strerror(op_ret) << dendl;
    return;
  }

  rgw_bucket source_bucket;

  if (source_key.empty() ||
      source_key == key) {
    source_bucket = info.bucket;
  } else {
    op_ret = rgw_bucket_parse_bucket_key(s->cct, source_key, &source_bucket, nullptr);
    if (op_ret < 0) {
      ldpp_dout(s, 4) << "invalid 'source-bucket' provided (key=" << source_key << ")" << dendl;
      return;
    }
  }

  const auto& local_zone_id = store->svc()->zone->zone_id();

  if (!merge) {
    rgw_sync_bucket_pipe pipe;
    pipe.source.zone = source_zone;
    pipe.source.bucket = source_bucket;
    pipe.dest.zone = local_zone_id;
    pipe.dest.bucket = info.bucket;

    ldout(s->cct, 20) << "RGWOp_BILog_Status::execute(optional_yield y): getting sync status for pipe=" << pipe << dendl;

    op_ret = rgw_bucket_sync_status(this, store, pipe, info, nullptr, &status);

    if (op_ret < 0) {
      lderr(s->cct) << "ERROR: rgw_bucket_sync_status() on pipe=" << pipe << " returned ret=" << op_ret << dendl;
    }
    return;
  }

  rgw_zone_id source_zone_id(source_zone);

  RGWBucketSyncPolicyHandlerRef source_handler;
  op_ret = store->ctl()->bucket->get_sync_policy_handler(source_zone_id, source_bucket, &source_handler, y);
  if (op_ret < 0) {
    lderr(s->cct) << "could not get bucket sync policy handler (r=" << op_ret << ")" << dendl;
    return;
  }

  auto local_dests = source_handler->get_all_dests_in_zone(local_zone_id);

  std::vector<rgw_bucket_shard_sync_info> current_status;
  for (auto& entry : local_dests) {
    auto pipe = entry.second;

    ldout(s->cct, 20) << "RGWOp_BILog_Status::execute(optional_yield y): getting sync status for pipe=" << pipe << dendl;

    RGWBucketInfo *pinfo = &info;
    std::optional<RGWBucketInfo> opt_dest_info;

    if (!pipe.dest.bucket) {
      /* Uh oh, something went wrong */
      ldout(s->cct, 20) << "ERROR: RGWOp_BILog_Status::execute(optional_yield y): BUG: pipe.dest.bucket was not initialized" << pipe << dendl;
      op_ret = -EIO;
      return;
    }

    if (*pipe.dest.bucket != info.bucket) {
      opt_dest_info.emplace();
      pinfo = &(*opt_dest_info);

      /* dest bucket might not have a bucket id */
      op_ret = store->ctl()->bucket->read_bucket_info(*pipe.dest.bucket,
                                                        pinfo,
                                                        s->yield,
                                                        RGWBucketCtl::BucketInstance::GetParams(),
                                                        nullptr);
      if (op_ret < 0) {
        ldpp_dout(s, 4) << "failed to read target bucket info (bucket=: " << cpp_strerror(op_ret) << dendl;
        return;
      }

      pipe.dest.bucket = pinfo->bucket;
    }

    int r = rgw_bucket_sync_status(this, store, pipe, *pinfo, &info, &current_status);
    if (r < 0) {
      lderr(s->cct) << "ERROR: rgw_bucket_sync_status() on pipe=" << pipe << " returned ret=" << r << dendl;
      op_ret = r;
      return;
    }

    if (status.empty()) {
      status = std::move(current_status);
    } else {
      if (current_status.size() !=
          status.size()) {
        op_ret = -EINVAL;
        lderr(s->cct) << "ERROR: different number of shards for sync status of buckets syncing from the same source: status.size()= " << status.size() << " current_status.size()=" << current_status.size() << dendl;
        return;
      }
      auto m = status.begin();
      for (auto& cur_shard_status : current_status) {
        auto& result_shard_status = *m++;
        // always take the first marker, or any later marker that's smaller
        if (cur_shard_status.inc_marker.position < result_shard_status.inc_marker.position) {
          result_shard_status = std::move(cur_shard_status);
        }
      }
    }
  }
}

void RGWOp_BILog_Status::send_response()
{
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret >= 0) {
    encode_json("status", status, s->formatter);
  }
  flusher.flush();
}

// not in header to avoid pulling in rgw_data_sync.h
class RGWOp_DATALog_Status : public RGWRESTOp {
  rgw_data_sync_status status;
public:
  int check_caps(const RGWUserCaps& caps) override {
    return caps.check_cap("datalog", RGW_CAP_READ);
  }
  int verify_permission(optional_yield y) override {
    return check_caps(s->user->get_caps());
  }
  void execute(optional_yield y) override ;
  void send_response() override;
  const char* name() const override { return "get_data_changes_log_status"; }
};

void RGWOp_DATALog_Status::execute(optional_yield y)
{
  const auto source_zone = s->info.args.get("source-zone");
  auto sync = store->getRados()->get_data_sync_manager(source_zone);
  if (sync == nullptr) {
    ldout(s->cct, 1) << "no sync manager for source-zone " << source_zone << dendl;
    op_ret = -ENOENT;
    return;
  }
  op_ret = sync->read_sync_status(&status);
}

void RGWOp_DATALog_Status::send_response()
{
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret >= 0) {
    encode_json("status", status, s->formatter);
  }
  flusher.flush();
}


RGWOp *RGWHandler_Log::op_get() {
  bool exists;
  string type = s->info.args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0) {
    if (s->info.args.exists("id")) {
      if (s->info.args.exists("info")) {
        return new RGWOp_MDLog_ShardInfo;
      } else {
        return new RGWOp_MDLog_List;
      }
    } else if (s->info.args.exists("status")) {
      return new RGWOp_MDLog_Status;
    } else {
      return new RGWOp_MDLog_Info;
    }
  } else if (type.compare("bucket-index") == 0) {
    if (s->info.args.exists("info")) {
      return new RGWOp_BILog_Info;
    } else if (s->info.args.exists("status")) {
      return new RGWOp_BILog_Status;
    } else {
      return new RGWOp_BILog_List;
    }
  } else if (type.compare("data") == 0) {
    if (s->info.args.exists("id")) {
      if (s->info.args.exists("info")) {
        return new RGWOp_DATALog_ShardInfo;
      } else {
        return new RGWOp_DATALog_List;
      }
    } else if (s->info.args.exists("status")) {
      return new RGWOp_DATALog_Status;
    } else {
      return new RGWOp_DATALog_Info;
    }
  }
  return NULL;
}

RGWOp *RGWHandler_Log::op_delete() {
  bool exists;
  string type = s->info.args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0)
    return new RGWOp_MDLog_Delete;
  else if (type.compare("bucket-index") == 0) 
    return new RGWOp_BILog_Delete;
  else if (type.compare("data") == 0)
    return new RGWOp_DATALog_Delete;
  return NULL;
}

RGWOp *RGWHandler_Log::op_post() {
  bool exists;
  string type = s->info.args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0) {
    if (s->info.args.exists("lock"))
      return new RGWOp_MDLog_Lock;
    else if (s->info.args.exists("unlock"))
      return new RGWOp_MDLog_Unlock;
    else if (s->info.args.exists("notify"))
      return new RGWOp_MDLog_Notify;	    
  } else if (type.compare("data") == 0) {
    if (s->info.args.exists("notify"))
      return new RGWOp_DATALog_Notify;	    
  }
  return NULL;
}

