// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include "rgw_sal_fwd.h"
#include "include/buffer.h"
#include "include/encoding.h"
#include "common/async/yield_context.h"

class XMLObj;
namespace ceph { class Formatter; }
class DoutPrefixProvider;
struct req_state;

/* S3 bucket logging configuration
 * based on: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
 * with ceph extensions
<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <LoggingEnabled>
      <TargetBucket>string</TargetBucket>
      <TargetGrants>
         <Grant>
            <Grantee>
               <DisplayName>string</DisplayName>
               <EmailAddress>string</EmailAddress>
               <ID>string</ID>
               <xsi:type>string</xsi:type>
               <URI>string</URI>
            </Grantee>
            <Permission>string</Permission>
         </Grant>
      </TargetGrants>
      <TargetObjectKeyFormat>
         <PartitionedPrefix>
            <PartitionDateSource>DeliveryTime|EventTime</PartitionDateSource>
         </PartitionedPrefix>
         <SimplePrefix>
         </SimplePrefix>
         <RGWPrefix>                                    <!-- Ceph extension -->
         </RGWPrefix>
      </TargetObjectKeyFormat>
      <TargetPrefix>string</TargetPrefix>
      <EventType>Read|Write|ReadWrite</EventType>       <!-- Ceph extension -->
      <RecordType>Standard|Short</RecordType>           <!-- Ceph extension -->
      <ObjectRollTime>integer</ObjectRollTime>          <!-- Ceph extension -->
      <RecordsBatchSize>integer</RecordsBatchSize>      <!-- Ceph extension -->
   </LoggingEnabled>
</BucketLoggingStatus>
*/

enum class BucketLoggingKeyFormat {Partitioned, RGW, Simple};
enum class BucketLoggingRecordType {Standard, Short};
enum class BucketLoggingEventType {Read, Write, ReadWrite};
enum class BucketLoggingPartitionDateSource {DeliveryTime, EventTime};

struct rgw_bucket_logging {
  bool enabled = false;
  std::string target_bucket;
  BucketLoggingKeyFormat obj_key_format = BucketLoggingKeyFormat::RGW;
  // target object key formats:
  // Partitioned: [DestinationPrefix][SourceAccountId]/[SourceRegion]/[SourceBucket]/[YYYY]/[MM]/[DD]/[YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]
  // Simple: [DestinationPrefix][YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]
  // RGW: [DestinationPrefix]/RGWId]/[YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]
  std::string target_prefix; // a prefix for all log object keys. 
                             // useful when multiple bucket log to the same target 
                             // or when the target bucket is used for other things than logs
  uint32_t obj_roll_time; // time in seconds to move object to bucket and start another object
  BucketLoggingRecordType record_type;
  uint32_t records_batch_size = 0; // how many records to batch in memory before writing to the object
                                   // if set to zero, records are written syncronously to the object.
                                   // if obj_roll_time is reached, the batch of records will be written to the object
                                   // regardless of the number of records
  BucketLoggingEventType event_type = BucketLoggingEventType::Write;
  // which events to log:
  // Write: PUT, COPY, DELETE, lifecycle, Complete MPU
  // Read: GET
  // ReadWrite: all the above
  BucketLoggingPartitionDateSource date_source = BucketLoggingPartitionDateSource::DeliveryTime;
  // EventTime: use only year, month, and day. The hour, minutes and seconds are set to 00 in the key
  // DeliveryTime: the time the log object was created
  bool decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
  void dump(Formatter *f) const; // json
  std::string to_json_str() const;

  void encode(ceph::bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(target_bucket, bl);
    encode(static_cast<int>(obj_key_format), bl);
    encode(target_prefix, bl);
    encode(obj_roll_time, bl);
    encode(static_cast<int>(record_type), bl);
    encode(records_batch_size, bl);
    encode(static_cast<int>(event_type), bl);
    encode(static_cast<int>(date_source), bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator& bl) {
    DECODE_START(1, bl);
    decode(target_bucket, bl);
    int type;
    decode(type, bl);
    obj_key_format = static_cast<BucketLoggingKeyFormat>(type);
    decode(target_prefix, bl);
    decode(obj_roll_time, bl);
    decode(type, bl);
    record_type = static_cast<BucketLoggingRecordType>(type);
    decode(records_batch_size, bl);
    decode(type, bl);
    event_type = static_cast<BucketLoggingEventType>(type);
    decode(type, bl);
    date_source = static_cast<BucketLoggingPartitionDateSource>(type);
    DECODE_FINISH(bl);
  }
};
WRITE_CLASS_ENCODER(rgw_bucket_logging)

constexpr unsigned MAX_BUCKET_LOGGING_BUFFER = 1000;

using bucket_logging_records = std::array<std::string, MAX_BUCKET_LOGGING_BUFFER>;

template <typename Records>
inline std::string to_string(const Records& records) {
  std::string str_records;
  for (const auto& record : records) {
    str_records.append(to_string(record)).append("\n");
  }
  return str_records;
}

// log a bucket logging record according to the configuration
int log_record(rgw::sal::Driver* driver, const req_state* s, const std::string& op_name, const std::string& etag, const rgw_bucket_logging& configuration,
    const DoutPrefixProvider *dpp, optional_yield y);

// return the oid of the object holding the name of the temporary logging object
// bucket - log bucket
// prefix - logging prefix from configuration. should be used when multiple buckets log into the same log bucket
std::string logging_object_name_oid(const rgw::sal::Bucket* bucket, const std::string& prefix);

