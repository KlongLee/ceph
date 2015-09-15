// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>
#include <iostream>
#include <sstream>
#include <string>

#include "auth/Crypto.h"

#include "common/armor.h"
#include "common/ceph_json.h"
#include "common/config.h"
#include "common/ceph_argparse.h"
#include "common/Formatter.h"
#include "common/errno.h"

#include "global/global_init.h"

#include "include/utime.h"
#include "include/str_list.h"

#include "rgw_user.h"
#include "rgw_bucket.h"
#include "rgw_rados.h"
#include "rgw_acl.h"
#include "rgw_acl_s3.h"
#include "rgw_log.h"
#include "rgw_formats.h"
#include "rgw_usage.h"
#include "rgw_replica_log.h"
#include "rgw_orphan.h"
#include "rgw_sync.h"
#include "rgw_data_sync.h"
#include "rgw_rest_conn.h"

using namespace std;

#define dout_subsys ceph_subsys_rgw

#define SECRET_KEY_LEN 40
#define PUBLIC_ID_LEN 20

static RGWRados *store = NULL;

void _usage() 
{
  cerr << "usage: radosgw-admin <cmd> [options...]" << std::endl;
  cerr << "commands:\n";
  cerr << "  user create                create a new user\n" ;
  cerr << "  user modify                modify user\n";
  cerr << "  user info                  get user info\n";
  cerr << "  user rm                    remove user\n";
  cerr << "  user suspend               suspend a user\n";
  cerr << "  user enable                re-enable user after suspension\n";
  cerr << "  user check                 check user info\n";
  cerr << "  user stats                 show user stats as accounted by quota subsystem\n";
  cerr << "  caps add                   add user capabilities\n";
  cerr << "  caps rm                    remove user capabilities\n";
  cerr << "  subuser create             create a new subuser\n" ;
  cerr << "  subuser modify             modify subuser\n";
  cerr << "  subuser rm                 remove subuser\n";
  cerr << "  key create                 create access key\n";
  cerr << "  key rm                     remove access key\n";
  cerr << "  bucket list                list buckets\n";
  cerr << "  bucket link                link bucket to specified user\n";
  cerr << "  bucket unlink              unlink bucket from specified user\n";
  cerr << "  bucket stats               returns bucket statistics\n";
  cerr << "  bucket rm                  remove bucket\n";
  cerr << "  bucket check               check bucket index\n";
  cerr << "  object rm                  remove object\n";
  cerr << "  object unlink              unlink object from bucket index\n";
  cerr << "  objects expire             run expired objects cleanup\n";
  cerr << "  period prepare             prepare a new period\n";
  cerr << "  period delete              delete a period\n";
  cerr << "  period activate            activate a period \n";
  cerr << "  period get                 get period info\n";
  cerr << "  period get-current         get current period info\n";
  cerr << "  period pull                pull a period\n";
  cerr << "  period push                push a period\n";
  cerr << "  period list                list all periods\n";
  cerr << "  quota set                  set quota params\n";
  cerr << "  quota enable               enable quota\n";
  cerr << "  quota disable              disable quota\n";
  cerr << "  realm create               create a new realm\n";
  cerr << "  realm delete               delete a realm\n";
  cerr << "  realm get                  show realm info\n";
  cerr << "  realm get-default          get default realm name\n";
  cerr << "  realm list                 list realms\n";
  cerr << "  realm list-periods         list all realm periods\n";
  cerr << "  realm remove               remove a zonegroup from the realm\n";
  cerr << "  realm rename               rename a realm\n";
  cerr << "  realm set                  set realm info (requires infile)\n";
  cerr << "  realm set-default          set realm as default\n";
  cerr << "  zonegroup create           create a new zone group info\n";
  cerr << "  zonegroup default          set default zone group\n";
  cerr << "  zonegroup delete           delete a zone group info\n";
  cerr << "  zonegroup get              show zone group info\n";
  cerr << "  zonegroup set              set zone group info (requires infile)\n";
  cerr << "  zonegroup rename          rename a zone group\n";
  cerr << "  zonegroups list            list all zone groups set on this cluster\n";
  cerr << "  zonegroup-map get          show zonegroup-map\n";
  cerr << "  zonegroup-map set          set zonegroup-map (requires infile)\n";
  cerr << "  zone add                   add a zone to a zonegroup\n";
  cerr << "  zone create                create a new zone\n";
  cerr << "  zone get                   show zone cluster params\n";
  cerr << "  zone set                   set zone cluster params (requires infile)\n";
  cerr << "  zone list                  list all zones set on this cluster\n";
  cerr << "  pool add                   add an existing pool for data placement\n";
  cerr << "  pool rm                    remove an existing pool from data placement set\n";
  cerr << "  pools list                 list placement active set\n";
  cerr << "  policy                     read bucket/object policy\n";
  cerr << "  log list                   list log objects\n";
  cerr << "  log show                   dump a log from specific object or (bucket + date\n";
  cerr << "                             + bucket-id)\n";
  cerr << "  log rm                     remove log object\n";
  cerr << "  usage show                 show usage (by user, date range)\n";
  cerr << "  usage trim                 trim usage (by user, date range)\n";
  cerr << "  temp remove                remove temporary objects that were created up to\n";
  cerr << "                             specified date (and optional time)\n";
  cerr << "  gc list                    dump expired garbage collection objects (specify\n";
  cerr << "                             --include-all to list all entries, including unexpired)\n";
  cerr << "  gc process                 manually process garbage\n";
  cerr << "  metadata get               get metadata info\n";
  cerr << "  metadata put               put metadata info\n";
  cerr << "  metadata rm                remove metadata info\n";
  cerr << "  metadata list              list metadata info\n";
  cerr << "  mdlog list                 list metadata log\n";
  cerr << "  mdlog trim                 trim metadata log\n";
  cerr << "  bilog list                 list bucket index log\n";
  cerr << "  bilog trim                 trim bucket index log (use start-marker, end-marker)\n";
  cerr << "  datalog list               list data log\n";
  cerr << "  datalog trim               trim data log\n";
  cerr << "  opstate list               list stateful operations entries (use client_id,\n";
  cerr << "                             op_id, object)\n";
  cerr << "  opstate set                set state on an entry (use client_id, op_id, object, state)\n";
  cerr << "  opstate renew              renew state on an entry (use client_id, op_id, object)\n";
  cerr << "  opstate rm                 remove entry (use client_id, op_id, object)\n";
  cerr << "  replicalog get             get replica metadata log entry\n";
  cerr << "  replicalog update          update replica metadata log entry\n";
  cerr << "  replicalog delete          delete replica metadata log entry\n";
  cerr << "options:\n";
  cerr << "   --uid=<id>                user id\n";
  cerr << "   --subuser=<name>          subuser name\n";
  cerr << "   --access-key=<key>        S3 access key\n";
  cerr << "   --email=<email>\n";
  cerr << "   --secret/--secret-key=<key>\n";
  cerr << "                             specify secret key\n";
  cerr << "   --gen-access-key          generate random access key (for S3)\n";
  cerr << "   --gen-secret              generate random secret key\n";
  cerr << "   --key-type=<type>         key type, options are: swift, s3\n";
  cerr << "   --temp-url-key[-2]=<key>  temp url key\n";
  cerr << "   --access=<access>         Set access permissions for sub-user, should be one\n";
  cerr << "                             of read, write, readwrite, full\n";
  cerr << "   --display-name=<name>\n";
  cerr << "   --max_buckets             max number of buckets for a user\n";
  cerr << "   --system                  set the system flag on the user\n";
  cerr << "   --bucket=<bucket>\n";
  cerr << "   --pool=<pool>\n";
  cerr << "   --object=<object>\n";
  cerr << "   --date=<date>\n";
  cerr << "   --start-date=<date>\n";
  cerr << "   --end-date=<date>\n";
  cerr << "   --bucket-id=<bucket-id>\n";
  cerr << "   --shard-id=<shard-id>     optional for mdlog list\n";
  cerr << "                             required for: \n";
  cerr << "                               mdlog trim\n";
  cerr << "                               replica mdlog get/delete\n";
  cerr << "                               replica datalog get/delete\n";
  cerr << "   --metadata-key=<key>      key to retrieve metadata from with metadata get\n";
  cerr << "   --remote=<remote>         remote to pull period\n";
  cerr << "   --parent=<id>             parent period id\n";
  cerr << "   --period=<id>             period id\n";
  cerr << "   --epoch=<number>          period epoch\n";
  cerr << "   --master                  set as master\n";
  cerr << "   --master-url              master url\n";
  cerr << "   --master-zonegroup=<id>   master zonegroup id\n";
  cerr << "   --master-zone=<id>        master zone id\n";
  cerr << "   --realm=<realm>           realm name\n";
  cerr << "   --realm-id=<realm id>     realm id\n";
  cerr << "   --realm-new-name=<realm new name> realm new name\n";
  cerr << "   --zonegroup=<zonegroup>   zonegroup name\n";
  cerr << "   --zone=<zone>             zone name\n";
  cerr << "   --rgw-zone=<zone>         zone in which radosgw is running\n";
  cerr << "   --fix                     besides checking bucket index, will also fix it\n";
  cerr << "   --check-objects           bucket check: rebuilds bucket index according to\n";
  cerr << "                             actual objects state\n";
  cerr << "   --format=<format>         specify output format for certain operations: xml,\n";
  cerr << "                             json\n";
  cerr << "   --purge-data              when specified, user removal will also purge all the\n";
  cerr << "                             user data\n";
  cerr << "   --purge-keys              when specified, subuser removal will also purge all the\n";
  cerr << "                             subuser keys\n";
  cerr << "   --purge-objects           remove a bucket's objects before deleting it\n";
  cerr << "                             (NOTE: required to delete a non-empty bucket)\n";
  cerr << "   --sync-stats              option to 'user stats', update user stats with current\n";
  cerr << "                             stats reported by user's buckets indexes\n";
  cerr << "   --show-log-entries=<flag> enable/disable dump of log entries on log show\n";
  cerr << "   --show-log-sum=<flag>     enable/disable dump of log summation on log show\n";
  cerr << "   --skip-zero-entries       log show only dumps entries that don't have zero value\n";
  cerr << "                             in one of the numeric field\n";
  cerr << "   --infile                  specify a file to read in when setting data\n";
  cerr << "   --state=<state string>    specify a state for the opstate set command\n";
  cerr << "   --replica-log-type        replica log type (metadata, data, bucket), required for\n";
  cerr << "                             replica log operations\n";
  cerr << "   --categories=<list>       comma separated list of categories, used in usage show\n";
  cerr << "   --caps=<caps>             list of caps (e.g., \"usage=read, write; user=read\"\n";
  cerr << "   --yes-i-really-mean-it    required for certain operations\n";
  cerr << "   --reset-regions           reset regionmap when regionmap update";
  cerr << "\n";
  cerr << "<date> := \"YYYY-MM-DD[ hh:mm:ss]\"\n";
  cerr << "\nQuota options:\n";
  cerr << "   --bucket                  specified bucket for quota command\n";
  cerr << "   --max-objects             specify max objects (negative value to disable)\n";
  cerr << "   --max-size                specify max size (in bytes, negative value to disable)\n";
  cerr << "   --quota-scope             scope of quota (bucket, user)\n";
  cerr << "\n";
  generic_client_usage();
}

int usage()
{
  _usage();
  return 1;
}

void usage_exit()
{
  _usage();
  exit(1);
}

enum {
  OPT_NO_CMD = 0,
  OPT_USER_CREATE,
  OPT_USER_INFO,
  OPT_USER_MODIFY,
  OPT_USER_RM,
  OPT_USER_SUSPEND,
  OPT_USER_ENABLE,
  OPT_USER_CHECK,
  OPT_USER_STATS,
  OPT_SUBUSER_CREATE,
  OPT_SUBUSER_MODIFY,
  OPT_SUBUSER_RM,
  OPT_KEY_CREATE,
  OPT_KEY_RM,
  OPT_BUCKETS_LIST,
  OPT_BUCKET_LINK,
  OPT_BUCKET_UNLINK,
  OPT_BUCKET_STATS,
  OPT_BUCKET_CHECK,
  OPT_BUCKET_RM,
  OPT_BUCKET_REWRITE,
  OPT_POLICY,
  OPT_POOL_ADD,
  OPT_POOL_RM,
  OPT_POOLS_LIST,
  OPT_LOG_LIST,
  OPT_LOG_SHOW,
  OPT_LOG_RM,
  OPT_USAGE_SHOW,
  OPT_USAGE_TRIM,
  OPT_OBJECT_RM,
  OPT_OBJECT_UNLINK,
  OPT_OBJECT_STAT,
  OPT_OBJECT_REWRITE,
  OPT_OBJECTS_EXPIRE,
  OPT_BI_GET,
  OPT_BI_PUT,
  OPT_BI_LIST,
  OPT_OLH_GET,
  OPT_OLH_READLOG,
  OPT_QUOTA_SET,
  OPT_QUOTA_ENABLE,
  OPT_QUOTA_DISABLE,
  OPT_GC_LIST,
  OPT_GC_PROCESS,
  OPT_ORPHANS_FIND,
  OPT_ORPHANS_FINISH,
  OPT_ZONEGROUP_CREATE,
  OPT_ZONEGROUP_DEFAULT,
  OPT_ZONEGROUP_DELETE,
  OPT_ZONEGROUP_GET,
  OPT_ZONEGROUP_SET,
  OPT_ZONEGROUP_LIST,
  OPT_ZONEGROUP_RENAME ,  
  OPT_ZONEGROUPMAP_GET,
  OPT_ZONEGROUPMAP_SET,
  OPT_ZONEGROUPMAP_UPDATE,
  OPT_ZONE_ADD,
  OPT_ZONE_CREATE,  
  OPT_ZONE_DELETE,
  OPT_ZONE_GET,
  OPT_ZONE_SET,
  OPT_ZONE_LIST,
  OPT_ZONE_RENAME,
  OPT_CAPS_ADD,
  OPT_CAPS_RM,
  OPT_METADATA_GET,
  OPT_METADATA_PUT,
  OPT_METADATA_RM,
  OPT_METADATA_LIST,
  OPT_METADATA_SYNC_STATUS,
  OPT_METADATA_SYNC_INIT,
  OPT_METADATA_SYNC_RUN,
  OPT_MDLOG_LIST,
  OPT_MDLOG_TRIM,
  OPT_MDLOG_FETCH,
  OPT_BILOG_LIST,
  OPT_BILOG_TRIM,
  OPT_DATA_SYNC_STATUS,
  OPT_DATA_SYNC_INIT,
  OPT_DATA_SYNC_RUN,
  OPT_DATALOG_LIST,
  OPT_DATALOG_TRIM,
  OPT_OPSTATE_LIST,
  OPT_OPSTATE_SET,
  OPT_OPSTATE_RENEW,
  OPT_OPSTATE_RM,
  OPT_REPLICALOG_GET,
  OPT_REPLICALOG_UPDATE,
  OPT_REPLICALOG_DELETE,
  OPT_REALM_CREATE,
  OPT_REALM_DELETE,
  OPT_REALM_GET,
  OPT_REALM_GET_DEFAULT,
  OPT_REALM_LIST,
  OPT_REALM_LIST_PERIODS,
  OPT_REALM_REMOVE,
  OPT_REALM_RENAME,
  OPT_REALM_SET,
  OPT_REALM_SET_DEFAULT,
  OPT_PERIOD_PREPARE,
  OPT_PERIOD_DELETE,
  OPT_PERIOD_GET,
  OPT_PERIOD_GET_CURRENT,
  OPT_PERIOD_ACTIVATE,
  OPT_PERIOD_PULL,
  OPT_PERIOD_PUSH,
  OPT_PERIOD_LIST,
};

static int get_cmd(const char *cmd, const char *prev_cmd, const char *prev_prev_cmd, bool *need_more)
{
  *need_more = false;
  // NOTE: please keep the checks in alphabetical order !!!
  if (strcmp(cmd, "bi") == 0 ||
      strcmp(cmd, "bilog") == 0 ||
      strcmp(cmd, "bucket") == 0 ||
      strcmp(cmd, "buckets") == 0 ||
      strcmp(cmd, "caps") == 0 ||
      strcmp(cmd, "data") == 0 ||
      strcmp(cmd, "datalog") == 0 ||
      strcmp(cmd, "gc") == 0 || 
      strcmp(cmd, "key") == 0 ||
      strcmp(cmd, "log") == 0 ||
      strcmp(cmd, "mdlog") == 0 ||
      strcmp(cmd, "metadata") == 0 ||
      strcmp(cmd, "object") == 0 ||
      strcmp(cmd, "objects") == 0 ||
      strcmp(cmd, "olh") == 0 ||
      strcmp(cmd, "opstate") == 0 ||
      strcmp(cmd, "orphans") == 0 || 
      strcmp(cmd, "period") == 0 ||
      strcmp(cmd, "pool") == 0 ||
      strcmp(cmd, "pools") == 0 ||
      strcmp(cmd, "quota") == 0 ||
      strcmp(cmd, "realm") == 0 ||
      strcmp(cmd, "replicalog") == 0 ||
      strcmp(cmd, "subuser") == 0 ||
      strcmp(cmd, "temp") == 0 ||
      strcmp(cmd, "usage") == 0 ||
      strcmp(cmd, "user") == 0 ||
      strcmp(cmd, "zone") == 0 ||
      strcmp(cmd, "zonegroup") == 0 ||
      strcmp(cmd, "zonegroups") == 0 ||
      strcmp(cmd, "zonegroup-map") == 0 ||
      strcmp(cmd, "zonegroupmap") == 0 )
{
    *need_more = true;
    return 0;
  }

  if (strcmp(cmd, "policy") == 0)
    return OPT_POLICY;

  if (!prev_cmd)
    return -EINVAL;

  if (strcmp(prev_cmd, "user") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_USER_CREATE;
    if (strcmp(cmd, "info") == 0)
      return OPT_USER_INFO;
    if (strcmp(cmd, "modify") == 0)
      return OPT_USER_MODIFY;
    if (strcmp(cmd, "rm") == 0)
      return OPT_USER_RM;
    if (strcmp(cmd, "suspend") == 0)
      return OPT_USER_SUSPEND;
    if (strcmp(cmd, "enable") == 0)
      return OPT_USER_ENABLE;
    if (strcmp(cmd, "check") == 0)
      return OPT_USER_CHECK;
    if (strcmp(cmd, "stats") == 0)
      return OPT_USER_STATS;
  } else if (strcmp(prev_cmd, "subuser") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_SUBUSER_CREATE;
    if (strcmp(cmd, "modify") == 0)
      return OPT_SUBUSER_MODIFY;
    if (strcmp(cmd, "rm") == 0)
      return OPT_SUBUSER_RM;
  } else if (strcmp(prev_cmd, "key") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_KEY_CREATE;
    if (strcmp(cmd, "rm") == 0)
      return OPT_KEY_RM;
  } else if (strcmp(prev_cmd, "buckets") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_BUCKETS_LIST;
  } else if (strcmp(prev_cmd, "bucket") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_BUCKETS_LIST;
    if (strcmp(cmd, "link") == 0)
      return OPT_BUCKET_LINK;
    if (strcmp(cmd, "unlink") == 0)
      return OPT_BUCKET_UNLINK;
    if (strcmp(cmd, "stats") == 0)
      return OPT_BUCKET_STATS;
    if (strcmp(cmd, "rm") == 0)
      return OPT_BUCKET_RM;
    if (strcmp(cmd, "rewrite") == 0)
      return OPT_BUCKET_REWRITE;
    if (strcmp(cmd, "check") == 0)
      return OPT_BUCKET_CHECK;
  } else if (strcmp(prev_cmd, "log") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_LOG_LIST;
    if (strcmp(cmd, "show") == 0)
      return OPT_LOG_SHOW;
    if (strcmp(cmd, "rm") == 0)
      return OPT_LOG_RM;
  } else if (strcmp(prev_cmd, "usage") == 0) {
    if (strcmp(cmd, "show") == 0)
      return OPT_USAGE_SHOW;
    if (strcmp(cmd, "trim") == 0)
      return OPT_USAGE_TRIM;
  } else if (strcmp(prev_cmd, "caps") == 0) {
    if (strcmp(cmd, "add") == 0)
      return OPT_CAPS_ADD;
    if (strcmp(cmd, "rm") == 0)
      return OPT_CAPS_RM;
  } else if (strcmp(prev_cmd, "pool") == 0) {
    if (strcmp(cmd, "add") == 0)
      return OPT_POOL_ADD;
    if (strcmp(cmd, "rm") == 0)
      return OPT_POOL_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_POOLS_LIST;
  } else if (strcmp(prev_cmd, "pools") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_POOLS_LIST;
  } else if (strcmp(prev_cmd, "object") == 0) {
    if (strcmp(cmd, "rm") == 0)
      return OPT_OBJECT_RM;
    if (strcmp(cmd, "unlink") == 0)
      return OPT_OBJECT_UNLINK;
    if (strcmp(cmd, "stat") == 0)
      return OPT_OBJECT_STAT;
    if (strcmp(cmd, "rewrite") == 0)
      return OPT_OBJECT_REWRITE;
  } else if (strcmp(prev_cmd, "objects") == 0) {
    if (strcmp(cmd, "expire") == 0)
      return OPT_OBJECTS_EXPIRE;
  } else if (strcmp(prev_cmd, "olh") == 0) {
    if (strcmp(cmd, "get") == 0)
      return OPT_OLH_GET;
    if (strcmp(cmd, "readlog") == 0)
      return OPT_OLH_READLOG;
  } else if (strcmp(prev_cmd, "bi") == 0) {
    if (strcmp(cmd, "get") == 0)
      return OPT_BI_GET;
    if (strcmp(cmd, "put") == 0)
      return OPT_BI_PUT;
    if (strcmp(cmd, "list") == 0)
      return OPT_BI_LIST;
  } else if (strcmp(prev_cmd, "period") == 0) {
    if (strcmp(cmd, "prepare") == 0)
      return OPT_PERIOD_PREPARE;
    if (strcmp(cmd, "delete") == 0)
      return OPT_PERIOD_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_PERIOD_GET;
    if (strcmp(cmd, "get-current") == 0)
      return OPT_PERIOD_GET_CURRENT;
    if (strcmp(cmd, "activate") == 0)
      return OPT_PERIOD_ACTIVATE;
    if (strcmp(cmd, "pull") == 0)
      return OPT_PERIOD_PULL;
    if (strcmp(cmd, "push") == 0)
      return OPT_PERIOD_PUSH;
    if (strcmp(cmd, "list") == 0)
      return OPT_PERIOD_LIST;
  } else if (strcmp(prev_cmd, "realm") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_REALM_CREATE;
    if (strcmp(cmd, "delete") == 0)
      return OPT_REALM_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_REALM_GET;
    if (strcmp(cmd, "get-default") == 0)
      return OPT_REALM_GET_DEFAULT;
    if (strcmp(cmd, "list") == 0)
      return OPT_REALM_LIST;
    if (strcmp(cmd, "list-periods") == 0)
      return OPT_REALM_LIST_PERIODS;
    if (strcmp(cmd, "remove") == 0)
      return OPT_REALM_REMOVE;
    if (strcmp(cmd, "rename") == 0)
      return OPT_REALM_RENAME;
    if (strcmp(cmd, "set") == 0)
      return OPT_REALM_SET;
    if (strcmp(cmd, "set-default") == 0)
      return OPT_REALM_SET_DEFAULT;
  } else if (strcmp(prev_cmd, "zonegroup") == 0) {
    if (strcmp(cmd, "create")== 0)
      return OPT_ZONEGROUP_CREATE;
    if (strcmp(cmd, "default") == 0)
      return OPT_ZONEGROUP_DEFAULT;
    if (strcmp(cmd, "delete") == 0)
      return OPT_ZONEGROUP_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_ZONEGROUP_GET;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONEGROUP_LIST;
    if (strcmp(cmd, "set") == 0)
      return OPT_ZONEGROUP_SET;
    if (strcmp(cmd, "rename") == 0)
      return OPT_ZONEGROUP_RENAME;
  } else if (strcmp(prev_cmd, "quota") == 0) {
    if (strcmp(cmd, "set") == 0)
      return OPT_QUOTA_SET;
    if (strcmp(cmd, "enable") == 0)
      return OPT_QUOTA_ENABLE;
    if (strcmp(cmd, "disable") == 0)
      return OPT_QUOTA_DISABLE;
  } else if (strcmp(prev_cmd, "zonegroups") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONEGROUP_LIST;
  } else if (strcmp(prev_cmd, "zonegroup-map") == 0 ||
             strcmp(prev_cmd, "zonegroupmap") == 0) {
    if (strcmp(cmd, "get") == 0)
      return OPT_ZONEGROUPMAP_GET;
    if (strcmp(cmd, "set") == 0)
      return OPT_ZONEGROUPMAP_SET;
    if (strcmp(cmd, "update") == 0)
      return OPT_ZONEGROUPMAP_UPDATE;
  } else if (strcmp(prev_cmd, "zone") == 0) {
    if (strcmp(cmd, "delete") == 0)
      return OPT_ZONE_DELETE;
    if (strcmp(cmd, "create") == 0)
      return OPT_ZONE_CREATE;
    if (strcmp(cmd, "add") == 0)
      return OPT_ZONE_ADD;
    if (strcmp(cmd, "get") == 0)
      return OPT_ZONE_GET;
    if (strcmp(cmd, "set") == 0)
      return OPT_ZONE_SET;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONE_LIST;
    if (strcmp(cmd, "rename") == 0)
      return OPT_ZONE_RENAME;
  } else if (strcmp(prev_cmd, "zones") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONE_LIST;
  } else if (strcmp(prev_cmd, "gc") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_GC_LIST;
    if (strcmp(cmd, "process") == 0)
      return OPT_GC_PROCESS;
  } else if (strcmp(prev_cmd, "orphans") == 0) {
    if (strcmp(cmd, "find") == 0)
      return OPT_ORPHANS_FIND;
    if (strcmp(cmd, "finish") == 0)
      return OPT_ORPHANS_FINISH;
  } else if (strcmp(prev_cmd, "metadata") == 0) {
    if (strcmp(cmd, "get") == 0)
      return OPT_METADATA_GET;
    if (strcmp(cmd, "put") == 0)
      return OPT_METADATA_PUT;
    if (strcmp(cmd, "rm") == 0)
      return OPT_METADATA_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_METADATA_LIST;
    if (strcmp(cmd, "sync") == 0) {
      *need_more = true;
      return 0;
    }
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "metadata") == 0) &&
	     (strcmp(prev_cmd, "sync") == 0)) {
    if (strcmp(cmd, "status") == 0)
      return OPT_METADATA_SYNC_STATUS;
    if (strcmp(cmd, "init") == 0)
      return OPT_METADATA_SYNC_INIT;
    if (strcmp(cmd, "run") == 0)
      return OPT_METADATA_SYNC_RUN;
  } else if (strcmp(prev_cmd, "mdlog") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_MDLOG_LIST;
    if (strcmp(cmd, "trim") == 0)
      return OPT_MDLOG_TRIM;
    if (strcmp(cmd, "fetch") == 0)
      return OPT_MDLOG_FETCH;
  } else if (strcmp(prev_cmd, "bilog") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_BILOG_LIST;
    if (strcmp(cmd, "trim") == 0)
      return OPT_BILOG_TRIM;
  } else if (strcmp(prev_cmd, "data") == 0) {
    if (strcmp(cmd, "sync") == 0) {
      *need_more = true;
      return 0;
    }
  } else if (strcmp(prev_cmd, "datalog") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_DATALOG_LIST;
    if (strcmp(cmd, "trim") == 0)
      return OPT_DATALOG_TRIM;
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "data") == 0) &&
	     (strcmp(prev_cmd, "sync") == 0)) {
    if (strcmp(cmd, "status") == 0)
      return OPT_DATA_SYNC_STATUS;
    if (strcmp(cmd, "init") == 0)
      return OPT_DATA_SYNC_INIT;
    if (strcmp(cmd, "run") == 0)
      return OPT_DATA_SYNC_RUN;
  } else if (strcmp(prev_cmd, "opstate") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_OPSTATE_LIST;
    if (strcmp(cmd, "set") == 0)
      return OPT_OPSTATE_SET;
    if (strcmp(cmd, "renew") == 0)
      return OPT_OPSTATE_RENEW;
    if (strcmp(cmd, "rm") == 0)
      return OPT_OPSTATE_RM;
  } else if (strcmp(prev_cmd, "replicalog") == 0) {
    if (strcmp(cmd, "get") == 0)
      return OPT_REPLICALOG_GET;
    if (strcmp(cmd, "update") == 0)
      return OPT_REPLICALOG_UPDATE;
    if (strcmp(cmd, "delete") == 0)
      return OPT_REPLICALOG_DELETE;
  }

  return -EINVAL;
}

enum ReplicaLogType {
  ReplicaLog_Invalid = 0,
  ReplicaLog_Metadata,
  ReplicaLog_Data,
  ReplicaLog_Bucket,
};

ReplicaLogType get_replicalog_type(const string& name) {
  if (name == "md" || name == "meta" || name == "metadata")
    return ReplicaLog_Metadata;
  if (name == "data")
    return ReplicaLog_Data;
  if (name == "bucket")
    return ReplicaLog_Bucket;

  return ReplicaLog_Invalid;
}

BIIndexType get_bi_index_type(const string& type_str) {
  if (type_str == "plain")
    return PlainIdx;
  if (type_str == "instance")
    return InstanceIdx;
  if (type_str == "olh")
    return OLHIdx;

  return InvalidIdx;
}

void dump_bi_entry(bufferlist& bl, BIIndexType index_type, Formatter *formatter)
{
  bufferlist::iterator iter = bl.begin();
  switch (index_type) {
    case PlainIdx:
    case InstanceIdx:
      {
        rgw_bucket_dir_entry entry;
        ::decode(entry, iter);
        encode_json("entry", entry, formatter);
      }
      break;
    case OLHIdx:
      {
        rgw_bucket_olh_entry entry;
        ::decode(entry, iter);
        encode_json("entry", entry, formatter);
      }
      break;
    default:
      assert(0);
      break;
  }
}

static void show_user_info(RGWUserInfo& info, Formatter *formatter)
{
  encode_json("user_info", info, formatter);
  formatter->flush(cout);
  cout << std::endl;
}

static void dump_bucket_usage(map<RGWObjCategory, RGWStorageStats>& stats, Formatter *formatter)
{
  map<RGWObjCategory, RGWStorageStats>::iterator iter;

  formatter->open_object_section("usage");
  for (iter = stats.begin(); iter != stats.end(); ++iter) {
    RGWStorageStats& s = iter->second;
    const char *cat_name = rgw_obj_category_name(iter->first);
    formatter->open_object_section(cat_name);
    formatter->dump_int("size_kb", s.num_kb);
    formatter->dump_int("size_kb_actual", s.num_kb_rounded);
    formatter->dump_int("num_objects", s.num_objects);
    formatter->close_section();
    formatter->flush(cout);
  }
  formatter->close_section();
}

int bucket_stats(rgw_bucket& bucket, int shard_id, Formatter *formatter)
{
  RGWBucketInfo bucket_info;
  time_t mtime;
  RGWObjectCtx obj_ctx(store);
  int r = store->get_bucket_info(obj_ctx, bucket.name, bucket_info, &mtime);
  if (r < 0)
    return r;

  map<RGWObjCategory, RGWStorageStats> stats;
  string bucket_ver, master_ver;
  string max_marker;
  int ret = store->get_bucket_stats(bucket, shard_id, &bucket_ver, &master_ver, stats, &max_marker);
  if (ret < 0) {
    cerr << "error getting bucket stats ret=" << ret << std::endl;
    return ret;
  }
  formatter->open_object_section("stats");
  formatter->dump_string("bucket", bucket.name);
  formatter->dump_string("pool", bucket.data_pool);
  formatter->dump_string("index_pool", bucket.index_pool);
  
  formatter->dump_string("id", bucket.bucket_id);
  formatter->dump_string("marker", bucket.marker);
  formatter->dump_string("owner", bucket_info.owner);
  formatter->dump_int("mtime", mtime);
  formatter->dump_string("ver", bucket_ver);
  formatter->dump_string("master_ver", master_ver);
  formatter->dump_string("max_marker", max_marker);
  dump_bucket_usage(stats, formatter);
  formatter->close_section();

  return 0;
}

class StoreDestructor {
  RGWRados *store;
public:
  StoreDestructor(RGWRados *_s) : store(_s) {}
  ~StoreDestructor() {
    RGWStoreManager::close_storage(store);
  }
};

static int init_bucket(const string& bucket_name, const string& bucket_id,
                       RGWBucketInfo& bucket_info, rgw_bucket& bucket)
{
  if (!bucket_name.empty()) {
    RGWObjectCtx obj_ctx(store);
    int r;
    if (bucket_id.empty()) {
      r = store->get_bucket_info(obj_ctx, bucket_name, bucket_info, NULL);
    } else {
      string bucket_instance_id = bucket_name + ":" + bucket_id;
      r = store->get_bucket_instance_info(obj_ctx, bucket_instance_id, bucket_info, NULL, NULL);
    }
    if (r < 0) {
      cerr << "could not get bucket info for bucket=" << bucket_name << std::endl;
      return r;
    }
    bucket = bucket_info.bucket;
  }
  return 0;
}

static int read_input(const string& infile, bufferlist& bl)
{
  int fd = 0;
  if (infile.size()) {
    fd = open(infile.c_str(), O_RDONLY);
    if (fd < 0) {
      int err = -errno;
      cerr << "error reading input file " << infile << std::endl;
      return err;
    }
  }

#define READ_CHUNK 8196
  int r;
  int err;

  do {
    char buf[READ_CHUNK];

    r = read(fd, buf, READ_CHUNK);
    if (r < 0) {
      err = -errno;
      cerr << "error while reading input" << std::endl;
      goto out;
    }
    bl.append(buf, r);
  } while (r > 0);
  err = 0;

 out:
  if (infile.size()) {
    close(fd);
  }
  return err;
}

template <class T>
static int read_decode_json(const string& infile, T& t)
{
  bufferlist bl;
  int ret = read_input(infile, bl);
  if (ret < 0) {
    cerr << "ERROR: failed to read input: " << cpp_strerror(-ret) << std::endl;
    return ret;
  }
  JSONParser p;
  ret = p.parse(bl.c_str(), bl.length());
  if (ret < 0) {
    cout << "failed to parse JSON" << std::endl;
    return ret;
  }

  try {
    decode_json_obj(t, &p);
  } catch (JSONDecoder::err& e) {
    cout << "failed to decode JSON input: " << e.message << std::endl;
    return -EINVAL;
  }
  return 0;
}
    
template <class T, class K>
static int read_decode_json(const string& infile, T& t, K *k)
{
  bufferlist bl;
  int ret = read_input(infile, bl);
  if (ret < 0) {
    cerr << "ERROR: failed to read input: " << cpp_strerror(-ret) << std::endl;
    return ret;
  }
  JSONParser p;
  ret = p.parse(bl.c_str(), bl.length());
  if (ret < 0) {
    cout << "failed to parse JSON" << std::endl;
    return ret;
  }

  try {
    t.decode_json(&p, k);
  } catch (JSONDecoder::err& e) {
    cout << "failed to decode JSON input: " << e.message << std::endl;
    return -EINVAL;
  }
  return 0;
}

static int parse_date_str(const string& date_str, utime_t& ut)
{
  uint64_t epoch = 0;
  uint64_t nsec = 0;

  if (!date_str.empty()) {
    int ret = utime_t::parse_date(date_str, &epoch, &nsec);
    if (ret < 0) {
      cerr << "ERROR: failed to parse date: " << date_str << std::endl;
      return -EINVAL;
    }
  }

  ut = utime_t(epoch, nsec);

  return 0;
}

template <class T>
static bool decode_dump(const char *field_name, bufferlist& bl, Formatter *f)
{
  T t;

  bufferlist::iterator iter = bl.begin();

  try {
    ::decode(t, iter);
  } catch (buffer::error& err) {
    return false;
  }

  encode_json(field_name, t, f);

  return true;
}

static bool dump_string(const char *field_name, bufferlist& bl, Formatter *f)
{
  string val;
  if (bl.length() > 0) {
    val.assign(bl.c_str(), bl.length());
  }
  f->dump_string(field_name, val);

  return true;
}

void set_quota_info(RGWQuotaInfo& quota, int opt_cmd, int64_t max_size, int64_t max_objects,
                    bool have_max_size, bool have_max_objects)
{
  switch (opt_cmd) {
    case OPT_QUOTA_ENABLE:
      quota.enabled = true;

      // falling through on purpose

    case OPT_QUOTA_SET:
      if (have_max_objects) {
        quota.max_objects = max_objects;
      }
      if (have_max_size) {
        if (max_size < 0) {
          quota.max_size_kb = -1;
        } else {
          quota.max_size_kb = rgw_rounded_kb(max_size);
        }
      }
      break;
    case OPT_QUOTA_DISABLE:
      quota.enabled = false;
      break;
  }
}

int set_bucket_quota(RGWRados *store, int opt_cmd, string& bucket_name, int64_t max_size, int64_t max_objects,
                     bool have_max_size, bool have_max_objects)
{
  RGWBucketInfo bucket_info;
  map<string, bufferlist> attrs;
  RGWObjectCtx obj_ctx(store);
  int r = store->get_bucket_info(obj_ctx, bucket_name, bucket_info, NULL, &attrs);
  if (r < 0) {
    cerr << "could not get bucket info for bucket=" << bucket_name << ": " << cpp_strerror(-r) << std::endl;
    return -r;
  }

  set_quota_info(bucket_info.quota, opt_cmd, max_size, max_objects, have_max_size, have_max_objects);

   r = store->put_bucket_instance_info(bucket_info, false, 0, &attrs);
  if (r < 0) {
    cerr << "ERROR: failed writing bucket instance info: " << cpp_strerror(-r) << std::endl;
    return -r;
  }
  return 0;
}

int set_user_bucket_quota(int opt_cmd, RGWUser& user, RGWUserAdminOpState& op_state, int64_t max_size, int64_t max_objects,
                          bool have_max_size, bool have_max_objects)
{
  RGWUserInfo& user_info = op_state.get_user_info();

  set_quota_info(user_info.bucket_quota, opt_cmd, max_size, max_objects, have_max_size, have_max_objects);

  op_state.set_bucket_quota(user_info.bucket_quota);

  string err;
  int r = user.modify(op_state, &err);
  if (r < 0) {
    cerr << "ERROR: failed updating user info: " << cpp_strerror(-r) << ": " << err << std::endl;
    return -r;
  }
  return 0;
}

int set_user_quota(int opt_cmd, RGWUser& user, RGWUserAdminOpState& op_state, int64_t max_size, int64_t max_objects,
                   bool have_max_size, bool have_max_objects)
{
  RGWUserInfo& user_info = op_state.get_user_info();

  set_quota_info(user_info.user_quota, opt_cmd, max_size, max_objects, have_max_size, have_max_objects);

  op_state.set_user_quota(user_info.user_quota);

  string err;
  int r = user.modify(op_state, &err);
  if (r < 0) {
    cerr << "ERROR: failed updating user info: " << cpp_strerror(-r) << ": " << err << std::endl;
    return -r;
  }
  return 0;
}

static bool bucket_object_check_filter(const string& name)
{
  string ns;
  string obj = name;
  string instance;
  return rgw_obj::translate_raw_obj_to_obj_in_ns(obj, instance, ns);
}

int check_min_obj_stripe_size(RGWRados *store, RGWBucketInfo& bucket_info, rgw_obj& obj, uint64_t min_stripe_size, bool *need_rewrite)
{
  map<string, bufferlist> attrs;
  uint64_t obj_size;

  RGWObjectCtx obj_ctx(store);
  RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrs;
  read_op.params.obj_size = &obj_size;

  int ret = read_op.prepare(NULL, NULL);
  if (ret < 0) {
    lderr(store->ctx()) << "ERROR: failed to stat object, returned error: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  map<string, bufferlist>::iterator iter;
  iter = attrs.find(RGW_ATTR_MANIFEST);
  if (iter == attrs.end()) {
    *need_rewrite = (obj_size >= min_stripe_size);
    return 0;
  }

  RGWObjManifest manifest;

  try {
    bufferlist& bl = iter->second;
    bufferlist::iterator biter = bl.begin();
    ::decode(manifest, biter);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode manifest" << dendl;
    return -EIO;
  }

  map<uint64_t, RGWObjManifestPart>& objs = manifest.get_explicit_objs();
  map<uint64_t, RGWObjManifestPart>::iterator oiter;
  for (oiter = objs.begin(); oiter != objs.end(); ++oiter) {
    RGWObjManifestPart& part = oiter->second;

    if (part.size >= min_stripe_size) {
      *need_rewrite = true;
      return 0;
    }
  }
  *need_rewrite = false;

  return 0;
}


int check_obj_locator_underscore(RGWBucketInfo& bucket_info, rgw_obj& obj, rgw_obj_key& key, bool fix, bool remove_bad, Formatter *f) {
  f->open_object_section("object");
  f->open_object_section("key");
  f->dump_string("type", "head");
  f->dump_string("name", key.name);
  f->dump_string("instance", key.instance);
  f->close_section();

  string oid;
  string locator;

  get_obj_bucket_and_oid_loc(obj, obj.bucket, oid, locator);

  f->dump_string("oid", oid);
  f->dump_string("locator", locator);

  
  RGWObjectCtx obj_ctx(store);

  RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);
  RGWRados::Object::Read read_op(&op_target);

  int ret = read_op.prepare(NULL, NULL);
  bool needs_fixing = (ret == -ENOENT);

  f->dump_bool("needs_fixing", needs_fixing);

  string status = (needs_fixing ? "needs_fixing" : "ok");

  if ((needs_fixing || remove_bad) && fix) {
    ret = store->fix_head_obj_locator(obj.bucket, needs_fixing, remove_bad, key);
    if (ret < 0) {
      cerr << "ERROR: fix_head_object_locator() returned ret=" << ret << std::endl;
      goto done;
    }
    status = "fixed";
  }

done:
  f->dump_string("status", status);

  f->close_section();

  return 0;
}

int check_obj_tail_locator_underscore(RGWBucketInfo& bucket_info, rgw_obj& obj, rgw_obj_key& key, bool fix, Formatter *f) {
  f->open_object_section("object");
  f->open_object_section("key");
  f->dump_string("type", "tail");
  f->dump_string("name", key.name);
  f->dump_string("instance", key.instance);
  f->close_section();

  string oid;
  string locator;

  bool needs_fixing;
  string status;

  int ret = store->fix_tail_obj_locator(obj.bucket, key, fix, &needs_fixing);
  if (ret < 0) {
    cerr << "ERROR: fix_tail_object_locator_underscore() returned ret=" << ret << std::endl;
    status = "failed";
  } else {
    status = (needs_fixing && !fix ? "needs_fixing" : "ok");
  }

  f->dump_bool("needs_fixing", needs_fixing);
  f->dump_string("status", status);

  f->close_section();

  return 0;
}

int do_check_object_locator(const string& bucket_name, bool fix, bool remove_bad, Formatter *f)
{
  if (remove_bad && !fix) {
    cerr << "ERROR: can't have remove_bad specified without fix" << std::endl;
    return -EINVAL;
  }

  RGWBucketInfo bucket_info;
  rgw_bucket bucket;
  string bucket_id;

  f->open_object_section("bucket");
  f->dump_string("bucket", bucket_name);
  int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
  if (ret < 0) {
    cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
    return ret;
  }
  bool truncated;
  int count = 0;

  int max_entries = 1000;

  string prefix;
  string delim;
  vector<RGWObjEnt> result;
  map<string, bool> common_prefixes;
  string ns;

  RGWRados::Bucket target(store, bucket);
  RGWRados::Bucket::List list_op(&target);

  string marker;

  list_op.params.prefix = prefix;
  list_op.params.delim = delim;
  list_op.params.marker = rgw_obj_key(marker);
  list_op.params.ns = ns;
  list_op.params.enforce_ns = true;
  list_op.params.list_versions = true;
  
  f->open_array_section("check_objects");
  do {
    ret = list_op.list_objects(max_entries - count, &result, &common_prefixes, &truncated);
    if (ret < 0) {
      cerr << "ERROR: store->list_objects(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    count += result.size();

    list<rgw_obj> objs;
    for (vector<RGWObjEnt>::iterator iter = result.begin(); iter != result.end(); ++iter) {
      rgw_obj_key key = iter->key;
      rgw_obj obj(bucket, key);

      if (key.name[0] == '_') {
        ret = check_obj_locator_underscore(bucket_info, obj, key, fix, remove_bad, f);
	
	if (ret >= 0) {
          ret = check_obj_tail_locator_underscore(bucket_info, obj, key, fix, f);
	}
      }
    }
    f->flush(cout);
  } while (truncated && count < max_entries);
  f->close_section();
  f->close_section();

  f->flush(cout);

  return 0;
}

#define MAX_REST_RESPONSE (128 * 1024) // we expect a very small response
int send_to_remote_gateway(const string& remote, req_info& info, JSONParser& p,
                           bufferlist &in_data)
{
  bufferlist response;
  RGWRESTConn *conn;
  if (remote.empty()) {
    if (!store->rest_master_conn) {
      cerr << "Invalid rest master connection" << std::endl;
      return -EINVAL;
    }
    conn = store->rest_master_conn;
  } else {
    map<string, RGWRESTConn *>::iterator iter = store->zonegroup_conn_map.find(remote);
    if (iter == store->zonegroup_conn_map.end()) {
      cerr << "could not find connection to: " << remote << std::endl;
      return -ENOENT;
    }
    conn = iter->second;
  }
  int ret = conn->forward("", info, NULL, MAX_REST_RESPONSE, &in_data, &response);
  if (ret < 0) {
    return ret;
  }
  ret = p.parse(response.c_str(), response.length());
  if (ret < 0) {
    cout << "failed to parse response" << std::endl;
    return ret;
  }
  return 0;
}

int send_to_url(const string& url, RGWAccessKey& key, req_info& info,
                JSONParser& p, bufferlist &in_data)
{
  list<pair<string, string> > params;
  RGWRESTSimpleRequest req(g_ceph_context, url, NULL, &params);

  bufferlist response;
  int ret = req.forward_request(key, info, MAX_REST_RESPONSE, &in_data, &response);
  if (ret < 0) {
    return ret;
  }
  ret = p.parse(response.c_str(), response.length());
  if (ret < 0) {
    cout << "failed to parse response" << std::endl;
    return ret;
  }
  return 0;
}

int main(int argc, char **argv) 
{
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);
  env_to_vec(args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  std::string user_id, access_key, secret_key, user_email, display_name;
  std::string bucket_name, pool_name, object;
  std::string date, subuser, access, format;
  std::string start_date, end_date;
  std::string key_type_str;
  std::string period_id, period_epoch, remote, url, parent_period;
  std::string master_zonegroup, master_zone;
  std::string realm_name, realm_id, realm_new_name;
  std::string zone_name, zone_id, zone_new_name;
  std::string zonegroup_name, zonegroup_id, zonegroup_new_name;
  std::string master_url;
  bool is_master = false;
  int key_type = KEY_TYPE_UNDEFINED;
  rgw_bucket bucket;
  uint32_t perm_mask = 0;
  RGWUserInfo info;
  int opt_cmd = OPT_NO_CMD;
  bool need_more;
  int gen_access_key = 0;
  int gen_secret_key = 0;
  bool set_perm = false;
  bool set_temp_url_key = false;
  map<int, string> temp_url_keys;
  string bucket_id;
  Formatter *formatter = NULL;
  int purge_data = false;
  RGWBucketInfo bucket_info;
  int pretty_format = false;
  int show_log_entries = true;
  int show_log_sum = true;
  int skip_zero_entries = false;  // log show
  int purge_keys = false;
  int yes_i_really_mean_it = false;
  int delete_child_objects = false;
  int fix = false;
  int remove_bad = false;
  int check_head_obj_locator = false;
  int max_buckets = -1;
  map<string, bool> categories;
  string caps;
  int check_objects = false;
  RGWUserAdminOpState user_op;
  RGWBucketAdminOpState bucket_op;
  string infile;
  string metadata_key;
  RGWObjVersionTracker objv_tracker;
  string marker;
  string start_marker;
  string end_marker;
  int max_entries = -1;
  int system = false;
  bool system_specified = false;
  int shard_id = -1;
  bool specified_shard_id = false;
  string daemon_id;
  bool specified_daemon_id = false;
  string client_id;
  string op_id;
  string state_str;
  string replica_log_type_str;
  ReplicaLogType replica_log_type = ReplicaLog_Invalid;
  string op_mask_str;
  string quota_scope;
  string object_version;

  int64_t max_objects = -1;
  int64_t max_size = -1;
  bool have_max_objects = false;
  bool have_max_size = false;
  int include_all = false;

  int sync_stats = false;
  int reset_regions = false;

  uint64_t min_rewrite_size = 4 * 1024 * 1024;
  uint64_t max_rewrite_size = ULLONG_MAX;
  uint64_t min_rewrite_stripe_size = 0;

  BIIndexType bi_index_type = PlainIdx;

  string job_id;
  int num_shards = 0;
  int max_concurrent_ios = 32;
  uint64_t orphan_stale_secs = (24 * 3600);

  std::string val;
  std::ostringstream errs;
  string err;
  long long tmp = 0;

  string source_zone;

  for (std::vector<const char*>::iterator i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      usage();
      return 0;
    } else if (ceph_argparse_witharg(args, i, &val, "-i", "--uid", (char*)NULL)) {
      user_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--access-key", (char*)NULL)) {
      access_key = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--subuser", (char*)NULL)) {
      subuser = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--secret", "--secret-key", (char*)NULL)) {
      secret_key = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-e", "--email", (char*)NULL)) {
      user_email = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-n", "--display-name", (char*)NULL)) {
      display_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-b", "--bucket", (char*)NULL)) {
      bucket_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-p", "--pool", (char*)NULL)) {
      pool_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-o", "--object", (char*)NULL)) {
      object = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--object-version", (char*)NULL)) {
      object_version = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--client-id", (char*)NULL)) {
      client_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--op-id", (char*)NULL)) {
      op_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--state", (char*)NULL)) {
      state_str = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--op-mask", (char*)NULL)) {
      op_mask_str = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--key-type", (char*)NULL)) {
      key_type_str = val;
      if (key_type_str.compare("swift") == 0) {
        key_type = KEY_TYPE_SWIFT;
      } else if (key_type_str.compare("s3") == 0) {
        key_type = KEY_TYPE_S3;
      } else {
        cerr << "bad key type: " << key_type_str << std::endl;
        return usage();
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--job-id", (char*)NULL)) {
      job_id = val;
    } else if (ceph_argparse_binary_flag(args, i, &gen_access_key, NULL, "--gen-access-key", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &gen_secret_key, NULL, "--gen-secret", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &show_log_entries, NULL, "--show_log_entries", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &show_log_sum, NULL, "--show_log_sum", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &skip_zero_entries, NULL, "--skip_zero_entries", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &system, NULL, "--system", (char*)NULL)) {
      system_specified = true;
    } else if (ceph_argparse_witharg(args, i, &tmp, errs, "-a", "--auth-uid", (char*)NULL)) {
      if (!errs.str().empty()) {
	cerr << errs.str() << std::endl;
	exit(EXIT_FAILURE);
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--min-rewrite-size", (char*)NULL)) {
      min_rewrite_size = (uint64_t)atoll(val.c_str());
    } else if (ceph_argparse_witharg(args, i, &val, "--max-rewrite-size", (char*)NULL)) {
      max_rewrite_size = (uint64_t)atoll(val.c_str());
    } else if (ceph_argparse_witharg(args, i, &val, "--min-rewrite-stripe-size", (char*)NULL)) {
      min_rewrite_stripe_size = (uint64_t)atoll(val.c_str());
    } else if (ceph_argparse_witharg(args, i, &val, "--max-buckets", (char*)NULL)) {
      max_buckets = (int)strict_strtol(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse max buckets: " << err << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--max-entries", (char*)NULL)) {
      max_entries = (int)strict_strtol(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse max entries: " << err << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--max-size", (char*)NULL)) {
      max_size = (int64_t)strict_strtoll(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse max size: " << err << std::endl;
        return EINVAL;
      }
      have_max_size = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--max-objects", (char*)NULL)) {
      max_objects = (int64_t)strict_strtoll(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse max objects: " << err << std::endl;
        return EINVAL;
      }
      have_max_objects = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--date", "--time", (char*)NULL)) {
      date = val;
      if (end_date.empty())
        end_date = date;
    } else if (ceph_argparse_witharg(args, i, &val, "--start-date", "--start-time", (char*)NULL)) {
      start_date = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--end-date", "--end-time", (char*)NULL)) {
      end_date = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--num-shards", (char*)NULL)) {
      num_shards = (int)strict_strtol(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse num shards: " << err << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--max-concurrent-ios", (char*)NULL)) {
      max_concurrent_ios = (int)strict_strtol(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse max concurrent ios: " << err << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--orphan-stale-secs", (char*)NULL)) {
      orphan_stale_secs = (uint64_t)strict_strtoll(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse orphan stale secs: " << err << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--shard-id", (char*)NULL)) {
      shard_id = (int)strict_strtol(val.c_str(), 10, &err);
      if (!err.empty()) {
        cerr << "ERROR: failed to parse shard id: " << err << std::endl;
        return EINVAL;
      }
      specified_shard_id = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--daemon-id", (char*)NULL)) {
      daemon_id = val;
      specified_daemon_id = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--access", (char*)NULL)) {
      access = val;
      perm_mask = rgw_str_to_perm(access.c_str());
      set_perm = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--temp-url-key", (char*)NULL)) {
      temp_url_keys[0] = val;
      set_temp_url_key = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--temp-url-key2", "--temp-url-key-2", (char*)NULL)) {
      temp_url_keys[1] = val;
      set_temp_url_key = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--bucket-id", (char*)NULL)) {
      bucket_id = val;
      if (bucket_id.empty()) {
        cerr << "bad bucket-id" << std::endl;
        return usage();
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--format", (char*)NULL)) {
      format = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--categories", (char*)NULL)) {
      string cat_str = val;
      list<string> cat_list;
      list<string>::iterator iter;
      get_str_list(cat_str, cat_list);
      for (iter = cat_list.begin(); iter != cat_list.end(); ++iter) {
	categories[*iter] = true;
      }
    } else if (ceph_argparse_binary_flag(args, i, &delete_child_objects, NULL, "--purge-objects", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &pretty_format, NULL, "--pretty-format", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &purge_data, NULL, "--purge-data", (char*)NULL)) {
      delete_child_objects = purge_data;
    } else if (ceph_argparse_binary_flag(args, i, &purge_keys, NULL, "--purge-keys", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &yes_i_really_mean_it, NULL, "--yes-i-really-mean-it", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &fix, NULL, "--fix", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &remove_bad, NULL, "--remove-bad", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &check_head_obj_locator, NULL, "--check-head-obj-locator", (char*)NULL)) {
      // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &check_objects, NULL, "--check-objects", (char*)NULL)) {
     // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &sync_stats, NULL, "--sync-stats", (char*)NULL)) {
     // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &include_all, NULL, "--include-all", (char*)NULL)) {
     // do nothing
    } else if (ceph_argparse_binary_flag(args, i, &reset_regions, NULL, "--reset-regions", (char*)NULL)) {
     // do nothing
    } else if (ceph_argparse_witharg(args, i, &val, "--caps", (char*)NULL)) {
      caps = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-i", "--infile", (char*)NULL)) {
      infile = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--metadata-key", (char*)NULL)) {
      metadata_key = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--marker", (char*)NULL)) {
      marker = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--start-marker", (char*)NULL)) {
      start_marker = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--end-marker", (char*)NULL)) {
      end_marker = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--quota-scope", (char*)NULL)) {
      quota_scope = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--replica-log-type", (char*)NULL)) {
      replica_log_type_str = val;
      replica_log_type = get_replicalog_type(replica_log_type_str);
      if (replica_log_type == ReplicaLog_Invalid) {
        cerr << "ERROR: invalid replica log type" << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--index-type", (char*)NULL)) {
      string index_type_str = val;
      bi_index_type = get_bi_index_type(index_type_str);
      if (bi_index_type == InvalidIdx) {
        cerr << "ERROR: invalid bucket index entry type" << std::endl;
        return EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, &val, "--parent", (char*)NULL)) {
      parent_period = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--master", (char*)NULL)) {
      is_master = true;
    } else if (ceph_argparse_witharg(args, i, &val, "--master-url", (char*)NULL)) {
      master_url = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--master-zonegroup", (char*)NULL)) {
      master_zonegroup = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--master-zone", (char*)NULL)) {
      master_zone = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--period", (char*)NULL)) {
      period_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--epoch", (char*)NULL)) {
      period_epoch = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--remote", (char*)NULL)) {
      remote = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--url", (char*)NULL)) {
      url = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--realm", (char*)NULL)) {
      realm_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--realm-id", (char*)NULL)) {
      realm_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--realm-new-name", (char*)NULL)) {
      realm_new_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zonegroup-id", (char*)NULL)) {
      zonegroup_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zonegroup", (char*)NULL)) {
      zonegroup_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zonegroup-new-name", (char*)NULL)) {
      zonegroup_new_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zone", (char*)NULL)) {
      zone_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zone-id", (char*)NULL)) {
      zone_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--zone-new-name", (char*)NULL)) {
      zone_new_name = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--source-zone", (char*)NULL)) {
      source_zone = val;
    } else if (strncmp(*i, "-", 1) == 0) {
      cerr << "ERROR: invalid flag " << *i << std::endl;
      return EINVAL;
    } else {
      ++i;
    }
  }

  if (args.empty()) {
    return usage();
  }
  else {
    const char *prev_cmd = NULL;
    const char *prev_prev_cmd = NULL;
    std::vector<const char*>::iterator i ;
    for (i = args.begin(); i != args.end(); ++i) {
      opt_cmd = get_cmd(*i, prev_cmd, prev_prev_cmd, &need_more);
      if (opt_cmd < 0) {
	cerr << "unrecognized arg " << *i << std::endl;
	return usage();
      }
      if (!need_more) {
	++i;
	break;
      }
      prev_prev_cmd = prev_cmd;
      prev_cmd = *i;
    }

    if (opt_cmd == OPT_NO_CMD)
      return usage();

    /* some commands may have an optional extra param */
    if (i != args.end()) {
      switch (opt_cmd) {
        case OPT_METADATA_GET:
        case OPT_METADATA_PUT:
        case OPT_METADATA_RM:
        case OPT_METADATA_LIST:
          metadata_key = *i;
          break;
        default:
          break;
      }
    }

    /* check key parameter conflict */
    if ((!access_key.empty()) && gen_access_key) {
        cerr << "ERROR: key parameter conflict, --access-key & --gen-access-key" << std::endl;
        return -EINVAL;
    }
    if ((!secret_key.empty()) && gen_secret_key) {
        cerr << "ERROR: key parameter conflict, --secret & --gen-secret" << std::endl;
        return -EINVAL;
    }
  }

  // default to pretty json
  if (format.empty()) {
    format = "json";
    pretty_format = true;
  }

  if (format ==  "xml")
    formatter = new XMLFormatter(pretty_format);
  else if (format == "json")
    formatter = new JSONFormatter(pretty_format);
  else {
    cerr << "unrecognized format: " << format << std::endl;
    return usage();
  }

  RGWStreamFlusher f(formatter, cout);

  bool raw_storage_op = (opt_cmd == OPT_ZONEGROUP_CREATE || opt_cmd == OPT_ZONEGROUP_DELETE ||
			 opt_cmd == OPT_ZONEGROUP_GET || opt_cmd == OPT_ZONEGROUP_LIST ||
                         opt_cmd == OPT_ZONEGROUP_SET || opt_cmd == OPT_ZONEGROUP_DEFAULT ||
			 opt_cmd == OPT_ZONEGROUP_RENAME ||
                         opt_cmd == OPT_ZONEGROUPMAP_GET || opt_cmd == OPT_ZONEGROUPMAP_SET ||
                         opt_cmd == OPT_ZONEGROUPMAP_UPDATE ||
			 opt_cmd == OPT_ZONE_ADD || opt_cmd == OPT_ZONE_CREATE || opt_cmd == OPT_ZONE_DELETE ||
                         opt_cmd == OPT_ZONE_GET || opt_cmd == OPT_ZONE_SET || opt_cmd == OPT_ZONE_RENAME ||
                         opt_cmd == OPT_ZONE_LIST || opt_cmd == OPT_REALM_CREATE ||
			 opt_cmd == OPT_PERIOD_PREPARE || opt_cmd == OPT_PERIOD_ACTIVATE ||
			 opt_cmd == OPT_PERIOD_DELETE || opt_cmd == OPT_PERIOD_GET ||
			 opt_cmd == OPT_PERIOD_GET_CURRENT || opt_cmd == OPT_PERIOD_LIST ||
			 opt_cmd == OPT_REALM_DELETE || opt_cmd == OPT_REALM_GET || opt_cmd == OPT_REALM_LIST ||
			 opt_cmd == OPT_REALM_LIST_PERIODS ||
			 opt_cmd == OPT_REALM_GET_DEFAULT || opt_cmd == OPT_REALM_REMOVE ||
			 opt_cmd == OPT_REALM_RENAME || opt_cmd == OPT_REALM_SET ||
			 opt_cmd == OPT_REALM_SET_DEFAULT);

  if (raw_storage_op) {
    store = RGWStoreManager::get_raw_storage(g_ceph_context);
  } else {
    store = RGWStoreManager::get_storage(g_ceph_context, false, false, false);
  }
  if (!store) {
    cerr << "couldn't init storage provider" << std::endl;
    return 5; //EIO
  }

  rgw_user_init(store);
  rgw_bucket_init(store->meta_mgr);

  StoreDestructor store_destructor(store);

  if (raw_storage_op) {
    switch (opt_cmd) {
    case OPT_PERIOD_PREPARE:
      {
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "could not init realm " << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	RGWPeriod period(g_ceph_context, store, master_zonegroup, master_zone);
	ret = period.init(realm.get_id(), realm.get_name(), false);
	if (ret < 0) {
	  cerr << "failed to init period " << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	ret = period.create();
	if (ret < 0) {
	  cerr << "ERROR: couldn't create period " << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	encode_json("period", period, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_PERIOD_DELETE:
      {
	if (period_id.empty()) {
	  cerr << "missing realm name or id" << std::endl;
	  return -EINVAL;
	}
	RGWPeriod period(g_ceph_context, store, period_id);
	int ret = period.init();
	if (ret < 0) {
	  cerr << "period.init failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = period.delete_obj();
	if (ret < 0) {
	  cerr << "ERROR: couldn't delete period: " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}

      }
      break;
    case OPT_PERIOD_GET:
      {
	if (period_id.empty()) {
	  cerr << "missing period id" << std::endl;
	  return -EINVAL;
	}
	epoch_t epoch = 0;
	if (!period_epoch.empty()) {
	  epoch = atoi(period_epoch.c_str());
	}
	RGWPeriod period(g_ceph_context, store, period_id, epoch);
	int ret = period.init();
	if (ret < 0) {
	  cerr << "period init failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	encode_json("realm", period.get_realm(), formatter);
	encode_json("period", period, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_PERIOD_GET_CURRENT:
      {
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0 ) {
	  cerr << "Error initing realm " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	string current_id = realm.get_current_period();
	if (ret < 0) {
	  cerr << "Error reading current period:" << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	formatter->open_object_section("period_get_current");
	encode_json("current_period", current_id, formatter);
	formatter->close_section();
	formatter->flush(cout);
      }
      break;
    case OPT_PERIOD_ACTIVATE:
      {
	if (period_id.empty()) {
	  cerr << "Missing period id" << std::endl;
	  return -EINVAL;
	}
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0 ) {
	  cerr << "Error initing realm " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	cerr << "realm id " << realm.get_id() << " name " << realm.get_name() << std::endl;
	ret = realm.set_current_period(period_id);
	if (ret < 0 ) {
	  cerr << "Error setting current period " << period_id << ":" << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
      }
      break;
    case OPT_PERIOD_LIST:
      {
	list<string> periods;
	int ret = store->list_periods(periods);
	if (ret < 0) {
	  cerr << "failed to list periods: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	formatter->open_object_section("periods_list");
	encode_json("periods", periods, formatter);
	formatter->close_section();
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_REALM_CREATE:
      {
	if (realm_name.empty()) {
	  cerr << "missing realm name" << std::endl;
	  return -EINVAL;
	}

	RGWRealm realm(realm_name, g_ceph_context, store);
	int ret = realm.create();
	if (ret < 0) {
	  cerr << "ERROR: couldn't create realm " << realm_name << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	encode_json("realm", realm, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_REALM_DELETE:
      {
	RGWRealm realm(realm_id, realm_name);
	if (realm_name.empty() && realm_id.empty()) {
	  cerr << "missing realm name or id" << std::endl;
	  return -EINVAL;
	}
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "realm.init failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = realm.delete_obj();
	if (ret < 0) {
	  cerr << "ERROR: couldn't : " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}

      }
      break;
    case OPT_REALM_GET:
      {
	RGWRealm realm(realm_id, realm_name);
#if 0
	if (
	  cerr << "missing realm name or id" << std::endl;
	  return -EINVAL;
	}
#endif
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  if (ret == -ENOENT && realm_name.empty() && realm_id.empty()) {
	    cerr << "missing realm name or id, or default realm not found" << std::endl;
	  } else {
	    cerr << "realm.init failed: " << cpp_strerror(-ret) << std::endl;
          }
	  return -ret;
	}
	encode_json("realm", realm, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_REALM_GET_DEFAULT:
      {
	RGWRealm realm(g_ceph_context, store);
	string default_id;
	int ret = realm.read_default_id(default_id);
	if (ret == -ENOENT) {
	  cout << "No default realm is set" << std::endl;
	  return ret;
	} else if (ret < 0) {
	  cerr << "Error reading default realm:" << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	cout << "default realm: " << default_id << std::endl;
      }
      break;
    case OPT_REALM_LIST:
      {
	RGWRealm realm(g_ceph_context, store);
	string default_id;
	int ret = realm.read_default_id(default_id);
	if (ret < 0 && ret != -ENOENT) {
	  cerr << "could not determine default realm: " << cpp_strerror(-ret) << std::endl;
	}
	list<string> realms;
	ret = store->list_realms(realms);
	if (ret < 0) {
	  cerr << "failed to list realmss: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	formatter->open_object_section("realmss_list");
	encode_json("default_info", default_id, formatter);
	encode_json("realms", realms, formatter);
	formatter->close_section();
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_REALM_LIST_PERIODS:
      {
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "realm.init failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	string current_period = realm.get_current_period();
	list<string> periods;
	ret = store->list_periods(current_period, periods);
	if (ret < 0) {
	  cerr << "list periods failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}	
	formatter->open_object_section("realm_periods_list");
	encode_json("current_period", current_period, formatter);
	encode_json("periods", periods, formatter);
	formatter->close_section();
	formatter->flush(cout);
	cout << std::endl;
      }
      break;

    case OPT_REALM_RENAME:
      {
	RGWRealm realm(realm_id, realm_name);
	if (realm_new_name.empty()) {
	  cerr << "missing realm new name" << std::endl;
	  return -EINVAL;
	}
	if (realm_name.empty() && realm_id.empty()) {
	  cerr << "missing realm name or id" << std::endl;
	  return -EINVAL;
	}
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "realm.init failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = realm.rename(realm_new_name);
	if (ret < 0) {
	  cerr << "realm.rename failed: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
      }
      break;
    case OPT_REALM_SET:
      {
	if (realm_id.empty() && realm_name.empty()) {
	  cerr << "no realm name or id provided" << std::endl;
	  return -EINVAL;
	}
        if (infile.empty()) {
	  cerr << "no realm input file provided" << std::endl;
	  return -EINVAL;
        }
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store, false);
	if (ret < 0) {
	  cerr << "failed to init realm: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = read_decode_json(infile, realm);
	if (ret < 0) {
	  return 1;
	}
	ret = realm.update();
	if (ret < 0) {
	  cerr << "ERROR: couldn't store realm info: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	}
	encode_json("realm", realm, formatter);
	formatter->flush(cout);
      }
      break;

    case OPT_REALM_SET_DEFAULT:
      {
	RGWRealm realm(realm_id, realm_name);
	int ret = realm.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to init realm: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = realm.set_as_default();
	if (ret < 0) {
	  cerr << "failed to set realm as default: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
      }
      break;
    case OPT_ZONEGROUP_CREATE:
      {
	if (zonegroup_name.empty()) {
	  cerr << " Missing zonegroup name" << std::endl;
	  return -EINVAL;
	}
	RGWZoneGroup zonegroup(zonegroup_name, is_master, g_ceph_context, store);
	int ret = zonegroup.create();
	if (ret < 0) {
	  cerr << "failed to create zonegroup" << zonegroup_name << ": " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

	encode_json("zonegroup", zonegroup, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_ZONEGROUP_DEFAULT:
      {
	RGWZoneGroup zonegroup;
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

	ret = zonegroup.set_as_default();
	if (ret < 0) {
	  cerr << "failed to set zonegroup as default: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
      }
      break;
    case OPT_ZONEGROUP_DELETE:
      {
	if (zonegroup_id.empty() && zonegroup_name.empty()) {
	  cerr << "no zonegroup name or id provided" << std::endl;
	  return -EINVAL;
	}
	RGWZoneGroup zonegroup(zonegroup_id, zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zonegroup.delete_obj();
	if (ret < 0) {
	  cerr << "ERROR: couldn't delete zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
      }
      break;
    case OPT_ZONEGROUP_GET:
      {
	if (zonegroup_id.empty() && zonegroup_name.empty()) {
	  cerr << "no zonegroup name or id provided" << std::endl;
	  return -EINVAL;
	}

	RGWZoneGroup zonegroup(zonegroup_id, zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

	encode_json("zonegroup", zonegroup, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_ZONEGROUP_LIST:
      {
	RGWZoneGroup zonegroup;
	int ret = zonegroup.init(g_ceph_context, store, false);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

	list<string> zonegroups;
	ret = store->list_zonegroups(zonegroups);
	if (ret < 0) {
	  cerr << "failed to list zonegroups: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	string default_zonegroup;
	ret = zonegroup.read_default_id(default_zonegroup);
	if (ret < 0 && ret != -ENOENT) {
	  cerr << "could not determine default zonegroup: " << cpp_strerror(-ret) << std::endl;
	}
	formatter->open_object_section("zonegroups_list");
	encode_json("default_info", default_zonegroup, formatter);
	encode_json("zonegroups", zonegroups, formatter);
	formatter->close_section();
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_ZONEGROUP_SET:
      {
	RGWZoneGroup zonegroup;
	int ret = zonegroup.init(g_ceph_context, store, false);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = read_decode_json(infile, zonegroup);
	if (ret < 0) {
	  return 1;
	}
	ret = zonegroup.create();
	if (ret < 0 && ret != -EEXIST) {
	  cerr << "ERROR: couldn't create zonegroup info: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	} else if (ret == -EEXIST) {
	  ret = zonegroup.update();
	  if (ret < 0) {
	    cerr << "ERROR: couldn't store zonegroup info: " << cpp_strerror(-ret) << std::endl;
	    return 1;
	  }
	}
	encode_json("zonegroup", zonegroup, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONEGROUP_RENAME:
      {
	if (zonegroup_new_name.empty()) {
	  cerr << " missing zonegroup new name" << std::endl;
	  return -EINVAL;
	}
	if (zonegroup_id.empty() && zonegroup_name.empty()) {
	  cerr << "no zonegroup name or id provided" << std::endl;
	  return -EINVAL;
	}
	RGWZoneGroup zonegroup(zonegroup_id, zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zonegroup.rename(zonegroup_new_name);
	if (ret < 0) {
	  cerr << "failed to rename zonegroup: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
      }
      break;
    case OPT_ZONEGROUPMAP_GET:
      {
	RGWZoneGroupMap zonegroupmap;
	int ret = zonegroupmap.read(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to read zonegroup map: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	encode_json("zonegroup-map", zonegroupmap, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONEGROUPMAP_SET:
      {
	RGWZoneGroupMap zonegroupmap;
	int ret = read_decode_json(infile, zonegroupmap);
	if (ret < 0) {
	  return 1;
	}

	ret = zonegroupmap.store(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "ERROR: couldn't store zonegroup map info: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	}

	encode_json("zonegroup-map", zonegroupmap, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONEGROUPMAP_UPDATE:
      {
	RGWZoneGroupMap zonegroupmap;
	int ret = zonegroupmap.read(g_ceph_context, store);
	if (ret < 0 && ret != -ENOENT) {
	  cerr << "failed to read zonegroup map: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

        if (reset_regions) {
          zonegroupmap.zonegroups.clear();
        }

	list<string> zonegroups;
	ret = store->list_zonegroups(zonegroups);
	if (ret < 0) {
	  cerr << "failed to list zonegroups: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}

	for (list<string>::iterator iter = zonegroups.begin(); iter != zonegroups.end(); ++iter) {
	  RGWZoneGroup zonegroup(*iter);
	  ret = zonegroup.init(g_ceph_context, store);
	  if (ret < 0) {
	    cerr << "failed to init zonegroup: " << cpp_strerror(-ret) << std::endl;
	    return -ret;
	  }
	  zonegroupmap.update(zonegroup);
	}

	ret = zonegroupmap.store(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "ERROR: couldn't store zonegroup map info: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	}

	encode_json("zonegroup-map", zonegroupmap, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONE_ADD:
      {
	RGWZoneGroup zonegroup(zonegroup_id,zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "failed to initialize zonegroup " << zonegroup_name << " id " << zonegroup_id << " :"
	       << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	RGWZoneParams zone(zone_id, zone_name);
	ret = zone.init(g_ceph_context, store, zonegroup);
	if (ret < 0) {
	  cerr << "unable to initialize zone: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zonegroup.add_zone(zone);
	if (ret < 0) {
	  cerr << "failed to add zone " << zone_name << " to zonegroup " << zonegroup.get_name() << ": "
	       << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
      }
      break;
    case OPT_ZONE_CREATE:
      {
	int ret;
	RGWZoneGroup zonegroup(zonegroup_id, zonegroup_name);
	if (!zonegroup_id.empty() || !zonegroup_name.empty()) {
	  ret = zonegroup.init(g_ceph_context, store);
	  if (ret < 0) {
	    cerr << "unable to initialize zonegroup " << zonegroup_name << ": " << cpp_strerror(-ret) << std::endl;
	    return ret;
	  }
	}
	RGWZoneParams zone(zone_name, is_master);
	ret = zone.init(g_ceph_context, store, false);
	if (ret < 0) {
	  cerr << "unable to initialize zone: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zone.create();
	if (ret < 0) {
	  cerr << "failed to create zone " << zone_name << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	if (!zonegroup_id.empty() || !zonegroup_name.empty()) {
	  ret = zonegroup.add_zone(zone);
	  if (ret < 0) {
	    cerr << "failed to add zone " << zone_name << " to zonegroup " << zonegroup.get_name() << ": "
		 << cpp_strerror(-ret) << std::endl;
	    return ret;
	  }
	}
	encode_json("zone", zone, formatter);
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
   case OPT_ZONE_DELETE:
      {
	RGWZoneGroup zonegroup(zonegroup_id,zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "WARNING: failed to initialize zonegroup " << zonegroup_name << std::endl;
	}
	if (zone_id.empty() && zone_name.empty()) {
	  cerr << "no zone name or id provided" << std::endl;
	  return -EINVAL;
	}
	RGWZoneParams zone(zone_id, zone_name);
	ret = zone.init(g_ceph_context, store, zonegroup);
	if (ret < 0) {
	  cerr << "unable to initialize zone: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zonegroup.remove_zone(zone);
	if (ret < 0 && ret != -ENOENT) {
	  cerr << "failed to remove zone " << zone_name << " from zonegroup " << zonegroup.get_name() << ": "
	       << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
	ret = zone.delete_obj();
	if (ret < 0) {
	  cerr << "failed to create zone " << zone_name << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
      }
      break;
    case OPT_ZONE_GET:
      {
	RGWZoneGroup zonegroup(zonegroup_id,zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "WARNING: failed to initialize zonegroup" << std::endl;
	}
	RGWZoneParams zone;
	ret = zone.init(g_ceph_context, store, zonegroup);
	if (ret < 0) {
	  cerr << "unable to initialize zone: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	encode_json("zone", zone, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONE_SET:
      {
	RGWZoneGroup zonegroup(zonegroup_id,zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "WARNING: failed to initialize zonegroup" << std::endl;
	}
	RGWZoneParams zone;
	ret = zone.init(g_ceph_context, store, zonegroup, false);
	if (ret < 0) {
	  return 1;
	}
	ret = read_decode_json(infile, zone);
	if (ret < 0) {
	  return 1;
	}
	if (zone.get_name().empty() && zone.get_id().empty()) {
	  cerr << "ERROR: missing zone name " << cpp_strerror(-ret) << std::endl;
	  return 1;
	}
	ret = zone.create();
	if (ret < 0 && ret != -EEXIST) {
	  cerr << "ERROR: couldn't create zone: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	} else if (ret == -EEXIST) {
	  ret = zone.update();
	  if (ret < 0) {
	    cerr << "ERROR: couldn't update zone: " << cpp_strerror(-ret) << std::endl;
	    return 1;
	  }
	}
	ret = zonegroup.add_zone(zone);
	if (ret < 0) {
	  cerr << "ERROR: couldn't add zone: " << cpp_strerror(-ret) << std::endl;
	  return 1;
	}
	encode_json("zone", zone, formatter);
	formatter->flush(cout);
      }
      break;
    case OPT_ZONE_LIST:
      {
	list<string> zones;
	int ret = store->list_zones(zones);
	if (ret < 0) {
	  cerr << "failed to list zones: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	formatter->open_object_section("zones_list");
	encode_json("zones", zones, formatter);
	formatter->close_section();
	formatter->flush(cout);
	cout << std::endl;
      }
      break;
    case OPT_ZONE_RENAME:
      {
	RGWZoneGroup zonegroup(zonegroup_id,zonegroup_name);
	int ret = zonegroup.init(g_ceph_context, store);
	if (ret < 0) {
	  cerr << "WARNING: failed to initialize zonegroup " << zonegroup_name << std::endl;
	}
	if (zone_new_name.empty()) {
	  cerr << " missing zone new name" << std::endl;
	  return -EINVAL;
	}
	if (zone_id.empty() && zone_name.empty()) {
	  cerr << "no zonegroup name or id provided" << std::endl;
	  return -EINVAL;
	}
	RGWZoneParams zone(zone_id,zone_name);
	ret = zone.init(g_ceph_context, store, zonegroup);
	if (ret < 0) {
	  cerr << "unable to initialize zone: " << cpp_strerror(-ret) << std::endl;
	  return -ret;
	}
	ret = zone.rename(zone_new_name);
	if (ret < 0) {
	  cerr << "failed to create zone " << zone_name << ": " << cpp_strerror(-ret) << std::endl;
	  return ret;
	}
      }
      break;
    }
    return 0;
  }

  if (!user_id.empty()) {
    user_op.set_user_id(user_id);
    bucket_op.set_user_id(user_id);
  }

  if (!display_name.empty())
    user_op.set_display_name(display_name);

  if (!user_email.empty())
    user_op.set_user_email(user_email);

  if (!access_key.empty())
    user_op.set_access_key(access_key);

  if (!secret_key.empty())
    user_op.set_secret_key(secret_key);

  if (!subuser.empty())
    user_op.set_subuser(subuser);

  if (!caps.empty())
    user_op.set_caps(caps);

  user_op.set_purge_data(purge_data);

  if (purge_keys)
    user_op.set_purge_keys();

  if (gen_access_key)
    user_op.set_generate_key();

  if (gen_secret_key)
    user_op.set_gen_secret(); // assume that a key pair should be created

  if (max_buckets >= 0)
    user_op.set_max_buckets(max_buckets);

  if (system_specified)
    user_op.set_system(system);

  if (set_perm)
    user_op.set_perm(perm_mask);

  if (set_temp_url_key) {
    map<int, string>::iterator iter = temp_url_keys.begin();
    for (; iter != temp_url_keys.end(); ++iter) {
      user_op.set_temp_url_key(iter->second, iter->first);
    }
  }

  if (!op_mask_str.empty()) {
    uint32_t op_mask;
    int ret = rgw_parse_op_type_list(op_mask_str, &op_mask);
    if (ret < 0) {
      cerr << "failed to parse op_mask: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    user_op.set_op_mask(op_mask);
  }

  if (key_type != KEY_TYPE_UNDEFINED)
    user_op.set_key_type(key_type);

  // set suspension operation parameters
  if (opt_cmd == OPT_USER_ENABLE)
    user_op.set_suspension(false);
  else if (opt_cmd == OPT_USER_SUSPEND)
    user_op.set_suspension(true);

  // RGWUser to use for user operations
  RGWUser user;
  int ret = 0;
  if (!user_id.empty() || !subuser.empty()) {
    ret = user.init(store, user_op);
    if (ret < 0) {
      cerr << "user.init failed: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  /* populate bucket operation */
  bucket_op.set_bucket_name(bucket_name);
  bucket_op.set_object(object);
  bucket_op.set_check_objects(check_objects);
  bucket_op.set_delete_children(delete_child_objects);

  // required to gather errors from operations
  std::string err_msg;

  bool output_user_info = true;

  switch (opt_cmd) {
  case OPT_USER_INFO:
    break;
  case OPT_USER_CREATE:
    if (!user_op.has_existing_user()) {
      user_op.set_generate_key(); // generate a new key by default
    }
    ret = user.add(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not create user: " << err_msg << std::endl;
      return -ret;
    }
    if (!subuser.empty()) {
      ret = user.subusers.add(user_op, &err_msg);
      if (ret < 0) {
        cerr << "could not create subuser: " << err_msg << std::endl;
        return -ret;
      }
    }
    break;
  case OPT_USER_RM:
    ret = user.remove(user_op, &err_msg);
    if (ret == -ENOENT) {
      cerr << err_msg << std::endl;
    } else if (ret < 0) {
      cerr << "could not remove user: " << err_msg << std::endl;
      return -ret;
    }

    output_user_info = false;
    break;
  case OPT_USER_ENABLE:
  case OPT_USER_SUSPEND:
  case OPT_USER_MODIFY:
    ret = user.modify(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not modify user: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_SUBUSER_CREATE:
    ret = user.subusers.add(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not create subuser: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_SUBUSER_MODIFY:
    ret = user.subusers.modify(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not modify subuser: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_SUBUSER_RM:
    ret = user.subusers.remove(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not remove subuser: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_CAPS_ADD:
    ret = user.caps.add(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not add caps: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_CAPS_RM:
    ret = user.caps.remove(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not add remove caps: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_KEY_CREATE:
    ret = user.keys.add(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not create key: " << err_msg << std::endl;
      return -ret;
    }

    break;
  case OPT_KEY_RM:
    ret = user.keys.remove(user_op, &err_msg);
    if (ret < 0) {
      cerr << "could not remove key: " << err_msg << std::endl;
      return -ret;
    }
  case OPT_PERIOD_PUSH:
    {
      RGWEnv env;
      req_info info(g_ceph_context, &env);
      info.method = "POST";
      info.request_uri = "/admin/realm/period";

      map<string, string> &params = info.args.get_params();
      if (!period_id.empty())
        params["period_id"] = period_id;
      if (!period_epoch.empty())
        params["epoch"] = period_epoch;

      // load the period
      RGWPeriod period(g_ceph_context, store, period_id);
      int ret = period.init();
      if (ret < 0) {
        cerr << "period init failed: " << cpp_strerror(-ret) << std::endl;
        return ret;
      }
      // json format into a bufferlist
      JSONFormatter jf(false);
      encode_json("period", period, &jf);
      bufferlist bl;
      jf.flush(bl);

      JSONParser p;
      ret = send_to_remote_gateway(url, info, p, bl);
      if (ret < 0) {
        cerr << "request failed: " << cpp_strerror(-ret) << std::endl;
        return ret;
      }
    }
    return 0;
  case OPT_PERIOD_PULL:
    {
      RGWEnv env;
      req_info info(g_ceph_context, &env);
      info.method = "GET";
      info.request_uri = "/admin/realm/period";

      map<string, string> &params = info.args.get_params();
      if (!period_id.empty())
        params["period_id"] = period_id;
      if (!period_epoch.empty())
        params["epoch"] = period_epoch;

      int ret = 0;

      bufferlist bl;
      JSONParser p;
      if (!url.empty()) {
        if (access_key.empty() || secret_key.empty()) {
          cerr << "An --access-key and --secret must be provided with --url." << std::endl;
          return -EINVAL;
        }
        RGWAccessKey key;
        key.id = access_key;
        key.key = secret_key;
        ret = send_to_url(url, key, info, p, bl);
      } else {
        ret = send_to_remote_gateway(remote, info, p, bl);
      }
      if (ret < 0) {
        cerr << "request failed: " << cpp_strerror(-ret) << std::endl;
        return ret;
      }
      RGWPeriod period(g_ceph_context, store);
      try {
        decode_json_obj(period, &p);
      } catch (JSONDecoder::err& e) {
        cout << "failed to decode JSON input: " << e.message << std::endl;
        return -EINVAL;
      }
      ret = period.store_info(false);
      if (ret < 0) {
        cerr << "Error storing period " << period.get_id() << ": " << cpp_strerror(ret) << std::endl;
      }

      encode_json("period", period, formatter);
      formatter->flush(cout);
      cout << std::endl;
    }
    return 0;
  default:
    output_user_info = false;
  }

  // output the result of a user operation
  if (output_user_info) {
    ret = user.info(info, &err_msg);
    if (ret < 0) {
      cerr << "could not fetch user info: " << err_msg << std::endl;
      return -ret;
    }
    show_user_info(info, formatter);
  }

  if (opt_cmd == OPT_POLICY) {
    int ret = RGWBucketAdminOp::get_policy(store, bucket_op, cout);
    if (ret >= 0) {
      cout << std::endl;
    }
  }

  if (opt_cmd == OPT_BUCKETS_LIST) {
    if (bucket_name.empty()) {
      RGWBucketAdminOp::info(store, bucket_op, f);
    } else {
      RGWBucketInfo bucket_info;
      int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
      if (ret < 0) {
        cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
      formatter->open_array_section("entries");
      bool truncated;
      int count = 0;
      if (max_entries < 0)
        max_entries = 1000;

      string prefix;
      string delim;
      vector<RGWObjEnt> result;
      map<string, bool> common_prefixes;
      string ns;

      RGWRados::Bucket target(store, bucket);
      RGWRados::Bucket::List list_op(&target);

      list_op.params.prefix = prefix;
      list_op.params.delim = delim;
      list_op.params.marker = rgw_obj_key(marker);
      list_op.params.ns = ns;
      list_op.params.enforce_ns = false;
      list_op.params.list_versions = true;
      
      do {
        ret = list_op.list_objects(max_entries - count, &result, &common_prefixes, &truncated);
        if (ret < 0) {
          cerr << "ERROR: store->list_objects(): " << cpp_strerror(-ret) << std::endl;
          return -ret;
        }

        count += result.size();

        for (vector<RGWObjEnt>::iterator iter = result.begin(); iter != result.end(); ++iter) {
          RGWObjEnt& entry = *iter;
          encode_json("entry", entry, formatter);
        }
        formatter->flush(cout);
      } while (truncated && count < max_entries);

      formatter->close_section();
      formatter->flush(cout);
    }
  }

  if (opt_cmd == OPT_BUCKET_STATS) {
    bucket_op.set_fetch_stats(true);

    RGWBucketAdminOp::info(store, bucket_op, f);
  }

  if (opt_cmd == OPT_BUCKET_LINK) {
    bucket_op.set_bucket_id(bucket_id);
    string err;
    int r = RGWBucketAdminOp::link(store, bucket_op, &err);
    if (r < 0) {
      cerr << "failure: " << cpp_strerror(-r) << ": " << err << std::endl;
      return -r;
    }
  }

  if (opt_cmd == OPT_BUCKET_UNLINK) {
    int r = RGWBucketAdminOp::unlink(store, bucket_op);
    if (r < 0) {
      cerr << "failure: " << cpp_strerror(-r) << std::endl;
      return -r;
    }
  }

  if (opt_cmd == OPT_LOG_LIST) {
    // filter by date?
    if (date.size() && date.size() != 10) {
      cerr << "bad date format for '" << date << "', expect YYYY-MM-DD" << std::endl;
      return -EINVAL;
    }

    formatter->reset();
    formatter->open_array_section("logs");
    RGWAccessHandle h;
    int r = store->log_list_init(date, &h);
    if (r == -ENOENT) {
      // no logs.
    } else {
      if (r < 0) {
	cerr << "log list: error " << r << std::endl;
	return r;
      }
      while (true) {
	string name;
	int r = store->log_list_next(h, &name);
	if (r == -ENOENT)
	  break;
	if (r < 0) {
	  cerr << "log list: error " << r << std::endl;
	  return r;
	}
	formatter->dump_string("object", name);
      }
    }
    formatter->close_section();
    formatter->flush(cout);
    cout << std::endl;
  }

  if (opt_cmd == OPT_LOG_SHOW || opt_cmd == OPT_LOG_RM) {
    if (object.empty() && (date.empty() || bucket_name.empty() || bucket_id.empty())) {
      cerr << "specify an object or a date, bucket and bucket-id" << std::endl;
      return usage();
    }

    string oid;
    if (!object.empty()) {
      oid = object;
    } else {
      oid = date;
      oid += "-";
      oid += bucket_id;
      oid += "-";
      oid += bucket_name;
    }

    if (opt_cmd == OPT_LOG_SHOW) {
      RGWAccessHandle h;

      int r = store->log_show_init(oid, &h);
      if (r < 0) {
	cerr << "error opening log " << oid << ": " << cpp_strerror(-r) << std::endl;
	return -r;
      }

      formatter->reset();
      formatter->open_object_section("log");

      struct rgw_log_entry entry;
      
      // peek at first entry to get bucket metadata
      r = store->log_show_next(h, &entry);
      if (r < 0) {
	cerr << "error reading log " << oid << ": " << cpp_strerror(-r) << std::endl;
	return -r;
      }
      formatter->dump_string("bucket_id", entry.bucket_id);
      formatter->dump_string("bucket_owner", entry.bucket_owner);
      formatter->dump_string("bucket", entry.bucket);

      uint64_t agg_time = 0;
      uint64_t agg_bytes_sent = 0;
      uint64_t agg_bytes_received = 0;
      uint64_t total_entries = 0;

      if (show_log_entries)
        formatter->open_array_section("log_entries");

      do {
	uint64_t total_time =  entry.total_time.sec() * 1000000LL * entry.total_time.usec();

        agg_time += total_time;
        agg_bytes_sent += entry.bytes_sent;
        agg_bytes_received += entry.bytes_received;
        total_entries++;

        if (skip_zero_entries && entry.bytes_sent == 0 &&
            entry.bytes_received == 0)
          goto next;

        if (show_log_entries) {

	  rgw_format_ops_log_entry(entry, formatter);
	  formatter->flush(cout);
        }
next:
	r = store->log_show_next(h, &entry);
      } while (r > 0);

      if (r < 0) {
      	cerr << "error reading log " << oid << ": " << cpp_strerror(-r) << std::endl;
	return -r;
      }
      if (show_log_entries)
        formatter->close_section();

      if (show_log_sum) {
        formatter->open_object_section("log_sum");
	formatter->dump_int("bytes_sent", agg_bytes_sent);
	formatter->dump_int("bytes_received", agg_bytes_received);
	formatter->dump_int("total_time", agg_time);
	formatter->dump_int("total_entries", total_entries);
        formatter->close_section();
      }
      formatter->close_section();
      formatter->flush(cout);
      cout << std::endl;
    }
    if (opt_cmd == OPT_LOG_RM) {
      int r = store->log_remove(oid);
      if (r < 0) {
	cerr << "error removing log " << oid << ": " << cpp_strerror(-r) << std::endl;
	return -r;
      }
    }
  }
  
  if (opt_cmd == OPT_POOL_ADD) {
    if (pool_name.empty()) {
      cerr << "need to specify pool to add!" << std::endl;
      return usage();
    }

    int ret = store->add_bucket_placement(pool_name);
    if (ret < 0)
      cerr << "failed to add bucket placement: " << cpp_strerror(-ret) << std::endl;
  }

  if (opt_cmd == OPT_POOL_RM) {
    if (pool_name.empty()) {
      cerr << "need to specify pool to remove!" << std::endl;
      return usage();
    }

    int ret = store->remove_bucket_placement(pool_name);
    if (ret < 0)
      cerr << "failed to remove bucket placement: " << cpp_strerror(-ret) << std::endl;
  }

  if (opt_cmd == OPT_POOLS_LIST) {
    set<string> pools;
    int ret = store->list_placement_set(pools);
    if (ret < 0) {
      cerr << "could not list placement set: " << cpp_strerror(-ret) << std::endl;
      return ret;
    }
    formatter->reset();
    formatter->open_array_section("pools");
    set<string>::iterator siter;
    for (siter = pools.begin(); siter != pools.end(); ++siter) {
      formatter->open_object_section("pool");
      formatter->dump_string("name",  *siter);
      formatter->close_section();
    }
    formatter->close_section();
    formatter->flush(cout);
    cout << std::endl;
  }

  if (opt_cmd == OPT_USAGE_SHOW) {
    uint64_t start_epoch = 0;
    uint64_t end_epoch = (uint64_t)-1;

    int ret;
    
    if (!start_date.empty()) {
      ret = utime_t::parse_date(start_date, &start_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse start date" << std::endl;
        return 1;
      }
    }
    if (!end_date.empty()) {
      ret = utime_t::parse_date(end_date, &end_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse end date" << std::endl;
        return 1;
      }
    }


    ret = RGWUsage::show(store, user_id, start_epoch, end_epoch,
			 show_log_entries, show_log_sum, &categories,
			 f);
    if (ret < 0) {
      cerr << "ERROR: failed to show usage" << std::endl;
      return 1;
    }
  }

  if (opt_cmd == OPT_USAGE_TRIM) {
    if (user_id.empty() && !yes_i_really_mean_it) {
      cerr << "usage trim without user specified will remove *all* users data" << std::endl;
      cerr << "do you really mean it? (requires --yes-i-really-mean-it)" << std::endl;
      return 1;
    }
    int ret;
    uint64_t start_epoch = 0;
    uint64_t end_epoch = (uint64_t)-1;


    if (!start_date.empty()) {
      ret = utime_t::parse_date(start_date, &start_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse start date" << std::endl;
        return 1;
      }
    }

    if (!end_date.empty()) {
      ret = utime_t::parse_date(end_date, &end_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse end date" << std::endl;
        return 1;
      }
    }

    ret = RGWUsage::trim(store, user_id, start_epoch, end_epoch);
    if (ret < 0) {
      cerr << "ERROR: read_usage() returned ret=" << ret << std::endl;
      return 1;
    }   
  }

  if (opt_cmd == OPT_OLH_GET || opt_cmd == OPT_OLH_READLOG) {
    if (bucket_name.empty()) {
      cerr << "ERROR: bucket not specified" << std::endl;
      return EINVAL;
    }
    if (object.empty()) {
      cerr << "ERROR: object not specified" << std::endl;
      return EINVAL;
    }
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_OLH_GET) {
    RGWOLHInfo olh;
    rgw_obj obj(bucket, object);
    int ret = store->get_olh(obj, &olh);
    if (ret < 0) {
      cerr << "ERROR: failed reading olh: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    encode_json("olh", olh, formatter);
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_OLH_READLOG) {
    map<uint64_t, vector<rgw_bucket_olh_log_entry> > log;
    bool is_truncated;

    RGWObjectCtx rctx(store);
    rgw_obj obj(bucket, object);

    RGWObjState *state;

    int ret = store->get_obj_state(&rctx, obj, &state, false); /* don't follow olh */
    if (ret < 0) {
      return ret;
    }

    ret = store->bucket_index_read_olh_log(*state, obj, 0, &log, &is_truncated);
    if (ret < 0) {
      cerr << "ERROR: failed reading olh: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    formatter->open_object_section("result");
    encode_json("is_truncated", is_truncated, formatter);
    encode_json("log", log, formatter);
    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_BI_GET) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    rgw_obj obj(bucket, object);
    if (!object_version.empty()) {
      obj.set_instance(object_version);
    }

    rgw_cls_bi_entry entry;

    ret = store->bi_get(bucket, obj, bi_index_type, &entry);
    if (ret < 0) {
      cerr << "ERROR: bi_get(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    encode_json("entry", entry, formatter);
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_BI_PUT) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    rgw_cls_bi_entry entry;
    cls_rgw_obj_key key;
    ret = read_decode_json(infile, entry, &key);
    if (ret < 0) {
      return 1;
    }

    rgw_obj obj(bucket, key.name);
    obj.set_instance(key.instance);

    ret = store->bi_put(bucket, obj, entry);
    if (ret < 0) {
      cerr << "ERROR: bi_put(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_BI_LIST) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    list<rgw_cls_bi_entry> entries;
    bool is_truncated;
    if (max_entries < 0) {
      max_entries = 1000;
    }


    formatter->open_array_section("entries");

    do {
      entries.clear();
      ret = store->bi_list(bucket, object, marker, max_entries, &entries, &is_truncated);
      if (ret < 0) {
        cerr << "ERROR: bi_list(): " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      list<rgw_cls_bi_entry>::iterator iter;
      for (iter = entries.begin(); iter != entries.end(); ++iter) {
        rgw_cls_bi_entry& entry = *iter;
        encode_json("entry", entry, formatter);
        marker = entry.idx;
      }
      formatter->flush(cout);
    } while (is_truncated);
    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_OBJECT_RM) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    rgw_obj_key key(object, object_version);
    ret = rgw_remove_object(store, bucket_info, bucket, key);

    if (ret < 0) {
      cerr << "ERROR: object remove returned: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_OBJECT_REWRITE) {
    if (bucket_name.empty()) {
      cerr << "ERROR: bucket not specified" << std::endl;
      return EINVAL;
    }
    if (object.empty()) {
      cerr << "ERROR: object not specified" << std::endl;
      return EINVAL;
    }

    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    rgw_obj obj(bucket, object);
    obj.set_instance(object_version);
    bool need_rewrite = true;
    if (min_rewrite_stripe_size > 0) {
      ret = check_min_obj_stripe_size(store, bucket_info, obj, min_rewrite_stripe_size, &need_rewrite);
      if (ret < 0) {
        ldout(store->ctx(), 0) << "WARNING: check_min_obj_stripe_size failed, r=" << ret << dendl;
      }
    }
    if (need_rewrite) {
      ret = store->rewrite_obj(bucket_info, obj);
      if (ret < 0) {
        cerr << "ERROR: object rewrite returned: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    } else {
      ldout(store->ctx(), 20) << "skipped object" << dendl;
    }
  }

  if (opt_cmd == OPT_OBJECTS_EXPIRE) {
    int ret = store->process_expire_objects();
    if (ret < 0) {
      cerr << "ERROR: process_expire_objects() processing returned error: " << cpp_strerror(-ret) << std::endl;
      return 1;
    }
  }

  if (opt_cmd == OPT_BUCKET_REWRITE) {
    if (bucket_name.empty()) {
      cerr << "ERROR: bucket not specified" << std::endl;
      return EINVAL;
    }

    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    uint64_t start_epoch = 0;
    uint64_t end_epoch = 0;

    if (!end_date.empty()) {
      int ret = utime_t::parse_date(end_date, &end_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse end date" << std::endl;
        return EINVAL;
      }
    }
    if (!start_date.empty()) {
      int ret = utime_t::parse_date(start_date, &start_epoch, NULL);
      if (ret < 0) {
        cerr << "ERROR: failed to parse start date" << std::endl;
        return EINVAL;
      }
    }

    bool is_truncated = true;

    rgw_obj_key marker;
    string prefix;

    formatter->open_object_section("result");
    formatter->dump_string("bucket", bucket_name);
    formatter->open_array_section("objects");
    while (is_truncated) {
      map<string, RGWObjEnt> result;
      int r = store->cls_bucket_list(bucket, RGW_NO_SHARD, marker, prefix, 1000, true,
                                     result, &is_truncated, &marker,
                                     bucket_object_check_filter);

      if (r < 0 && r != -ENOENT) {
        cerr << "ERROR: failed operation r=" << r << std::endl;
      }

      if (r == -ENOENT)
        break;

      map<string, RGWObjEnt>::iterator iter;
      for (iter = result.begin(); iter != result.end(); ++iter) {
        rgw_obj_key key = iter->second.key;
        RGWObjEnt& entry = iter->second;

        formatter->open_object_section("object");
        formatter->dump_string("name", key.name);
        formatter->dump_string("instance", key.instance);
        formatter->dump_int("size", entry.size);
        utime_t ut(entry.mtime, 0);
        ut.gmtime(formatter->dump_stream("mtime"));

        if ((entry.size < min_rewrite_size) ||
            (entry.size > max_rewrite_size) ||
            (start_epoch > 0 && start_epoch > (uint64_t)ut.sec()) ||
            (end_epoch > 0 && end_epoch < (uint64_t)ut.sec())) {
          formatter->dump_string("status", "Skipped");
        } else {
          rgw_obj obj(bucket, key.name);
          obj.set_instance(key.instance);

          bool need_rewrite = true;
          if (min_rewrite_stripe_size > 0) {
            r = check_min_obj_stripe_size(store, bucket_info, obj, min_rewrite_stripe_size, &need_rewrite);
            if (r < 0) {
              ldout(store->ctx(), 0) << "WARNING: check_min_obj_stripe_size failed, r=" << r << dendl;
            }
          }
          if (!need_rewrite) {
            formatter->dump_string("status", "Skipped");
          } else {
            r = store->rewrite_obj(bucket_info, obj);
            if (r == 0) {
              formatter->dump_string("status", "Success");
            } else {
              formatter->dump_string("status", cpp_strerror(-r));
            }
          }
        }
        formatter->dump_int("flags", entry.flags);

        formatter->close_section();
        formatter->flush(cout);
      }
    }
    formatter->close_section();
    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_OBJECT_UNLINK) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    list<rgw_obj_key> oid_list;
    rgw_obj_key key(object, object_version);
    oid_list.push_back(key);
    ret = store->remove_objs_from_index(bucket, oid_list);
    if (ret < 0) {
      cerr << "ERROR: remove_obj_from_index() returned error: " << cpp_strerror(-ret) << std::endl;
      return 1;
    }
  }

  if (opt_cmd == OPT_OBJECT_STAT) {
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    rgw_obj obj(bucket, object);
    obj.set_instance(object_version);

    uint64_t obj_size;
    map<string, bufferlist> attrs;
    RGWObjectCtx obj_ctx(store);
    RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);
    RGWRados::Object::Read read_op(&op_target);

    read_op.params.attrs = &attrs;
    read_op.params.obj_size = &obj_size;

    ret = read_op.prepare(NULL, NULL);
    if (ret < 0) {
      cerr << "ERROR: failed to stat object, returned error: " << cpp_strerror(-ret) << std::endl;
      return 1;
    }
    formatter->open_object_section("object_metadata");
    formatter->dump_string("name", object);
    formatter->dump_unsigned("size", obj_size);

    map<string, bufferlist>::iterator iter;
    map<string, bufferlist> other_attrs;
    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      bufferlist& bl = iter->second;
      bool handled = false;
      if (iter->first == RGW_ATTR_MANIFEST) {
        handled = decode_dump<RGWObjManifest>("manifest", bl, formatter);
      } else if (iter->first == RGW_ATTR_ACL) {
        handled = decode_dump<RGWAccessControlPolicy>("policy", bl, formatter);
      } else if (iter->first == RGW_ATTR_ID_TAG) {
        handled = dump_string("tag", bl, formatter);
      } else if (iter->first == RGW_ATTR_ETAG) {
        handled = dump_string("etag", bl, formatter);
      }

      if (!handled)
        other_attrs[iter->first] = bl;
    }

    formatter->open_object_section("attrs");
    for (iter = other_attrs.begin(); iter != other_attrs.end(); ++iter) {
      dump_string(iter->first.c_str(), iter->second, formatter);
    }
    formatter->close_section();
    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_BUCKET_CHECK) {
    if (check_head_obj_locator) {
      if (bucket_name.empty()) {
        cerr << "ERROR: need to specify bucket name" << std::endl;
        return EINVAL;
      }
      do_check_object_locator(bucket_name, fix, remove_bad, formatter);
    } else {
      RGWBucketAdminOp::check_index(store, bucket_op, f);
    }
  }

  if (opt_cmd == OPT_BUCKET_RM) {
    RGWBucketAdminOp::remove_bucket(store, bucket_op);
  }

  if (opt_cmd == OPT_GC_LIST) {
    int index = 0;
    bool truncated;
    formatter->open_array_section("entries");

    do {
      list<cls_rgw_gc_obj_info> result;
      int ret = store->list_gc_objs(&index, marker, 1000, !include_all, result, &truncated);
      if (ret < 0) {
	cerr << "ERROR: failed to list objs: " << cpp_strerror(-ret) << std::endl;
	return 1;
      }


      list<cls_rgw_gc_obj_info>::iterator iter;
      for (iter = result.begin(); iter != result.end(); ++iter) {
	cls_rgw_gc_obj_info& info = *iter;
	formatter->open_object_section("chain_info");
	formatter->dump_string("tag", info.tag);
	formatter->dump_stream("time") << info.time;
	formatter->open_array_section("objs");
        list<cls_rgw_obj>::iterator liter;
	cls_rgw_obj_chain& chain = info.chain;
	for (liter = chain.objs.begin(); liter != chain.objs.end(); ++liter) {
	  cls_rgw_obj& obj = *liter;
          encode_json("obj", obj, formatter);
	}
	formatter->close_section(); // objs
	formatter->close_section(); // obj_chain
	formatter->flush(cout);
      }
    } while (truncated);
    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_GC_PROCESS) {
    int ret = store->process_gc();
    if (ret < 0) {
      cerr << "ERROR: gc processing returned error: " << cpp_strerror(-ret) << std::endl;
      return 1;
    }
  }

  if (opt_cmd == OPT_ORPHANS_FIND) {
    RGWOrphanSearch search(store, max_concurrent_ios, orphan_stale_secs);

    if (job_id.empty()) {
      cerr << "ERROR: --job-id not specified" << std::endl;
      return EINVAL;
    }
    if (pool_name.empty()) {
      cerr << "ERROR: --pool not specified" << std::endl;
      return EINVAL;
    }

    RGWOrphanSearchInfo info;

    info.pool = pool_name;
    info.job_name = job_id;
    info.num_shards = num_shards;

    int ret = search.init(job_id, &info);
    if (ret < 0) {
      cerr << "could not init search, ret=" << ret << std::endl;
      return -ret;
    }
    ret = search.run();
    if (ret < 0) {
      return -ret;
    }
  }

  if (opt_cmd == OPT_ORPHANS_FINISH) {
    RGWOrphanSearch search(store, max_concurrent_ios, orphan_stale_secs);

    if (job_id.empty()) {
      cerr << "ERROR: --job-id not specified" << std::endl;
      return EINVAL;
    }
    int ret = search.init(job_id, NULL);
    if (ret < 0) {
      if (ret == -ENOENT) {
        cerr << "job not found" << std::endl;
      }
      return -ret;
    }
    ret = search.finish();
    if (ret < 0) {
      return -ret;
    }
  }

  if (opt_cmd == OPT_USER_CHECK) {
    check_bad_user_bucket_mapping(store, user_id, fix);
  }

  if (opt_cmd == OPT_USER_STATS) {
    if (sync_stats) {
      if (!bucket_name.empty()) {
        int ret = rgw_bucket_sync_user_stats(store, bucket_name);
        if (ret < 0) {
          cerr << "ERROR: could not sync bucket stats: " << cpp_strerror(-ret) << std::endl;
          return -ret;
        }
      } else {
        int ret = rgw_user_sync_all_stats(store, user_id);
        if (ret < 0) {
          cerr << "ERROR: failed to sync user stats: " << cpp_strerror(-ret) << std::endl;
          return -ret;
        }
      }
    }

    if (user_id.empty()) {
      cerr << "ERROR: uid not specified" << std::endl;
      return EINVAL;
    }
    cls_user_header header;
    int ret = store->cls_user_get_header(user_id, &header);
    if (ret < 0) {
      cerr << "ERROR: can't read user header: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    encode_json("header", header, formatter);
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_METADATA_GET) {
    int ret = store->meta_mgr->get(metadata_key, formatter);
    if (ret < 0) {
      cerr << "ERROR: can't get key: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    formatter->flush(cout);
  }

  if (opt_cmd == OPT_METADATA_PUT) {
    bufferlist bl;
    int ret = read_input(infile, bl);
    if (ret < 0) {
      cerr << "ERROR: failed to read input: " << cpp_strerror(-ret) << std::endl;
      return ret;
    }
    ret = store->meta_mgr->put(metadata_key, bl, RGWMetadataHandler::APPLY_ALWAYS);
    if (ret < 0) {
      cerr << "ERROR: can't put key: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_METADATA_RM) {
    int ret = store->meta_mgr->remove(metadata_key);
    if (ret < 0) {
      cerr << "ERROR: can't remove key: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_METADATA_LIST) {
    void *handle;
    int max = 1000;
    int ret = store->meta_mgr->list_keys_init(metadata_key, &handle);
    if (ret < 0) {
      cerr << "ERROR: can't get key: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    bool truncated;

    formatter->open_array_section("keys");

    do {
      list<string> keys;
      ret = store->meta_mgr->list_keys_next(handle, max, keys, &truncated);
      if (ret < 0 && ret != -ENOENT) {
        cerr << "ERROR: lists_keys_next(): " << cpp_strerror(-ret) << std::endl;
        return -ret;
      } if (ret != -ENOENT) {
	for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter) {
	  formatter->dump_string("key", *iter);
	}
	formatter->flush(cout);
      }
    } while (truncated);

    formatter->close_section();
    formatter->flush(cout);

    store->meta_mgr->list_keys_complete(handle);
  }

  if (opt_cmd == OPT_MDLOG_LIST) {
    utime_t start_time, end_time;

    int ret = parse_date_str(start_date, start_time);
    if (ret < 0)
      return -ret;

    ret = parse_date_str(end_date, end_time);
    if (ret < 0)
      return -ret;

    int i = (specified_shard_id ? shard_id : 0);

    formatter->open_array_section("entries");
    for (; i < g_ceph_context->_conf->rgw_md_log_max_shards; i++) {
      RGWMetadataLog *meta_log = store->meta_mgr->get_log();
      void *handle;
      list<cls_log_entry> entries;


      meta_log->init_list_entries(i, start_time, end_time, marker, &handle);

      bool truncated;
      do {
	  int ret = meta_log->list_entries(handle, 1000, entries, NULL, &truncated);
        if (ret < 0) {
          cerr << "ERROR: meta_log->list_entries(): " << cpp_strerror(-ret) << std::endl;
          return -ret;
        }

        for (list<cls_log_entry>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
          cls_log_entry& entry = *iter;
          store->meta_mgr->dump_log_entry(entry, formatter);
        }
        formatter->flush(cout);
      } while (truncated);

      meta_log->complete_list_entries(handle);

      if (specified_shard_id)
        break;
    }
  

    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_MDLOG_TRIM) {
    utime_t start_time, end_time;

    if (!specified_shard_id) {
      cerr << "ERROR: shard-id must be specified for trim operation" << std::endl;
      return EINVAL;
    }

    int ret = parse_date_str(start_date, start_time);
    if (ret < 0)
      return -ret;

    ret = parse_date_str(end_date, end_time);
    if (ret < 0)
      return -ret;

    RGWMetadataLog *meta_log = store->meta_mgr->get_log();

    ret = meta_log->trim(shard_id, start_time, end_time, start_marker, end_marker);
    if (ret < 0) {
      cerr << "ERROR: meta_log->trim(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }
  
  if (opt_cmd == OPT_MDLOG_FETCH) {
    RGWMetaSyncStatusManager sync(store);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.fetch();
    if (ret < 0) {
      cerr << "ERROR: sync.fetch() returned ret=" << ret << std::endl;
      return -ret;
    }

  }

  if (opt_cmd == OPT_METADATA_SYNC_STATUS) {
    RGWMetaSyncStatusManager sync(store);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.read_sync_status();
    if (ret < 0) {
      cerr << "ERROR: sync.read_sync_status() returned ret=" << ret << std::endl;
      return -ret;
    }

    rgw_meta_sync_status& sync_status = sync.get_sync_status();

    encode_json("sync_status", sync_status, formatter);
    formatter->flush(cout);

  }

  if (opt_cmd == OPT_METADATA_SYNC_INIT) {
    RGWMetaSyncStatusManager sync(store);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.init_sync_status();
    if (ret < 0) {
      cerr << "ERROR: sync.get_sync_status() returned ret=" << ret << std::endl;
      return -ret;
    }
  }


  if (opt_cmd == OPT_METADATA_SYNC_RUN) {
    RGWMetaSyncStatusManager sync(store);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.run();
    if (ret < 0) {
      cerr << "ERROR: sync.run() returned ret=" << ret << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_DATA_SYNC_STATUS) {
    if (source_zone.empty()) {
      cerr << "ERROR: source zone not specified" << std::endl;
      return EINVAL;
    }
    RGWDataSyncStatusManager sync(store, source_zone);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.read_sync_status();
    if (ret < 0) {
      cerr << "ERROR: sync.read_sync_status() returned ret=" << ret << std::endl;
      return -ret;
    }

    rgw_data_sync_status& sync_status = sync.get_sync_status();

    encode_json("sync_status", sync_status, formatter);
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_DATA_SYNC_INIT) {
#if 0
    RGWDataSyncStatusManager sync(store);

    int ret = sync.init();
    if (ret < 0) {
      cerr << "ERROR: sync.init() returned ret=" << ret << std::endl;
      return -ret;
    }

    ret = sync.init_sync_status();
    if (ret < 0) {
      cerr << "ERROR: sync.get_sync_status() returned ret=" << ret << std::endl;
      return -ret;
    }
#endif
  }

  if (opt_cmd == OPT_BILOG_LIST) {
    if (bucket_name.empty()) {
      cerr << "ERROR: bucket not specified" << std::endl;
      return -EINVAL;
    }
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    formatter->open_array_section("entries");
    bool truncated;
    int count = 0;
    if (max_entries < 0)
      max_entries = 1000;

    do {
      list<rgw_bi_log_entry> entries;
      ret = store->list_bi_log_entries(bucket, shard_id, marker, max_entries - count, entries, &truncated);
      if (ret < 0) {
        cerr << "ERROR: list_bi_log_entries(): " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      count += entries.size();

      for (list<rgw_bi_log_entry>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
        rgw_bi_log_entry& entry = *iter;
        encode_json("entry", entry, formatter);

        marker = entry.id;
      }
      formatter->flush(cout);
    } while (truncated && count < max_entries);

    formatter->close_section();
    formatter->flush(cout);
  }

  if (opt_cmd == OPT_BILOG_TRIM) {
    if (bucket_name.empty()) {
      cerr << "ERROR: bucket not specified" << std::endl;
      return -EINVAL;
    }
    RGWBucketInfo bucket_info;
    int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
    if (ret < 0) {
      cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
    ret = store->trim_bi_log_entries(bucket, shard_id, start_marker, end_marker);
    if (ret < 0) {
      cerr << "ERROR: trim_bi_log_entries(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_DATALOG_LIST) {
    formatter->open_array_section("entries");
    bool truncated;
    int count = 0;
    if (max_entries < 0)
      max_entries = 1000;

    utime_t start_time, end_time;

    int ret = parse_date_str(start_date, start_time);
    if (ret < 0)
      return -ret;

    ret = parse_date_str(end_date, end_time);
    if (ret < 0)
      return -ret;

    RGWDataChangesLog *log = store->data_log;
    RGWDataChangesLog::LogMarker marker;

    do {
      list<rgw_data_change> entries;
      ret = log->list_entries(start_time, end_time, max_entries - count, entries, marker, &truncated);
      if (ret < 0) {
        cerr << "ERROR: list_bi_log_entries(): " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      count += entries.size();

      for (list<rgw_data_change>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
        rgw_data_change& entry = *iter;
        encode_json("entry", entry, formatter);
      }
      formatter->flush(cout);
    } while (truncated && count < max_entries);

    formatter->close_section();
    formatter->flush(cout);
  }
  
  if (opt_cmd == OPT_DATALOG_TRIM) {
    utime_t start_time, end_time;

    int ret = parse_date_str(start_date, start_time);
    if (ret < 0)
      return -ret;

    ret = parse_date_str(end_date, end_time);
    if (ret < 0)
      return -ret;

    RGWDataChangesLog *log = store->data_log;
    ret = log->trim_entries(start_time, end_time, start_marker, end_marker);
    if (ret < 0) {
      cerr << "ERROR: trim_entries(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_OPSTATE_LIST) {
    RGWOpState oc(store);

    int max = 1000;

    void *handle;
    oc.init_list_entries(client_id, op_id, object, &handle);
    list<cls_statelog_entry> entries;
    bool done;
    formatter->open_array_section("entries");
    do {
      int ret = oc.list_entries(handle, max, entries, &done);
      if (ret < 0) {
        cerr << "oc.list_entries returned " << cpp_strerror(-ret) << std::endl;
        oc.finish_list_entries(handle);
        return -ret;
      }

      for (list<cls_statelog_entry>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
        oc.dump_entry(*iter, formatter);
      }

      formatter->flush(cout);
    } while (!done);
    formatter->close_section();
    formatter->flush(cout);
    oc.finish_list_entries(handle);
  }

  if (opt_cmd == OPT_OPSTATE_SET || opt_cmd == OPT_OPSTATE_RENEW) {
    RGWOpState oc(store);

    RGWOpState::OpState state;
    if (object.empty() || client_id.empty() || op_id.empty()) {
      cerr << "ERROR: need to specify client_id, op_id, and object" << std::endl;
      return EINVAL;
    }
    if (state_str.empty()) {
      cerr << "ERROR: state was not specified" << std::endl;
      return EINVAL;
    }
    int ret = oc.state_from_str(state_str, &state);
    if (ret < 0) {
      cerr << "ERROR: invalid state: " << state_str << std::endl;
      return -ret;
    }

    if (opt_cmd == OPT_OPSTATE_SET) {
      ret = oc.set_state(client_id, op_id, object, state);
      if (ret < 0) {
        cerr << "ERROR: failed to set state: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    } else {
      ret = oc.renew_state(client_id, op_id, object, state);
      if (ret < 0) {
        cerr << "ERROR: failed to renew state: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    }
  }
  if (opt_cmd == OPT_OPSTATE_RM) {
    RGWOpState oc(store);

    if (object.empty() || client_id.empty() || op_id.empty()) {
      cerr << "ERROR: need to specify client_id, op_id, and object" << std::endl;
      return EINVAL;
    }
    ret = oc.remove_entry(client_id, op_id, object);
    if (ret < 0) {
      cerr << "ERROR: failed to set state: " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }
  }

  if (opt_cmd == OPT_REPLICALOG_GET || opt_cmd == OPT_REPLICALOG_UPDATE ||
      opt_cmd == OPT_REPLICALOG_DELETE) {
    if (replica_log_type_str.empty()) {
      cerr << "ERROR: need to specify --replica-log-type=<metadata | data | bucket>" << std::endl;
      return EINVAL;
    }
  }

  if (opt_cmd == OPT_REPLICALOG_GET) {
    RGWReplicaBounds bounds;
    if (replica_log_type == ReplicaLog_Metadata) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for get operation" << std::endl;
        return EINVAL;
      }

      RGWReplicaObjectLogger logger(store, pool_name, META_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.get_bounds(shard_id, bounds);
      if (ret < 0)
        return -ret;
    } else if (replica_log_type == ReplicaLog_Data) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for get operation" << std::endl;
        return EINVAL;
      }
      RGWReplicaObjectLogger logger(store, pool_name, DATA_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.get_bounds(shard_id, bounds);
      if (ret < 0)
        return -ret;
    } else if (replica_log_type == ReplicaLog_Bucket) {
      if (bucket_name.empty()) {
        cerr << "ERROR: bucket not specified" << std::endl;
        return -EINVAL;
      }
      RGWBucketInfo bucket_info;
      int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
      if (ret < 0) {
        cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      RGWReplicaBucketLogger logger(store);
      ret = logger.get_bounds(bucket, shard_id, bounds);
      if (ret < 0)
        return -ret;
    } else { // shouldn't get here
      assert(0);
    }
    encode_json("bounds", bounds, formatter);
    formatter->flush(cout);
    cout << std::endl;
  }

  if (opt_cmd == OPT_REPLICALOG_DELETE) {
    if (replica_log_type == ReplicaLog_Metadata) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for delete operation" << std::endl;
        return EINVAL;
      }
      if (!specified_daemon_id) {
        cerr << "ERROR: daemon-id must be specified for delete operation" << std::endl;
        return EINVAL;
      }
      RGWReplicaObjectLogger logger(store, pool_name, META_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.delete_bound(shard_id, daemon_id, false);
      if (ret < 0)
        return -ret;
    } else if (replica_log_type == ReplicaLog_Data) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for delete operation" << std::endl;
        return EINVAL;
      }
      if (!specified_daemon_id) {
        cerr << "ERROR: daemon-id must be specified for delete operation" << std::endl;
        return EINVAL;
      }
      RGWReplicaObjectLogger logger(store, pool_name, DATA_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.delete_bound(shard_id, daemon_id, false);
      if (ret < 0)
        return -ret;
    } else if (replica_log_type == ReplicaLog_Bucket) {
      if (bucket_name.empty()) {
        cerr << "ERROR: bucket not specified" << std::endl;
        return -EINVAL;
      }
      RGWBucketInfo bucket_info;
      int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
      if (ret < 0) {
        cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      RGWReplicaBucketLogger logger(store);
      ret = logger.delete_bound(bucket, shard_id, daemon_id, false);
      if (ret < 0)
        return -ret;
    }
  }

  if (opt_cmd == OPT_REPLICALOG_UPDATE) {
    if (marker.empty()) {
      cerr << "ERROR: marker was not specified" <<std::endl;
      return EINVAL;
    }
    utime_t time = ceph_clock_now(NULL);
    if (!date.empty()) {
      ret = parse_date_str(date, time);
      if (ret < 0) {
        cerr << "ERROR: failed to parse start date" << std::endl;
        return EINVAL;
      }
    }
    list<RGWReplicaItemMarker> entries;
    int ret = read_decode_json(infile, entries);
    if (ret < 0) {
      cerr << "ERROR: failed to decode entries" << std::endl;
      return EINVAL;
    }
    RGWReplicaBounds bounds;
    if (replica_log_type == ReplicaLog_Metadata) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for get operation" << std::endl;
        return EINVAL;
      }

      RGWReplicaObjectLogger logger(store, pool_name, META_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.update_bound(shard_id, daemon_id, marker, time, &entries);
      if (ret < 0) {
        cerr << "ERROR: failed to update bounds: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    } else if (replica_log_type == ReplicaLog_Data) {
      if (!specified_shard_id) {
        cerr << "ERROR: shard-id must be specified for get operation" << std::endl;
        return EINVAL;
      }
      RGWReplicaObjectLogger logger(store, pool_name, DATA_REPLICA_LOG_OBJ_PREFIX);
      int ret = logger.update_bound(shard_id, daemon_id, marker, time, &entries);
      if (ret < 0) {
        cerr << "ERROR: failed to update bounds: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    } else if (replica_log_type == ReplicaLog_Bucket) {
      if (bucket_name.empty()) {
        cerr << "ERROR: bucket not specified" << std::endl;
        return -EINVAL;
      }
      RGWBucketInfo bucket_info;
      int ret = init_bucket(bucket_name, bucket_id, bucket_info, bucket);
      if (ret < 0) {
        cerr << "ERROR: could not init bucket: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }

      RGWReplicaBucketLogger logger(store);
      ret = logger.update_bound(bucket, shard_id, daemon_id, marker, time, &entries);
      if (ret < 0) {
        cerr << "ERROR: failed to update bounds: " << cpp_strerror(-ret) << std::endl;
        return -ret;
      }
    }
  }

  bool quota_op = (opt_cmd == OPT_QUOTA_SET || opt_cmd == OPT_QUOTA_ENABLE || opt_cmd == OPT_QUOTA_DISABLE);

  if (quota_op) {
    if (bucket_name.empty() && user_id.empty()) {
      cerr << "ERROR: bucket name or uid is required for quota operation" << std::endl;
      return EINVAL;
    }

    if (!bucket_name.empty()) {
      if (!quota_scope.empty() && quota_scope != "bucket") {
        cerr << "ERROR: invalid quota scope specification." << std::endl;
        return EINVAL;
      }
      set_bucket_quota(store, opt_cmd, bucket_name, max_size, max_objects, have_max_size, have_max_objects);
    } else if (!user_id.empty()) {
      if (quota_scope == "bucket") {
        set_user_bucket_quota(opt_cmd, user, user_op, max_size, max_objects, have_max_size, have_max_objects);
      } else if (quota_scope == "user") {
        set_user_quota(opt_cmd, user, user_op, max_size, max_objects, have_max_size, have_max_objects);
      } else {
        cerr << "ERROR: invalid quota scope specification. Please specify either --quota-scope=bucket, or --quota-scope=user" << std::endl;
        return EINVAL;
      }
    }
  }

  return 0;
}
