// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_admin_common.h"

#include <sstream>

#include "auth/Crypto.h"
#include "compressor/Compressor.h"

#include "common/ceph_json.h"
#include "common/config.h"
#include "common/ceph_argparse.h"

#include "cls/rgw/cls_rgw_client.h"
#include "global/global_init.h"

#include "rgw_user.h"
#include "rgw_replica_log.h"
#include "rgw_sync.h"
#include "rgw_rest_conn.h"
#include "rgw_reshard.h"


void usage()
{
  cout << "usage: radosgw-admin <cmd> [options...]" << std::endl;
  cout << "commands:\n";
  cout << "  user create                create a new user\n" ;
  cout << "  user modify                modify user\n";
  cout << "  user info                  get user info\n";
  cout << "  user rm                    remove user\n";
  cout << "  user suspend               suspend a user\n";
  cout << "  user enable                re-enable user after suspension\n";
  cout << "  user check                 check user info\n";
  cout << "  user stats                 show user stats as accounted by quota subsystem\n";
  cout << "  user list                  list users\n";
  cout << "  caps add                   add user capabilities\n";
  cout << "  caps rm                    remove user capabilities\n";
  cout << "  subuser create             create a new subuser\n" ;
  cout << "  subuser modify             modify subuser\n";
  cout << "  subuser rm                 remove subuser\n";
  cout << "  key create                 create access key\n";
  cout << "  key rm                     remove access key\n";
  cout << "  bucket list                list buckets\n";
  cout << "  bucket limit check         show bucket sharding stats\n";
  cout << "  bucket link                link bucket to specified user\n";
  cout << "  bucket unlink              unlink bucket from specified user\n";
  cout << "  bucket stats               returns bucket statistics\n";
  cout << "  bucket rm                  remove bucket\n";
  cout << "  bucket check               check bucket index\n";
  cout << "  bucket reshard             reshard bucket\n";
  cout << "  bucket rewrite             rewrite all objects in the specified bucket\n";
  cout << "  bucket sync disable        disable bucket sync\n";
  cout << "  bucket sync enable         enable bucket sync\n";
  cout << "  bi get                     retrieve bucket index object entries\n";
  cout << "  bi put                     store bucket index object entries\n";
  cout << "  bi list                    list raw bucket index entries\n";
  cout << "  bi purge                   purge bucket index entries\n";
  cout << "  object rm                  remove object\n";
  cout << "  object stat                stat an object for its metadata\n";
  cout << "  object unlink              unlink object from bucket index\n";
  cout << "  object rewrite             rewrite the specified object\n";
  cout << "  objects expire             run expired objects cleanup\n";
  cout << "  period delete              delete a period\n";
  cout << "  period get                 get period info\n";
  cout << "  period get-current         get current period info\n";
  cout << "  period pull                pull a period\n";
  cout << "  period push                push a period\n";
  cout << "  period list                list all periods\n";
  cout << "  period update              update the staging period\n";
  cout << "  period commit              commit the staging period\n";
  cout << "  quota set                  set quota params\n";
  cout << "  quota enable               enable quota\n";
  cout << "  quota disable              disable quota\n";
  cout << "  global quota get           view global quota params\n";
  cout << "  global quota set           set global quota params\n";
  cout << "  global quota enable        enable a global quota\n";
  cout << "  global quota disable       disable a global quota\n";
  cout << "  realm create               create a new realm\n";
  cout << "  realm delete               delete a realm\n";
  cout << "  realm get                  show realm info\n";
  cout << "  realm get-default          get default realm name\n";
  cout << "  realm list                 list realms\n";
  cout << "  realm list-periods         list all realm periods\n";
  cout << "  realm rename               rename a realm\n";
  cout << "  realm set                  set realm info (requires infile)\n";
  cout << "  realm default              set realm as default\n";
  cout << "  realm pull                 pull a realm and its current period\n";
  cout << "  zonegroup add              add a zone to a zonegroup\n";
  cout << "  zonegroup create           create a new zone group info\n";
  cout << "  zonegroup default          set default zone group\n";
  cout << "  zonegroup delete           delete a zone group info\n";
  cout << "  zonegroup get              show zone group info\n";
  cout << "  zonegroup modify           modify an existing zonegroup\n";
  cout << "  zonegroup set              set zone group info (requires infile)\n";
  cout << "  zonegroup remove           remove a zone from a zonegroup\n";
  cout << "  zonegroup rename           rename a zone group\n";
  cout << "  zonegroup list             list all zone groups set on this cluster\n";
  cout << "  zonegroup placement list   list zonegroup's placement targets\n";
  cout << "  zonegroup placement add    add a placement target id to a zonegroup\n";
  cout << "  zonegroup placement modify modify a placement target of a specific zonegroup\n";
  cout << "  zonegroup placement rm     remove a placement target from a zonegroup\n";
  cout << "  zonegroup placement default  set a zonegroup's default placement target\n";
  cout << "  zone create                create a new zone\n";
  cout << "  zone delete                delete a zone\n";
  cout << "  zone get                   show zone cluster params\n";
  cout << "  zone modify                modify an existing zone\n";
  cout << "  zone set                   set zone cluster params (requires infile)\n";
  cout << "  zone list                  list all zones set on this cluster\n";
  cout << "  zone rename                rename a zone\n";
  cout << "  zone placement list        list zone's placement targets\n";
  cout << "  zone placement add         add a zone placement target\n";
  cout << "  zone placement modify      modify a zone placement target\n";
  cout << "  zone placement rm          remove a zone placement target\n";
  cout << "  metadata sync status       get metadata sync status\n";
  cout << "  metadata sync init         init metadata sync\n";
  cout << "  metadata sync run          run metadata sync\n";
  cout << "  data sync status           get data sync status of the specified source zone\n";
  cout << "  data sync init             init data sync for the specified source zone\n";
  cout << "  data sync run              run data sync for the specified source zone\n";
  cout << "  pool add                   add an existing pool for data placement\n";
  cout << "  pool rm                    remove an existing pool from data placement set\n";
  cout << "  pools list                 list placement active set\n";
  cout << "  policy                     read bucket/object policy\n";
  cout << "  log list                   list log objects\n";
  cout << "  log show                   dump a log from specific object or (bucket + date\n";
  cout << "                             + bucket-id)\n";
  cout << "                             (NOTE: required to specify formatting of date\n";
  cout << "                             to \"YYYY-MM-DD-hh\")\n";
  cout << "  log rm                     remove log object\n";
  cout << "  usage show                 show usage (by user, date range)\n";
  cout << "  usage trim                 trim usage (by user, date range)\n";
  cout << "  gc list                    dump expired garbage collection objects (specify\n";
  cout << "                             --include-all to list all entries, including unexpired)\n";
  cout << "  gc process                 manually process garbage (specify\n";
  cout << "                             --include-all to process all entries, including unexpired)\n";
  cout << "  lc list                    list all bucket lifecycle progress\n";
  cout << "  lc process                 manually process lifecycle\n";
  cout << "  metadata get               get metadata info\n";
  cout << "  metadata put               put metadata info\n";
  cout << "  metadata rm                remove metadata info\n";
  cout << "  metadata list              list metadata info\n";
  cout << "  mdlog list                 list metadata log\n";
  cout << "  mdlog trim                 trim metadata log (use start-date, end-date or\n";
  cout << "                             start-marker, end-marker)\n";
  cout << "  mdlog status               read metadata log status\n";
  cout << "  bilog list                 list bucket index log\n";
  cout << "  bilog trim                 trim bucket index log (use start-marker, end-marker)\n";
  cout << "  datalog list               list data log\n";
  cout << "  datalog trim               trim data log\n";
  cout << "  datalog status             read data log status\n";
  cout << "  opstate list               list stateful operations entries (use client_id,\n";
  cout << "                             op_id, object)\n";
  cout << "  opstate set                set state on an entry (use client_id, op_id, object, state)\n";
  cout << "  opstate renew              renew state on an entry (use client_id, op_id, object)\n";
  cout << "  opstate rm                 remove entry (use client_id, op_id, object)\n";
  cout << "  replicalog get             get replica metadata log entry\n";
  cout << "  replicalog update          update replica metadata log entry\n";
  cout << "  replicalog delete          delete replica metadata log entry\n";
  cout << "  orphans find               init and run search for leaked rados objects (use job-id, pool)\n";
  cout << "  orphans finish             clean up search for leaked rados objects\n";
  cout << "  orphans list-jobs          list the current job-ids for orphans search\n";
  cout << "  role create                create a AWS role for use with STS\n";
  cout << "  role delete                delete a role\n";
  cout << "  role get                   get a role\n";
  cout << "  role list                  list roles with specified path prefix\n";
  cout << "  role modify                modify the assume role policy of an existing role\n";
  cout << "  role-policy put            add/update permission policy to role\n";
  cout << "  role-policy list           list policies attached to a role\n";
  cout << "  role-policy get            get the specified inline policy document embedded with the given role\n";
  cout << "  role-policy delete         delete policy attached to a role\n";
  cout << "  reshard add                schedule a resharding of a bucket\n";
  cout << "  reshard list               list all bucket resharding or scheduled to be resharded\n";
  cout << "  reshard status             read bucket resharding status\n";
  cout << "  reshard process            process of scheduled reshard jobs\n";
  cout << "  reshard cancel             cancel resharding a bucket\n";
  cout << "options:\n";
  cout << "   --tenant=<tenant>         tenant name\n";
  cout << "   --uid=<id>                user id\n";
  cout << "   --subuser=<name>          subuser name\n";
  cout << "   --access-key=<key>        S3 access key\n";
  cout << "   --email=<email>           user's email address\n";
  cout << "   --secret/--secret-key=<key>\n";
  cout << "                             specify secret key\n";
  cout << "   --gen-access-key          generate random access key (for S3)\n";
  cout << "   --gen-secret              generate random secret key\n";
  cout << "   --key-type=<type>         key type, options are: swift, s3\n";
  cout << "   --temp-url-key[-2]=<key>  temp url key\n";
  cout << "   --access=<access>         Set access permissions for sub-user, should be one\n";
  cout << "                             of read, write, readwrite, full\n";
  cout << "   --display-name=<name>     user's display name\n";
  cout << "   --max-buckets             max number of buckets for a user\n";
  cout << "   --admin                   set the admin flag on the user\n";
  cout << "   --system                  set the system flag on the user\n";
  cout << "   --bucket=<bucket>         Specify the bucket name. Also used by the quota command.\n";
  cout << "   --pool=<pool>             Specify the pool name. Also used to scan for leaked rados objects.\n";
  cout << "   --object=<object>         object name\n";
  cout << "   --date=<date>             date in the format yyyy-mm-dd\n";
  cout << "   --start-date=<date>       start date in the format yyyy-mm-dd\n";
  cout << "   --end-date=<date>         end date in the format yyyy-mm-dd\n";
  cout << "   --bucket-id=<bucket-id>   bucket id\n";
  cout << "   --shard-id=<shard-id>     optional for mdlog list\n";
  cout << "                             required for: \n";
  cout << "                               mdlog trim\n";
  cout << "                               replica mdlog get/delete\n";
  cout << "                               replica datalog get/delete\n";
  cout << "   --metadata-key=<key>      key to retrieve metadata from with metadata get\n";
  cout << "   --remote=<remote>         zone or zonegroup id of remote gateway\n";
  cout << "   --period=<id>             period id\n";
  cout << "   --epoch=<number>          period epoch\n";
  cout << "   --commit                  commit the period during 'period update'\n";
  cout << "   --staging                 get staging period info\n";
  cout << "   --master                  set as master\n";
  cout << "   --master-zone=<id>        master zone id\n";
  cout << "   --rgw-realm=<name>        realm name\n";
  cout << "   --realm-id=<id>           realm id\n";
  cout << "   --realm-new-name=<name>   realm new name\n";
  cout << "   --rgw-zonegroup=<name>    zonegroup name\n";
  cout << "   --zonegroup-id=<id>       zonegroup id\n";
  cout << "   --zonegroup-new-name=<name>\n";
  cout << "                             zonegroup new name\n";
  cout << "   --rgw-zone=<name>         name of zone in which radosgw is running\n";
  cout << "   --zone-id=<id>            zone id\n";
  cout << "   --zone-new-name=<name>    zone new name\n";
  cout << "   --source-zone             specify the source zone (for data sync)\n";
  cout << "   --default                 set entity (realm, zonegroup, zone) as default\n";
  cout << "   --read-only               set zone as read-only (when adding to zonegroup)\n";
  cout << "   --redirect-zone           specify zone id to redirect when response is 404 (not found)\n";
  cout << "   --placement-id            placement id for zonegroup placement commands\n";
  cout << "   --tags=<list>             list of tags for zonegroup placement add and modify commands\n";
  cout << "   --tags-add=<list>         list of tags to add for zonegroup placement modify command\n";
  cout << "   --tags-rm=<list>          list of tags to remove for zonegroup placement modify command\n";
  cout << "   --endpoints=<list>        zone endpoints\n";
  cout << "   --index-pool=<pool>       placement target index pool\n";
  cout << "   --data-pool=<pool>        placement target data pool\n";
  cout << "   --data-extra-pool=<pool>  placement target data extra (non-ec) pool\n";
  cout << "   --placement-index-type=<type>\n";
  cout << "                             placement target index type (normal, indexless, or #id)\n";
  cout << "   --compression=<type>      placement target compression type (plugin name or empty/none)\n";
  cout << "   --tier-type=<type>        zone tier type\n";
  cout << "   --tier-config=<k>=<v>[,...]\n";
  cout << "                             set zone tier config keys, values\n";
  cout << "   --tier-config-rm=<k>[,...]\n";
  cout << "                             unset zone tier config keys\n";
  cout << "   --sync-from-all[=false]   set/reset whether zone syncs from all zonegroup peers\n";
  cout << "   --sync-from=[zone-name][,...]\n";
  cout << "                             set list of zones to sync from\n";
  cout << "   --sync-from-rm=[zone-name][,...]\n";
  cout << "                             remove zones from list of zones to sync from\n";
  cout << "   --fix                     besides checking bucket index, will also fix it\n";
  cout << "   --check-objects           bucket check: rebuilds bucket index according to\n";
  cout << "                             actual objects state\n";
  cout << "   --format=<format>         specify output format for certain operations: xml,\n";
  cout << "                             json\n";
  cout << "   --purge-data              when specified, user removal will also purge all the\n";
  cout << "                             user data\n";
  cout << "   --purge-keys              when specified, subuser removal will also purge all the\n";
  cout << "                             subuser keys\n";
  cout << "   --purge-objects           remove a bucket's objects before deleting it\n";
  cout << "                             (NOTE: required to delete a non-empty bucket)\n";
  cout << "   --sync-stats              option to 'user stats', update user stats with current\n";
  cout << "                             stats reported by user's buckets indexes\n";
  cout << "   --show-log-entries=<flag> enable/disable dump of log entries on log show\n";
  cout << "   --show-log-sum=<flag>     enable/disable dump of log summation on log show\n";
  cout << "   --skip-zero-entries       log show only dumps entries that don't have zero value\n";
  cout << "                             in one of the numeric field\n";
  cout << "   --infile=<file>           specify a file to read in when setting data\n";
  cout << "   --state=<state>           specify a state for the opstate set command\n";
  cout << "   --replica-log-type=<logtypestr>\n";
  cout << "                             replica log type (metadata, data, bucket), required for\n";
  cout << "                             replica log operations\n";
  cout << "   --categories=<list>       comma separated list of categories, used in usage show\n";
  cout << "   --caps=<caps>             list of caps (e.g., \"usage=read, write; user=read\")\n";
  cout << "   --yes-i-really-mean-it    required for certain operations\n";
  cout << "   --warnings-only           when specified with bucket limit check, list\n";
  cout << "                             only buckets nearing or over the current max\n";
  cout << "                             objects per shard value\n";
  cout << "   --bypass-gc               when specified with bucket deletion, triggers\n";
  cout << "                             object deletions by not involving GC\n";
  cout << "   --inconsistent-index      when specified with bucket deletion and bypass-gc set to true,\n";
  cout << "                             ignores bucket index consistency\n";
  cout << "   --min-rewrite-size        min object size for bucket rewrite (default 4M)\n";
  cout << "   --max-rewrite-size        max object size for bucket rewrite (default ULLONG_MAX)\n";
  cout << "   --min-rewrite-stripe-size min stripe size for object rewrite (default 0)\n";
  cout << "\n";
  cout << "<date> := \"YYYY-MM-DD[ hh:mm:ss]\"\n";
  cout << "\nQuota options:\n";
  cout << "   --max-objects             specify max objects (negative value to disable)\n";
  cout << "   --max-size                specify max size (in B/K/M/G/T, negative value to disable)\n";
  cout << "   --quota-scope             scope of quota (bucket, user)\n";
  cout << "\nOrphans search options:\n";
  cout << "   --num-shards              num of shards to use for keeping the temporary scan info\n";
  cout << "   --orphan-stale-secs       num of seconds to wait before declaring an object to be an orphan (default: 86400)\n";
  cout << "   --job-id                  set the job id (for orphans find)\n";
  cout << "   --max-concurrent-ios      maximum concurrent ios for orphans find (default: 32)\n";
  cout << "\nOrphans list-jobs options:\n";
  cout << "   --extra-info              provide extra info in job list\n";
  cout << "\nRole options:\n";
  cout << "   --role-name               name of the role to create\n";
  cout << "   --path                    path to the role\n";
  cout << "   --assume-role-policy-doc  the trust relationship policy document that grants an entity permission to assume the role\n";
  cout << "   --policy-name             name of the policy document\n";
  cout << "   --policy-doc              permission policy document\n";
  cout << "   --path-prefix             path prefix for filtering roles\n";
  cout << "\n";
  generic_client_usage();
}

int get_cmd(const char *cmd, const char *prev_cmd, const char *prev_prev_cmd, bool *need_more)
{
  *need_more = false;
  // NOTE: please keep the checks in alphabetical order !!!
  if (strcmp(cmd, "bi") == 0 ||
      strcmp(cmd, "bilog") == 0 ||
      strcmp(cmd, "buckets") == 0 ||
      strcmp(cmd, "caps") == 0 ||
      strcmp(cmd, "data") == 0 ||
      strcmp(cmd, "datalog") == 0 ||
      strcmp(cmd, "error") == 0 ||
      strcmp(cmd, "gc") == 0 ||
      strcmp(cmd, "global") == 0 ||
      strcmp(cmd, "key") == 0 ||
      strcmp(cmd, "log") == 0 ||
      strcmp(cmd, "lc") == 0 ||
      strcmp(cmd, "mdlog") == 0 ||
      strcmp(cmd, "metadata") == 0 ||
      strcmp(cmd, "object") == 0 ||
      strcmp(cmd, "objects") == 0 ||
      strcmp(cmd, "olh") == 0 ||
      strcmp(cmd, "opstate") == 0 ||
      strcmp(cmd, "orphans") == 0 ||
      strcmp(cmd, "period") == 0 ||
      strcmp(cmd, "placement") == 0 ||
      strcmp(cmd, "pool") == 0 ||
      strcmp(cmd, "pools") == 0 ||
      strcmp(cmd, "quota") == 0 ||
      strcmp(cmd, "realm") == 0 ||
      strcmp(cmd, "replicalog") == 0 ||
      strcmp(cmd, "role") == 0 ||
      strcmp(cmd, "role-policy") == 0 ||
      strcmp(cmd, "subuser") == 0 ||
      strcmp(cmd, "sync") == 0 ||
      strcmp(cmd, "usage") == 0 ||
      strcmp(cmd, "user") == 0 ||
      strcmp(cmd, "zone") == 0 ||
      strcmp(cmd, "zonegroup") == 0 ||
      strcmp(cmd, "zonegroups") == 0) {
    *need_more = true;
    return 0;
  }

  /*
   * can do both radosgw-admin bucket reshard, and radosgw-admin reshard bucket
   */
  if (strcmp(cmd, "reshard") == 0 &&
      !(prev_cmd && strcmp(prev_cmd, "bucket") == 0)) {
    *need_more = true;
    return 0;
  }
  if (strcmp(cmd, "bucket") == 0 &&
      !(prev_cmd && strcmp(prev_cmd, "reshard") == 0)) {
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
    if (strcmp(cmd, "list") == 0)
      return OPT_USER_LIST;
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
    if (strcmp(cmd, "reshard") == 0)
      return OPT_BUCKET_RESHARD;
    if (strcmp(cmd, "check") == 0)
      return OPT_BUCKET_CHECK;
    if (strcmp(cmd, "sync") == 0) {
      *need_more = true;
      return 0;
    }
    if (strcmp(cmd, "limit") == 0) {
      *need_more = true;
      return 0;
    }
  } else if (prev_prev_cmd && strcmp(prev_prev_cmd, "bucket") == 0) {
    if (strcmp(prev_cmd, "sync") == 0) {
      if (strcmp(cmd, "status") == 0)
        return OPT_BUCKET_SYNC_STATUS;
      if (strcmp(cmd, "init") == 0)
        return OPT_BUCKET_SYNC_INIT;
      if (strcmp(cmd, "run") == 0)
        return OPT_BUCKET_SYNC_RUN;
      if (strcmp(cmd, "disable") == 0)
        return OPT_BUCKET_SYNC_DISABLE;
      if (strcmp(cmd, "enable") == 0)
        return OPT_BUCKET_SYNC_ENABLE;
    } else if ((strcmp(prev_cmd, "limit") == 0) &&
               (strcmp(cmd, "check") == 0)) {
      return OPT_BUCKET_LIMIT_CHECK;
    }
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
    if (strcmp(cmd, "purge") == 0)
      return OPT_BI_PURGE;
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "global") == 0) &&
             (strcmp(prev_cmd, "quota") == 0)) {
    if (strcmp(cmd, "get") == 0)
      return OPT_GLOBAL_QUOTA_GET;
    if (strcmp(cmd, "set") == 0)
      return OPT_GLOBAL_QUOTA_SET;
    if (strcmp(cmd, "enable") == 0)
      return OPT_GLOBAL_QUOTA_ENABLE;
    if (strcmp(cmd, "disable") == 0)
      return OPT_GLOBAL_QUOTA_DISABLE;
  } else if (strcmp(prev_cmd, "period") == 0) {
    if (strcmp(cmd, "delete") == 0)
      return OPT_PERIOD_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_PERIOD_GET;
    if (strcmp(cmd, "get-current") == 0)
      return OPT_PERIOD_GET_CURRENT;
    if (strcmp(cmd, "pull") == 0)
      return OPT_PERIOD_PULL;
    if (strcmp(cmd, "push") == 0)
      return OPT_PERIOD_PUSH;
    if (strcmp(cmd, "list") == 0)
      return OPT_PERIOD_LIST;
    if (strcmp(cmd, "update") == 0)
      return OPT_PERIOD_UPDATE;
    if (strcmp(cmd, "commit") == 0)
      return OPT_PERIOD_COMMIT;
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
    if (strcmp(cmd, "rename") == 0)
      return OPT_REALM_RENAME;
    if (strcmp(cmd, "set") == 0)
      return OPT_REALM_SET;
    if (strcmp(cmd, "default") == 0)
      return OPT_REALM_DEFAULT;
    if (strcmp(cmd, "pull") == 0)
      return OPT_REALM_PULL;
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "zonegroup") == 0) &&
             (strcmp(prev_cmd, "placement") == 0)) {
    if (strcmp(cmd, "add") == 0)
      return OPT_ZONEGROUP_PLACEMENT_ADD;
    if (strcmp(cmd, "modify") == 0)
      return OPT_ZONEGROUP_PLACEMENT_MODIFY;
    if (strcmp(cmd, "rm") == 0)
      return OPT_ZONEGROUP_PLACEMENT_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONEGROUP_PLACEMENT_LIST;
    if (strcmp(cmd, "default") == 0)
      return OPT_ZONEGROUP_PLACEMENT_DEFAULT;
  } else if (strcmp(prev_cmd, "zonegroup") == 0) {
    if (strcmp(cmd, "add") == 0)
      return OPT_ZONEGROUP_ADD;
    if (strcmp(cmd, "create")== 0)
      return OPT_ZONEGROUP_CREATE;
    if (strcmp(cmd, "default") == 0)
      return OPT_ZONEGROUP_DEFAULT;
    if (strcmp(cmd, "delete") == 0)
      return OPT_ZONEGROUP_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_ZONEGROUP_GET;
    if (strcmp(cmd, "modify") == 0)
      return OPT_ZONEGROUP_MODIFY;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONEGROUP_LIST;
    if (strcmp(cmd, "set") == 0)
      return OPT_ZONEGROUP_SET;
    if (strcmp(cmd, "remove") == 0)
      return OPT_ZONEGROUP_REMOVE;
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
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "zone") == 0) &&
             (strcmp(prev_cmd, "placement") == 0)) {
    if (strcmp(cmd, "add") == 0)
      return OPT_ZONE_PLACEMENT_ADD;
    if (strcmp(cmd, "modify") == 0)
      return OPT_ZONE_PLACEMENT_MODIFY;
    if (strcmp(cmd, "rm") == 0)
      return OPT_ZONE_PLACEMENT_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONE_PLACEMENT_LIST;
  } else if (strcmp(prev_cmd, "zone") == 0) {
    if (strcmp(cmd, "delete") == 0)
      return OPT_ZONE_DELETE;
    if (strcmp(cmd, "create") == 0)
      return OPT_ZONE_CREATE;
    if (strcmp(cmd, "get") == 0)
      return OPT_ZONE_GET;
    if (strcmp(cmd, "set") == 0)
      return OPT_ZONE_SET;
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONE_LIST;
    if (strcmp(cmd, "modify") == 0)
      return OPT_ZONE_MODIFY;
    if (strcmp(cmd, "rename") == 0)
      return OPT_ZONE_RENAME;
    if (strcmp(cmd, "default") == 0)
      return OPT_ZONE_DEFAULT;
  } else if (strcmp(prev_cmd, "zones") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_ZONE_LIST;
  } else if (strcmp(prev_cmd, "gc") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_GC_LIST;
    if (strcmp(cmd, "process") == 0)
      return OPT_GC_PROCESS;
  } else if (strcmp(prev_cmd, "lc") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_LC_LIST;
    if (strcmp(cmd, "process") == 0)
      return OPT_LC_PROCESS;
  } else if (strcmp(prev_cmd, "orphans") == 0) {
    if (strcmp(cmd, "find") == 0)
      return OPT_ORPHANS_FIND;
    if (strcmp(cmd, "finish") == 0)
      return OPT_ORPHANS_FINISH;
    if (strcmp(cmd, "list-jobs") == 0)
      return OPT_ORPHANS_LIST_JOBS;
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
  } else if ((prev_prev_cmd && strcmp(prev_prev_cmd, "sync") == 0) &&
             (strcmp(prev_cmd, "error") == 0)) {
    if (strcmp(cmd, "list") == 0)
      return OPT_SYNC_ERROR_LIST;
  } else if (strcmp(prev_cmd, "mdlog") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_MDLOG_LIST;
    if (strcmp(cmd, "autotrim") == 0)
      return OPT_MDLOG_AUTOTRIM;
    if (strcmp(cmd, "trim") == 0)
      return OPT_MDLOG_TRIM;
    if (strcmp(cmd, "fetch") == 0)
      return OPT_MDLOG_FETCH;
    if (strcmp(cmd, "status") == 0)
      return OPT_MDLOG_STATUS;
  } else if (strcmp(prev_cmd, "bilog") == 0) {
    if (strcmp(cmd, "list") == 0)
      return OPT_BILOG_LIST;
    if (strcmp(cmd, "trim") == 0)
      return OPT_BILOG_TRIM;
    if (strcmp(cmd, "status") == 0)
      return OPT_BILOG_STATUS;
    if (strcmp(cmd, "autotrim") == 0)
      return OPT_BILOG_AUTOTRIM;
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
    if (strcmp(cmd, "status") == 0)
      return OPT_DATALOG_STATUS;
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
  } else if (strcmp(prev_cmd, "sync") == 0) {
    if (strcmp(cmd, "status") == 0)
      return OPT_SYNC_STATUS;
  } else if (strcmp(prev_cmd, "role") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_ROLE_CREATE;
    if (strcmp(cmd, "delete") == 0)
      return OPT_ROLE_DELETE;
    if (strcmp(cmd, "get") == 0)
      return OPT_ROLE_GET;
    if (strcmp(cmd, "modify") == 0)
      return OPT_ROLE_MODIFY;
    if (strcmp(cmd, "list") == 0)
      return OPT_ROLE_LIST;
  } else if (strcmp(prev_cmd, "role-policy") == 0) {
    if (strcmp(cmd, "put") == 0)
      return OPT_ROLE_POLICY_PUT;
    if (strcmp(cmd, "list") == 0)
      return OPT_ROLE_POLICY_LIST;
    if (strcmp(cmd, "get") == 0)
      return OPT_ROLE_POLICY_GET;
    if (strcmp(cmd, "delete") == 0)
      return OPT_ROLE_POLICY_DELETE;
  } else if (strcmp(prev_cmd, "reshard") == 0) {
    if (strcmp(cmd, "bucket") == 0)
      return OPT_BUCKET_RESHARD;
    if (strcmp(cmd, "add") == 0)
      return OPT_RESHARD_ADD;
    if (strcmp(cmd, "list") == 0)
      return OPT_RESHARD_LIST;
    if (strcmp(cmd, "status") == 0)
      return OPT_RESHARD_STATUS;
    if (strcmp(cmd, "process") == 0)
      return OPT_RESHARD_PROCESS;
    if (strcmp(cmd, "cancel") == 0)
      return OPT_RESHARD_CANCEL;
  }

  return -EINVAL;
}