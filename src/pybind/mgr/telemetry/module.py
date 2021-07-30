"""
Telemetry module for ceph-mgr

Collect statistics from Ceph cluster and send this back to the Ceph project
when user has opted-in
"""
import logging
import numbers
import errno
import hashlib
import json
import rbd
import re
import requests
import uuid
import time
from datetime import datetime, timedelta
from threading import Event
from collections import defaultdict

from mgr_module import MgrModule


ALL_CHANNELS = ['basic', 'ident', 'crash', 'device', 'perf']

LICENSE='sharing-1-0'
LICENSE_NAME='Community Data License Agreement - Sharing - Version 1.0'
LICENSE_URL='https://cdla.io/sharing-1-0/'

# If the telemetry revision has changed since this point, re-require
# an opt-in.  This should happen each time we add new information to
# the telemetry report.
LAST_REVISION_RE_OPT_IN = 2

# Latest revision of the telemetry report.  Bump this each time we make
# *any* change.
REVISION = 3

# History of revisions
# --------------------
#
# Version 1:
#   Mimic and/or nautilus are lumped together here, since
#   we didn't track revisions yet.
#
# Version 2:
#   - added revision tracking, nagging, etc.
#   - added config option changes
#   - added channels
#   - added explicit license acknowledgement to the opt-in process
#
# Version 3:
#   - added device health metrics (i.e., SMART data, minus serial number)
#   - remove crush_rule
#   - added CephFS metadata (how many MDSs, fs features, how many data pools,
#     how much metadata is cached, rfiles, rbytes, rsnapshots)
#   - added more pool metadata (rep vs ec, cache tiering mode, ec profile)
#   - added host count, and counts for hosts with each of (mon, osd, mds, mgr)
#   - whether an OSD cluster network is in use
#   - rbd pool and image count, and rbd mirror mode (pool-level)
#   - rgw daemons, zones, zonegroups; which rgw frontends
#   - crush map stats

class Module(MgrModule):
    config = dict()

    metadata_keys = [
            "arch",
            "ceph_version",
            "os",
            "cpu",
            "kernel_description",
            "kernel_version",
            "distro_description",
            "distro"
    ]

    MODULE_OPTIONS = [
        {
            'name': 'url',
            'type': 'str',
            'default': 'https://telemetry.ceph.com/report'
        },
        {
            'name': 'device_url',
            'type': 'str',
            'default': 'https://telemetry.ceph.com/device'
        },
        {
            'name': 'enabled',
            'type': 'bool',
            'default': False
        },
        {
            'name': 'last_opt_revision',
            'type': 'int',
            'default': 1,
        },
        {
            'name': 'leaderboard',
            'type': 'bool',
            'default': False
        },
        {
            'name': 'description',
            'type': 'str',
            'default': None
        },
        {
            'name': 'contact',
            'type': 'str',
            'default': None
        },
        {
            'name': 'organization',
            'type': 'str',
            'default': None
        },
        {
            'name': 'proxy',
            'type': 'str',
            'default': None
        },
        {
            'name': 'interval',
            'type': 'int',
            'default': 24,
            'min': 8
        },
        {
            'name': 'channel_basic',
            'type': 'bool',
            'default': True,
            'desc': 'Share basic cluster information (size, version)',
        },
        {
            'name': 'channel_ident',
            'type': 'bool',
            'default': False,
            'description': 'Share a user-provided description and/or contact email for the cluster',
        },
        {
            'name': 'channel_crash',
            'type': 'bool',
            'default': True,
            'description': 'Share metadata about Ceph daemon crashes (version, stack straces, etc)',
        },
        {
            'name': 'channel_device',
            'type': 'bool',
            'default': True,
            'description': 'Share device health metrics (e.g., SMART data, minus potentially identifying info like serial numbers)',
        },
        {
            'name': 'channel_perf',
            'type': 'bool',
            'default': False,
            'description': 'Share perf counter metrics summed across the whole cluster',
        },

    ]

    COMMANDS = [
        {
            "cmd": "telemetry status",
            "desc": "Show current configuration",
            "perm": "r"
        },
        {
            "cmd": "telemetry send "
                   "name=endpoint,type=CephChoices,strings=ceph|device,n=N,req=false "
                   "name=license,type=CephString,req=false",
            "desc": "Force sending data to Ceph telemetry",
            "perm": "rw"
        },
        {
            "cmd": "telemetry show "
                   "name=channels,type=CephString,n=N,req=False",
            "desc": "Show last report or report to be sent",
            "perm": "r"
        },
        {
            "cmd": "telemetry show-device",
            "desc": "Show last device report or device report to be sent",
            "perm": "r"
        },
        {
            "cmd": "telemetry show-all",
            "desc": "Show report of all channels",
            "perm": "r"
        },
        {
            "cmd": "telemetry on name=license,type=CephString,req=false",
            "desc": "Enable telemetry reports from this cluster",
            "perm": "rw",
        },
        {
            "cmd": "telemetry off",
            "desc": "Disable telemetry reports from this cluster",
            "perm": "rw",
        },
    ]

    @property
    def config_keys(self):
        return dict((o['name'], o.get('default', None)) for o in self.MODULE_OPTIONS)

    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)
        self.event = Event()
        self.run = False
        self.last_upload = None
        self.last_report = dict()
        self.report_id = None
        self.salt = None

    def config_notify(self):
        for opt in self.MODULE_OPTIONS:
            setattr(self,
                    opt['name'],
                    self.get_module_option(opt['name']))
            self.log.debug(' %s = %s', opt['name'], getattr(self, opt['name']))
        # wake up serve() thread
        self.event.set()

    def load(self):
        self.last_upload = self.get_store('last_upload', None)
        if self.last_upload is not None:
            self.last_upload = int(self.last_upload)

        self.report_id = self.get_store('report_id', None)
        if self.report_id is None:
            self.report_id = str(uuid.uuid4())
            self.set_store('report_id', self.report_id)

        self.salt = self.get_store('salt', None)
        if not self.salt:
            self.salt = str(uuid.uuid4())
            self.set_store('salt', self.salt)

    def gather_osd_metadata(self, osd_map):
        keys = ["osd_objectstore", "rotational"]
        keys += self.metadata_keys

        metadata = dict()
        for key in keys:
            metadata[key] = defaultdict(int)

        for osd in osd_map['osds']:
            res = self.get_metadata('osd', str(osd['osd'])).items()
            if res is None:
                self.log.debug('Could not get metadata for osd.%s' % str(osd['osd']))
                continue
            for k, v in res:
                if k not in keys:
                    continue

                metadata[k][v] += 1

        return metadata

    def gather_mon_metadata(self, mon_map):
        keys = list()
        keys += self.metadata_keys

        metadata = dict()
        for key in keys:
            metadata[key] = defaultdict(int)

        for mon in mon_map['mons']:
            res = self.get_metadata('mon', mon['name']).items()
            if res is None:
                self.log.debug('Could not get metadata for mon.%s' % (mon['name']))
                continue
            for k, v in res:
                if k not in keys:
                    continue

                metadata[k][v] += 1

        return metadata

    def gather_crush_info(self):
        osdmap = self.get_osdmap()
        crush_raw = osdmap.get_crush()
        crush = crush_raw.dump()

        def inc(d, k):
            if k in d:
                d[k] += 1
            else:
                d[k] = 1

        device_classes = {}
        for dev in crush['devices']:
            inc(device_classes, dev.get('class', ''))

        bucket_algs = {}
        bucket_types = {}
        bucket_sizes = {}
        for bucket in crush['buckets']:
            if '~' in bucket['name']:  # ignore shadow buckets
                continue
            inc(bucket_algs, bucket['alg'])
            inc(bucket_types, bucket['type_id'])
            inc(bucket_sizes, len(bucket['items']))

        return {
            'num_devices': len(crush['devices']),
            'num_types': len(crush['types']),
            'num_buckets': len(crush['buckets']),
            'num_rules': len(crush['rules']),
            'device_classes': list(device_classes.values()),
            'tunables': crush['tunables'],
            'compat_weight_set': '-1' in crush['choose_args'],
            'num_weight_sets': len(crush['choose_args']),
            'bucket_algs': bucket_algs,
            'bucket_sizes': bucket_sizes,
            'bucket_types': bucket_types,
        }

    def gather_configs(self):
        # cluster config options
        cluster = set()
        r, outb, outs = self.mon_command({
            'prefix': 'config dump',
            'format': 'json'
        });
        if r != 0:
            return {}
        try:
            dump = json.loads(outb)
        except json.decoder.JSONDecodeError:
            return {}
        for opt in dump:
            name = opt.get('name')
            if name:
                cluster.add(name)
        # daemon-reported options (which may include ceph.conf)
        active = set()
        ls = self.get("modified_config_options");
        for opt in ls.get('options', {}):
            active.add(opt)
        return {
            'cluster_changed': sorted(list(cluster)),
            'active_changed': sorted(list(active)),
        }

    def get_stat_sum_per_pool(self) -> List[dict]:
        # Initialize 'result' list
        result: List[dict] = []

        # Create a list of tuples containing pool ids and their associated names
        # that will later act as a queue, i.e.:
        #   pool_queue = [('1', '.mgr'), ('2', 'cephfs.a.meta'), ('3', 'cephfs.a.data')]
        osd_map = self.get('osd_map')
        pool_queue: List[tuple] = []
        for pool in osd_map['pools']:
            pool_queue.append((str(pool['pool']), pool['pool_name']))

        # Populate 'result', i.e.:
        #   {
        #       'pool_id': '1'
        #       'pool_name': '.mgr'
        #       'stats_sum': {
        #           'num_bytes': 36,
        #           'num_bytes_hit_set_archive': 0,
        #           ...
        #           'num_write_kb': 0
        #           }
        #       }
        #   }
        while pool_queue:
            # Pop a pool out of pool_queue
            curr_pool = pool_queue.pop(0)

            # Get the current pool's id and name
            curr_pool_id, curr_pool_name = curr_pool[0], curr_pool[1]

            # Initialize a dict that will hold aggregated stats for the current pool
            compiled_stats_dict: Dict[str, dict] = defaultdict(lambda: defaultdict(int))

            # Find out which pgs belong to the current pool and add up
            # their stats
            pg_dump = self.get('pg_dump')
            for pg in pg_dump['pg_stats']:
                pool_id = pg['pgid'][0:1]
                if pool_id == curr_pool_id:
                    for metric in pg['stat_sum']:
                        compiled_stats_dict['pool_id'] = int(pool_id)
                        compiled_stats_dict['pool_name'] = curr_pool_name
                        compiled_stats_dict['stats_sum'][metric] += pg['stat_sum'][metric]
                else:
                    continue
            # 'compiled_stats_dict' now holds all stats pertaining to
            # the current pool. Adding it to the list of results.
            result.append(compiled_stats_dict)

        return result

    def get_osd_histograms(self) -> Dict[str, dict]:
        # Initialize result dict
        result: Dict[str, dict] = defaultdict(lambda: defaultdict(
                                              lambda: defaultdict(
                                              lambda: defaultdict(
                                              lambda: defaultdict(
                                              lambda: defaultdict(int))))))

        # Get list of osd ids from the metadata
        osd_metadata = self.get('osd_metadata')
        
        # Grab output from the "osd.x perf histogram dump" command
        for osd_id in osd_metadata:
            cmd_dict = {
                'prefix': 'perf histogram dump',
                'id': str(osd_id),
                'format': 'json'
            }
            r, outb, outs = self.osd_command(cmd_dict)
            # Check for invalid calls
            if r != 0:
                self.log.debug("Invalid command dictionary.")
                continue
            else:
                try:
                    # This is where the histograms will land if there are any.
                    dump = json.loads(outb)

                    for histogram in dump['osd']:
                        # Log axis information. There are two axes, each represented
                        # as a dictionary. Both dictionaries are contained inside a
                        # list called 'axes'.
                        axes = []
                        for axis in dump['osd'][histogram]['axes']:

                            # This is the dict that contains information for an individual
                            # axis. It will be appended to the 'axes' list at the end.
                            axis_dict: Dict[str, dict] = defaultdict(int)

                            # Collecting information for buckets, min, name, etc.
                            # TODO: In some cases, the user might change the size of
                            # their buckets. A check needs to be written that separates
                            # out histograms with unique bucket sizes.
                            axis_dict['buckets'] = axis['buckets']
                            axis_dict['min'] = axis['min']
                            axis_dict['name'] = axis['name']
                            axis_dict['quant_size'] = axis['quant_size']
                            axis_dict['scale_type'] = axis['scale_type']

                            # Collecting ranges; placing them in lists to
                            # improve readability later on.
                            ranges = []
                            for _range in axis['ranges']:
                                _max, _min = None, None
                                if 'max' in _range:
                                    _max = _range['max']
                                if 'min' in _range:
                                    _min = _range['min']
                                ranges.append([_min, _max])
                            axis_dict['ranges'] = ranges

                            # Now that 'axis_dict' contains all the appropriate
                            # information for the current axis, append it to the 'axes' list.
                            # There will end up being two axes in the 'axes' list, since the
                            # histograms are 2D.
                            axes.append(axis_dict)

                        # Add the 'axes' list, containing both axes, to result.
                        result['osd'][histogram]['axes'] = axes

                        # Collect current values and make sure they are in
                        # integer form.
                        values = []
                        for value_list in dump['osd'][histogram]['values']:
                            values.append([int(v) for v in value_list])

                        # Aggregate values. If 'values' have already been initialized,
                        # we can safely add.
                        if 'values' in result['osd'][histogram]:
                            for i in range (0, len(values)):
                                for j in range (0, len(values[i])):
                                    values[i][j] += result['osd'][histogram]['values'][i][j]

                        # Add the values to result.
                        result['osd'][histogram]['values'] = values

                # Sometimes, json errors occur if you give it an empty string.
                # I am also putting in a catch for a KeyError since it could
                # happen where the code is assuming that a key exists in the
                # schema when it doesn't. In either case, we'll handle that
                # bt returning an empty dict.
                except (json.decoder.JSONDecodeError, KeyError) as e:
                    self.log.debug("Error caught: {}".format(e))
                    return {}

        # TODO: Improve the JSON formatting of the histograms to make them
        # more human-readable. This can be done directly in this function with json.dumps(),
        # but it will be better to locate the exact area where the whole report
        # is getting formatted, and make some formatting edits there. We want to ensure
        # that the data is easily retrievable on the server side.
        return result

    def get_io_rate(self) -> dict:
        return self.get('io_rate')

    def gather_crashinfo(self):
        crashlist = list()
        errno, crashids, err = self.remote('crash', 'ls')
        if errno:
            return ''
        for crashid in crashids.split():
            cmd = {'id': crashid}
            errno, crashinfo, err = self.remote('crash', 'do_info', cmd, '')
            if errno:
                continue
            c = json.loads(crashinfo)
            del c['utsname_hostname']
            # entity_name might have more than one '.', beware
            (etype, eid) = c.get('entity_name', '').split('.', 1)
            m = hashlib.sha1()
            m.update(self.salt.encode('utf-8'))
            m.update(eid.encode('utf-8'))
            m.update(self.salt.encode('utf-8'))
            c['entity_name'] = etype + '.' + m.hexdigest()
            crashlist.append(c)
        return crashlist

    def gather_perf_counters(self) -> Dict[str, dict]:
        # Extract perf counter data with get_all_perf_counters(), a method
        # from mgr/mgr_module.py. This method returns a nested dictionary that
        # looks a lot like perf schema, except with some additional fields.
        #
        # Example of output, a snapshot of a mon daemon:
        #   "mon.b": {
        #       "bluestore.kv_flush_lat": {
        #           "count": 2431,
        #           "description": "Average kv_thread flush latency",
        #           "nick": "fl_l",
        #           "priority": 8,
        #           "type": 5,
        #           "units": 1,
        #           "value": 88814109
        #       },
        #   },
        all_perf_counters = self.get_all_perf_counters()

        # Initialize 'result' dict
        result: Dict[str, dict] = defaultdict(lambda: defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))))

        # Condense metrics among like daemons (i.e. 'osd' = 'osd.0' +
        # 'osd.1' + 'osd.2'), and update the 'result' dict.
        for daemon in all_perf_counters:
            daemon_type = daemon[0:3] # i.e. 'mds', 'osd', 'rgw'
            for collection in all_perf_counters[daemon]:

                # Split the collection to avoid redundancy in final report; i.e.:
                #   bluestore.kv_flush_lat, bluestore.kv_final_lat --> 
                #   bluestore: kv_flush_lat, kv_final_lat
                col_0, col_1 = collection.split('.')

                # Debug log for empty keys. This initially was a problem for prioritycache
                # perf counters, where the col_0 was empty for certain mon counters:
                #
                # "mon.a": {                  instead of    "mon.a": {
                #      "": {                                     "prioritycache": {
                #        "cache_bytes": {...},                          "cache_bytes": {...},
                #
                # This log is here to detect any future instances of a similar issue.
                if (daemon == "") or (col_0 == "") or (col_1 == ""):
                    self.log.debug("Instance of an empty key: {}{}".format(daemon, collection))

                # Not every rgw daemon has the same schema. Specifically, each rgw daemon
                # has a uniquely-named collection that starts off identically (i.e.
                # "objecter-0x...") then diverges (i.e. "...55f4e778e140.op_rmw").
                # This bit of code combines these unique counters all under one rgw instance.
                # Without this check, the schema would remain separeted out in the final report.
                if col_0[0:11] == "objecter-0x":
                    col_0 = "objecter-0x"

                # Check that the value can be incremented. In some cases,
                # the files are of type 'pair' (real-integer-pair, integer-integer pair).
                # In those cases, the value is a dictionary, and not a number.
                #   i.e. throttle-msgr_dispatch_throttler-hbserver["wait"]
                if isinstance(all_perf_counters[daemon][collection]['value'], numbers.Number):
                    result[daemon_type][col_0][col_1]['value'] += \
                            all_perf_counters[daemon][collection]['value']
                
                # Check that 'count' exists, as not all counters have a count field. 
                if 'count' in all_perf_counters[daemon][collection]:
                    result[daemon_type][col_0][col_1]['count'] += \
                            all_perf_counters[daemon][collection]['count']

        return result

    def get_active_channels(self):
        r = []
        if self.channel_basic:
            r.append('basic')
        if self.channel_crash:
            r.append('crash')
        if self.channel_device:
            r.append('device')
        if self.channel_ident:
            r.append('ident')
        if self.channel_perf:
            r.append('perf')
        return r

    def gather_device_report(self):
        try:
            time_format = self.remote('devicehealth', 'get_time_format')
        except:
            return None
        cutoff = datetime.utcnow() - timedelta(hours=self.interval * 2)
        min_sample = cutoff.strftime(time_format)

        devices = self.get('devices')['devices']

        res = {}  # anon-host-id -> anon-devid -> { timestamp -> record }
        for d in devices:
            devid = d['devid']
            try:
                # this is a map of stamp -> {device info}
                m = self.remote('devicehealth', 'get_recent_device_metrics',
                                devid, min_sample)
            except:
                continue

            # anonymize host id
            try:
                host = d['location'][0]['host']
            except:
                continue
            anon_host = self.get_store('host-id/%s' % host)
            if not anon_host:
                anon_host = str(uuid.uuid1())
                self.set_store('host-id/%s' % host, anon_host)
            serial = None
            for dev, rep in m.items():
                rep['host_id'] = anon_host
                if serial is None and 'serial_number' in rep:
                    serial = rep['serial_number']

            # anonymize device id
            anon_devid = self.get_store('devid-id/%s' % devid)
            if not anon_devid:
                # ideally devid is 'vendor_model_serial',
                # but can also be 'model_serial', 'serial'
                if '_' in devid:
                    anon_devid = f"{devid.rsplit('_', 1)[0]}_{uuid.uuid1()}"
                else:
                    anon_devid = str(uuid.uuid1())
                self.set_store('devid-id/%s' % devid, anon_devid)
            self.log.info('devid %s / %s, host %s / %s' % (devid, anon_devid,
                                                           host, anon_host))

            # anonymize the smartctl report itself
            if serial:
                m_str = json.dumps(m)
                m = json.loads(m_str.replace(serial, 'deleted'))

            if anon_host not in res:
                res[anon_host] = {}
            res[anon_host][anon_devid] = m
        return res

    def get_latest(self, daemon_type, daemon_name, stat):
        data = self.get_counter(daemon_type, daemon_name, stat)[stat]
        #self.log.error("get_latest {0} data={1}".format(stat, data))
        if data:
            return data[-1][1]
        else:
            return 0

    def compile_report(self, channels=[]):
        if not channels:
            channels = self.get_active_channels()
        report = {
            'leaderboard': self.leaderboard,
            'report_version': 1,
            'report_timestamp': datetime.utcnow().isoformat(),
            'report_id': self.report_id,
            'channels': channels,
            'channels_available': ALL_CHANNELS,
            'license': LICENSE,
        }

        if 'ident' in channels:
            for option in ['description', 'contact', 'organization']:
                report[option] = getattr(self, option)

        if 'basic' in channels:
            mon_map = self.get('mon_map')
            osd_map = self.get('osd_map')
            service_map = self.get('service_map')
            fs_map = self.get('fs_map')
            df = self.get('df')

            report['created'] = mon_map['created']

            # mons
            v1_mons = 0
            v2_mons = 0
            ipv4_mons = 0
            ipv6_mons = 0
            for mon in mon_map['mons']:
                for a in mon['public_addrs']['addrvec']:
                    if a['type'] == 'v2':
                        v2_mons += 1
                    elif a['type'] == 'v1':
                        v1_mons += 1
                    if a['addr'].startswith('['):
                        ipv6_mons += 1
                    else:
                        ipv4_mons += 1
            report['mon'] = {
                'count': len(mon_map['mons']),
                'features': mon_map['features'],
                'min_mon_release': mon_map['min_mon_release'],
                'v1_addr_mons': v1_mons,
                'v2_addr_mons': v2_mons,
                'ipv4_addr_mons': ipv4_mons,
                'ipv6_addr_mons': ipv6_mons,
            }

            report['config'] = self.gather_configs()

            # pools
            report['rbd'] = {
                'num_pools': 0,
                'num_images_by_pool': [],
                'mirroring_by_pool': [],
            }
            num_pg = 0
            report['pools'] = list()
            for pool in osd_map['pools']:
                num_pg += pool['pg_num']
                ec_profile = {}
                if pool['erasure_code_profile']:
                    orig = osd_map['erasure_code_profiles'].get(
                        pool['erasure_code_profile'], {})
                    ec_profile = {
                        k: orig[k] for k in orig.keys()
                        if k in ['k', 'm', 'plugin', 'technique',
                                 'crush-failure-domain', 'l']
                    }
                report['pools'].append(
                    {
                        'pool': pool['pool'],
                        'type': pool['type'],
                        'pg_num': pool['pg_num'],
                        'pgp_num': pool['pg_placement_num'],
                        'size': pool['size'],
                        'min_size': pool['min_size'],
                        'pg_autoscale_mode': pool['pg_autoscale_mode'],
                        'target_max_bytes': pool['target_max_bytes'],
                        'target_max_objects': pool['target_max_objects'],
                        'type': ['', 'replicated', '', 'erasure'][pool['type']],
                        'erasure_code_profile': ec_profile,
                        'cache_mode': pool['cache_mode'],
                    }
                )
                if 'rbd' in pool['application_metadata']:
                    report['rbd']['num_pools'] += 1
                    ioctx = self.rados.open_ioctx(pool['pool_name'])
                    report['rbd']['num_images_by_pool'].append(
                        sum(1 for _ in rbd.RBD().list2(ioctx)))
                    report['rbd']['mirroring_by_pool'].append(
                        rbd.RBD().mirror_mode_get(ioctx) != rbd.RBD_MIRROR_MODE_DISABLED)

            # osds
            cluster_network = False
            for osd in osd_map['osds']:
                if osd['up'] and not cluster_network:
                    front_ip = osd['public_addrs']['addrvec'][0]['addr'].split(':')[0]
                    back_ip = osd['cluster_addrs']['addrvec'][0]['addr'].split(':')[0]
                    if front_ip != back_ip:
                        cluster_network = True
            report['osd'] = {
                'count': len(osd_map['osds']),
                'require_osd_release': osd_map['require_osd_release'],
                'require_min_compat_client': osd_map['require_min_compat_client'],
                'cluster_network': cluster_network,
            }

            # crush
            report['crush'] = self.gather_crush_info()

            # cephfs
            report['fs'] = {
                'count': len(fs_map['filesystems']),
                'feature_flags': fs_map['feature_flags'],
                'num_standby_mds': len(fs_map['standbys']),
                'filesystems': [],
            }
            num_mds = len(fs_map['standbys'])
            for fsm in fs_map['filesystems']:
                fs = fsm['mdsmap']
                num_sessions = 0
                cached_ino = 0
                cached_dn = 0
                cached_cap = 0
                subtrees = 0
                rfiles = 0
                rbytes = 0
                rsnaps = 0
                for gid, mds in fs['info'].items():
                    num_sessions += self.get_latest('mds', mds['name'],
                                                    'mds_sessions.session_count')
                    cached_ino += self.get_latest('mds', mds['name'],
                                                  'mds_mem.ino')
                    cached_dn += self.get_latest('mds', mds['name'],
                                                 'mds_mem.dn')
                    cached_cap += self.get_latest('mds', mds['name'],
                                                  'mds_mem.cap')
                    subtrees += self.get_latest('mds', mds['name'],
                                                'mds.subtrees')
                    if mds['rank'] == 0:
                        rfiles = self.get_latest('mds', mds['name'],
                                                 'mds.root_rfiles')
                        rbytes = self.get_latest('mds', mds['name'],
                                                 'mds.root_rbytes')
                        rsnaps = self.get_latest('mds', mds['name'],
                                                 'mds.root_rsnaps')
                report['fs']['filesystems'].append({
                    'max_mds': fs['max_mds'],
                    'ever_allowed_features': fs['ever_allowed_features'],
                    'explicitly_allowed_features': fs['explicitly_allowed_features'],
                    'num_in': len(fs['in']),
                    'num_up': len(fs['up']),
                    'num_standby_replay': len(
                        [mds for gid, mds in fs['info'].items()
                         if mds['state'] == 'up:standby-replay']),
                    'num_mds': len(fs['info']),
                    'num_sessions': num_sessions,
                    'cached_inos': cached_ino,
                    'cached_dns': cached_dn,
                    'cached_caps': cached_cap,
                    'cached_subtrees': subtrees,
                    'balancer_enabled': len(fs['balancer']) > 0,
                    'num_data_pools': len(fs['data_pools']),
                    'standby_count_wanted': fs['standby_count_wanted'],
                    'approx_ctime': fs['created'][0:7],
                    'files': rfiles,
                    'bytes': rbytes,
                    'snaps': rsnaps,
                })
                num_mds += len(fs['info'])
            report['fs']['total_num_mds'] = num_mds

            # daemons
            report['metadata'] = dict()
            report['metadata']['osd'] = self.gather_osd_metadata(osd_map)
            report['metadata']['mon'] = self.gather_mon_metadata(mon_map)

            # host counts
            servers = self.list_servers()
            self.log.debug('servers %s' % servers)
            report['hosts'] = {
                'num': len([h for h in servers if h['hostname']]),
            }
            for t in ['mon', 'mds', 'osd', 'mgr']:
                report['hosts']['num_with_' + t] = len(
                    [h for h in servers
                     if len([s for s in h['services'] if s['type'] == t])]
                )

            report['usage'] = {
                'pools': len(df['pools']),
                'pg_num': num_pg,
                'total_used_bytes': df['stats']['total_used_bytes'],
                'total_bytes': df['stats']['total_bytes'],
                'total_avail_bytes': df['stats']['total_avail_bytes']
            }

            report['services'] = defaultdict(int)
            for key, value in service_map['services'].items():
                report['services'][key] += 1
                if key == 'rgw':
                    report['rgw'] = {
                        'count': 0,
                    }
                    zones = set()
                    realms = set()
                    zonegroups = set()
                    frontends = set()
                    d = value.get('daemons', dict())

                    for k,v in d.items():
                        if k == 'summary' and v:
                            report['rgw'][k] = v
                        elif isinstance(v, dict) and 'metadata' in v:
                            report['rgw']['count'] += 1
                            zones.add(v['metadata']['zone_id'])
                            zonegroups.add(v['metadata']['zonegroup_id'])
                            frontends.add(v['metadata']['frontend_type#0'])

                            # we could actually iterate over all the keys of
                            # the dict and check for how many frontends there
                            # are, but it is unlikely that one would be running
                            # more than 2 supported ones
                            f2 = v['metadata'].get('frontend_type#1', None)
                            if f2:
                                frontends.add(f2)

                    report['rgw']['zones'] = len(zones)
                    report['rgw']['zonegroups'] = len(zonegroups)
                    report['rgw']['frontends'] = list(frontends)  # sets aren't json-serializable

            try:
                report['balancer'] = self.remote('balancer', 'gather_telemetry')
            except ImportError:
                report['balancer'] = {
                    'active': False
                }

        if 'crash' in channels:
            report['crashes'] = self.gather_crashinfo()

        if 'perf' in channels:
            report['perf_counters'] = self.gather_perf_counters()
            report['stat_sum_per_pool'] = self.get_stat_sum_per_pool()
            report['io_rate'] = self.get_io_rate()
            report['osd_perf_histograms'] = self.get_osd_histograms()

        # NOTE: We do not include the 'device' channel in this report; it is
        # sent to a different endpoint.

        return report

    def _try_post(self, what, url, report):
        self.log.info('Sending %s to: %s' % (what, url))
        proxies = dict()
        if self.proxy:
            self.log.info('Send using HTTP(S) proxy: %s', self.proxy)
            proxies['http'] = self.proxy
            proxies['https'] = self.proxy
        try:
            resp = requests.put(url=url, json=report, proxies=proxies)
            resp.raise_for_status()
        except Exception as e:
            fail_reason = 'Failed to send %s to %s: %s' % (what, url, str(e))
            self.log.error(fail_reason)
            return fail_reason
        return None

    def send(self, report, endpoint=None):
        if not endpoint:
            endpoint = ['ceph', 'device']
        failed = []
        success = []
        self.log.debug('Send endpoints %s' % endpoint)
        for e in endpoint:
            if e == 'ceph':
                fail_reason = self._try_post('ceph report', self.url, report)
                if fail_reason:
                    failed.append(fail_reason)
                else:
                    now = int(time.time())
                    self.last_upload = now
                    self.set_store('last_upload', str(now))
                    success.append('Ceph report sent to {0}'.format(self.url))
                    self.log.info('Sent report to {0}'.format(self.url))
            elif e == 'device':
                if 'device' in self.get_active_channels():
                    devices = self.gather_device_report()
                    num_devs = 0
                    num_hosts = 0
                    for host, ls in devices.items():
                        self.log.debug('host %s devices %s' % (host, ls))
                        if not len(ls):
                            continue
                        fail_reason = self._try_post('devices', self.device_url,
                                                     ls)
                        if fail_reason:
                            failed.append(fail_reason)
                        else:
                            num_devs += len(ls)
                            num_hosts += 1
                    if num_devs:
                        success.append('Reported %d devices across %d hosts' % (
                            num_devs, len(devices)))
        if failed:
            return 1, '', '\n'.join(success + failed)
        return 0, '', '\n'.join(success)

    def handle_command(self, inbuf, command):
        if command['prefix'] == 'telemetry status':
            r = {}
            for opt in self.MODULE_OPTIONS:
                r[opt['name']] = getattr(self, opt['name'])
            r['last_upload'] = time.ctime(self.last_upload) if self.last_upload else self.last_upload
            return 0, json.dumps(r, indent=4, sort_keys=True), ''
        elif command['prefix'] == 'telemetry on':
            if command.get('license') != LICENSE:
                return -errno.EPERM, '', "Telemetry data is licensed under the " + LICENSE_NAME + " (" + LICENSE_URL + ").\nTo enable, add '--license " + LICENSE + "' to the 'ceph telemetry on' command."
            self.on()
            return 0, '', ''
        elif command['prefix'] == 'telemetry off':
            self.off()
            return 0, '', ''
        elif command['prefix'] == 'telemetry send':
            if self.last_opt_revision < LAST_REVISION_RE_OPT_IN and command.get('license') != LICENSE:
                self.log.debug('A telemetry send attempt while opted-out. Asking for license agreement')
                return -errno.EPERM, '', "Telemetry data is licensed under the " + LICENSE_NAME + " (" + LICENSE_URL + ").\nTo manually send telemetry data, add '--license " + LICENSE + "' to the 'ceph telemetry send' command.\nPlease consider enabling the telemetry module with 'ceph telemetry on'."
            self.last_report = self.compile_report()
            return self.send(self.last_report, command.get('endpoint'))

        elif command['prefix'] == 'telemetry show':
            report = self.get_report(channels=command.get('channels', None))
            report = json.dumps(report, indent=4, sort_keys=True)
            if self.channel_device:
                report += '\n \nDevice report is generated separately. To see it run \'ceph telemetry show-device\'.'
            return 0, report, ''
        elif command['prefix'] == 'telemetry show-device':
            return 0, json.dumps(self.get_report('device'), indent=4, sort_keys=True), ''
        elif command['prefix'] == 'telemetry show-all':
            return 0, json.dumps(self.get_report('all'), indent=4, sort_keys=True), ''
        else:
            return (-errno.EINVAL, '',
                    "Command not found '{0}'".format(command['prefix']))

    def on(self):
        self.set_module_option('enabled', True)
        self.set_module_option('last_opt_revision', REVISION)

    def off(self):
        self.set_module_option('enabled', False)
        self.set_module_option('last_opt_revision', 1)

    def get_report(self, report_type='default', channels=None):
        if report_type == 'default':
            return self.compile_report(channels=channels)
        elif report_type == 'device':
            return self.gather_device_report()
        elif report_type == 'all':
            return {'report': self.compile_report(channels=channels),
                    'device_report': self.gather_device_report()}
        return {}

    def self_test(self):
        report = self.compile_report()
        if len(report) == 0:
            raise RuntimeError('Report is empty')

        if 'report_id' not in report:
            raise RuntimeError('report_id not found in report')

    def shutdown(self):
        self.run = False
        self.event.set()

    def refresh_health_checks(self):
        health_checks = {}
        if self.enabled and self.last_opt_revision < LAST_REVISION_RE_OPT_IN:
            health_checks['TELEMETRY_CHANGED'] = {
                'severity': 'warning',
                'summary': 'Telemetry requires re-opt-in',
                'detail': [
                    'telemetry report includes new information; must re-opt-in (or out)'
                ]
            }
        self.set_health_checks(health_checks)

    def serve(self):
        self.load()
        self.config_notify()
        self.run = True

        self.log.debug('Waiting for mgr to warm up')
        self.event.wait(10)

        while self.run:
            self.event.clear()

            self.refresh_health_checks()

            if self.last_opt_revision < LAST_REVISION_RE_OPT_IN:
                self.log.debug('Not sending report until user re-opts-in')
                self.event.wait(1800)
                continue
            if not self.enabled:
                self.log.debug('Not sending report until configured to do so')
                self.event.wait(1800)
                continue

            now = int(time.time())
            if not self.last_upload or (now - self.last_upload) > \
                            self.interval * 3600:
                self.log.info('Compiling and sending report to %s',
                              self.url)

                try:
                    self.last_report = self.compile_report()
                except:
                    self.log.exception('Exception while compiling report:')

                self.send(self.last_report)
            else:
                self.log.debug('Interval for sending new report has not expired')

            sleep = 3600
            self.log.debug('Sleeping for %d seconds', sleep)
            self.event.wait(sleep)

    def self_test(self):
        self.compile_report()
        return True

    @staticmethod
    def can_run():
        return True, ''
