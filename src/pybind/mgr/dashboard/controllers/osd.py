# -*- coding: utf-8 -*-
from datetime import datetime
from __future__ import absolute_import
from . import ApiController, RESTController, UpdatePermission
from .. import mgr, logger
from ..security import Scope
from ..services.ceph_service import CephService, SendCommandError
from ..services.exception import handle_send_command_error
from ..tools import str_to_bool

WEEK_DAYS_TIME = 7 * 24 * 60 * 60


@ApiController('/osd', Scope.OSD)
class Osd(RESTController):
    def list(self):
        osds = self.get_osd_map()
        devices = mgr.get('devices')
        # Extending by osd stats information
        for s in mgr.get('osd_stats')['osd_stats']:
            osds[str(s['osd'])].update({'osd_stats': s})
        # Extending by osd node information
        nodes = mgr.get('osd_map_tree')['nodes']
        osd_tree = [(str(o['id']), o) for o in nodes if o['id'] >= 0]
        for o in osd_tree:
            osds[o[0]].update({'tree': o[1]})
        # Extending by osd parent node information
        hosts = [(h['name'], h) for h in nodes if h['id'] < 0]
        for h in hosts:
            for o_id in h[1]['children']:
                if o_id >= 0:
                    osds[str(o_id)]['host'] = h[1]
        # Extending by osd histogram data
        for o_id in osds:
            o = osds[o_id]
            o['stats'] = {}
            o['stats_history'] = {}
            life_expectancy_weeks = None
            # Get device info
            devs = self._parse_osd_devices(o_id, devices)
            o['devices'] = \
                {
                    dev_info.get('dev_id'):
                        self._get_device_life_expectancy_weeks(dev_info) for dev_info in devs}
            if o['devices'] and o['devices'].values():
                try:
                    life_expectancy_weeks = min(filter(None, o['devices'].values()))
                except ValueError:
                    life_expectancy_weeks = None
            osd_spec = str(o['osd'])
            for s in ['osd.op_w', 'osd.op_in_bytes', 'osd.op_r', 'osd.op_out_bytes']:
                prop = s.split('.')[1]
                o['stats'][prop] = CephService.get_rate('osd', osd_spec, s)
                o['stats_history'][prop] = CephService.get_rates('osd', osd_spec, s)
            o['stats']['lf_s'] = self._convert_expectency_state(life_expectancy_weeks)
            # Gauge stats
            for s in ['osd.numpg', 'osd.stat_bytes', 'osd.stat_bytes_used']:
                o['stats'][s.split('.')[1]] = mgr.get_latest('osd', osd_spec, s)
        return list(osds.values())

    def get_osd_map(self):
        osds = {}
        for osd in mgr.get('osd_map')['osds']:
            osd['id'] = osd['osd']
            osds[str(osd['id'])] = osd
        return osds

    def _convert_expectency_state(self, life_expectancy_weeks):
        if life_expectancy_weeks is None:
            state = 'unknown'
        elif life_expectancy_weeks >= 6:
            state = 'green'
        elif 6 > life_expectancy_weeks >= 4:
            state = 'yellow'
        elif life_expectancy_weeks < 4:
            state = 'red'
        return state

    def _get_device_life_expectancy_weeks(self, dev_info):
        life_expectancy_weeks = None
        dev_id = dev_info.get('dev_id', 'None')
        try:
            if dev_info:
                i_to_day = None
                i_from_day = None
                from_day = dev_info.get('life_expectancy_min', '')
                to_day = dev_info.get('life_expectancy_max', '')
                if to_day:
                    try:
                        i_to_day = \
                            int(datetime.strptime(
                                to_day[:10], '%Y-%m-%d').strftime('%s'))
                    except ValueError:
                        i_to_day = None
                if from_day:
                    try:
                        i_from_day = \
                            int(datetime.strptime(
                                from_day[:10], '%Y-%m-%d').strftime('%s'))
                    except ValueError:
                        i_from_day = None
                if i_to_day and i_from_day:
                    life_expectancy_weeks = \
                        int((i_to_day - i_from_day) // WEEK_DAYS_TIME)
                elif i_from_day and not i_to_day:
                    # When i_to_day is not defied, it means forever life.
                    life_expectancy_weeks = 9999
        except ValueError:
            logger.error(
                'failed to parse device %s life expectancy weeks', dev_id)
        return life_expectancy_weeks

    def _parse_osd_devices(self, osd_id, devices):
        result = []
        if str(osd_id).isdigit():
            osd_name = 'osd.%s' % osd_id
        else:
            osd_name = osd_id
        if devices:
            for dev in devices.get('devices', []):
                if osd_name in dev.get('daemons', []):
                    dev_id = dev.get('devid')
                    dev_info = {
                        'dev_id': dev_id,
                        'life_expectancy_max':
                            dev.get('life_expectancy_max', None),
                        'life_expectancy_min':
                            dev.get('life_expectancy_min', None)
                    }
                    result.append(dev_info)
        return result

    @handle_send_command_error('osd')
    def get(self, svc_id):
        histogram = CephService.send_command('osd', srv_spec=svc_id, prefix='perf histogram dump')
        return {
            'osd_map': self.get_osd_map()[svc_id],
            'osd_metadata': mgr.get_metadata('osd', svc_id),
            'histogram': histogram,
        }

    @RESTController.Resource('POST', query_params=['deep'])
    @UpdatePermission
    def scrub(self, svc_id, deep=False):
        api_scrub = "osd deep-scrub" if str_to_bool(deep) else "osd scrub"
        CephService.send_command("mon", api_scrub, who=svc_id)

    @RESTController.Resource('POST')
    def mark_out(self, svc_id):
        CephService.send_command('mon', 'osd out', ids=[svc_id])

    @RESTController.Resource('POST')
    def mark_in(self, svc_id):
        CephService.send_command('mon', 'osd in', ids=[svc_id])

    @RESTController.Resource('POST')
    def mark_down(self, svc_id):
        CephService.send_command('mon', 'osd down', ids=[svc_id])

    @RESTController.Resource('POST')
    def reweight(self, svc_id, weight):
        """
        Reweights the OSD temporarily.

        Note that ‘ceph osd reweight’ is not a persistent setting. When an OSD
        gets marked out, the osd weight will be set to 0. When it gets marked
        in again, the weight will be changed to 1.

        Because of this ‘ceph osd reweight’ is a temporary solution. You should
        only use it to keep your cluster running while you’re ordering more
        hardware.

        - Craig Lewis (http://lists.ceph.com/pipermail/ceph-users-ceph.com/2014-June/040967.html)
        """
        CephService.send_command(
            'mon',
            'osd reweight',
            id=int(svc_id),
            weight=float(weight))

    @RESTController.Resource('POST')
    def mark_lost(self, svc_id):
        """
        Note: osd must be marked `down` before marking lost.
        """
        CephService.send_command(
            'mon',
            'osd lost',
            id=int(svc_id),
            sure='--yes-i-really-mean-it')

    def create(self, uuid=None, svc_id=None):
        """
        :param uuid: Will be set automatically if the OSD starts up.
        :param id: The ID is only used if a valid uuid is given.
        :return:
        """
        result = CephService.send_command(
            'mon', 'osd create', id=svc_id, uuid=uuid)
        return {
            'result': result,
            'svc_id': svc_id,
            'uuid': uuid,
        }

    @RESTController.Resource('POST')
    def remove(self, svc_id):
        """
        Note: osd must be marked `down` before removal.
        """
        CephService.send_command('mon', 'osd rm', ids=[svc_id])

    @RESTController.Resource('POST')
    def destroy(self, svc_id):
        """
        Mark osd as being destroyed. Keeps the ID intact (allowing reuse), but
        removes cephx keys, config-key data and lockbox keys, rendering data
        permanently unreadable.

        The osd must be marked down before being destroyed.
        """
        CephService.send_command(
            'mon', 'osd destroy-actual', id=int(svc_id), sure='--yes-i-really-mean-it')

    @RESTController.Resource('GET')
    def safe_to_destroy(self, svc_id):
        """
        :type svc_id: int|[int]
        """
        if not isinstance(svc_id, list):
            svc_id = [svc_id]
        svc_id = list(map(str, svc_id))
        try:
            CephService.send_command(
                'mon', 'osd safe-to-destroy', ids=svc_id, target=('mgr', ''))
            return {'safe-to-destroy': True}
        except SendCommandError as e:
            return {
                'message': e.message,
                'safe-to-destroy': False,
            }


@ApiController('/osd/flags', Scope.OSD)
class OsdFlagsController(RESTController):
    @staticmethod
    def _osd_flags():
        enabled_flags = mgr.get('osd_map')['flags_set']
        if 'pauserd' in enabled_flags and 'pausewr' in enabled_flags:
            # 'pause' is set by calling `ceph osd set pause` and unset by
            # calling `set osd unset pause`, but `ceph osd dump | jq '.flags'`
            # will contain 'pauserd,pausewr' if pause is set.
            # Let's pretend to the API that 'pause' is in fact a proper flag.
            enabled_flags = list(
                set(enabled_flags) - {'pauserd', 'pausewr'} | {'pause'})
        return sorted(enabled_flags)

    def list(self):
        return self._osd_flags()

    def bulk_set(self, flags):
        """
        The `recovery_deletes` and `sortbitwise` flags cannot be unset.
        `purged_snapshots` cannot even be set. It is therefore required to at
        least include those three flags for a successful operation.
        """
        assert isinstance(flags, list)

        enabled_flags = set(self._osd_flags())
        data = set(flags)
        added = data - enabled_flags
        removed = enabled_flags - data
        for flag in added:
            CephService.send_command('mon', 'osd set', '', key=flag)
        for flag in removed:
            CephService.send_command('mon', 'osd unset', '', key=flag)
        logger.info('Changed OSD flags: added=%s removed=%s', added, removed)

        return sorted(enabled_flags - removed | added)
