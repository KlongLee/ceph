import os
import json
import time
import errno
import logging

from tasks.cephfs.cephfs_test_case import CephFSTestCase
from teuthology.exceptions import CommandFailedError
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

def extract_schedule_and_retention_spec(spec=[]):
    schedule = set([s[0] for s in spec])
    retention = set([s[1] for s in spec])
    return (schedule, retention)

def seconds_upto_next_schedule(time_from, timo):
    ts = int(time_from)
    return ((int(ts / 60) * 60) + timo) - ts

class TestSnapSchedules(CephFSTestCase):
    CLIENTS_REQUIRED = 1

    TEST_VOLUME_NAME = 'snap_vol'
    TEST_DIRECTORY = 'snap_test_dir1'

    # this should be in sync with snap_schedule format
    SNAPSHOT_TS_FORMAT = '%Y-%m-%d-%H_%M_%S'

    def check_scheduled_snapshot(self, exec_time, timo):
        now = time.time()
        delta = now - exec_time
        log.debug(f'exec={exec_time}, now = {now}, timo = {timo}')
        # tolerate snapshot existance in the range [-5,+5]
        self.assertTrue((delta <= timo + 5) and (delta >= timo - 5))

    def _fs_cmd(self, *args):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("fs", *args)

    def fs_snap_schedule_cmd(self, *args):
        args = list(args)
        args.append(f'fs={self.volname}')
        res = self._fs_cmd('snap-schedule', *args)
        log.debug(f'res={res}')
        return res

    def _create_or_reuse_test_volume(self):
        result = json.loads(self._fs_cmd("volume", "ls"))
        if len(result) == 0:
            self.vol_created = True
            self.volname = TestSnapSchedules.TEST_VOLUME_NAME
            self._fs_cmd("volume", "create", self.volname)
        else:
            self.volname = result[0]['name']

    def _enable_snap_schedule(self):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("mgr", "module", "enable", "snap_schedule")

    def _disable_snap_schedule(self):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("mgr", "module", "disable", "snap_schedule")

    def _allow_minute_granularity_snapshots(self):
        self.config_set('mgr', 'mgr/snap_schedule/allow_m_granularity', True)

    def _dump_on_update(self):
        self.config_set('mgr', 'mgr/snap_schedule/dump_on_update', True)

    def setUp(self):
        super(TestSnapSchedules, self).setUp()
        self.volname = None
        self.vol_created = False
        self._create_or_reuse_test_volume()
        self.create_cbks = []
        self.remove_cbks = []
        # used to figure out which snapshots are created/deleted
        self.snapshots = set()
        self._enable_snap_schedule()
        self._allow_minute_granularity_snapshots()
        self._dump_on_update()

    def tearDown(self):
        if self.vol_created:
            self._delete_test_volume()
        self._disable_snap_schedule()
        super(TestSnapSchedules, self).tearDown()

    def _schedule_to_timeout(self, schedule):
        mult = schedule[-1]
        period = int(schedule[0:-1])
        if mult == 'M':
            return period * 60
        elif mult == 'h':
            return period * 60 * 60
        elif mult == 'd':
            return period * 60 * 60 * 24
        elif mult == 'w':
            return period * 60 * 60 * 24 * 7
        else:
            raise RuntimeError('schedule multiplier not recognized')

    def add_snap_create_cbk(self, cbk):
        self.create_cbks.append(cbk)
    def remove_snap_create_cbk(self, cbk):
        self.create_cbks.remove(cbk)

    def add_snap_remove_cbk(self, cbk):
        self.remove_cbks.append(cbk)
    def remove_snap_remove_cbk(self, cbk):
        self.remove_cbks.remove(cbk)

    def assert_if_not_verified(self):
        self.assertListEqual(self.create_cbks, [])
        self.assertListEqual(self.remove_cbks, [])

    def verify(self, dir_path, max_trials):
        trials = 0
        snap_path = "{0}/.snap".format(dir_path)
        while (len(self.create_cbks) or len(self.remove_cbks)) and trials < max_trials:
            snapshots = set(self.mount_a.ls(path=snap_path))
            log.info(f"snapshots: {snapshots}")
            added = snapshots - self.snapshots
            log.info(f"added: {added}")
            removed = self.snapshots - snapshots
            log.info(f"removed: {removed}")
            if added:
                for cbk in list(self.create_cbks):
                    res = cbk(list(added))
                    if res:
                        self.remove_snap_create_cbk(cbk)
                        break
            if removed:
                for cbk in list(self.remove_cbks):
                    res = cbk(list(removed))
                    if res:
                        self.remove_snap_remove_cbk(cbk)
                        break
            self.snapshots = snapshots
            trials += 1
            time.sleep(1)

    def calc_wait_time_and_snap_name(self, snap_sched_exec_epoch, schedule):
        timo = self._schedule_to_timeout(schedule)
        # calculate wait time upto the next minute
        wait_timo = seconds_upto_next_schedule(snap_sched_exec_epoch, timo)

        # expected "scheduled" snapshot name
        ts_name = (datetime.utcfromtimestamp(snap_sched_exec_epoch)
                   + timedelta(seconds=wait_timo)).strftime(TestSnapSchedules.SNAPSHOT_TS_FORMAT)
        return (wait_timo, ts_name)

    def verify_schedule(self, dir_path, schedules, retentions=[]):
        log.debug(f'expected_schedule: {schedules}, expected_retention: {retentions}')

        result = self.fs_snap_schedule_cmd('list', f'path={dir_path}', 'format=json')
        json_res = json.loads(result)
        log.debug(f'json_res: {json_res}')

        for schedule in schedules:
            self.assertTrue(schedule in json_res['schedule'])
        for retention in retentions:
            self.assertTrue(retention in json_res['retention'])

    def remove_snapshots(self, dir_path):
        snap_path = f'{dir_path}/.snap'

        snapshots = self.mount_a.ls(path=snap_path)
        for snapshot in snapshots:
            snapshot_path = os.path.join(snap_path, snapshot)
            log.debug(f'removing snapshot: {snapshot_path}')
            self.mount_a.run_shell(['rmdir', snapshot_path])

    def test_non_existent_snap_schedule_list(self):
        """Test listing snap schedules on a non-existing filesystem path failure"""
        try:
            self.fs_snap_schedule_cmd('list', f'path={TestSnapSchedules.TEST_DIRECTORY}')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.ENOENT:
                raise RuntimeError('incorrect errno when listing a non-existing snap schedule')
        else:
            raise RuntimeError('expected "fs snap-schedule list" to fail')

    def test_non_existent_schedule(self):
        """Test listing non-existing snap schedules failure"""
        self.mount_a.run_shell(['mkdir', '-p', TestSnapSchedules.TEST_DIRECTORY])

        try:
            self.fs_snap_schedule_cmd('list', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'format=json')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.ENOENT:
                raise RuntimeError('incorrect errno when listing a non-existing snap schedule')
        else:
            raise RuntimeError('expected "fs snap-schedule list" returned fail')

        self.mount_a.run_shell(['rmdir', TestSnapSchedules.TEST_DIRECTORY])

    def test_snap_schedule_list_post_schedule_remove(self):
        """Test listing snap schedules post removal of a schedule"""
        self.mount_a.run_shell(['mkdir', '-p', TestSnapSchedules.TEST_DIRECTORY])

        self.fs_snap_schedule_cmd('add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'snap-schedule=1h')

        self.fs_snap_schedule_cmd('remove', f'path={TestSnapSchedules.TEST_DIRECTORY}')

        try:
            self.fs_snap_schedule_cmd('list', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'format=json')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.ENOENT:
                raise RuntimeError('incorrect errno when listing a non-existing snap schedule')
        else:
            raise RuntimeError('"fs snap-schedule list" returned error')

        self.mount_a.run_shell(['rmdir', TestSnapSchedules.TEST_DIRECTORY])

    def test_snap_schedule(self):
        """Test existence of a scheduled snapshot"""
        self.mount_a.run_shell(['mkdir', '-p', TestSnapSchedules.TEST_DIRECTORY])

        # set a schedule on the dir
        self.fs_snap_schedule_cmd('add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'snap-schedule=1M')
        exec_time = time.time()

        timo, snap_sfx = self.calc_wait_time_and_snap_name(exec_time, '1M')
        log.debug(f'expecting snap {TestSnapSchedules.TEST_DIRECTORY}/.snap/scheduled-{snap_sfx} in ~{timo}s...')
        to_wait = timo + 2 # some leeway to avoid false failures...

        # verify snapshot schedule
        self.verify_schedule(TestSnapSchedules.TEST_DIRECTORY, ['1M'])

        def verify_added(snaps_added):
            log.debug(f'snapshots added={snaps_added}')
            self.assertEquals(len(snaps_added), 1)
            snapname = snaps_added[0]
            if snapname.startswith('scheduled-') and snapname[10:] == snap_sfx:
                self.check_scheduled_snapshot(exec_time, timo)
                return True
            return False
        self.add_snap_create_cbk(verify_added)
        self.verify(TestSnapSchedules.TEST_DIRECTORY, to_wait)
        self.assert_if_not_verified()

        # remove snapshot schedule
        self.fs_snap_schedule_cmd('remove', f'path={TestSnapSchedules.TEST_DIRECTORY}')

        # remove all scheduled snapshots
        self.remove_snapshots(TestSnapSchedules.TEST_DIRECTORY)

        self.mount_a.run_shell(['rmdir', TestSnapSchedules.TEST_DIRECTORY])

    def test_multi_snap_schedule(self):
        """Test exisitence of multiple scheduled snapshots"""
        self.mount_a.run_shell(['mkdir', '-p', TestSnapSchedules.TEST_DIRECTORY])

        # set schedules on the dir
        self.fs_snap_schedule_cmd('add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'snap-schedule=1M')
        self.fs_snap_schedule_cmd('add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'snap-schedule=2M')
        exec_time = time.time()

        timo_1, snap_sfx_1 = self.calc_wait_time_and_snap_name(exec_time, '1M')
        log.debug(f'expecting snap {TestSnapSchedules.TEST_DIRECTORY}/.snap/scheduled-{snap_sfx_1} in ~{timo_1}s...')
        timo_2, snap_sfx_2 = self.calc_wait_time_and_snap_name(exec_time, '2M')
        log.debug(f'expecting snap {TestSnapSchedules.TEST_DIRECTORY}/.snap/scheduled-{snap_sfx_2} in ~{timo_2}s...')
        to_wait = timo_2 + 2 # use max timeout

        # verify snapshot schedule
        self.verify_schedule(TestSnapSchedules.TEST_DIRECTORY, ['1M', '2M'])

        def verify_added_1(snaps_added):
            log.debug(f'snapshots added={snaps_added}')
            self.assertEquals(len(snaps_added), 1)
            snapname = snaps_added[0]
            if snapname.startswith('scheduled-') and snapname[10:] == snap_sfx_1:
                self.check_scheduled_snapshot(exec_time, timo_1)
                return True
            return False
        def verify_added_2(snaps_added):
            log.debug(f'snapshots added={snaps_added}')
            self.assertEquals(len(snaps_added), 1)
            snapname = snaps_added[0]
            if snapname.startswith('scheduled-') and snapname[10:] == snap_sfx_2:
                self.check_scheduled_snapshot(exec_time, timo_2)
                return True
            return False
        self.add_snap_create_cbk(verify_added_1)
        self.add_snap_create_cbk(verify_added_2)
        self.verify(TestSnapSchedules.TEST_DIRECTORY, to_wait)
        self.assert_if_not_verified()

        # remove snapshot schedule
        self.fs_snap_schedule_cmd('remove', f'path={TestSnapSchedules.TEST_DIRECTORY}')

        # remove all scheduled snapshots
        self.remove_snapshots(TestSnapSchedules.TEST_DIRECTORY)

        self.mount_a.run_shell(['rmdir', TestSnapSchedules.TEST_DIRECTORY])

    def test_snap_schedule_with_retention(self):
        """Test scheduled snapshots along with rentention policy"""
        self.mount_a.run_shell(['mkdir', '-p', TestSnapSchedules.TEST_DIRECTORY])

        # set a schedule on the dir
        self.fs_snap_schedule_cmd('add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'snap-schedule=1M')
        self.fs_snap_schedule_cmd('retention', 'add', f'path={TestSnapSchedules.TEST_DIRECTORY}', 'retention-spec-or-period=1M')
        exec_time = time.time()

        timo_1, snap_sfx = self.calc_wait_time_and_snap_name(exec_time, '1M')
        log.debug(f'expecting snap {TestSnapSchedules.TEST_DIRECTORY}/.snap/scheduled-{snap_sfx} in ~{timo_1}s...')
        to_wait = timo_1 + 2 # some leeway to avoid false failures...

        # verify snapshot schedule
        self.verify_schedule(TestSnapSchedules.TEST_DIRECTORY, ['1M'], retentions=[{'M':1}])

        def verify_added(snaps_added):
            log.debug(f'snapshots added={snaps_added}')
            self.assertEquals(len(snaps_added), 1)
            snapname = snaps_added[0]
            if snapname.startswith('scheduled-') and snapname[10:] == snap_sfx:
                self.check_scheduled_snapshot(exec_time, timo_1)
                return True
            return False
        self.add_snap_create_cbk(verify_added)
        self.verify(TestSnapSchedules.TEST_DIRECTORY, to_wait)
        self.assert_if_not_verified()

        timo_2 = timo_1 + 60 # expected snapshot removal timeout
        def verify_removed(snaps_removed):
            log.debug(f'snapshots removed={snaps_removed}')
            self.assertEquals(len(snaps_removed), 1)
            snapname = snaps_removed[0]
            if snapname.startswith('scheduled-') and snapname[10:] == snap_sfx:
                self.check_scheduled_snapshot(exec_time, timo_2)
                return True
            return False
        log.debug(f'expecting removal of snap {TestSnapSchedules.TEST_DIRECTORY}/.snap/scheduled-{snap_sfx} in ~{timo_2}s...')
        to_wait = timo_2
        self.add_snap_remove_cbk(verify_removed)
        self.verify(TestSnapSchedules.TEST_DIRECTORY, to_wait+2)
        self.assert_if_not_verified()

        # remove snapshot schedule
        self.fs_snap_schedule_cmd('remove', f'path={TestSnapSchedules.TEST_DIRECTORY}')

        # remove all scheduled snapshots
        self.remove_snapshots(TestSnapSchedules.TEST_DIRECTORY)

        self.mount_a.run_shell(['rmdir', TestSnapSchedules.TEST_DIRECTORY])
