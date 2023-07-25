import os
import json
import errno
import logging
import random
import time

from io import StringIO
from collections import deque

from tasks.cephfs.cephfs_test_case import CephFSTestCase
from teuthology.exceptions import CommandFailedError
from teuthology.contextutil import safe_while

log = logging.getLogger(__name__)


class MirroringHelpers(CephFSTestCase):
    def enable_mirroring_module(self):
        self.run_ceph_cmd("mgr", "module", "enable", "mirroring")

    def disable_mirroring_module(self):
        self.run_ceph_cmd("mgr", "module", "disable", "mirroring")

    def enable_mirroring(self, fs_name, fs_id):
        self.run_ceph_cmd("fs", "snapshot", "mirror", "enable", fs_name)
        time.sleep(10)
        # verify via asok
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        self.assertTrue(res['peers'] == {})
        self.assertTrue(res['snap_dirs']['dir_count'] == 0)

    def disable_mirroring(self, fs_name, fs_id):
        self.run_ceph_cmd("fs", "snapshot", "mirror", "disable", fs_name)
        time.sleep(10)
        # verify via asok
        try:
            self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                       'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        except CommandFailedError:
            pass
        else:
            raise RuntimeError('expected admin socket to be unavailable')

    def verify_peer_added(self, fs, peer_spec, peer_fs_name=None):
        # verify via asok
        res = self.mirror_daemon_command(f'mirror status for fs: {fs.name}',
                                         'fs', 'mirror', 'status', f'{fs.name}@{fs.id}')
        peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_fs_name)
        self.assertTrue(peer_uuid in res['peers'])
        client_name = res['peers'][peer_uuid]['remote']['client_name']
        cluster_name = res['peers'][peer_uuid]['remote']['cluster_name']
        self.assertTrue(peer_spec == f'{client_name}@{cluster_name}')
        if peer_fs_name:
            self.assertTrue(peer_fs_name == res['peers'][peer_uuid]['remote']['fs_name'])
        else:
            self.assertTrue(self.fs.name == res['peers'][peer_uuid]['remote']['fs_name'])

    def peer_add(self, fs, peer_spec, peer_fs_name=None):
        if peer_fs_name:
            self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_add", fs.name, peer_spec, peer_fs_name)
        else:
            self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_add", fs.name, peer_spec)
        time.sleep(10)
        self.verify_peer_added(fs, peer_spec, peer_fs_name)

    def peer_remove(self, fs, peer_spec, peer_name=None):
        peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_name)
        self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_remove", fs.name, peer_uuid)
        time.sleep(10)
        # verify via asok
        res = self.mirror_daemon_command(f'mirror status for fs: {fs.name}',
                                         'fs', 'mirror', 'status', f'{fs.name}@{fs.id}')
        self.assertTrue(res['peers'] == {} and res['snap_dirs']['dir_count'] == 0)

    def remove_peers(self, fs, peer_spec, peers):
        for peer_name in peers:
            peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_name)
            self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_remove",
                              fs.name, peer_uuid)
            time.sleep(10)
        res = self.mirror_daemon_command(f'mirror status for fs: {fs.name}',
                                         'fs', 'mirror', 'status',
                                         f'{fs.name}@{fs.id}')
        self.assertTrue(res['peers'] == {} and res['snap_dirs']['dir_count'] == 0)

    def bootstrap_peer(self, fs_name, client_name, site_name):
        outj = json.loads(self.get_ceph_cmd_stdout(
            "fs", "snapshot", "mirror", "peer_bootstrap", "create", fs_name,
            client_name, site_name))
        return outj['token']

    def import_peer(self, fs_name, token):
        self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_bootstrap",
                          "import", fs_name, token)

    def add_directory(self, fs_name, fs_id, dir_name):
        # get initial dir count
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        dir_count = res['snap_dirs']['dir_count']
        log.debug(f'initial dir_count={dir_count}')

        self.run_ceph_cmd("fs", "snapshot", "mirror", "add", fs_name, dir_name)

        time.sleep(10)
        # verify via asok
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        new_dir_count = res['snap_dirs']['dir_count']
        log.debug(f'new dir_count={new_dir_count}')
        self.assertTrue(new_dir_count > dir_count)

    def remove_directory(self, fs_name, fs_id, dir_name):
        # get initial dir count
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        dir_count = res['snap_dirs']['dir_count']
        log.debug(f'initial dir_count={dir_count}')

        self.run_ceph_cmd("fs", "snapshot", "mirror", "remove", fs_name, dir_name)

        time.sleep(10)
        # verify via asok
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        new_dir_count = res['snap_dirs']['dir_count']
        log.debug(f'new dir_count={new_dir_count}')
        self.assertTrue(new_dir_count < dir_count)

    def check_peer_status(self, fs, dir_name, expected_snap_name,
                          expected_snap_count, peer_spec, peer_name=None):
        peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_name)
        res = self.mirror_daemon_command(f'peer status for fs: {fs.name}',
                                         'fs', 'mirror', 'peer', 'status',
                                         f'{fs.name}@{fs.id}', peer_uuid)
        self.assertTrue(dir_name in res)
        self.assertTrue(res[dir_name]['last_synced_snap']['name'] == expected_snap_name)
        self.assertTrue(res[dir_name]['snaps_synced'] == expected_snap_count)

    def check_peer_status_deleted_snap(self, fs, dir_name,
                                       expected_delete_count, peer_spec,
                                       peer_name=None):
        peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_name)
        res = self.mirror_daemon_command(f'peer status for fs: {fs.name}',
                                         'fs', 'mirror', 'peer', 'status',
                                         f'{fs.name}@{fs.id}', peer_uuid)
        self.assertTrue(dir_name in res)
        self.assertTrue(res[dir_name]['snaps_deleted'] == expected_delete_count)

    def check_peer_status_renamed_snap(self, fs, dir_name,
                                       expected_rename_count, peer_spec,
                                       peer_name=None):
        peer_uuid = self.get_peer_uuid(fs, peer_spec, peer_name)
        res = self.mirror_daemon_command(f'peer status for fs: {fs.name}',
                                         'fs', 'mirror', 'peer', 'status',
                                         f'{fs.name}@{fs.id}', peer_uuid)
        self.assertTrue(dir_name in res)
        self.assertTrue(res[dir_name]['snaps_renamed'] == expected_rename_count)

    def check_peer_snap_in_progress(self, fs, peer_spec, dir_name, snap_name):
        peer_uuid = self.get_peer_uuid(fs, peer_spec)
        res = self.mirror_daemon_command(f'peer status for fs: {fs.name}',
                                         'fs', 'mirror', 'peer', 'status',
                                         f'{fs.name}@{fs.id}', peer_uuid)
        self.assertTrue('syncing' == res[dir_name]['state'])
        self.assertTrue(res[dir_name]['current_sycning_snap']['name'] == snap_name)

    def verify_snapshot(self, dir_name, snap_name, src_mnt=None,
                        dest_mnt=None):
        self.assertGreaterEqual(self.CLIENTS_REQUIRED, 2,
                                "need at least two clients to verify snapshot")

        if src_mnt is None:
            src_mnt = self.mount_a
        if dest_mnt is None:
            dest_mnt = self.mount_b

        snap_list = dest_mnt.ls(path=f'{dir_name}/.snap')
        self.assertTrue(snap_name in snap_list)

        source_res = src_mnt.dir_checksum(path=f'{dir_name}/.snap/{snap_name}',
                                               follow_symlinks=True)
        log.debug(f'source snapshot checksum {snap_name} {source_res}')

        dest_res = dest_mnt.dir_checksum(path=f'{dir_name}/.snap/{snap_name}',
                                         follow_symlinks=True)
        log.debug(f'destination snapshot checksum {snap_name} {dest_res}')
        self.assertTrue(source_res == dest_res)

    def check_snapshot_exists(self, snap, snap_path, mount):
        snap_list = mount.ls(path=snap_path)
        self.assertTrue(snap in snap_list)

    def check_snapshot_doesnt_exist(self, snap, snap_path, mount):
        snap_list = mount.ls(path=snap_path)
        self.assertTrue(snap not in snap_list)

    def verify_failed_directory(self, fs, peer_spec, dir_name):
        peer_uuid = self.get_peer_uuid(fs, peer_spec)
        res = self.mirror_daemon_command(f'peer status for fs: {fs.name}',
                                         'fs', 'mirror', 'peer', 'status',
                                         f'{fs.name}@{fs.id}', peer_uuid)
        self.assertTrue('failed' == res[dir_name]['state'])

    def get_peer_uuid(self, fs, peer_spec, peer_fs_name=None):
        if peer_fs_name is None:
            peer_fs_name = "backup_fs"

        status = fs.status()
        fs_map = status.get_fsmap_byname(fs.name)
        peers = fs_map['mirror_info']['peers']
        for peer_uuid, mirror_info in peers.items():
            client_name = mirror_info['remote']['client_name']
            cluster_name = mirror_info['remote']['cluster_name']
            fs_name = mirror_info['remote']['fs_name']
            remote_peer_spec = f'{client_name}@{cluster_name}'
            if peer_spec == remote_peer_spec and peer_fs_name == fs_name:
                return peer_uuid
        return None

    def get_daemon_admin_socket(self):
        """overloaded by teuthology override (fs/mirror/clients/mirror.yaml)"""
        return "/var/run/ceph/cephfs-mirror.asok"

    def get_mirror_daemon_pid(self):
        """pid file overloaded in fs/mirror/clients/mirror.yaml"""
        return self.mount_a.run_shell(['cat', '/var/run/ceph/cephfs-mirror.pid']).stdout.getvalue().strip()

    def get_mirror_rados_addr(self, fs_name, fs_id):
        """return the rados addr used by cephfs-mirror instance"""
        res = self.mirror_daemon_command(f'mirror status for fs: {fs_name}',
                                         'fs', 'mirror', 'status', f'{fs_name}@{fs_id}')
        return res['rados_inst']

    def mirror_daemon_command(self, cmd_label, *args):
        asok_path = self.get_daemon_admin_socket()
        try:
            # use mount_a's remote to execute command
            p = self.mount_a.client_remote.run(args=
                     ['ceph', '--admin-daemon', asok_path] + list(args),
                     stdout=StringIO(), stderr=StringIO(), timeout=30,
                     check_status=True, label=cmd_label)
            p.wait()
        except CommandFailedError as ce:
            log.warn(f'mirror daemon command with label "{cmd_label}" failed: {ce}')
            raise
        res = p.stdout.getvalue().strip()
        log.debug(f'command returned={res}')
        return json.loads(res)

    def get_mirror_daemon_status(self):
        daemon_status = json.loads(self.get_ceph_cmd_stdout("fs", "snapshot", "mirror", "daemon", "status"))
        log.debug(f'daemon_status: {daemon_status}')
        # running a single mirror daemon is supported
        status = daemon_status[0]
        log.debug(f'status: {status}')
        return status


class TestMirroring(MirroringHelpers):
    MDSS_REQUIRED = 5
    CLIENTS_REQUIRED = 2
    REQUIRE_BACKUP_FILESYSTEM = True

    def setUp(self):
        super(TestMirroring, self).setUp()
        self.primary_fs_name = self.fs.name
        self.primary_fs_id = self.fs.id
        self.secondary_fs_name = self.backup_fs.name
        self.secondary_fs_id = self.backup_fs.id
        self.enable_mirroring_module()

    def tearDown(self):
        self.disable_mirroring_module()
        super(TestMirroring, self).tearDown()

    def test_basic_mirror_commands(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_mirror_peer_commands(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # add peer
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)
        # remove peer
        self.peer_remove(self.fs, "client.mirror_remote@ceph")

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_mirror_disable_with_peer(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # add peer
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_matching_peer(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        try:
            self.peer_add(self.fs, "client.mirror_remote@ceph")
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError('invalid errno when adding a matching remote peer')
        else:
            raise RuntimeError('adding a peer matching local spec should fail')

        # verify via asok -- nothing should get added
        res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                         'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        self.assertTrue(res['peers'] == {})

        # and explicitly specifying the spec (via filesystem name) should fail too
        try:
            self.peer_add(self.fs, "client.mirror_remote@ceph", self.primary_fs_name)
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError('invalid errno when adding a matching remote peer')
        else:
            raise RuntimeError('adding a peer matching local spec should fail')

        # verify via asok -- nothing should get added
        res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                         'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        self.assertTrue(res['peers'] == {})

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_mirror_peer_add_existing(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # add peer
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # adding the same peer should be idempotent
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # remove peer
        self.peer_remove(self.fs, "client.mirror_remote@ceph")

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_peer_commands_with_mirroring_disabled(self):
        # try adding peer when mirroring is not enabled
        try:
            self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when adding a peer')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected peer_add to fail')

        # try removing peer
        try:
            self.run_ceph_cmd("fs", "snapshot", "mirror", "peer_remove", self.primary_fs_name, 'dummy-uuid')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when removing a peer')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected peer_remove to fail')

    def test_add_directory_with_mirroring_disabled(self):
        # try adding a directory when mirroring is not enabled
        try:
            self.add_directory(self.primary_fs_name, self.primary_fs_id, "/d1")
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when adding a directory')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected directory add to fail')

    def test_directory_commands(self):
        self.mount_a.run_shell(["mkdir", "d1"])
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        try:
            self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EEXIST:
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when re-adding a directory')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected directory add to fail')
        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        try:
            self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        except CommandFailedError as ce:
            if ce.exitstatus not in (errno.ENOENT, errno.EINVAL):
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when re-deleting a directory')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected directory removal to fail')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.mount_a.run_shell(["rmdir", "d1"])

    def test_add_relative_directory_path(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        try:
            self.add_directory(self.primary_fs_name, self.primary_fs_id, './d1')
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError(-errno.EINVAL, 'incorrect error code when adding a relative path dir')
        else:
            raise RuntimeError(-errno.EINVAL, 'expected directory add to fail')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_add_directory_path_normalization(self):
        self.mount_a.run_shell(["mkdir", "-p", "d1/d2/d3"])
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1/d2/d3')
        def check_add_command_failure(dir_path):
            try:
                self.add_directory(self.primary_fs_name, self.primary_fs_id, dir_path)
            except CommandFailedError as ce:
                if ce.exitstatus != errno.EEXIST:
                    raise RuntimeError(-errno.EINVAL, 'incorrect error code when re-adding a directory')
            else:
                raise RuntimeError(-errno.EINVAL, 'expected directory add to fail')

        # everything points for /d1/d2/d3
        check_add_command_failure('/d1/d2/././././././d3')
        check_add_command_failure('/d1/d2/././././././d3//////')
        check_add_command_failure('/d1/d2/../d2/././././d3')
        check_add_command_failure('/././././d1/./././d2/./././d3//////')
        check_add_command_failure('/./d1/./d2/./d3/../../../d1/d2/d3')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.mount_a.run_shell(["rm", "-rf", "d1"])

    def test_add_ancestor_and_child_directory(self):
        self.mount_a.run_shell(["mkdir", "-p", "d1/d2/d3"])
        self.mount_a.run_shell(["mkdir", "-p", "d1/d4"])
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1/d2/')
        def check_add_command_failure(dir_path):
            try:
                self.add_directory(self.primary_fs_name, self.primary_fs_id, dir_path)
            except CommandFailedError as ce:
                if ce.exitstatus != errno.EINVAL:
                    raise RuntimeError(-errno.EINVAL, 'incorrect error code when adding a directory')
            else:
                raise RuntimeError(-errno.EINVAL, 'expected directory add to fail')

        # cannot add ancestors or a subtree for an existing directory
        check_add_command_failure('/')
        check_add_command_failure('/d1')
        check_add_command_failure('/d1/d2/d3')

        # obviously, one can add a non-ancestor or non-subtree
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1/d4/')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.mount_a.run_shell(["rm", "-rf", "d1"])

    def test_cephfs_mirror_blocklist(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # add peer
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                         'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        peers_1 = set(res['peers'])

        # fetch rados address for blacklist check
        rados_inst = self.get_mirror_rados_addr(self.primary_fs_name, self.primary_fs_id)

        # simulate non-responding mirror daemon by sending SIGSTOP
        pid = self.get_mirror_daemon_pid()
        log.debug(f'SIGSTOP to cephfs-mirror pid {pid}')
        self.mount_a.run_shell(['kill', '-SIGSTOP', pid])

        # wait for blocklist timeout -- the manager module would blocklist
        # the mirror daemon
        time.sleep(40)

        # wake up the mirror daemon -- at this point, the daemon should know
        # that it has been blocklisted
        log.debug('SIGCONT to cephfs-mirror')
        self.mount_a.run_shell(['kill', '-SIGCONT', pid])

        # check if the rados addr is blocklisted
        self.assertTrue(self.mds_cluster.is_addr_blocklisted(rados_inst))

        # wait enough so that the mirror daemon restarts blocklisted instances
        time.sleep(40)
        rados_inst_new = self.get_mirror_rados_addr(self.primary_fs_name, self.primary_fs_id)

        # and we should get a new rados instance
        self.assertTrue(rados_inst != rados_inst_new)

        # along with peers that were added
        res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                         'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        peers_2 = set(res['peers'])
        self.assertTrue(peers_1, peers_2)

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_stats(self):
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        # create a bunch of files in a directory to snap
        self.mount_a.run_shell(["mkdir", "d0"])
        self.mount_a.create_n_files('d0/file', 50, sync=True)

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # take a snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])

        time.sleep(30)
        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d0', 'snap0')

        # some more IO
        self.mount_a.run_shell(["mkdir", "d0/d00"])
        self.mount_a.run_shell(["mkdir", "d0/d01"])

        self.mount_a.create_n_files('d0/d00/more_file', 20, sync=True)
        self.mount_a.create_n_files('d0/d01/some_more_file', 75, sync=True)

        # take another snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap1"])

        time.sleep(60)
        self.check_peer_status(self.fs, '/d0', 'snap1', 2,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d0', 'snap1')

        # delete a snapshot
        self.mount_a.run_shell(["rmdir", "d0/.snap/snap0"])

        time.sleep(10)
        snap_list = self.mount_b.ls(path='d0/.snap')
        self.assertTrue('snap0' not in snap_list)
        self.check_peer_status_deleted_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph")

        # rename a snapshot
        self.mount_a.run_shell(["mv", "d0/.snap/snap1", "d0/.snap/snap2"])

        time.sleep(10)
        snap_list = self.mount_b.ls(path='d0/.snap')
        self.assertTrue('snap1' not in snap_list)
        self.assertTrue('snap2' in snap_list)
        self.check_peer_status_renamed_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph")

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_cancel_sync(self):
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        # create a bunch of files in a directory to snap
        self.mount_a.run_shell(["mkdir", "d0"])
        for i in range(8):
            filename = f'file.{i}'
            self.mount_a.write_n_mb(os.path.join('d0', filename), 1024)

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # take a snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])

        time.sleep(10)
        self.check_peer_snap_in_progress(self.fs, "client.mirror_remote@ceph", '/d0', 'snap0')

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')

        snap_list = self.mount_b.ls(path='d0/.snap')
        self.assertTrue('snap0' not in snap_list)
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_restart_sync_on_blocklist(self):
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        # create a bunch of files in a directory to snap
        self.mount_a.run_shell(["mkdir", "d0"])
        for i in range(8):
            filename = f'file.{i}'
            self.mount_a.write_n_mb(os.path.join('d0', filename), 1024)

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # fetch rados address for blacklist check
        rados_inst = self.get_mirror_rados_addr(self.primary_fs_name, self.primary_fs_id)

        # take a snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])

        time.sleep(10)
        self.check_peer_snap_in_progress(self.fs, "client.mirror_remote@ceph", '/d0', 'snap0')

        # simulate non-responding mirror daemon by sending SIGSTOP
        pid = self.get_mirror_daemon_pid()
        log.debug(f'SIGSTOP to cephfs-mirror pid {pid}')
        self.mount_a.run_shell(['kill', '-SIGSTOP', pid])

        # wait for blocklist timeout -- the manager module would blocklist
        # the mirror daemon
        time.sleep(40)

        # wake up the mirror daemon -- at this point, the daemon should know
        # that it has been blocklisted
        log.debug('SIGCONT to cephfs-mirror')
        self.mount_a.run_shell(['kill', '-SIGCONT', pid])

        # check if the rados addr is blocklisted
        self.assertTrue(self.mds_cluster.is_addr_blocklisted(rados_inst))

        time.sleep(500)
        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d0', 'snap0')

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_failed_sync_with_correction(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # add a non-existent directory for synchronization
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')

        # wait for mirror daemon to mark it the directory as failed
        time.sleep(120)
        self.verify_failed_directory(self.fs, "client.mirror_remote@ceph", '/d0')

        # create the directory
        self.mount_a.run_shell(["mkdir", "d0"])
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])

        # wait for correction
        time.sleep(120)
        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_service_daemon_status(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        time.sleep(30)
        status = self.get_mirror_daemon_status()

        # assumption for this test: mirroring enabled for a single filesystem w/ single
        # peer

        # we have not added any directories
        peer = status['filesystems'][0]['peers'][0]
        self.assertEquals(status['filesystems'][0]['directory_count'], 0)
        self.assertEquals(peer['stats']['failure_count'], 0)
        self.assertEquals(peer['stats']['recovery_count'], 0)

        # add a non-existent directory for synchronization -- check if its reported
        # in daemon stats
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')

        time.sleep(120)
        status = self.get_mirror_daemon_status()
        # we added one
        peer = status['filesystems'][0]['peers'][0]
        self.assertEquals(status['filesystems'][0]['directory_count'], 1)
        # failure count should be reflected
        self.assertEquals(peer['stats']['failure_count'], 1)
        self.assertEquals(peer['stats']['recovery_count'], 0)

        # create the directory, mirror daemon would recover
        self.mount_a.run_shell(["mkdir", "d0"])

        time.sleep(120)
        status = self.get_mirror_daemon_status()
        peer = status['filesystems'][0]['peers'][0]
        self.assertEquals(status['filesystems'][0]['directory_count'], 1)
        # failure and recovery count should be reflected
        self.assertEquals(peer['stats']['failure_count'], 1)
        self.assertEquals(peer['stats']['recovery_count'], 1)

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_mirroring_init_failure(self):
        """Test mirror daemon init failure"""

        # disable mgr mirroring plugin as it would try to load dir map on
        # on mirroring enabled for a filesystem (an throw up erorrs in
        # the logs)
        self.disable_mirroring_module()

        # enable mirroring through mon interface -- this should result in the mirror daemon
        # failing to enable mirroring due to absence of `cephfs_mirorr` index object.
        self.run_ceph_cmd("fs", "mirror", "enable", self.primary_fs_name)

        with safe_while(sleep=5, tries=10, action='wait for failed state') as proceed:
            while proceed():
                try:
                    # verify via asok
                    res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                                     'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
                    if not 'state' in res:
                        return
                    self.assertTrue(res['state'] == "failed")
                    return True
                except:
                    pass

        self.run_ceph_cmd("fs", "mirror", "disable", self.primary_fs_name)
        time.sleep(10)
        # verify via asok
        try:
            self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                       'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        except CommandFailedError:
            pass
        else:
            raise RuntimeError('expected admin socket to be unavailable')

    def test_mirroring_init_failure_with_recovery(self):
        """Test if the mirror daemon can recover from a init failure"""

        # disable mgr mirroring plugin as it would try to load dir map on
        # on mirroring enabled for a filesystem (an throw up erorrs in
        # the logs)
        self.disable_mirroring_module()

        # enable mirroring through mon interface -- this should result in the mirror daemon
        # failing to enable mirroring due to absence of `cephfs_mirror` index object.

        self.run_ceph_cmd("fs", "mirror", "enable", self.primary_fs_name)
        # need safe_while since non-failed status pops up as mirroring is restarted
        # internally in mirror daemon.
        with safe_while(sleep=5, tries=20, action='wait for failed state') as proceed:
            while proceed():
                try:
                    # verify via asok
                    res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                                     'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
                    if not 'state' in res:
                        return
                    self.assertTrue(res['state'] == "failed")
                    return True
                except:
                    pass

        # create the index object and check daemon recovery
        try:
            p = self.mount_a.client_remote.run(args=['rados', '-p', self.fs.metadata_pool_name, 'create', 'cephfs_mirror'],
                                               stdout=StringIO(), stderr=StringIO(), timeout=30,
                                               check_status=True, label="create index object")
            p.wait()
        except CommandFailedError as ce:
            log.warn(f'mirror daemon command to create mirror index object failed: {ce}')
            raise
        time.sleep(30)
        res = self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                         'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        self.assertTrue(res['peers'] == {})
        self.assertTrue(res['snap_dirs']['dir_count'] == 0)

        self.run_ceph_cmd("fs", "mirror", "disable", self.primary_fs_name)
        time.sleep(10)
        # verify via asok
        try:
            self.mirror_daemon_command(f'mirror status for fs: {self.primary_fs_name}',
                                       'fs', 'mirror', 'status', f'{self.primary_fs_name}@{self.primary_fs_id}')
        except CommandFailedError:
            pass
        else:
            raise RuntimeError('expected admin socket to be unavailable')

    def test_cephfs_mirror_peer_bootstrap(self):
        """Test importing peer bootstrap token"""
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # create a bootstrap token for the peer
        bootstrap_token = self.bootstrap_peer(self.secondary_fs_name, "client.mirror_peer_bootstrap", "site-remote")

        # import the peer via bootstrap token
        self.import_peer(self.primary_fs_name, bootstrap_token)
        time.sleep(10)
        self.verify_peer_added(self.fs, "client.mirror_peer_bootstrap@site-remote",
                               self.secondary_fs_name)

        # verify via peer_list interface
        peer_uuid = self.get_peer_uuid(self.fs, "client.mirror_peer_bootstrap@site-remote")
        res = json.loads(self.get_ceph_cmd_stdout("fs", "snapshot", "mirror", "peer_list", self.primary_fs_name))
        self.assertTrue(peer_uuid in res)
        self.assertTrue('mon_host' in res[peer_uuid] and res[peer_uuid]['mon_host'] != '')

        # remove peer
        self.peer_remove(self.fs, "client.mirror_peer_bootstrap@site-remote")
        # disable mirroring
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_symlink_sync(self):
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        # create a bunch of files w/ symbolic links in a directory to snap
        self.mount_a.run_shell(["mkdir", "d0"])
        self.mount_a.create_n_files('d0/file', 10, sync=True)
        self.mount_a.run_shell(["ln", "-s", "./file_0", "d0/sym_0"])
        self.mount_a.run_shell(["ln", "-s", "./file_1", "d0/sym_1"])
        self.mount_a.run_shell(["ln", "-s", "./file_2", "d0/sym_2"])

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # take a snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])

        time.sleep(30)
        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d0', 'snap0')

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_with_parent_snapshot(self):
        """Test snapshot synchronization with parent directory snapshots"""
        self.mount_a.run_shell(["mkdir", "-p", "d0/d1/d2/d3"])

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0/d1/d2/d3')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # take a snapshot
        self.mount_a.run_shell(["mkdir", "d0/d1/d2/d3/.snap/snap0"])

        time.sleep(30)
        self.check_peer_status(self.fs, '/d0/d1/d2/d3', 'snap0', 1,
                               "client.mirror_remote@ceph")

        # create snapshots in parent directories
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap_d0"])
        self.mount_a.run_shell(["mkdir", "d0/d1/.snap/snap_d1"])
        self.mount_a.run_shell(["mkdir", "d0/d1/d2/.snap/snap_d2"])

        # try syncing more snapshots
        self.mount_a.run_shell(["mkdir", "d0/d1/d2/d3/.snap/snap1"])
        time.sleep(30)
        self.check_peer_status(self.fs, '/d0/d1/d2/d3', 'snap1', 2,
                               "client.mirror_remote@ceph")

        self.mount_a.run_shell(["rmdir", "d0/d1/d2/d3/.snap/snap0"])
        self.mount_a.run_shell(["rmdir", "d0/d1/d2/d3/.snap/snap1"])
        time.sleep(15)
        self.check_peer_status_deleted_snap(self.fs, '/d0/d1/d2/d3', 2,
                                            "client.mirror_remote@ceph")

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0/d1/d2/d3')
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_remove_on_stall(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)

        # fetch rados address for blacklist check
        rados_inst = self.get_mirror_rados_addr(self.primary_fs_name, self.primary_fs_id)

        # simulate non-responding mirror daemon by sending SIGSTOP
        pid = self.get_mirror_daemon_pid()
        log.debug(f'SIGSTOP to cephfs-mirror pid {pid}')
        self.mount_a.run_shell(['kill', '-SIGSTOP', pid])

        # wait for blocklist timeout -- the manager module would blocklist
        # the mirror daemon
        time.sleep(40)

        # make sure the rados addr is blocklisted
        self.assertTrue(self.mds_cluster.is_addr_blocklisted(rados_inst))

        # now we are sure that there are no "active" mirror daemons -- add a directory path.
        dir_path_p = "/d0/d1"
        dir_path = "/d0/d1/d2"

        self.run_ceph_cmd("fs", "snapshot", "mirror", "add", self.primary_fs_name, dir_path)

        time.sleep(10)
        # this uses an undocumented interface to get dirpath map state
        res_json = self.get_ceph_cmd_stdout("fs", "snapshot", "mirror", "dirmap", self.primary_fs_name, dir_path)
        res = json.loads(res_json)
        # there are no mirror daemons
        self.assertTrue(res['state'], 'stalled')

        self.run_ceph_cmd("fs", "snapshot", "mirror", "remove", self.primary_fs_name, dir_path)

        time.sleep(10)
        try:
            self.run_ceph_cmd("fs", "snapshot", "mirror", "dirmap", self.primary_fs_name, dir_path)
        except CommandFailedError as ce:
            if ce.exitstatus != errno.ENOENT:
                raise RuntimeError('invalid errno when checking dirmap status for non-existent directory')
        else:
            raise RuntimeError('incorrect errno when checking dirmap state for non-existent directory')

        # adding a parent directory should be allowed
        self.run_ceph_cmd("fs", "snapshot", "mirror", "add", self.primary_fs_name, dir_path_p)

        time.sleep(10)
        # however, this directory path should get stalled too
        res_json = self.get_ceph_cmd_stdout("fs", "snapshot", "mirror", "dirmap", self.primary_fs_name, dir_path_p)
        res = json.loads(res_json)
        # there are no mirror daemons
        self.assertTrue(res['state'], 'stalled')

        # wake up the mirror daemon -- at this point, the daemon should know
        # that it has been blocklisted
        log.debug('SIGCONT to cephfs-mirror')
        self.mount_a.run_shell(['kill', '-SIGCONT', pid])

        # wait for restart mirror on blocklist
        time.sleep(60)
        res_json = self.get_ceph_cmd_stdout("fs", "snapshot", "mirror", "dirmap", self.primary_fs_name, dir_path_p)
        res = json.loads(res_json)
        # there are no mirror daemons
        self.assertTrue(res['state'], 'mapped')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_incremental_sync(self):
        """ Test incremental snapshot synchronization (based on mtime differences)."""
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                self.backup_fs.get_data_pool_name(),
                self.backup_fs.get_data_pool_name()))
        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        repo = 'ceph-qa-suite'
        repo_dir = 'ceph_repo'
        repo_path = f'{repo_dir}/{repo}'

        def clone_repo():
            self.mount_a.run_shell([
                'git', 'clone', '--branch', 'giant',
                f'http://github.com/ceph/{repo}', repo_path])

        def exec_git_cmd(cmd_list):
            self.mount_a.run_shell(['git', '--git-dir', f'{self.mount_a.mountpoint}/{repo_path}/.git', *cmd_list])

        self.mount_a.run_shell(["mkdir", repo_dir])
        clone_repo()

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        self.add_directory(self.primary_fs_name, self.primary_fs_id, f'/{repo_path}')
        self.mount_a.run_shell(['mkdir', f'{repo_path}/.snap/snap_a'])

        # full copy, takes time
        time.sleep(500)
        self.check_peer_status(self.fs, f'/{repo_path}', 'snap_a', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot(repo_path, 'snap_a')

        # create some diff
        num = random.randint(5, 20)
        log.debug(f'resetting to HEAD~{num}')
        exec_git_cmd(["reset", "--hard", f'HEAD~{num}'])

        self.mount_a.run_shell(['mkdir', f'{repo_path}/.snap/snap_b'])
        # incremental copy, should be fast
        time.sleep(180)
        self.check_peer_status(self.fs, f'/{repo_path}', 'snap_b', 2,
                               "client.mirror_remote@ceph")
        self.verify_snapshot(repo_path, 'snap_b')

        # diff again, this time back to HEAD
        log.debug('resetting to HEAD')
        exec_git_cmd(["pull"])

        self.mount_a.run_shell(['mkdir', f'{repo_path}/.snap/snap_c'])
        # incremental copy, should be fast
        time.sleep(180)
        self.check_peer_status(self.fs, f'/{repo_path}', 'snap_c', 3,
                               "client.mirror_remote@ceph")
        self.verify_snapshot(repo_path, 'snap_c')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_incremental_sync_with_type_mixup(self):
        """ Test incremental snapshot synchronization with file type changes.

        The same filename exist as a different type in subsequent snapshot.
        This verifies if the mirror daemon can identify file type mismatch and
        sync snapshots.

              \    snap_0       snap_1      snap_2      snap_3
               \-----------------------------------------------
        file_x |   reg          sym         dir         reg
               |
        file_y |   dir          reg         sym         dir
               |
        file_z |   sym          dir         reg         sym
        """
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))
        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        typs = deque(['reg', 'dir', 'sym'])
        def cleanup_and_create_with_type(dirname, fnames):
            self.mount_a.run_shell_payload(f"rm -rf {dirname}/*")
            fidx = 0
            for t in typs:
                fname = f'{dirname}/{fnames[fidx]}'
                log.debug(f'file: {fname} type: {t}')
                if t == 'reg':
                    self.mount_a.run_shell(["touch", fname])
                    self.mount_a.write_file(fname, data=fname)
                elif t == 'dir':
                    self.mount_a.run_shell(["mkdir", fname])
                elif t == 'sym':
                    # verify ELOOP in mirror daemon
                    self.mount_a.run_shell(["ln", "-s", "..", fname])
                fidx += 1

        def verify_types(dirname, fnames, snap_name):
            tidx = 0
            for fname in fnames:
                t = self.mount_b.run_shell_payload(f"stat -c %F {dirname}/.snap/{snap_name}/{fname}").stdout.getvalue().strip()
                if typs[tidx] == 'reg':
                    self.assertEquals('regular file', t)
                elif typs[tidx] == 'dir':
                    self.assertEquals('directory', t)
                elif typs[tidx] == 'sym':
                    self.assertEquals('symbolic link', t)
                tidx += 1

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        self.mount_a.run_shell(["mkdir", "d0"])
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')

        fnames = ['file_x', 'file_y', 'file_z']
        turns = 0
        while turns != len(typs):
            snapname = f'snap_{turns}'
            cleanup_and_create_with_type('d0', fnames)
            self.mount_a.run_shell(['mkdir', f'd0/.snap/{snapname}'])
            time.sleep(30)
            self.check_peer_status(self.fs, '/d0', snapname, turns+1,
                                   "client.mirror_remote@ceph")
            verify_types('d0', fnames, snapname)
            # next type
            typs.rotate(1)
            turns += 1

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_sync_with_purged_snapshot(self):
        """Test snapshot synchronization in midst of snapshot deletes.

        Deleted the previous snapshot when the mirror daemon is figuring out
        incremental differences between current and previous snaphot. The
        mirror daemon should identify the purge and switch to using remote
        comparison to sync the snapshot (in the next iteration of course).
        """

        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                self.backup_fs.get_data_pool_name(),
                self.backup_fs.get_data_pool_name()))
        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        repo = 'ceph-qa-suite'
        repo_dir = 'ceph_repo'
        repo_path = f'{repo_dir}/{repo}'

        def clone_repo():
            self.mount_a.run_shell([
                'git', 'clone', '--branch', 'giant',
                f'http://github.com/ceph/{repo}', repo_path])

        def exec_git_cmd(cmd_list):
            self.mount_a.run_shell(['git', '--git-dir', f'{self.mount_a.mountpoint}/{repo_path}/.git', *cmd_list])

        self.mount_a.run_shell(["mkdir", repo_dir])
        clone_repo()

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        self.add_directory(self.primary_fs_name, self.primary_fs_id, f'/{repo_path}')
        self.mount_a.run_shell(['mkdir', f'{repo_path}/.snap/snap_a'])

        # full copy, takes time
        time.sleep(500)
        self.check_peer_status(self.fs, f'/{repo_path}', 'snap_a', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot(repo_path, 'snap_a')

        # create some diff
        num = random.randint(60, 100)
        log.debug(f'resetting to HEAD~{num}')
        exec_git_cmd(["reset", "--hard", f'HEAD~{num}'])

        self.mount_a.run_shell(['mkdir', f'{repo_path}/.snap/snap_b'])

        time.sleep(15)
        self.mount_a.run_shell(['rmdir', f'{repo_path}/.snap/snap_a'])

        # incremental copy but based on remote dir_root
        time.sleep(300)
        self.check_peer_status(self.fs, f'/{repo_path}', 'snap_b', 2,
                               "client.mirror_remote@ceph")
        self.verify_snapshot(repo_path, 'snap_b')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_peer_add_primary(self):
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # try adding the primary file system as a peer to secondary file
        # system
        try:
            self.peer_add(self.backup_fs, "client.mirror_remote@ceph", self.primary_fs_name)
        except CommandFailedError as ce:
            if ce.exitstatus != errno.EINVAL:
                raise RuntimeError('invalid errno when adding a primary file system')
        else:
            raise RuntimeError('adding peer should fail')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_cephfs_mirror_cancel_mirroring_and_readd(self):
        """
        Test adding a directory path for synchronization post removal of already added directory paths

        ... to ensure that synchronization of the newly added directory path functions
        as expected. Note that we schedule three (3) directories for mirroring to ensure
        that all replayer threads (3 by default) in the mirror daemon are busy.
        """
        log.debug('reconfigure client auth caps')
        self.get_ceph_cmd_result(
            'auth', 'caps', "client.{0}".format(self.mount_b.client_id),
                'mds', 'allow rw',
                'mon', 'allow r',
                'osd', 'allow rw pool={0}, allow rw pool={1}'.format(
                    self.backup_fs.get_data_pool_name(),
                    self.backup_fs.get_data_pool_name()))

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        # create a bunch of files in a directory to snap
        self.mount_a.run_shell(["mkdir", "d0"])
        self.mount_a.run_shell(["mkdir", "d1"])
        self.mount_a.run_shell(["mkdir", "d2"])
        for i in range(4):
            filename = f'file.{i}'
            self.mount_a.write_n_mb(os.path.join('d0', filename), 1024)
            self.mount_a.write_n_mb(os.path.join('d1', filename), 1024)
            self.mount_a.write_n_mb(os.path.join('d2', filename), 1024)

        log.debug('enabling mirroring')
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        log.debug('adding directory paths')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d2')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        # take snapshots
        log.debug('taking snapshots')
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])
        self.mount_a.run_shell(["mkdir", "d1/.snap/snap0"])
        self.mount_a.run_shell(["mkdir", "d2/.snap/snap0"])

        time.sleep(10)
        log.debug('checking snap in progress')
        self.check_peer_snap_in_progress(self.fs, "client.mirror_remote@ceph", '/d0', 'snap0')
        self.check_peer_snap_in_progress(self.fs, "client.mirror_remote@ceph", '/d1', 'snap0')
        self.check_peer_snap_in_progress(self.fs, "client.mirror_remote@ceph", '/d2', 'snap0')

        log.debug('removing directories 1')
        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        log.debug('removing directories 2')
        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        log.debug('removing directories 3')
        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d2')

        log.debug('removing snapshots')
        self.mount_a.run_shell(["rmdir", "d0/.snap/snap0"])
        self.mount_a.run_shell(["rmdir", "d1/.snap/snap0"])
        self.mount_a.run_shell(["rmdir", "d2/.snap/snap0"])

        for i in range(4):
            filename = f'file.{i}'
            log.debug(f'deleting {filename}')
            self.mount_a.run_shell(["rm", "-f", os.path.join('d0', filename)])
            self.mount_a.run_shell(["rm", "-f", os.path.join('d1', filename)])
            self.mount_a.run_shell(["rm", "-f", os.path.join('d2', filename)])

        log.debug('creating new files...')
        self.mount_a.create_n_files('d0/file', 50, sync=True)
        self.mount_a.create_n_files('d1/file', 50, sync=True)
        self.mount_a.create_n_files('d2/file', 50, sync=True)

        log.debug('adding directory paths')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d1')
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d2')

        log.debug('creating new snapshots...')
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])
        self.mount_a.run_shell(["mkdir", "d1/.snap/snap0"])
        self.mount_a.run_shell(["mkdir", "d2/.snap/snap0"])

        time.sleep(60)
        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d0', 'snap0')

        self.check_peer_status(self.fs, '/d1', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d1', 'snap0')

        self.check_peer_status(self.fs, '/d2', 'snap0', 1,
                               "client.mirror_remote@ceph")
        self.verify_snapshot('d2', 'snap0')

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)

    def test_local_and_remote_dir_root_mode(self):
        log.debug('reconfigure client auth caps')
        cid = self.mount_b.client_id
        data_pool = self.backup_fs.get_data_pool_name()
        self.get_ceph_cmd_result(
            'auth', 'caps', f"client.{cid}",
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', f"allow rw pool={data_pool}, allow rw pool={data_pool}")

        log.debug(f'mounting filesystem {self.secondary_fs_name}')
        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        self.mount_a.run_shell(["mkdir", "l1"])
        self.mount_a.run_shell(["mkdir", "l1/.snap/snap0"])
        self.mount_a.run_shell(["chmod", "go-rwx", "l1"])

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/l1')
        self.peer_add(self.fs, "client.mirror_remote@ceph", self.secondary_fs_name)

        time.sleep(60)
        self.check_peer_status(self.fs, '/l1', 'snap0', 1,
                               "client.mirror_remote@ceph")

        mode_local = self.mount_a.run_shell(["stat", "--format=%A", "l1"]).stdout.getvalue().strip()
        mode_remote = self.mount_b.run_shell(["stat", "--format=%A", "l1"]).stdout.getvalue().strip()

        self.assertTrue(mode_local == mode_remote, f"mode mismatch, local mode: {mode_local}, remote mode: {mode_remote}")

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.mount_a.run_shell(["rmdir", "l1/.snap/snap0"])
        self.mount_a.run_shell(["rmdir", "l1"])


class TestMirroringMultiplePeersFanOut(MirroringHelpers):
    MDSS_REQUIRED = 5
    CLIENTS_REQUIRED = 4
    REQUIRE_BACKUP_FILESYSTEM = True

    MODULE_NAME = "mirroring"

    def setUp(self):
        super(TestMirroringMultiplePeersFanOut, self).setUp()
        self.primary_fs_name = self.fs.name
        self.primary_fs_id = self.fs.id
        self.secondary_fs_name = self.backup_fs.name
        self.secondary_fs_id = self.backup_fs.id
        self.backup_fs1 = self.mds_cluster.newfs(name="backup_fs1")
        self.backup_fs1_name = self.backup_fs1.name
        self.backup_fs2 = self.mds_cluster.newfs(name="backup_fs2")
        self.backup_fs2_name = self.backup_fs2.name
        self.enable_mirroring_module()

    def tearDown(self):
        self.disable_mirroring_module()
        super(TestMirroringMultiplePeersFanOut, self).tearDown()

    def test_snaps_with_multiple_peers(self):

        self.get_ceph_cmd_result(
            'auth', 'caps', f"client.{self.mount_b.client_id}",
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', f'allow rw pool={self.backup_fs.get_data_pool_name()},'
                   f'allow rw pool={self.backup_fs.get_data_pool_name()}')
        self.get_ceph_cmd_result(
            'auth', 'caps', f"client.{self.mount_c.client_id}",
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', f'allow rw pool={self.backup_fs1.get_data_pool_name()},'
                   f'allow rw pool={self.backup_fs1.get_data_pool_name()}')
        self.get_ceph_cmd_result(
            'auth', 'caps', f"client.{self.mount_d.client_id}",
            'mds', 'allow rw',
            'mon', 'allow r',
            'osd', f'allow rw pool={self.backup_fs2.get_data_pool_name()},'
                   f'allow rw pool={self.backup_fs2.get_data_pool_name()}')

        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        self.mount_c.umount_wait()
        self.mount_c.mount_wait(cephfs_name=self.backup_fs1_name)

        self.mount_d.umount_wait()
        self.mount_d.mount_wait(cephfs_name=self.backup_fs2_name)

        self.mount_a.run_shell(["mkdir", "d0"])
        self.mount_a.create_n_files('d0/file', 50, sync=True)

        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/d0')

        self.peer_add(self.fs, "client.mirror_remote@ceph",
                      self.secondary_fs_name)
        self.peer_add(self.fs, "client.mirror_remote@ceph",
                      self.backup_fs1_name)
        self.peer_add(self.fs, "client.mirror_remote@ceph",
                      self.backup_fs2_name)

        self.mount_a.run_shell(["mkdir", "d0/.snap/snap0"])
        time.sleep(30)

        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph",
                               self.secondary_fs_name)
        self.verify_snapshot('d0', 'snap0', self.mount_a, self.mount_b)

        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph",
                               self.backup_fs1_name)
        self.verify_snapshot('d0', 'snap0', self.mount_a, self.mount_c)

        self.check_peer_status(self.fs, '/d0', 'snap0', 1,
                               "client.mirror_remote@ceph",
                               self.backup_fs2_name)
        self.verify_snapshot('d0', 'snap0', self.mount_a, self.mount_d)

        # some more IO
        self.mount_a.run_shell(["mkdir", "d0/d00"])
        self.mount_a.run_shell(["mkdir", "d0/d01"])

        self.mount_a.create_n_files('d0/d00/more_file', 20, sync=True)
        self.mount_a.create_n_files('d0/d01/some_more_file', 75, sync=True)

        # take another snapshot
        self.mount_a.run_shell(["mkdir", "d0/.snap/snap1"])

        time.sleep(60)
        self.check_peer_status(self.fs, '/d0', 'snap1', 2,
                               "client.mirror_remote@ceph",
                               self.secondary_fs_name)
        self.verify_snapshot('d0', 'snap1', self.mount_a, self.mount_b)

        self.check_peer_status(self.fs, '/d0', 'snap1', 2,
                               "client.mirror_remote@ceph",
                               self.backup_fs1_name)
        self.verify_snapshot('d0', 'snap1', self.mount_a, self.mount_c)

        self.check_peer_status(self.fs, '/d0', 'snap1', 2,
                               "client.mirror_remote@ceph",
                               self.backup_fs2_name)
        self.verify_snapshot('d0', 'snap1', self.mount_a, self.mount_d)

        # delete a snapshot
        self.mount_a.run_shell(["rmdir", "d0/.snap/snap0"])

        time.sleep(10)

        self.check_snapshot_doesnt_exist("snap0", "d0/.snap", self.mount_b)
        self.check_peer_status_deleted_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.secondary_fs_name)

        self.check_snapshot_doesnt_exist("snap0", "d0/.snap", self.mount_c)
        self.check_peer_status_deleted_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs1_name)

        self.check_snapshot_doesnt_exist("snap0", "d0/.snap", self.mount_d)
        self.check_peer_status_deleted_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs2_name)

        # rename a snapshot
        self.mount_a.run_shell(["mv", "d0/.snap/snap1", "d0/.snap/snap2"])

        time.sleep(10)

        self.check_snapshot_doesnt_exist("snap1", "d0/.snap", self.mount_b)
        self.check_snapshot_exists("snap2", "d0/.snap", self.mount_b)
        self.check_peer_status_renamed_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.secondary_fs_name)

        self.check_snapshot_doesnt_exist("snap1", "d0/.snap", self.mount_c)
        self.check_snapshot_exists("snap2", "d0/.snap", self.mount_c)
        self.check_peer_status_renamed_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs1_name)

        self.check_snapshot_doesnt_exist("snap1", "d0/.snap", self.mount_d)
        self.check_snapshot_exists("snap2", "d0/.snap", self.mount_d)
        self.check_peer_status_renamed_snap(self.fs, '/d0', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs2_name)

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/d0')
        self.remove_peers(self.fs, "client.mirror_remote@ceph",
                          [self.secondary_fs_name, self.backup_fs1_name,
                           self.backup_fs2_name])
        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)


class TestMirroringMuliplePeersCascaded(MirroringHelpers):
    MDSS_REQUIRED = 5
    CLIENTS_REQUIRED = 4
    REQUIRE_BACKUP_FILESYSTEM = True

    MODULE_NAME = "mirroring"

    def setUp(self):
        super(TestMirroringMuliplePeersCascaded, self).setUp()
        self.primary_fs_name = self.fs.name
        self.primary_fs_id = self.fs.id
        self.secondary_fs_name = self.backup_fs.name
        self.secondary_fs_id = self.backup_fs.id
        self.backup_fs1 = self.mds_cluster.newfs(name="backup_fs1")
        self.backup_fs1_name = self.backup_fs1.name
        self.backup_fs1_id = self.backup_fs1.id
        self.backup_fs2 = self.mds_cluster.newfs(name="backup_fs2")
        self.backup_fs2_name = self.backup_fs2.name
        self.backup_fs2_id = self.backup_fs2.id
        self.enable_mirroring_module()

    def tearDown(self):
        self.disable_mirroring_module()
        super(TestMirroringMuliplePeersCascaded, self).tearDown()

    def test_snaps_multiple_peers(self):

        self.mount_b.umount_wait()
        self.mount_b.mount_wait(cephfs_name=self.secondary_fs_name)

        self.mount_c.umount_wait()
        self.mount_c.mount_wait(cephfs_name=self.backup_fs1_name)

        self.mount_d.umount_wait()
        self.mount_d.mount_wait(cephfs_name=self.backup_fs2_name)

        self.mount_a.run_shell(["mkdir", "a"])
        self.mount_a.create_n_files('a/file', 50, sync=True)
        self.enable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.add_directory(self.primary_fs_name, self.primary_fs_id, '/a')

        self.mount_b.run_shell(["mkdir", "b"])
        self.mount_b.create_n_files('b/file', 50, sync=True)
        self.enable_mirroring(self.secondary_fs_name, self.secondary_fs_id)
        self.add_directory(self.secondary_fs_name, self.secondary_fs_id, '/b')

        self.mount_c.run_shell(["mkdir", "c"])
        self.mount_c.create_n_files('c/file', 50, sync=True)
        self.enable_mirroring(self.backup_fs1_name, self.backup_fs1_id)
        self.add_directory(self.backup_fs1_name, self.backup_fs1_id, '/c')

        self.peer_add(self.fs, "client.mirror_remote@ceph",
                      self.secondary_fs_name)
        self.peer_add(self.backup_fs, "client.mirror_remote@ceph",
                      self.backup_fs1_name)
        self.peer_add(self.backup_fs1, "client.mirror_remote@ceph",
                      self.backup_fs2_name)

        self.mount_a.run_shell(["mkdir", "a/.snap/snapa0"])
        self.mount_b.run_shell(["mkdir", "b/.snap/snapb0"])
        self.mount_c.run_shell(["mkdir", "c/.snap/snapc0"])

        time.sleep(30)

        self.check_peer_status(self.fs, '/a', 'snapa0', 1,
                               "client.mirror_remote@ceph",
                               self.secondary_fs_name)
        self.verify_snapshot('a', 'snapa0', self.mount_a, self.mount_b)

        self.check_peer_status(self.backup_fs, '/b', 'snapb0', 1,
                               "client.mirror_remote@ceph",
                               self.backup_fs1_name)
        self.verify_snapshot('b', 'snapb0', self.mount_b, self.mount_c)

        self.check_peer_status(self.backup_fs1, '/c', 'snapc0', 1,
                               "client.mirror_remote@ceph",
                               self.backup_fs2_name)
        self.verify_snapshot('c', 'snapc0', self.mount_c, self.mount_d)

        # some more IO and a new snap on each fs
        self.mount_a.run_shell(["mkdir", "a/a00"])
        self.mount_a.run_shell(["mkdir", "a/a01"])
        self.mount_a.create_n_files('a/a00/more_file', 20, sync=True)
        self.mount_a.create_n_files('a/a01/some_more_file', 75, sync=True)
        self.mount_a.run_shell(["mkdir", "a/.snap/snapa1"])

        self.mount_b.run_shell(["mkdir", "b/b00"])
        self.mount_b.run_shell(["mkdir", "b/b01"])
        self.mount_b.create_n_files('b/b00/more_file', 20, sync=True)
        self.mount_b.create_n_files('b/b01/some_more_file', 75, sync=True)
        self.mount_b.run_shell(["mkdir", "b/.snap/snapb1"])

        self.mount_c.run_shell(["mkdir", "c/c00"])
        self.mount_c.run_shell(["mkdir", "c/c01"])
        self.mount_c.create_n_files('c/c00/more_file', 20, sync=True)
        self.mount_c.create_n_files('c/c01/some_more_file', 75, sync=True)
        self.mount_c.run_shell(["mkdir", "c/.snap/snapc1"])

        time.sleep(60)

        self.check_peer_status(self.fs, '/a', 'snapa1', 2,
                               "client.mirror_remote@ceph",
                               self.secondary_fs_name)
        self.verify_snapshot('a', 'snapa1', self.mount_a, self.mount_b)

        self.check_peer_status(self.backup_fs, '/b', 'snapb1', 2,
                               "client.mirror_remote@ceph",
                               self.backup_fs1_name)
        self.verify_snapshot('b', 'snapb1', self.mount_b, self.mount_c)

        self.check_peer_status(self.backup_fs1, '/c', 'snapc1', 2,
                               "client.mirror_remote@ceph",
                               self.backup_fs2_name)
        self.verify_snapshot('c', 'snapc1', self.mount_c, self.mount_d)

        # delete snapshot from each fs
        self.mount_a.run_shell(["rmdir", "a/.snap/snapa0"])
        self.mount_b.run_shell(["rmdir", "b/.snap/snapb0"])
        self.mount_c.run_shell(["rmdir", "c/.snap/snapc0"])

        time.sleep(20)

        self.check_snapshot_doesnt_exist("snapa0", "a/.snap", self.mount_b)
        self.check_peer_status_deleted_snap(self.fs, '/a', 1,
                                            "client.mirror_remote@ceph",
                                            self.secondary_fs_name)

        self.check_snapshot_doesnt_exist("snapb0", "b/.snap", self.mount_c)
        self.check_peer_status_deleted_snap(self.backup_fs, '/b', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs1_name)

        self.check_snapshot_doesnt_exist("snapc0", "c/.snap", self.mount_d)
        self.check_peer_status_deleted_snap(self.backup_fs1, '/c', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs2_name)

        # rename a snapshot in each fs
        self.mount_a.run_shell(["mv", "a/.snap/snapa1", "a/.snap/snapa2"])
        self.mount_b.run_shell(["mv", "b/.snap/snapb1", "b/.snap/snapb2"])
        self.mount_c.run_shell(["mv", "c/.snap/snapc1", "c/.snap/snapc2"])

        time.sleep(20)

        self.check_snapshot_doesnt_exist("snapa1", "a/.snap", self.mount_b)
        self.check_snapshot_exists("snapa2", "a/.snap", self.mount_b)
        self.check_peer_status_renamed_snap(self.fs, '/a', 1,
                                            "client.mirror_remote@ceph",
                                            self.secondary_fs_name)

        self.check_snapshot_doesnt_exist("snapb1", "b/.snap", self.mount_c)
        self.check_snapshot_exists("snapb2", "b/.snap", self.mount_c)
        self.check_peer_status_renamed_snap(self.backup_fs, '/b', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs1_name)

        self.check_snapshot_doesnt_exist("snapc1", "c/.snap", self.mount_d)
        self.check_snapshot_exists("snapc2", "c/.snap", self.mount_d)
        self.check_peer_status_renamed_snap(self.backup_fs1, '/c', 1,
                                            "client.mirror_remote@ceph",
                                            self.backup_fs2_name)

        self.remove_directory(self.primary_fs_name, self.primary_fs_id, '/a')
        self.remove_directory(self.secondary_fs_name, self.secondary_fs_id,
                              '/b')
        self.remove_directory(self.backup_fs1_name, self.backup_fs1_id,
                              '/c')

        self.peer_remove(self.fs, "client.mirror_remote@ceph",
                         self.secondary_fs_name)
        self.peer_remove(self.backup_fs, "client.mirror_remote@ceph",
                         self.backup_fs1_name)
        self.peer_remove(self.backup_fs1, "client.mirror_remote@ceph",
                         self.backup_fs2_name)

        self.disable_mirroring(self.primary_fs_name, self.primary_fs_id)
        self.disable_mirroring(self.secondary_fs_name, self.secondary_fs_id)
        self.disable_mirroring(self.backup_fs2_name, self.backup_fs2_id)
