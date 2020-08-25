"""
Task (and subtasks) for SES test automation

Linter:
    flake8 --max-line-length=100
"""
import logging

from tasks.salt_manager import SaltManager
from tasks.scripts import Scripts

from teuthology.exceptions import (
    ConfigError,
    )
from teuthology.task import Task

log = logging.getLogger(__name__)
ses_qa_ctx = {}
number_of_osds_in_cluster = """sudo ceph osd tree -f json-pretty |
                               jq '[.nodes[] | select(.type == \"osd\")] | length'"""


class SESQA(Task):

    def __init__(self, ctx, config):
        global ses_qa_ctx
        super(SESQA, self).__init__(ctx, config)
        if ses_qa_ctx:
            self.log = ses_qa_ctx['logger_obj']
            self.log.debug("ses_qa_ctx already populated (we are in a subtask)")
        if not ses_qa_ctx:
            ses_qa_ctx['logger_obj'] = log
            self.log = log
            self.log.debug("populating ses_qa_ctx (we are *not* in a subtask)")
            self._populate_ses_qa_context()
        self.master_remote = ses_qa_ctx['master_remote']
        self.nodes = self.ctx['nodes']
        self.nodes_client_only = self.ctx['nodes_client_only']
        self.nodes_cluster = self.ctx['nodes_cluster']
        self.nodes_gateway = self.ctx['nodes_gateway']
        self.nodes_storage = self.ctx['nodes_storage']
        self.nodes_random_storage = self.ctx['nodes_random_storage']
        self.nodes_storage_only = self.ctx['nodes_storage_only']
        self.nodes_monitor = self.ctx['nodes_monitor']
        self.nodes_random_monitor = self.ctx['nodes_random_monitor']
        self.remote_lookup_table = self.ctx['remote_lookup_table']
        self.remotes = self.ctx['remotes']
        self.roles = self.ctx['roles']
        self.role_lookup_table = self.ctx['role_lookup_table']
        self.role_types = self.ctx['role_types']
        self.scripts = Scripts(self.ctx, self.log)
        self.sm = ses_qa_ctx['salt_manager_instance']

    def _populate_ses_qa_context(self):
        global ses_qa_ctx
        ses_qa_ctx['salt_manager_instance'] = SaltManager(self.ctx)
        ses_qa_ctx['master_remote'] = ses_qa_ctx['salt_manager_instance'].master_remote

    def os_type_and_version(self):
        os_type = self.ctx.config.get('os_type', 'unknown')
        os_version = float(self.ctx.config.get('os_version', 0))
        return (os_type, os_version)

    def setup(self):
        super(SESQA, self).setup()

    def begin(self):
        super(SESQA, self).begin()

    def end(self):
        super(SESQA, self).end()
        self.sm.gather_logs('/home/farm/.npm/_logs', 'dashboard-e2e-npm')
        self.sm.gather_logs('/home/farm/.protractor-report', 'dashboard-e2e-protractor')

    def teardown(self):
        super(SESQA, self).teardown()


class Validation(SESQA):

    err_prefix = "(validation subtask) "

    def __init__(self, ctx, config):
        global ses_qa_ctx
        ses_qa_ctx['logger_obj'] = log.getChild('validation')
        self.name = 'ses_qa.validation'
        super(Validation, self).__init__(ctx, config)
        self.log.debug("munged config is {}".format(self.config))

    def mgr_plugin_influx(self, **kwargs):
        """
        Minimal/smoke test for the MGR influx plugin

        Tests the 'influx' MGR plugin, but only on openSUSE Leap 15.0.

        Testing on SLE-15 is not currently possible because the influxdb
        package is not built in IBS for anything higher than SLE-12-SP4.
        Getting it to build for SLE-15 requires a newer golang stack than what
        is available in SLE-15 - see
        https://build.suse.de/project/show/NON_Public:infrastructure:icinga2
        for how another team is building it (and no, we don't want to do that).

        Testing on openSUSE Leap 15.0 is only possible because we are building
        the influxdb package in filesystems:ceph:nautilus with modified project
        metadata.

        (This problem will hopefully go away when we switch to SLE-15-SP1.)
        """
        zypper_cmd = ("sudo zypper --non-interactive --no-gpg-check "
                      "install --force --no-recommends {}")
        os_type, os_version = self.os_type_and_version()
        if os_type == 'opensuse' and os_version >= 15:
            self.ctx.cluster.run(
                args=zypper_cmd.format(' '.join(["python3-influxdb", "influxdb"]))
                )
            self.scripts.run(
                self.master_remote,
                'mgr_plugin_influx.sh',
                )
        else:
            self.log.warning(
                "mgr_plugin_influx test case not implemented for OS ->{}<-"
                .format(os_type + " " + str(os_version))
                )

    def begin(self):
        self.log.debug("Processing tests: ->{}<-".format(self.config.keys()))
        for method_spec, kwargs in self.config.items():
            kwargs = {} if not kwargs else kwargs
            if not isinstance(kwargs, dict):
                raise ConfigError(self.err_prefix + "Method config must be a dict")
            self.log.info(
                "Running test {} with config ->{}<-"
                .format(method_spec, kwargs)
                )
            method = getattr(self, method_spec, None)
            if method:
                method(**kwargs)
            else:
                raise ConfigError(self.err_prefix + "No such method ->{}<-"
                                  .format(method_spec))

    def drive_replace_initiate(self, **kwargs):
        """
        Initiate Deepsea drive replacement

        Assumes there is 1 drive not being deployed (1node5disks - with DriveGroup `limit: 4`)

        In order to "hide" an existing disk from the ceph.c_v in teuthology
        the disk is formatted and mounted.
        """
        osd_id = 0
        self.scripts.run(
                self.master_remote,
                'drive_replace.sh',
                args=[osd_id]
                )

    def drive_replace_check(self, **kwargs):
        """
        Deepsea drive replacement after check

        Replaced osd_id should be back in the osd tree once stage.3 is ran
        """
        self.master_remote.sh("sudo ceph osd tree | tee after.txt")
        self.master_remote.sh("diff before.txt after.txt && echo 'Drive Replaced OK'")

    def ses_rack_dc_region_unavailability(self, **kwargs):
        """
        Simulates rack, DC and region unavailability by
        modifying Ceph crushmap
        """
        self.scripts.run(
                self.master_remote,
                'ses_rack_dc_region_unavailability.sh',
                )

    def ses_network_failure(self, **kwargs):
        """
        Simulates network failure using tc netem tool
        """
        self.scripts.run(
                self.master_remote,
                'ses_network_failure.sh',
                )

    def ses_cephfs_test_mount(self, **kwargs):
        if kwargs['part'] == 1:
            self.scripts.run(
                    self.master_remote,
                    'ses_cephfs_test_mount_part1.sh',
                    args=self.nodes_monitor,
                    )
        if kwargs['part'] == 2:
            self.scripts.run(
                    self.master_remote,
                    'ses_cephfs_test_mount_part2.sh',
                    args=self.nodes_monitor,
                    )

    def ses_ceph_osd_tiering(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_ceph_osd_tiering.sh',
                )

    def ses_disk_fault_injection(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_disk_fault_injection.sh',
                args=self.nodes_random_storage,
                )

    def ses_erasure_code_profile(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_erasure_code_profile.sh',
                )

    def ses_happy_path_scenario(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_happy_path_scenario.sh',
                args=self.nodes_random_storage,
                )

    def ses_install_nfs_ganesha(self, **kwargs):
        if kwargs['part'] == 1:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_nfs_ganesha_part1.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 2:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_nfs_ganesha_part2.sh',
                    args=self.nodes_random_storage,
                    )

    def ses_install_rgw(self, **kwargs):
        if kwargs['part'] == 1:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_rgw_part1.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 2:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_rgw_part2.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 3:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_rgw_part3.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 4:
            self.scripts.run(
                    self.master_remote,
                    'ses_install_rgw_part4.sh',
                    args=self.nodes_random_storage,
                    )

    def ses_monitor_failover(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_monitor_failover.sh',
                args=self.nodes_monitor,
                )

    def ses_pool_compression(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_pool_compression.sh',
                )

    def ses_rbd_persistent(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_rbd_persistent.sh',
                args=self.nodes_random_storage,
                )

    def ses_rgw_zones(self, **kwargs):
        if kwargs['part'] == 1:
            self.scripts.run(
                    self.master_remote,
                    'ses_rgw_zones_part1.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 2:
            self.scripts.run(
                    self.master_remote,
                    'ses_rgw_zones_part2.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 3:
            self.scripts.run(
                    self.master_remote,
                    'ses_rgw_zones_part3.sh',
                    args=self.nodes_random_storage,
                    )

    def ses_removing_osd(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_removing_osd.sh',
                args=self.nodes_random_storage,
                )

    def ses_replace_disk(self, **kwargs):
        if kwargs['part'] == 1:
            self.scripts.run(
                    self.master_remote,
                    'ses_replace_disk_part1.sh',
                    args=self.nodes_random_storage,
                    )
        if kwargs['part'] == 2:
            self.scripts.run(
                    self.master_remote,
                    'ses_replace_disk_part2.sh',
                    args=self.nodes_random_storage,
                    )

    def ses_stop_osd_daemon(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_stop_osd_daemon.sh',
                args=self.nodes_random_storage,
                )

    def ses_tuned(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_tuned.sh',
                )

    def ses_uninstall_ceph(self, **kwargs):
        self.scripts.run(
                self.master_remote,
                'ses_uninstall_ceph.sh',
                )


task = SESQA
validation = Validation
