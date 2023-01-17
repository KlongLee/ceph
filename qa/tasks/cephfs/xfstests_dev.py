from io import StringIO
from logging import getLogger

from tasks.cephfs.cephfs_test_case import CephFSTestCase


logger = getLogger(__name__)


# TODO: add code to run non-ACL tests too.
# TODO: get tests running with SCRATCH_DEV and SCRATCH_DIR.
# TODO: make xfstests-dev tests running without running `make install`.
# TODO: make xfstests-dev compatible with ceph-fuse. xfstests-dev remounts
# CephFS before running tests using kernel, so ceph-fuse mounts are never
# actually testsed.
class XFSTestsDev(CephFSTestCase):

    def setUp(self):
        super(XFSTestsDev, self).setUp()
        self.setup_xfsprogs_devs()
        self.prepare_xfstests_devs()

    def setup_xfsprogs_devs(self):
        self.install_xfsprogs = False

    def prepare_xfstests_devs(self):
        self.get_repos()
        self.get_test_and_scratch_dirs_ready()
        self.install_deps()
        self.create_reqd_users()
        self.write_local_config()

        # NOTE: On teuthology machines it's necessary to run "make" as
        # superuser since the repo is cloned somewhere in /tmp.
        self.mount_a.client_remote.run(args=['sudo', 'make'],
                                       cwd=self.xfstests_repo_path, stdout=StringIO(),
                                       stderr=StringIO())
        self.mount_a.client_remote.run(args=['sudo', 'make', 'install'],
                                       cwd=self.xfstests_repo_path, omit_sudo=False,
                                       stdout=StringIO(), stderr=StringIO())

        if self.install_xfsprogs:
            self.mount_a.client_remote.run(args=['sudo', 'make'],
                                           cwd=self.xfsprogs_repo_path,
                                           stdout=StringIO(), stderr=StringIO())
            self.mount_a.client_remote.run(args=['sudo', 'make', 'install'],
                                           cwd=self.xfsprogs_repo_path, omit_sudo=False,
                                           stdout=StringIO(), stderr=StringIO())

    def get_repos(self):
        """
        Clone xfstests_dev and xfsprogs-dev repositories. If already present,
        update them. The xfsprogs-dev will be used to test the encrypt.
        """
        # TODO: make sure that repo is not cloned for every test. it should
        # happen only once.
        remoteurl = 'https://git.ceph.com/xfstests-dev.git'
        self.xfstests_repo_path = self.mount_a.client_remote.mkdtemp(suffix=
                                                            'xfstests-dev')
        self.mount_a.run_shell(['git', 'clone', remoteurl, '--depth', '1',
                                self.xfstests_repo_path])

        if self.install_xfsprogs:
            remoteurl = 'https://git.ceph.com/xfsprogs-dev.git'
            self.xfsprogs_repo_path = self.mount_a.client_remote.mkdtemp(suffix=
                                                                'xfsprogs-dev')
            self.mount_a.run_shell(['git', 'clone', remoteurl, '--depth', '1',
                                    self.xfsprogs_repo_path])

    def get_admin_key(self):
        import configparser

        cp = configparser.ConfigParser()
        cp.read_string(self.fs.mon_manager.raw_cluster_cmd(
            'auth', 'get-or-create', 'client.admin'))

        return cp['client.admin']['key']

    def get_test_and_scratch_dirs_ready(self):
        """ "test" and "scratch" directories are directories inside Ceph FS.
            And, test and scratch mounts are path on the local FS where "test"
            and "scratch" directories would be mounted. Look at xfstests-dev
            local.config's template inside this file to get some context.
        """
        from os.path import join

        self.test_dirname = 'test'
        self.mount_a.run_shell(['mkdir', self.test_dirname])
        # read var name as "test dir's mount path"
        self.test_dirs_mount_path = self.mount_a.client_remote.mkdtemp(
            suffix=self.test_dirname)
        self.mount_a.run_shell(['sudo','ln','-s',join(self.mount_a.mountpoint,
                                                      self.test_dirname),
                                self.test_dirs_mount_path])

        self.scratch_dirname = 'scratch'
        self.mount_a.run_shell(['mkdir', self.scratch_dirname])
        # read var name as "scratch dir's mount path"
        self.scratch_dirs_mount_path = self.mount_a.client_remote.mkdtemp(
            suffix=self.scratch_dirname)
        self.mount_a.run_shell(['sudo','ln','-s',join(self.mount_a.mountpoint,
                                                      self.scratch_dirname),
                                self.scratch_dirs_mount_path])

    def install_deps(self):
        from teuthology.misc import get_system_type

        distro, version = get_system_type(self.mount_a.client_remote,
                                          distro=True, version=True)
        distro = distro.lower()
        major_ver_num = int(version.split('.')[0]) # only keep major release
                                                   # number

        # we keep fedora here so that right deps are installed when this test
        # is run locally by a dev.
        if distro in ('redhatenterpriseserver', 'redhatenterprise', 'fedora',
                      'centos', 'centosstream'):
            deps = """acl attr automake bc dbench dump e2fsprogs fio \
            gawk gcc indent libtool lvm2 make psmisc quota sed \
            xfsdump xfsprogs \
            libacl-devel libattr-devel libaio-devel libuuid-devel \
            xfsprogs-devel btrfs-progs-devel python2 sqlite""".split()

            if self.install_xfsprogs:
                deps += ['inih-devel', 'userspace-rcu-devel', 'libblkid-devel',
                         'gettext', 'libedit-devel', 'libattr-devel',
                         'device-mapper-devel', 'libicu-devel']

            deps_old_distros = ['xfsprogs-qa-devel']

            if distro != 'fedora' and major_ver_num > 7:
                    deps.remove('btrfs-progs-devel')

            args = ['sudo', 'yum', 'install', '-y'] + deps + deps_old_distros
        elif distro == 'ubuntu':
            deps = """xfslibs-dev uuid-dev libtool-bin \
            e2fsprogs automake gcc libuuid1 quota attr libattr1-dev make \
            libacl1-dev libaio-dev xfsprogs libgdbm-dev gawk fio dbench \
            uuid-runtime python sqlite3""".split()

            if self.install_xfsprogs:
                deps += ['libinih-dev', 'liburcu-dev', 'libblkid-dev',
                         'gettext', 'libedit-dev', 'libattr1-dev',
                         'libdevmapper-dev', 'libicu-dev', 'pkg-config']

            if major_ver_num >= 19:
                deps[deps.index('python')] ='python2'
            args = ['sudo', 'apt-get', 'install', '-y'] + deps
        else:
            raise RuntimeError('expected a yum based or a apt based system')

        self.mount_a.client_remote.run(args=args, omit_sudo=False)

    def create_reqd_users(self):
        self.mount_a.client_remote.run(args=['sudo', 'useradd', 'fsgqa'],
                                       omit_sudo=False, check_status=False)
        self.mount_a.client_remote.run(args=['sudo', 'groupadd', 'fsgqa'],
                                       omit_sudo=False, check_status=False)
        self.mount_a.client_remote.run(args=['sudo', 'useradd',
                                             '123456-fsgqa'], omit_sudo=False,
                                       check_status=False)

    def write_local_config(self):
        from os.path import join
        from textwrap import dedent

        mon_sock = self.fs.mon_manager.get_msgrv1_mon_socks()[0]
        self.test_dev = mon_sock + ':/' + self.test_dirname
        self.scratch_dev = mon_sock + ':/' + self.scratch_dirname

        xfstests_config_contents = dedent('''\
            export FSTYP=ceph
            export TEST_DEV={}
            export TEST_DIR={}
            export SCRATCH_DEV={}
            export SCRATCH_MNT={}
            export CEPHFS_MOUNT_OPTIONS="-o name=admin,secret={}"
            ''').format(self.test_dev, self.test_dirs_mount_path, self.scratch_dev,
                        self.scratch_dirs_mount_path, self.get_admin_key())

        self.mount_a.client_remote.write_file(join(self.xfstests_repo_path, 'local.config'),
                                              xfstests_config_contents, sudo=True)

    def tearDown(self):
        self.mount_a.client_remote.run(args=['sudo', 'userdel', '--force',
                                             '--remove', 'fsgqa'],
                                       omit_sudo=False, check_status=False)
        self.mount_a.client_remote.run(args=['sudo', 'userdel', '--force',
                                             '--remove', '123456-fsgqa'],
                                       omit_sudo=False, check_status=False)
        self.mount_a.client_remote.run(args=['sudo', 'groupdel', 'fsgqa'],
                                       omit_sudo=False, check_status=False)

        self.mount_a.client_remote.run(args=['sudo', 'rm', '-rf',
                                             self.xfstests_repo_path],
                                       omit_sudo=False, check_status=False)

        if self.install_xfsprogs:
            self.mount_a.client_remote.run(args=['sudo', 'rm', '-rf',
                                                 self.xfsprogs_repo_path],
                                           omit_sudo=False, check_status=False)

        super(XFSTestsDev, self).tearDown()
