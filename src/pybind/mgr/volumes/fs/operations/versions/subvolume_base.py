import os
import stat
import uuid
import errno
import logging
from hashlib import md5
from typing import Dict, Union

import cephfs

from ..pin_util import pin
from .subvolume_attrs import SubvolumeTypes, SubvolumeStates
from .metadata_manager import MetadataManager
from ..trash import create_trashcan, open_trashcan
from ...fs_util import get_ancestor_xattr
from ...exception import MetadataMgrException, VolumeException
from .op_sm import SubvolumeOpSm

log = logging.getLogger(__name__)

class SubvolumeBase(object):
    LEGACY_CONF_DIR = "_legacy"

    def __init__(self, mgr, fs, vol_spec, group, subvolname, legacy=False):
        self.mgr = mgr
        self.fs = fs
        self.cmode = None
        self.user_id = None
        self.group_id = None
        self.vol_spec = vol_spec
        self.group = group
        self.subvolname = subvolname
        self.legacy_mode = legacy
        self.load_config()

    @property
    def uid(self):
        return self.user_id

    @uid.setter
    def uid(self, val):
        self.user_id = val

    @property
    def gid(self):
        return self.group_id

    @gid.setter
    def gid(self, val):
        self.group_id = val

    @property
    def mode(self):
        return self.cmode

    @mode.setter
    def mode(self, val):
        self.cmode = val

    @property
    def base_path(self):
        return os.path.join(self.group.path, self.subvolname.encode('utf-8'))

    @property
    def config_path(self):
        return os.path.join(self.base_path, b".meta")

    @property
    def legacy_dir(self):
        return os.path.join(self.vol_spec.base_dir.encode('utf-8'), SubvolumeBase.LEGACY_CONF_DIR.encode('utf-8'))

    @property
    def legacy_config_path(self):
        m = md5()
        m.update(self.base_path)
        meta_config = "{0}.meta".format(m.digest().hex())
        return os.path.join(self.legacy_dir, meta_config.encode('utf-8'))

    @property
    def namespace(self):
        return "{0}{1}".format(self.vol_spec.fs_namespace, self.subvolname)

    @property
    def group_name(self):
        return self.group.group_name

    @property
    def subvol_name(self):
        return self.subvolname

    @property
    def legacy_mode(self):
        return self.legacy

    @legacy_mode.setter
    def legacy_mode(self, mode):
        self.legacy = mode

    @property
    def path(self):
        """ Path to subvolume data directory """
        raise NotImplementedError

    @property
    def features(self):
        """ List of features supported by the subvolume, containing items from SubvolumeFeatures """
        raise NotImplementedError

    @property
    def state(self):
        """ Subvolume state, one of SubvolumeStates """
        raise NotImplementedError

    @property
    def subvol_type(self):
        return SubvolumeTypes.from_value(self.metadata_mgr.get_global_option(MetadataManager.GLOBAL_META_KEY_TYPE))

    @property
    def purgeable(self):
        """ Boolean declaring if subvolume can be purged """
        raise NotImplementedError

    def load_config(self):
        if self.legacy_mode:
            self.metadata_mgr = MetadataManager(self.fs, self.legacy_config_path, 0o640)
        else:
            self.metadata_mgr = MetadataManager(self.fs, self.config_path, 0o640)

    def get_attrs(self, pathname):
        # get subvolume attributes
        attrs = {} # type: Dict[str, Union[int, str, None]]
        stx = self.fs.statx(pathname,
                            cephfs.CEPH_STATX_UID | cephfs.CEPH_STATX_GID | cephfs.CEPH_STATX_MODE,
                            cephfs.AT_SYMLINK_NOFOLLOW)

        attrs["uid"] = int(stx["uid"])
        attrs["gid"] = int(stx["gid"])
        attrs["mode"] = int(int(stx["mode"]) & ~stat.S_IFMT(stx["mode"]))

        try:
            attrs["data_pool"] = self.fs.getxattr(pathname, 'ceph.dir.layout.pool').decode('utf-8')
        except cephfs.NoData:
            attrs["data_pool"] = None

        try:
            attrs["pool_namespace"] = self.fs.getxattr(pathname, 'ceph.dir.layout.pool_namespace').decode('utf-8')
        except cephfs.NoData:
            attrs["pool_namespace"] = None

        try:
            attrs["quota"] = int(self.fs.getxattr(pathname, 'ceph.quota.max_bytes').decode('utf-8'))
        except cephfs.NoData:
            attrs["quota"] = None

        return attrs

    def set_attrs(self, path, attrs):
        # set subvolume attributes
        # set size
        quota = attrs.get("quota")
        if quota is not None:
            try:
                self.fs.setxattr(path, 'ceph.quota.max_bytes', str(quota).encode('utf-8'), 0)
            except cephfs.InvalidValue as e:
                raise VolumeException(-errno.EINVAL, "invalid size specified: '{0}'".format(quota))
            except cephfs.Error as e:
                raise VolumeException(-e.args[0], e.args[1])

        # set pool layout
        data_pool = attrs.get("data_pool")
        if data_pool is not None:
            try:
                self.fs.setxattr(path, 'ceph.dir.layout.pool', data_pool.encode('utf-8'), 0)
            except cephfs.InvalidValue:
                raise VolumeException(-errno.EINVAL,
                                      "invalid pool layout '{0}' -- need a valid data pool".format(data_pool))
            except cephfs.Error as e:
                raise VolumeException(-e.args[0], e.args[1])

        # isolate namespace
        xattr_key = xattr_val = None
        pool_namespace = attrs.get("pool_namespace")
        if pool_namespace is not None:
            # enforce security isolation, use separate namespace for this subvolume
            xattr_key = 'ceph.dir.layout.pool_namespace'
            xattr_val = pool_namespace
        elif not data_pool:
            # If subvolume's namespace layout is not set, then the subvolume's pool
            # layout remains unset and will undesirably change with ancestor's
            # pool layout changes.
            xattr_key = 'ceph.dir.layout.pool'
            xattr_val = None
            try:
                self.fs.getxattr(path, 'ceph.dir.layout.pool').decode('utf-8')
            except cephfs.NoData as e:
                xattr_val = get_ancestor_xattr(self.fs, os.path.split(path)[0], "ceph.dir.layout.pool")
        if xattr_key and xattr_val:
            try:
                self.fs.setxattr(path, xattr_key, xattr_val.encode('utf-8'), 0)
            except cephfs.Error as e:
                raise VolumeException(-e.args[0], e.args[1])

        # set uid/gid
        uid = attrs.get("uid")
        if uid is None:
            uid = self.group.uid
        else:
            try:
                if uid < 0:
                    raise ValueError
            except ValueError:
                raise VolumeException(-errno.EINVAL, "invalid UID")

        gid = attrs.get("gid")
        if gid is None:
            gid = self.group.gid
        else:
            try:
                if gid < 0:
                    raise ValueError
            except ValueError:
                raise VolumeException(-errno.EINVAL, "invalid GID")

        if uid is not None and gid is not None:
            self.fs.chown(path, uid, gid)

    def _resize(self, path, newsize, noshrink):
        try:
            newsize = int(newsize)
            if newsize <= 0:
                raise VolumeException(-errno.EINVAL, "Invalid subvolume size")
        except ValueError:
            newsize = newsize.lower()
            if not (newsize == "inf" or newsize == "infinite"):
                raise VolumeException(-errno.EINVAL, "invalid size option '{0}'".format(newsize))
            newsize = 0
            noshrink = False

        try:
            maxbytes = int(self.fs.getxattr(path, 'ceph.quota.max_bytes').decode('utf-8'))
        except cephfs.NoData:
            maxbytes = 0
        except cephfs.Error as e:
            raise VolumeException(-e.args[0], e.args[1])

        subvolstat = self.fs.stat(path)
        if newsize > 0 and newsize < subvolstat.st_size:
            if noshrink:
                raise VolumeException(-errno.EINVAL, "Can't resize the subvolume. The new size '{0}' would be lesser than the current "
                                      "used size '{1}'".format(newsize, subvolstat.st_size))

        if not newsize == maxbytes:
            try:
                self.fs.setxattr(path, 'ceph.quota.max_bytes', str(newsize).encode('utf-8'), 0)
            except cephfs.Error as e:
                raise VolumeException(-e.args[0], "Cannot set new size for the subvolume. '{0}'".format(e.args[1]))
        return newsize, subvolstat.st_size

    def pin(self, pin_type, pin_setting):
        return pin(self.fs, self.base_path, pin_type, pin_setting)

    def init_config(self, version, subvolume_type, subvolume_path, subvolume_state):
        self.metadata_mgr.init(version, subvolume_type.value, subvolume_path, subvolume_state.value)
        self.metadata_mgr.flush()

    def discover(self):
        log.debug("discovering subvolume '{0}' [mode: {1}]".format(self.subvolname, "legacy" if self.legacy_mode else "new"))
        try:
            self.fs.stat(self.base_path)
            self.metadata_mgr.refresh()
            log.debug("loaded subvolume '{0}'".format(self.subvolname))
        except MetadataMgrException as me:
            if me.errno == -errno.ENOENT and not self.legacy_mode:
                self.legacy_mode = True
                self.load_config()
                self.discover()
            else:
                raise
        except cephfs.Error as e:
            if e.args[0] == errno.ENOENT:
                raise VolumeException(-errno.ENOENT, "subvolume '{0}' does not exist".format(self.subvolname))
            raise VolumeException(-e.args[0], "error accessing subvolume '{0}'".format(self.subvolname))

    def _trash_dir(self, path):
        create_trashcan(self.fs, self.vol_spec)
        with open_trashcan(self.fs, self.vol_spec) as trashcan:
            trashcan.dump(path)
            log.info("subvolume path '{0}' moved to trashcan".format(path))

    def _link_dir(self, path, bname):
        create_trashcan(self.fs, self.vol_spec)
        with open_trashcan(self.fs, self.vol_spec) as trashcan:
            trashcan.link(path, bname)
            log.info("subvolume path '{0}' linked in trashcan bname {1}".format(path, bname))

    def trash_base_dir(self):
        if self.legacy_mode:
            self.fs.unlink(self.legacy_config_path)
        self._trash_dir(self.base_path)

    def create_base_dir(self, mode):
        try:
            self.fs.mkdirs(self.base_path, mode)
        except cephfs.Error as e:
            raise VolumeException(-e.args[0], e.args[1])

    def info (self):
        subvolpath = self.metadata_mgr.get_global_option(MetadataManager.GLOBAL_META_KEY_PATH)
        etype = self.subvol_type
        st = self.fs.statx(subvolpath, cephfs.CEPH_STATX_BTIME | cephfs.CEPH_STATX_SIZE |
                                       cephfs.CEPH_STATX_UID | cephfs.CEPH_STATX_GID |
                                       cephfs.CEPH_STATX_MODE | cephfs.CEPH_STATX_ATIME |
                                       cephfs.CEPH_STATX_MTIME | cephfs.CEPH_STATX_CTIME,
                                       cephfs.AT_SYMLINK_NOFOLLOW)
        usedbytes = st["size"]
        try:
            nsize = int(self.fs.getxattr(subvolpath, 'ceph.quota.max_bytes').decode('utf-8'))
        except cephfs.NoData:
            nsize = 0

        try:
            data_pool = self.fs.getxattr(subvolpath, 'ceph.dir.layout.pool').decode('utf-8')
            pool_namespace = self.fs.getxattr(subvolpath, 'ceph.dir.layout.pool_namespace').decode('utf-8')
        except cephfs.Error as e:
            raise VolumeException(-e.args[0], e.args[1])

        return {'path': subvolpath, 'type': etype.value, 'uid': int(st["uid"]), 'gid': int(st["gid"]),
            'atime': str(st["atime"]), 'mtime': str(st["mtime"]), 'ctime': str(st["ctime"]),
            'mode': int(st["mode"]), 'data_pool': data_pool, 'created_at': str(st["btime"]),
            'bytes_quota': "infinite" if nsize == 0 else nsize, 'bytes_used': int(usedbytes),
            'bytes_pcent': "undefined" if nsize == 0 else '{0:.2f}'.format((float(usedbytes) / nsize) * 100.0),
            'pool_namespace': pool_namespace, 'features': self.features, 'state': self.state.value}
