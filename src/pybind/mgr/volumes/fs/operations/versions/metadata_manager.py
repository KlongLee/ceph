import os
import errno
import logging
import threading
import configparser
import re

import cephfs

from ...exception import MetadataMgrException

log = logging.getLogger(__name__)

# _lock needs to be shared across all instances of MetadataManager.
# that is why we have a file level instance
_lock = threading.Lock()


def _conf_reader(fs, fd, offset=0, length=4096):
    while True:
        buf = fs.read(fd, offset, length)
        offset += len(buf)
        if not buf:
            return
        yield buf.decode('utf-8')


class _ConfigWriter:
    def __init__(self, fs, fd):
        self._fs = fs
        self._fd = fd
        self._wrote = 0

    def write(self, value):
        buf = value.encode('utf-8')
        wrote = self._fs.write(self._fd, buf, -1)
        self._wrote += wrote
        return wrote

    def fsync(self):
        self._fs.fsync(self._fd, 0)

    @property
    def wrote(self):
        return self._wrote

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self._fs.close(self._fd)


class MetadataManager(object):
    GLOBAL_SECTION = "GLOBAL"
    USER_METADATA_SECTION   = "USER_METADATA"
    GLOBAL_META_KEY_VERSION = "version"
    GLOBAL_META_KEY_TYPE    = "type"
    GLOBAL_META_KEY_PATH    = "path"
    GLOBAL_META_KEY_STATE   = "state"

    CLONE_FAILURE_SECTION = "CLONE_FAILURE"
    CLONE_FAILURE_META_KEY_ERRNO = "errno"
    CLONE_FAILURE_META_KEY_ERROR_MSG = "error_msg"

    def __init__(self, fs, config_path, mode):
        self.fs = fs
        self.mode = mode
        self.config_path = config_path
        self.config = configparser.ConfigParser()

    def refresh(self):
        fd = None
        try:
            log.debug("opening config {0}".format(self.config_path))
            with _lock:
                fd = self.fs.open(self.config_path, os.O_RDONLY)
                cfg = ''.join(_conf_reader(self.fs, fd))
            self.config.read_string(cfg, source=self.config_path)
        except UnicodeDecodeError:
            raise MetadataMgrException(-errno.EINVAL,
                    "failed to decode, erroneous metadata config '{0}'".format(self.config_path))
        except cephfs.ObjectNotFound:
            raise MetadataMgrException(-errno.ENOENT, "metadata config '{0}' not found".format(self.config_path))
        except cephfs.Error as e:
            raise MetadataMgrException(-e.args[0], e.args[1])
        except configparser.Error:
            raise MetadataMgrException(-errno.EINVAL, "failed to parse, erroneous metadata config "
                    "'{0}'".format(self.config_path))
        finally:
            if fd is not None:
                self.fs.close(fd)

    def flush(self):
        # cull empty sections
        for section in list(self.config.sections()):
            if len(self.config.items(section)) == 0:
                self.config.remove_section(section)

        try:
            with _lock:
                tmp_config_path = self.config_path + b'.tmp'
                fd = self.fs.open(tmp_config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, self.mode)
                with _ConfigWriter(self.fs, fd) as cfg_writer:
                    self.config.write(cfg_writer)
                    cfg_writer.fsync()
                self.fs.rename(tmp_config_path, self.config_path)
            log.info(f"wrote {cfg_writer.wrote} bytes to config {tmp_config_path}")
            log.info(f"Renamed {tmp_config_path} to config {self.config_path}")
        except cephfs.Error as e:
            raise MetadataMgrException(-e.args[0], e.args[1])

    def init(self, version, typ, path, state):
        # you may init just once before refresh (helps to overwrite conf)
        if self.has_section(MetadataManager.GLOBAL_SECTION):
            raise MetadataMgrException(-errno.EINVAL, "init called on an existing config")

        self.add_section(MetadataManager.GLOBAL_SECTION)
        self.update_section_multi(
            MetadataManager.GLOBAL_SECTION, {MetadataManager.GLOBAL_META_KEY_VERSION : str(version),
                                             MetadataManager.GLOBAL_META_KEY_TYPE    : str(typ),
                                             MetadataManager.GLOBAL_META_KEY_PATH    : str(path),
                                             MetadataManager.GLOBAL_META_KEY_STATE   : str(state)
            })

    def add_section(self, section):
        try:
            self.config.add_section(section)
        except configparser.DuplicateSectionError:
            return
        except:
            raise MetadataMgrException(-errno.EINVAL, "error adding section to config")

    def remove_option(self, section, key):
        if not self.has_section(section):
            raise MetadataMgrException(-errno.ENOENT, "section '{0}' does not exist".format(section))
        return self.config.remove_option(section, key)

    def remove_section(self, section):
        self.config.remove_section(section)

    def update_section(self, section, key, value):
        if not self.has_section(section):
            raise MetadataMgrException(-errno.ENOENT, "section '{0}' does not exist".format(section))
        self.set_option(section, key, value)

    def update_section_multi(self, section, dct):
        if not self.has_section(section):
            raise MetadataMgrException(-errno.ENOENT, "section '{0}' does not exist".format(section))
        for key,value in dct.items():
            self.set_option(section, key, value)

    def update_global_section(self, key, value):
        self.update_section(MetadataManager.GLOBAL_SECTION, key, str(value))

    def has_section(self, section):
        return True if self.config.has_section(section) else False

    def has_option(self, section, key, raise_ex=True):
        if not self.has_section(section):
            if raise_ex:
                raise MetadataMgrException(
                    -errno.ENOENT, f'section "{section}" does not exist')
            else:
                return False
        if not self.config.has_option(section, key):
            if raise_ex:
                raise MetadataMgrException(
                    -errno.ENOENT, f'no "{key}" in section "{section}"')
            else:
                return False
        return True

    def get_option(self, section, key):
        if self.has_option(section, key, raise_ex=True):
            return self.config.get(section, key)

    def get_global_option(self, key):
        return self.get_option(MetadataManager.GLOBAL_SECTION, key)

    def set_option(self, section, key, value):
        if not isinstance(value, str):
            value = str(value)
        self.config.set(section, key, value)

    def set_global_option(self, key, value):
        if not isinstance(value, str):
            value = str(value)
        self.config.set(MetadataManager.GLOBAL_SECTION, key, value)

    def list_all_options_from_section(self, section):
        metadata_dict = {}
        if self.has_section(section):
            options = self.config.options(section)
            for option in options:
                metadata_dict[option] = self.config.get(section,option)
        return metadata_dict

    def list_all_keys_with_specified_values_from_section(self, section, value):
        keys = []
        if self.has_section(section):
            options = self.config.options(section)
            for option in options:
                if (value == self.config.get(section, option)) :
                    keys.append(option)
        return keys

    def section_has_item(self, section, item):
        if not self.has_section(section):
            raise MetadataMgrException(-errno.ENOENT, "section '{0}' does not exist".format(section))
        return item in [v[1] for v in self.config.items(section)]

    def has_snap_metadata_section(self):
        sections = self.config.sections()
        r = re.compile('SNAP_METADATA_.*')
        for section in sections:
            if r.match(section):
                return True
        return False

    def list_snaps_with_metadata(self):
        sections = self.config.sections()
        r = re.compile('SNAP_METADATA_.*')
        return [section[len("SNAP_METADATA_"):] for section in sections if r.match(section)]
