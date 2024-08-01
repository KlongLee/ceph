"""Assorted enum values used throughout the smb mgr module."""

import sys

if sys.version_info >= (3, 11):  # pragma: no cover
    from enum import StrEnum as _StrEnum
else:  # pragma: no cover
    import enum

    # work like StrEnum for older python versions for our purposes
    class _StrEnum(str, enum.Enum):
        def __str__(self) -> str:
            return self.value


class CephFSStorageProvider(_StrEnum):
    KERNEL_MOUNT = 'kcephfs'
    SAMBA_VFS = 'samba-vfs'
    SAMBA_VFS_CLASSIC = 'samba-vfs/classic'
    SAMBA_VFS_NEW = 'samba-vfs/new'


class SubSystem(_StrEnum):
    CEPHFS = 'cephfs'


class Intent(_StrEnum):
    PRESENT = 'present'
    REMOVED = 'removed'


class State(_StrEnum):
    CREATED = 'created'
    NOT_PRESENT = 'not present'
    PRESENT = 'present'
    REMOVED = 'removed'
    UPDATED = 'updated'


class AuthMode(_StrEnum):
    USER = 'user'
    ACTIVE_DIRECTORY = 'active-directory'


class JoinSourceType(_StrEnum):
    RESOURCE = 'resource'


class UserGroupSourceType(_StrEnum):
    RESOURCE = 'resource'
    EMPTY = 'empty'


class ConfigNS(_StrEnum):
    CLUSTERS = 'clusters'
    SHARES = 'shares'
    USERS_AND_GROUPS = 'users_and_groups'
    JOIN_AUTHS = 'join_auths'


class LoginCategory(_StrEnum):
    USER = 'user'
    GROUP = 'group'


class LoginAccess(_StrEnum):
    ADMIN = 'admin'
    NONE = 'none'
    READ_ONLY = 'read'
    READ_ONLY_SHORT = 'r'
    READ_WRITE = 'read-write'
    READ_WRITE_SHORT = 'rw'

    def expand(self) -> 'LoginAccess':
        """Exapend abbreviated enum values into their full forms."""
        # the extra LoginAccess(...) calls are to appease mypy
        if self == self.READ_ONLY_SHORT:
            return LoginAccess(self.READ_ONLY)
        if self == self.READ_WRITE_SHORT:
            return LoginAccess(self.READ_WRITE)
        return self
