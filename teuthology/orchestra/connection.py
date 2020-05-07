"""
Connection utilities
"""
import base64
import paramiko
import os
import socket
import logging

from paramiko import AuthenticationException
from paramiko.ssh_exception import NoValidConnectionsError

from teuthology.config import config
from teuthology.contextutil import safe_while

log = logging.getLogger(__name__)

RECONNECT_EXCEPTIONS = (
  socket.error,
  AuthenticationException,
  NoValidConnectionsError,
)


def split_user(user_at_host):
    """
    break apart user@host fields into user and host.
    """
    try:
        user, host = user_at_host.rsplit('@', 1)
    except ValueError:
        user, host = None, user_at_host
    assert user != '', \
        "Bad input to split_user: {user_at_host!r}".format(user_at_host=user_at_host)
    return user, host


def create_key(keytype, key):
    """
    Create an ssh-rsa, ssh-dss or ssh-ed25519 key.
    """
    if keytype == 'ssh-rsa':
        return paramiko.rsakey.RSAKey(data=base64.decodestring(key.encode()))
    elif keytype == 'ssh-dss':
        return paramiko.dsskey.DSSKey(data=base64.decodestring(key.encode()))
    elif keytype == 'ssh-ed25519':
        return paramiko.ed25519key.Ed25519Key(data=base64.decodestring(key.encode()))
    else:
        raise ValueError('keytype must be ssh-rsa, ssh-dss (DSA) or ssh-ed25519')


def connect(user_at_host, host_key=None, keep_alive=False, timeout=60,
            _SSHClient=None, _create_key=None, retry=True, key_filename=None):
    """
    ssh connection routine.

    :param user_at_host: user@host
    :param host_key: ssh key
    :param keep_alive: keep_alive indicator
    :param timeout:    timeout in seconds
    :param _SSHClient: client, default is paramiko ssh client
    :param _create_key: routine to create a key (defaults to local reate_key)
    :param retry:       Whether or not to retry failed connection attempts
                        (eventually giving up if none succeed). Default is True
    :param key_filename:  Optionally override which private key to use.
    :return: ssh connection.
    """
    user, host = split_user(user_at_host)
    if _SSHClient is None:
        _SSHClient = paramiko.SSHClient
    ssh = _SSHClient()

    if _create_key is None:
        _create_key = create_key

    if host_key is None:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if config.verify_host_keys is True:
            ssh.load_system_host_keys()

    else:
        keytype, key = host_key.split(' ', 1)
        ssh.get_host_keys().add(
            hostname=host,
            keytype=keytype,
            key=_create_key(keytype, key)
            )

    connect_args = dict(
        hostname=host,
        username=user,
        timeout=timeout
    )

    ssh_config_path = os.path.expanduser("~/.ssh/config")
    if os.path.exists(ssh_config_path):
        ssh_config = paramiko.SSHConfig()
        ssh_config.parse(open(ssh_config_path))
        opts = ssh_config.lookup(host)
        if not key_filename and 'identityfile' in opts:
            key_filename = opts['identityfile']

    if key_filename:
        if not isinstance(key_filename, list):
            key_filename = [key_filename]
        key_filename = [os.path.expanduser(f) for f in key_filename]
        connect_args['key_filename'] = key_filename

    log.debug(connect_args)

    if not retry:
        ssh.connect(**connect_args)
    else:
        # Retries are implemented using safe_while
        with safe_while(sleep=1, action='connect to ' + host) as proceed:
            while proceed():
                try:
                    ssh.connect(**connect_args)
                    break
                except RECONNECT_EXCEPTIONS as e:
                    log.debug("Error connecting to {host}: {e}".format(host=host,e=e))
                except Exception as e:
                    # gevent.__hub_primitives returns a generic Exception, *sigh*
                    if "timed out" in str(e):
                        log.debug("Error connecting to {host}: {e}".format(host=host,e=e))
                    else:
                        raise

    ssh.get_transport().set_keepalive(keep_alive)
    return ssh
