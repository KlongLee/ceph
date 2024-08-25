import errno

from .. import mgr


class Oauth2:
    def __init__(self, realm_name=None):
        self.realm_name = realm_name

    def to_dict(self):
        return {
            'realm_name': self.realm_name
    }


OAUTH2_SSO_COMMANDS = [
    {
        'cmd': 'dashboard sso enable oauth2',
        'desc': 'Enable Oauth2 Single Sign-On',
        'perm': 'w'
    },
    {
        'cmd': 'dashboard sso show oauth2',
        'desc': 'Show Oauth2 configuration',
        'perm': 'r'
    },
    {
        'cmd': 'dashboard sso setup oauth2 '
               'name=idp_realm_name,type=CephString ',
        'desc': 'Setup Oauth2 Single Sign-On',
        'perm': 'w'
    }
]


def handle_oauth2_sso_command(cmd):
    if cmd['prefix'] not in ['dashboard sso enable oauth2',
                             'dashboard sso show oauth2',
                             'dashboard sso setup oauth2']:
        return -errno.ENOSYS, '', ''

    if cmd['prefix'] == 'dashboard sso disable':
        mgr.SSO_DB.protocol = ''
        mgr.SSO_DB.save()
        return 0, 'SSO is "disabled".', ''

    if cmd['prefix'] == 'dashboard sso enable oauth2':
        configured = _is_sso_configured()
        if configured:
            mgr.SSO_DB.protocol = 'oauth2'
            mgr.SSO_DB.save()
            return 0, 'SSO is "enabled" with "oauth2" protocol.', ''
        return -errno.EPERM, '', 'Single Sign-On is not configured: ' \
            'use `ceph dashboard sso setup oauth2`'

    if cmd['prefix'] == 'dashboard sso show oauth2':
        return 0, mgr.SSO_DB.oauth2.idp_realm_name, ''

    if cmd['prefix'] == 'dashboard sso setup oauth2':
        idp_realm_name = cmd['idp_realm_name']
        mgr.SSO_DB.oauth2.realm_name = idp_realm_name
        mgr.SSO_DB.save()
        return 0, f'Configured "oauth2" SSO with realm: "{idp_realm_name}"', ''

    return -errno.ENOSYS, '', ''


def _is_sso_configured():
    return bool(mgr.SSO_DB.oauth2.idp_realm_name)


