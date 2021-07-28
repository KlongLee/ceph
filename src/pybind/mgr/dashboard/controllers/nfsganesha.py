# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import os
from functools import partial

import cephfs
import cherrypy

from .. import mgr
from ..security import Scope
from ..services.cephfs import CephFS
from ..services.exception import DashboardException, serialize_dashboard_exception
from ..services.rgw_client import NoCredentialsException, \
    NoRgwDaemonsException, RequestException, RgwClient
from . import APIDoc, APIRouter, BaseController, Endpoint, EndpointDoc, \
    ReadPermission, RESTController, Task, UIRouter

logger = logging.getLogger('controllers.nfs')


class NFSException(DashboardException):
    def __init__(self, msg):
        super(NFSException, self).__init__(component="nfs", msg=msg)


# documentation helpers
EXPORT_SCHEMA = {
    'export_id': (int, 'Export ID'),
    'path': (str, 'Export path'),
    'cluster_id': (str, 'Cluster identifier'),
    'daemons': ([str], 'List of NFS Ganesha daemons identifiers'),
    'pseudo': (str, 'Pseudo FS path'),
    'tag': (str, 'NFSv3 export tag'),
    'access_type': (str, 'Export access type'),
    'squash': (str, 'Export squash policy'),
    'security_label': (str, 'Security label'),
    'protocols': ([int], 'List of protocol types'),
    'transports': ([str], 'List of transport types'),
    'fsal': ({
        'name': (str, 'name of FSAL'),
        'user_id': (str, 'CephX user id', True),
        'filesystem': (str, 'CephFS filesystem ID', True),
        'sec_label_xattr': (str, 'Name of xattr for security label', True),
        'rgw_user_id': (str, 'RGW user id', True)
    }, 'FSAL configuration'),
    'clients': ([{
        'addresses': ([str], 'list of IP addresses'),
        'access_type': (str, 'Client access type'),
        'squash': (str, 'Client squash policy')
    }], 'List of client configurations'),
}


CREATE_EXPORT_SCHEMA = {
    'path': (str, 'Export path'),
    'cluster_id': (str, 'Cluster identifier'),
    'daemons': ([str], 'List of NFS Ganesha daemons identifiers'),
    'pseudo': (str, 'Pseudo FS path'),
    'tag': (str, 'NFSv3 export tag'),
    'access_type': (str, 'Export access type'),
    'squash': (str, 'Export squash policy'),
    'security_label': (str, 'Security label'),
    'protocols': ([int], 'List of protocol types'),
    'transports': ([str], 'List of transport types'),
    'fsal': ({
        'name': (str, 'name of FSAL'),
        'user_id': (str, 'CephX user id', True),
        'filesystem': (str, 'CephFS filesystem ID', True),
        'sec_label_xattr': (str, 'Name of xattr for security label', True),
        'rgw_user_id': (str, 'RGW user id', True)
    }, 'FSAL configuration'),
    'clients': ([{
        'addresses': ([str], 'list of IP addresses'),
        'access_type': (str, 'Client access type'),
        'squash': (str, 'Client squash policy')
    }], 'List of client configurations'),
    'reload_daemons': (bool,
                       'Trigger reload of NFS-Ganesha daemons configuration',
                       True)
}


# pylint: disable=not-callable
def NfsTask(name, metadata, wait_for):  # noqa: N802
    def composed_decorator(func):
        return Task("nfs/{}".format(name), metadata, wait_for,
                    partial(serialize_dashboard_exception,
                            include_http_status=True))(func)
    return composed_decorator


@APIRouter('/nfs-ganesha', Scope.NFS_GANESHA)
@APIDoc("NFS-Ganesha Management API", "NFS-Ganesha")
class NFSGanesha(RESTController):

    @EndpointDoc("Status of NFS-Ganesha management feature",
                 responses={200: {
                     'available': (bool, "Is API available?"),
                     'message': (str, "Error message")
                 }})
    @Endpoint()
    @ReadPermission
    def status(self):
        status = {'available': True, 'message': None}
        try:
            mgr.remote('nfs', 'is_active')
        except (NameError, ImportError) as e:
            status['message'] = str(e)  # type: ignore
            status['available'] = False

        return status


@APIRouter('/nfs-ganesha/export', Scope.NFS_GANESHA)
@APIDoc(group="NFS-Ganesha")
class NFSGaneshaExports(RESTController):
    RESOURCE_ID = "cluster_id/export_id"

    @EndpointDoc("List all NFS-Ganesha exports",
                 responses={200: [EXPORT_SCHEMA]})
    def list(self):
        return mgr.remote('nfs', 'export_ls')

    @NfsTask('create', {'path': '{path}', 'fsal': '{fsal.name}',
                        'cluster_id': '{cluster_id}'}, 2.0)
    @EndpointDoc("Creates a new NFS-Ganesha export",
                 parameters=CREATE_EXPORT_SCHEMA,
                 responses={201: EXPORT_SCHEMA})
    def create(self, path, cluster_id, daemons, pseudo, tag, access_type,
               squash, security_label, protocols, transports, fsal, clients,
               reload_daemons=True):
        if fsal['name'] not in mgr.remote('nfs', 'cluster_fsals'):
            raise NFSException("Cannot create this export. "
                               "FSAL '{}' cannot be managed by the dashboard."
                               .format(fsal['name']))

        fsal.pop('user_id')  # mgr/nfs does not let you customize user_id
        # FIXME: what was this?     'tag': tag,
        raw_ex = {
            'path': path,
            'pseudo': pseudo,
            'cluster_id': cluster_id,
            'daemons': daemons,
            'access_type': access_type,
            'squash': squash,
            'security_label': security_label,
            'protocols': protocols,
            'transports': transports,
            'fsal': fsal,
            'clients': clients
        }
        export = mgr.remote('nfs', 'export_apply', cluster_id, raw_ex)
        return export

    @EndpointDoc("Get an NFS-Ganesha export",
                 parameters={
                     'cluster_id': (str, 'Cluster identifier'),
                     'export_id': (int, "Export ID")
                 },
                 responses={200: EXPORT_SCHEMA})
    def get(self, cluster_id, export_id):
        return mgr.remote('nfs', 'export_get', cluster_id, export_id)

    @NfsTask('edit', {'cluster_id': '{cluster_id}', 'export_id': '{export_id}'},
             2.0)
    @EndpointDoc("Updates an NFS-Ganesha export",
                 parameters=dict(export_id=(int, "Export ID"),
                                 **CREATE_EXPORT_SCHEMA),
                 responses={200: EXPORT_SCHEMA})
    def set(self, cluster_id, export_id, path, daemons, pseudo, tag, access_type,
            squash, security_label, protocols, transports, fsal, clients,
            reload_daemons=True):
        export_id = int(export_id)

        if not mgr.remote('nfs', 'export_get', export_id):
            raise cherrypy.HTTPError(404)  # pragma: no cover - the handling is too obvious

        if fsal['name'] not in mgr.remote('nfs', 'cluster_fsals'):
            raise NFSException("Cannot make modifications to this export. "
                               "FSAL '{}' cannot be managed by the dashboard."
                               .format(fsal['name']))

        fsal.pop('user_id')  # mgr/nfs does not let you customize user_id
        # FIXME: what was this? 'tag': tag,
        raw_ex = {
            'path': path,
            'pseudo': pseudo,
            'cluster_id': cluster_id,
            'daemons': daemons,
            'access_type': access_type,
            'squash': squash,
            'security_label': security_label,
            'protocols': protocols,
            'transports': transports,
            'fsal': fsal,
            'clients': clients
        }
        export = mgr.remote('nfs', 'export_apply', cluster_id, raw_ex)
        return export

    @NfsTask('delete', {'cluster_id': '{cluster_id}',
                        'export_id': '{export_id}'}, 2.0)
    @EndpointDoc("Deletes an NFS-Ganesha export",
                 parameters={
                     'cluster_id': (str, 'Cluster identifier'),
                     'export_id': (int, "Export ID"),
                     'reload_daemons': (bool,
                                        'Trigger reload of NFS-Ganesha daemons'
                                        ' configuration',
                                        True)
                 })
    def delete(self, cluster_id, export_id, reload_daemons=True):
        export_id = int(export_id)

        export = mgr.remote('nfs', 'export_get', cluster_id, export_id)
        if not export:
            raise cherrypy.HTTPError(404)  # pragma: no cover - the handling is too obvious
        mgr.remote('nfs', 'export_rm', cluster_id, export['pseudo'])


@APIRouter('/nfs-ganesha/daemon', Scope.NFS_GANESHA)
@APIDoc(group="NFS-Ganesha")
class NFSGaneshaService(RESTController):

    @EndpointDoc("List NFS-Ganesha daemons information",
                 responses={200: [{
                     'daemon_id': (str, 'Daemon identifier'),
                     'cluster_id': (str, 'Cluster identifier'),
                     'cluster_type': (str, 'Cluster type'),   # FIXME: remove this property
                     'status': (int, 'Status of daemon', True),
                     'desc': (str, 'Status description', True)
                 }]})
    def list(self):
        # FIXME: remove this; dashboard should only care about clusters.
        return mgr.remote('nfs', 'daemon_ls')


@UIRouter('/nfs-ganesha', Scope.NFS_GANESHA)
class NFSGaneshaUi(BaseController):
    @Endpoint('GET', '/cephx/clients')
    @ReadPermission
    def cephx_clients(self):
        # FIXME: remove this; cephx users/creds are managed by mgr/nfs
        return ['admin']

    @Endpoint('GET', '/fsals')
    @ReadPermission
    def fsals(self):
        return mgr.remote('nfs', 'cluster_fsals')

    @Endpoint('GET', '/lsdir')
    @ReadPermission
    def lsdir(self, fs_name, root_dir=None, depth=1):  # pragma: no cover
        if root_dir is None:
            root_dir = "/"
        if not root_dir.startswith('/'):
            root_dir = '/{}'.format(root_dir)
        root_dir = os.path.normpath(root_dir)

        try:
            depth = int(depth)
            error_msg = ''
            if depth < 0:
                error_msg = '`depth` must be greater or equal to 0.'
            if depth > 5:
                logger.warning("Limiting depth to maximum value of 5: "
                               "input depth=%s", depth)
                depth = 5
        except ValueError:
            error_msg = '`depth` must be an integer.'
        finally:
            if error_msg:
                raise DashboardException(code=400,
                                         component='nfsganesha',
                                         msg=error_msg)

        try:
            cfs = CephFS(fs_name)
            paths = [root_dir]
            paths.extend([p['path'].rstrip('/')
                          for p in cfs.ls_dir(root_dir, depth)])
        except (cephfs.ObjectNotFound, cephfs.PermissionError):
            paths = []
        return {'paths': paths}

    @Endpoint('GET', '/cephfs/filesystems')
    @ReadPermission
    def filesystems(self):
        return CephFS.list_filesystems()

    @Endpoint('GET', '/rgw/buckets')
    @ReadPermission
    def buckets(self, user_id=None):
        try:
            return RgwClient.instance(user_id).get_buckets()
        except (DashboardException, NoCredentialsException, RequestException,
                NoRgwDaemonsException):
            return []

    @Endpoint('GET', '/clusters')
    @ReadPermission
    def clusters(self):
        return mgr.remote('nfs', 'cluster_ls')
