"""
This module wrap's Rook + Kubernetes APIs to expose the calls
needed to implement an orchestrator module.  While the orchestrator
module exposes an async API, this module simply exposes blocking API
call methods.

This module is runnable outside of ceph-mgr, useful for testing.
"""
import threading
import logging
import json
from contextlib import contextmanager

import jsonpatch
from six.moves.urllib.parse import urljoin  # pylint: disable=import-error

# Optional kubernetes imports to enable MgrModule.can_run
# to behave cleanly.
from urllib3.exceptions import ProtocolError

from ceph.deployment.drive_group import DriveGroupSpec
from mgr_util import merge_dicts

try:
    from typing import Optional
except ImportError:
    pass  # just for type annotations

try:
    from kubernetes.client.rest import ApiException
    from kubernetes.client import V1ListMeta, CoreV1Api, V1Pod
    from kubernetes import watch
except ImportError:
    class ApiException(Exception):  # type: ignore
        status = 0

from .rook_client.ceph import cephfilesystem as cfs
from .rook_client.ceph import cephnfs as cnfs
from .rook_client.ceph import cephobjectstore as cos
from .rook_client.ceph import cephcluster as ccl


import orchestrator


try:
    from rook.module import RookEnv
    from typing import List, Dict
except ImportError:
    pass  # just used for type checking.

log = logging.getLogger(__name__)


def _urllib3_supports_read_chunked():
    # There is a bug in CentOS 7 as it ships a urllib3 which is lower
    # than required by kubernetes-client
    try:
        from urllib3.response import HTTPResponse
        return hasattr(HTTPResponse, 'read_chunked')
    except ImportError:
        return False


_urllib3_supports_read_chunked = _urllib3_supports_read_chunked()

class ApplyException(orchestrator.OrchestratorError):
    """
    For failures to update the Rook CRDs, usually indicating
    some kind of interference between our attempted update
    and other conflicting activity.
    """


def threaded(f):
    def wrapper(*args, **kwargs):
        t = threading.Thread(target=f, args=args, kwargs=kwargs)
        t.start()
        return t

    return wrapper


class KubernetesResource(object):
    def __init__(self, api_func, **kwargs):
        """
        Generic kubernetes Resource parent class

        The api fetch and watch methods should be common across resource types,

        Exceptions in the runner thread are propagated to the caller.

        :param api_func: kubernetes client api function that is passed to the watcher
        :param filter_func: signature: ``(Item) -> bool``.
        """
        self.kwargs = kwargs
        self.api_func = api_func

        # ``_items`` is accessed by different threads. I assume assignment is atomic.
        self._items = dict()
        self.thread = None  # type: Optional[threading.Thread]
        self.exception = None
        if not _urllib3_supports_read_chunked:
            logging.info('urllib3 is too old. Fallback to full fetches')

    def _fetch(self):
        """ Execute the requested api method as a one-off fetch"""
        response = self.api_func(**self.kwargs)
        # metadata is a V1ListMeta object type
        metadata = response.metadata  # type: V1ListMeta
        self._items = {item.metadata.name: item for item in response.items}
        log.info('Full fetch of {}. result: {}'.format(self.api_func, len(self._items)))
        return metadata.resource_version

    @property
    def items(self):
        """
        Returns the items of the request.
        Creates the watcher as a side effect.
        :return:
        """
        if self.exception:
            e = self.exception
            self.exception = None
            raise e  # Propagate the exception to the user.
        if not self.thread or not self.thread.is_alive():
            resource_version = self._fetch()
            if _urllib3_supports_read_chunked:
                # Start a thread which will use the kubernetes watch client against a resource
                log.debug("Attaching resource watcher for k8s {}".format(self.api_func))
                self.thread = self._watch(resource_version)

        return self._items.values()

    @threaded
    def _watch(self, res_ver):
        """ worker thread that runs the kubernetes watch """

        self.exception = None

        w = watch.Watch()

        try:
            # execute generator to continually watch resource for changes
            for event in w.stream(self.api_func, resource_version=res_ver, watch=True,
                                  **self.kwargs):
                self.health = ''
                item = event['object']
                try:
                    name = item.metadata.name
                except AttributeError:
                    raise AttributeError(
                        "{} doesn't contain a metadata.name. Unable to track changes".format(
                            self.api_func))

                log.info('{} event: {}'.format(event['type'], name))

                if event['type'] in ('ADDED', 'MODIFIED'):
                    self._items = merge_dicts(self._items, {name: item})
                elif event['type'] == 'DELETED':
                    self._items = {k:v for k,v in self._items.items() if k != name}
                elif event['type'] == 'BOOKMARK':
                    pass
                elif event['type'] == 'ERROR':
                    raise ApiException(str(event))
                else:
                    raise KeyError('Unknown watch event {}'.format(event['type']))
        except ProtocolError as e:
            if 'Connection broken' in str(e):
                log.info('Connection reset.')
                return
            raise
        except ApiException as e:
            log.exception('K8s API failed. {}'.format(self.api_func))
            self.exception = e
            raise
        except Exception as e:
            log.exception("Watcher failed. ({})".format(self.api_func))
            self.exception = e
            raise


class RookCluster(object):
    def __init__(self, k8s, rook_env):
        self.rook_env = rook_env  # type: RookEnv
        self.k8s = k8s  # type: CoreV1Api

        #  TODO: replace direct k8s calls with Rook API calls
        # when they're implemented
        self.inventory_maps = KubernetesResource(self.k8s.list_namespaced_config_map,
                                                 namespace=self.rook_env.operator_namespace,
                                                 label_selector="app=rook-discover")

        self.rook_pods = KubernetesResource(self.k8s.list_namespaced_pod,
                                            namespace=self.rook_env.namespace,
                                            label_selector="rook_cluster={0}".format(
                                                self.rook_env.cluster_name))
        self.nodes = KubernetesResource(self.k8s.list_node)

    def rook_url(self, path):
        prefix = "/apis/ceph.rook.io/%s/namespaces/%s/" % (
            self.rook_env.crd_version, self.rook_env.namespace)
        return urljoin(prefix, path)

    def rook_api_call(self, verb, path, **kwargs):
        full_path = self.rook_url(path)
        log.debug("[%s] %s" % (verb, full_path))

        return self.k8s.api_client.call_api(
            full_path,
            verb,
            auth_settings=['BearerToken'],
            response_type="object",
            _return_http_data_only=True,
            _preload_content=True,
            **kwargs)

    def rook_api_get(self, path, **kwargs):
        return self.rook_api_call("GET", path, **kwargs)

    def rook_api_delete(self, path):
        return self.rook_api_call("DELETE", path)

    def rook_api_patch(self, path, **kwargs):
        return self.rook_api_call("PATCH", path,
                                  header_params={"Content-Type": "application/json-patch+json"},
                                  **kwargs)

    def rook_api_post(self, path, **kwargs):
        return self.rook_api_call("POST", path, **kwargs)

    def get_discovered_devices(self, nodenames=None):
        def predicate(item):
            if nodenames is not None:
                return item.metadata.labels['rook.io/node'] in nodenames
            else:
                return True

        try:
            result = [i for i in self.inventory_maps.items if predicate(i)]
        except ApiException as e:
            log.exception("Failed to fetch device metadata")
            raise

        nodename_to_devices = {}
        for i in result:
            drives = json.loads(i.data['devices'])
            nodename_to_devices[i.metadata.labels['rook.io/node']] = drives

        return nodename_to_devices

    def get_nfs_conf_url(self, nfs_cluster, instance):
        #
        # Fetch cephnfs object for "nfs_cluster" and then return a rados://
        # URL for the instance within that cluster. If the fetch fails, just
        # return None.
        #
        try:
            ceph_nfs = self.rook_api_get("cephnfses/{0}".format(nfs_cluster))
        except ApiException as e:
            log.info("Unable to fetch cephnfs object: {}".format(e.status))
            return None

        pool = ceph_nfs['spec']['rados']['pool']
        namespace = ceph_nfs['spec']['rados'].get('namespace', None)

        if namespace == None:
            url = "rados://{0}/conf-{1}.{2}".format(pool, nfs_cluster, instance)
        else:
            url = "rados://{0}/{1}/conf-{2}.{3}".format(pool, namespace, nfs_cluster, instance)
        return url

    def describe_pods(self, service_type, service_id, nodename):
        """
        Go query the k8s API about deployment, containers related to this
        filesystem

        Example Rook Pod labels for a mgr daemon:
        Labels:         app=rook-ceph-mgr
                        pod-template-hash=2171958073
                        rook_cluster=rook
        And MDS containers additionally have `rook_filesystem` label

        Label filter is rook_cluster=<cluster name>
                        rook_file_system=<self.fs_name>
        """
        def predicate(item):
            # type: (V1Pod) -> bool
            metadata = item.metadata
            if service_type is not None:
                if metadata.labels['app'] != "rook-ceph-{0}".format(service_type):
                    return False

                if service_id is not None:
                    try:
                        k, v = {
                            "mds": ("rook_file_system", service_id),
                            "osd": ("ceph-osd-id", service_id),
                            "mon": ("mon", service_id),
                            "mgr": ("mgr", service_id),
                            "ceph_nfs": ("ceph_nfs", service_id),
                            "rgw": ("ceph_rgw", service_id),
                        }[service_type]
                    except KeyError:
                        raise orchestrator.OrchestratorValidationError(
                            '{} not supported'.format(service_type))
                    if metadata.labels[k] != v:
                        return False

            if nodename is not None:
                if item.spec.node_name != nodename:
                    return False
            return True

        pods = [i for i in self.rook_pods.items if predicate(i)]

        pods_summary = []

        for p in pods:
            d = p.to_dict()
            # p['metadata']['creationTimestamp']
            pods_summary.append({
                "name": d['metadata']['name'],
                "nodename": d['spec']['node_name'],
                "labels": d['metadata']['labels'],
                'phase': d['status']['phase']
            })

        return pods_summary

    def get_node_names(self):
        return [i.metadata.name for i in self.nodes.items]

    @contextmanager
    def ignore_409(self, what):
        try:
            yield
        except ApiException as e:
            if e.status == 409:
                # Idempotent, succeed.
                log.info("{} already exists".format(what))
            else:
                raise

    def add_filesystem(self, spec):
        # type: (orchestrator.ServiceSpec) -> None
        # TODO use spec.placement
        # TODO warn if spec.extended has entries we don't kow how
        #      to action.

        rook_fs = cfs.CephFilesystem(
            apiVersion=self.rook_env.api_name,
            metadata=dict(
                name=spec.name,
                namespace=self.rook_env.namespace,
            ),
            spec=cfs.Spec(
                metadataServer=cfs.MetadataServer(
                    activeCount=spec.count,
                    activeStandby=True
                )
            )
        )

        with self.ignore_409("CephFilesystem '{0}' already exists".format(spec.name)):
            self.rook_api_post("cephfilesystems/", body=rook_fs.to_json())

    def add_nfsgw(self, spec):
        # TODO use spec.placement
        # TODO warn if spec.extended has entries we don't kow how
        #      to action.

        rook_nfsgw = cnfs.CephNFS(
            apiVersion=self.rook_env.api_name,
            metadata=dict(
                name=spec.name,
                namespace=self.rook_env.namespace,
            ),
            spec=cnfs.Spec(
                rados=cnfs.Rados(
                    pool=spec.pool
                ),
                server=cnfs.Server(
                    active=spec.count
                )
            )
        )

        if spec.namespace:
            rook_nfsgw.spec.rados.namespace = spec.namespace

        with self.ignore_409("NFS cluster '{0}' already exists".format(spec.name)):
            self.rook_api_post("cephnfses/", body=rook_nfsgw.to_json())

    def add_objectstore(self, spec):

        rook_os = cos.CephObjectStore(
            apiVersion=self.rook_env.api_name,
            metadata=dict(
                name=spec.name,
                namespace=self.rook_env.namespace
            ),
            spec=cos.Spec(
                metadataPool=cos.MetadataPool(
                    failureDomain='host',
                    replicated=cos.Replicated(
                        size=1
                    )
                ),
                dataPool=cos.DataPool(
                    failureDomain='osd',
                    replicated=cos.Replicated(
                        size=1
                    )
                ),
                gateway=cos.Gateway(
                    type='s3',
                    port=spec.rgw_frontend_port if spec.rgw_frontend_port is not None else 80,
                    instances=spec.count
                )
            )
        )
        
        with self.ignore_409("CephObjectStore '{0}' already exists".format(spec.name)):
            self.rook_api_post("cephobjectstores/", body=rook_os.to_json())

    def rm_service(self, rooktype, service_id):

        objpath = "{0}/{1}".format(rooktype, service_id)

        try:
            self.rook_api_delete(objpath)
        except ApiException as e:
            if e.status == 404:
                log.info("{0} service '{1}' does not exist".format(rooktype, service_id))
                # Idempotent, succeed.
            else:
                raise

    def can_create_osd(self):
        current_cluster = self.rook_api_get(
            "cephclusters/{0}".format(self.rook_env.cluster_name))
        use_all_nodes = current_cluster['spec'].get('useAllNodes', False)

        # If useAllNodes is set, then Rook will not be paying attention
        # to anything we put in 'nodes', so can't do OSD creation.
        return not use_all_nodes

    def node_exists(self, node_name):
        return node_name in self.get_node_names()

    def update_mon_count(self, newcount):
        def _update_mon_count(current, new):
            # type: (ccl.CephCluster, ccl.CephCluster) -> ccl.CephCluster
            new.spec.mon.count = newcount
            return new
        return self._patch(ccl.CephCluster, 'cephclusters', self.rook_env.cluster_name, _update_mon_count)

    def update_mds_count(self, svc_id, newcount):
        def _update_nfs_count(current, new):
            # type: (cfs.CephFilesystem, cfs.CephFilesystem) -> cfs.CephFilesystem
            new.spec.metadataServer.activeCount = newcount
            return new
        return self._patch(cnfs.CephNFS, 'cephnfses', svc_id, _update_nfs_count)

    def update_nfs_count(self, svc_id, newcount):
        def _update_nfs_count(current, new):
            # type: (cnfs.CephNFS, cnfs.CephNFS) -> cnfs.CephNFS
            new.spec.server.active = newcount
            return new
        return self._patch(cnfs.CephNFS, 'cephnfses',svc_id, _update_nfs_count)

    def add_osds(self, drive_group, all_hosts):
        # type: (DriveGroupSpec, List[str]) -> str
        """
        Rook currently (0.8) can only do single-drive OSDs, so we
        treat all drive groups as just a list of individual OSDs.
        """
        block_devices = drive_group.data_devices.paths if drive_group.data_devices else []
        directories = drive_group.data_directories

        assert drive_group.objectstore in ("bluestore", "filestore")

        def _add_osds(current_cluster, new_cluster):
            # type: (ccl.CephCluster, ccl.CephCluster) -> ccl.CephCluster

            # FIXME: this is all not really atomic, because jsonpatch doesn't
            # let us do "test" operations that would check if items with
            # matching names were in existing lists.

            if not hasattr(new_cluster.spec.storage, 'nodes'):
                new_cluster.spec.storage.nodes = ccl.NodesList()

            current_nodes = getattr(current_cluster.spec.storage, 'nodes', ccl.NodesList())

            if drive_group.hosts(all_hosts)[0] not in [n.name for n in current_nodes]:
                pd = ccl.NodesItem(
                    name=drive_group.hosts(all_hosts)[0],
                    config=ccl.Config(
                        storeType=drive_group.objectstore
                    )
                )

                if block_devices:
                    pd.devices = ccl.DevicesList(
                        ccl.DevicesItem(name=d.path) for d in block_devices
                    )
                if directories:
                    pd.directories = ccl.DirectoriesList(
                        ccl.DirectoriesItem(path=p) for p in directories
                    )
                new_cluster.spec.storage.nodes.append(pd)
            else:
                for _node in new_cluster.spec.storage.nodes:
                    current_node = _node  # type: ccl.NodesItem
                    if current_node.name == drive_group.hosts(all_hosts)[0]:
                        if block_devices:
                            if not hasattr(current_node, 'devices'):
                                current_node.devices = ccl.DevicesList()
                            new_devices = list(set(block_devices) - set([d.name for d in current_node.devices]))
                            current_node.devices.extend(
                                ccl.DevicesItem(name=n.path) for n in new_devices
                            )

                        if directories:
                            if not hasattr(current_node, 'directories'):
                                current_node.directories = ccl.DirectoriesList()
                            new_dirs = list(set(directories) - set([d.path for d in current_node.directories]))
                            current_node.directories.extend(
                                ccl.DirectoriesItem(path=n) for n in new_dirs
                            )
            return new_cluster

        return self._patch(ccl.CephCluster, 'cephclusters', self.rook_env.cluster_name, _add_osds)

    def _patch(self, crd, crd_name, cr_name, func):
        current_json = self.rook_api_get(
            "{}/{}".format(crd_name, cr_name)
        )

        current = crd.from_json(current_json)
        new = crd.from_json(current_json)  # no deepcopy.

        new = func(current, new)

        patch = list(jsonpatch.make_patch(current_json, new.to_json()))

        log.info('patch for {}/{}: \n{}'.format(crd_name, cr_name, patch))

        if len(patch) == 0:
            return "No change"

        try:
            self.rook_api_patch(
                "{}/{}".format(crd_name, cr_name),
                body=patch)
        except ApiException as e:
            log.exception("API exception: {0}".format(e))
            raise ApplyException(
                "Failed to update {}/{}: {}".format(crd_name, cr_name, e))

        return "Success"
