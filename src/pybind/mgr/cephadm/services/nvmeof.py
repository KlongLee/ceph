import errno
import logging
import json
from typing import List, cast, Optional
from ipaddress import ip_address, IPv6Address

from mgr_module import HandleCommandResult
from ceph.deployment.service_spec import NvmeofServiceSpec

from orchestrator import OrchestratorError, DaemonDescription, DaemonDescriptionStatus
from .cephadmservice import CephadmDaemonDeploySpec, CephService
from .. import utils

logger = logging.getLogger(__name__)


class NvmeofService(CephService):
    TYPE = 'nvmeof'
    PROMETHEUS_PORT = 10008

    def config(self, spec: NvmeofServiceSpec) -> None:  # type: ignore
        assert self.TYPE == spec.service_type
        if not spec.pool:
            raise OrchestratorError("pool should be in the spec")
        self.pool = spec.pool
        if spec.group is None:
            raise OrchestratorError("group should be in the spec")
        self.group = spec.group
        self.mgr._check_pool_exists(spec.pool, spec.service_name())

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type

        spec = cast(NvmeofServiceSpec, self.mgr.spec_store[daemon_spec.service_name].spec)
        nvmeof_gw_id = daemon_spec.daemon_id
        host_ip = self.mgr.inventory.get_addr(daemon_spec.host)

        keyring = self.get_keyring_with_caps(self.get_auth_entity(nvmeof_gw_id),
                                             ['mon', 'profile rbd',
                                              'osd', 'profile rbd'])

        # TODO: check if we can force jinja2 to generate dicts with double quotes instead of using json.dumps
        transport_tcp_options = json.dumps(spec.transport_tcp_options) if spec.transport_tcp_options else None
        name = '{}.{}'.format(utils.name_to_config_section('nvmeof'), nvmeof_gw_id)
        rados_id = name[len('client.'):] if name.startswith('client.') else name
        context = {
            'spec': spec,
            'name': name,
            'addr': host_ip,
            'port': spec.port,
            'spdk_log_level': 'WARNING',
            'rpc_socket_dir': '/var/tmp/',
            'rpc_socket_name': 'spdk.sock',
            'transport_tcp_options': transport_tcp_options,
            'rados_id': rados_id
        }
        gw_conf = self.mgr.template.render('services/nvmeof/ceph-nvmeof.conf.j2', context)

        daemon_spec.keyring = keyring
        daemon_spec.extra_files = {'ceph-nvmeof.conf': gw_conf}

        if spec.enable_auth:
            if (
                not spec.client_cert
                or not spec.client_key
                or not spec.server_cert
                or not spec.server_key
                or not spec.root_ca_cert
            ):
                err_msg = 'enable_auth is true but '
                for cert_key_attr in ['server_key', 'server_cert', 'client_key', 'client_cert', 'root_ca_cert']:
                    if not hasattr(spec, cert_key_attr):
                        err_msg += f'{cert_key_attr}, '
                err_msg += 'attribute(s) missing from nvmeof spec'
                self.mgr.log.error(err_msg)
            else:
                daemon_spec.extra_files['server_cert'] = spec.server_cert
                daemon_spec.extra_files['client_cert'] = spec.client_cert
                daemon_spec.extra_files['server_key'] = spec.server_key
                daemon_spec.extra_files['client_key'] = spec.client_key
                daemon_spec.extra_files['root_ca_cert'] = spec.root_ca_cert

        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        daemon_spec.deps = []
        if not hasattr(self, 'gws'):
            self.gws = {} # id -> name map of gateways for this service.
        self.gws[nvmeof_gw_id] = name # add to map of service's gateway names
        return daemon_spec

    def daemon_check_post(self, daemon_descrs: List[DaemonDescription]) -> None:
        """ Overrides the daemon_check_post to add nvmeof gateways safely
        """
        self.mgr.log.info(f"nvmeof daemon_check_post {daemon_descrs}")
        # Assert configured
        if not self.pool or self.group is None:
            self.mgr.log.error(f"nvmeof daemon_check_post: invalid pool {self.pool} or group {self.group}")
        if not hasattr(self, 'pool'):
            err_msg = ('Trying to daemon_check_post nvmeof but no pool is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        if not hasattr(self, 'group') or self.group is None:
            err_msg = ('Trying to daemon_check_post nvmeof but no group is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        for dd in daemon_descrs:
            self.mgr.log.info(f"nvmeof daemon_descr {dd}")
            if dd.daemon_id not in self.gws:
                err_msg = ('Trying to daemon_check_post nvmeof but daemon_id is unknown')
                logger.error(err_msg)
                raise OrchestratorError(err_msg)
            name = self.gws[dd.daemon_id]
            self.mgr.log.info(f"nvmeof daemon name={name}")
            # Notify monitor about this gateway creation
            cmd = {
                'prefix': 'nvme-gw create',
                'id': name,
                'group': self.group,
                'pool': self.pool
            }
            self.mgr.log.info(f"create gateway: monitor command {cmd}")
            _, _, err = self.mgr.mon_command(cmd)
            if err:
                err_msg = (f"Unable to send monitor command {cmd}, error {err}")
                logger.error(err_msg)
                raise OrchestratorError(err_msg)
        super().daemon_check_post(daemon_descrs)

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        def get_set_cmd_dicts(out: str) -> List[dict]:
            gateways = json.loads(out)['gateways']
            cmd_dicts = []

            spec = cast(NvmeofServiceSpec,
                        self.mgr.spec_store.all_specs.get(daemon_descrs[0].service_name(), None))

            for dd in daemon_descrs:
                service_name = dd.service_name()
                if dd.hostname is None:
                    err_msg = ('Trying to config_dashboard nvmeof but no hostname is defined')
                    logger.error(err_msg)
                    raise OrchestratorError(err_msg)

                if not spec:
                    logger.warning(f'No ServiceSpec found for {service_name}')
                    continue

                ip = utils.resolve_ip(self.mgr.inventory.get_addr(dd.hostname))
                if type(ip_address(ip)) is IPv6Address:
                    ip = f'[{ip}]'
                service_url = '{}:{}'.format(ip, spec.port or '5500')
                gw = gateways.get(dd.hostname)
                if not gw or gw['service_url'] != service_url:
                    logger.info(f'Adding NVMeoF gateway {service_url} to Dashboard')
                    cmd_dicts.append({
                        'prefix': 'dashboard nvmeof-gateway-add',
                        'inbuf': service_url,
                        'name': service_name
                    })
            return cmd_dicts

        self._check_and_set_dashboard(
            service_name='nvmeof',
            get_cmd='dashboard nvmeof-gateway-list',
            get_set_cmd_dicts=get_set_cmd_dicts
        )

    def ok_to_stop(self,
                   daemon_ids: List[str],
                   force: bool = False,
                   known: Optional[List[str]] = None) -> HandleCommandResult:
        # if only 1 nvmeof, alert user (this is not passable with --force)
        warn, warn_message = self._enough_daemons_to_stop(self.TYPE, daemon_ids, 'Nvmeof', 1, True)
        if warn:
            return HandleCommandResult(-errno.EBUSY, '', warn_message)

        # if reached here, there is > 1 nvmeof daemon. make sure none are down
        warn_message = ('ALERT: 1 nvmeof daemon is already down. Please bring it back up before stopping this one')
        nvmeof_daemons = self.mgr.cache.get_daemons_by_type(self.TYPE)
        for i in nvmeof_daemons:
            if i.status != DaemonDescriptionStatus.running:
                return HandleCommandResult(-errno.EBUSY, '', warn_message)

        names = [f'{self.TYPE}.{d_id}' for d_id in daemon_ids]
        warn_message = f'It is presumed safe to stop {names}'
        return HandleCommandResult(0, warn_message, '')

    def post_remove(self, daemon: DaemonDescription, is_failed_deploy: bool) -> None:
        """
        Called after the daemon is removed.
        """
        # to clean the keyring up
        super().post_remove(daemon, is_failed_deploy=is_failed_deploy)
        service_name = daemon.service_name()

        # remove config for dashboard nvmeof gateways if any
        ret, out, err = self.mgr.mon_command({
            'prefix': 'dashboard nvmeof-gateway-rm',
            'name': service_name,
        })
        if not ret:
            logger.info(f'{daemon.hostname} removed from nvmeof gateways dashboard config')

        # Assert configured
        if not hasattr(self, 'pool'):
            err_msg = ('Trying to remove nvmeof but no pool is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        if not hasattr(self, 'group') or self.group is None:
            err_msg = ('Trying to remove nvmeof but no group is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        if daemon.daemon_id not in self.gws:
            err_msg = (f'Trying to remove nvmeof but {daemon.daemon_id} '
                       'not in gws list')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        name = self.gws[daemon.daemon_id]
        self.gws.pop(daemon.daemon_id)
        # Notify monitor about this gateway deletion
        cmd = {
            'prefix': 'nvme-gw delete',
            'id': name,
            'group': self.group,
            'pool': self.pool
        }
        self.mgr.log.info(f"delete gateway: monitor command {cmd}")
        _, _, err = self.mgr.mon_command(cmd)
        if err:
            self.mgr.log.error(f"Unable to send monitor command {cmd}, error {err}")

    def purge(self, service_name: str) -> None:
        """Make sure no zombie gateway is left behind
        """
        # Assert configured
        if not hasattr(self, 'pool'):
            err_msg = ('Trying to purge nvmeof but no pool is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        if not hasattr(self, 'group') or self.group is None:
            err_msg = ('Trying to purge nvmeof but no group is defined')
            logger.error(err_msg)
            raise OrchestratorError(err_msg)
        for daemon_id in self.gws:
            name = self.gws[daemon_id]
            self.gws.pop(daemon_id)
            # Notify monitor about this gateway deletion
            cmd = {
                'prefix': 'nvme-gw delete',
                'id': name,
                'group': self.group,
                'pool': self.pool
            }
            self.mgr.log.info(f"purge delete gateway: monitor command {cmd}")
            _, _, err = self.mgr.mon_command(cmd)
            if err:
                err_msg = (f"Unable to send monitor command {cmd}, error {err}")
                logger.error(err_msg)
                raise OrchestratorError(err_msg)
