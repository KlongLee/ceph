import errno
import logging
from typing import List, cast, Optional

from mgr_module import HandleCommandResult
from ceph.deployment.service_spec import NvmeofServiceSpec

from orchestrator import DaemonDescription, DaemonDescriptionStatus
from .cephadmservice import CephadmDaemonDeploySpec, CephService
from .. import utils

logger = logging.getLogger(__name__)


class NvmeofService(CephService):
    TYPE = 'nvmeof'

    def config(self, spec: NvmeofServiceSpec) -> None:  # type: ignore
        assert self.TYPE == spec.service_type
        assert spec.pool
        self.mgr._check_pool_exists(spec.pool, spec.service_name())

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type

        spec = cast(NvmeofServiceSpec, self.mgr.spec_store[daemon_spec.service_name].spec)
        igw_id = daemon_spec.daemon_id

        # TODO: fixme, we should restrict the permissions here to only the necessary ones
        keyring = self.get_keyring_with_caps(self.get_auth_entity(igw_id),
                                             ['mon', 'allow *',
                                              'mds', 'allow *',
                                              'mgr', 'allow *',
                                              'osd', 'allow *'])
        context = {
            'spec': spec,
            'name': '{}.{}'.format(utils.name_to_config_section('nvmeof'), igw_id),
            'addr': self.mgr.get_mgr_ip(),
            'port': spec.port,
            'tgt_cmd_extra_args': None,
            'log_level': 'WARN',
            'rpc_socket': '/var/tmp/spdk.sock',
        }
        gw_conf = self.mgr.template.render('services/nvmeof/ceph-nvmeof.conf.j2', context)

        daemon_spec.keyring = keyring
        daemon_spec.extra_files = {'ceph-nvmeof.conf': gw_conf}
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        daemon_spec.deps = []
        return daemon_spec

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        # TODO: what integration do we need with the dashboard?
        pass

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
        logger.debug(f'Post remove daemon {self.TYPE}.{daemon.daemon_id}')
        # TODO: remove config for dashboard nvmeof gateways if any
        # and any certificates being used for mTLS

    def purge(self, service_name: str) -> None:
        """Removes configuration
        """
        #  TODO: what should we purge in this case (if any)?
        pass
