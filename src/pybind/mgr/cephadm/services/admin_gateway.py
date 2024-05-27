import errno
import ipaddress
import logging
import os
import socket
from typing import List, Any, Tuple, Dict, Optional, cast
from urllib.parse import urlparse

from mgr_module import HandleCommandResult
from mgr_module import ServiceInfoT
from ceph.deployment.utils import wrap_ipv6
from mgr_util import build_url

from orchestrator import DaemonDescription
from ceph.deployment.service_spec import AdminGatewaySpec
from cephadm.services.cephadmservice import CephadmService, CephadmDaemonDeploySpec, get_dashboard_urls
from cephadm.ssl_cert_utils import SSLCerts

logger = logging.getLogger(__name__)


class AdminGatewayService(CephadmService):
    TYPE = 'admin-gateway'
    DEFAULT_SERVICE_PORT = 8447
    INTERNAL_SERVICE_PORT = 28447

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def get_service_endpoints(self, service_name):
        srv_entries = []
        for dd in self.mgr.cache.get_daemons_by_service(service_name):
            assert dd.hostname is not None
            addr = dd.ip if dd.ip else self.mgr.inventory.get_addr(dd.hostname)
            port = dd.ports[0] if dd.ports else AlertmanagerService.DEFAULT_SERVICE_PORT
            srv_entries.append(f'{addr}:{port}')
        return srv_entries

    def get_active_daemon(self, daemon_descrs: List[DaemonDescription]) -> DaemonDescription:
        if daemon_descrs:
            return daemon_descrs[0]
        # if empty list provided, return empty Daemon Desc
        return DaemonDescription()

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        dd = self.get_active_daemon(daemon_descrs)
        addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
        port = dd.ports[0] if dd.ports else AdminGatewayService.DEFAULT_SERVICE_PORT

        # Grafana has to be configured by using the 'external' URL
        admin_gw_external_ep = build_url(scheme='https', host=addr, port=port)
        self._set_value_on_dashboard(
            'Grafana',
            'dashboard get-grafana-api-url',
            'dashboard set-grafana-api-url',
            f'{admin_gw_external_ep}/grafana'
        )

        # configure prometheus
        admin_gw_internal_ep = build_url(scheme='https', host=addr, port=self.INTERNAL_SERVICE_PORT)
        self._set_value_on_dashboard(
            'Prometheus',
            'dashboard get-prometheus-api-host',
            'dashboard set-prometheus-api-host',
            f'{admin_gw_internal_ep}/internal/prometheus'
        )

        # configure alertmanager
        self._set_value_on_dashboard(
            'AlertManager',
            'dashboard get-alertmanager-api-host',
            'dashboard set-alertmanager-api-host',
            f'{admin_gw_internal_ep}/internal/alertmanager'
        )

        # Disable SSL verification on all the monitoring services
        # sicne we are using our own self-signed certificates

        self._set_value_on_dashboard(
            'Alertmanager',
            'dashboard get-alertmanager-api-ssl-verify',
            'dashboard set-alertmanager-api-ssl-verify',
            'false'
        )

        self._set_value_on_dashboard(
            'Prometheus',
            'dashboard get-prometheus-api-ssl-verify',
            'dashboard set-prometheus-api-ssl-verify',
            'false'
        )

        self._set_value_on_dashboard(
            'Grafana',
            'dashboard get-grafana-api-ssl-verify',
            'dashboard set-grafana-api-ssl-verify',
            'false'
        )

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:

        def read_certificate(spec_field):
            cert = ''
            if isinstance(spec_field, list):
                cert = '\n'.join(spec_field)
            elif isinstance(spec_field, str):
                cert = spec_field
            return cert

        spec = cast(AdminGatewaySpec, self.mgr.spec_store[daemon_spec.service_name].spec)
        assert self.TYPE == daemon_spec.daemon_type
        deps: List[str] = []

        # url_prefix for the following services depends on the presence of admin-gateway
        deps += [d.name() for d in self.mgr.cache.get_daemons_by_service('prometheus')]
        deps += [d.name() for d in self.mgr.cache.get_daemons_by_service('alertmanager')]
        deps += [d.name() for d in self.mgr.cache.get_daemons_by_service('grafana')]
        for dd in self.mgr.cache.get_daemons_by_service('mgr'):
            # we consider mgr a dep even if the dashboard is disabled
            # in order to be consistent with _calc_daemon_deps().
            deps.append(dd.name())

        scheme = 'https' if self.mgr.secure_monitoring_stack else 'http'
        context = {
            'spec': spec,
            'internal_port': self.INTERNAL_SERVICE_PORT,
            'grafana_scheme': 'https', # TODO(redo): fixme, get current value of grafana scheme
            'prometheus_scheme': scheme,
            'alertmanager_scheme': scheme,
            'dashboard_urls': get_dashboard_urls(self),
            'prometheus_eps': self.get_service_endpoints('prometheus'),
            'alertmanager_eps': self.get_service_endpoints('alertmanager'),
            'grafana_eps': self.get_service_endpoints('grafana')
        }
        conf = self.mgr.template.render('services/admin-gateway/nginx.conf.j2', context)

        if spec.disable_https:
            return {
                "files": {
                    "nginx.conf": conf,
                }
            }, sorted(deps)
        else:
            self.ssl_certs = SSLCerts()
            self.ssl_certs.generate_root_cert(self.mgr.get_mgr_ip())
            node_ip = self.mgr.inventory.get_addr(daemon_spec.host)
            host_fqdn = self._inventory_get_fqdn(daemon_spec.host)
            internal_cert, internal_pkey = self.ssl_certs.generate_cert(host_fqdn, node_ip)
            cert = read_certificate(spec.ssl_certificate)
            pkey = read_certificate(spec.ssl_certificate_key)
            if not (cert and pkey):
                # In case the user has not provided certificates then we generate self-signed ones
                cert, pkey = self.ssl_certs.generate_cert(host_fqdn, node_ip)
            return {
                "files": {
                    "nginx.conf": conf,
                    "nginx.crt": cert,
                    "nginx.key": pkey,
                    "nginx_internal.crt": internal_cert,
                    "nginx_internal.key": internal_pkey
                }
            }, sorted(deps)

    def pre_remove(self, daemon: DaemonDescription) -> None:
        """
        Called before grafana daemon is removed.
        """
        # TODO(redo): should we delete user certificates?
