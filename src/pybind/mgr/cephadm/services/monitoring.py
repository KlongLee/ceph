import errno
import ipaddress
import logging
import os
import socket
from typing import List, Any, Tuple, Dict, Optional, cast
from urllib.parse import urlparse

from mgr_module import HandleCommandResult

from orchestrator import DaemonDescription
from ceph.deployment.service_spec import AlertManagerSpec, GrafanaSpec, ServiceSpec, SNMPGatewaySpec
from cephadm.services.cephadmservice import CephadmService, CephadmDaemonDeploySpec
from cephadm.services.ingress import IngressSpec
from mgr_util import verify_tls, ServerConfigException, create_self_signed_cert, build_url

logger = logging.getLogger(__name__)


class GrafanaService(CephadmService):
    TYPE = 'grafana'
    DEFAULT_SERVICE_PORT = 3000

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps = []  # type: List[str]

        prom_services = []  # type: List[str]
        for dd in self.mgr.cache.get_daemons_by_service('prometheus'):
            assert dd.hostname is not None
            addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
            port = dd.ports[0] if dd.ports else 9095
            prom_services.append(build_url(scheme='http', host=addr, port=port))

            deps.append(dd.name())

        daemons = self.mgr.cache.get_daemons_by_service('loki')
        loki_host = ''
        for i, dd in enumerate(daemons):
            assert dd.hostname is not None
            if i == 0:
                addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
                loki_host = build_url(scheme='http', host=addr, port=3100)

            deps.append(dd.name())

        grafana_data_sources = self.mgr.template.render(
            'services/grafana/ceph-dashboard.yml.j2', {'hosts': prom_services, 'loki_host': loki_host})

        cert = self.mgr.get_store('grafana_crt')
        pkey = self.mgr.get_store('grafana_key')
        if cert and pkey:
            try:
                verify_tls(cert, pkey)
            except ServerConfigException as e:
                logger.warning('Provided grafana TLS certificates invalid: %s', str(e))
                cert, pkey = None, None
        if not (cert and pkey):
            cert, pkey = create_self_signed_cert('Ceph', 'cephadm')
            self.mgr.set_store('grafana_crt', cert)
            self.mgr.set_store('grafana_key', pkey)
            if 'dashboard' in self.mgr.get('mgr_map')['modules']:
                self.mgr.check_mon_command({
                    'prefix': 'dashboard set-grafana-api-ssl-verify',
                    'value': 'false',
                })

        spec: GrafanaSpec = cast(
            GrafanaSpec, self.mgr.spec_store.active_specs[daemon_spec.service_name])
        grafana_ini = self.mgr.template.render(
            'services/grafana/grafana.ini.j2', {
                'initial_admin_password': spec.initial_admin_password,
                'http_port': daemon_spec.ports[0] if daemon_spec.ports else self.DEFAULT_SERVICE_PORT,
                'http_addr': daemon_spec.ip if daemon_spec.ip else ''
            })

        config_file = {
            'files': {
                "grafana.ini": grafana_ini,
                'provisioning/datasources/ceph-dashboard.yml': grafana_data_sources,
                'certs/cert_file': '# generated by cephadm\n%s' % cert,
                'certs/cert_key': '# generated by cephadm\n%s' % pkey,
            }
        }
        return config_file, sorted(deps)

    def get_active_daemon(self, daemon_descrs: List[DaemonDescription]) -> DaemonDescription:
        # Use the least-created one as the active daemon
        if daemon_descrs:
            return daemon_descrs[-1]
        # if empty list provided, return empty Daemon Desc
        return DaemonDescription()

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        # TODO: signed cert
        dd = self.get_active_daemon(daemon_descrs)
        assert dd.hostname is not None
        addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
        port = dd.ports[0] if dd.ports else self.DEFAULT_SERVICE_PORT
        service_url = build_url(scheme='https', host=addr, port=port)
        self._set_service_url_on_dashboard(
            'Grafana',
            'dashboard get-grafana-api-url',
            'dashboard set-grafana-api-url',
            service_url
        )

    def ok_to_stop(self,
                   daemon_ids: List[str],
                   force: bool = False,
                   known: Optional[List[str]] = None) -> HandleCommandResult:
        warn, warn_message = self._enough_daemons_to_stop(self.TYPE, daemon_ids, 'Grafana', 1)
        if warn and not force:
            return HandleCommandResult(-errno.EBUSY, '', warn_message)
        return HandleCommandResult(0, warn_message, '')


class AlertmanagerService(CephadmService):
    TYPE = 'alertmanager'
    DEFAULT_SERVICE_PORT = 9093

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps: List[str] = []
        default_webhook_urls: List[str] = []

        spec = cast(AlertManagerSpec, self.mgr.spec_store[daemon_spec.service_name].spec)
        try:
            secure = spec.secure
        except AttributeError:
            secure = False
        user_data = spec.user_data
        if 'default_webhook_urls' in user_data and isinstance(
                user_data['default_webhook_urls'], list):
            default_webhook_urls.extend(user_data['default_webhook_urls'])

        # dashboard(s)
        dashboard_urls: List[str] = []
        snmp_gateway_urls: List[str] = []
        mgr_map = self.mgr.get('mgr_map')
        port = None
        proto = None  # http: or https:
        url = mgr_map.get('services', {}).get('dashboard', None)
        if url:
            p_result = urlparse(url.rstrip('/'))
            hostname = socket.getfqdn(p_result.hostname)

            try:
                ip = ipaddress.ip_address(hostname)
            except ValueError:
                pass
            else:
                if ip.version == 6:
                    hostname = f'[{hostname}]'

            dashboard_urls.append(
                f'{p_result.scheme}://{hostname}:{p_result.port}{p_result.path}')
            proto = p_result.scheme
            port = p_result.port
        # scan all mgrs to generate deps and to get standbys too.
        # assume that they are all on the same port as the active mgr.
        for dd in self.mgr.cache.get_daemons_by_service('mgr'):
            # we consider mgr a dep even if the dashboard is disabled
            # in order to be consistent with _calc_daemon_deps().
            deps.append(dd.name())
            if not port:
                continue
            if dd.daemon_id == self.mgr.get_mgr_id():
                continue
            assert dd.hostname is not None
            addr = self._inventory_get_fqdn(dd.hostname)
            dashboard_urls.append(build_url(scheme=proto, host=addr, port=port).rstrip('/'))

        for dd in self.mgr.cache.get_daemons_by_service('snmp-gateway'):
            assert dd.hostname is not None
            assert dd.ports
            addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
            deps.append(dd.name())

            snmp_gateway_urls.append(build_url(scheme='http', host=addr,
                                     port=dd.ports[0], path='/alerts'))

        context = {
            'dashboard_urls': dashboard_urls,
            'default_webhook_urls': default_webhook_urls,
            'snmp_gateway_urls': snmp_gateway_urls,
            'secure': secure,
        }
        yml = self.mgr.template.render('services/alertmanager/alertmanager.yml.j2', context)

        peers = []
        port = 9094
        for dd in self.mgr.cache.get_daemons_by_service('alertmanager'):
            assert dd.hostname is not None
            deps.append(dd.name())
            addr = self._inventory_get_fqdn(dd.hostname)
            peers.append(build_url(host=addr, port=port).lstrip('/'))

        return {
            "files": {
                "alertmanager.yml": yml
            },
            "peers": peers
        }, sorted(deps)

    def get_active_daemon(self, daemon_descrs: List[DaemonDescription]) -> DaemonDescription:
        # TODO: if there are multiple daemons, who is the active one?
        if daemon_descrs:
            return daemon_descrs[0]
        # if empty list provided, return empty Daemon Desc
        return DaemonDescription()

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        dd = self.get_active_daemon(daemon_descrs)
        assert dd.hostname is not None
        addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
        port = dd.ports[0] if dd.ports else self.DEFAULT_SERVICE_PORT
        service_url = build_url(scheme='http', host=addr, port=port)
        self._set_service_url_on_dashboard(
            'AlertManager',
            'dashboard get-alertmanager-api-host',
            'dashboard set-alertmanager-api-host',
            service_url
        )

    def ok_to_stop(self,
                   daemon_ids: List[str],
                   force: bool = False,
                   known: Optional[List[str]] = None) -> HandleCommandResult:
        warn, warn_message = self._enough_daemons_to_stop(self.TYPE, daemon_ids, 'Alertmanager', 1)
        if warn and not force:
            return HandleCommandResult(-errno.EBUSY, '', warn_message)
        return HandleCommandResult(0, warn_message, '')


class PrometheusService(CephadmService):
    TYPE = 'prometheus'
    DEFAULT_SERVICE_PORT = 9095
    DEFAULT_MGR_PROMETHEUS_PORT = 9283

    def config(self, spec: ServiceSpec) -> None:
        # make sure module is enabled
        mgr_map = self.mgr.get('mgr_map')
        if 'prometheus' not in mgr_map.get('services', {}):
            self.mgr.check_mon_command({
                'prefix': 'mgr module enable',
                'module': 'prometheus'
            })
            # we shouldn't get here (mon will tell the mgr to respawn), but no
            # harm done if we do.

    def prepare_create(
            self,
            daemon_spec: CephadmDaemonDeploySpec,
    ) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(
            self,
            daemon_spec: CephadmDaemonDeploySpec,
    ) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps = []  # type: List[str]

        # scrape mgrs
        mgr_scrape_list = []
        mgr_map = self.mgr.get('mgr_map')
        port = cast(int, self.mgr.get_module_option_ex(
            'prometheus', 'server_port', self.DEFAULT_MGR_PROMETHEUS_PORT))
        deps.append(str(port))
        t = mgr_map.get('services', {}).get('prometheus', None)
        if t:
            p_result = urlparse(t)
            # urlparse .hostname removes '[]' from the hostname in case
            # of ipv6 addresses so if this is the case then we just
            # append the brackets when building the final scrape endpoint
            if '[' in p_result.netloc and ']' in p_result.netloc:
                mgr_scrape_list.append(f"[{p_result.hostname}]:{port}")
            else:
                mgr_scrape_list.append(f"{p_result.hostname}:{port}")
        # scan all mgrs to generate deps and to get standbys too.
        # assume that they are all on the same port as the active mgr.
        for dd in self.mgr.cache.get_daemons_by_service('mgr'):
            # we consider the mgr a dep even if the prometheus module is
            # disabled in order to be consistent with _calc_daemon_deps().
            deps.append(dd.name())
            if not port:
                continue
            if dd.daemon_id == self.mgr.get_mgr_id():
                continue
            assert dd.hostname is not None
            addr = self._inventory_get_fqdn(dd.hostname)
            mgr_scrape_list.append(build_url(host=addr, port=port).lstrip('/'))

        # scrape node exporters
        nodes = []
        for dd in self.mgr.cache.get_daemons_by_service('node-exporter'):
            assert dd.hostname is not None
            deps.append(dd.name())
            addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
            port = dd.ports[0] if dd.ports else 9100
            nodes.append({
                'hostname': dd.hostname,
                'url': build_url(host=addr, port=port).lstrip('/')
            })

        # scrape alert managers
        alertmgr_targets = []
        for dd in self.mgr.cache.get_daemons_by_service('alertmanager'):
            assert dd.hostname is not None
            deps.append(dd.name())
            addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
            port = dd.ports[0] if dd.ports else 9093
            alertmgr_targets.append("'{}'".format(build_url(host=addr, port=port).lstrip('/')))

        # scrape haproxies
        haproxy_targets = []
        for dd in self.mgr.cache.get_daemons_by_type('ingress'):
            if dd.service_name() in self.mgr.spec_store:
                spec = cast(IngressSpec, self.mgr.spec_store[dd.service_name()].spec)
                assert dd.hostname is not None
                deps.append(dd.name())
                if dd.daemon_type == 'haproxy':
                    addr = self._inventory_get_fqdn(dd.hostname)
                    haproxy_targets.append({
                        "url": f"'{build_url(host=addr, port=spec.monitor_port).lstrip('/')}'",
                        "service": dd.service_name(),
                    })

        # generate the prometheus configuration
        context = {
            'alertmgr_targets': alertmgr_targets,
            'mgr_scrape_list': mgr_scrape_list,
            'haproxy_targets': haproxy_targets,
            'nodes': nodes,
        }
        r = {
            'files': {
                'prometheus.yml':
                    self.mgr.template.render(
                        'services/prometheus/prometheus.yml.j2', context)
            }
        }

        # include alerts, if present in the container
        if os.path.exists(self.mgr.prometheus_alerts_path):
            with open(self.mgr.prometheus_alerts_path, 'r', encoding='utf-8') as f:
                alerts = f.read()
            r['files']['/etc/prometheus/alerting/ceph_alerts.yml'] = alerts

        return r, sorted(deps)

    def get_active_daemon(self, daemon_descrs: List[DaemonDescription]) -> DaemonDescription:
        # TODO: if there are multiple daemons, who is the active one?
        if daemon_descrs:
            return daemon_descrs[0]
        # if empty list provided, return empty Daemon Desc
        return DaemonDescription()

    def config_dashboard(self, daemon_descrs: List[DaemonDescription]) -> None:
        dd = self.get_active_daemon(daemon_descrs)
        assert dd.hostname is not None
        addr = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)
        port = dd.ports[0] if dd.ports else self.DEFAULT_SERVICE_PORT
        service_url = build_url(scheme='http', host=addr, port=port)
        self._set_service_url_on_dashboard(
            'Prometheus',
            'dashboard get-prometheus-api-host',
            'dashboard set-prometheus-api-host',
            service_url
        )

    def ok_to_stop(self,
                   daemon_ids: List[str],
                   force: bool = False,
                   known: Optional[List[str]] = None) -> HandleCommandResult:
        warn, warn_message = self._enough_daemons_to_stop(self.TYPE, daemon_ids, 'Prometheus', 1)
        if warn and not force:
            return HandleCommandResult(-errno.EBUSY, '', warn_message)
        return HandleCommandResult(0, warn_message, '')


class NodeExporterService(CephadmService):
    TYPE = 'node-exporter'

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        return {}, []

    def ok_to_stop(self,
                   daemon_ids: List[str],
                   force: bool = False,
                   known: Optional[List[str]] = None) -> HandleCommandResult:
        # since node exporter runs on each host and cannot compromise data, no extra checks required
        names = [f'{self.TYPE}.{d_id}' for d_id in daemon_ids]
        out = f'It is presumed safe to stop {names}'
        return HandleCommandResult(0, out, '')


class LokiService(CephadmService):
    TYPE = 'loki'
    DEFAULT_SERVICE_PORT = 3100

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps: List[str] = []

        yml = self.mgr.template.render('services/loki.yml.j2')
        return {
            "files": {
                "loki.yml": yml
            }
        }, sorted(deps)


class PromtailService(CephadmService):
    TYPE = 'promtail'
    DEFAULT_SERVICE_PORT = 9080

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps: List[str] = []

        daemons = self.mgr.cache.get_daemons_by_service('loki')
        loki_host = ''
        for i, dd in enumerate(daemons):
            assert dd.hostname is not None
            if i == 0:
                loki_host = dd.ip if dd.ip else self._inventory_get_fqdn(dd.hostname)

            deps.append(dd.name())

        context = {
            'client_hostname': loki_host,
        }

        yml = self.mgr.template.render('services/promtail.yml.j2', context)
        return {
            "files": {
                "promtail.yml": yml
            }
        }, sorted(deps)


class SNMPGatewayService(CephadmService):
    TYPE = 'snmp-gateway'

    def prepare_create(self, daemon_spec: CephadmDaemonDeploySpec) -> CephadmDaemonDeploySpec:
        assert self.TYPE == daemon_spec.daemon_type
        daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
        return daemon_spec

    def generate_config(self, daemon_spec: CephadmDaemonDeploySpec) -> Tuple[Dict[str, Any], List[str]]:
        assert self.TYPE == daemon_spec.daemon_type
        deps: List[str] = []

        spec = cast(SNMPGatewaySpec, self.mgr.spec_store[daemon_spec.service_name].spec)
        config = {
            "destination": spec.snmp_destination,
            "snmp_version": spec.snmp_version,
        }
        if spec.snmp_version == 'V2c':
            community = spec.credentials.get('snmp_community', None)
            assert community is not None

            config.update({
                "snmp_community": community
            })
        else:
            # SNMP v3 settings can be either authNoPriv or authPriv
            auth_protocol = 'SHA' if not spec.auth_protocol else spec.auth_protocol

            auth_username = spec.credentials.get('snmp_v3_auth_username', None)
            auth_password = spec.credentials.get('snmp_v3_auth_password', None)
            assert auth_username is not None
            assert auth_password is not None
            assert spec.engine_id is not None

            config.update({
                "snmp_v3_auth_protocol": auth_protocol,
                "snmp_v3_auth_username": auth_username,
                "snmp_v3_auth_password": auth_password,
                "snmp_v3_engine_id": spec.engine_id,
            })
            # authPriv adds encryption
            if spec.privacy_protocol:
                priv_password = spec.credentials.get('snmp_v3_priv_password', None)
                assert priv_password is not None

                config.update({
                    "snmp_v3_priv_protocol": spec.privacy_protocol,
                    "snmp_v3_priv_password": priv_password,
                })

        logger.debug(
            f"Generated configuration for '{self.TYPE}' service. Dependencies={deps}")

        return config, sorted(deps)
