import datetime
import json
import logging
from collections import defaultdict
from contextlib import contextmanager
from typing import TYPE_CHECKING, Optional, List, Callable, cast, Set, Dict, Any, Union, Tuple, Iterator

from cephadm import remotes

try:
    import remoto
    import execnet.gateway_bootstrap
except ImportError:
    remoto = None

from ceph.deployment import inventory
from ceph.deployment.drive_group import DriveGroupSpec
from ceph.deployment.service_spec import ServiceSpec, HostPlacementSpec, RGWSpec, \
    HA_RGWSpec, CustomContainerSpec
from ceph.utils import str_to_datetime, datetime_now

import orchestrator
from orchestrator import OrchestratorError, set_exception_subject, OrchestratorEvent
from cephadm.services.cephadmservice import CephadmDaemonSpec
from cephadm.schedule import HostAssignment
from cephadm.utils import forall_hosts, cephadmNoImage, is_repo_digest, \
    CephadmNoImage, CEPH_UPGRADE_ORDER, ContainerInspectInfo
from orchestrator._interface import daemon_type_to_service, service_to_daemon_types

if TYPE_CHECKING:
    from cephadm.module import CephadmOrchestrator
    from remoto.backends import BaseConnection

logger = logging.getLogger(__name__)

CEPH_TYPES = set(CEPH_UPGRADE_ORDER)


class CephadmServe:
    """
    This module contains functions that are executed in the
    serve() thread. Thus they don't block the CLI.

    Please see the `Note regarding network calls from CLI handlers`
    chapter in the cephadm developer guide.

    On the other hand, These function should *not* be called form
    CLI handlers, to avoid blocking the CLI
    """

    def __init__(self, mgr: "CephadmOrchestrator"):
        self.mgr: "CephadmOrchestrator" = mgr
        self.log = logger

    def serve(self) -> None:
        """
        The main loop of cephadm.

        A command handler will typically change the declarative state
        of cephadm. This loop will then attempt to apply this new state.
        """
        self.log.debug("serve starting")
        while self.mgr.run:

            try:

                self.convert_tags_to_repo_digest()

                # refresh daemons
                self.log.debug('refreshing hosts and daemons')
                self._refresh_hosts_and_daemons()

                self._check_for_strays()

                self._update_paused_health()

                if not self.mgr.paused:
                    self.mgr.to_remove_osds.process_removal_queue()

                    self.mgr.migration.migrate()
                    if self.mgr.migration.is_migration_ongoing():
                        continue

                    if self._apply_all_services():
                        continue  # did something, refresh

                    self._check_daemons()

                    if self.mgr.upgrade.continue_upgrade():
                        continue

            except OrchestratorError as e:
                if e.event_subject:
                    self.mgr.events.from_orch_error(e)

            self._serve_sleep()
        self.log.debug("serve exit")

    def _serve_sleep(self) -> None:
        sleep_interval = 600
        self.log.debug('Sleeping for %d seconds', sleep_interval)
        ret = self.mgr.event.wait(sleep_interval)
        self.mgr.event.clear()

    def _update_paused_health(self) -> None:
        if self.mgr.paused:
            self.mgr.health_checks['CEPHADM_PAUSED'] = {
                'severity': 'warning',
                'summary': 'cephadm background work is paused',
                'count': 1,
                'detail': ["'ceph orch resume' to resume"],
            }
            self.mgr.set_health_checks(self.mgr.health_checks)
        else:
            if 'CEPHADM_PAUSED' in self.mgr.health_checks:
                del self.mgr.health_checks['CEPHADM_PAUSED']
                self.mgr.set_health_checks(self.mgr.health_checks)

    def _refresh_hosts_and_daemons(self) -> None:
        bad_hosts = []
        failures = []

        @forall_hosts
        def refresh(host: str) -> None:

            # skip hosts that are in maintenance - they could be powered off
            if self.mgr.inventory._inventory[host].get("status", "").lower() == "maintenance":
                return

            if self.mgr.cache.host_needs_check(host):
                r = self._check_host(host)
                if r is not None:
                    bad_hosts.append(r)
            if self.mgr.cache.host_needs_daemon_refresh(host):
                self.log.debug('refreshing %s daemons' % host)
                r = self._refresh_host_daemons(host)
                if r:
                    failures.append(r)

            if self.mgr.cache.host_needs_registry_login(host) and self.mgr.registry_url:
                self.log.debug(f"Logging `{host}` into custom registry")
                r = self._registry_login(host, self.mgr.registry_url,
                                         self.mgr.registry_username, self.mgr.registry_password)
                if r:
                    bad_hosts.append(r)

            if self.mgr.cache.host_needs_device_refresh(host):
                self.log.debug('refreshing %s devices' % host)
                r = self._refresh_host_devices(host)
                if r:
                    failures.append(r)

            if self.mgr.cache.host_needs_facts_refresh(host):
                self.log.info(('refreshing %s facts' % host))
                r = self._refresh_facts(host)
                if r:
                    failures.append(r)

            if self.mgr.cache.host_needs_osdspec_preview_refresh(host):
                self.log.debug(f"refreshing OSDSpec previews for {host}")
                r = self._refresh_host_osdspec_previews(host)
                if r:
                    failures.append(r)

            if self.mgr.cache.host_needs_new_etc_ceph_ceph_conf(host):
                self.log.debug(f"deploying new /etc/ceph/ceph.conf on `{host}`")
                r = self._deploy_etc_ceph_ceph_conf(host)
                if r:
                    bad_hosts.append(r)

        refresh(self.mgr.cache.get_hosts())

        health_changed = False
        for k in [
                'CEPHADM_HOST_CHECK_FAILED',
                'CEPHADM_FAILED_DAEMON'
                'CEPHADM_REFRESH_FAILED',
        ]:
            if k in self.mgr.health_checks:
                del self.mgr.health_checks[k]
                health_changed = True
        if bad_hosts:
            self.mgr.health_checks['CEPHADM_HOST_CHECK_FAILED'] = {
                'severity': 'warning',
                'summary': '%d hosts fail cephadm check' % len(bad_hosts),
                'count': len(bad_hosts),
                'detail': bad_hosts,
            }
            health_changed = True
        if failures:
            self.mgr.health_checks['CEPHADM_REFRESH_FAILED'] = {
                'severity': 'warning',
                'summary': 'failed to probe daemons or devices',
                'count': len(failures),
                'detail': failures,
            }
            health_changed = True
        failed_daemons = []
        for dd in self.mgr.cache.get_daemons():
            if dd.status is not None and dd.status < 0:
                failed_daemons.append('daemon %s on %s is in %s state' % (
                    dd.name(), dd.hostname, dd.status_desc
                ))
        if failed_daemons:
            self.mgr.health_checks['CEPHADM_FAILED_DAEMON'] = {
                'severity': 'warning',
                'summary': '%d failed cephadm daemon(s)' % len(failed_daemons),
                'count': len(failed_daemons),
                'detail': failed_daemons,
            }
            health_changed = True
        if health_changed:
            self.mgr.set_health_checks(self.mgr.health_checks)

    def _check_host(self, host: str) -> Optional[str]:
        if host not in self.mgr.inventory:
            return None
        self.log.debug(' checking %s' % host)
        try:
            out, err, code = self._run_cephadm(
                host, cephadmNoImage, 'check-host', [],
                error_ok=True, no_fsid=True)
            self.mgr.cache.update_last_host_check(host)
            self.mgr.cache.save_host(host)
            if code:
                self.log.debug(' host %s failed check' % host)
                if self.mgr.warn_on_failed_host_check:
                    return 'host %s failed check: %s' % (host, err)
            else:
                self.log.debug(' host %s ok' % host)
        except Exception as e:
            self.log.debug(' host %s failed check' % host)
            return 'host %s failed check: %s' % (host, e)
        return None

    def _refresh_host_daemons(self, host: str) -> Optional[str]:
        try:
            ls = self._run_cephadm_json(host, 'mon', 'ls', [], no_fsid=True)
        except OrchestratorError as e:
            return str(e)
        dm = {}
        for d in ls:
            if not d['style'].startswith('cephadm'):
                continue
            if d['fsid'] != self.mgr._cluster_fsid:
                continue
            if '.' not in d['name']:
                continue
            sd = orchestrator.DaemonDescription()
            sd.last_refresh = datetime_now()
            for k in ['created', 'started', 'last_configured', 'last_deployed']:
                v = d.get(k, None)
                if v:
                    setattr(sd, k, str_to_datetime(d[k]))
            sd.daemon_type = d['name'].split('.')[0]
            sd.daemon_id = '.'.join(d['name'].split('.')[1:])
            sd.hostname = host
            sd.container_id = d.get('container_id')
            if sd.container_id:
                # shorten the hash
                sd.container_id = sd.container_id[0:12]
            sd.container_image_name = d.get('container_image_name')
            sd.container_image_id = d.get('container_image_id')
            sd.version = d.get('version')
            if sd.daemon_type == 'osd':
                sd.osdspec_affinity = self.mgr.osd_service.get_osdspec_affinity(sd.daemon_id)
            if 'state' in d:
                sd.status_desc = d['state']
                sd.status = {
                    'running': 1,
                    'stopped': 0,
                    'error': -1,
                    'unknown': -1,
                }[d['state']]
            else:
                sd.status_desc = 'unknown'
                sd.status = None
            dm[sd.name()] = sd
        self.log.debug('Refreshed host %s daemons (%d)' % (host, len(dm)))
        self.mgr.cache.update_host_daemons(host, dm)
        self.mgr.cache.save_host(host)
        return None

    def _refresh_facts(self, host: str) -> Optional[str]:
        try:
            val = self._run_cephadm_json(host, cephadmNoImage, 'gather-facts', [], no_fsid=True)
        except OrchestratorError as e:
            return str(e)

        self.mgr.cache.update_host_facts(host, val)

        return None

    def _refresh_host_devices(self, host: str) -> Optional[str]:
        try:
            devices = self._run_cephadm_json(host, 'osd', 'ceph-volume',
                                             ['--', 'inventory', '--format=json', '--filter-for-batch'])
            networks = self._run_cephadm_json(host, 'mon', 'list-networks', [], no_fsid=True)
        except OrchestratorError as e:
            return str(e)

        self.log.debug('Refreshed host %s devices (%d) networks (%s)' % (
            host, len(devices), len(networks)))
        devices = inventory.Devices.from_json(devices)
        self.mgr.cache.update_host_devices_networks(host, devices.devices, networks)
        self.update_osdspec_previews(host)
        self.mgr.cache.save_host(host)
        return None

    def _refresh_host_osdspec_previews(self, host: str) -> Optional[str]:
        self.update_osdspec_previews(host)
        self.mgr.cache.save_host(host)
        self.log.debug(f'Refreshed OSDSpec previews for host <{host}>')
        return None

    def update_osdspec_previews(self, search_host: str = '') -> None:
        # Set global 'pending' flag for host
        self.mgr.cache.loading_osdspec_preview.add(search_host)
        previews = []
        # query OSDSpecs for host <search host> and generate/get the preview
        # There can be multiple previews for one host due to multiple OSDSpecs.
        previews.extend(self.mgr.osd_service.get_previews(search_host))
        self.log.debug(f"Loading OSDSpec previews to HostCache")
        self.mgr.cache.osdspec_previews[search_host] = previews
        # Unset global 'pending' flag for host
        self.mgr.cache.loading_osdspec_preview.remove(search_host)

    def _deploy_etc_ceph_ceph_conf(self, host: str) -> Optional[str]:
        config = self.mgr.get_minimal_ceph_conf()

        try:
            with self._remote_connection(host) as tpl:
                conn, connr = tpl
                out, err, code = remoto.process.check(
                    conn,
                    ['mkdir', '-p', '/etc/ceph'])
                if code:
                    return f'failed to create /etc/ceph on {host}: {err}'
                out, err, code = remoto.process.check(
                    conn,
                    ['dd', 'of=/etc/ceph/ceph.conf'],
                    stdin=config.encode('utf-8')
                )
                if code:
                    return f'failed to create /etc/ceph/ceph.conf on {host}: {err}'
                self.mgr.cache.update_last_etc_ceph_ceph_conf(host)
                self.mgr.cache.save_host(host)
        except OrchestratorError as e:
            return f'failed to create /etc/ceph/ceph.conf on {host}: {str(e)}'
        return None

    def _check_for_strays(self) -> None:
        self.log.debug('_check_for_strays')
        for k in ['CEPHADM_STRAY_HOST',
                  'CEPHADM_STRAY_DAEMON']:
            if k in self.mgr.health_checks:
                del self.mgr.health_checks[k]
        if self.mgr.warn_on_stray_hosts or self.mgr.warn_on_stray_daemons:
            ls = self.mgr.list_servers()
            managed = self.mgr.cache.get_daemon_names()
            host_detail = []     # type: List[str]
            host_num_daemons = 0
            daemon_detail = []  # type: List[str]
            for item in ls:
                host = item.get('hostname')
                assert isinstance(host, str)
                daemons = item.get('services')  # misnomer!
                assert isinstance(daemons, list)
                missing_names = []
                for s in daemons:
                    daemon_id = s.get('id')
                    assert daemon_id
                    name = '%s.%s' % (s.get('type'), daemon_id)
                    if s.get('type') == 'rbd-mirror':
                        metadata = self.mgr.get_metadata(
                            "rbd-mirror", daemon_id)
                        try:
                            name = '%s.%s' % (s.get('type'), metadata['id'])
                        except (KeyError, TypeError):
                            self.log.debug(
                                "Failed to find daemon id for rbd-mirror service %s" % (s.get('id')))

                    if host not in self.mgr.inventory:
                        missing_names.append(name)
                        host_num_daemons += 1
                    if name not in managed:
                        daemon_detail.append(
                            'stray daemon %s on host %s not managed by cephadm' % (name, host))
                if missing_names:
                    host_detail.append(
                        'stray host %s has %d stray daemons: %s' % (
                            host, len(missing_names), missing_names))
            if self.mgr.warn_on_stray_hosts and host_detail:
                self.mgr.health_checks['CEPHADM_STRAY_HOST'] = {
                    'severity': 'warning',
                    'summary': '%d stray host(s) with %s daemon(s) '
                    'not managed by cephadm' % (
                        len(host_detail), host_num_daemons),
                    'count': len(host_detail),
                    'detail': host_detail,
                }
            if self.mgr.warn_on_stray_daemons and daemon_detail:
                self.mgr.health_checks['CEPHADM_STRAY_DAEMON'] = {
                    'severity': 'warning',
                    'summary': '%d stray daemon(s) not managed by cephadm' % (
                        len(daemon_detail)),
                    'count': len(daemon_detail),
                    'detail': daemon_detail,
                }
        self.mgr.set_health_checks(self.mgr.health_checks)

    def _apply_all_services(self) -> bool:
        r = False
        specs = []  # type: List[ServiceSpec]
        for sn, spec in self.mgr.spec_store.specs.items():
            specs.append(spec)
        for spec in specs:
            try:
                if self._apply_service(spec):
                    r = True
            except Exception as e:
                self.log.exception('Failed to apply %s spec %s: %s' % (
                    spec.service_name(), spec, e))
                self.mgr.events.for_service(spec, 'ERROR', 'Failed to apply: ' + str(e))

        return r

    def _config_fn(self, service_type: ServiceType) -> Optional[Callable[[ServiceSpec, str], None]]:
        return cast(Callable[[ServiceSpec, str], None], self.mgr.cephadm_services[service_type].config)

    def _apply_service(self, spec: ServiceSpec) -> bool:
        """
        Schedule a service.  Deploy new daemons or remove old ones, depending
        on the target label and count specified in the placement.
        """
        self.mgr.migration.verify_no_migration()

        service_type = spec.service_type
        service_name = spec.service_name()
        if spec.unmanaged:
            self.log.debug('Skipping unmanaged service %s' % service_name)
            return False
        if spec.preview_only:
            self.log.debug('Skipping preview_only service %s' % service_name)
            return False
        self.log.debug('Applying service %s spec' % service_name)

        config_func = self._config_fn(service_type)

        if service_type == 'osd':
            self.mgr.osd_service.create_from_spec(cast(DriveGroupSpec, spec))
            # TODO: return True would result in a busy loop
            # can't know if daemon count changed; create_from_spec doesn't
            # return a solid indication
            return False

        daemons = self.mgr.cache.get_daemons_by_service(service_name)

        public_network = None
        if service_type == 'mon':
            ret, out, err = self.mgr.check_mon_command({
                'prefix': 'config get',
                'who': 'mon',
                'key': 'public_network',
            })
            if '/' in out:
                public_network = out.strip()
                self.log.debug('mon public_network is %s' % public_network)

        def matches_network(host):
            # type: (str) -> bool
            if not public_network:
                return False
            # make sure we have 1 or more IPs for that network on that
            # host
            return len(self.mgr.cache.networks[host].get(public_network, [])) > 0

        def virtual_ip_allowed(host):
            # type: (str) -> bool
            # Verify that it is possible to use Virtual IPs in the host
            try:
                if self.mgr.cache.facts[host]['kernel_parameters']['net.ipv4.ip_nonlocal_bind'] == '0':
                    return False
            except KeyError:
                return False

            return True

        ha = HostAssignment(
            spec=spec,
            hosts=self.mgr._hosts_with_daemon_inventory(),
            get_daemons_func=self.mgr.cache.get_daemons_by_service,
            filter_new_host=matches_network if service_type == 'mon'
            else virtual_ip_allowed if service_type == 'ha-rgw' else None,
        )

        try:
            hosts: List[HostPlacementSpec] = ha.place()
            self.log.debug('Usable hosts: %s' % hosts)
        except OrchestratorError as e:
            self.log.error('Failed to apply %s spec %s: %s' % (
                spec.service_name(), spec, e))
            self.mgr.events.for_service(spec, 'ERROR', 'Failed to apply: ' + str(e))
            return False

        r = None

        # sanity check
        if service_type in ['mon', 'mgr'] and len(hosts) < 1:
            self.log.debug('cannot scale mon|mgr below 1 (hosts=%s)' % hosts)
            return False

        # add any?
        did_config = False

        add_daemon_hosts: Set[HostPlacementSpec] = ha.add_daemon_hosts(hosts)
        self.log.debug('Hosts that will receive new daemons: %s' % add_daemon_hosts)

        remove_daemon_hosts: Set[orchestrator.DaemonDescription] = ha.remove_daemon_hosts(hosts)
        self.log.debug('Hosts that will loose daemons: %s' % remove_daemon_hosts)

        if service_type == 'ha-rgw':
            spec = self.update_ha_rgw_definitive_hosts(spec, hosts, add_daemon_hosts)

        for host, network, name in add_daemon_hosts:
            for daemon_type in service_to_daemon_types(service_type):
                daemon_id = self.mgr.get_unique_name(daemon_type, host, daemons,
                                                     prefix=spec.service_id,
                                                     forcename=name)

                if not did_config and config_func:
                    config_func(spec, daemon_id)
                    did_config = True

                daemon_spec = self.mgr.cephadm_services[service_type].make_daemon_spec(
                    host, daemon_id, network, spec, daemon_type=daemon_type)
                self.log.debug('Placing %s.%s on host %s' % (
                    daemon_type, daemon_id, host))

                try:
                    daemon_spec = self.mgr.cephadm_services[service_type].prepare_create(
                        daemon_spec)
                    self._create_daemon(daemon_spec)
                    r = True
                except (RuntimeError, OrchestratorError) as e:
                    self.mgr.events.for_service(spec, 'ERROR',
                                                f"Failed while placing {daemon_type}.{daemon_id}"
                                                f"on {host}: {e}")
                    # only return "no change" if no one else has already succeeded.
                    # later successes will also change to True
                    if r is None:
                        r = False
                    continue

                # add to daemon list so next name(s) will also be unique
                sd = orchestrator.DaemonDescription(
                    hostname=host,
                    daemon_type=daemon_type,
                    daemon_id=daemon_id,
                )
                daemons.append(sd)

        # remove any?
        def _ok_to_stop(remove_daemon_hosts: Set[orchestrator.DaemonDescription]) -> bool:
            daemon_ids = [d.daemon_id for d in remove_daemon_hosts]
            assert None not in daemon_ids
            # setting force flag retains previous behavior, should revisit later.
            r = self.mgr.cephadm_services[service_type].ok_to_stop(cast(List[str], daemon_ids), force=True)
            return not r.retval

        while remove_daemon_hosts and not _ok_to_stop(remove_daemon_hosts):
            # let's find a subset that is ok-to-stop
            remove_daemon_hosts.pop()
        for d in remove_daemon_hosts:
            r = True
            # NOTE: we are passing the 'force' flag here, which means
            # we can delete a mon instances data.
            assert d.hostname is not None
            self._remove_daemon(d.name(), d.hostname)

        if r is None:
            r = False
        return r

    def _check_daemons(self) -> None:

        daemons = self.mgr.cache.get_daemons()
        daemons_post: Dict[str, List[orchestrator.DaemonDescription]] = defaultdict(list)
        for dd in daemons:
            # orphan?
            spec = self.mgr.spec_store.specs.get(dd.service_name(), None)
            assert dd.hostname is not None
            assert dd.daemon_type is not None
            assert dd.daemon_id is not None
            if not spec and dd.daemon_type not in ['mon', 'mgr', 'osd']:
                # (mon and mgr specs should always exist; osds aren't matched
                # to a service spec)
                self.log.info('Removing orphan daemon %s...' % dd.name())
                self._remove_daemon(dd.name(), dd.hostname)

            # ignore unmanaged services
            if spec and spec.unmanaged:
                continue

            # These daemon types require additional configs after creation
            if dd.daemon_type in ['grafana', 'iscsi', 'prometheus', 'alertmanager', 'nfs']:
                daemons_post[dd.daemon_type].append(dd)

            if self.mgr.cephadm_services[daemon_type_to_service(dd.daemon_type)].get_active_daemon(
               self.mgr.cache.get_daemons_by_service(dd.service_name())).daemon_id == dd.daemon_id:
                dd.is_active = True
            else:
                dd.is_active = False

            deps = self.mgr._calc_daemon_deps(dd.daemon_type, dd.daemon_id)
            last_deps, last_config = self.mgr.cache.get_daemon_last_config_deps(
                dd.hostname, dd.name())
            if last_deps is None:
                last_deps = []
            action = self.mgr.cache.get_scheduled_daemon_action(dd.hostname, dd.name())
            if not last_config:
                self.log.info('Reconfiguring %s (unknown last config time)...' % (
                    dd.name()))
                action = 'reconfig'
            elif last_deps != deps:
                self.log.debug('%s deps %s -> %s' % (dd.name(), last_deps,
                                                     deps))
                self.log.info('Reconfiguring %s (dependencies changed)...' % (
                    dd.name()))
                action = 'reconfig'
            elif self.mgr.last_monmap and \
                    self.mgr.last_monmap > last_config and \
                    dd.daemon_type in CEPH_TYPES:
                self.log.info('Reconfiguring %s (monmap changed)...' % dd.name())
                action = 'reconfig'
            elif self.mgr.extra_ceph_conf_is_newer(last_config) and \
                    dd.daemon_type in CEPH_TYPES:
                self.log.info('Reconfiguring %s (extra config changed)...' % dd.name())
                action = 'reconfig'
            if action:
                if self.mgr.cache.get_scheduled_daemon_action(dd.hostname, dd.name()) == 'redeploy' \
                        and action == 'reconfig':
                    action = 'redeploy'
                try:
                    self.mgr._daemon_action(
                        daemon_type=dd.daemon_type,
                        daemon_id=dd.daemon_id,
                        host=dd.hostname,
                        action=action
                    )
                    self.mgr.cache.rm_scheduled_daemon_action(dd.hostname, dd.name())
                except OrchestratorError as e:
                    self.mgr.events.from_orch_error(e)
                    if dd.daemon_type in daemons_post:
                        del daemons_post[dd.daemon_type]
                    # continue...
                except Exception as e:
                    self.mgr.events.for_daemon_from_exception(dd.name(), e)
                    if dd.daemon_type in daemons_post:
                        del daemons_post[dd.daemon_type]
                    # continue...

        # do daemon post actions
        for daemon_type, daemon_descs in daemons_post.items():
            if daemon_type in self.mgr.requires_post_actions:
                self.mgr.requires_post_actions.remove(daemon_type)
                self.mgr._get_cephadm_service(daemon_type_to_service(
                    daemon_type)).daemon_check_post(daemon_descs)

    def convert_tags_to_repo_digest(self) -> None:
        if not self.mgr.use_repo_digest:
            return
        settings = self.mgr.upgrade.get_distinct_container_image_settings()
        digests: Dict[str, ContainerInspectInfo] = {}
        for container_image_ref in set(settings.values()):
            if not is_repo_digest(container_image_ref):
                image_info = self._get_container_image_info(container_image_ref)
                if image_info.repo_digest:
                    assert is_repo_digest(image_info.repo_digest), image_info
                digests[container_image_ref] = image_info

        for entity, container_image_ref in settings.items():
            if not is_repo_digest(container_image_ref):
                image_info = digests[container_image_ref]
                if image_info.repo_digest:
                    self.mgr.set_container_image(entity, image_info.repo_digest)

    # ha-rgw needs definitve host list to create keepalived config files
    # if definitive host list has changed, all ha-rgw daemons must get new
    # config, including those that are already on the correct host and not
    # going to be deployed
    def update_ha_rgw_definitive_hosts(self, spec: ServiceSpec, hosts: List[HostPlacementSpec],
                                       add_hosts: Set[HostPlacementSpec]) -> HA_RGWSpec:
        spec = cast(HA_RGWSpec, spec)
        if not (set(hosts) == set(spec.definitive_host_list)):
            spec.definitive_host_list = hosts
            ha_rgw_daemons = self.mgr.cache.get_daemons_by_service(spec.service_name())
            for daemon in ha_rgw_daemons:
                if daemon.hostname in [h.hostname for h in hosts] and daemon.hostname not in add_hosts:
                    assert daemon.hostname is not None
                    self.mgr.cache.schedule_daemon_action(
                        daemon.hostname, daemon.name(), 'reconfig')
        return spec

    def _create_daemon(self,
                       daemon_spec: CephadmDaemonSpec,
                       reconfig: bool = False,
                       osd_uuid_map: Optional[Dict[str, Any]] = None,
                       ) -> str:

        with set_exception_subject('service', orchestrator.DaemonDescription(
                daemon_type=daemon_spec.daemon_type,
                daemon_id=daemon_spec.daemon_id,
                hostname=daemon_spec.host,
        ).service_id(), overwrite=True):

            image = ''
            start_time = datetime_now()
            ports: List[int] = daemon_spec.ports if daemon_spec.ports else []

            if daemon_spec.daemon_type == 'container':
                spec: Optional[CustomContainerSpec] = daemon_spec.spec
                if spec is None:
                    # Exit here immediately because the required service
                    # spec to create a daemon is not provided. This is only
                    # provided when a service is applied via 'orch apply'
                    # command.
                    msg = "Failed to {} daemon {} on {}: Required " \
                          "service specification not provided".format(
                              'reconfigure' if reconfig else 'deploy',
                              daemon_spec.name(), daemon_spec.host)
                    self.log.info(msg)
                    return msg
                image = spec.image
                if spec.ports:
                    ports.extend(spec.ports)

            if daemon_spec.daemon_type == 'cephadm-exporter':
                if not reconfig:
                    assert daemon_spec.host
                    deploy_ok = self._deploy_cephadm_binary(daemon_spec.host)
                    if not deploy_ok:
                        msg = f"Unable to deploy the cephadm binary to {daemon_spec.host}"
                        self.log.warning(msg)
                        return msg

            if daemon_spec.daemon_type == 'haproxy':
                haspec = cast(HA_RGWSpec, daemon_spec.spec)
                if haspec.haproxy_container_image:
                    image = haspec.haproxy_container_image

            if daemon_spec.daemon_type == 'keepalived':
                haspec = cast(HA_RGWSpec, daemon_spec.spec)
                if haspec.keepalived_container_image:
                    image = haspec.keepalived_container_image

            cephadm_config, deps = self.mgr.cephadm_services[daemon_type_to_service(daemon_spec.daemon_type)].generate_config(
                daemon_spec)

            # TCP port to open in the host firewall
            if len(ports) > 0:
                daemon_spec.extra_args.extend([
                    '--tcp-ports', ' '.join(map(str, ports))
                ])

            # osd deployments needs an --osd-uuid arg
            if daemon_spec.daemon_type == 'osd':
                if not osd_uuid_map:
                    osd_uuid_map = self.mgr.get_osd_uuid_map()
                osd_uuid = osd_uuid_map.get(daemon_spec.daemon_id)
                if not osd_uuid:
                    raise OrchestratorError('osd.%s not in osdmap' % daemon_spec.daemon_id)
                daemon_spec.extra_args.extend(['--osd-fsid', osd_uuid])

            if reconfig:
                daemon_spec.extra_args.append('--reconfig')
            if self.mgr.allow_ptrace:
                daemon_spec.extra_args.append('--allow-ptrace')

            if self.mgr.cache.host_needs_registry_login(daemon_spec.host) and self.mgr.registry_url:
                self._registry_login(daemon_spec.host, self.mgr.registry_url,
                                     self.mgr.registry_username, self.mgr.registry_password)

            daemon_spec.extra_args.extend(['--config-json', '-'])

            self.log.info('%s daemon %s on %s' % (
                'Reconfiguring' if reconfig else 'Deploying',
                daemon_spec.name(), daemon_spec.host))

            out, err, code = self._run_cephadm(
                daemon_spec.host, daemon_spec.name(), 'deploy',
                [
                    '--name', daemon_spec.name(),
                ] + daemon_spec.extra_args,
                stdin=json.dumps(cephadm_config),
                image=image)
            if not code and daemon_spec.host in self.mgr.cache.daemons:
                # prime cached service state with what we (should have)
                # just created
                sd = orchestrator.DaemonDescription()
                sd.daemon_type = daemon_spec.daemon_type
                sd.daemon_id = daemon_spec.daemon_id
                sd.hostname = daemon_spec.host
                sd.status = 1
                sd.status_desc = 'starting'
                self.mgr.cache.add_daemon(daemon_spec.host, sd)
                if daemon_spec.daemon_type in ['grafana', 'iscsi', 'prometheus', 'alertmanager']:
                    self.mgr.requires_post_actions.add(daemon_spec.daemon_type)
            self.mgr.cache.invalidate_host_daemons(daemon_spec.host)
            self.mgr.cache.update_daemon_config_deps(
                daemon_spec.host, daemon_spec.name(), deps, start_time)
            self.mgr.cache.save_host(daemon_spec.host)
            msg = "{} {} on host '{}'".format(
                'Reconfigured' if reconfig else 'Deployed', daemon_spec.name(), daemon_spec.host)
            if not code:
                self.mgr.events.for_daemon(daemon_spec.name(), OrchestratorEvent.INFO, msg)
            else:
                what = 'reconfigure' if reconfig else 'deploy'
                self.mgr.events.for_daemon(
                    daemon_spec.name(), OrchestratorEvent.ERROR, f'Failed to {what}: {err}')
            return msg

    def _remove_daemon(self, name: str, host: str) -> str:
        """
        Remove a daemon
        """
        (daemon_type, daemon_id) = name.split('.', 1)
        daemon = orchestrator.DaemonDescription(
            daemon_type=daemon_type,
            daemon_id=daemon_id,
            hostname=host)

        with set_exception_subject('service', daemon.service_id(), overwrite=True):

            self.mgr.cephadm_services[daemon_type_to_service(daemon_type)].pre_remove(daemon)

            args = ['--name', name, '--force']
            self.log.info('Removing daemon %s from %s' % (name, host))
            out, err, code = self._run_cephadm(
                host, name, 'rm-daemon', args)
            if not code:
                # remove item from cache
                self.mgr.cache.rm_daemon(host, name)
            self.mgr.cache.invalidate_host_daemons(host)

            self.mgr.cephadm_services[daemon_type_to_service(daemon_type)].post_remove(daemon)

            return "Removed {} from host '{}'".format(name, host)

    def _run_cephadm_json(self,
                          host: str,
                          entity: Union[CephadmNoImage, str],
                          command: str,
                          args: List[str],
                          no_fsid: Optional[bool] = False,
                          image: Optional[str] = "",
                          ) -> Any:
        try:
            out, err, code = self._run_cephadm(
                host, entity, command, args, no_fsid=no_fsid, image=image)
            if code:
                raise OrchestratorError(f'host {host} `cephadm {command}` returned {code}: {err}')
        except Exception as e:
            raise OrchestratorError(f'host {host} `cephadm {command}` failed: {e}')
        try:
            return json.loads(''.join(out))
        except (ValueError, KeyError):
            msg = f'host {host} `cephadm {command}` failed: Cannot decode JSON'
            self.log.exception(f'{msg}: {"".join(out)}')
            raise OrchestratorError(msg)

    def _run_cephadm(self,
                     host: str,
                     entity: Union[CephadmNoImage, str],
                     command: str,
                     args: List[str],
                     addr: Optional[str] = "",
                     stdin: Optional[str] = "",
                     no_fsid: Optional[bool] = False,
                     error_ok: Optional[bool] = False,
                     image: Optional[str] = "",
                     env_vars: Optional[List[str]] = None,
                     ) -> Tuple[List[str], List[str], int]:
        """
        Run cephadm on the remote host with the given command + args

        Important: You probably don't want to run _run_cephadm from CLI handlers

        :env_vars: in format -> [KEY=VALUE, ..]
        """
        self.log.debug(f"_run_cephadm : command = {command}")
        self.log.debug(f"_run_cephadm : args = {args}")

        bypass_image = ('cephadm-exporter',)

        with self._remote_connection(host, addr) as tpl:
            conn, connr = tpl
            assert image or entity
            # Skip the image check for daemons deployed that are not ceph containers
            if not str(entity).startswith(bypass_image):
                if not image and entity is not cephadmNoImage:
                    image = self.mgr._get_container_image(entity)

            final_args = []

            if env_vars:
                for env_var_pair in env_vars:
                    final_args.extend(['--env', env_var_pair])

            if image:
                final_args.extend(['--image', image])
            final_args.append(command)

            if not no_fsid:
                final_args += ['--fsid', self.mgr._cluster_fsid]

            if self.mgr.container_init:
                final_args += ['--container-init']

            final_args += args

            self.log.debug('args: %s' % (' '.join(final_args)))
            if self.mgr.mode == 'root':
                if stdin:
                    self.log.debug('stdin: %s' % stdin)
                script = 'injected_argv = ' + json.dumps(final_args) + '\n'
                if stdin:
                    script += 'injected_stdin = ' + json.dumps(stdin) + '\n'
                script += self.mgr._cephadm
                python = connr.choose_python()
                if not python:
                    raise RuntimeError(
                        'unable to find python on %s (tried %s in %s)' % (
                            host, remotes.PYTHONS, remotes.PATH))
                try:
                    out, err, code = remoto.process.check(
                        conn,
                        [python, '-u'],
                        stdin=script.encode('utf-8'))
                except RuntimeError as e:
                    self.mgr._reset_con(host)
                    if error_ok:
                        return [], [str(e)], 1
                    raise
            elif self.mgr.mode == 'cephadm-package':
                try:
                    out, err, code = remoto.process.check(
                        conn,
                        ['sudo', '/usr/bin/cephadm'] + final_args,
                        stdin=stdin)
                except RuntimeError as e:
                    self.mgr._reset_con(host)
                    if error_ok:
                        return [], [str(e)], 1
                    raise
            else:
                assert False, 'unsupported mode'

            self.log.debug('code: %d' % code)
            if out:
                self.log.debug('out: %s' % '\n'.join(out))
            if err:
                self.log.debug('err: %s' % '\n'.join(err))
            if code and not error_ok:
                raise OrchestratorError(
                    'cephadm exited with an error code: %d, stderr:%s' % (
                        code, '\n'.join(err)))
            return out, err, code

    def _get_container_image_info(self, image_name: str) -> ContainerInspectInfo:
        # pick a random host...
        host = None
        for host_name in self.mgr.inventory.keys():
            host = host_name
            break
        if not host:
            raise OrchestratorError('no hosts defined')
        if self.mgr.cache.host_needs_registry_login(host) and self.mgr.registry_url:
            self._registry_login(host, self.mgr.registry_url,
                                 self.mgr.registry_username, self.mgr.registry_password)

        j = self._run_cephadm_json(host, '', 'pull', [], image=image_name, no_fsid=True)

        r = ContainerInspectInfo(
            j['image_id'],
            j.get('ceph_version'),
            j.get('repo_digest')
        )
        self.log.debug(f'image {image_name} -> {r}')
        return r

    # function responsible for logging single host into custom registry
    def _registry_login(self, host: str, url: Optional[str], username: Optional[str], password: Optional[str]) -> Optional[str]:
        self.log.debug(f"Attempting to log host {host} into custom registry @ {url}")
        # want to pass info over stdin rather than through normal list of args
        args_str = json.dumps({
            'url': url,
            'username': username,
            'password': password,
        })
        out, err, code = self._run_cephadm(
            host, 'mon', 'registry-login',
            ['--registry-json', '-'], stdin=args_str, error_ok=True)
        if code:
            return f"Host {host} failed to login to {url} as {username} with given password"
        return None

    def _deploy_cephadm_binary(self, host: str) -> bool:
        # Use tee (from coreutils) to create a copy of cephadm on the target machine
        self.log.info(f"Deploying cephadm binary to {host}")
        with self._remote_connection(host) as tpl:
            conn, _connr = tpl
            _out, _err, code = remoto.process.check(
                conn,
                ['tee', '-', '/var/lib/ceph/{}/cephadm'.format(self.mgr._cluster_fsid)],
                stdin=self.mgr._cephadm.encode('utf-8'))
        return code == 0

    @contextmanager
    def _remote_connection(self,
                           host: str,
                           addr: Optional[str] = None,
                           ) -> Iterator[Tuple["BaseConnection", Any]]:
        if not addr and host in self.mgr.inventory:
            addr = self.mgr.inventory.get_addr(host)

        self.mgr.offline_hosts_remove(host)

        try:
            try:
                if not addr:
                    raise OrchestratorError("host address is empty")
                conn, connr = self.mgr._get_connection(addr)
            except OSError as e:
                self.mgr._reset_con(host)
                msg = f"Can't communicate with remote host `{addr}`, possibly because python3 is not installed there: {str(e)}"
                raise execnet.gateway_bootstrap.HostNotFound(msg)

            yield (conn, connr)

        except execnet.gateway_bootstrap.HostNotFound as e:
            # this is a misleading exception as it seems to be thrown for
            # any sort of connection failure, even those having nothing to
            # do with "host not found" (e.g., ssh key permission denied).
            self.mgr.offline_hosts.add(host)
            self.mgr._reset_con(host)

            user = self.mgr.ssh_user if self.mgr.mode == 'root' else 'cephadm'
            if str(e).startswith("Can't communicate"):
                msg = str(e)
            else:
                msg = f'''Failed to connect to {host} ({addr}).
Please make sure that the host is reachable and accepts connections using the cephadm SSH key

To add the cephadm SSH key to the host:
> ceph cephadm get-pub-key > ~/ceph.pub
> ssh-copy-id -f -i ~/ceph.pub {user}@{host}

To check that the host is reachable:
> ceph cephadm get-ssh-config > ssh_config
> ceph config-key get mgr/cephadm/ssh_identity_key > ~/cephadm_private_key
> ssh -F ssh_config -i ~/cephadm_private_key {user}@{host}'''
            raise OrchestratorError(msg) from e
        except Exception as ex:
            self.log.exception(ex)
            raise
