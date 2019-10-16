# -*- coding: utf-8 -*-
from __future__ import absolute_import
import json

from .helper import DashboardTestCase
from .test_orchestrator import test_data


class HostControllerTest(DashboardTestCase):

    AUTH_ROLES = ['read-only']

    URL_HOST = '/api/host'

    @classmethod
    def setUpClass(cls):
        super(HostControllerTest, cls).setUpClass()
        cls._load_module("test_orchestrator")

        cmd = ['orchestrator', 'set', 'backend', 'test_orchestrator']
        cls.mgr_cluster.mon_manager.raw_cluster_cmd(*cmd)

        cmd = ['test_orchestrator', 'load_data', '-i', '-']
        cls.mgr_cluster.mon_manager.raw_cluster_cmd_result(*cmd, stdin=json.dumps(test_data))

    @classmethod
    def tearDownClass(cls):
        cmd = ['test_orchestrator', 'load_data', '-i', '-']
        cls.mgr_cluster.mon_manager.raw_cluster_cmd_result(*cmd, stdin='{}')

    @DashboardTestCase.RunAs('test', 'test', ['block-manager'])
    def test_access_permissions(self):
        self._get(self.URL_HOST)
        self.assertStatus(403)

    def test_host_list(self):
        data = self._get(self.URL_HOST)
        self.assertStatus(200)

        orch_hostnames = {inventory_node['name'] for inventory_node in test_data['inventory']}

        for server in data:
            self.assertIn('services', server)
            self.assertIn('hostname', server)
            self.assertIn('ceph_version', server)
            self.assertIsNotNone(server['hostname'])
            self.assertIsNotNone(server['ceph_version'])
            for service in server['services']:
                self.assertIn('type', service)
                self.assertIn('id', service)
                self.assertIsNotNone(service['type'])
                self.assertIsNotNone(service['id'])

            self.assertIn('sources', server)
            in_ceph, in_orchestrator = server['sources']['ceph'], server['sources']['orchestrator']
            if in_ceph:
                self.assertGreaterEqual(len(server['services']), 1)
                if not in_orchestrator:
                    self.assertNotIn(server['hostname'], orch_hostnames)
            if in_orchestrator:
                self.assertEqual(len(server['services']), 0)
                self.assertIn(server['hostname'], orch_hostnames)

    def test_host_list_with_sources(self):
        data = self._get('{}?sources=orchestrator'.format(self.URL_HOST))
        self.assertStatus(200)
        test_hostnames = {inventory_node['name'] for inventory_node in test_data['inventory']}
        resp_hostnames = {host['hostname'] for host in data}
        self.assertEqual(test_hostnames, resp_hostnames)

        data = self._get('{}?sources=ceph'.format(self.URL_HOST))
        self.assertStatus(200)
        test_hostnames = {inventory_node['name'] for inventory_node in test_data['inventory']}
        resp_hostnames = {host['hostname'] for host in data}
        self.assertEqual(len(test_hostnames.intersection(resp_hostnames)), 0)
