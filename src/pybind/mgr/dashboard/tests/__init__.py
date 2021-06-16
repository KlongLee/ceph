# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments
from __future__ import absolute_import

import json
import logging
import threading
import time
from unittest.mock import Mock

import cherrypy
from cherrypy._cptools import HandlerWrapperTool
from cherrypy.test import helper
from mgr_module import HandleCommandResult
from pyfakefs import fake_filesystem

from .. import DEFAULT_VERSION, mgr
from ..controllers import generate_controller_routes, json_error_page
from ..module import Module
from ..plugins import PLUGIN_MANAGER, debug, feature_toggles  # noqa
from ..services.auth import AuthManagerTool
from ..services.exception import dashboard_exception_handler
from ..tools import RequestLoggingTool

PLUGIN_MANAGER.hook.init()
PLUGIN_MANAGER.hook.register_commands()


logger = logging.getLogger('tests')


class ModuleTestClass(Module):
    """Dashboard module subclass for testing the module methods."""

    def __init__(self) -> None:
        pass

    def _unconfigure_logging(self) -> None:
        pass


class CmdException(Exception):
    def __init__(self, retcode, message):
        super(CmdException, self).__init__(message)
        self.retcode = retcode


class KVStoreMockMixin(object):
    CONFIG_KEY_DICT = {}

    @classmethod
    def mock_set_module_option(cls, attr, val):
        cls.CONFIG_KEY_DICT[attr] = val

    @classmethod
    def mock_get_module_option(cls, attr, default=None):
        return cls.CONFIG_KEY_DICT.get(attr, default)

    @classmethod
    def mock_kv_store(cls):
        cls.CONFIG_KEY_DICT.clear()
        mgr.set_module_option.side_effect = cls.mock_set_module_option
        mgr.get_module_option.side_effect = cls.mock_get_module_option
        # kludge below
        mgr.set_store.side_effect = cls.mock_set_module_option
        mgr.get_store.side_effect = cls.mock_get_module_option

    @classmethod
    def get_key(cls, key):
        return cls.CONFIG_KEY_DICT.get(key, None)


# pylint: disable=protected-access
class CLICommandTestMixin(KVStoreMockMixin):
    _dashboard_module = ModuleTestClass()

    @classmethod
    def exec_cmd(cls, cmd, **kwargs):
        inbuf = kwargs['inbuf'] if 'inbuf' in kwargs else None
        cmd_dict = {'prefix': 'dashboard {}'.format(cmd)}
        cmd_dict.update(kwargs)

        result = HandleCommandResult(*cls._dashboard_module._handle_command(inbuf, cmd_dict))

        if result.retval < 0:
            raise CmdException(result.retval, result.stderr)
        try:
            return json.loads(result.stdout)
        except ValueError:
            return result.stdout


class FakeFsMixin(object):
    fs = fake_filesystem.FakeFilesystem()
    f_open = fake_filesystem.FakeFileOpen(fs)
    f_os = fake_filesystem.FakeOsModule(fs)
    builtins_open = 'builtins.open'


class ControllerTestCase(helper.CPWebCase):
    _endpoints_cache = {}

    @classmethod
    def setup_controllers(cls, ctrl_classes, base_url=''):
        if not isinstance(ctrl_classes, list):
            ctrl_classes = [ctrl_classes]
        mapper = cherrypy.dispatch.RoutesDispatcher()
        endpoint_list = []
        for ctrl in ctrl_classes:
            inst = ctrl()

            # We need to cache the controller endpoints because
            # BaseController#endpoints method is not idempontent
            # and a controller might be needed by more than one
            # unit test.
            if ctrl not in cls._endpoints_cache:
                ctrl_endpoints = ctrl.endpoints()
                cls._endpoints_cache[ctrl] = ctrl_endpoints

            ctrl_endpoints = cls._endpoints_cache[ctrl]
            for endpoint in ctrl_endpoints:
                endpoint.inst = inst
                endpoint_list.append(endpoint)
        endpoint_list = sorted(endpoint_list, key=lambda e: e.url)
        for endpoint in endpoint_list:
            generate_controller_routes(endpoint, mapper, base_url)
        if base_url == '':
            base_url = '/'
        cherrypy.tree.mount(None, config={
            base_url: {'request.dispatch': mapper}})

    _request_logging = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cherrypy.tools.authenticate = AuthManagerTool()
        cherrypy.tools.dashboard_exception_handler = HandlerWrapperTool(dashboard_exception_handler,
                                                                        priority=31)
        cherrypy.config.update({
            'error_page.default': json_error_page,
            'tools.json_in.on': True,
            'tools.json_in.force': False
        })
        PLUGIN_MANAGER.hook.configure_cherrypy(config=cherrypy.config)

        if cls._request_logging:
            cherrypy.tools.request_logging = RequestLoggingTool()
            cherrypy.config.update({'tools.request_logging.on': True})

    @classmethod
    def tearDownClass(cls):
        if cls._request_logging:
            cherrypy.config.update({'tools.request_logging.on': False})

    def _request(self, url, method, data=None, headers=None, version=DEFAULT_VERSION):
        if not data:
            b = None
            if version:
                h = [('Accept', 'application/vnd.ceph.api.v{}+json'.format(version)),
                     ('Content-Length', '0')]
            else:
                h = None
        else:
            b = json.dumps(data)
            if version is not None:
                h = [('Accept', 'application/vnd.ceph.api.v{}+json'.format(version)),
                     ('Content-Type', 'application/json'),
                     ('Content-Length', str(len(b)))]

            else:
                h = [('Content-Type', 'application/json'),
                     ('Content-Length', str(len(b)))]

        if headers:
            h = headers
        self.getPage(url, method=method, body=b, headers=h)

    def _get(self, url, headers=None, version=DEFAULT_VERSION):
        self._request(url, 'GET', headers=headers, version=version)

    def _post(self, url, data=None, version=DEFAULT_VERSION):
        self._request(url, 'POST', data, version=version)

    def _delete(self, url, data=None, version=DEFAULT_VERSION):
        self._request(url, 'DELETE', data, version=version)

    def _put(self, url, data=None, version=DEFAULT_VERSION):
        self._request(url, 'PUT', data, version=version)

    def _task_request(self, method, url, data, timeout, version=DEFAULT_VERSION):
        self._request(url, method, data, version=version)
        if self.status != '202 Accepted':
            logger.info("task finished immediately")
            return

        res = self.json_body()
        self.assertIsInstance(res, dict)
        self.assertIn('name', res)
        self.assertIn('metadata', res)

        task_name = res['name']
        task_metadata = res['metadata']

        # pylint: disable=protected-access
        class Waiter(threading.Thread):
            def __init__(self, task_name, task_metadata, tc):
                super(Waiter, self).__init__()
                self.task_name = task_name
                self.task_metadata = task_metadata
                self.ev = threading.Event()
                self.abort = False
                self.res_task = None
                self.tc = tc

            def run(self):
                running = True
                while running and not self.abort:
                    logger.info("task (%s, %s) is still executing", self.task_name,
                                self.task_metadata)
                    time.sleep(1)
                    self.tc._get('/api/task?name={}'.format(self.task_name), version=version)
                    res = self.tc.json_body()
                    for task in res['finished_tasks']:
                        if task['metadata'] == self.task_metadata:
                            # task finished
                            running = False
                            self.res_task = task
                            self.ev.set()

        thread = Waiter(task_name, task_metadata, self)
        thread.start()
        status = thread.ev.wait(timeout)
        if not status:
            # timeout expired
            thread.abort = True
            thread.join()
            raise Exception("Waiting for task ({}, {}) to finish timed out"
                            .format(task_name, task_metadata))
        logger.info("task (%s, %s) finished", task_name, task_metadata)
        if thread.res_task['success']:
            self.body = json.dumps(thread.res_task['ret_value'])
            if method == 'POST':
                self.status = '201 Created'
            elif method == 'PUT':
                self.status = '200 OK'
            elif method == 'DELETE':
                self.status = '204 No Content'
            return

        if 'status' in thread.res_task['exception']:
            self.status = thread.res_task['exception']['status']
        else:
            self.status = 500
        self.body = json.dumps(thread.res_task['exception'])

    def _task_post(self, url, data=None, timeout=60, version=DEFAULT_VERSION):
        self._task_request('POST', url, data, timeout, version=version)

    def _task_delete(self, url, timeout=60, version=DEFAULT_VERSION):
        self._task_request('DELETE', url, None, timeout, version=version)

    def _task_put(self, url, data=None, timeout=60, version=DEFAULT_VERSION):
        self._task_request('PUT', url, data, timeout, version=version)

    def json_body(self):
        body_str = self.body.decode('utf-8') if isinstance(self.body, bytes) else self.body
        return json.loads(body_str)

    def assertJsonBody(self, data, msg=None):  # noqa: N802
        """Fail if value != self.body."""
        json_body = self.json_body()
        if data != json_body:
            if msg is None:
                msg = 'expected body:\n%r\n\nactual body:\n%r' % (
                    data, json_body)
            self._handlewebError(msg)

    def assertInJsonBody(self, data, msg=None):  # noqa: N802
        json_body = self.json_body()
        if data not in json_body:
            if msg is None:
                msg = 'expected %r to be in %r' % (data, json_body)
            self._handlewebError(msg)


class Stub:
    """Test class for returning predefined values"""

    @classmethod
    def get_mgr_no_services(cls):
        mgr.get = Mock(return_value={})


class RgwStub(Stub):

    @classmethod
    def get_daemons(cls):
        mgr.get = Mock(return_value={'services': {'rgw': {'daemons': {
            '5297': {
                'addr': '192.168.178.3:49774/1534999298',
                'metadata': {
                    'frontend_config#0': 'beast port=8000',
                    'id': 'daemon1',
                    'zonegroup_name': 'zonegroup1',
                    'zone_name': 'zone1'
                }
            },
            '5398': {
                'addr': '[2001:db8:85a3::8a2e:370:7334]:49774/1534999298',
                'metadata': {
                    'frontend_config#0': 'civetweb port=8002',
                    'id': 'daemon2',
                    'zonegroup_name': 'zonegroup2',
                    'zone_name': 'zone2'
                }
            }
        }}}})

    @classmethod
    def get_settings(cls):
        settings = {
            'RGW_API_HOST': '',
            'RGW_API_PORT': 0,
            'RGW_API_ACCESS_KEY': 'fake-access-key',
            'RGW_API_SECRET_KEY': 'fake-secret-key',
        }
        mgr.get_module_option = Mock(side_effect=settings.get)
