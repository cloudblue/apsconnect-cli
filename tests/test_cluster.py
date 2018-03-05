import base64
import sys
from unittest import TestCase

from apsconnectcli.cluster import (
    check_containers_exist,
    error_report,
    get_log,
    poll_deployment,
    read_cluster_certificate,
)

if sys.version_info >= (3,):
    from unittest.mock import patch, MagicMock

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch, MagicMock

    _BUILTINS_OPEN = 'apsconnectcli.cluster.open'
    _BUILTINS_PRINT = 'apsconnectcli.cluster.print'


class TestClusterOperation(TestCase):
    def test_read_cluster_certificate_file_not_found(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch('apsconnectcli.cluster.sys') as sys_mock:
            open_mock.side_effect = Exception("All is lost")

            read_cluster_certificate(None)

        sys_mock.exit.assert_called_with(1)

    def test_read_cluster_certificate_ok(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch('apsconnectcli.cluster.sys') as sys_mock:
            _file = MagicMock()
            _file.read.return_value = "Certificate data"
            open_mock.return_value.__enter__.return_value = _file
            data = read_cluster_certificate(None)

        self.assertEqual(base64.b64decode(data).decode(), "Certificate data")
        sys_mock.exit.assert_not_called()

    def test_check_containers_exist_ok(self):
        api_mock = MagicMock()

        pods_mock = MagicMock()
        pod_mock = MagicMock()

        broken_pods_mock = MagicMock()
        broken_pod_mock = MagicMock()
        pod_mock.status.container_statuses = True
        broken_pod_mock.status.container_statuses = False

        pods_mock.items = [pod_mock]
        broken_pods_mock.items = [broken_pod_mock]

        api_mock.list_namespaced_pod.side_effect = [broken_pods_mock, broken_pods_mock, pods_mock]
        with patch('apsconnectcli.cluster.sleep'):
            result = check_containers_exist(api_mock, 'namespace', 'name')
        self.assertTrue(result)
        self.assertEqual(api_mock.list_namespaced_pod.call_count, 3)

    def test_check_containers_exist_error(self):
        api_mock = MagicMock()

        broken_pods_mock = MagicMock()
        broken_pod_mock = MagicMock()
        broken_pod_mock.status.container_statuses = False
        broken_pods_mock.items = [broken_pod_mock]

        api_mock.list_namespaced_pod.return_value = broken_pods_mock
        with patch('apsconnectcli.cluster.sleep'):
            result = check_containers_exist(api_mock, 'namespace', 'name', num_retries=7)
        self.assertFalse(result)
        self.assertEqual(api_mock.list_namespaced_pod.call_count, 7)

    def test_get_log(self):
        api_mock = MagicMock()
        api_mock.read_namespaced_pod_log.return_value = 'LOG'

        log = get_log('name', api_mock, 'namespace')
        self.assertEqual(log, 'LOG')

    def test_error_report_generic(self):
        with patch('apsconnectcli.cluster.get_log'):
            message = error_report('name', MagicMock(), 'default',
                                   'SomeErrorCode', 'SomeErrorMessage')

        self.assertTrue('SomeError' in message)
        self.assertTrue('SomeErrorMessage' in message)

    def test_error_report_crashloopbackoff(self):
        with patch('apsconnectcli.cluster.get_log') as log_mock:
            log_mock.return_value = 'LOG'
            message = error_report('name', MagicMock(), 'default',
                                   'CrashLoopBackOff', 'SomeErrorMessage')

        self.assertTrue('Container failed to start' in message)
        self.assertTrue('LOG' in message)

    def test_poll_deployment_ok(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertTrue(result.available)
        self.assertEqual(result.message, 'Deployment has just become available')

    def test_poll_deployment_no_containers(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        with patch('apsconnectcli.cluster.check_containers_exist') as exist_mock:
            exist_mock.return_value = False
            ext_v1_mock.read_namespaced_deployment.return_value.status.available_replicas = False
            result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertFalse(result.available)
        self.assertTrue('No containers available' in result.message)

    def test_poll_deployment_too_many_restarts(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        pod_mock = MagicMock()
        status_mock = MagicMock()
        status_mock.restart_count = 10
        condition_mock = MagicMock()
        condition_mock.type = 'Ready'
        condition_mock.status = 'False'
        condition_mock.reason = 'ContainersNotReady'

        pod_mock.status.conditions = [condition_mock, ]
        pod_mock.status.container_statuses = [status_mock, ]

        with patch('apsconnectcli.cluster.get_log') as log_mock:
            log_mock.return_value = 'LOG'
            ext_v1_mock.read_namespaced_deployment.return_value.status.available_replicas = False
            core_v1_mock.list_namespaced_pod.return_value.items = [pod_mock]
            result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertFalse(result.available)
        self.assertTrue('Readiness check failed' in result.message)
        self.assertTrue('LOG' in result.message)

    def test_poll_deployment_waiting_error(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        pod_mock = MagicMock()

        status_mock = MagicMock()
        status_mock.restart_count = 0
        condition_mock = MagicMock()
        condition_mock.type = 'Ready'
        condition_mock.status = 'True'

        pod_mock.status.conditions = [condition_mock, ]
        states_mock = MagicMock()
        states_mock.state.waiting.reason = 'InvalidImageName'
        states_mock.state.waiting.message = 'SomeErrorMessage'

        pod_mock.status.container_statuses = [states_mock, ]

        with patch('apsconnectcli.cluster.get_log') as log_mock:
            log_mock.return_value = 'LOG'
            ext_v1_mock.read_namespaced_deployment.return_value.status.available_replicas = False
            core_v1_mock.list_namespaced_pod.return_value.items = [pod_mock]
            result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertFalse(result.available)
        self.assertTrue('InvalidImageName' in result.message)
        self.assertTrue('SomeErrorMessage' in result.message)

    def test_poll_deployment_waiting_unexpected(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        pod_mock = MagicMock()

        status_mock = MagicMock()
        status_mock.restart_count = 0
        condition_mock = MagicMock()
        condition_mock.type = 'Ready'
        condition_mock.status = 'True'

        pod_mock.status.conditions = [condition_mock, ]
        states_mock = MagicMock()
        states_mock.state.waiting.reason = 'SomeWeirdError'
        states_mock.state.waiting.message = 'SomeErrorMessage'

        pod_mock.status.container_statuses = [states_mock, ]

        with patch('apsconnectcli.cluster.get_log') as log_mock:
            log_mock.return_value = 'LOG'
            ext_v1_mock.read_namespaced_deployment.return_value.status.available_replicas = False
            core_v1_mock.list_namespaced_pod.return_value.items = [pod_mock]
            result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertFalse(result.available)
        self.assertTrue('Unexpected error' in result.message)
        self.assertTrue('SomeWeirdError' in result.message)
        self.assertTrue('SomeErrorMessage' in result.message)

    def test_poll_deployment_timeout(self):
        core_v1_mock = MagicMock()
        ext_v1_mock = MagicMock()

        pod_mock = MagicMock()

        status_mock = MagicMock()
        status_mock.restart_count = 0
        condition_mock = MagicMock()
        condition_mock.type = 'Ready'
        condition_mock.status = 'True'

        pod_mock.status.conditions = [condition_mock, ]
        states_mock = MagicMock()
        states_mock.state.waiting = None

        pod_mock.status.container_statuses = [states_mock, ]

        with patch('apsconnectcli.cluster.sleep'), \
            patch('apsconnectcli.cluster.sys'), \
            patch('apsconnectcli.cluster.datetime') as datetime_mock, \
                patch('apsconnectcli.cluster.timedelta') as timedelta_mock:
            datetime_mock.now.side_effect = [0, 100]
            timedelta_mock.return_value = 0
            ext_v1_mock.read_namespaced_deployment.return_value.status.available_replicas = False
            core_v1_mock.list_namespaced_pod.return_value.items = [pod_mock]
            result = poll_deployment(core_v1_mock, ext_v1_mock, 'namespace', 'name')

        self.assertFalse(result.available)
        self.assertTrue('Timed out' in result.message)
