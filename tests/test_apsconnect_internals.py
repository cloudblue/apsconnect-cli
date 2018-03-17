import base64
import os
import sys
from pkg_resources import DistributionNotFound
from unittest import TestCase

from apsconnectcli.apsconnect import (
    GITHUB_RELEASES_PAGE,
    KUBE_FILE_PATH,
    _get_k8s_api_client,
    _cluster_probe_connection,
    _create_secret,
    _create_deployment,
    _create_service,
    _to_bytes,
    bin_version,
    get_version,
    get_latest_version,
    main,
    APSConnectUtil,
)

from apsconnectcli.cluster import AvailabilityCheckResult

from tests.fakes import FakeData, FakeK8sApi
from tests import utils

if sys.version_info >= (3,):
    from unittest.mock import patch, call, MagicMock

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch, call, MagicMock

    _BUILTINS_OPEN = 'apsconnectcli.apsconnect.open'
    _BUILTINS_PRINT = 'apsconnectcli.apsconnect.print'


class GetK8sApiClientTest(TestCase):
    """Tests for _get_k8s_api_client"""

    @patch('kubernetes.config.new_client_from_config')
    def test_default_config(self, config_mock):
        _get_k8s_api_client()
        config_mock.assert_called_once_with(config_file=KUBE_FILE_PATH)

    @patch('kubernetes.config.new_client_from_config')
    def test_custom_config(self, config_mock):
        custom_file_path = '/tmp/kube_config'
        _get_k8s_api_client(custom_file_path)
        config_mock.assert_called_once_with(config_file=custom_file_path)


class ClusterProbeConnectionTest(TestCase):
    """Tests for _cluster_probe_connection"""
    DEFAULT_K8S_NAME = 'k8s-srv-42'

    def test_no_connection_with_k8s(self):
        mock_api_client = MagicMock()
        mock_api_client.host = self.DEFAULT_K8S_NAME
        mock_ver_api = FakeK8sApi(True)
        self.assertRaises(SystemExit,
                          _cluster_probe_connection,
                          api=mock_ver_api,
                          api_client=mock_api_client)

    def test_success(self):
        mock_ver_api = FakeK8sApi(False)
        mock_api_client = MagicMock()
        mock_api_client.host = self.DEFAULT_K8S_NAME
        with patch(_BUILTINS_PRINT) as mock_print:
            _cluster_probe_connection(mock_ver_api, mock_api_client)
            mock_print.assert_called_once_with("Connect {} [ok]".format(self.DEFAULT_K8S_NAME))


class CreateSecretTest(TestCase):
    """Tests for _create_secret"""

    def _create_secret_dict(self, name, config):
        return {
            'apiVersion': 'v1',
            'data': {
                'config.yml': base64.b64encode(_to_bytes(config)).decode(),
            },
            'kind': 'Secret',
            'metadata': {
                'name': name,
            },
            'type': 'Opaque',
        }

    def _perform_check(self, dformat, data_str, namespace=None):
        fake_api = MagicMock()
        test_name = 'TEST'
        test_body = self._create_secret_dict(test_name, data_str)

        if namespace is not None:
            test_namespace = namespace
            _create_secret(name=test_name,
                           data_format=dformat,
                           data=FakeData.SCHEMA_DICT,
                           api=fake_api,
                           namespace=test_namespace)
        else:
            test_namespace = FakeData.DEFAULT_NAMESPACE
            _create_secret(name=test_name,
                           data_format=dformat,
                           data=FakeData.SCHEMA_DICT,
                           api=fake_api)

        fake_api.delete_namespaced_secret.assert_not_called()
        fake_api.create_namespaced_secret.assert_called_once_with(namespace=test_namespace,
                                                                  body=test_body)

    def test_json(self):
        self._perform_check('json', FakeData.SCHEMA_JSON)

    def test_yaml(self):
        self._perform_check('yaml', FakeData.SCHEMA_YAML)

    def test_unsupported_format(self):
        fake_api = MagicMock()
        test_name = 'TEST'
        unsupported_format = 'xml'
        self.assertRaisesRegexp(Exception,
                                r'Unknown config data format: {}'.format(unsupported_format),
                                _create_secret,
                                name=test_name,
                                data_format=unsupported_format,
                                data=FakeData.SCHEMA_DICT,
                                api=fake_api)

    def test_custom_namespace(self):
        self._perform_check('yaml', FakeData.SCHEMA_YAML, namespace='custom_namespace')

    @patch('kubernetes.client.V1DeleteOptions')
    def test_force_creation(self, mock_del_opts):
        fake_api = MagicMock()
        test_name = 'TEST'
        test_body = self._create_secret_dict(test_name, FakeData.SCHEMA_YAML)

        _create_secret(name=test_name,
                       data_format='yaml',
                       data=FakeData.SCHEMA_DICT,
                       api=fake_api,
                       force=True)
        fake_api.delete_namespaced_secret.assert_called_once_with(
            name=test_name,
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=mock_del_opts(),
        )
        fake_api.create_namespaced_secret.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=test_body,
        )


class CreateDeploymentBaseTest(TestCase):
    """Superclass for _create_deployment/_delete_deployment tests."""

    _TEST_NAME = 'TEST'
    _FAKE_DEL_OPTS = {'no-promt': True, 'recursive': True}
    _EXP_LBL_SEL = 'name={}'.format(_TEST_NAME)

    def _create_test_body(self, name, replicas, image, healthcheck_path):
        return {
            'apiVersion': 'extensions/v1beta1',
            'kind': 'Deployment',
            'metadata': {
                'name': name,
            },
            'spec': {
                'replicas': replicas,
                'template': {
                    'metadata': {
                        'labels': {
                            'name': name,
                        },
                    },
                    'spec': {
                        'containers': [
                            {
                                'name': name,
                                'image': image,
                                'env': [
                                    {
                                        'name': 'CONFIG_FILE',
                                        'value': '/config/config.yml',
                                    },
                                ],
                                'livenessProbe': {
                                    'httpGet': {
                                        'path': healthcheck_path,
                                        'port': 80,
                                    },
                                },
                                'readinessProbe': {
                                    'httpGet': {
                                        'path': healthcheck_path,
                                        'port': 80,
                                    },
                                },
                                'ports': [
                                    {
                                        'containerPort': 80,
                                        'name': 'http-server',
                                    },
                                ],
                                'resources': {
                                    'requests': {
                                        'cpu': '100m',
                                        'memory': '128Mi',
                                    },
                                    'limits': {
                                        'cpu': '200m',
                                        'memory': '256Mi',
                                    },
                                },
                                'volumeMounts': [
                                    {
                                        'mountPath': '/config',
                                        'name': 'config-volume',
                                    },
                                ],
                            },
                        ],
                        'volumes': [
                            {
                                'name': 'config-volume',
                                'secret': {
                                    'secretName': name,
                                },
                            },
                        ],
                    },
                },
            },
        }

    def _create_fake_core_v1_with_empty_pods(self):
        fake_core_v1 = MagicMock()
        fake_pods = MagicMock()
        fake_core_v1.list_namespaced_pod.return_value = fake_pods
        return fake_core_v1

    def _create_fake_ext_api_with_empty_replicas(self):
        fake_ext_v1 = MagicMock()
        fake_replica_set = MagicMock()
        fake_ext_v1.list_namespaced_replica_set.return_value = fake_replica_set
        return fake_ext_v1

    def _assert_ext_v1_called_for_fresh_deployment(self, fake_ext_v1, test_body):
        fake_ext_v1.delete_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            name=self._TEST_NAME,
            body=self._FAKE_DEL_OPTS,
            grace_period_seconds=0)
        fake_ext_v1.list_namespaced_replica_set.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL)
        fake_ext_v1.delete_namespaced_replica_set.assert_not_called()
        fake_ext_v1.create_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=test_body)

    def _assert_core_v1_called_for_fresh_deployment(self, fake_core_v1):
        fake_core_v1.list_namespaced_pod.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL)
        fake_core_v1.delete_namespaced_pod.assert_not_called()

    @patch('kubernetes.client.V1DeleteOptions')
    def _perform_check(self,
                       mock_get_del_opts,
                       is_force,
                       fake_core_v1,
                       fake_ext_v1,
                       assert_ext_v1_fn,
                       assert_core_v1_fn):
        mock_get_del_opts.return_value = self._FAKE_DEL_OPTS

        dummy_str = '1q2w3e4r5t!Q@W#E$R%T^Y'
        replicas_count = 2
        test_image = _to_bytes(dummy_str)
        test_body = self._create_test_body(self._TEST_NAME, replicas_count, test_image, '/')

        _create_deployment(name=self._TEST_NAME,
                           image=test_image,
                           api=fake_ext_v1,
                           core_api=fake_core_v1,
                           force=is_force)

        assert_ext_v1_fn(fake_ext_v1, test_body)
        assert_core_v1_fn(fake_core_v1)


class CreateNewDeploymentTest(CreateDeploymentBaseTest):
    """Tests for _create_deployment when it is a new deployment."""

    def _assert_ext_v1_called_only_create(self, fake_ext_v1, test_body):
        fake_ext_v1.delete_namespaced_deployment.assert_not_called()
        fake_ext_v1.list_namespaced_replica_set.assert_not_called()
        fake_ext_v1.delete_namespaced_replica_set.assert_not_called()
        fake_ext_v1.create_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=test_body,
        )

    def _assert_core_v1_not_called(self, fake_core_v1):
        fake_core_v1.list_namespaced_pod.assert_not_called()
        fake_core_v1.delete_namespaced_pod.assert_not_called()

    def test_soft_creation(self):
        self._perform_check(is_force=False,
                            fake_core_v1=self._create_fake_core_v1_with_empty_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_empty_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_only_create,
                            assert_core_v1_fn=self._assert_core_v1_not_called)

    def test_force_creation(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_empty_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_empty_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_fresh_deployment,
                            assert_core_v1_fn=self._assert_core_v1_called_for_fresh_deployment)


class CreateDeploymentOverExistingItemsTest(CreateDeploymentBaseTest):
    """Tests for _create_deployment over existing one with pods and/or replicas."""

    _REPLICA_NAME = 'rs-451'
    _POD_1_NAME = 'pod-1984'
    _POD_2_NAME = 'pod-42'

    def _create_fake_core_v1_with_pods(self):
        fake_core_v1 = MagicMock()

        fake_pods = MagicMock()
        fake_pods.items = [
            utils.create_pod(self._POD_1_NAME),
            utils.create_pod(self._POD_2_NAME),
        ]
        fake_core_v1.list_namespaced_pod.return_value = fake_pods

        return fake_core_v1

    def _create_fake_core_v1(self):
        fake_core_v1 = MagicMock()

        fake_pods = MagicMock()
        fake_core_v1.list_namespaced_pod.return_value = fake_pods

        return fake_core_v1

    def _create_fake_core_v1_with_none_pods(self):
        fake_core_v1 = MagicMock()
        fake_core_v1.list_namespaced_pod.return_value = None
        return fake_core_v1

    def _create_fake_ext_api_with_replicas(self):
        fake_ext_v1 = MagicMock()

        fake_replica_set = MagicMock()
        fake_replica_set.items = [
            utils.create_replica(self._REPLICA_NAME)
        ]
        fake_ext_v1.list_namespaced_replica_set.return_value = fake_replica_set

        return fake_ext_v1

    def _create_fake_ext_api_with_none_replica_set(self):
        fake_ext_v1 = MagicMock()
        fake_ext_v1.list_namespaced_replica_set.return_value = None
        return fake_ext_v1

    def _assert_ext_v1_called_for_replicas(self, fake_ext_v1, test_body):
        fake_ext_v1.delete_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            name=self._TEST_NAME,
            body=self._FAKE_DEL_OPTS,
            grace_period_seconds=0)
        fake_ext_v1.list_namespaced_replica_set.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL)
        fake_ext_v1.delete_namespaced_replica_set.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            name=self._REPLICA_NAME,
            body=self._FAKE_DEL_OPTS,
            grace_period_seconds=0)
        fake_ext_v1.create_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=test_body)

    def _assert_ext_v1_calls(self, fake_ext_v1, test_body):
        fake_ext_v1.delete_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            name=self._TEST_NAME,
            body=self._FAKE_DEL_OPTS,
            grace_period_seconds=0)
        fake_ext_v1.list_namespaced_replica_set.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL)
        fake_ext_v1.delete_namespaced_replica_set.assert_not_called()
        fake_ext_v1.create_namespaced_deployment.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            body=test_body)

    def _assert_core_v1_called_for_pods(self, fake_core_v1):
        fake_core_v1.list_namespaced_pod.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL,
        )
        fake_core_v1.delete_namespaced_pod.assert_has_calls([
            call(namespace=FakeData.DEFAULT_NAMESPACE,
                 name='pod-1984',
                 body=self._FAKE_DEL_OPTS,
                 grace_period_seconds=0),
            call(namespace=FakeData.DEFAULT_NAMESPACE,
                 name='pod-42',
                 body=self._FAKE_DEL_OPTS,
                 grace_period_seconds=0)])

    def _assert_core_v1_calls(self, fake_core_v1):
        fake_core_v1.list_namespaced_pod.assert_called_once_with(
            namespace=FakeData.DEFAULT_NAMESPACE,
            label_selector=self._EXP_LBL_SEL,
        )
        fake_core_v1.delete_namespaced_pod.assert_not_called()

    def test_creation_over_replicas_and_pods(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_replicas,
                            assert_core_v1_fn=self._assert_core_v1_called_for_pods)

    def test_creation_over_replicas(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_empty_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_replicas,
                            assert_core_v1_fn=self._assert_core_v1_called_for_fresh_deployment)

    def test_creation_over_replicas_and_bad_pods(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_none_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_replicas,
                            assert_core_v1_fn=self._assert_core_v1_called_for_fresh_deployment)

    def test_creation_over_pods(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_empty_replicas(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_fresh_deployment,
                            assert_core_v1_fn=self._assert_core_v1_called_for_pods)

    def test_creation_over_pods_and_bad_replicas(self):
        self._perform_check(is_force=True,
                            fake_core_v1=self._create_fake_core_v1_with_pods(),
                            fake_ext_v1=self._create_fake_ext_api_with_none_replica_set(),
                            assert_ext_v1_fn=self._assert_ext_v1_called_for_fresh_deployment,
                            assert_core_v1_fn=self._assert_core_v1_called_for_pods)


class CreateDeploymentPollingTest(TestCase):
    def test_poll_ok(self):
        api = MagicMock()
        with patch('apsconnectcli.apsconnect.poll_deployment') as poll_deployment_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            poll_deployment_mock.return_value = AvailabilityCheckResult(True, 'OK')
            _create_deployment('name', 'image', api)
            self.assertTrue(poll_deployment_mock.called)
            sys_mock.exit.assert_not_called()

    def test_poll_error(self):
        api = MagicMock()
        with patch('apsconnectcli.apsconnect.poll_deployment') as poll_deployment_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            poll_deployment_mock.return_value = AvailabilityCheckResult(False, 'Error')
            _create_deployment('name', 'image', api)
            self.assertTrue(poll_deployment_mock.called)
            sys_mock.exit.assert_called_with(1)


class CreateServiceTest(TestCase):
    """Tests for _create_service()"""

    def _create_body(self, name):
        return {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'labels': {
                    'name': name,
                },
                'name': name,
            },
            'spec': {
                'ports': [
                    {
                        'port': 80,
                        'protocol': 'TCP',
                        'targetPort': 80,
                    }
                ],
                'selector': {
                    'name': name
                },
                'type': 'ClusterIP'
            }
        }

    def test_soft_creation(self):
        fake_core_v1 = MagicMock()
        namespace = FakeData.DEFAULT_NAMESPACE
        service_name = 'Test service'
        service = self._create_body(service_name)

        _create_service(service_name, fake_core_v1, namespace, force=False)

        fake_core_v1.create_namespaced_service.assert_called_once_with(
            namespace=namespace, body=service)

    def test_force_creation(self):
        fake_core_v1 = MagicMock()
        namespace = FakeData.DEFAULT_NAMESPACE
        service_name = 'Test service'
        service = self._create_body(service_name)
        deletion_kwargs = {'namespace': namespace, 'name': service_name}

        _create_service(service_name, fake_core_v1, namespace, force=True)

        fake_core_v1.delete_namespaced_service.assert_called_once_with(**deletion_kwargs)
        fake_core_v1.create_namespaced_service.assert_called_once_with(
            namespace=namespace, body=service)


class TestVersion(TestCase):
    def test_latest_version(self):
        with patch('apsconnectcli.apsconnect.get_version') as version_mock, \
            patch('apsconnectcli.apsconnect.get_latest_version') as latest_version_mock, \
                patch(_BUILTINS_PRINT) as print_mock:

            version_mock.return_value = '1.2.3'
            latest_version_mock.return_value = '1.2.3'
            APSConnectUtil().version()

        self.assertEqual(print_mock.call_count, 1)
        self.assertTrue('1.2.3' in print_mock.call_args[0][0])

    def test_outdated_version(self):
        with patch('apsconnectcli.apsconnect.get_version') as version_mock, \
            patch('apsconnectcli.apsconnect.get_latest_version') as latest_version_mock, \
                patch(_BUILTINS_PRINT) as print_mock:

            version_mock.return_value = '1.2.3'
            latest_version_mock.return_value = '1.2.4'
            APSConnectUtil().version()

        self.assertEqual(print_mock.call_count, 2)
        self.assertTrue('1.2.4' in print_mock.call_args[0][0])

    def test_unknown_version(self):
        with patch('apsconnectcli.apsconnect.get_version') as version_mock, \
            patch('apsconnectcli.apsconnect.get_latest_version'), \
                patch(_BUILTINS_PRINT) as print_mock:

            version_mock.return_value = None

            APSConnectUtil().version()

        self.assertEqual(print_mock.call_count, 1)
        self.assertTrue(GITHUB_RELEASES_PAGE in print_mock.call_args[0][0])


class TestHelpers(TestCase):
    def test_bin_version_ok(self):
        with patch('apsconnectcli.apsconnect.sys') as sys_mock, \
                patch(_BUILTINS_OPEN) as open_mock:
            open_mock.return_value.__enter__.return_value.read.return_value = 'v100500'
            sys_mock._MEIPASS = 'pyinstaller_data_dir'
            result = bin_version()

        open_mock.assert_called_once_with(os.path.join(sys_mock._MEIPASS, 'VERSION'))
        self.assertEqual(result, 'v100500')

    def test_bin_version_exception(self):
        self.assertEqual(bin_version(), None)

    def test_get_version_from_package_ok(self):
        with patch('apsconnectcli.apsconnect.pkg_resources') as pkg_mock:
            pkg_mock.get_distribution.return_value.version = 'v100500'
            result = get_version()

        self.assertEqual(result, 'v100500')

    def test_get_version_from_package_error(self):
        with patch('apsconnectcli.apsconnect.pkg_resources') as pkg_mock, \
                patch('apsconnectcli.apsconnect.bin_version') as bin_mock:
            bin_mock.return_value = 'v100500'
            pkg_mock.DistributionNotFound = DistributionNotFound
            pkg_mock.get_distribution.side_effect = DistributionNotFound()
            result = get_version()

        self.assertEqual(result, 'v100500')

    def test_get_latest_version_ok(self):
        with patch('apsconnectcli.apsconnect.get') as get_mock:
            get_mock.return_value.json.return_value = {'tag_name': 'v123'}
            result = get_latest_version()

        self.assertEqual(result, '123')

    def test_get_latest_version_error(self):
        with patch('apsconnectcli.apsconnect.get') as get_mock:
            get_mock.return_value = 'Definitely not JSON'
            result = get_latest_version()

        self.assertIsNone(result)

    def test_main_prints_version(self):
        with patch('apsconnectcli.apsconnect.fire'), \
             patch('apsconnectcli.apsconnect.get_version') as get_version_mock, \
                patch(_BUILTINS_PRINT) as print_mock:

            get_version_mock.return_value = '100.500'
            main()

        self.assertTrue('100.500' in print_mock.call_args[0][0])

    def test_main_prints_error_and_exists_if_there_are_problems(self):
        with patch('apsconnectcli.apsconnect.fire') as fire_mock, \
                patch('apsconnectcli.apsconnect.get_version'), \
                patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:

            fire_mock.Fire.side_effect = Exception('All is lost')
            main()

        self.assertTrue('All is lost' in print_mock.call_args[0][0])
        sys_mock.exit.assert_called_once_with(1)
