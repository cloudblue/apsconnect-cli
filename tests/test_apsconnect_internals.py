import base64
import os
import sys
from pkg_resources import DistributionNotFound
from unittest import TestCase

from apsconnectcli.apsconnect import (
    KUBE_FILE_PATH,
    _assert_hub_version,
    _osaapi_raise_for_status,
    _get_cfg,
    _get_k8s_api_client,
    _get_properties,
    _get_resclass_name,
    _cluster_probe_connection,
    _create_secret,
    _create_deployment,
    _create_service,
    _extract_files,
    _to_bytes,
    bin_version,
    get_version,
)

from tests.fakes import FakeData, FakeK8sApi
from tests import utils

if sys.version_info >= (3,):
    from unittest.mock import patch, mock_open, call, MagicMock

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch, mock_open, call, MagicMock

    _BUILTINS_OPEN = 'apsconnectcli.apsconnect.open'
    _BUILTINS_PRINT = 'apsconnectcli.apsconnect.print'


class OsaApiRaiseForStatusTest(TestCase):
    """Tests for apsconnect._osaapi_raise_for_status"""

    _SUCCESS_CODE = 0
    _FAKE_ERR_CODE = 100500
    _FAKE_ERR_MSG = 'Not enough minerals.'

    def test_response_with_error_message(self):
        resp_with_err_msg = {
            'status': self._FAKE_ERR_CODE,
            'error_message': self._FAKE_ERR_MSG
        }
        self.assertRaisesRegexp(Exception,
                                r'Error: {}'.format(self._FAKE_ERR_MSG),
                                _osaapi_raise_for_status,
                                resp_with_err_msg)

    def test_response_with_status_without_err_msg(self):
        response = {
            'status': self._FAKE_ERR_CODE
        }
        self.assertRaisesRegexp(Exception,
                                r'Error: Unknown {}'.format(response),
                                _osaapi_raise_for_status,
                                response)

    def test_successful_response(self):
        response = {
            'status': self._SUCCESS_CODE
        }
        _osaapi_raise_for_status(response)  # no exceptions


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


class GetPropertiesTest(TestCase):
    """Tests for _get_properties"""

    def test_schema_with_properties_section(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.SCHEMA_JSON)) as mock_file:
            props = _get_properties(FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)
            self.assertEqual(FakeData.PROPERTIES, props)

    def test_schema_without_properties(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.BAD_SCHEMA_JSON)) as mock_file:
            self.assertRaises(SystemExit, _get_properties, FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)

    def test_bad_json(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.BAD_JSON)) as mock_file:
            self.assertRaises(SystemExit, _get_properties, FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)


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


class ResClassTest(TestCase):
    """Tests for _get_resclass_name()"""

    def test_get_resclass_name_for_current_units(self):
        data = {
            'Kbit/sec': 'rc.saas.resource.kbps',
            'kb': 'rc.saas.resource',
            'mb-h': 'rc.saas.resource.mbh',
            'mhz': 'rc.saas.resource.mhz',
            'mhzh': 'rc.saas.resource.mhzh',
            'unit': 'rc.saas.resource.unit',
            'unit-h': 'rc.saas.resource.unith'
        }

        for key, value in data.items():
            self.assertEqual(_get_resclass_name(key), value)

    def test_get_resclass_name_for_new_unit(self):
        self.assertEqual(
            _get_resclass_name('new-unit'),
            'rc.saas.resource.unit',
        )

    def test_get_resclass_name_witout_unit(self):
        self.assertEqual(
            _get_resclass_name(''),
            'rc.saas.resource.unit',
        )


class ExtractFilesTest(TestCase):
    def test_user_detected_correctly_if_user_schema(self):
        with patch('apsconnectcli.apsconnect.zipfile') as zipfile_mock:
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            package_info = _extract_files('zz', 'zz')
            self.assertTrue(package_info.user_service)

    def test_user_detected_correctly_if_user_user_schema(self):
        with patch('apsconnectcli.apsconnect.zipfile') as zipfile_mock:
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                if 'user' in filename and 'user.user' not in filename:
                    raise KeyError("Fail")
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            package_info = _extract_files('zz', 'zz')
            self.assertTrue(package_info.user_service)

    def test_user_detected_correctly_if_no_user_integration(self):
        with patch('apsconnectcli.apsconnect.zipfile') as zipfile_mock:
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                if 'user' in filename:
                    raise KeyError("Fail")
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            package_info = _extract_files('zz', 'zz')
            self.assertFalse(package_info.user_service)


class GetCfgTest(TestCase):
    def test_file_not_found(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            err = IOError()
            err.errno = 2
            open_mock.side_effect = err
            _get_cfg()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not find connected hub data."
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_file_other_ioerr(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            err = IOError("Error message text")
            err.errno = 13
            open_mock.side_effect = err
            _get_cfg()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not open configuration file"
                            in print_mock.call_args[0][0])
            self.assertTrue("Error message text"
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_file_unreadable(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.json') as json_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            json_mock.load.side_effect = ValueError()

            _get_cfg()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not parse the configuration file"
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_unexpected_error(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.json') as json_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            json_mock.load.side_effect = Exception("All is lost")

            _get_cfg()

            self.assertTrue(print_mock.called)
            self.assertTrue("All is lost" in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_ok(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.apsconnect.json') as json_mock, \
                patch('apsconnectcli.apsconnect.sys') as sys_mock:
            json_mock.load.return_value = "Config data"

            config = _get_cfg()

            self.assertEqual(config, "Config data")
            self.assertFalse(print_mock.called)
            sys_mock.exit.assert_not_called()


class AssertHubVersion(TestCase):
    def test_supported_version(self):
        with patch('apsconnectcli.apsconnect.sys') as sys_mock:
            _assert_hub_version('oa-7.13-1216')

            sys_mock.exit.assert_not_called()

    def test_unsupported_version(self):
        with patch('apsconnectcli.apsconnect.sys') as sys_mock:
            _assert_hub_version('oa-7.0-1216')

            sys_mock.exit.assert_called_with(1)


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
