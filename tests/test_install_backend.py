import sys
import inspect

from unittest import TestCase

from apsconnectcli.apsconnect import APSConnectUtil
from tests.fakes import FakeK8sApi, FakeData, FakeErrors
from tests import utils

from apsconnectcli.awsmanager.aws import AWSClient
from apsconnectcli.awsmanager.ecr import ECRClient

if sys.version_info >= (3,):
    from unittest.mock import patch, mock_open, call, MagicMock
    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch, mock_open, call, MagicMock
    _BUILTINS_OPEN = 'apsconnectcli.apsconnect.open'
    _BUILTINS_PRINT = 'apsconnectcli.apsconnect.print'


def init_mocks(func):
    @patch('apsconnectcli.apsconnect._cluster_probe_connection')
    @patch('apsconnectcli.apsconnect._get_k8s_api_client')
    @patch('kubernetes.client.VersionApi')
    @patch('kubernetes.client.CoreV1Api')
    @patch('kubernetes.client.ExtensionsV1beta1Api')
    @patch('apsconnectcli.apsconnect._create_secret')
    @patch('apsconnectcli.apsconnect._create_deployment')
    @patch('apsconnectcli.apsconnect._create_service')
    @patch('apsconnectcli.apsconnect._create_ingress')
    @patch('apsconnectcli.apsconnect._polling_service_access')
    @patch('apsconnectcli.apsconnect._check_connector_backend_access')
    @patch('apsconnectcli.apsconnect._create_image_pull_secret')
    def mocked_fn(self,
                  create_image_pull_secret,
                  check_connector_backend_access,
                  polling_service_access,
                  create_ingress,
                  create_service,
                  create_deployment,
                  create_secret,
                  extensions_api,
                  core_api,
                  version_api,
                  get_k8s_client,
                  probe_conn):
        frame = inspect.currentframe()
        args, _, _, values = inspect.getargvalues(frame)
        mocks_dict = dict([(i, values[i]) for i in args if i != 'self'])
        return func(self, mocks_dict)

    return mocked_fn


class InstallBackendTest(TestCase):
    """Tests for apsconnect.install_backend"""

    _TEST_NAME = 'TEST NAME'

    def _read_valid_json(self):
        return mock_open(read_data=FakeData.VALID_JSON)

    def _check_bad_config(self, mock_reader):
        util = APSConnectUtil()
        with patch(_BUILTINS_OPEN, mock_reader) as mock_file:
            self.assertRaises(SystemExit,
                              util.install_backend,
                              name=self._TEST_NAME,
                              image='',
                              config_file=FakeData.CONFIG_PATH,
                              hostname='localhost')
            mock_file.assert_has_calls([call(FakeData.CONFIG_PATH)])

    def _check_internal_fn_causes_systemexit(self,
                                             mock_dict,
                                             expected_err_msg):
        mock_dict['get_k8s_client'].return_value = FakeK8sApi(False)
        mock_dict['version_api'].return_value = MagicMock()
        mock_dict['core_api'].return_value = MagicMock()
        mock_dict['extensions_api'].return_value = MagicMock()

        util = APSConnectUtil()

        with patch(_BUILTINS_PRINT) as mock_print:
            with patch(_BUILTINS_OPEN, self._read_valid_json()) as mock_file:
                self.assertRaises(SystemExit,
                                  util.install_backend,
                                  name=self._TEST_NAME,
                                  image='',
                                  config_file=FakeData.CONFIG_PATH,
                                  hostname='localhost')
                mock_file.assert_has_calls([call(FakeData.CONFIG_PATH)])
                mock_print.assert_called_with(expected_err_msg)

    def _setup_external_api_mocks(self, mocks_dict):
        mocks_dict['get_k8s_client'].return_value = FakeK8sApi(False)
        mocks_dict['version_api'].return_value = MagicMock()
        mocks_dict['core_api'].return_value = MagicMock()
        mocks_dict['extensions_api'].return_value = MagicMock()

    def _assert_create_deployment_call(self, mocks_dict, path):
        mocks_dict['create_deployment'].assert_called_once_with(
            self._TEST_NAME,
            '',
            mocks_dict['extensions_api'](),
            path,
            2,
            FakeData.DEFAULT_NAMESPACE,
            False,
            core_api=mocks_dict['core_api'](),
        )

    def test_config_file_read_failure(self):
        file_read_err_msg = 'File read error.'
        with patch(_BUILTINS_PRINT) as mock_print:
            with patch(_BUILTINS_OPEN, mock_open(read_data=None)) as mock_file:
                mock_file.side_effect = Exception(file_read_err_msg)
                util = APSConnectUtil()

                self.assertRaises(SystemExit,
                                  util.install_backend,
                                  name=self._TEST_NAME,
                                  image='',
                                  config_file=FakeData.CONFIG_PATH,
                                  hostname='localhost')
                err_msg = "Unable to read config file, error: {}".format(file_read_err_msg)
                mock_print.assert_called_with(err_msg)

    def test_unsupported_config(self):
        self._check_bad_config(
            mock_open(read_data=FakeData.CONFIG_WITH_UNSUPPORTED_FORMAT)
        )

    def test_bad_json(self):
        self._check_bad_config(
            mock_open(read_data=FakeData.BAD_JSON)
        )

    def test_bad_yaml(self):
        self._check_bad_config(
            mock_open(read_data=FakeData.BAD_YAML)
        )

    @init_mocks
    def test_when_create_secret_failed(self, mocks_dict):
        err_txt = 'encoding or errors without a string argument'
        mocks_dict['create_secret'].side_effect = utils.create_fn_raising_error(err_txt)

        exp_output = "Can't create config in cluster, error: {}".format(err_txt)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_create_deployment_is_failed(self, mocks_dict):
        mocks_dict['create_deployment'].side_effect = utils.create_fn_raising_error(
            FakeErrors.FAKE_ERR_MSG)

        exp_output = "Can't create deployment in cluster, error: {}".format(FakeErrors.FAKE_ERR_MSG)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_create_service_is_failed(self, mocks_dict):
        mocks_dict['create_service'].side_effect = utils.create_fn_raising_error(
            FakeErrors.FAKE_ERR_MSG)

        exp_output = "Can't create service in cluster, error: {}".format(FakeErrors.FAKE_ERR_MSG)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_create_ingress_is_failed(self, mocks_dict):
        mocks_dict['create_ingress'].side_effect = utils.create_fn_raising_error(
            FakeErrors.FAKE_ERR_MSG)

        exp_output = "Can't create ingress in cluster, error: {}".format(FakeErrors.FAKE_ERR_MSG)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_polling_service_access_is_failed(self, mocks_dict):
        mocks_dict['polling_service_access'].side_effect = utils.create_fn_raising_error(
            FakeErrors.FAKE_ERR_MSG)

        exp_output = 'Service expose FAILED, error: {}'.format(FakeErrors.FAKE_ERR_MSG)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_check_connector_backend_access_is_failed(self, mocks_dict):
        mocks_dict['check_connector_backend_access'].side_effect = utils.create_fn_raising_error(
            FakeErrors.FAKE_ERR_MSG)

        exp_output = 'Check connector backend host error: {}'.format(FakeErrors.FAKE_ERR_MSG)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_when_create_image_pull_secret_failed(self, mocks_dict):
        err_txt = 'encoding or errors without a string argument'
        mocks_dict['create_image_pull_secret'].side_effect = utils.create_fn_raising_error(err_txt)

        exp_output = "Can't create create image pull secret, error: {}".format(err_txt)
        self._check_internal_fn_causes_systemexit(mocks_dict, exp_output)

    @init_mocks
    def test_success_defaults(self, mocks_dict):
        test_root_path = '/'

        self._setup_external_api_mocks(mocks_dict)

        with patch(_BUILTINS_OPEN, self._read_valid_json()) as mock_file:
            with patch(_BUILTINS_PRINT) as mock_print:
                util = APSConnectUtil()
                util.install_backend(name=self._TEST_NAME,
                                     image='',
                                     config_file=FakeData.CONFIG_PATH,
                                     hostname='localhost',
                                     root_path=test_root_path)
                loading_file_msg = 'Loading config file: {}'.format(FakeData.CONFIG_PATH)
                connector_backend_msg = 'Connector backend - https://{}/'.format('localhost')
                mock_print.assert_has_calls([call(loading_file_msg),
                                             call('Create config [ok]'),
                                             call('Create deployment [ok]'),
                                             call('Create service [ok]'),
                                             call('Create ingress [ok]'),
                                             call('Checking service availability'),
                                             call('Expose service [ok]'),
                                             call('Checking connector backend availability'),
                                             call('Check connector backend host [ok]'),
                                             call(connector_backend_msg),
                                             call('[Success]')])
                mock_file.assert_has_calls([call(FakeData.CONFIG_PATH)])
                self._assert_create_deployment_call(mocks_dict, test_root_path)

    @init_mocks
    def test_success_healthcheck(self, mocks_dict):
        test_root_path = '/'
        test_healthcheck_path = '/healthchk_dir'
        healthcheck_warning = \
            "WARNING --healthcheck-path is deprecated and will be dropped in future releases." \
            " The connector should have the same value for root path and health check path."

        self._setup_external_api_mocks(mocks_dict)

        with patch(_BUILTINS_OPEN, self._read_valid_json()) as mock_file:
            with patch(_BUILTINS_PRINT) as mock_print:
                util = APSConnectUtil()
                util.install_backend(name=self._TEST_NAME,
                                     image='',
                                     config_file=FakeData.CONFIG_PATH,
                                     hostname='localhost',
                                     root_path=test_root_path,
                                     healthcheck_path=test_healthcheck_path)
                loading_file_msg = 'Loading config file: {}'.format(FakeData.CONFIG_PATH)
                connector_backend_msg = 'Connector backend - https://{}/'.format('localhost')
                mock_print.assert_has_calls([call(healthcheck_warning),
                                             call(loading_file_msg),
                                             call('Create config [ok]'),
                                             call('Create deployment [ok]'),
                                             call('Create service [ok]'),
                                             call('Create ingress [ok]'),
                                             call('Checking service availability'),
                                             call('Expose service [ok]'),
                                             call('Checking connector backend availability'),
                                             call('Check connector backend host [ok]'),
                                             call(connector_backend_msg),
                                             call('[Success]')])
                mock_file.assert_has_calls([call(FakeData.CONFIG_PATH)])
                self._assert_create_deployment_call(mocks_dict, test_healthcheck_path)
