import sys
from unittest import TestCase

from mock import MagicMock, patch

from apsconnectcli.apsconnect import APSConnectUtil
from apsconnectcli.hub import APS, Hub, osaapi_raise_for_status

if sys.version_info >= (3,):
    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
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
                                osaapi_raise_for_status,
                                resp_with_err_msg)

    def test_response_with_status_without_err_msg(self):
        response = {
            'status': self._FAKE_ERR_CODE
        }
        self.assertRaisesRegexp(Exception,
                                r'Error: Unknown {}'.format(response),
                                osaapi_raise_for_status,
                                response)

    def test_successful_response(self):
        response = {
            'status': self._SUCCESS_CODE
        }
        osaapi_raise_for_status(response)  # no exceptions


class TestHub(TestCase):
    def test_supported_version(self):
        with patch('apsconnectcli.hub.sys') as sys_mock:
            Hub._assert_supported_version('oa-8.2-1216')

            sys_mock.exit.assert_not_called()

    def test_unsupported_version(self):
        with patch('apsconnectcli.hub.sys') as sys_mock:
            Hub._assert_supported_version('oa-7.0-1216')

            sys_mock.exit.assert_called_with(1)

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
            self.assertEqual(Hub._get_resclass_name(key), value)

    def test_get_resclass_name_for_new_unit(self):
        self.assertEqual(
            Hub._get_resclass_name('new-unit'),
            'rc.saas.resource.unit',
        )

    def test_get_resclass_name_without_unit(self):
        self.assertEqual(
            Hub._get_resclass_name(''),
            'rc.saas.resource.unit',
        )

    def test_hub_init(self):
        with patch('apsconnectcli.hub.osaapi'), \
                patch('apsconnectcli.hub.APS') as aps_mock, \
                patch('apsconnectcli.hub.get_config'), \
                patch('apsconnectcli.hub.osaapi_raise_for_status'):
            resp_mock = MagicMock()
            resp_mock.content = b'[{"aps": {"id": "12345"}}]'
            aps_mock.return_value.get.return_value = resp_mock

            hub = Hub()

            self.assertEqual(hub.hub_id, '12345')

    def test_get_hub_version(self):
        with patch('apsconnectcli.hub.xml_et') as xml_mock, \
                patch('apsconnectcli.hub.osaapi_raise_for_status'):
            api = MagicMock()
            xml_mock.fromstring.return_value.find.return_value.text = 'test'

            version = Hub._get_hub_version(api)

        self.assertEqual(version, 'test')
        xml_mock.fromstring.return_value.find.assert_called()
        self.assertEqual(xml_mock.fromstring.return_value.find.call_args[0][0], 'Build/Build')

    def test_hub_incorrect_id(self):
        with patch('apsconnectcli.hub.osaapi'), \
                patch('apsconnectcli.hub.APS') as aps_mock, \
                patch('apsconnectcli.hub.get_config'), \
                patch('apsconnectcli.hub.osaapi_raise_for_status'), \
                patch('apsconnectcli.hub.sys') as sys_mock:
            sys_mock.version_info.major = sys.version_info.major
            sys_mock.version_info.minor = sys.version_info.minor
            resp_mock = MagicMock()
            resp_mock.content = b'["aps": {"id": "12345"}}]'
            aps_mock.return_value.get.return_value = resp_mock

            Hub()

            sys_mock.exit.assert_called_with(1)

    def test_import_package_http(self):
        with patch('apsconnectcli.hub.osaapi') as api_mock, \
                patch('apsconnectcli.hub.APS') as aps_mock, \
                patch('apsconnectcli.hub.get_config'), \
                patch('apsconnectcli.hub.osaapi_raise_for_status'):
            resp_mock = MagicMock()
            resp_mock.content = b'[{"aps": {"id": "12345"}}]'
            aps_mock.return_value.get.return_value = resp_mock

            hub = Hub()

            package = MagicMock()
            package.http = True
            package.source = 'http_source'
            package.body = 'package_body'

            hub.import_package(package)

            import_mock = api_mock.OSA.return_value.APS.importPackage

            import_mock.assert_called()
            self.assertEqual(import_mock.call_args[1].get('package_url', ''), 'http_source')

    def test_import_package_body(self):
        with patch('apsconnectcli.hub.osaapi') as api_mock, \
                patch('apsconnectcli.hub.APS') as aps_mock, \
                patch('apsconnectcli.hub.get_config'), \
                patch('apsconnectcli.hub.osaapi_raise_for_status'):
            resp_mock = MagicMock()
            resp_mock.content = b'[{"aps": {"id": "12345"}}]'
            aps_mock.return_value.get.return_value = resp_mock

            hub = Hub()

            package = MagicMock()
            package.is_http = False
            package.source = 'http_source'
            package.body = 'package_body'

            hub.import_package(package)

            import_mock = api_mock.OSA.return_value.APS.importPackage

            import_mock.assert_called()
            self.assertEqual(import_mock.call_args[1].get('package_body', ''), 'package_body')


class TestAPS(TestCase):
    def test_init(self):
        with patch('apsconnectcli.hub.get_config') as config_mock:
            config_mock.return_value = {
                'use_tls_aps': True,
                'aps_host': 'aps_host',
                'aps_port': 'aps_port'
            }
            aps = APS('token')
            self.assertEqual(aps.token, 'token')
            self.assertEqual(aps.url, 'https://aps_host:aps_port')

    def test_get(self):
        with patch('apsconnectcli.hub.get_config') as config_mock, \
                patch('apsconnectcli.hub.requests') as requests_mock:
            config_mock.return_value = {
                'use_tls_aps': True,
                'aps_host': 'aps_host',
                'aps_port': 'aps_port'
            }
            aps = APS('token')

            aps.get('test')

        requests_mock.get.assert_called()
        self.assertEqual(requests_mock.get.call_args[1].get('headers'), 'token')
        self.assertEqual(requests_mock.get.call_args[1].get('verify'), False)
        self.assertEqual(requests_mock.get.call_args[0][0], 'https://aps_host:aps_port/test')

    def test_post(self):
        with patch('apsconnectcli.hub.get_config') as config_mock, \
                patch('apsconnectcli.hub.requests') as requests_mock:
            config_mock.return_value = {
                'use_tls_aps': True,
                'aps_host': 'aps_host',
                'aps_port': 'aps_port'
            }
            aps = APS('token')

            aps.post('test', 'json')

        requests_mock.post.assert_called()
        self.assertEqual(requests_mock.post.call_args[1].get('headers'), 'token')
        self.assertEqual(requests_mock.post.call_args[1].get('json'), 'json')
        self.assertEqual(requests_mock.post.call_args[1].get('verify'), False)
        self.assertEqual(requests_mock.post.call_args[0][0], 'https://aps_host:aps_port/test')

    def test_put(self):
        with patch('apsconnectcli.hub.get_config') as config_mock, \
                patch('apsconnectcli.hub.requests') as requests_mock:
            config_mock.return_value = {
                'use_tls_aps': True,
                'aps_host': 'aps_host',
                'aps_port': 'aps_port'
            }
            aps = APS('token')

            aps.put('test', 'json')

        requests_mock.put.assert_called()
        self.assertEqual(requests_mock.put.call_args[1].get('headers'), 'token')
        self.assertEqual(requests_mock.put.call_args[1].get('json'), 'json')
        self.assertEqual(requests_mock.put.call_args[1].get('verify'), False)
        self.assertEqual(requests_mock.put.call_args[0][0], 'https://aps_host:aps_port/test')

    def test_delete(self):
        with patch('apsconnectcli.hub.get_config') as config_mock, \
                patch('apsconnectcli.hub.requests') as requests_mock:
            config_mock.return_value = {
                'use_tls_aps': True,
                'aps_host': 'aps_host',
                'aps_port': 'aps_port'
            }
            aps = APS('token')

            aps.delete('test')

        requests_mock.delete.assert_called()
        self.assertEqual(requests_mock.delete.call_args[1].get('headers'), 'token')
        self.assertEqual(requests_mock.delete.call_args[1].get('verify'), False)
        self.assertEqual(requests_mock.delete.call_args[0][0], 'https://aps_host:aps_port/test')


class TestApsConnectUtilHubCommands(TestCase):
    @patch('apsconnectcli.apsconnect.Hub')
    def test_hub_token(self, hub_cls):
        with patch(_BUILTINS_PRINT) as mock_print:
            expected_hub_token = '359b67d3-fdd7-4e90-a891-b909734fb64a'
            hub_mock = MagicMock()
            hub_mock.hub_id = expected_hub_token
            hub_cls.return_value = hub_mock

            util = APSConnectUtil()
            util.hub_token()
            mock_print.assert_called_with(expected_hub_token)
