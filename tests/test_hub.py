from unittest import TestCase

from mock import patch

from apsconnectcli.hub import _osaapi_raise_for_status, Hub


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


class AssertHubVersion(TestCase):
    def test_supported_version(self):
        with patch('apsconnectcli.hub.sys') as sys_mock:
            Hub._assert_supported_version('oa-7.13-1216')

            sys_mock.exit.assert_not_called()

    def test_unsupported_version(self):
        with patch('apsconnectcli.hub.sys') as sys_mock:
            Hub._assert_supported_version('oa-7.0-1216')

            sys_mock.exit.assert_called_with(1)


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
            self.assertEqual(Hub._get_resclass_name(key), value)

    def test_get_resclass_name_for_new_unit(self):
        self.assertEqual(
            Hub._get_resclass_name('new-unit'),
            'rc.saas.resource.unit',
        )

    def test_get_resclass_name_witout_unit(self):
        self.assertEqual(
            Hub._get_resclass_name(''),
            'rc.saas.resource.unit',
        )
