import os
import sys
from unittest import TestCase

from pkg_resources import DistributionNotFound

from apsconnectcli.apsconnect import (
    GITHUB_RELEASES_PAGE,
    bin_version,
    get_version,
    get_latest_version,
    main,
    APSConnectUtil,
)

if sys.version_info >= (3,):
    from unittest.mock import patch

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch

    _BUILTINS_OPEN = 'apsconnectcli.apsconnect.open'
    _BUILTINS_PRINT = 'apsconnectcli.apsconnect.print'


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
