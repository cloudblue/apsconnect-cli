import sys
from unittest import TestCase

from apsconnectcli.config import get_config

if sys.version_info >= (3,):
    from unittest.mock import patch

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch

    _BUILTINS_OPEN = 'apsconnectcli.config.open'
    _BUILTINS_PRINT = 'apsconnectcli.config.print'


class GetCfgTest(TestCase):
    def test_file_not_found(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.config.sys') as sys_mock:
            err = IOError()
            err.errno = 2
            open_mock.side_effect = err
            get_config()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not find connected hub data."
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_file_other_ioerr(self):
        with patch(_BUILTINS_OPEN) as open_mock, \
                patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.config.sys') as sys_mock:
            err = IOError("Error message text")
            err.errno = 13
            open_mock.side_effect = err
            get_config()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not open configuration file"
                            in print_mock.call_args[0][0])
            self.assertTrue("Error message text"
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_file_unreadable(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.config.json') as json_mock, \
                patch('apsconnectcli.config.sys') as sys_mock:
            json_mock.load.side_effect = ValueError()

            get_config()

            self.assertTrue(print_mock.called)
            self.assertTrue("Could not parse the configuration file"
                            in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_unexpected_error(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.config.json') as json_mock, \
                patch('apsconnectcli.config.sys') as sys_mock:
            json_mock.load.side_effect = Exception("All is lost")

            get_config()

            self.assertTrue(print_mock.called)
            self.assertTrue("All is lost" in print_mock.call_args[0][0])
            sys_mock.exit.assert_called_with(1)

    def test_ok(self):
        with patch(_BUILTINS_OPEN), \
             patch(_BUILTINS_PRINT) as print_mock, \
                patch('apsconnectcli.config.json') as json_mock, \
                patch('apsconnectcli.config.sys') as sys_mock:
            json_mock.load.return_value = 'Config data'

            config = get_config()

            self.assertEqual(config, 'Config data')
            self.assertFalse(print_mock.called)
            sys_mock.exit.assert_not_called()
