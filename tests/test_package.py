import sys
from unittest import TestCase

from apsconnectcli.package import Package
from tests.fakes import FakeData

if sys.version_info >= (3,):
    from unittest.mock import patch, MagicMock, mock_open

    _BUILTINS_OPEN = 'builtins.open'
    _BUILTINS_PRINT = 'builtins.print'
else:
    from mock import patch, MagicMock, mock_open

    _BUILTINS_OPEN = 'apsconnectcli.package.open'
    _BUILTINS_PRINT = 'apsconnectcli.package.print'


class GetPropertiesTest(TestCase):
    """Tests for _get_properties"""

    def test_schema_with_properties_section(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.SCHEMA_JSON)) as mock_file:
            props = Package._get_properties(FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)
            self.assertEqual(FakeData.PROPERTIES, props)

    def test_schema_without_properties(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.BAD_SCHEMA_JSON)) as mock_file:
            self.assertRaises(SystemExit, Package._get_properties, FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)

    def test_bad_json(self):
        with patch(_BUILTINS_OPEN, mock_open(read_data=FakeData.BAD_JSON)) as mock_file:
            self.assertRaises(SystemExit, Package._get_properties, FakeData.SCHEMA_PATH)
            mock_file.assert_called_once_with(FakeData.SCHEMA_PATH)
