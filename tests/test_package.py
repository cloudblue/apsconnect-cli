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


class ExtractFilesTest(TestCase):
    def test_user_detected_correctly_if_user_schema(self):
        with patch('apsconnectcli.package.zipfile') as zipfile_mock, \
                patch(_BUILTINS_OPEN), \
                patch('apsconnectcli.package.copyfile'), \
                patch('apsconnectcli.package.xml_et')as xml_mock, \
                patch('apsconnectcli.package.xmlrpclib'), \
                patch('apsconnectcli.package.json'):
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            tree_mock = MagicMock()
            tree_mock.find.return_value.text = 'http://test.test'
            xml_mock.ElementTree.return_value = tree_mock

            package = Package('zz')
            self.assertTrue(package.user_service)

    def test_user_detected_correctly_if_user_user_schema(self):
        with patch('apsconnectcli.package.zipfile') as zipfile_mock, \
                patch(_BUILTINS_OPEN), \
                patch('apsconnectcli.package.copyfile'), \
                patch('apsconnectcli.package.xml_et') as xml_mock, \
                patch('apsconnectcli.package.xmlrpclib'), \
                patch('apsconnectcli.package.json'):
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                if 'user' in filename and 'user.user' not in filename:
                    raise KeyError('Fail')
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            tree_mock = MagicMock()
            tree_mock.find.return_value.text = 'http://test.test'
            xml_mock.ElementTree.return_value = tree_mock

            package = Package('zz')
            self.assertTrue(package.user_service)

    def test_user_detected_correctly_if_no_user_integration(self):
        with patch('apsconnectcli.package.zipfile') as zipfile_mock, \
                patch(_BUILTINS_OPEN), \
                patch('apsconnectcli.package.copyfile'), \
                patch('apsconnectcli.package.xml_et') as xml_mock, \
                patch('apsconnectcli.package.xmlrpclib'), \
                patch('apsconnectcli.package.json'):
            zip_ref = MagicMock('zz')

            def extract(filename, path):
                if 'user' in filename:
                    raise KeyError('Fail')
                return filename

            zip_ref.extract = extract
            zipfile_mock.ZipFile.return_value.__enter__.return_value = zip_ref

            tree_mock = MagicMock()
            tree_mock.find.return_value.text = 'http://test.test'
            xml_mock.ElementTree.return_value = tree_mock

            package = Package('zz')
            self.assertFalse(package.user_service)


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
