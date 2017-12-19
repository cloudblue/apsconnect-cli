import base64
import sys
from unittest import TestCase

from apsconnectcli.cluster import read_cluster_certificate

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
