import base64
import os
import sys

from apsconnectcli.action_logger import Logger

LOG_DIR = os.path.expanduser('~/.apsconnect')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "apsconnect.log")

sys.stdout = Logger(LOG_FILE, sys.stdout)
sys.stderr = Logger(LOG_FILE, sys.stderr)


def read_cluster_certificate(ca_cert):
    try:
        with open(ca_cert) as _file:
            print(_file)
            ca_cert_data = base64.b64encode(_file.read().encode())
    except Exception as e:
        print("Unable to read ca_cert file, error: {}".format(e))
        sys.exit(1)
    else:
        return ca_cert_data
