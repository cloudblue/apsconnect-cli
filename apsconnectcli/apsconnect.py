from __future__ import print_function

import json
import os
import sys
import uuid
import warnings
from distutils.util import strtobool

import fire
import pkg_resources
from requests import get
from six.moves import input

from apsconnectcli.action_logger import Logger
from apsconnectcli.config import CFG_FILE_PATH, NULL_CFG_INFO
from apsconnectcli.hub import Hub
from apsconnectcli.package import Package

LOG_DIR = os.path.expanduser('~/.apsconnect')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "apsconnect.log")

sys.stdout = Logger(LOG_FILE, sys.stdout)
sys.stderr = Logger(LOG_FILE, sys.stderr)

warnings.filterwarnings('ignore')

IS_PYTHON3 = sys.version_info >= (3,)

LATEST_RELEASE_URL = 'https://api.github.com/repos/ingrammicro/apsconnect-cli/releases/latest'
REQUEST_TIMEOUT = 5
GITHUB_RELEASES_PAGE = 'https://github.com/ingrammicro/apsconnect-cli/releases/'


class APSConnectUtil:
    """ A command line tool for APS connector installation on Odin Automation in the relaxed way"""

    def init_hub(self, hub_host, user='admin', pwd='1q2w3e', use_tls=False, port=8440,
                 aps_host=None, aps_port=6308, use_tls_aps=True):
        """ Connect your Odin Automation Hub"""
        Hub.configure(hub_host, user, pwd, use_tls, port, aps_host, aps_port, use_tls_aps)

    def version(self):
        package_version = get_version()
        latest_version = get_latest_version()

        if package_version:
            print("apsconnect-cli v{} built with love.".format(package_version))
            if latest_version and latest_version != package_version:
                print('apsconnect-cli v{} is available, check it here: {}'
                      .format(latest_version, GITHUB_RELEASES_PAGE))
        else:
            print("Could not determine apsconnect-cli version. Check {} for latest release."
                  .format(GITHUB_RELEASES_PAGE))

    def install_frontend(self, source, oauth_key, oauth_secret, backend_url, settings=None,
                         network='proxy', hub_id=None, instance_only=False):
        """ Install connector-frontend in Odin Automation Hub, --source can be http(s):// or
        filepath"""

        if backend_url.startswith('http://'):
            print("WARN: Make sure that the APS development mode enabled for http backend. "
                  "Run `apsconnect aps_devel_mode` command.")
        elif not backend_url.startswith('https://'):
            print("Backend url must be URL http(s)://, got {}".format(backend_url))
            sys.exit(1)

        settings = json.load(open(settings)) if settings else {}
        hub = Hub()

        package = Package(source, instance_only=instance_only)
        print("Importing connector {} {}-{}".format(package.connector_id,
                                                    package.version,
                                                    package.release))
        application_id = hub.import_package(package)
        print("Connector {} imported with id={} [ok]"
              .format(package.connector_id, application_id))

        # Create app instance
        instance_uuid = hub.create_instance(package, oauth_key, oauth_secret, backend_url,
                                            settings, network, hub_id)
        print("Application instance creation completed [ok]")

        if instance_only:
            return

        # Create resource types
        resource_types = hub.create_rts(package, application_id, instance_uuid)
        print("Resource types creation completed [ok]")

        # Create service template
        service_template_id = hub.create_st(package, resource_types)
        print("Service template \"{}\" created with id={} [ok]".format(package.connector_name,
                                                                       service_template_id))

        # Set up service template limits
        hub.apply_st_limits(service_template_id, resource_types)
        print("Limits for Service template \"{}\" are applied [ok]".format(service_template_id))

    def generate_oauth(self, namespace=''):
        """ Helper for Oauth credentials generation"""
        if namespace:
            namespace += '-'
        print("OAuh key: {}{}\nSecret: {}".format(namespace, uuid.uuid4().hex, uuid.uuid4().hex))

    def aps_devel_mode(self, disable=False):
        """ Enable development mode for OA Hub"""
        Hub().aps_devel_mode(disable)

    def info(self):
        """ Show current state of apsconnect-cli binding with OA Hub"""
        print("OA Hub:")
        print(_check_binding(lambda: os.path.exists(CFG_FILE_PATH),  _get_hub_info))

    def hub_token(self):
        hub = Hub()
        print(hub.hub_id)


def _confirm(prompt):
    while True:
        try:
            answer = strtobool(input(prompt))
        except ValueError:
            continue
        except EOFError:
            sys.exit(1)
        else:
            break
    return answer


def _check_binding(check_config, get_config_info):
    state_not_initiated = "\tNot initiated"
    state_is_ready = "\thost: {}\n\tuser: {}"
    state_config_corrupted = "\tConfig file is corrupted: {}"

    if not check_config():
        return state_not_initiated

    try:
        info = get_config_info()
    except Exception as e:
        return state_config_corrupted.format(e)

    if info == NULL_CFG_INFO:
        return state_config_corrupted.format("binding attributes are not assigned")
    else:
        host, user = info
        return state_is_ready.format(host, user)


def _get_hub_info():
    if not os.path.exists(CFG_FILE_PATH):
        return NULL_CFG_INFO

    with open(CFG_FILE_PATH) as f:
        hub_cfg = json.load(f)

    host = "{}:{}".format(hub_cfg['host'], hub_cfg['port'])
    user = hub_cfg['user']
    return (host, user)


def bin_version():
    """
    This method will return version in binaries built with pyinstaller.
    In all other cases it will return NONE.
    """
    try:
        with open(os.path.join(sys._MEIPASS, 'VERSION')) as f:
            return f.read()
    except:
        return None


def get_version():
    try:
        return pkg_resources.get_distribution('apsconnectcli').version
    except pkg_resources.DistributionNotFound:
        return bin_version()


def get_latest_version():
    try:
        return get(LATEST_RELEASE_URL, timeout=REQUEST_TIMEOUT).json()['tag_name'][1:]
    except:
        return None


def main():
    version = get_version()
    if version:
        print("APSConnect-cli v{}".format(get_version()))

    try:
        log_entry = ("=============================\n{}\n".format(" ".join(sys.argv)))
        Logger(LOG_FILE).log(log_entry)
        fire.Fire(APSConnectUtil, name='apsconnect')
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
