from __future__ import print_function

import json
import os
import sys
import time
import tempfile
import copy
import uuid
import base64
import warnings
import pkg_resources
from datetime import datetime, timedelta
from distutils.util import strtobool
from six.moves import input

import fire
import yaml

from requests import get
from requests.exceptions import Timeout, ConnectionError, SSLError

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from apsconnectcli.action_logger import Logger
from apsconnectcli.cluster import read_cluster_certificate, poll_deployment
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

KUBE_DIR_PATH = os.path.expanduser('~/.kube')
KUBE_FILE_PATH = '{}/config'.format(KUBE_DIR_PATH)
AUTH_TEMPLATE = {
    'apiVersion': 'v1',
    'clusters': [
        {
            'cluster': {
                'api-version': 'v1',
                'certificate-authority-data': '{BASE64CERT}',
                'server': '{ENDPOINT}',
            },
            'name': 'cluster',
        },
    ],
    'contexts': [
        {
            'context': {
                'cluster': 'cluster',
                'user': 'cluster-admin',
            },
            'name': 'cluster-context',
        },
    ],
    'current-context': 'cluster-context',
    'kind': 'Config',
    'preferences': {},
    'users': [
        {
            'name': 'cluster-admin',
            'user': {
                'username': '{USERNAME}',
                'password': '{PASSWORD}',
            },
        },
    ],
}
IS_PYTHON3 = sys.version_info >= (3,)

LATEST_RELEASE_URL = 'https://api.github.com/repos/ingrammicro/apsconnect-cli/releases/latest'
REQUEST_TIMEOUT = 5
GITHUB_RELEASES_PAGE = 'https://github.com/ingrammicro/apsconnect-cli/releases/'


class APSConnectUtil:
    """ A command line tool for APS connector installation on Odin Automation in the relaxed way"""

    def init_cluster(self, cluster_endpoint, user, pwd, ca_cert):
        """ Connect your kubernetes (k8s) cluster"""
        ca_cert_data = read_cluster_certificate(ca_cert)

        auth_template = copy.deepcopy(AUTH_TEMPLATE)
        cluster = auth_template['clusters'][0]['cluster']
        user_data = auth_template['users'][0]['user']

        cluster['certificate-authority-data'] = ca_cert_data.decode()
        cluster['server'] = 'https://{}'.format(cluster_endpoint)
        user_data['username'] = user
        user_data['password'] = pwd

        fd, tmp_path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as tmp:
            yaml.safe_dump(auth_template, tmp)

        try:
            api_client = _get_k8s_api_client(tmp_path)
            api = client.VersionApi(api_client)
            code = api.get_code()
            print("Connectivity with k8s cluster api [ok]")
            print("k8s cluster version - {}".format(code.git_version))
        except Exception as e:
            print("Unable to communicate with k8s cluster {}, error: {}".format(
                cluster_endpoint, e))
            sys.exit(1)
        finally:
            os.close(fd)
            os.remove(tmp_path)

        if not os.path.exists(KUBE_DIR_PATH):
            os.mkdir(KUBE_DIR_PATH)
            print("Created directory [{}]".format(KUBE_DIR_PATH))

        if os.path.isfile(KUBE_FILE_PATH):
            if not _confirm("Kubernetes configuration file already exists. Overwrite? "):
                print("{} configuration update was declined.".format(KUBE_FILE_PATH))
                return

        with open(KUBE_FILE_PATH, 'w+') as fd:
            yaml.safe_dump(auth_template, fd)
            print("Config saved [{}]".format(KUBE_FILE_PATH))

    def init_hub(self, hub_host, user='admin', pwd='1q2w3e', use_tls=False, port=8440,
                 aps_host=None, aps_port=6308, use_tls_aps=True):
        """ Connect your Odin Automation Hub"""
        Hub.configure(hub_host, user, pwd, use_tls, port, aps_host, aps_port, use_tls_aps)

    def check_backend(self):
        """ Validate k8s components and get useful information"""
        api_client = _get_k8s_api_client()
        api = client.VersionApi(api_client)
        core_v1 = client.CoreV1Api(api_client)

        _cluster_probe_connection(api, api_client)

        lbs = core_v1.list_service_for_all_namespaces(label_selector='app=nginx-ingress,'
                                                                     'component=controller')
        if not lbs or not lbs.items:
            print("Unable to find suitable nginx ingress service. "
                  "Details https://github.com/jetstack/kube-lego/tree/master/examples/nginx")
            sys.exit(1)
        if len(lbs.items) > 1:
            print("WARN: Found more than one suitable nginx ingress services.")
        for lb in lbs.items:
            print("Service {} IP {}"
                  .format(lb.metadata._name, lb.status.load_balancer.ingress[0].ip))
        sys.exit(0)

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

    def install_backend(self, name, image, config_file, hostname, healthcheck_path=None,
                        root_path='/', namespace='default', replicas=2,
                        tls_secret_name=None, force=False):
        """ Install connector-backend in the k8s cluster"""
        if healthcheck_path:
            print("WARNING --healthcheck-path is deprecated and will be dropped in future releases."
                  " The connector should have the same value for root path and health check path.")
        else:
            healthcheck_path = root_path

        try:
            with open(config_file) as config:
                print("Loading config file: {}".format(config_file))
                config_data, config_format = json.load(config), 'json'
        except ValueError:
            try:
                with open(config_file, 'r') as config:
                    config_data, config_format = yaml.load(config), 'yaml'
            except yaml.YAMLError as e:
                print("Config file should be valid JSON or YAML structure, error: {}".format(e))
                sys.exit(1)
        except Exception as e:
            print("Unable to read config file, error: {}".format(e))
            sys.exit(1)

        api_client = _get_k8s_api_client()
        api = client.VersionApi(api_client)
        core_v1 = client.CoreV1Api(api_client)
        ext_v1 = client.ExtensionsV1beta1Api(api_client)

        _cluster_probe_connection(api, api_client)

        try:
            _create_secret(name, config_format, config_data, core_v1, namespace, force)
            print("Create config [ok]")
        except Exception as e:
            print("Can't create config in cluster, error: {}".format(e))
            sys.exit(1)

        try:
            _create_deployment(name, image, ext_v1, healthcheck_path, replicas,
                               namespace, force, core_api=core_v1)
            print("Create deployment [ok]")
        except Exception as e:
            print("Can't create deployment in cluster, error: {}".format(e))
            sys.exit(1)

        try:
            _create_service(name, core_v1, namespace, force)
            print("Create service [ok]")
        except Exception as e:
            print("Can't create service in cluster, error: {}".format(e))
            sys.exit(1)

        try:
            _create_ingress(hostname, name, core_v1, ext_v1, namespace,
                            tls_secret_name, force)
            print("Create ingress [ok]")
        except Exception as e:
            print("Can't create ingress in cluster, error: {}".format(e))
            sys.exit(1)

        print("Checking service availability")

        try:
            _polling_service_access(name, ext_v1, namespace, timeout=180)
            print("Expose service [ok]")
        except Exception as e:
            print("Service expose FAILED, error: {}".format(e))
            sys.exit(1)

        print("Checking connector backend availability")

        try:
            service_url = 'https://{}/{}'.format(hostname, root_path.lstrip('/'))
            _check_connector_backend_access(service_url)
            print("Check connector backend host [ok]")
            print("Connector backend - {}".format(service_url))
        except Exception as e:
            print()
            print("Check connector backend host error: {}".format(e))
            sys.exit(1)

        print("[Success]")

    def install_frontend(self, source, oauth_key, oauth_secret, backend_url, settings=None,
                         network='proxy', hub_id=None):
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

        package = Package(source)
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
        """ Show current state of apsconnect-cli binding with Kubernetes cluster and OA Hub"""

        kube_check = ("Kube cluster:", lambda: os.path.exists(KUBE_FILE_PATH), _get_cluster_info)
        oa_hub_check = ("OA Hub:", lambda: os.path.exists(CFG_FILE_PATH), Hub.info())

        for (item_name, check_config, get_info) in [oa_hub_check, kube_check]:
            print(item_name)
            print(_check_binding(check_config, get_info))


def _get_k8s_api_client(config_file=None):
    if not config_file:
        config_file = KUBE_FILE_PATH

    return config.new_client_from_config(config_file=config_file)


def _to_bytes(raw_str):
    if IS_PYTHON3:
        return bytes(raw_str, 'utf-8')
    else:
        return bytearray(raw_str, 'utf-8')


def _cluster_probe_connection(api, api_client):
    try:
        api.get_code()
        print("Connect {} [ok]".format(api_client.host))
    except Exception as e:
        print("Unable to communicate with the k8s cluster, error: {}".format(e))
        sys.exit(1)


def _create_secret(name, data_format, data, api, namespace='default', force=False):
    if data_format == 'json':
        config = json.dumps(data, ensure_ascii=False)
    elif data_format == 'yaml':
        config = yaml.dump(data, allow_unicode=True, default_flow_style=False)
    else:
        raise Exception("Unknown config data format: {}".format(data_format))

    secret = {
        'apiVersion': 'v1',
        'data': {
            'config.yml': base64.b64encode(_to_bytes(config)).decode(),
        },
        'kind': 'Secret',
        'metadata': {
            'name': name,
        },
        'type': 'Opaque',
    }

    if force:
        _delete_secret(name, api, namespace)

    api.create_namespaced_secret(
        namespace=namespace,
        body=secret,
    )


def _delete_secret(name, api, namespace):
    try:
        api.delete_namespaced_secret(
            namespace=namespace,
            body=client.V1DeleteOptions(),
            name=name,
        )
    except ApiException as e:
        if e.status != 404:
            raise


def _create_deployment(name, image, api, healthcheck_path='/', replicas=2,
                       namespace='default', force=False, core_api=None):
    template = {
        'apiVersion': 'extensions/v1beta1',
        'kind': 'Deployment',
        'metadata': {
            'name': name,
        },
        'spec': {
            'replicas': replicas,
            'template': {
                'metadata': {
                    'labels': {
                        'name': name,
                    },
                },
                'spec': {
                    'containers': [
                        {
                            'name': name,
                            'image': image,
                            'env': [
                                {
                                    'name': 'CONFIG_FILE',
                                    'value': '/config/config.yml',
                                },
                            ],
                            'livenessProbe': {
                                'httpGet': {
                                    'path': healthcheck_path,
                                    'port': 80,
                                },
                            },
                            'readinessProbe': {
                                'httpGet': {
                                    'path': healthcheck_path,
                                    'port': 80,
                                },
                            },
                            'ports': [
                                {
                                    'containerPort': 80,
                                    'name': 'http-server',
                                },
                            ],
                            'resources': {
                                'requests': {
                                    'cpu': '100m',
                                    'memory': '128Mi',
                                },
                                # TODO need more limits by default?
                                'limits': {
                                    'cpu': '200m',
                                    'memory': '256Mi',
                                },
                            },
                            'volumeMounts': [
                                {
                                    'mountPath': '/config',
                                    'name': 'config-volume',
                                },
                            ],
                        },
                    ],
                    'volumes': [
                        {
                            'name': 'config-volume',
                            'secret': {
                                'secretName': name,
                            },
                        },
                    ],
                },
            },
        },
    }

    if force:
        _delete_deployment(name, api=api, namespace=namespace, core_api=core_api)

    api.create_namespaced_deployment(namespace=namespace, body=template)

    # Check deployment availability
    sys.stdout.write("Waiting for deployment to become ready...")
    sys.stdout.flush()
    poll_result = poll_deployment(core_v1=core_api, ext_v1=api, namespace=namespace, name=name)
    print()
    if not poll_result.available:
        print(poll_result.message)
        sys.exit(1)


def _delete_deployment(name, api, namespace, core_api=None):
    try:
        api.delete_namespaced_deployment(
            namespace=namespace,
            name=name,
            body=client.V1DeleteOptions(),
            grace_period_seconds=0,
        )
    except ApiException as e:
        if e.status != 404:
            raise

    replica_set = api.list_namespaced_replica_set(
        namespace=namespace,
        label_selector='name={}'.format(name),
    )

    if replica_set and replica_set.items:
        for rs in replica_set.items:
            rs_name = rs.metadata.name
            api.delete_namespaced_replica_set(namespace=namespace, name=rs_name,
                                              body=client.V1DeleteOptions(),
                                              grace_period_seconds=0)

    pods = core_api.list_namespaced_pod(
        namespace=namespace,
        label_selector='name={}'.format(name)
    )

    if not pods or not pods.items:
        return

    pod_names = [pod.metadata.name for pod in pods.items]

    for name in pod_names:
        core_api.delete_namespaced_pod(
            namespace=namespace,
            name=name,
            body=client.V1DeleteOptions(),
            grace_period_seconds=0,
        )


def _create_service(name, api, namespace='default', force=False):
    service = {
        'apiVersion': 'v1',
        'kind': 'Service',
        'metadata': {
            'labels': {
                'name': name,
            },
            'name': name,
        },
        'spec': {
            'ports': [
                {
                    'port': 80,
                    'protocol': 'TCP',
                    'targetPort': 80,
                }
            ],
            'selector': {
                'name': name
            },
            'type': 'ClusterIP'
        }
    }

    if force:
        _delete_by_namespace('service', name, api, namespace)

    api.create_namespaced_service(namespace=namespace, body=service)


def _create_ingress(hostname, name, api, ext_api, namespace='default',
                    tls_secret_name=None, force=False):
    if not tls_secret_name:
        try:
            api.read_namespace('kube-lego')
            tls_secret_name = '{}-tls'.format(hostname)
        except ApiException as e:
            if e.status == 404:
                # Hostname without a subdomain part
                _, hostname_domain = hostname.split('.', 1)
                tls_secret_name = 'star.{}'.format(hostname_domain)
            else:
                raise ApiException("Kube-lego namespace cannot be checked")

    ingress = {
        'apiVersion': 'extensions/v1beta1',
        'kind': 'Ingress',
        'metadata': {
            'annotations': {
                'kubernetes.io/tls-acme': 'true',
                'kubernetes.io/ingress.class': 'nginx'},
            'name': name,
            'namespace': namespace
        },
        'spec': {
            'tls': [
                {'hosts': [hostname, ],
                 'secretName': tls_secret_name}],
            'rules': [
                {
                    'host': hostname,
                    'http': {
                        'paths': [
                            {'path': '/',
                             'backend': {
                                 'servicePort': 80,
                                 'serviceName': name
                             }
                             }
                        ]
                    }
                }
            ]
        }
    }

    if force:
        _delete_by_namespace('ingress', name, ext_api, namespace)

    ext_api.create_namespaced_ingress(namespace=namespace, body=ingress, pretty=True)


def _delete_by_namespace(kind, name, api, namespace):
    kwargs = {'namespace': namespace, 'name': name}
    if kind in ('secret', 'ingress'):
        kwargs.update({'body': client.V1DeleteOptions()})
    try:
        getattr(api, 'delete_namespaced_{}'.format(kind))(**kwargs)
    except ApiException as e:
        if e.status != 404:
            raise


def _polling_service_access(name, ext_v1, namespace, timeout=120):
    max_time = datetime.now() + timedelta(seconds=timeout)

    while True:
        try:
            data = ext_v1.read_namespaced_ingress_status(name=name, namespace=namespace)
            ingress = data.status.load_balancer.ingress

            if ingress:
                print()
                return ingress[0].ip

            sys.stdout.write('.')
            sys.stdout.flush()
        except:
            raise

        if datetime.now() > max_time:
            raise Exception("Waiting time exceeded")

        time.sleep(10)


def _check_connector_backend_access(url, timeout=120):
    max_time = datetime.now() + timedelta(seconds=timeout)

    while True:
        try:
            response = get(url=url, timeout=10)

            if response.status_code == 200:
                print()
                return

            raise_by_max_time("Waiting time exceeded", max_time)
        except SSLError:
            raise_by_max_time("An SSL error occurred", max_time)
        except Timeout:
            raise_by_max_time("Timeout connecting to Connector Backend", max_time)
        except ConnectionError:
            raise_by_max_time("Connection error to Connector Backend", max_time)
        except Exception as e:
            raise_by_max_time(str(e), max_time)

        time.sleep(10)


def raise_by_max_time(msg, max_time):
    if datetime.now() >= max_time:
        raise Exception(msg)

    sys.stdout.write('.')
    sys.stdout.flush()


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


def _get_cluster_info():
    with open(KUBE_FILE_PATH, 'r') as f:
        kube_cfg = yaml.load(f.read())

    if not isinstance(kube_cfg, dict):
        return NULL_CFG_INFO

    user = kube_cfg['users'][0]['user']['username']
    host = kube_cfg['clusters'][0]['cluster']['server']
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
