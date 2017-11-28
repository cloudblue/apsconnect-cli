from __future__ import print_function

import json
import os
import re
import sys
import time
import copy
import uuid
import base64
import warnings
import zipfile
import pkg_resources
from future.moves.urllib.parse import urlparse
from shutil import copyfile
from xml.etree import ElementTree as xml_et
from datetime import datetime, timedelta
from distutils.util import strtobool
from six.moves import input

import fire
import yaml
import osaapi
from requests import request, get
from requests.exceptions import Timeout, ConnectionError, SSLError

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from apsconnectcli.action_logger import Logger

if sys.version_info >= (3,):
    import tempfile
    import xmlrpc.client as xmlrpclib
    from tempfile import TemporaryDirectory
else:
    import xmlrpclib
    import tempfile
    from backports.tempfile import TemporaryDirectory


LOG_DIR = os.path.expanduser('~/.apsconnect')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "apsconnect.log")

sys.stdout = Logger(LOG_FILE, sys.stdout)
sys.stderr = Logger(LOG_FILE, sys.stderr)

warnings.filterwarnings('ignore')

CFG_FILE_PATH = os.path.expanduser('~/.apsconnect/.aps_config')
KUBE_DIR_PATH = os.path.expanduser('~/.kube')
KUBE_FILE_PATH = '{}/config'.format(KUBE_DIR_PATH)
RPC_CONNECT_PARAMS = ('host', 'user', 'password', 'ssl', 'port')
APS_CONNECT_PARAMS = ('aps_host', 'aps_port', 'use_tls_aps')
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
NULL_CFG_INFO = (None, None)


class APSConnectUtil:
    """ A command line tool for APS connector installation on Odin Automation in the relaxed way"""

    def init_cluster(self, cluster_endpoint, user, pwd, ca_cert):
        """ Connect your kubernetes (k8s) cluster"""
        try:
            with open(ca_cert) as _file:
                ca_cert_data = base64.b64encode(_file.read().encode())
        except Exception as e:
            print("Unable to read ca_cert file, error: {}".format(e))
            sys.exit(1)

        auth_template = copy.deepcopy(AUTH_TEMPLATE)
        cluster = auth_template['clusters'][0]['cluster']
        user_data = auth_template['users'][0]['user']

        cluster['certificate-authority-data'] = ca_cert_data.decode()
        cluster['server'] = 'https://{}'.format(cluster_endpoint)
        user_data['username'] = user
        user_data['password'] = pwd

        _, temp_config = tempfile.mkstemp()
        with open(temp_config, 'w') as fd:
            yaml.safe_dump(auth_template, fd)

        try:
            api_client = _get_k8s_api_client(temp_config)
            api = client.VersionApi(api_client)
            code = api.get_code()
            print("Connectivity with k8s cluster api [ok]")
            print("k8s cluster version - {}".format(code.git_version))
        except Exception as e:
            print("Unable to communicate with k8s cluster {}, error: {}".format(
                cluster_endpoint, e))
            sys.exit(1)

        os.remove(temp_config)

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
        if not aps_host:
            aps_host = hub_host
        use_tls = use_tls in ('Yes', 'True', '1')
        hub = osaapi.OSA(host=hub_host, user=user, password=pwd, ssl=use_tls, port=port)
        try:
            hub_version = _get_hub_version(hub)
            print("Connectivity with Hub RPC API [ok]")
            _assert_hub_version(hub_version)
            print("Hub version {}".format(hub_version))
            response = request('GET', '{}/{}'.format(_get_aps_url(aps_host, aps_port, use_tls_aps),
                                                     'aps/2/applications/'),
                               headers=_get_user_token(hub, user), verify=False)
            response.raise_for_status()
            print("Connectivity with Hub APS API [ok]")

        except Exception as e:
            print("Unable to communicate with hub {}, error: {}".format(hub_host, e))
            sys.exit(1)

        with open(CFG_FILE_PATH, 'w+') as cfg:
            cfg.write(json.dumps({'host': hub_host, 'user': user, 'password': pwd, 'ssl': use_tls,
                                  'port': port, 'aps_port': aps_port, 'aps_host': aps_host,
                                  'use_tls_aps': use_tls_aps},
                                 indent=4))
            print("Config saved [{}]".format(CFG_FILE_PATH))

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
        print("apsconnect-cli v.{} built with love."
              .format(pkg_resources.get_distribution('apsconnectcli').version))

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

    def install_frontend(self, source, oauth_key, oauth_secret, backend_url, settings_file=None,
                         network='public', hub_id=None):
        """ Install connector-frontend in Odin Automation Hub, --source can be http(s):// or
        filepath"""

        with TemporaryDirectory() as tdir:
            is_http_source = True if source.startswith('http://') or source.startswith('https://') \
                else False

            if is_http_source:
                package_name = _download_file(source, target=tdir)
            else:
                package_name = os.path.basename(source)
                copyfile(os.path.expanduser(source), os.path.join(tdir, package_name))

            package_path = os.path.join(tdir, package_name)
            with zipfile.ZipFile(package_path, 'r') as zip_ref:
                meta_path = zip_ref.extract('APP-META.xml', path=tdir)
                tenant_schema_path = zip_ref.extract('schemas/tenant.schema', tdir)
                app_schema_path = zip_ref.extract('schemas/app.schema', tdir)

                try:
                    zip_ref.extract('schemas/user.schema', tdir)
                    user_service = True
                except KeyError:
                    user_service = False

            tree = xml_et.ElementTree(file=meta_path)
            namespace = '{http://aps-standard.org/ns/2}'
            connector_id = tree.find('{}id'.format(namespace)).text
            version = tree.find('{}version'.format(namespace)).text
            release = tree.find('{}release'.format(namespace)).text

            # Get connector name from id as <name> field may not be unique
            url_path = urlparse(connector_id).path
            connector_name = os.path.split(url_path)[-1]

            if not settings_file:
                settings_file = {}
            else:
                settings_file = json.load(open(settings_file))

            if backend_url.startswith('http://'):
                print("WARN: Make sure that the APS development mode enabled for http backend. "
                      "Run `apsconnect aps_devel_mode` command.")
            elif backend_url.startswith('https://'):
                pass
            else:
                print("Backend url must be URL http(s)://, got {}".format(backend_url))
                sys.exit(1)

            cfg, hub = _get_cfg(), _get_hub()

            with open(package_path, 'rb') as package_binary:
                print("Importing connector {} {}-{}".format(connector_id, version, release))
                import_kwargs = {'package_url': source} if is_http_source \
                    else {'package_body': xmlrpclib.Binary(package_binary.read())}
                response = hub.APS.importPackage(**import_kwargs)
                _osaapi_raise_for_status(response)

                application_id = str(response['result']['application_id'])

                print("Connector {} imported with id={} [ok]"
                      .format(connector_id, application_id))

            payload = {
                'aps': {
                    'package': {
                        'type': connector_id,
                        'version': version,
                        'release': release,
                    },
                    'endpoint': backend_url,
                    'network': network,
                    'auth': {
                        'oauth': {
                            'key': oauth_key,
                            'secret': oauth_secret,
                        },
                    },
                },
            }

            # Get Unique OA id for using as hubId parameter while endpoint deploying
            base_aps_url = _get_aps_url(**{k: _get_cfg()[k] for k in APS_CONNECT_PARAMS})

            app_properties = _get_properties(app_schema_path)

            if 'hubId' in app_properties:
                url = '{}/{}'.format(
                    base_aps_url,
                    'aps/2/resources?implementing(http://parallels.com/aps/types/pa/poa/1.0)',
                )

                response = request(method='GET', url=url, headers=_get_user_token(hub, cfg['user']),
                                   verify=False)
                response.raise_for_status()

                try:
                    data = json.loads(response.content.decode('utf-8'))
                except ValueError:
                    print("APSController provided non-json format")
                    sys.exit(1)

                if not data and not hub_id:
                    raise Exception("Core OA resource is not found\n"
                                    "Use --hub-id={value} argument to specify the ID "
                                    "manually or --hub-id=auto to generate it automatically")
                elif data:
                    hub_id = data[0]['aps']['id']
                elif hub_id == 'auto':
                    hub_id = str(uuid.uuid4())

                payload.update({
                    'app': {
                        'hubId': hub_id
                    }
                })

            payload.update(settings_file)

            response = request(
                method='POST',
                url='{}/{}'.format(base_aps_url, 'aps/2/applications/'),
                headers=_get_user_token(hub, cfg['user']), verify=False, json=payload
            )
            try:
                response.raise_for_status()
            except Exception as e:
                if 'error' in response.json():
                    err = "{} {}".format(response.json()['error'], response.json()['message'])
                else:
                    err = str(e)
                print("Installation of connector {} FAILED.\n"
                      "Hub APS API response {} code.\n"
                      "Error: {}".format(connector_id, response.status_code, err))

            # Create app, tenant, users resource types
            resource_uid = json.loads(response.content.decode('utf-8'))['app']['aps']['id']

            core_resource_types_payload = [
                {
                    'resclass_name': 'rc.saas.service.link',
                    'name': connector_name,
                    'act_params': [
                        {
                            'var_name': 'app_id',
                            'var_value': application_id
                        },
                        {
                            'var_name': 'resource_uid',
                            'var_value': resource_uid
                        },
                    ]
                },
                {
                    'resclass_name': 'rc.saas.service',
                    'name': '{} tenant'.format(connector_name),
                    'act_params': [
                        {
                            'var_name': 'app_id',
                            'var_value': application_id
                        },
                        {
                            'var_name': 'service_id',
                            'var_value': 'tenant'
                        },
                        {
                            'var_name': 'autoprovide_service',
                            'var_value': '1'
                        },
                    ]
                },
            ]

            # Collect ids for service template creation
            resource_types_ids = []
            limited_resources = {}

            for type in core_resource_types_payload:
                response = hub.addResourceType(**type)
                _osaapi_raise_for_status(response)

                resource_types_ids.append(response['result']['resource_type_id'])

            for id in list(resource_types_ids):
                limited_resources[id] = 1

            if user_service:
                user_resource_type_payload = {
                    'resclass_name': 'rc.saas.service',
                    'name': '{} users'.format(connector_name),
                    'act_params': [
                        {
                            'var_name': 'app_id',
                            'var_value': application_id
                        },
                        {
                            'var_name': 'service_id',
                            'var_value': 'user'
                        },
                        {
                            'var_name': 'autoprovide_service',
                            'var_value': '0'
                        },
                    ]
                }

                response = hub.addResourceType(**user_resource_type_payload)
                _osaapi_raise_for_status(response)

                resource_types_ids.append(response['result']['resource_type_id'])

            # Create counters resource types
            counters = _get_counters(tenant_schema_path)

            for counter in counters:
                payload = {
                    'resclass_name': "rc.saas.resource.unit",
                    'name': '{} {}'.format(connector_name, counter),
                    'act_params': [
                        {
                            'var_name': 'app_id',
                            'var_value': application_id
                        },
                        {
                            'var_name': 'service_id',
                            'var_value': "tenant"
                        },
                        {
                            'var_name': 'resource_id',
                            'var_value': counter
                        },
                    ]
                }

                response = hub.addResourceType(**payload)
                _osaapi_raise_for_status(response)
                resource_types_ids.append(response['result']['resource_type_id'])

            # Create parameters resource types
            parameters = _get_parameters(tenant_schema_path)

            for parameter in parameters:
                payload = {
                    'resclass_name': "rc.saas.resource.unit",
                    'name': '{} {}'.format(connector_name, parameter),
                    'act_params': [
                        {
                            'var_name': 'app_id',
                            'var_value': application_id
                        },
                        {
                            'var_name': 'service_id',
                            'var_value': "tenant"
                        },
                        {
                            'var_name': 'resource_id',
                            'var_value': parameter
                        },
                    ]
                }

                response = hub.addResourceType(**payload)
                _osaapi_raise_for_status(response)

                resource_types_ids.append(response['result']['resource_type_id'])
                limited_resources[response['result']['resource_type_id']] = 0

            print("Resource types creation [ok]")

        # Create service template
        payload = {
            'name': connector_name,
            'owner_id': 1,
            'resources': [],
        }

        for type_id in resource_types_ids:
            payload['resources'].append({'resource_type_id': type_id})

        response = hub.addServiceTemplate(**payload)
        _osaapi_raise_for_status(response)
        service_template_id = response['result']['st_id']
        print("Service template \"{}\" created with id={} [ok]".format(connector_name,
                                                                       service_template_id))

        # Set up limits
        payload = {
            'st_id': service_template_id,
            'limits': [],
        }

        for type_id, limit in limited_resources.items():
            payload['limits'].append({'resource_id': type_id, 'resource_limit64': str(limit)})

        response = hub.setSTRTLimits(**payload)
        _osaapi_raise_for_status(response)
        print("Limits for Service template \"{}\" are applied [ok]".format(service_template_id))

    def generate_oauth(self, namespace=''):
        """ Helper for Oauth credentials generation"""
        if namespace:
            namespace += '-'
        print("OAuh key: {}{}\nSecret: {}".format(namespace, uuid.uuid4().hex, uuid.uuid4().hex))

    def aps_devel_mode(self, disable=False):
        """ Enable development mode for OA Hub"""
        hub = _get_hub()
        r = hub.setSystemProperty(account_id=1, name='APS_DEVEL_MODE', bool_value=not bool(disable))
        _osaapi_raise_for_status(r)
        print("APS Development mode {}.".format('DISABLED' if disable else 'ENABLED'))

    def info(self):
        """ Show current state of apsconnect-cli binding with Kubernetes cluster and OA Hub"""

        kube_check = ("Kube cluster:", lambda: os.path.exists(KUBE_FILE_PATH), _get_cluster_info)
        oa_hub_check = ("OA Hub:", lambda: os.path.exists(CFG_FILE_PATH), _get_hub_info)

        for (item_name, check_config, get_info) in [oa_hub_check, kube_check]:
            print(item_name)
            print(_check_binding(check_config, get_info))


def _get_aps_url(aps_host, aps_port, use_tls_aps):
    return '{}://{}:{}'.format('https' if use_tls_aps else 'http', aps_host, aps_port)


def _get_hub_version(hub):
    r = hub.statistics.getStatisticsReport(reports=[{'name': 'report-for-cep', 'value': ''}])
    _osaapi_raise_for_status(r)
    tree = xml_et.fromstring(r['result'][0]['value'])
    return tree.find('ClientVersion').text


def _assert_hub_version(hub_version):
    supported_version = False

    match = re.match(r'^oa-(?P<major>\d)\.(?P<minor>\d)-', hub_version)
    if match:
        major = int(match.groupdict()['major'])
        minor = int(match.groupdict()['minor'])
        supported_version = (major == 7 and minor > 0) or major > 7

    if not supported_version:
        print("Hub 7.1 version or above needed, got {}".format(hub_version))
        sys.exit(1)


def _get_user_token(hub, user):
    # TODO user -> user_id
    r = hub.APS.getUserToken(user_id=1)
    _osaapi_raise_for_status(r)
    return {'APS-Token': r['result']['aps_token']}


def _get_hub():
    return osaapi.OSA(**{k: _get_cfg()[k] for k in RPC_CONNECT_PARAMS})


def _get_k8s_api_client(config_file=None):
    if not config_file:
        config_file = KUBE_FILE_PATH

    return config.new_client_from_config(config_file=config_file)


def _osaapi_raise_for_status(r):
    if r['status']:
        if 'error_message' in r:
            raise Exception("Error: {}".format(r['error_message']))
        else:
            raise Exception("Error: Unknown {}".format(r))


def _download_file(url, target=None):
    local_filename = url.split('/')[-1]
    if target:
        local_filename = os.path.join(target, local_filename)
    r = get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)
    return local_filename


def _get_cfg():
    cfg = json.load(open(CFG_FILE_PATH))
    if not cfg:
        print("Run init command.")
        sys.exit(1)
    return cfg


def _to_bytes(raw_str):
    if sys.version_info >= (3,):
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
        config = json.dumps(data, ensure_ascii=False).encode('utf-8')
    elif data_format == 'yaml':
        config = yaml.dump(data, allow_unicode=True, default_flow_style=False)
    else:
        raise Exception("Unknown config data format: {}".format(data_format))
    secret = {
        'apiVersion': 'v1',
        'data': {
            'config': base64.b64encode(_to_bytes(config)).decode(),
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
                                    'value': '/config/config',
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

    if len(replica_set.items):
        for rs in replica_set.items:
            rs_name = rs.metadata.name
            api.delete_namespaced_replica_set(namespace=namespace, name=rs_name,
                                              body=client.V1DeleteOptions(),
                                              grace_period_seconds=0)

    pods = core_api.list_namespaced_pod(
        namespace=namespace,
        label_selector='name={}'.format(name)
    )
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


def _get_resources(tenant_schema_path, type='Counter', _filter=None):
    resource_type = 'http://aps-standard.org/types/core/resource/1.0#{}'.format(type)
    tenant_properties = _get_properties(tenant_schema_path)
    resources = {}

    for key in tenant_properties:
        if tenant_properties[key]['type'] == resource_type:
            resources[key] = (tenant_properties[key])

    if _filter:
        resources = dict(filter(_filter, resources.items()))

    return resources


def _get_counters(tenant_schema_path):
    return _get_resources(tenant_schema_path, 'Counter', lambda x: 'title' in x[1])


def _get_parameters(tenant_schema_path):
    parameters = _get_resources(tenant_schema_path, 'Counter', lambda x: 'title' not in x[1])
    parameters.update(_get_resources(tenant_schema_path, 'Limit'))
    return parameters


def _get_properties(schema_path):
    with open(schema_path) as file:
        try:
            properties = json.load(file)['properties']
        except ValueError:
            print("Schema is not correct json file")
            sys.exit(1)

        return properties


def _confirm(prompt):
    answer = False
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


def _get_hub_info():
    if not os.path.exists(CFG_FILE_PATH):
        return NULL_CFG_INFO

    with open(CFG_FILE_PATH) as f:
        hub_cfg = json.load(f)

    host = "{}:{}".format(hub_cfg['host'], hub_cfg['port'])
    user = hub_cfg['user']
    return (host, user)


def main():
    try:
        print("APSConnect-cli v.{}".format(
            pkg_resources.get_distribution('apsconnectcli').version))
    except pkg_resources.DistributionNotFound:
        pass

    try:
        log_entry = ("=============================\n{}\n".format(" ".join(sys.argv)))
        Logger(LOG_FILE).log(log_entry)
        fire.Fire(APSConnectUtil, name='apsconnect')
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
