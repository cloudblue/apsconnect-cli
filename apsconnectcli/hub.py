from __future__ import print_function

import json
import re
import sys
import uuid

from xml.etree import ElementTree as xml_et

import osaapi
import requests

from apsconnectcli.config import get_config, CFG_FILE_PATH

RPC_CONNECT_PARAMS = ('host', 'user', 'password', 'ssl', 'port')
APS_CONNECT_PARAMS = ('aps_host', 'aps_port', 'use_tls_aps')


def osaapi_raise_for_status(r):
    if r['status']:
        if 'error_message' in r:
            raise Exception("Error: {}".format(r['error_message']))
        else:
            raise Exception("Error: Unknown {}".format(r))


class Hub(object):
    osaapi = None
    aps = None
    hub_id = None

    def __init__(self):
        config = get_config()
        self.osaapi = osaapi.OSA(**{k: config[k] for k in RPC_CONNECT_PARAMS})
        self.aps = APS(self.get_admin_token())
        self.hub_id = self._get_id()

    @staticmethod
    def configure(hub_host, user='admin', pwd='1q2w3e', use_tls=False, port=8440, aps_host=None,
                  aps_port=6308, use_tls_aps=True):
        if not aps_host:
            aps_host = hub_host
        use_tls = use_tls in ('Yes', 'True', '1')
        hub = osaapi.OSA(host=hub_host, user=user, password=pwd, ssl=use_tls, port=port)
        try:
            hub_version = Hub._get_hub_version(hub)
            print("Connectivity with Hub RPC API [ok]")
            Hub._assert_supported_version(hub_version)
            print("Hub version {}".format(hub_version))
            aps_url = '{}://{}:{}'.format('https' if use_tls_aps else 'http', aps_host, aps_port)
            aps = APS(Hub._get_user_token(hub, 1), aps_url)
            response = aps.get('aps/2/applications/')
            response.raise_for_status()
            print("Connectivity with Hub APS API [ok]")
        except Exception as e:
            print("Unable to communicate with hub {}, error: {}".format(hub_host, e))
            sys.exit(1)
        else:
            with open(CFG_FILE_PATH, 'w+') as cfg:
                cfg.write(json.dumps({'host': hub_host, 'user': user, 'password': pwd,
                                      'ssl': use_tls, 'port': port, 'aps_port': aps_port,
                                      'aps_host': aps_host, 'use_tls_aps': use_tls_aps},
                                     indent=4))
                print("Config saved [{}]".format(CFG_FILE_PATH))

    @staticmethod
    def _get_hub_version(api):
        r = api.statistics.getStatisticsReport(reports=[{'name': 'report-for-cep', 'value': ''}])
        osaapi_raise_for_status(r)
        tree = xml_et.fromstring(r['result'][0]['value'].encode('utf-8'))
        return tree.find('ClientVersion').text

    @staticmethod
    def _assert_supported_version(version):
        supported = False

        match = re.match(r'^oa-(?P<major>\d)\.(?P<minor>\d+)-', version)
        if match:
            major = int(match.groupdict()['major'])
            minor = int(match.groupdict()['minor'])
            supported = (major == 7 and minor > 0) or major > 7

        if not supported:
            print("Hub 7.1 version or above needed, got {}".format(version))
            sys.exit(1)

    @staticmethod
    def _get_user_token(hub, user_id):
        r = hub.APS.getUserToken(user_id=user_id)
        osaapi_raise_for_status(r)
        return {'APS-Token': r['result']['aps_token']}

    @staticmethod
    def _get_resclass_name(unit):
        resclass_name = {
            'Kbit/sec': 'rc.saas.resource.kbps',
            'kb': 'rc.saas.resource',
            'mb-h': 'rc.saas.resource.mbh',
            'mhz': 'rc.saas.resource.mhz',
            'mhzh': 'rc.saas.resource.mhzh',
            'unit': 'rc.saas.resource.unit',
            'unit-h': 'rc.saas.resource.unith'
        }.get(unit)

        return resclass_name or 'rc.saas.resource.unit'

    def _get_id(self):
        url = 'aps/2/resources?implementing(http://parallels.com/aps/types/pa/poa/1.0)'
        r = self.aps.get(url)
        r.raise_for_status()

        try:
            data = json.loads(r.content.decode('utf-8'))
        except ValueError:
            print("APSController provided non-json format")
            sys.exit(1)
        else:
            return data[0]['aps']['id'] if data else None

    def get_admin_token(self):
        return Hub._get_user_token(self.osaapi, 1)

    def aps_devel_mode(self, disable=False):
        r = self.osaapi.setSystemProperty(account_id=1, name='APS_DEVEL_MODE',
                                          bool_value=not bool(disable))
        osaapi_raise_for_status(r)
        print("APS Development mode {}.".format('DISABLED' if disable else 'ENABLED'))

    def import_package(self, package):
        args = {'package_url': package.source} if package.is_http else {
            'package_body': package.body}
        r = self.osaapi.APS.importPackage(**args)
        osaapi_raise_for_status(r)

        return str(r['result']['application_id'])

    def create_instance(self, package, oauth_key, oauth_secret, backend_url, settings={},
                        network='proxy', hub_id=None):
        payload = {
            'aps': {
                'package': {
                    'type': package.connector_id,
                    'version': package.version,
                    'release': package.release,
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

        if 'hubId' in package.app_properties:
            if not self.hub_id and not hub_id:
                raise Exception("Core OA resource is not found\n"
                                "Use --hub-id={value} argument to specify the ID "
                                "manually or --hub-id=auto to generate it automatically")
            elif self.hub_id:
                hub_id = self.hub_id
            elif hub_id == 'auto':
                hub_id = str(uuid.uuid4())

            payload.update({
                'app': {
                    'hubId': hub_id
                }
            })

        payload.update(settings)

        r = self.aps.post('aps/2/applications/', json=payload)

        try:
            r.raise_for_status()
        except Exception as e:
            if 'error' in r.json():
                err = "{} {}".format(r.json()['error'], r.json()['message'])
            else:
                err = str(e)
            print("Installation of connector {} FAILED.\n"
                  "Hub APS API response {} code.\n"
                  "Error: {}".format(package.connector_id, r.status_code, err))
            sys.exit(1)

        return r.json()['app']['aps']['id'] if not package.instance_only else None

    def _create_core_rts(self, package, app_id, instance_uuid):
        rt_ids = {}
        core_resource_types_payload = [
            {
                'resclass_name': 'rc.saas.service.link',
                'name': '{} app instance'.format(package.connector_name),
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': app_id
                    },
                    {
                        'var_name': 'resource_uid',
                        'var_value': instance_uuid
                    },
                ]
            },
            {
                'resclass_name': 'rc.saas.service',
                'name': '{} tenant'.format(package.connector_name),
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': app_id
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

        for t in core_resource_types_payload:
            r = self.osaapi.addResourceType(**t)
            osaapi_raise_for_status(r)
            rt_ids[r['result']['resource_type_id']] = 1

        return rt_ids

    def _create_counter_rts(self, package, app_id):
        rt_ids = {}
        for counter, schema in package.counters.items():
            oa_unit_type = Hub._get_resclass_name(schema['unit'])
            payload = {
                'resclass_name': oa_unit_type,
                'name': '{}'.format(schema.get('title')),
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': app_id
                    },
                    {
                        'var_name': 'service_id',
                        'var_value': 'tenant'
                    },
                    {
                        'var_name': 'resource_id',
                        'var_value': counter
                    },
                ]
            }

            response = self.osaapi.addResourceType(**payload)
            osaapi_raise_for_status(response)
            if oa_unit_type == "rc.saas.resource.unith" or oa_unit_type == "rc.saas.resource.mhzh":
                rt_ids[response['result']['resource_type_id']] = -1
            else:
                rt_ids[response['result']['resource_type_id']] = 0

        return rt_ids

    def _create_parameter_rts(self, package, app_id):
        rt_ids = {}
        for parameter, schema in package.parameters.items():
            payload = {
                'resclass_name': Hub._get_resclass_name(schema['unit']),
                'name': '{} {}'.format(package.connector_name, parameter),
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': app_id
                    },
                    {
                        'var_name': 'service_id',
                        'var_value': 'tenant'
                    },
                    {
                        'var_name': 'resource_id',
                        'var_value': parameter
                    },
                ]
            }

            response = self.osaapi.addResourceType(**payload)
            osaapi_raise_for_status(response)

            rt_ids[response['result']['resource_type_id']] = 0

        return rt_ids

    def create_rts(self, package, app_id, instance_uuid):
        rts = self._create_core_rts(package, app_id, instance_uuid)
        rts.update(self._create_counter_rts(package, app_id))
        rts.update(self._create_parameter_rts(package, app_id))
        return rts

    def create_st(self, package, rts):
        payload = {
            'name': package.connector_name,
            'owner_id': 1,
            'resources': [{'resource_type_id': rt_id} for rt_id in rts],
        }

        r = self.osaapi.addServiceTemplate(**payload)
        osaapi_raise_for_status(r)

        return r['result']['st_id']

    def apply_st_limits(self, st_id, rts):
        payload = {
            'st_id': st_id,
            'limits': [{'resource_id': t, 'resource_limit64': str(l)} for t, l in rts.items()],
        }

        r = self.osaapi.setSTRTLimits(**payload)
        osaapi_raise_for_status(r)


class APS(object):
    url = None
    token = None

    def __init__(self, token, url=None):
        if url:
            self.url = url
        else:
            config = get_config()
            self.url = APS._get_aps_url(**{k: config[k] for k in APS_CONNECT_PARAMS})
        self.token = token

    @staticmethod
    def _get_aps_url(aps_host, aps_port, use_tls_aps):
        return '{}://{}:{}'.format('https' if use_tls_aps else 'http', aps_host, aps_port)

    def get(self, uri):
        return requests.get('{}/{}'.format(self.url, uri), headers=self.token, verify=False)

    def post(self, uri, json=None):
        return requests.post('{}/{}'.format(self.url, uri), headers=self.token, json=json,
                             verify=False)

    def put(self, uri, json=None):
        return requests.put('{}/{}'.format(self.url, uri), headers=self.token, json=json,
                            verify=False)

    def delete(self, uri):
        return requests.delete('{}/{}'.format(self.url, uri), headers=self.token, verify=False)
