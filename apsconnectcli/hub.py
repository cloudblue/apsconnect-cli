from __future__ import print_function

import json
import re
import sys

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


def apsapi_raise_for_status(r):
    try:
        r.raise_for_status()
    except Exception as e:
        if 'error' in r.json():
            err = "{} {}".format(r.json()['error'], r.json()['message'])
        else:
            err = str(e)
        print("Hub APS API response {} code.\n"
              "Error: {}".format(r.status_code, err))
        sys.exit(1)


class Hub(object):
    osaapi = None
    aps = None
    hub_id = None
    extension_id = None

    def __init__(self):
        config = get_config()
        self.osaapi = osaapi.OSA(**{k: config[k] for k in RPC_CONNECT_PARAMS})
        self.aps = APS(self.get_admin_token())
        self.hub_id = self._get_id()
        self.extension_id = self._get_extension_id()

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
    def _assert_supported_version(version, experimental=False):
        supported = False

        match = re.match(r'^((?P<oamajor>oa-8)|(?P<cbmajor>cb-20))\.(?P<minor>\d+)-', version)
        if match:
            '''
            Supported versions:
            OA-8.0 or upper on counter mode
            OA-8.3 or upper in experimental mode
            CB-20.5 in any mode
            '''
            if match.groupdict()['oamajor']:
                oamajor = int(match.groupdict()['oamajor'].replace('oa-', ''))
            else:
                oamajor = 0

            if match.groupdict()['cbmajor']:
                cbmajor = int(match.groupdict()['cbmajor'].replace('cb-', ''))
            else:
                cbmajor = 0
            minor = int(match.groupdict()['minor'])
            if experimental:
                supported = (oamajor >= 8 and minor >= 3)\
                            or (cbmajor >= 20 and minor >= 5)\
                            or cbmajor > 20
                if not supported:
                    print(
                        "Experimental functionality requires Hub version 8.3 " +
                        "and above, got {}".format(version))
                    sys.exit(1)
            else:
                supported = (oamajor >= 8 and minor >= 0)\
                            or (cbmajor >= 20 and minor >= 5)\
                            or cbmajor > 20

        if not supported:
            print("Hub 8.0 version or above needed, got {}".format(version))
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

    def _get_extension_id(self):
        url = 'aps/2/resources?implementing(http://odin.com/servicesSelector/globals/2.0)'
        r = self.aps.get(url)
        try:
            data = json.loads(r.content.decode('utf-8'))
        except ValueError:
            print("APSController provided non-json format")
            sys.exit(1)
        else:
            return data[0]['aps']['id'] if data else None

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

    def check_package_operation(self, package):
        app_id = self.get_application_id(package.connector_id)
        if app_id is None:
            print("INFO: package is not installed")
            return "install"
        app_instances = self.get_application_instances(int(app_id))
        if len(app_instances) == 0:
            return "install"
        url = '/aps/2/resources/{}'.format(app_instances[0]['application_resource_id'])
        r = self.aps.get(url)
        try:
            data = json.loads(r.content.decode('utf-8'))
        except ValueError:
            print("APSController provided non-json format")
            sys.exit(1)
        if 'aps' not in data:
            print("INFO: package is not installed")
            return "install"
        latest = 0
        match = re.match(r'{}/app/(?P<major>\d+)\.0'.format(
            package.connector_id),
            data['aps']['type']
        )
        if match:
            major = int(match.groupdict()['major'])
            if int(latest) < major:
                latest = major
        if int(latest) == int(package.version):
            return "createRTs"
        elif int(latest) > int(package.version):
            print("ERROR: Is not possible to import a version older than existing one at hub")
            sys.exit(1)
        print("Upgrade operation from version {} to version {} required".format(latest,
                                                                                package.version))
        return "upgrade"

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

    def _get_package(self, instance_uuid):
        r = self.aps.get('aps/2/resources/{}'.format(instance_uuid))
        apsapi_raise_for_status(r)
        return r.json()['aps']['package']['id']

    def _is_service_profile_supported(self, instance_uuid):
        package_uuid = self._get_package(instance_uuid)
        r = self.aps.get('aps/2/packages/{}'.format(package_uuid))
        apsapi_raise_for_status(r)
        services = r.json()['services']
        if 'itemProfile' in services.keys():
            print("INFO: Item Profile is Supported")
            return True
        print("INFO: Item profile is not supported")
        return False

    def _get_item_info_from_local_id(self, product, local_id):
        payload = {
            'product': product,
            'local_id': local_id,
        }
        r = self.aps.post('aps/2/resources/{}/itemInfo'.format(self.extension_id), json=payload)
        try:
            apsapi_raise_for_status(r)
            data = json.loads(r.content.decode('utf-8'))
        except ValueError:
            print("Error while decoding item information")
            sys.exit(1)
        if data.get('local_id'):
            return data
        print("ERROR: Connector contains non valid items, please contact CloudBlue Connect Support")
        sys.exit(1)

    def _create_service_profile(self, package, counter, title):
        item_info = self._get_item_info_from_local_id(package.product_id, counter)
        payload = {
            'aps': {'type': '{}/{}/{}.{}'.format(
                package.connector_id, "itemProfile", package.version, package.release)},
            'profileName': title,
            'mpn': item_info.get('mpn'),
            'itemId': item_info.get('id'),
        }

        r = self.aps.post('aps/2/resources/', json=payload)
        try:
            r.raise_for_status()
        except Exception as e:
            if 'error' in r.json():
                err = "{} {}".format(r.json()['error'], r.json()['message'])
            else:
                err = str(e)
            print("ERROR: Adding service profile {} FAILED.\n"
                  "Hub APS API response {} code.\n"
                  "Error: {}".format(counter, r.status_code, err))
            sys.exit(1)

        return r.json()['aps']['id']

    def _type_manager_available(self):
        r = self.aps.get('aps/2/services/resource-type-manager')
        try:
            apsapi_raise_for_status(r)
        except Exception:
            print("ERROR: Operations with type manager app needed, but not available on this\n" +
                  "HUB.\nCreation of new resource types is not possible without it.\n" +
                  "Please contact CloudBlue support to update your Hub or use Configure Option " +
                  "available on the connector instance on Hub control panel")
            sys.exit(1)
        return r.json()

    def _exists_item_profile_resource(self, package):
        r = self.aps.get('aps/2/resources?implementing({}/{}/{}.{})'.format(
            package.connector_id, "itemProfile", package.version, package.release))
        try:
            data = json.loads(r.content.decode('utf-8'))
            if data[0]['aps']['id']:
                return True
            return False
        except Exception:
            return False

    def _get_existing_ref_rts(self, app_id):
        self._type_manager_available()
        payload = {
            'resclass_name': 'rc.saas.countedlenk',
        }
        rts = self.osaapi.getResourceTypesByClass(**payload)
        existing_resources = []
        for resource in rts['result']:
            aps_rt = json.loads(
                self.aps.get('aps/2/services/resource-type-manager/resourceTypes/{}'.format(
                    resource['resource_type_id'])).content.decode('utf-8'))
            if 'app_id' in aps_rt['activationParameters'] and int(aps_rt['activationParameters'][
                                                                      'app_id']) == int(app_id):
                existing_resources.append(aps_rt['activationParameters']['resource_id'])
        return existing_resources

    def _find_existing(self, resource, app_id):
        aps_rt = json.loads(
            self.aps.get('aps/2/services/resource-type-manager/resourceTypes/{}'.format(
                resource['resource_type_id'])).content.decode('utf-8'))
        if 'app_id' in aps_rt['activationParameters'] and int(
                aps_rt['activationParameters'][
                    'app_id']) == int(app_id):
            return aps_rt['activationParameters']['resource_id']
        return False

    def _get_existing_counter_rts(self, app_id):
        self._type_manager_available()
        existing_resources = []
        rt_classes = ['rc.saas.resource.kbps',
                      'rc.saas.resource',
                      'rc.saas.resource.mbh',
                      'rc.saas.resource.mhz',
                      'rc.saas.resource.mhzh',
                      'rc.saas.resource.unit',
                      'rc.saas.resource.unith',
                      ]
        for rt_class in rt_classes:
            payload = {
                'resclass_name': rt_class,
            }
            rts = self.osaapi.getResourceTypesByClass(**payload)
            for resource in rts['result']:
                existing = self._find_existing(resource=resource, app_id=app_id)
                if existing:
                    existing_resources.append(existing)
        return existing_resources

    def _create_counted_ref_rts(self, package, app_id, update=False):
        rt_ids = {}
        if update:
            existis_item_profile = self._exists_item_profile_resource(package)
            if not existis_item_profile:
                print("ERROR: Create new resource types for this package version requested \n" +
                      "using new experimental mode, but seams this package uses counter mode.\n" +
                      "update operation aborted, either use normal mode, either ensure " +
                      "some item resources")
                sys.exit(1)
            existing_resources = self._get_existing_ref_rts(app_id)
        for counter, schema in package.counters.items():
            if update and counter in existing_resources:
                continue
            title = schema.get('title')
            resource_uid = self._create_service_profile(package, counter, title)
            payload = {
                'resclass_name': 'rc.saas.countedlenk',
                'name': title,
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': str(app_id)
                    },
                    {
                        'var_name': 'resource_uid',
                        'var_value': str(resource_uid)
                    },
                    {
                        'var_name': 'service_id',
                        'var_value': 'tenant'
                    },
                    {
                        'var_name': 'resource_id',
                        'var_value': str(counter)
                    }
                ]
            }

            response = self.osaapi.addResourceType(**payload)
            osaapi_raise_for_status(response)
            rt_ids[response['result']['resource_type_id']] = 0

        return rt_ids

    def _create_counter_rts(self, package, app_id, update=False):
        rt_ids = {}
        if update:
            existis_item_profile = self._exists_item_profile_resource(package)
            if existis_item_profile:
                print("ERROR: Create new resource types for this package version requested \n" +
                      "but seams this package has been instantiated using experimental mode.\n" +
                      "update operation aborted, either use experimental mode, either ensure " +
                      "marketProfile resources does not exists")
                sys.exit(1)
            existing_resources = self._get_existing_counter_rts(app_id)
        for counter, schema in package.counters.items():
            if update and counter in existing_resources:
                continue
            oa_unit_type = Hub._get_resclass_name(schema['unit'])
            payload = {
                'resclass_name': oa_unit_type,
                'name': '{}'.format(schema.get('title')),
                'act_params': [
                    {
                        'var_name': 'app_id',
                        'var_value': str(app_id)
                    },
                    {
                        'var_name': 'service_id',
                        'var_value': 'tenant'
                    },
                    {
                        'var_name': 'resource_id',
                        'var_value': str(counter)
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

    def create_rts(self, package, app_id, instance_uuid, experimental, update_rts=False):
        rts = {}
        if not update_rts:
            rts.update(self._create_core_rts(package, app_id, instance_uuid))
        if self._is_service_profile_supported(instance_uuid) and experimental:
            rts.update(self._create_counted_ref_rts(package, app_id, update_rts))
        else:
            rts.update(self._create_counter_rts(package, app_id, update_rts))
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

    def check_experimental_support(self):
        hub_version = self._get_hub_version(self.osaapi)
        self._assert_supported_version(hub_version, experimental=True)

    def check_connect_hub_app_installed(self):
        url = 'aps/2/resources?implementing(http://odin.com/servicesSelector/globals/2.0)'
        r = self.aps.get(url)
        try:
            data = json.loads(r.content.decode('utf-8'))
        except ValueError:
            print("APSController provided non-json format")
            sys.exit(1)
        else:
            if len(data) == 0:
                print("ERROR: Connect Hub extension is not installed")
                print("ERROR: Please follow the instructions available here: " +
                      "https://connect.cloudblue.com/documentation/extensions/" +
                      "cloudblue-commerce/reseller-control-panel/")
                sys.exit(1)

            match = re.match(
                r'http://odin.com/servicesSelector/globals/(?P<major>\d)\.(?P<minor>\d+)',
                data[0]['aps']['type'])
            if match:
                major = int(match.groupdict()['major'])
                minor = int(match.groupdict()['minor'])
                supported = (major >= 2 and minor > 1) or major > 2
                if not supported:
                    print("ERROR: Connect Hub extension is outdated")
                    print("ERROR: Please upgrade it using instructions available here: " +
                          "https://connect.cloudblue.com/documentation/extensions/" +
                          "cloudblue-commerce/reseller-control-panel/")
                    sys.exit(1)

    def get_connections(self, product_id):
        url = 'aps/2/resources/{}/connectionsInfo'.format(self.extension_id)
        payload = {
            "product": product_id
        }
        r = self.aps.post(url, json=payload)
        try:
            data = json.loads(r.content.decode('utf-8'))
            if data.get('id'):
                return data
            print("ERROR: Product {} has no connection to this HUB.\n".format(product_id) +
                  "Please access CloudBlue Connect provider panel to create a new one")
            exit(1)

        except ValueError:
            print("APSController provided non-json format")
            sys.exit(1)

    def get_application_id(self, package_id):
        payload = {
            'aps_application_id': package_id,
        }

        r = self.osaapi.aps.getApplications(**payload)
        osaapi_raise_for_status(r)

        if len(r['result']) == 0:
            return None
        return r['result'][0]['application_id'] or None

    def get_application_instances(self, application_id):
        payload = {
            'app_id': application_id,
        }

        r = self.osaapi.aps.getApplicationInstances(**payload)
        osaapi_raise_for_status(r)

        return r['result']

    def upgrade_application_instance(self, instance):
        payload = {
            'application_instance_id': int(instance),
        }

        r = self.osaapi.aps.upgradeApplicationInstance(**payload)
        osaapi_raise_for_status(r)

        return


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
