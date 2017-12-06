import json
import yaml


class FakeK8sApi(object):
    def __init__(self, is_no_connection=False):
        self.is_no_connection = is_no_connection

    def get_code(self):
        if self.is_no_connection:
            raise Exception('K8s-host refused connection.')
        return 0


class FakeData:
    SCHEMA_PATH = '/tmp/schema'
    CONFIG_PATH = '/tmp/fake_config'
    VALID_JSON = '{"properties": {"foo": "bar"}}'
    CONFIG_WITH_UNSUPPORTED_FORMAT = """
        <?xml version="1.0"?>
        <properties>
            <foo>ba: r: sd</foo>
        </properties>
    """
    BAD_JSON = '{"props": '
    BAD_YAML = 'properties: foo: bar'
    PROPERTIES = 'fake properties'
    SCHEMA_DICT = {'properties': PROPERTIES}
    SCHEMA_YAML = yaml.dump(SCHEMA_DICT, allow_unicode=True, default_flow_style=False)
    SCHEMA_JSON = json.dumps(SCHEMA_DICT)
    BAD_SCHEMA_JSON = '{{"props": "{}"}}'.format(PROPERTIES)
    DEFAULT_NAMESPACE = 'default'


class FakeErrors(object):
    FAKE_ERR_MSG_500 = '500: internal server error'
    FAKE_ERR_MSG = 'Not enough minerals.'
