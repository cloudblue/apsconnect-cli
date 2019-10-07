import json
import os
import sys
import zipfile
from xml.etree import ElementTree as xml_et

from shutil import copyfile

from requests import get

if sys.version_info >= (3,):
    from tempfile import TemporaryDirectory
    import xmlrpc.client as xmlrpclib
else:
    from backports.tempfile import TemporaryDirectory
    import xmlrpclib


class Package(object):
    source = None
    tempdir = None
    filename = None
    path = None
    instance_only = False

    package_body = None
    meta_path = None
    tenant_schema_path = None
    app_schema_path = None

    connector_id = None
    connector_name = None
    version = None
    release = None

    app_properties = {}
    tenant_properties = {}

    def __init__(self, source, instance_only=False):
        self.instance_only = instance_only
        with TemporaryDirectory() as tempdir:
            self.source = source
            self.tempdir = tempdir
            if self.is_http:
                self.filename = Package._download(self.source, self.tempdir)
            else:
                self.filename = os.path.basename(self.source)
                copyfile(os.path.expanduser(self.source), os.path.join(self.tempdir, self.filename))
            self.path = os.path.join(self.tempdir, self.filename)
            with open(self.path, 'rb') as f:
                self.body = xmlrpclib.Binary(f.read())
            self._extract_files()
            self._parse_metadata()

    @staticmethod
    def _download(source, target=None):
        local_filename = source.split('/')[-1]
        if target:
            local_filename = os.path.join(target, local_filename)

        r = get(source, stream=True)
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        return local_filename

    @staticmethod
    def _get_properties(schema_file):
        with open(schema_file) as f:
            try:
                return json.load(f)['properties']
            except (ValueError, KeyError):
                print("Schema is not correct json file")
                sys.exit(1)

    @property
    def resources(self):
        resource_types = [
            'http://aps-standard.org/types/core/resource/1.0#Counter',
            'http://aps-standard.org/types/core/resource/1.0#Limit',
        ]
        resources = {}

        for key in self.tenant_properties:
            if self.tenant_properties[key]['type'] in resource_types:
                resources[key] = self.tenant_properties[key]

        return resources

    @property
    def counters(self):
        return {k: v for k, v in self.resources.items() if 'title' in v}

    @property
    def parameters(self):
        return {k: v for k, v in self.resources.items() if 'title' not in v}

    @property
    def is_http(self):
        return self.source.startswith('http://') or self.source.startswith('https://')

    def _extract_files(self):
        with zipfile.ZipFile(self.path) as zip_ref:
            self.meta_path = zip_ref.extract('APP-META.xml', path=self.tempdir)
            if self.instance_only:
                return

            self.tenant_schema_path = zip_ref.extract('schemas/tenant.schema', self.tempdir)
            self.app_schema_path = zip_ref.extract('schemas/app.schema', self.tempdir)

    def _parse_metadata(self):
        tree = xml_et.ElementTree(file=self.meta_path)
        ns = '{http://aps-standard.org/ns/2}'
        self.connector_id = tree.find('{}id'.format(ns)).text
        self.version = tree.find('{}version'.format(ns)).text
        self.release = tree.find('{}release'.format(ns)).text

        self.connector_name = tree.find('{}name'.format(ns)).text

        if self.instance_only:
            return

        self.app_properties = Package._get_properties(self.app_schema_path)
        self.tenant_properties = Package._get_properties(self.tenant_schema_path)
