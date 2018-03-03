import datetime
import hashlib
import hmac
import requests
import logging
import json
from collections import OrderedDict

logger = logging.getLogger(__name__)


class AWSAPIException(Exception):
    def __init___(self, error_text):
        Exception.__init__(self, "Error while calling AWS API. Error details from AWS: {0}".
                           format(error_text))


class AWSClient(object):
    """Parent client class for asw services"""

    def __init__(self, service_name, region, key_id, access_key):
        self.service_name = service_name
        self.region = region
        self.key = key_id
        self.secret = access_key

    def sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def get_signature_key(self, date_stamp):
        k_date = self.sign(("AWS4{}".format(self.secret)).encode("utf-8"), date_stamp)
        k_region = self.sign(k_date, self.region)
        k_service = self.sign(k_region, self.service_name)
        k_signing = self.sign(k_service, "aws4_request")
        return k_signing

    def resolve_api_url(self):
        endpoint_url = "https://<service_name>.<region>.amazonaws.com"
        if not self.region:
            raise ValueError('AWS region is not provided')
        else:
            return endpoint_url.replace("<service_name>", self.service_name) \
                .replace("<region>", self.region)

    def resolve_host_name(self):
        host = "<service_name>.<region>.amazonaws.com"
        if not self.region:
            raise ValueError('AWS region is not provided')
        else:
            return host.replace("<service_name>", self.service_name) \
                .replace("<region>", self.region)

    def get_common_headers(self):
        headers = OrderedDict()
        headers['content-type'] = 'application/x-amz-json-1.1'
        headers['host'] = self.resolve_host_name()
        return headers

    def get_canonical_headers(self, headers):
        canonical_header = ''
        for key, value in headers.iteritems():
            canonical_header += "{}:{}{}".format(key, value, '\n')

        return canonical_header

    def get_signed_headers(self, headers):
        signed_header = ''
        for key, value in headers.iteritems():
            signed_header += "{};".format(key)

        return signed_header[:-1]

    def get_canonical_request(self, method, request_params, canonical_headers, signed_headers):
        # Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)
        canonical_uri = '/'

        # Create the canonical query string. In this example, request
        # parameters are passed in the body of the request and the query string
        # is blank.
        canonical_querystring = ''

        if method.lower() == "get":
            canonical_querystring = request_params
        # Create payload hash.(body of the request) contains the request parameters.

        payload_hash = hashlib.sha256(request_params.encode('utf-8')).hexdigest()
        # Combine elements to create canonical request
        canonical_request = "{}\n{}\n{}\n".format(method, canonical_uri, canonical_querystring)
        canonical_request += "{}\n{}\n{}".format(canonical_headers, signed_headers, payload_hash)

        return canonical_request

    def get_request_headers(self, method=None, request_params=None, aws_target=None):
        # Create a date for headers and the credential string
        datetime_now = datetime.datetime.utcnow()
        amz_date = datetime_now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = datetime_now.strftime('%Y%m%d')  # date without time, used in credential scope
        headers = self.get_common_headers()
        headers.update({'x-amz-date': amz_date,
                        'x-amz-target': aws_target})
        cannonical_header = self.get_canonical_headers(headers)
        signed_header = self.get_signed_headers(headers)
        canonical_request = self.get_canonical_request(method, request_params,
                                                       cannonical_header, signed_header)

        auth_algorithm = 'AWS4-HMAC-SHA256'

        credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, self.region,
                                                          self.service_name)
        string_to_sign = "{}\n{}\n{}\n".format(auth_algorithm, amz_date, credential_scope)
        string_to_sign += hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        signing_key = self.get_signature_key(date_stamp)

        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).\
            hexdigest()

        authorization_header = "{} Credential={}/".format(auth_algorithm, self.key)
        authorization_header += "{}, SignedHeaders={}, ".format(credential_scope, signed_header)
        authorization_header += "Signature={}".format(signature)
        del headers['host']
        headers.update({'Authorization': authorization_header})
        return headers

    def call_api(self, url, method, params, aws_target):
        headers = self.get_request_headers(method=method, request_params=params,
                                           aws_target=aws_target)

        response = requests.post(url, data=params, headers=headers)

        if response.ok:
            return json.loads(response.text)
        else:
            raise AWSAPIException(response.text)
