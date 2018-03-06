import boto3
import logging

logger = logging.getLogger(__name__)


class AWSAPIException(Exception):
    def __init___(self, error_text):
        Exception.__init__(self, "Error while calling AWS API. Error details from AWS: {0}".
                           format(error_text))


class AWSClient(object):
    """Parent client class for asw services"""
    def __init__(self, service_name, region, key_id, access_key):
        session = boto3.session.Session()
        self.client = session.client(
            service_name=service_name,
            region_name=region,
            aws_access_key_id=key_id,
            aws_secret_access_key=access_key,
        )


class ECRClient(AWSClient):
    """Client for ECR operations"""
    service_name = 'ecr'

    def __init__(self, region, key_id, access_key):
        super(ECRClient, self) \
            .__init__(self.service_name, region, key_id, access_key)

    def get_auth_token(self, registry_id=None):
        response = self.client.get_authorization_token(registryIds=[registry_id, ])
        return response
