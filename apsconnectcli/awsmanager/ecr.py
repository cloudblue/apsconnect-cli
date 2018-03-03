import json
import logging

from aws import AWSClient

logger = logging.getLogger(__name__)


class ECRClient(AWSClient):
    """Client for ECR operations"""
    serviceName = 'ecr'

    def __init__(self, region, key_id, access_key):
        super(ECRClient, self) \
            .__init__(ECRClient.serviceName, region, key_id, access_key)

    def get_authorization_token(self, registry_ids=None):
        url = self.resolve_api_url()

        if not registry_ids:
            params = '{}'
        else:
            params = json.dumps({"registryIds": registry_ids})
        aws_target = 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken'

        return self.call_api(url, 'POST', params, aws_target)
