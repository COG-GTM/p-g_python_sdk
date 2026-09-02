from uid2_client import Uid2Client
from .request_response_util import DEFAULT_TIMEOUT_SECONDS


class Uid2ClientFactory:
    @staticmethod
    def create(endpoint, auth_key, secret_key, timeout=DEFAULT_TIMEOUT_SECONDS, retries=0):
        return Uid2Client.create_uid2(endpoint, auth_key, secret_key, timeout=timeout, retries=retries)
