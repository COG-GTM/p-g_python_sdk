from uid2_client import Uid2Client
from .request_response_util import DEFAULT_TIMEOUT_SECONDS


class EuidClientFactory:
    @staticmethod
    def create(endpoint, auth_key, secret_key, timeout=DEFAULT_TIMEOUT_SECONDS, retries=0):
        return Uid2Client.create_euid(endpoint, auth_key, secret_key, timeout=timeout, retries=retries)
