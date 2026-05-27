"""Internal module for holding the Uid2Client class.

Do not use this module directly, import through uid2_client module instead, e.g.

>>> from uid2_client import Uid2PublisherClient
"""
from __future__ import annotations

import base64
import datetime as dt
from datetime import timezone


from .encryption import _decrypt_gcm
from .identity_tokens import IdentityTokens
from .request_response_util import (
    post, auth_headers, make_v2_request, parse_v2_response,
    _DEFAULT_TIMEOUT_SECONDS, _DEFAULT_MAX_RETRIES, _DEFAULT_RETRY_BASE_DELAY,
)
from .token_generate_input import TokenGenerateInput
from .token_generate_response import TokenGenerateResponse
from .token_refresh_response import TokenRefreshResponse
from .input_util import base64_to_byte_array


class Uid2PublisherClient:
    """Client for interacting with UID2 publisher services.

        You will need to have the base URL of the endpoint and a client key pair (auth/secret)
        to consume web services.

        Methods:
            generate_token: generate an advertising token from an email, phone #, or hash
            refresh_token: refresh an advertising token

        Examples:
            Connect to the UID2 service and obtain the latest encryption keys:
            >>> from uid2_client import *
            >>> client = Uid2PublisherClient('https://prod.uidapi.com', 'my-authorization-key', 'my-secret-key')
            >>> response = client.generate_token(TokenGenerateInput.from_email("test@email.com"))
            >>> new_token = client.refresh_token(response.get_identity())
    """

    def __init__(
        self,
        base_url: str,
        auth_key: str,
        secret_key: str,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        retry_base_delay: float = _DEFAULT_RETRY_BASE_DELAY,
    ) -> None:
        """Create a new Uid2PublisherClient client.

        Args:
            base_url (str): base URL for all requests to UID2 services (e.g. 'https://prod.uidapi.com')
            auth_key (str): authorization key for consuming the UID2 services
            secret_key (str): secret key for consuming the UID2 services
            timeout (float): HTTP request timeout in seconds (default 10)
            max_retries (int): maximum number of retry attempts for transient errors (default 3)
            retry_base_delay (float): base delay in seconds for exponential backoff (default 1.0)

        Note:
            Your authorization key will determine which UID2 services you are allowed to use.
        """
        self._base_url = base_url
        self._auth_key = auth_key
        self._secret_key = base64.b64decode(secret_key)
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay

    def generate_token(self, token_generate_input: TokenGenerateInput) -> TokenGenerateResponse:
        req, nonce = make_v2_request(self._secret_key, dt.datetime.now(tz=timezone.utc),
                                     token_generate_input.get_as_json_string().encode())
        resp = post(
            self._base_url, '/v2/token/generate', headers=auth_headers(self._auth_key), data=req,
            timeout=self._timeout, max_retries=self._max_retries, retry_base_delay=self._retry_base_delay,
        )
        resp_body = parse_v2_response(self._secret_key, resp.read(), nonce)
        return TokenGenerateResponse(resp_body)

    def refresh_token(self, current_identity: IdentityTokens) -> TokenRefreshResponse:
        resp = post(
            self._base_url, '/v2/token/refresh', headers=auth_headers(self._auth_key),
            data=current_identity.get_refresh_token().encode(),
            timeout=self._timeout, max_retries=self._max_retries, retry_base_delay=self._retry_base_delay,
        )
        resp_bytes = base64_to_byte_array(resp.read())
        decrypted = _decrypt_gcm(resp_bytes, base64_to_byte_array(current_identity.get_refresh_response_key()))
        return TokenRefreshResponse(decrypted.decode(), dt.datetime.now(tz=timezone.utc))
