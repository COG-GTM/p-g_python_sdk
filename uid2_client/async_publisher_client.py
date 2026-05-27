"""Async publisher client for interacting with UID2 publisher services.

Usage:
    >>> from uid2_client.async_client import AsyncUid2PublisherClient
    >>> client = AsyncUid2PublisherClient('https://prod.uidapi.com', 'my-auth-key', 'my-secret-key')
    >>> response = await client.generate_token(TokenGenerateInput.from_email("test@email.com"))
"""
from __future__ import annotations

import base64
import datetime as dt
import logging
from datetime import timezone

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from .encryption import _decrypt_gcm
from .identity_tokens import IdentityTokens
from .input_util import base64_to_byte_array
from .request_response_util import (
    _DEFAULT_TIMEOUT_SECONDS,
    _make_url,
    auth_headers,
    make_v2_request,
    parse_v2_response,
)
from .token_generate_input import TokenGenerateInput
from .token_generate_response import TokenGenerateResponse
from .token_refresh_response import TokenRefreshResponse

logger = logging.getLogger(__name__)


class AsyncUid2PublisherClient:
    """Async client for interacting with UID2 publisher services.

    Mirrors the synchronous Uid2PublisherClient API but uses aiohttp for HTTP calls.
    """

    def __init__(
        self,
        base_url: str,
        auth_key: str,
        secret_key: str,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not _HAS_AIOHTTP:
            raise ImportError(
                "aiohttp is required for async support. "
                "Install it with: pip install uid2-client[async]"
            )
        self._base_url = base_url
        self._auth_key = auth_key
        self._secret_key = base64.b64decode(secret_key)
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    async def generate_token(self, token_generate_input: TokenGenerateInput) -> TokenGenerateResponse:
        """Generate an advertising token from an email, phone number, or hash."""
        req, nonce = make_v2_request(
            self._secret_key, dt.datetime.now(tz=timezone.utc),
            token_generate_input.get_as_json_string().encode(),
        )
        url = _make_url(self._base_url, '/v2/token/generate')
        headers = auth_headers(self._auth_key)

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.post(url, headers=headers, data=req) as resp:
                resp.raise_for_status()
                resp_bytes = await resp.read()

        resp_body = parse_v2_response(self._secret_key, resp_bytes, nonce)
        return TokenGenerateResponse(resp_body)

    async def refresh_token(self, current_identity: IdentityTokens) -> TokenRefreshResponse:
        """Refresh an advertising token."""
        refresh_token = current_identity.get_refresh_token()
        if refresh_token is None:
            raise ValueError("No refresh token available in identity")
        url = _make_url(self._base_url, '/v2/token/refresh')
        headers = auth_headers(self._auth_key)

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.post(
                url, headers=headers,
                data=refresh_token.encode(),
            ) as resp:
                resp.raise_for_status()
                resp_bytes = await resp.read()

        decrypted_bytes = base64_to_byte_array(resp_bytes)
        decrypted = _decrypt_gcm(decrypted_bytes, base64_to_byte_array(current_identity.get_refresh_response_key()))
        return TokenRefreshResponse(decrypted.decode(), dt.datetime.now(tz=timezone.utc))
