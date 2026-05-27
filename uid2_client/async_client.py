"""Async client for interacting with UID2 services.

Usage:
    >>> from uid2_client.async_client import AsyncUid2Client
    >>> client = AsyncUid2Client('https://prod.uidapi.com', 'my-auth-key', 'my-secret-key')
    >>> keys = await client.refresh_keys()
    >>> result = client.decrypt(token)
"""
from __future__ import annotations

import base64
import datetime as dt
from datetime import timezone
import json
import logging
import threading
from typing import Any, Dict, Optional

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from . import encryption
from .encryption import DecryptedToken
from .identity_scope import IdentityScope
from .keys import EncryptionKey, EncryptionKeysCollection
from .request_response_util import (
    auth_headers, make_v2_request, parse_v2_response,
    _make_url, _DEFAULT_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class AsyncUid2Client:
    """Async client for interacting with UID2 services.

    Mirrors the synchronous Uid2Client API but uses aiohttp for HTTP calls.
    Crypto operations remain synchronous (CPU-bound).
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
        self._identity_scope: Optional[IdentityScope] = None
        self._keys: Optional[EncryptionKeysCollection] = None
        self._keys_lock = threading.Lock()
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    @classmethod
    def create_uid2(cls, base_url: str, auth_key: str, secret_key: str) -> AsyncUid2Client:
        client = cls(base_url, auth_key, secret_key)
        client._identity_scope = IdentityScope.UID2
        return client

    @classmethod
    def create_euid(cls, base_url: str, auth_key: str, secret_key: str) -> AsyncUid2Client:
        client = cls(base_url, auth_key, secret_key)
        client._identity_scope = IdentityScope.EUID
        return client

    async def refresh_keys(self) -> EncryptionKeysCollection:
        """Fetch the latest encryption keys from the UID2 service."""
        req, nonce = make_v2_request(self._secret_key, dt.datetime.now(tz=timezone.utc))
        url = _make_url(self._base_url, '/v2/key/sharing')
        headers = auth_headers(self._auth_key)

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.post(url, headers=headers, data=req) as resp:
                resp.raise_for_status()
                resp_bytes = await resp.read()

        resp_body = json.loads(parse_v2_response(self._secret_key, resp_bytes, nonce)).get('body')
        keys = self._parse_keys_json(resp_body)
        with self._keys_lock:
            self._keys = keys
        return keys

    def refresh_json(self, json_str: str) -> EncryptionKeysCollection:
        """Parse JSON to get encryption keys (synchronous, no HTTP)."""
        body = json.loads(json_str)
        return self._parse_keys_json(body['body'])

    def encrypt(self, uid2: str, keyset_id: Optional[int] = None) -> str:
        """Encrypt a UID2 into a sharing token."""
        with self._keys_lock:
            keys = self._keys
        return encryption.encrypt(uid2, self._identity_scope, keys, keyset_id)

    def decrypt(self, token: str) -> DecryptedToken:
        """Decrypt an advertising token to extract UID2 details."""
        with self._keys_lock:
            keys = self._keys
        return encryption.decrypt(token, keys)

    def _parse_keys_json(self, resp_body: Dict[str, Any]) -> EncryptionKeysCollection:
        keys = []
        for key_data in resp_body["keys"]:
            keyset_id = None
            if "keyset_id" in key_data:
                keyset_id = key_data["keyset_id"]
            key = EncryptionKey(
                key_data['id'],
                key_data.get('site_id', -1),
                dt.datetime.fromtimestamp(key_data['created'], tz=timezone.utc),
                dt.datetime.fromtimestamp(key_data['activates'], tz=timezone.utc),
                dt.datetime.fromtimestamp(key_data['expires'], tz=timezone.utc),
                base64.b64decode(key_data['secret']),
                keyset_id,
            )
            keys.append(key)
        return EncryptionKeysCollection(
            keys,
            caller_site_id=resp_body.get("caller_site_id"),
            master_keyset_id=resp_body.get("master_keyset_id"),
            default_keyset_id=resp_body.get("default_keyset_id"),
            token_expiry_seconds=resp_body.get("token_expiry_seconds"),
        )
