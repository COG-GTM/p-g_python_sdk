from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as get_version
from typing import Dict, Optional, Tuple
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.response import addinfourl

from uid2_client.encryption import _decrypt_gcm, _encrypt_gcm

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 10
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_RETRY_BASE_DELAY = 1.0


def _make_url(base_url: str, path: str) -> str:
    return base_url + path


def auth_headers(auth_key: str) -> Dict[str, str]:
    try:
        ver = get_version("uid2_client")
    except PackageNotFoundError:
        ver = "non-packaged-mode"

    return {'Authorization': 'Bearer ' + auth_key,
            "X-UID2-Client-Version": "uid2-client-python-" + ver}


def make_v2_request(secret_key: bytes, now: dt.datetime, data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
    nonce = os.urandom(8)
    payload += nonce
    if data:
        payload += data

    envelope = int.to_bytes(1, 1, 'big')
    envelope += _encrypt_gcm(payload, None, secret_key)

    return base64.b64encode(envelope), nonce


def parse_v2_response(secret_key: bytes, encrypted: bytes, nonce: bytes) -> bytes:
    payload = _decrypt_gcm(base64.b64decode(encrypted), secret_key)
    if nonce != payload[8:16]:
        raise ValueError("nonce mismatch")
    return payload[16:]


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, HTTPError):
        return exc.code >= 500
    if isinstance(exc, (URLError, TimeoutError, OSError)):
        return True
    return False


def post(
    base_url: str,
    path: str,
    headers: Dict[str, str],
    data: bytes,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    retry_base_delay: float = _DEFAULT_RETRY_BASE_DELAY,
) -> addinfourl:
    url = _make_url(base_url, path)
    req = request.Request(url, headers=headers, method='POST', data=data)
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            return request.urlopen(req, timeout=timeout)  # type: ignore[return-value]
        except Exception as exc:
            last_exc = exc
            if not _is_retryable(exc) or attempt == max_retries - 1:
                raise
            delay = retry_base_delay * (2 ** attempt)
            logger.warning(
                "Request to %s failed (attempt %d/%d): %s. Retrying in %.1fs",
                url, attempt + 1, max_retries, exc, delay,
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]
