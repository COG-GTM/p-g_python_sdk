from __future__ import annotations

import base64
import datetime as dt
import email.message
import io
import os
import time
import urllib.error
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import IO
from urllib import request

from uid2_client.encryption import _encrypt_gcm, _decrypt_gcm

DEFAULT_TIMEOUT_SECONDS = 30


class Uid2HttpError(urllib.error.HTTPError):
    """Raised when the UID2 service returns a non-2xx HTTP response."""

    def __init__(self, status: int, reason: str, body: bytes, url: str):
        super().__init__(url, status, reason, email.message.Message(), io.BytesIO(body))
        self.body = body
        self.url = url

    def __str__(self) -> str:
        return f"UID2 request to {self.url} failed with HTTP {self.status}: {self.reason}"


def _make_url(base_url: str, path: str) -> str:
    return base_url + path


def auth_headers(auth_key: str) -> dict[str, str]:
    try:
        version = _pkg_version("uid2_client")
    except PackageNotFoundError:
        version = "non-packaged-mode"

    return {'Authorization': 'Bearer ' + auth_key,
            "X-UID2-Client-Version": "uid2-client-python-" + version}


def make_v2_request(secret_key: bytes, now: dt.datetime, data: bytes | None = None) -> tuple[bytes, bytes]:
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


def post(base_url: str, path: str, headers: dict[str, str], data: bytes,
         timeout: int = DEFAULT_TIMEOUT_SECONDS, retries: int = 0, backoff_seconds: float = 0.5) -> IO[bytes]:
    url = _make_url(base_url, path)
    req = request.Request(url, headers=headers, method='POST', data=data)
    for attempt in range(retries + 1):
        try:
            return request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if (exc.code >= 500 or exc.code == 429) and attempt < retries:
                time.sleep(backoff_seconds * 2 ** attempt)
                continue
            raise Uid2HttpError(exc.code, exc.reason, exc.read(), url) from exc
        except (urllib.error.URLError, TimeoutError):
            if attempt < retries:
                time.sleep(backoff_seconds * 2 ** attempt)
                continue
            raise
    raise RuntimeError("request attempts exhausted")
