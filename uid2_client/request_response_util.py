import base64
import os
import time
import urllib.error
from urllib import request

import pkg_resources

from uid2_client.encryption import _encrypt_gcm, _decrypt_gcm

DEFAULT_TIMEOUT_SECONDS = 30


class Uid2HttpError(Exception):
    """Raised when the UID2 service returns a non-2xx HTTP response."""

    def __init__(self, status: int, reason: str, body: bytes, url: str):
        super().__init__(f"UID2 request to {url} failed with HTTP {status}: {reason}")
        self.status = status
        self.reason = reason
        self.body = body
        self.url = url


def _make_url(base_url, path):
    return base_url + path


def auth_headers(auth_key):
    try:
        version = pkg_resources.get_distribution("uid2_client").version
    except Exception:
        version = "non-packaged-mode"

    return {'Authorization': 'Bearer ' + auth_key,
            "X-UID2-Client-Version": "uid2-client-python-" + version}


def make_v2_request(secret_key, now, data=None):
    payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
    nonce = os.urandom(8)
    payload += nonce
    if data:
        payload += data

    envelope = int.to_bytes(1, 1, 'big')
    envelope += _encrypt_gcm(payload, None, secret_key)

    return base64.b64encode(envelope), nonce


def parse_v2_response(secret_key, encrypted, nonce):
    payload = _decrypt_gcm(base64.b64decode(encrypted), secret_key)
    if nonce != payload[8:16]:
        raise ValueError("nonce mismatch")
    return payload[16:]


def post(base_url, path, headers, data, timeout=DEFAULT_TIMEOUT_SECONDS, retries=0, backoff_seconds=0.5):
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
    raise RuntimeError('request attempts exhausted')
