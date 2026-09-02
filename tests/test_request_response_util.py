import base64
import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from uid2_client.request_response_util import (
    DEFAULT_TIMEOUT_SECONDS,
    Uid2HttpError,
    post,
)
from uid2_client.uid2_client_factory import Uid2ClientFactory
from tests.test_utils import client_secret


class TestPost(unittest.TestCase):
    def test_post_uses_default_timeout(self):
        with patch("uid2_client.request_response_util.request.urlopen") as urlopen:
            response = object()
            urlopen.return_value = response
            self.assertIs(response, post("https://example.com", "/path", {}, b"data"))
            self.assertEqual(DEFAULT_TIMEOUT_SECONDS, urlopen.call_args.kwargs["timeout"])

    def test_http_500_raises_uid2_http_error_without_retry(self):
        error = HTTPError("https://example.com/path", 500, "server error", {}, io.BytesIO(b"body"))
        with patch("uid2_client.request_response_util.request.urlopen", side_effect=error):
            with self.assertRaises(Uid2HttpError) as context:
                post("https://example.com", "/path", {}, b"data")
        self.assertEqual(500, context.exception.status)
        self.assertEqual(b"body", context.exception.body)

    def test_http_503_retries_then_returns_success(self):
        error = HTTPError("https://example.com/path", 503, "unavailable", {}, io.BytesIO(b""))
        response = object()
        with patch("uid2_client.request_response_util.request.urlopen", side_effect=[error, response]) as urlopen:
            with patch("uid2_client.request_response_util.time.sleep") as sleep:
                self.assertIs(response, post("https://example.com", "/path", {}, b"data", retries=1))
        self.assertEqual(2, urlopen.call_count)
        sleep.assert_called_once_with(0.5)

    def test_http_400_does_not_retry(self):
        error = HTTPError("https://example.com/path", 400, "bad request", {}, io.BytesIO(b"body"))
        with patch("uid2_client.request_response_util.request.urlopen", side_effect=error) as urlopen:
            with self.assertRaises(Uid2HttpError) as context:
                post("https://example.com", "/path", {}, b"data", retries=2)
        self.assertEqual(400, context.exception.status)
        self.assertEqual(1, urlopen.call_count)

    def test_url_error_retries_then_returns_success(self):
        response = object()
        with patch("uid2_client.request_response_util.request.urlopen",
                   side_effect=[URLError("temporary"), response]) as urlopen:
            with patch("uid2_client.request_response_util.time.sleep"):
                self.assertIs(response, post("https://example.com", "/path", {}, b"data", retries=1))
        self.assertEqual(2, urlopen.call_count)

    @patch("uid2_client.client.parse_v2_response", return_value=b'{"body": {"keys": [], "caller_site_id": null, '
                                                                b'"master_keyset_id": null, "token_expiry_seconds": null}}')
    @patch("uid2_client.client.make_v2_request", return_value=(b"request", b"nonce"))
    @patch("uid2_client.client.post")
    def test_factory_forwards_timeout_and_retries(self, post_mock, make_request, parse_response):
        post_mock.return_value.read.return_value = base64.b64encode(b"response")
        client = Uid2ClientFactory.create("u", "k", client_secret, timeout=5, retries=2)
        client.refresh_keys()
        self.assertEqual(5, post_mock.call_args.kwargs["timeout"])
        self.assertEqual(2, post_mock.call_args.kwargs["retries"])


if __name__ == "__main__":
    unittest.main()
