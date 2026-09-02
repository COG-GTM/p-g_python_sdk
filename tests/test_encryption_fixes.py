import datetime as dt
import unittest

from uid2_client import (
    EncryptionError,
    EncryptionKeysAutoRefresher,
    EncryptionKeysCollection,
    IdentityScope,
    decrypt,
    encrypt,
)
from tests.test_utils import (
    example_uid,
    master_key,
    site_key,
)
from tests.uid2_token_generator import UID2TokenGenerator


class TestEncryptionFixes(unittest.TestCase):
    def test_decrypt_uses_current_time_when_now_is_omitted(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(example_uid, master_key, 9000, site_key)
        result = decrypt(token, EncryptionKeysCollection([master_key, site_key]))
        self.assertEqual(example_uid, result.uid2)

    def test_encrypt_without_caller_site_id_raises_encryption_error(self):
        keys = EncryptionKeysCollection([master_key, site_key], None, 1, 99999)
        with self.assertRaises(EncryptionError):
            encrypt(example_uid, IdentityScope.UID2, keys)

    def test_auto_refresh_records_runtime_error_and_repr_is_safe(self):
        class FailingClient:
            def refresh_keys(self):
                raise RuntimeError("refresh failed")

        refresher = EncryptionKeysAutoRefresher(FailingClient(), dt.timedelta(seconds=1), dt.timedelta(seconds=1))
        self.assertFalse(refresher._try_refresh_keys())
        result = refresher.current_result()
        self.assertFalse(result.ready)
        self.assertIsNotNone(result.last_error)
        self.assertIsInstance(repr(result), str)

    def test_auto_refresh_does_not_swallow_keyboard_interrupt(self):
        class InterruptingClient:
            def refresh_keys(self):
                raise KeyboardInterrupt()

        refresher = EncryptionKeysAutoRefresher(InterruptingClient(), dt.timedelta(seconds=1), dt.timedelta(seconds=1))
        with self.assertRaises(KeyboardInterrupt):
            refresher._try_refresh_keys()


if __name__ == "__main__":
    unittest.main()
