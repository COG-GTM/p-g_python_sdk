"""Client implementation and helper functions for integrating with the UID2 services.

Classes:
    Uid2Client: main API for interacting with a UID service

Functions:
    decrypt_token: decrypt and advertising token to extract advertising ID from it
"""


from .auto_refresh import EncryptionKeysAutoRefresher, EncryptionKeysAutoRefreshResult
from .client import Uid2Client, Uid2ClientError
from .encryption import (
    decrypt,
    decrypt_data,
    encrypt,
    encrypt_data,
    DecryptedToken,
    DecryptedData,
    EncryptionError,
    encryption_block_size,
)
from .keys import EncryptionKey, EncryptionKeysCollection
from .euid_client_factory import EuidClientFactory
from .uid2_client_factory import Uid2ClientFactory
from .token_generate_input import TokenGenerateInput
from .token_generate_response import TokenGenerateResponse
from .publisher_client import Uid2PublisherClient
from .identity_tokens import IdentityTokens
from .identity_scope import IdentityScope
from .identity_type import IdentityType
from .advertising_token_version import AdvertisingTokenVersion

__all__ = [
    "EncryptionKeysAutoRefresher",
    "EncryptionKeysAutoRefreshResult",
    "Uid2Client",
    "Uid2ClientError",
    "decrypt",
    "decrypt_data",
    "encrypt",
    "encrypt_data",
    "DecryptedToken",
    "DecryptedData",
    "EncryptionError",
    "encryption_block_size",
    "EncryptionKey",
    "EncryptionKeysCollection",
    "EuidClientFactory",
    "Uid2ClientFactory",
    "TokenGenerateInput",
    "TokenGenerateResponse",
    "Uid2PublisherClient",
    "IdentityTokens",
    "IdentityScope",
    "IdentityType",
    "AdvertisingTokenVersion",
]

try:
    from .async_client import AsyncUid2Client
    from .async_publisher_client import AsyncUid2PublisherClient
    __all__ += ["AsyncUid2Client", "AsyncUid2PublisherClient"]
except ImportError:
    pass
