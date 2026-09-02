"""Internal module for keeping facilities related to encryption keys.

Do not use this module directly, import from uid2_client instead, e.g.
>>> from uid2_client import EncryptionKeysCollection
"""

from __future__ import annotations


import datetime as dt
from bisect import bisect_right
from typing import Iterable, KeysView, ValuesView


class EncryptionKey:
    """Wrapper class for keeping data about an encryption key.

    Attrs:
        key_id (int): identifier of the key
        site_id (int): id of the site the key belongs to
        created (datetime): UTC date/time for when the key was created
        activates (datetime): UTC date/time for when the key becomes active
        expires (datetime): UTC date/time for when the key expires
        secret (bytes): the actual encryption key
    """

    def __init__(self, key_id: int, site_id: int, created: dt.datetime, activates: dt.datetime,
                 expires: dt.datetime, secret: bytes, keyset_id: int | None = None) -> None:
        """Create a new encryption key."""
        self._id = key_id
        self._site_id = site_id
        self._created = created
        self._activates = activates
        self._expires = expires
        self._secret = secret
        self._keyset_id = keyset_id


    @property
    def key_id(self) -> int:
        """int: Unique identifier of the key."""
        return self._id


    @property
    def site_id(self) -> int:
        """int: id of the site the key belongs to."""
        return self._site_id

    @property
    def keyset_id(self) -> int | None:
        """int: keyset id, can be None"""
        return self._keyset_id


    @property
    def created(self) -> dt.datetime:
        """datetime: UTC date/time for when the key was created."""
        return self._created


    @property
    def activates(self) -> dt.datetime:
        """datetime: UTC date/time for when the key becomes active."""
        return self._activates


    @property
    def expires(self) -> dt.datetime:
        """datetime: UTC date/time for when the key expires."""
        return self._expires


    @property
    def secret(self) -> bytes:
        """bytes: encryption key data. """
        return self._secret


    def is_active(self, now: dt.datetime) -> bool:
        """Whether the key is active at the specified time."""
        return self._activates <= now and now < self._expires


class _SiteKeyActivatesList:
    """Internal wrapper for list of site keys."""

    def __init__(self, site_keys):
        self._site_keys = site_keys


    def __len__(self):
        return len(self._site_keys)


    def __getitem__(self, i):
        return self._site_keys[i].activates


class EncryptionKeysCollection:
    """A collection of EncryptionKey objects.

    This is a dictionary like immutable collection object containing encryption keys
    used for decoding UID2 advertising tokens.
    """

    def __init__(self, keys: Iterable[EncryptionKey], caller_site_id: int | None = None,
                 master_keyset_id: int | None = None, default_keyset_id: int | None = None,
                 token_expiry_seconds: int | None = None) -> None:
        self._latest_expires: dt.datetime | None = None
        self._keys: dict[int, EncryptionKey] = {}
        self._keys_by_site: dict[int, list[EncryptionKey]] = {}
        self._keys_by_keyset: dict[int, list[EncryptionKey]] = {}
        self.set_keys(keys)
        self._caller_site_id = caller_site_id
        self._master_keyset_id = master_keyset_id
        self._default_keyset_id = default_keyset_id
        self._token_expiry_seconds = token_expiry_seconds

    def set_keys(self, keys: Iterable[EncryptionKey]) -> None:
        for key in keys:
            self._keys[key.key_id] = key
            if key.site_id > 0:
                self._keys_by_site.setdefault(key.site_id, []).append(key)
            if key.keyset_id is not None:
                self._keys_by_keyset.setdefault(key.keyset_id, []).append(key)
            if self._latest_expires is None or key.expires > self._latest_expires:
                self._latest_expires = key.expires
        for _, site_keys in self._keys_by_site.items():
            site_keys.sort(key=lambda x: x.activates)

    def __len__(self) -> int:
        return len(self._keys)


    def __contains__(self, key_id: int) -> bool:
        return key_id in self._keys.keys()


    def __getitem__(self, key_id: int) -> EncryptionKey:
        return self._keys[key_id]

    def get_caller_site_id(self) -> int | None:
        return self._caller_site_id

    def get_master_keyset_id(self) -> int | None:
        return self._master_keyset_id

    def get_default_keyset_id(self) -> int | None:
        return self._default_keyset_id

    def get_token_expiry_seconds(self) -> int | None:
        return self._token_expiry_seconds


    def get(self, key_id: int, default: EncryptionKey | None = None) -> EncryptionKey | None:
        """Get encryption key with the specified id, else default."""
        return self._keys.get(key_id, default)


    def key_ids(self) -> KeysView[int]:
        """Get list of ids of the keys available in the collection."""
        return self._keys.keys()


    def values(self) -> ValuesView[EncryptionKey]:
        """Get all encryption keys in the collection as a list."""
        return self._keys.values()


    def get_default_keyset_key(self, now: dt.datetime) -> EncryptionKey | None:
        return self.get_by_keyset_key(self._default_keyset_id, now)

    def get_master_key(self, now: dt.datetime) -> EncryptionKey | None:
        return self.get_by_keyset_key(self._master_keyset_id, now)


    def get_by_keyset_key(self, keyset_id: int | None, now: dt.datetime) -> EncryptionKey | None:
        """ Gets Active Key by keyset_id

        Args:
            keyset_id: the keyset id to get

        Returns: EncryptionKey: active keyset key or None

        """
        if keyset_id is None:
            return None
        keyset_keys = self._keys_by_keyset.get(keyset_id)
        if keyset_keys is None or len(keyset_keys) == 0:
            return None
        i = bisect_right(_SiteKeyActivatesList(keyset_keys), now)
        while i > 0:
            i -= 1
            key = keyset_keys[i]
            if key.is_active(now):
                return key
        return None

    def get_active_site_key(self, site_id: int | None, now: dt.datetime) -> EncryptionKey | None:
        """Get active encryption key for the specified site, else None.

        Args:
            site_id (int): ID of the site to get the key for
            now (datetime): date/time to use as timestamp to determine whether the key is active

        Returns:
            EncryptionKey: active site key or None
        """
        if site_id is None:
            return None
        site_keys = self._keys_by_site.get(site_id)
        if site_keys is None or len(site_keys) == 0:
            return None
        i = bisect_right(_SiteKeyActivatesList(site_keys), now)
        while i > 0:
            i -= 1
            key = site_keys[i]
            if key.is_active(now):
                return key
        return None


    def valid(self, now: dt.datetime) -> bool:
        """Check whether the collection is valid.

        Collection is considered valid if at least one key has expiry date/time after now."""
        return self._latest_expires is not None and self._latest_expires > now
