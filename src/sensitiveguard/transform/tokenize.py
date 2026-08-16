"""HMAC-backed one-way tokenization."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from threading import RLock


class TokenResolutionDisabled(LookupError):
    """Raised when reverse lookup is requested from a one-way vault."""


class TokenVault:
    """Issue deterministic, run-scoped HMAC tokens.

    Raw values are not retained unless ``store_raw=True`` is explicitly chosen.
    The default therefore provides tokenized correlation, not reversible vaulting.
    """

    def __init__(self, secret_key: bytes | None = None, *, store_raw: bool = False) -> None:
        key = secret_key if secret_key is not None else secrets.token_bytes(32)
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("secret_key must contain at least 16 bytes")
        self._secret_key = key
        self._store_raw = bool(store_raw)
        self._raw_values: dict[str, str] | None = {} if self._store_raw else None
        self._tokens_by_run: dict[str, set[str]] = {} if self._store_raw else {}
        self._lock = RLock()

    @property
    def stores_raw(self) -> bool:
        return self._store_raw

    def tokenize(self, value: str, label: str, run_id: str) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        if not run_id:
            raise ValueError("run_id must not be empty")
        normalized_label = label.upper() or "SENSITIVE"
        payload = f"{len(run_id)}:{run_id}{len(normalized_label)}:{normalized_label}{len(value)}:{value}".encode()
        digest = hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()[:24].upper()
        safe_label = "".join(character for character in normalized_label if character.isalnum() or character == "_")
        token = f"{safe_label or 'SENSITIVE'}_TOKEN_{digest}"

        if self._raw_values is not None:
            with self._lock:
                self._raw_values[token] = value
                self._tokens_by_run.setdefault(run_id, set()).add(token)
        return token

    def resolve(self, token: str) -> str:
        if self._raw_values is None:
            raise TokenResolutionDisabled("This TokenVault was configured for one-way tokenization")
        with self._lock:
            if token not in self._raw_values:
                raise KeyError(token)
            return self._raw_values[token]

    def detokenize(self, token: str) -> str:
        """Compatibility alias for callers that explicitly enabled raw storage."""

        return self.resolve(token)

    def clear_run(self, run_id: str) -> None:
        if self._raw_values is None:
            return
        with self._lock:
            for token in self._tokens_by_run.pop(run_id, set()):
                self._raw_values.pop(token, None)

    def __repr__(self) -> str:
        return f"TokenVault(stores_raw={self.stores_raw})"
