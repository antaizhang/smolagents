"""Run-scoped, stable pseudonym generation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from threading import RLock


_PREFIXES = {
    "ADDRESS": "LOCATION",
    "EMAIL": "EMAIL",
    "FAX": "PHONE",
    "MOBILE": "PHONE",
    "NAME": "PERSON",
    "TEL": "PHONE",
}


class Pseudonymizer:
    """Create stable aliases without retaining the original value as a map key."""

    def __init__(self, secret_key: bytes | None = None) -> None:
        key = secret_key if secret_key is not None else secrets.token_bytes(32)
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("secret_key must contain at least 16 bytes")
        self._secret_key = key
        self._aliases: dict[str, dict[str, str]] = {}
        self._counters: dict[str, dict[str, int]] = {}
        self._lock = RLock()

    def pseudonymize(self, value: str, label: str, run_id: str) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        if not run_id:
            raise ValueError("run_id must not be empty")

        normalized_label = label.upper()
        prefix = _PREFIXES.get(normalized_label, normalized_label or "SENSITIVE")
        prefix = "".join(character for character in prefix if character.isalnum() or character == "_")
        fingerprint = self._fingerprint(value, normalized_label, run_id)

        with self._lock:
            run_aliases = self._aliases.setdefault(run_id, {})
            if fingerprint in run_aliases:
                return run_aliases[fingerprint]
            run_counters = self._counters.setdefault(run_id, {})
            sequence = run_counters.get(prefix, 0) + 1
            run_counters[prefix] = sequence
            alias = f"{prefix}_{sequence:04d}"
            run_aliases[fingerprint] = alias
            return alias

    def clear_run(self, run_id: str) -> None:
        with self._lock:
            self._aliases.pop(run_id, None)
            self._counters.pop(run_id, None)

    def _fingerprint(self, value: str, label: str, run_id: str) -> str:
        payload = f"{len(run_id)}:{run_id}{len(label)}:{label}{len(value)}:{value}".encode()
        return hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        with self._lock:
            return f"Pseudonymizer(active_runs={len(self._aliases)})"
