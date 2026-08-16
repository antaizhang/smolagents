"""A small storage wrapper that never persists unguarded agent memory."""

from __future__ import annotations

from collections.abc import MutableMapping
from copy import deepcopy
from threading import RLock
from typing import Any

from .memory_guard import MemoryGuard, MemoryWriteBlocked


class SanitizedMemoryStore:
    """Thread-safe mapping wrapper that sanitizes values before committing them."""

    def __init__(self, memory_guard: MemoryGuard, backend: MutableMapping[str, Any] | None = None) -> None:
        self.memory_guard = memory_guard
        self._backend = backend if backend is not None else {}
        self._lock = RLock()

    def write(self, key: str, value: Any, *, context: Any | None = None) -> Any:
        self._validate_key(key, context=context)
        sanitized = self.memory_guard.sanitize(value, context=context, on_block="raise")
        with self._lock:
            self._backend[key] = deepcopy(sanitized)
        return deepcopy(sanitized)

    set = write
    save = write
    put = write

    def read(self, key: str, default: Any = None) -> Any:
        if not isinstance(key, str) or not key:
            return deepcopy(default)
        with self._lock:
            return deepcopy(self._backend.get(key, default))

    get = read

    def delete(self, key: str) -> bool:
        with self._lock:
            if key not in self._backend:
                return False
            del self._backend[key]
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(dict(self._backend))

    def clear(self) -> None:
        with self._lock:
            self._backend.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._backend)

    def _validate_key(self, key: str, *, context: Any | None) -> None:
        if not isinstance(key, str) or not key or len(key) > 256:
            raise MemoryWriteBlocked("Memory keys must be non-empty strings of at most 256 characters")
        sanitized_key = self.memory_guard.sanitize(key, context=context, on_block="raise")
        if sanitized_key != key:
            raise MemoryWriteBlocked("Sensitive or transformed memory keys are not permitted")
