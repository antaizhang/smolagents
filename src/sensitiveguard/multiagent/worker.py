"""Host-registered worker capability used by the guarded manager."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GuardedWorker:
    name: str
    handler: Callable[[dict[str, Any]], Any]
    allowed_fields: tuple[str, ...]
    allowed_artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.name.isidentifier():
            raise ValueError("Worker name must be a non-empty identifier")
        if not callable(self.handler):
            raise TypeError("Worker handler must be callable")
        if not self.allowed_fields:
            raise ValueError("A worker must declare a minimal allowed field set")
