"""Private registry for real capabilities hidden behind safe smolagents Tools."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Any

from .error_model import ToolExecutionError, UnsafeToolError


@dataclass(frozen=True, slots=True)
class RegisteredCapability:
    name: str
    callback: Callable[..., Any]
    destination: str
    trust_level: str


class ToolRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, RegisteredCapability] = {}
        self._lock = RLock()

    def register(
        self,
        name: str,
        callback: Callable[..., Any],
        *,
        destination: str,
        trust_level: str,
        replace: bool = False,
    ) -> None:
        if not callable(callback):
            raise TypeError("A registered capability must be callable")
        with self._lock:
            if name in self._capabilities and not replace:
                raise ValueError(f"Capability {name!r} is already registered")
            self._capabilities[name] = RegisteredCapability(name, callback, destination, trust_level)

    def get(self, name: str) -> RegisteredCapability:
        with self._lock:
            try:
                return self._capabilities[name]
            except KeyError as error:
                raise UnsafeToolError(details={"tool": name}) from error

    def execute(self, name: str, /, *args: Any, **kwargs: Any) -> Any:
        capability = self.get(name)
        exception_type: str | None = None
        try:
            return capability.callback(*args, **kwargs)
        except Exception as error:
            # Deliberately do not include callback arguments or the upstream
            # exception text: either can contain the protected payload.
            exception_type = type(error).__name__
        # Raise after leaving the provider exception handler. Otherwise the
        # exception's ``__context__`` and traceback retain callback frame
        # locals, including the raw protected arguments.
        raise ToolExecutionError(details={"tool": name, "exception_type": exception_type}) from None

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._capabilities))
