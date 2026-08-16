"""Sanitize smolagents memory steps before they are persisted or replayed."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

from sensitiveguard.models import GuardStage


BLOCKED_MEMORY_VALUE = "[BLOCKED_BY_SENSITIVEGUARD]"


class MemoryGuardError(RuntimeError):
    """Raised when a memory value cannot be inspected safely."""


class MemoryWriteBlocked(MemoryGuardError):
    """Raised when unsafe content is submitted to a strict memory sink."""


class MemoryGuard:
    """A fail-closed sanitizer that can be registered as an ``ActionStep`` callback.

    smolagents calls step callbacks as ``callback(step, agent=agent)``.  The
    callback mutates the step in place *before* it is appended to AgentMemory.
    Raw model provider objects are discarded because their shape is not stable
    enough to sanitize safely.
    """

    def __init__(
        self,
        gateway: Any,
        context: Any | None = None,
        *,
        context_resolver: Any | None = None,
        blocked_value: str = BLOCKED_MEMORY_VALUE,
        fail_closed: bool = True,
    ) -> None:
        self.gateway = gateway
        self.context = context
        self.context_resolver = context_resolver
        self.blocked_value = blocked_value
        self.fail_closed = fail_closed

    def __call__(self, memory_step: Any, *, agent: Any | None = None) -> None:
        """smolagents callback entry point."""

        self.sanitize_step(memory_step, agent=agent)

    def resolve_context(self, *, context: Any | None = None, agent: Any | None = None) -> Any:
        if context is not None:
            return context
        if self.context_resolver is not None:
            resolved = self.context_resolver(agent)
            if resolved is not None:
                return resolved
        if self.context is not None:
            return self.context
        if agent is not None:
            resolved = getattr(agent, "privacy_context", None)
            if resolved is not None:
                return resolved
            state = getattr(agent, "state", None)
            if isinstance(state, dict) and state.get("privacy_context") is not None:
                return state["privacy_context"]
        raise MemoryGuardError("A PrivacyContext is required to sanitize memory")

    def sanitize(
        self,
        value: Any,
        *,
        context: Any | None = None,
        agent: Any | None = None,
        tool_name: str | None = None,
        on_block: Literal["replace", "raise"] = "replace",
    ) -> Any:
        """Return a guarded copy of ``value`` without ever returning raw blocked data."""

        if value is None or isinstance(value, bool):
            return value

        try:
            privacy_context = self.resolve_context(context=context, agent=agent)
            kwargs = {
                "context": privacy_context,
                "stage": GuardStage.MEMORY,
                "destination": "agent_memory",
                "recipient": None,
                "tool_name": tool_name,
                "record_disclosure": False,
            }
            if isinstance(value, str):
                result = self.gateway.guard_text(value, **kwargs)
            else:
                result = self.gateway.guard_payload(value, **kwargs)
        except Exception as exc:
            if not self.fail_closed:
                raise MemoryGuardError("Memory guard failed") from exc
            return self._blocked(on_block, "Memory guard failed")

        if not getattr(result, "allowed", False):
            return self._blocked(on_block, "Memory write was blocked by policy")
        try:
            return deepcopy(result.content)
        except Exception as exc:
            if not self.fail_closed:
                raise MemoryGuardError("Guarded memory content could not be copied safely") from exc
            return self._blocked(on_block, "Guarded memory content could not be copied safely")

    def sanitize_step(self, memory_step: Any, *, context: Any | None = None, agent: Any | None = None) -> Any:
        """Sanitize every text-bearing field used by an ActionStep replay."""

        try:
            privacy_context = self.resolve_context(context=context, agent=agent)
        except MemoryGuardError:
            if not self.fail_closed:
                raise
            privacy_context = None

        def guard(value: Any, *, tool_name: str | None = None) -> Any:
            if privacy_context is None:
                return self.blocked_value if value is not None else None
            return self.sanitize(value, context=privacy_context, tool_name=tool_name)

        for attribute in ("observations", "action_output", "model_output", "code_action"):
            if hasattr(memory_step, attribute):
                value = getattr(memory_step, attribute)
                if value is not None:
                    setattr(memory_step, attribute, guard(value))

        self._sanitize_tool_calls(getattr(memory_step, "tool_calls", None), guard)
        self._sanitize_message(getattr(memory_step, "model_output_message", None), guard)

        model_input_messages = getattr(memory_step, "model_input_messages", None)
        if model_input_messages:
            for message in model_input_messages:
                self._sanitize_message(message, guard)

        error = getattr(memory_step, "error", None)
        if error is not None:
            sanitized_error = guard(str(error))
            if hasattr(error, "message"):
                error.message = sanitized_error
            if isinstance(error, BaseException):
                error.args = (sanitized_error,)
                # Exception chains and tracebacks retain frame locals. Those
                # locals can include the original tool arguments or provider
                # response even when the public exception text is generic.
                # Memory must never keep that hidden raw-data back-reference.
                error.__cause__ = None
                error.__context__ = None
                error.__traceback__ = None

        return memory_step

    sanitize_memory_step = sanitize_step

    def _sanitize_message(self, message: Any, guard: Any) -> None:
        if message is None:
            return
        if hasattr(message, "content") and message.content is not None:
            message.content = guard(message.content)
        self._sanitize_chat_tool_calls(getattr(message, "tool_calls", None), guard)
        # Provider-specific raw responses may contain duplicate prompt/tool data.
        if hasattr(message, "raw"):
            message.raw = None

    @staticmethod
    def _sanitize_tool_calls(tool_calls: Any, guard: Any) -> None:
        if not tool_calls:
            return
        for tool_call in tool_calls:
            if not hasattr(tool_call, "arguments"):
                continue
            tool_name = getattr(tool_call, "name", None)
            tool_call.arguments = guard(tool_call.arguments, tool_name=tool_name)

    @staticmethod
    def _sanitize_chat_tool_calls(tool_calls: Any, guard: Any) -> None:
        if not tool_calls:
            return
        for tool_call in tool_calls:
            function = getattr(tool_call, "function", None)
            if function is None or not hasattr(function, "arguments"):
                continue
            function.arguments = guard(function.arguments, tool_name=getattr(function, "name", None))

    def _blocked(self, on_block: Literal["replace", "raise"], reason: str) -> str:
        if on_block == "raise":
            raise MemoryWriteBlocked(reason)
        return self.blocked_value
