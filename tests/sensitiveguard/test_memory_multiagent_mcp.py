"""Offline tests for SensitiveGuard memory, handoff, and MCP boundaries."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from sensitiveguard.mcp import (
    MCPGateway,
    MCPInvocationError,
    MCPSchemaValidator,
    MCPToolSchema,
    SchemaValidationError,
    TrustStore,
    UntrustedMCPServerError,
)
from sensitiveguard.memory import BLOCKED_MEMORY_VALUE, MemoryGuard, MemoryWriteBlocked, SanitizedMemoryStore
from sensitiveguard.models import DecisionSet, DetectionResult, GuardResult, GuardStage, GuardStatus
from sensitiveguard.multiagent import HandoffGuard
from sensitiveguard.privacy import PrivacyContext
from smolagents.memory import ActionStep, CallbackRegistry, ToolCall
from smolagents.models import ChatMessage, ChatMessageToolCall, ChatMessageToolCallFunction, MessageRole
from smolagents.monitoring import Timing


SECRET = "SG-SECRET-440101199001011234"
BLOCKED = "SG-BLOCK-ME"


def _contains(value, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(_contains(key, needle) or _contains(item, needle) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains(item, needle) for item in value)
    return False


def _transform(value):
    if isinstance(value, str):
        return value.replace(SECRET, "[MASKED]")
    if isinstance(value, dict):
        return {key: _transform(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_transform(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_transform(item) for item in value)
    return deepcopy(value)


class FakeSafeToolGateway:
    """Deterministic guard with no model, filesystem, or network dependency."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls = []
        self.fail = fail

    def guard_text(self, content, **kwargs):
        return self._guard("text", content, kwargs)

    def guard_payload(self, payload, **kwargs):
        return self._guard("payload", payload, kwargs)

    def _guard(self, kind, content, kwargs):
        self.calls.append((kind, deepcopy(content), kwargs.copy()))
        if self.fail:
            raise RuntimeError(f"detector unavailable: {SECRET}")
        if _contains(content, BLOCKED):
            return GuardResult(
                status=GuardStatus.BLOCKED,
                detection=DetectionResult(),
                decisions=DecisionSet(),
                reason="blocked by test policy",
            )
        transformed = _transform(content)
        return GuardResult(
            status=GuardStatus.TRANSFORMED if transformed != content else GuardStatus.ALLOWED,
            content=transformed,
            detection=DetectionResult(),
            decisions=DecisionSet(),
        )


@pytest.fixture
def privacy_context():
    return PrivacyContext(
        task="prepare a privacy-safe risk summary",
        purpose="risk_reporting",
        run_id="run-1",
        allowed_scope=["summary", "task"],
        required_fields=[],
        forbidden_fields=["IDCARD", "PASSWD"],
    )


def test_memory_guard_is_an_action_step_callback_and_scrubs_replay_fields(privacy_context):
    gateway = FakeSafeToolGateway()
    guard = MemoryGuard(gateway, privacy_context)
    chat_tool_call = ChatMessageToolCall(
        id="provider-call",
        type="function",
        function=ChatMessageToolCallFunction(name="safe_http_post", arguments={"body": SECRET}),
    )
    step = ActionStep(
        step_number=1,
        timing=Timing(start_time=1.0, end_time=2.0),
        model_input_messages=[ChatMessage(role=MessageRole.USER, content=f"prior {SECRET}", raw={"raw": SECRET})],
        tool_calls=[ToolCall(name="safe_http_post", arguments={"body": SECRET}, id="call-1")],
        model_output_message=ChatMessage(
            role=MessageRole.ASSISTANT,
            content=f"send {SECRET}",
            tool_calls=[chat_tool_call],
            raw={"provider_copy": SECRET},
        ),
        model_output=f"send {SECRET}",
        code_action=f"upload({SECRET!r})",
        observations=f"tool returned {SECRET}",
        action_output={"customer": SECRET},
    )

    callbacks = CallbackRegistry()
    callbacks.register(ActionStep, guard)
    callbacks.callback(step, agent=SimpleNamespace(state={}))

    serialized = json.dumps(step.dict(), ensure_ascii=False, default=str)
    assert SECRET not in serialized
    assert "[MASKED]" in serialized
    assert step.model_output_message.raw is None
    assert step.model_input_messages[0].raw is None
    assert step.tool_calls[0].arguments == {"body": "[MASKED]"}
    assert step.model_output_message.tool_calls[0].function.arguments == {"body": "[MASKED]"}
    assert all(call[2]["stage"] is GuardStage.MEMORY for call in gateway.calls)
    assert all(call[2]["record_disclosure"] is False for call in gateway.calls)


def test_memory_guard_fails_closed_without_leaking_gateway_errors(privacy_context):
    guard = MemoryGuard(FakeSafeToolGateway(fail=True), privacy_context)
    step = SimpleNamespace(
        observations=SECRET,
        action_output={"value": SECRET},
        model_output=SECRET,
        code_action=None,
        tool_calls=[],
        model_output_message=None,
        model_input_messages=None,
        error=None,
    )

    guard(step)

    assert step.observations == BLOCKED_MEMORY_VALUE
    assert step.action_output == BLOCKED_MEMORY_VALUE
    assert step.model_output == BLOCKED_MEMORY_VALUE
    assert SECRET not in repr(vars(step))


def test_sanitized_memory_store_commits_only_guarded_defensive_copies(privacy_context):
    memory_guard = MemoryGuard(FakeSafeToolGateway(), privacy_context)
    store = SanitizedMemoryStore(memory_guard)

    original = {"note": SECRET, "nested": ["safe"]}
    stored = store.write("run-1", original)
    original["nested"].append(SECRET)
    stored["nested"].append("mutated")

    assert store.read("run-1") == {"note": "[MASKED]", "nested": ["safe"]}
    assert SECRET not in repr(store.snapshot())

    with pytest.raises(MemoryWriteBlocked):
        store.write("run-1", {"note": BLOCKED})
    assert store.read("run-1")["note"] == "[MASKED]"

    with pytest.raises(MemoryWriteBlocked):
        store.write(f"key-{SECRET}", "safe")


def test_handoff_minimizes_fields_and_artifact_capabilities(privacy_context):
    gateway = FakeSafeToolGateway()
    guard = HandoffGuard(gateway)
    payload = {
        "summary": f"customer risk: {SECRET}",
        "debug_context": {"raw": SECRET},
        "artifacts": ["artifact://scan-summary/001", "artifact://raw-customers/999"],
    }

    result = guard.prepare_handoff(
        payload,
        context=privacy_context,
        allowed_artifacts=["artifact://scan-summary/001"],
        recipient="report-agent",
    )

    assert result.status is GuardStatus.TRANSFORMED
    assert result.content == {
        "summary": "customer risk: [MASKED]",
        "artifacts": ["artifact://scan-summary/001"],
    }
    assert payload["summary"].endswith(SECRET)
    assert gateway.calls[-1][2]["stage"] is GuardStage.HANDOFF
    assert gateway.calls[-1][2]["recipient"] == "report-agent"
    assert gateway.calls[-1][2]["record_disclosure"] is True


def test_handoff_blocks_forbidden_fields_before_the_runtime_guard(privacy_context):
    gateway = FakeSafeToolGateway()
    payload = {"summary": {"IDCARD": SECRET}}

    result = HandoffGuard(gateway).guard(payload, context=privacy_context)

    assert result.status is GuardStatus.BLOCKED
    assert "IDCARD" in result.reason
    assert gateway.calls == []


def test_mcp_schema_validator_closes_nested_objects_and_rejects_type_confusion():
    validator = MCPSchemaValidator()
    permissive_schema = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "minLength": 1},
            "metadata": {
                "type": "object",
                "properties": {"count": {"type": "integer", "minimum": 0}},
                "additionalProperties": True,
            },
        },
        "required": ["text", "metadata"],
        "additionalProperties": True,
    }

    strict = validator.make_strict(permissive_schema)
    assert strict["additionalProperties"] is False
    assert strict["properties"]["metadata"]["additionalProperties"] is False
    validator.validate({"text": "hello", "metadata": {"count": 1}}, permissive_schema)

    with pytest.raises(SchemaValidationError, match="additional properties"):
        validator.validate({"text": "hello", "metadata": {"count": 1, "raw": SECRET}}, permissive_schema)
    with pytest.raises(SchemaValidationError, match="expected type integer"):
        validator.validate({"text": "hello", "metadata": {"count": True}}, permissive_schema)


def test_mcp_schema_validator_supports_closed_object_variants():
    validator = MCPSchemaValidator()
    schema = {
        "oneOf": [
            {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            {
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
            },
        ]
    }

    assert validator.describes_object(schema)
    validator.validate({"text": "hello"}, schema)
    with pytest.raises(SchemaValidationError):
        validator.validate({"text": "hello", "extra": SECRET}, schema)


def test_trust_store_defaults_to_deny_and_scopes_tools():
    store = TrustStore(
        {
            "reports": {
                "allowed_tools": ["summarize"],
                "destination": "https://mcp.internal.example",
                "recipient": "report-service",
            }
        }
    )

    assert not store.is_trusted("unknown")
    assert store.is_tool_allowed("reports", "summarize")
    assert not store.is_tool_allowed("reports", "export_raw")
    with pytest.raises(UntrustedMCPServerError):
        store.require("unknown", "summarize")
    with pytest.raises(UntrustedMCPServerError):
        store.require("reports", "export_raw")


def _mcp_components(invoker, guard=None):
    trust_store = TrustStore(
        {
            "reports": {
                "allowed_tools": ["summarize"],
                "destination": "https://mcp.internal.example",
                "recipient": "report-service",
            }
        }
    )
    schemas = {
        ("reports", "summarize"): MCPToolSchema(
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            output_schema={
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        )
    }
    return MCPGateway(
        guard=guard or FakeSafeToolGateway(),
        invoker=invoker,
        trust_store=trust_store,
        tool_schemas=schemas,
    )


def test_mcp_gateway_guards_both_sides_and_invokes_only_with_sanitized_input(privacy_context):
    calls = []

    def invoker(**kwargs):
        calls.append(deepcopy(kwargs))
        return {"summary": f"server returned {SECRET}"}

    guard = FakeSafeToolGateway()
    gateway = _mcp_components(invoker, guard)

    result = gateway.call_tool(
        "reports",
        "summarize",
        {"text": f"analyze {SECRET}"},
        context=privacy_context,
    )

    assert calls == [
        {
            "server_id": "reports",
            "tool_name": "summarize",
            "arguments": {"text": "analyze [MASKED]"},
        }
    ]
    assert result.status is GuardStatus.TRANSFORMED
    assert result.content == {"summary": "server returned [MASKED]"}
    assert [call[2]["stage"] for call in guard.calls] == [GuardStage.MCP_INPUT, GuardStage.MCP_OUTPUT]
    assert guard.calls[0][2]["destination"] == "https://mcp.internal.example"
    assert guard.calls[0][2]["record_disclosure"] is True
    assert guard.calls[1][2]["record_disclosure"] is False


@pytest.mark.parametrize(
    "server_id,tool_name,arguments",
    [
        ("unknown", "summarize", {"text": "safe"}),
        ("reports", "export_raw", {"text": "safe"}),
        ("reports", "summarize", {"text": "safe", "undeclared": SECRET}),
        ("reports", "summarize", {"text": BLOCKED}),
    ],
)
def test_mcp_gateway_preconditions_are_fail_closed(server_id, tool_name, arguments, privacy_context):
    calls = []
    gateway = _mcp_components(lambda **kwargs: calls.append(kwargs), FakeSafeToolGateway())

    result = gateway.call_tool(server_id, tool_name, arguments, context=privacy_context)

    assert result.status is GuardStatus.BLOCKED
    assert calls == []


def test_mcp_gateway_rejects_unexpected_output_fields(privacy_context):
    gateway = _mcp_components(lambda **_: {"summary": "safe", "undeclared": SECRET})

    result = gateway.call_tool("reports", "summarize", {"text": "safe"}, context=privacy_context)

    assert result.status is GuardStatus.BLOCKED
    assert SECRET not in (result.reason or "")


def test_mcp_gateway_sanitizes_invoker_failures(privacy_context):
    def failing_invoker(**_):
        raise RuntimeError(f"remote echoed {SECRET}")

    gateway = _mcp_components(failing_invoker)

    with pytest.raises(MCPInvocationError) as caught:
        gateway.call_tool("reports", "summarize", {"text": "safe"}, context=privacy_context)

    assert SECRET not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_mcp_gateway_cannot_weaken_a_registered_schema_at_call_time(privacy_context):
    calls = []
    gateway = _mcp_components(lambda **kwargs: calls.append(kwargs))
    permissive_override = {"type": "object", "additionalProperties": True}

    result = gateway.call_tool(
        "reports",
        "summarize",
        {"text": "safe", "undeclared": SECRET},
        context=privacy_context,
        input_schema=permissive_override,
    )

    assert result.status is GuardStatus.BLOCKED
    assert calls == []
