"""Regression tests for host-controlled SensitiveGuard security boundaries."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from sensitiveguard.factory import SensitiveGuardRuntime
from sensitiveguard.memory import MemoryGuard
from sensitiveguard.models import GuardStage, GuardStatus
from sensitiveguard.privacy import PrivacyContext
from sensitiveguard.runtime import (
    ApprovalStore,
    AuthorizationError,
    AuthorizationPolicy,
    DataAcquisitionGuard,
    FinalOutputGuard,
    ObservationGuard,
    ToolExecutionError,
    ToolInputGuard,
    ToolRegistry,
)
from sensitiveguard.tools import SafeSendMessageTool


RAW_IDENTITY = "440101199001011234"
OTHER_IDENTITY = "11010519491231002X"
RAW_MOBILE = "13800138000"
REGISTRY_SECRET = "registry-private-error-canary"


def _external_context(run_id: str) -> PrivacyContext:
    return PrivacyContext(
        task="release one explicitly required identity after approval",
        purpose="identity_verification",
        requester="compliance-reviewer",
        destination="external_llm",
        trust_level="untrusted",
        required_fields=("IDCARD",),
        allowed_scope=("IDCARD",),
        run_id=run_id,
    )


def test_approval_is_content_bound_single_use_and_charged_to_the_ledger() -> None:
    context = _external_context("approval-boundary")
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    text = f"身份证: {RAW_IDENTITY}"

    first = runtime.gateway.guard_text(
        text,
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
        record_disclosure=True,
    )
    assert first.status is GuardStatus.APPROVAL_REQUIRED
    request = runtime.approval_store.pending(context.run_id)[0]
    runtime.approval_store.approve(request.request_id, approver="privacy-officer")

    approved = runtime.gateway.guard_text(
        text,
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
        record_disclosure=True,
    )
    assert approved.status is GuardStatus.ALLOWED
    assert approved.content == text
    assert runtime.approval_store.get(request.request_id).status == "CONSUMED"
    assert runtime.ledger.cumulative_risk(context.run_id, "external_llm") > 0

    replay = runtime.gateway.guard_text(
        text,
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
        record_disclosure=True,
    )
    assert replay.status is GuardStatus.APPROVAL_REQUIRED
    assert runtime.approval_store.pending(context.run_id)[0].request_id != request.request_id

    audit = json.dumps([event.to_dict() for event in runtime.audit_logger.events()], ensure_ascii=False)
    assert RAW_IDENTITY not in audit


def test_approval_digest_rejects_changed_content_destination_and_concurrent_replay() -> None:
    context = _external_context("approval-concurrency")
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    original = runtime.gateway.guard_text(
        f"身份证: {RAW_IDENTITY}",
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
    )
    request = runtime.approval_store.pending(context.run_id)[0]
    runtime.approval_store.approve(request.request_id, approver="privacy-officer")

    changed = runtime.gateway.guard_text(
        f"身份证: {OTHER_IDENTITY}",
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
    )
    assert original.status is GuardStatus.APPROVAL_REQUIRED
    assert changed.status is GuardStatus.APPROVAL_REQUIRED

    decisions = original.decisions
    with ThreadPoolExecutor(max_workers=8) as executor:
        consumed = tuple(
            executor.map(
                lambda _: runtime.approval_store.consume(
                    decisions,
                    context,
                    "external_llm",
                    stage=GuardStage.TOOL_INPUT,
                    policy_version=runtime.policy_engine.policy_version,
                ),
                range(8),
            )
        )
    assert sum(consumed) == 1
    assert not runtime.approval_store.consume(
        decisions,
        context,
        "message:example.test",
        stage=GuardStage.TOOL_INPUT,
        recipient="bob@example.test",
        policy_version=runtime.policy_engine.policy_version,
    )


def test_expired_approval_is_not_consumed() -> None:
    clock_value = [100.0]
    store = ApprovalStore(key=b"a" * 32, ttl_seconds=5, clock=lambda: clock_value[0])
    context = _external_context("approval-expiry")
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    decision_set = runtime.gateway.guard_text(
        f"身份证: {RAW_IDENTITY}",
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
    ).decisions
    request = store.request(decision_set, context, "external_llm")
    store.approve(request.request_id, approver="privacy-officer")

    clock_value[0] = 106.0
    assert not store.consume(decision_set, context, "external_llm")


def test_message_approval_cannot_be_redirected_to_another_recipient_in_same_domain() -> None:
    context = PrivacyContext(
        task="send one required mobile number",
        purpose="customer_notification",
        destination="message:example.test",
        trust_level="untrusted",
        required_fields=("MOBILE",),
        allowed_scope=("MOBILE",),
        run_id="recipient-bound-approval",
    )
    runtime = SensitiveGuardRuntime.create(
        context,
        known_external_destinations=("message:example.test",),
        default_privacy_budget=1_000,
    )
    sent: list[tuple[str, str]] = []

    def sender(recipient: str, body: str) -> None:
        sent.append((recipient, body))

    tool = SafeSendMessageTool(
        gateway=runtime.gateway,
        context=context,
        sender=sender,
        allowed_recipients={"alice@example.test", "bob@example.test"},
    )
    body = f"手机号: {RAW_MOBILE}"
    first = tool.forward("alice@example.test", body)
    assert first["status"] == GuardStatus.APPROVAL_REQUIRED.value
    request = runtime.approval_store.pending(context.run_id)[0]
    runtime.approval_store.approve(request.request_id, approver="privacy-officer")

    redirected = tool.forward("bob@example.test", body)
    assert redirected["status"] == GuardStatus.APPROVAL_REQUIRED.value
    assert sent == []

    approved = tool.forward("alice@example.test", body)
    assert approved["status"] == "SENT"
    assert sent == [("alice@example.test", body)]


def test_data_acquisition_guard_enforces_minimal_explicit_projection() -> None:
    context = PrivacyContext(
        task="read an approved purchase projection",
        purpose="analytics",
        required_fields=("purchase",),
        optional_fields=("region",),
        forbidden_fields=("password",),
        allowed_scope=("purchase", "region"),
    )
    guard = DataAcquisitionGuard()

    plan = guard.plan_fields(("purchase", "region", "password", "email"), context)
    assert plan.approved_fields == ("purchase", "region")
    assert plan.omitted_fields == ("password", "email")
    with pytest.raises(AuthorizationError):
        guard.plan_fields(("*",), context)
    with pytest.raises(AuthorizationError):
        guard.plan_fields(("email",), context)


def test_named_guards_route_to_the_expected_runtime_boundaries() -> None:
    context = PrivacyContext(
        task="guard a harmless payload",
        purpose="testing",
        requester="requester",
        destination="external_llm",
        trust_level="untrusted",
        run_id="named-guards",
    )
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)

    tool_input = ToolInputGuard(runtime.gateway).guard("harmless", context, destination="external_llm")
    observation = ObservationGuard(runtime.gateway).guard("harmless", context)
    final = FinalOutputGuard(runtime.gateway).guard("harmless", context)

    assert tool_input.status is GuardStatus.ALLOWED
    assert observation.status is GuardStatus.ALLOWED
    assert final.status is GuardStatus.ALLOWED
    stages = [event.stage for event in runtime.audit_logger.events()]
    assert stages == [GuardStage.TOOL_INPUT.value, GuardStage.TOOL_OUTPUT.value, GuardStage.FINAL_OUTPUT.value]


def test_runtime_loads_validated_custom_policy_source() -> None:
    context = PrivacyContext(
        task="apply a custom policy",
        purpose="testing",
        destination="external_llm",
        trust_level="untrusted",
        run_id="custom-policy-source",
    )
    runtime = SensitiveGuardRuntime.create(
        context,
        policy_source={
            "version": "tenant-policy-v7",
            "rules": [
                {
                    "policy_id": "TENANT-NAME-BLOCK",
                    "action": "BLOCK",
                    "labels": ["NAME"],
                    "stages": ["tool_input"],
                    "destinations": ["external_llm"],
                }
            ],
        },
    )

    guarded = runtime.gateway.guard_text(
        "姓名: 张三",
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
    )

    assert runtime.policy_engine.policy_version == "tenant-policy-v7"
    assert guarded.status is GuardStatus.BLOCKED
    assert guarded.decisions.decisions[0].policy_id == "TENANT-NAME-BLOCK"


def test_recursive_guard_transforms_sensitive_dictionary_keys() -> None:
    context = PrivacyContext(
        task="return a safe keyed summary",
        purpose="testing",
        requester="requester",
        destination="external_llm",
        trust_level="untrusted",
        run_id="sensitive-keys",
    )
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    payload = {RAW_IDENTITY: {RAW_MOBILE: "safe value"}}

    guarded = FinalOutputGuard(runtime.gateway).guard(payload, context)

    assert guarded.status is GuardStatus.TRANSFORMED
    serialized = json.dumps(guarded.content, ensure_ascii=False)
    assert RAW_IDENTITY not in serialized
    assert RAW_MOBILE not in serialized


def test_numeric_identifiers_are_scanned_in_payloads_and_memory() -> None:
    context = PrivacyContext(
        task="guard numeric identifiers",
        purpose="testing",
        requester="requester",
        destination="external_llm",
        trust_level="untrusted",
        run_id="numeric-identifiers",
    )
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    raw_numeric = int(RAW_IDENTITY)

    guarded = runtime.gateway.guard_payload(
        {"customer_identifier": raw_numeric},
        context,
        GuardStage.TOOL_INPUT,
        destination="external_llm",
    )
    memory_value = MemoryGuard(runtime.gateway, context).sanitize(raw_numeric)

    assert guarded.status is GuardStatus.TRANSFORMED
    assert RAW_IDENTITY not in json.dumps(guarded.content, ensure_ascii=False)
    assert RAW_IDENTITY not in str(memory_value)


def test_generated_pseudonym_is_idempotent_under_observation_guard() -> None:
    context = PrivacyContext(
        task="retain an already safe pseudonym",
        purpose="testing",
        destination="external_llm",
        trust_level="untrusted",
        run_id="pseudonym-idempotence",
    )
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    pseudonym = "姓名: PERSON_0001"

    guarded = ObservationGuard(runtime.gateway).guard(pseudonym, context)

    assert guarded.status is GuardStatus.ALLOWED
    assert guarded.content == pseudonym


def test_dns_resolution_failure_is_denied_before_transport() -> None:
    policy = AuthorizationPolicy(allowed_http_hosts=frozenset({"api.example.test"}))
    with patch("sensitiveguard.runtime.authorization.socket.getaddrinfo", side_effect=OSError("offline")):
        with pytest.raises(AuthorizationError):
            policy.authorize_url("https://api.example.test/v1")


def test_tool_registry_does_not_retain_provider_exception_or_raw_arguments() -> None:
    registry = ToolRegistry()

    def explode(value: str) -> None:
        raise RuntimeError(f"{REGISTRY_SECRET}: {value}")

    registry.register("protected_adapter", explode, destination="internal", trust_level="trusted")
    with pytest.raises(ToolExecutionError) as captured:
        registry.execute("protected_adapter", RAW_IDENTITY)

    error = captured.value
    assert REGISTRY_SECRET not in str(error)
    assert RAW_IDENTITY not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert REGISTRY_SECRET not in json.dumps(error.to_dict())
    assert RAW_IDENTITY not in json.dumps(error.to_dict())


def test_registered_capability_sees_only_guarded_input_and_returns_guarded_output() -> None:
    context = PrivacyContext(
        task="use a registered external analyzer",
        purpose="purchase_behavior_analysis",
        destination="external_llm",
        trust_level="untrusted",
        run_id="registered-capability",
    )
    runtime = SensitiveGuardRuntime.create(context, default_privacy_budget=1_000)
    received: list[dict[str, str]] = []

    def capability(text: str) -> dict[str, str]:
        received.append({"text": text})
        return {"mobile": RAW_MOBILE, "result": "ok"}

    runtime.gateway.registry.register(
        "registered_analyzer",
        capability,
        destination="external_llm",
        trust_level="untrusted",
    )
    result = runtime.gateway.execute_registered(
        "registered_analyzer",
        {"text": f"姓名: 张三 身份证: {RAW_IDENTITY}"},
        context,
    )

    assert received
    assert "张三" not in received[0]["text"]
    assert RAW_IDENTITY not in received[0]["text"]
    serialized = json.dumps(result, ensure_ascii=False)
    assert RAW_MOBILE not in serialized
    assert result["status"] in {GuardStatus.TRANSFORMED.value, GuardStatus.ALLOWED.value}
