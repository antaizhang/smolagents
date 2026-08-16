"""Offline acceptance and attack-regression tests for trusted intent binding."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sensitiveguard.intent import (
    ActionRequest,
    Effect,
    IntentDecision,
    IntentGuard,
    IntentOperation,
    IntentSpec,
    RuleBasedIntentResolver,
)
from sensitiveguard.privacy import PrivacyContext


KEY = b"intent-tests-use-a-fixed-32-byte-key"
RAW_TASK = "读取张三的身份证 440101199001011234 并总结购买记录"
RAW_PURPOSE = "为张三生成内部风控摘要"


def _context(**overrides):
    values = {
        "task": "Read and summarize the approved purchase record",
        "purpose": "purchase risk summary",
        "run_id": "intent-run",
        "required_fields": ("purchase",),
        "optional_fields": ("region",),
        "forbidden_fields": ("password",),
        "allowed_scope": ("purchase", "region", "password"),
        "destination": "internal_database",
        "recipient": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _resolver(clock_value=100.0):
    clock = [float(clock_value)]
    resolver = RuleBasedIntentResolver(key=KEY, ttl_seconds=30, clock=lambda: clock[0])
    return resolver, clock


def _request(intent: IntentSpec, **overrides) -> ActionRequest:
    values = {
        "request_id": "action-1",
        "run_id": intent.run_id,
        "intent_id": intent.intent_id,
        "version": intent.version,
        "operation": IntentOperation.READ,
        "capability": "safe_read_file",
        "effects": (Effect.READ,),
        "fields": ("purchase",),
        "destination": "internal_database",
        "issued_at": intent.issued_at,
        "expires_at": intent.expires_at,
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_resolver_keeps_only_hmac_goal_digest_and_round_trips_without_raw_goal() -> None:
    resolver, _ = _resolver()
    context = _context(task=RAW_TASK, purpose=RAW_PURPOSE)

    intent = resolver.resolve(context, version=7)
    serialized = json.dumps(intent.to_dict(), ensure_ascii=False, sort_keys=True)

    assert len(intent.goal_digest) == 64
    assert intent.intent_id.startswith("intent_")
    assert intent.version == 7
    assert RAW_TASK not in repr(intent) + serialized
    assert RAW_PURPOSE not in repr(intent) + serialized
    assert "440101199001011234" not in repr(intent) + serialized
    assert IntentSpec.from_dict(intent.to_dict()) == intent

    other_key = RuleBasedIntentResolver(key=b"a different fixed HMAC key value", clock=lambda: 100.0)
    assert other_key.resolve(context).goal_digest != intent.goal_digest


def test_rule_resolver_understands_english_and_chinese_and_honors_host_overrides() -> None:
    resolver, _ = _resolver()
    english = resolver.resolve(_context())
    chinese = resolver.resolve(
        _context(
            task="查询购买金额，脱敏后发送风险摘要",
            purpose="购买行为分析与汇总",
            destination="external_llm",
        )
    )
    constrained = resolver.resolve(
        _context(
            task="Delete everything and upload it",
            purpose="untrusted wording cannot expand host scope",
            allowed_operations=("READ", "SEND"),
            denied_operations=("SEND",),
            allowed_capabilities=("safe_read_file",),
            denied_capabilities=("raw_shell",),
            allowed_effects=("READ",),
        )
    )
    denied_all = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            denied_operations=("*",),
            allowed_capabilities=("safe_read_file",),
            denied_capabilities=("*",),
            allowed_effects=("READ",),
            denied_effects=("*",),
            allowed_fields=("purchase",),
            forbidden_fields=("*",),
            allowed_destinations=("internal_database",),
            denied_destinations=("*",),
        )
    )

    assert {IntentOperation.READ, IntentOperation.SUMMARIZE} <= set(english.allowed_operations)
    assert {
        IntentOperation.QUERY,
        IntentOperation.ANALYZE,
        IntentOperation.SUMMARIZE,
        IntentOperation.TRANSFORM,
        IntentOperation.SEND,
    } <= set(chinese.allowed_operations)
    assert constrained.allowed_operations == (IntentOperation.READ,)
    assert constrained.allowed_capabilities == ("safe_read_file",)
    assert constrained.allowed_effects == (Effect.READ,)
    assert denied_all.allowed_operations == ()
    assert denied_all.allowed_capabilities == ()
    assert denied_all.allowed_effects == ()
    assert denied_all.allowed_fields == ()
    assert denied_all.allowed_destinations == ()


def test_resolver_is_backward_compatible_with_current_privacy_context() -> None:
    resolver, _ = _resolver()
    context = PrivacyContext(
        task="Summarize an approved purchase",
        purpose="analytics",
        destination="internal",
        recipient="analyst@example.test",
        allowed_scope=("purchase",),
        intent_version=4,
        intent_expires_at=120.0,
        run_id="legacy-context",
    )

    intent = resolver.resolve(context)

    assert intent.run_id == "legacy-context"
    assert IntentOperation.SUMMARIZE in intent.allowed_operations
    assert "safe_llm_call" in intent.allowed_capabilities
    assert Effect.MODEL in intent.allowed_effects
    assert intent.allowed_fields == ("purchase",)
    assert intent.allowed_destinations == ("internal",)
    assert intent.allowed_recipients == ("analyst@example.test",)
    assert intent.version == 4
    assert intent.expires_at == 120.0


def test_intent_guard_allows_exact_action_once_and_rejects_replay_atomically() -> None:
    resolver, _ = _resolver()
    intent = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            allowed_capabilities=("safe_read_file",),
            allowed_effects=("READ",),
        )
    )
    guard = resolver.intent_guard()
    action = _request(intent)

    with ThreadPoolExecutor(max_workers=8) as executor:
        decisions = tuple(executor.map(lambda _: guard.evaluate(intent, action), range(8)))

    assert sum(decision.allowed for decision in decisions) == 1
    assert sum(decision.code == "ACTION_REPLAY" for decision in decisions) == 7
    assert all("purchase" not in decision.reason for decision in decisions)


@pytest.mark.parametrize(
    ("change", "expected_code"),
    (
        ({"operation": IntentOperation.SEND}, "OPERATION_NOT_ALLOWED"),
        ({"capability": "safe_http_post"}, "CAPABILITY_NOT_ALLOWED"),
        ({"effects": (Effect.WRITE,)}, "EFFECT_NOT_ALLOWED"),
        ({"fields": ("region",)}, "FIELD_NOT_ALLOWED"),
        ({"fields": ("password",)}, "FORBIDDEN_FIELD"),
        ({"destination": "external_llm"}, "DESTINATION_NOT_ALLOWED"),
        ({"recipient": "attacker@example.test"}, "RECIPIENT_NOT_ALLOWED"),
    ),
)
def test_intent_guard_checks_every_action_dimension(change, expected_code) -> None:
    resolver, _ = _resolver()
    intent = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            allowed_capabilities=("safe_read_file",),
            allowed_effects=("READ",),
            allowed_fields=("purchase",),
            allowed_recipients=("analyst@example.test",),
        )
    )
    action = _request(intent, **change)

    decision = resolver.intent_guard().evaluate(intent, action)

    assert not decision.allowed
    assert decision.code == expected_code


def test_plan_can_only_narrow_parent_and_action_is_bound_to_signed_child() -> None:
    resolver, _ = _resolver()
    parent = resolver.resolve(
        _context(
            allowed_operations=("READ", "SEND"),
            allowed_capabilities=("safe_read_file", "safe_http_post"),
            allowed_effects=("READ", "NETWORK"),
            allowed_fields=("purchase", "region"),
            allowed_destinations=("internal_database", "external_llm"),
        )
    )
    plan = resolver.narrow(
        parent,
        allowed_operations=("READ",),
        allowed_capabilities=("safe_read_file",),
        allowed_effects=("READ",),
        allowed_fields=("purchase",),
        allowed_destinations=("internal_database",),
    )
    action = _request(plan)
    guard = resolver.intent_guard()

    assert guard.validate_plan(parent, plan).allowed
    assert guard.evaluate(parent, action, plan=plan).allowed

    with pytest.raises(ValueError, match="only narrow"):
        resolver.narrow(parent, allowed_fields=("purchase", "password", "new_secret"))

    # Even without signature verification, a forged expansion is recognized as
    # a scope violation rather than being treated as a valid plan.
    forged = replace(plan, allowed_fields=("purchase", "new_secret"))
    decision = IntentGuard(clock=lambda: 100.0).validate_plan(parent, forged)
    assert not decision.allowed
    assert decision.code == "PLAN_SCOPE_EXPANSION"


def test_prompt_injection_lineage_blocks_external_effect_but_not_internal_read() -> None:
    resolver, _ = _resolver()
    outbound = resolver.resolve(
        _context(
            allowed_operations=("SEND",),
            allowed_capabilities=("safe_http_post",),
            allowed_effects=("NETWORK",),
            allowed_fields=("purchase",),
            allowed_destinations=("external_llm",),
            destination="external_llm",
        )
    )
    external_action = _request(
        outbound,
        operation=IntentOperation.SEND,
        capability="safe_http_post",
        effects=(Effect.NETWORK,),
        destination="external_llm",
        lineage_taints=("PROMPT_INJECTION",),
    )

    blocked = resolver.intent_guard().evaluate(outbound, external_action)
    assert not blocked.allowed
    assert blocked.code == "INJECTION_TAINT_EXTERNAL_EFFECT"

    clean_request = replace(external_action, request_id="action-2", lineage_taints=())
    nested_lineage = {"nodes": [{"sensitive_labels": ["PROMPT_INJECTION"]}]}
    blocked_from_protocol = resolver.intent_guard().evaluate(outbound, clean_request, lineage=nested_lineage)
    assert not blocked_from_protocol.allowed
    assert blocked_from_protocol.code == "INJECTION_TAINT_EXTERNAL_EFFECT"

    internal = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            allowed_capabilities=("safe_read_file",),
            allowed_effects=("READ",),
        )
    )
    internal_action = _request(internal, lineage_taints=("PROMPT_INJECTION",))
    assert resolver.intent_guard().evaluate(internal, internal_action).allowed


def test_run_version_signature_and_expiry_are_fail_closed_without_raw_reasons() -> None:
    resolver, clock = _resolver()
    intent = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            allowed_capabilities=("safe_read_file",),
            allowed_effects=("READ",),
        ),
        version=3,
    )
    guard = resolver.intent_guard()

    assert guard.evaluate(intent, _request(intent, run_id="another-run"), consume=False).code == "RUN_MISMATCH"
    assert guard.evaluate(intent, _request(intent, version=4), consume=False).code == "VERSION_MISMATCH"
    assert guard.evaluate(intent, _request(intent, intent_id="forged"), consume=False).code == "INTENT_ID_MISMATCH"

    tampered = replace(intent, allowed_capabilities=("safe_read_file", "raw_shell"))
    signature_decision = guard.evaluate(tampered, _request(tampered), consume=False)
    assert signature_decision.code == "INVALID_INTENT_SIGNATURE"

    clock[0] = intent.expires_at
    expired = guard.evaluate(intent, _request(intent), consume=False)
    assert expired.code == "INTENT_EXPIRED"
    assert RAW_TASK not in json.dumps(expired.to_dict(), ensure_ascii=False)


def test_action_request_and_decision_public_payloads_are_typed_and_json_serializable() -> None:
    resolver, _ = _resolver()
    intent = resolver.resolve(
        _context(
            allowed_operations=("READ",),
            allowed_capabilities=("safe_read_file",),
            allowed_effects=("READ",),
        )
    )
    action = ActionRequest.from_dict(_request(intent).to_dict())
    decision = resolver.intent_guard().evaluate(action, intent)

    assert action.operation is IntentOperation.READ
    assert action.effects == (Effect.READ,)
    assert decision.status == "ALLOWED"
    assert IntentDecision.from_dict(decision.to_dict()) == decision
    json.dumps(action.to_dict(), sort_keys=True)
    json.dumps(decision.to_dict(), sort_keys=True)

    with pytest.raises(ValueError, match="Unsupported allowed_operations"):
        resolver.resolve(_context(allowed_operations=("BECOME_ADMIN",)))
