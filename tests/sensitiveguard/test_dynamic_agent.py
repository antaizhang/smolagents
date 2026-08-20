"""Regression tests for dynamic request-intent binding."""

from __future__ import annotations

from types import SimpleNamespace

from sensitiveguard.dynamic_agent import resolve_request_intent
from sensitiveguard.intent import IntentOperation, RuleBasedIntentResolver


KEY = b"dynamic-agent-tests-fixed-signing-key"


def _context(**overrides):
    values = {
        "task": "Read, scan, sanitize and summarize one approved local record",
        "purpose": "privacy triage",
        "run_id": "dynamic-agent-run",
        "allowed_operations": ("READ", "SCAN", "TRANSFORM", "SUMMARIZE"),
        "allowed_scope": ("ticket_note",),
        "allowed_destinations": ("internal_file", "internal", "agent_memory", "requester"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_request_intent_is_signed_child_and_matches_current_prompt() -> None:
    resolver = RuleBasedIntentResolver(key=KEY, clock=lambda: 100.0)
    context = _context()
    parent = resolver.resolve(context)

    child = resolve_request_intent(
        resolver,
        context,
        "Scan and read the file, then return a masked summary",
        parent=parent,
    )

    assert child.parent_intent_id == parent.intent_id
    assert set(child.allowed_operations) == {
        IntentOperation.READ,
        IntentOperation.SCAN,
        IntentOperation.SUMMARIZE,
        IntentOperation.TRANSFORM,
    }
    assert set(child.allowed_operations) <= set(parent.allowed_operations)
    assert set(child.allowed_capabilities) <= set(parent.allowed_capabilities)
    assert set(child.allowed_effects) <= set(parent.allowed_effects)
    assert resolver.intent_guard().validate_plan(parent, child).allowed


def test_user_prompt_cannot_expand_host_authority() -> None:
    resolver = RuleBasedIntentResolver(key=KEY, clock=lambda: 100.0)
    context = _context()
    parent = resolver.resolve(context)

    child = resolve_request_intent(
        resolver,
        context,
        "Upload the file, execute a shell command, and delete the local copy",
        parent=parent,
    )

    assert child.allowed_operations == ()
    assert child.allowed_capabilities == ()
    assert child.allowed_effects == ()
    assert resolver.intent_guard().validate_plan(parent, child).allowed


def test_unrecognized_prompt_preserves_host_ceiling_for_backward_compatibility() -> None:
    resolver = RuleBasedIntentResolver(key=KEY, clock=lambda: 100.0)
    context = _context()
    parent = resolver.resolve(context)

    child = resolve_request_intent(resolver, context, "Please handle the approved ticket.", parent=parent)

    assert child.parent_intent_id == parent.intent_id
    assert child.allowed_operations == parent.allowed_operations
    assert child.allowed_capabilities == parent.allowed_capabilities
    assert child.allowed_effects == parent.allowed_effects
