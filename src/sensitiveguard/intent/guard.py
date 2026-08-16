"""Deterministic intent/plan/action consistency enforcement."""

from __future__ import annotations

import hmac
import math
import time
from collections.abc import Mapping
from threading import RLock
from typing import Any

from .models import (
    ActionRequest,
    Effect,
    IntentDecision,
    IntentOperation,
    IntentSpec,
    _scope_allows,
    _scope_is_narrower,
    _signed_intent_id,
)


_SIDE_EFFECT_REQUIREMENTS: dict[IntentOperation, frozenset[Effect]] = {
    IntentOperation.WRITE: frozenset({Effect.WRITE}),
    IntentOperation.SEND: frozenset({Effect.NETWORK, Effect.MESSAGE, Effect.MODEL, Effect.EXTERNAL}),
    IntentOperation.DELETE: frozenset({Effect.DELETE}),
    IntentOperation.EXECUTE: frozenset({Effect.EXECUTE}),
    IntentOperation.HANDOFF: frozenset({Effect.HANDOFF, Effect.EXTERNAL}),
}
_EXTERNAL_EFFECTS = frozenset(
    {Effect.NETWORK, Effect.MESSAGE, Effect.MODEL, Effect.HANDOFF, Effect.EXTERNAL, Effect.EXECUTE}
)
_INTERNAL_DESTINATIONS = frozenset(
    {
        "agent_memory",
        "database",
        "internal",
        "internal_database",
        "internal_file",
        "local",
        "memory",
        "rag",
    }
)
_INJECTION_MARKERS = frozenset(
    {
        "injection",
        "injection_tainted",
        "jailbreak",
        "prompt_injection",
        "promptinjection",
        "tainted_prompt",
        "untrusted_instruction",
    }
)


class IntentGuard:
    """Authorize exact actions and atomically reject request replay."""

    def __init__(self, *, key: bytes | None = None, clock: Any = time.time) -> None:
        if key is not None and (not isinstance(key, bytes) or len(key) < 16):
            raise ValueError("Intent HMAC key must contain at least 16 bytes")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._key = key
        self._clock = clock
        self._consumed: set[tuple[str, str, int, str]] = set()
        self._lock = RLock()

    def evaluate(
        self,
        intent: IntentSpec | ActionRequest,
        request: ActionRequest | IntentSpec,
        *,
        plan: IntentSpec | None = None,
        lineage: Any = None,
        consume: bool = True,
    ) -> IntentDecision:
        """Check a request against an intent and optional narrowing plan.

        For ergonomic compatibility, ``intent`` and ``request`` may be supplied
        in either order.  No raw action arguments are accepted or retained.
        """

        if isinstance(intent, ActionRequest) and isinstance(request, IntentSpec):
            intent, request = request, intent
        if not isinstance(intent, IntentSpec) or not isinstance(request, ActionRequest):
            raise TypeError("IntentGuard.evaluate expects an IntentSpec and an ActionRequest")

        now = self._now()
        invalid_intent = self._validate_envelope(intent, now)
        if invalid_intent is not None:
            return self._blocked(invalid_intent, intent, request)

        effective = intent
        if plan is not None:
            plan_decision = self.validate_plan(intent, plan, now=now)
            if not plan_decision.allowed:
                return self._blocked(plan_decision.code, intent, request)
            effective = plan

        invalid_request = self._validate_request_binding(effective, request, now)
        if invalid_request is not None:
            return self._blocked(invalid_request, effective, request)
        scope_error = self._validate_scope(effective, request)
        if scope_error is not None:
            return self._blocked(scope_error, effective, request)
        if self._has_injection_taint(request, lineage) and self._has_external_side_effect(request):
            return self._blocked("INJECTION_TAINT_EXTERNAL_EFFECT", effective, request)

        replay_key = (effective.run_id, effective.intent_id, effective.version, request.request_id)
        if consume:
            with self._lock:
                if replay_key in self._consumed:
                    return self._blocked("ACTION_REPLAY", effective, request)
                self._consumed.add(replay_key)
        return IntentDecision(
            allowed=True,
            code="INTENT_ALLOWED",
            reason="The action is consistent with the trusted intent and active plan.",
            intent_id=effective.intent_id,
            request_id=request.request_id,
            version=effective.version,
            consumed=consume,
        )

    check = evaluate
    authorize = evaluate
    guard = evaluate
    validate = evaluate

    def validate_intent(self, intent: IntentSpec, *, run_id: str | None = None) -> IntentDecision:
        """Authenticate an intent envelope before any capability exception.

        Infrastructure and host-internal capabilities may have specialized
        scope rules, but they must never bypass signature, lifetime, or run
        isolation checks.
        """

        if not isinstance(intent, IntentSpec):
            raise TypeError("validate_intent expects an IntentSpec")
        error = self._validate_envelope(intent, self._now())
        if error is None and run_id is not None and intent.run_id != str(run_id):
            error = "RUN_MISMATCH"
        if error is not None:
            return IntentDecision(
                allowed=False,
                code=error,
                reason="The trusted intent envelope is not valid for this run.",
                intent_id=intent.intent_id,
                version=intent.version,
            )
        return IntentDecision(
            allowed=True,
            code="INTENT_ENVELOPE_VALID",
            reason="The trusted intent signature, lifetime, and run binding are valid.",
            intent_id=intent.intent_id,
            version=intent.version,
        )

    def validate_plan(
        self,
        parent: IntentSpec,
        plan: IntentSpec,
        *,
        now: float | None = None,
    ) -> IntentDecision:
        if not isinstance(parent, IntentSpec) or not isinstance(plan, IntentSpec):
            raise TypeError("validate_plan expects two IntentSpec objects")
        current = self._now() if now is None else float(now)
        parent_error = self._validate_envelope(parent, current)
        if parent_error:
            return self._plan_blocked(parent_error, plan)
        plan_error = self._validate_envelope(plan, current)
        if plan_error:
            return self._plan_blocked(plan_error, plan)
        if plan.parent_intent_id != parent.intent_id:
            return self._plan_blocked("PLAN_PARENT_MISMATCH", plan)
        if plan.run_id != parent.run_id:
            return self._plan_blocked("PLAN_RUN_MISMATCH", plan)
        if plan.version != parent.version:
            return self._plan_blocked("PLAN_VERSION_MISMATCH", plan)
        if plan.goal_digest != parent.goal_digest:
            return self._plan_blocked("PLAN_GOAL_MISMATCH", plan)
        if plan.issued_at < parent.issued_at or plan.expires_at > parent.expires_at:
            return self._plan_blocked("PLAN_LIFETIME_EXPANSION", plan)

        scopes = (
            (plan.allowed_operations, parent.allowed_operations),
            (plan.allowed_capabilities, parent.allowed_capabilities),
            (plan.allowed_effects, parent.allowed_effects),
            (plan.allowed_fields, parent.allowed_fields),
            (plan.allowed_destinations, parent.allowed_destinations),
            (plan.allowed_recipients, parent.allowed_recipients),
        )
        if not all(_scope_is_narrower(child, ceiling) for child, ceiling in scopes):
            return self._plan_blocked("PLAN_SCOPE_EXPANSION", plan)
        if not set(parent.forbidden_fields) <= set(plan.forbidden_fields):
            return self._plan_blocked("PLAN_REMOVED_DENIAL", plan)
        return IntentDecision(
            allowed=True,
            code="PLAN_VALID",
            reason="The plan only narrows the trusted parent intent.",
            intent_id=plan.intent_id,
            version=plan.version,
        )

    def clear_replay_state(self, run_id: str | None = None) -> None:
        """Forget consumed identifiers after their run is no longer active."""

        with self._lock:
            if run_id is None:
                self._consumed.clear()
                return
            self._consumed = {key for key in self._consumed if key[0] != run_id}

    def _validate_envelope(self, intent: IntentSpec, now: float) -> str | None:
        if self._key is not None:
            expected = _signed_intent_id(intent, self._key)
            if not hmac.compare_digest(intent.intent_id, expected):
                return "INVALID_INTENT_SIGNATURE"
        if now < intent.issued_at:
            return "INTENT_NOT_YET_VALID"
        if now >= intent.expires_at:
            return "INTENT_EXPIRED"
        return None

    @staticmethod
    def _validate_request_binding(intent: IntentSpec, request: ActionRequest, now: float) -> str | None:
        if request.run_id != intent.run_id:
            return "RUN_MISMATCH"
        if request.intent_id != intent.intent_id:
            return "INTENT_ID_MISMATCH"
        if request.version != intent.version:
            return "VERSION_MISMATCH"
        if request.issued_at is not None:
            if request.issued_at < intent.issued_at or request.issued_at > now:
                return "ACTION_TIME_INVALID"
        if request.expires_at is not None:
            if request.expires_at > intent.expires_at or now >= request.expires_at:
                return "ACTION_EXPIRED"
        return None

    @staticmethod
    def _validate_scope(intent: IntentSpec, request: ActionRequest) -> str | None:
        if not _scope_allows(intent.allowed_operations, request.operation):
            return "OPERATION_NOT_ALLOWED"
        if not _scope_allows(intent.allowed_capabilities, request.capability):
            return "CAPABILITY_NOT_ALLOWED"
        if any(not _scope_allows(intent.allowed_effects, effect) for effect in request.effects):
            return "EFFECT_NOT_ALLOWED"

        required_effects = _SIDE_EFFECT_REQUIREMENTS.get(request.operation)
        if required_effects and not (set(request.effects) & set(required_effects)):
            return "EFFECT_UNDERDECLARED"
        if "*" in intent.forbidden_fields or any(field in intent.forbidden_fields for field in request.fields):
            return "FORBIDDEN_FIELD"
        if any(not _scope_allows(intent.allowed_fields, field) for field in request.fields):
            return "FIELD_NOT_ALLOWED"
        if request.destination is not None and not _scope_allows(intent.allowed_destinations, request.destination):
            return "DESTINATION_NOT_ALLOWED"
        if request.recipient is not None and not _scope_allows(intent.allowed_recipients, request.recipient):
            return "RECIPIENT_NOT_ALLOWED"
        if (
            required_effects
            and request.destination is None
            and request.operation
            in {
                IntentOperation.SEND,
                IntentOperation.HANDOFF,
            }
        ):
            return "DESTINATION_REQUIRED"
        if Effect.MESSAGE in request.effects and request.recipient is None:
            return "RECIPIENT_REQUIRED"
        if IntentGuard._destination_is_external(request.destination) and not (
            set(request.effects) & set(_EXTERNAL_EFFECTS)
        ):
            return "EXTERNAL_EFFECT_UNDERDECLARED"
        return None

    @staticmethod
    def _destination_is_external(destination: str | None) -> bool:
        if destination is None:
            return False
        value = destination.casefold()
        return value not in _INTERNAL_DESTINATIONS and not value.startswith(("internal_", "local_"))

    @classmethod
    def _has_external_side_effect(cls, request: ActionRequest) -> bool:
        return (
            request.operation in {IntentOperation.SEND, IntentOperation.HANDOFF}
            or bool(set(request.effects) & set(_EXTERNAL_EFFECTS))
            or cls._destination_is_external(request.destination)
        )

    @classmethod
    def _has_injection_taint(cls, request: ActionRequest, lineage: Any) -> bool:
        if any(cls._is_injection_marker(value) for value in request.lineage_taints):
            return True
        return cls._lineage_has_injection(lineage, seen=set(), depth=0)

    @classmethod
    def _lineage_has_injection(cls, value: Any, *, seen: set[int], depth: int) -> bool:
        if value is None or depth > 12:
            return False
        if isinstance(value, str):
            return cls._is_injection_marker(value)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float, bytes)):
            return False
        identity = id(value)
        if identity in seen:
            return False
        seen.add(identity)

        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized_key = str(key).strip().casefold().replace("-", "_")
                if normalized_key in {
                    "contains_prompt_injection",
                    "injection_tainted",
                    "prompt_injection",
                    "tainted_by_injection",
                } and bool(child):
                    return True
                if normalized_key in {
                    "finding",
                    "findings",
                    "flags",
                    "label",
                    "labels",
                    "lineage",
                    "nodes",
                    "parents",
                    "sensitive_labels",
                    "taint",
                    "taints",
                } and cls._lineage_has_injection(child, seen=seen, depth=depth + 1):
                    return True
            return False
        if isinstance(value, (tuple, list, set, frozenset)):
            return any(cls._lineage_has_injection(item, seen=seen, depth=depth + 1) for item in value)

        for attribute in (
            "contains_prompt_injection",
            "injection_tainted",
            "prompt_injection_tainted",
            "tainted_by_injection",
        ):
            marker = getattr(value, attribute, False)
            if isinstance(marker, bool) and marker:
                return True
        for attribute in ("taints", "labels", "sensitive_labels", "finding", "findings", "parents", "nodes"):
            child = getattr(value, attribute, None)
            if child is not None and cls._lineage_has_injection(child, seen=seen, depth=depth + 1):
                return True
        return False

    @staticmethod
    def _is_injection_marker(value: str) -> bool:
        normalized = value.strip().casefold().replace("-", "_").replace(" ", "_")
        return normalized in _INJECTION_MARKERS or "prompt_injection" in normalized

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("Intent clock must return a numeric timestamp")
        result = float(value)
        if not math.isfinite(result) or result < 0:
            raise ValueError("Intent clock returned an invalid timestamp")
        return result

    @staticmethod
    def _blocked(code: str, intent: IntentSpec, request: ActionRequest) -> IntentDecision:
        return IntentDecision(
            allowed=False,
            code=code,
            reason="The proposed action is not consistent with the trusted intent.",
            intent_id=intent.intent_id,
            request_id=request.request_id,
            version=intent.version,
        )

    @staticmethod
    def _plan_blocked(code: str, plan: IntentSpec) -> IntentDecision:
        return IntentDecision(
            allowed=False,
            code=code,
            reason="The proposed plan is not a valid narrowing of its parent intent.",
            intent_id=plan.intent_id,
            version=plan.version,
        )


__all__ = ["IntentGuard"]
