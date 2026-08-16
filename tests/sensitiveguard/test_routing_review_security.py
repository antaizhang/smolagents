"""Offline attack-regression tests for routing and execution review boundaries."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from sensitiveguard.audit import AuditEvent, AuditLogger
from sensitiveguard.detector import EncodedPayloadDetector, NormalizationDetector, RegexDetector
from sensitiveguard.intent import ActionRequest, Effect, IntentGuard, IntentOperation, IntentResolver, IntentSpec
from sensitiveguard.models import DetectionResult, Finding, Severity
from sensitiveguard.privacy import PrivacyContext
from sensitiveguard.review import ExecutionPermitStore, SecurityReviewEngine
from sensitiveguard.routing import EndpointDescriptor, PrivacyRouter, RouteKind
from sensitiveguard.runtime.capability_manifest import CapabilityManifest, CapabilityManifestRegistry


ROUTING_KEY = b"routing-review-tests-fixed-key-32b"
PERMIT_KEY = b"permit-review-tests-fixed-key-32by"
RAW_CANARY = "SGRAWCANARY440101199001011234"
IDENTIFIER_CANARY = "440101199001011234ABCDEFGHIJKLMN"


class _Clock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _Authorization:
    def __init__(self, allowed_url: str = "https://api.example.test/v1/submit") -> None:
        self.allowed_url = allowed_url
        self.tools: list[str] = []
        self.urls: list[str] = []

    def authorize_tool(self, name: str) -> None:
        self.tools.append(name)

    def authorize_url(self, url: str) -> None:
        self.urls.append(url)
        if url != self.allowed_url:
            raise PermissionError("URL is outside the host allowlist")


class _Gateway:
    def __init__(self, authorization: _Authorization) -> None:
        self.authorization = authorization


class _HTTPTool:
    name = "safe_http_post"
    output_type = "object"

    def __init__(self, authorization: _Authorization, context: Any = None) -> None:
        self.gateway = _Gateway(authorization)
        self.context = context
        self.inputs = {
            "url": {"type": "string"},
            "body": {"type": "object"},
        }


class _MessageTool:
    name = "safe_send_message"

    def __init__(self, recipient: str) -> None:
        self.allowed_recipients = frozenset({recipient.casefold()})


class _CustomInternalTool:
    name = "custom_internal"
    inputs = {"value": {"type": "string"}}
    output_type = "object"

    def __init__(self, authorization: _Authorization, context: Any) -> None:
        self.gateway = _Gateway(authorization)
        self.context = context


class _Lineage:
    def __init__(self, *, tainted: bool = False) -> None:
        self.tainted = tainted
        self.chain_valid = True
        self.head = "a" * 64
        self.prepared: list[Any] = []
        self.aborted: list[str] = []

    def report(self, context: Any) -> Any:
        del context
        return SimpleNamespace(
            nodes=(),
            events=(SimpleNamespace(event_hash=self.head),),
            chain_valid=self.chain_valid,
            tainted_artifact_ids=("artifact_prompt_injection",) if self.tainted else (),
        )

    def prepare_operation(self, arguments: Any, context: Any, **kwargs: Any) -> Any:
        self.prepared.append((arguments, context, kwargs))
        return SimpleNamespace(operation_id=f"operation_{len(self.prepared):08d}")

    def abort_operation(self, operation_id: str, *, context: Any) -> None:
        del context
        self.aborted.append(operation_id)


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def log(self, **event: Any) -> None:
        self.events.append(event)


def _sensitive_detection() -> DetectionResult:
    value = "13800138000"
    return DetectionResult(
        (
            Finding(
                label="MOBILE",
                start=0,
                end=len(value),
                score=1.0,
                severity=Severity.CRITICAL,
                detector="offline-test",
                value=value,
            ),
        )
    )


def _review_context() -> PrivacyContext:
    return PrivacyContext(
        task="Send the approved aggregate to the approved endpoint",
        purpose="offline security review test",
        destination="internal",  # A model/task hint must not relabel the URL.
        allowed_destinations=("http:api.example.test",),
        run_id="review-run",
    )


def _intent(context: PrivacyContext, *, operation: IntentOperation = IntentOperation.SEND) -> IntentSpec:
    return IntentSpec(
        intent_id="intent_review_test",
        run_id=context.run_id,
        version=1,
        goal_digest="0" * 64,
        issued_at=0.0,
        expires_at=200.0,
        allowed_operations=(operation,),
        allowed_capabilities=("safe_http_post",),
        allowed_effects=(Effect.EXTERNAL, Effect.NETWORK, Effect.WRITE),
        allowed_destinations=("http:api.example.test",),
    )


def _review_engine(*, tainted: bool = False) -> tuple[SecurityReviewEngine, _HTTPTool, _Lineage]:
    authorization = _Authorization()
    context = _review_context()
    tool = _HTTPTool(authorization, context)
    lineage = _Lineage(tainted=tainted)
    manifests = CapabilityManifestRegistry()
    engine = SecurityReviewEngine(
        router=PrivacyRouter(key=ROUTING_KEY),
        intent_guard=IntentGuard(clock=lambda: 100.0),
        manifests=manifests,
        permits=ExecutionPermitStore(key=PERMIT_KEY, clock=lambda: 100.0),
        lineage_tracker=lineage,
        audit_logger=_Audit(),
        gateway=tool.gateway,
        context=context,
        policy_version="policy-v1",
    )
    engine.register_tools([tool])
    return engine, tool, lineage


def _http_arguments(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "url": "https://api.example.test/v1/submit",
        "body": {"aggregate": 7},
        # This is deliberately hostile. The route must come from the actual URL.
        "destination": "internal",
    }
    values.update(overrides)
    return values


def _permit_values(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "run_id": "permit-run",
        "intent_id": "intent-permit",
        "intent_version": 3,
        "capability": "safe_send_message",
        "manifest_digest": "manifest-original",
        "arguments": {"recipient": "approved@example.test", "body": {"count": 4}},
        "destination": "message:example.test",
        "recipient": "approved@example.test",
        "lineage_ids": ("artifact-a", "artifact-b"),
        "policy_version": "policy-v1",
    }
    values.update(overrides)
    return values


def _persisted_audit(logger: AuditLogger, path: Any, run_id: str) -> str:
    payload = {
        "events": [event.to_dict() for event in logger.events()],
        "report": logger.report(run_id),
    }
    return path.read_text(encoding="utf-8") + json.dumps(payload, ensure_ascii=False, sort_keys=True)


def test_model_routing_is_local_first_for_sensitive_input() -> None:
    router = PrivacyRouter(
        (
            EndpointDescriptor(
                endpoint_id="external-fast",
                destination="external_llm",
                trust_level="external",
                is_local=False,
                max_sensitivity=Severity.CRITICAL,
                priority=1,
            ),
            EndpointDescriptor(
                endpoint_id="local-private",
                destination="local",
                trust_level="internal",
                is_local=True,
                max_sensitivity=Severity.CRITICAL,
                priority=50,
            ),
        ),
        key=ROUTING_KEY,
    )

    decision = router.route_model(_sensitive_detection(), operation="analyze")

    assert decision.allowed
    assert decision.endpoint_id == "local-private"
    assert decision.route_kind is RouteKind.MODEL
    assert not decision.external


@pytest.mark.parametrize(
    ("endpoint_opt_in", "call_opt_in"),
    ((False, False), (False, True), (True, False)),
)
def test_unavailable_local_model_never_silently_falls_back_external(endpoint_opt_in: bool, call_opt_in: bool) -> None:
    router = PrivacyRouter(
        (
            EndpointDescriptor(
                endpoint_id="local-private",
                destination="local",
                trust_level="internal",
                is_local=True,
                available=False,
                allow_fallback=endpoint_opt_in,
                max_sensitivity=Severity.CRITICAL,
            ),
            EndpointDescriptor(
                endpoint_id="external-fallback",
                destination="external_llm",
                trust_level="external",
                is_local=False,
                max_sensitivity=Severity.CRITICAL,
            ),
        ),
        key=ROUTING_KEY,
    )

    decision = router.route_model(
        _sensitive_detection(),
        operation="analyze",
        preferred_endpoint="local-private",
        allow_external_fallback=call_opt_in,
    )

    assert not decision.allowed
    assert decision.endpoint_id is None
    assert decision.reason_code == "ROUTE_EXTERNAL_FALLBACK_DENIED"


def test_external_model_fallback_requires_both_host_and_call_opt_in() -> None:
    router = PrivacyRouter(
        (
            EndpointDescriptor(
                endpoint_id="local-private",
                destination="local",
                trust_level="internal",
                is_local=True,
                available=False,
                allow_fallback=True,
                max_sensitivity=Severity.CRITICAL,
            ),
            EndpointDescriptor(
                endpoint_id="external-fallback",
                destination="external_llm",
                trust_level="external",
                is_local=False,
                max_sensitivity=Severity.CRITICAL,
            ),
        ),
        key=ROUTING_KEY,
    )

    decision = router.route_model(
        _sensitive_detection(),
        operation="analyze",
        preferred_endpoint="local-private",
        allow_external_fallback=True,
    )

    assert decision.allowed
    assert decision.external
    assert decision.endpoint_id == "external-fallback"


def test_http_route_uses_authorized_actual_url_not_model_destination() -> None:
    authorization = _Authorization()
    tool = _HTTPTool(authorization)
    context = _review_context()

    decision = PrivacyRouter(key=ROUTING_KEY).route_tool(
        tool,
        _http_arguments(),
        context,
        operation="send",
        destination_hint="internal",
    )

    assert decision.allowed
    assert decision.route_kind is RouteKind.NETWORK
    assert decision.destination == "http:api.example.test"
    assert decision.external
    assert authorization.urls == ["https://api.example.test/v1/submit"]


def test_message_route_uses_authorized_actual_recipient_not_model_destination() -> None:
    recipient = "approved@trusted.example"
    tool = _MessageTool(recipient)
    context = PrivacyContext(
        task="Send the approved message",
        purpose="offline route test",
        destination="internal",
        allowed_destinations=("message:trusted.example",),
        run_id="message-route",
    )

    decision = PrivacyRouter(key=ROUTING_KEY).route_tool(
        tool,
        {"recipient": recipient, "destination": "internal"},
        context,
        operation="send",
        destination_hint="internal",
    )

    assert decision.allowed
    assert decision.route_kind is RouteKind.MESSAGE
    assert decision.destination == "message:trusted.example"
    assert decision.recipient == recipient
    assert decision.recipient_fingerprint is not None
    assert recipient not in decision.to_dict().values()


@pytest.mark.parametrize(
    "tampering",
    (
        {"arguments": {"recipient": "approved@example.test", "body": {"count": 5}}},
        {"recipient": "attacker@example.test"},
        {"lineage_ids": ("artifact-a", "artifact-injected")},
        {"manifest_digest": "manifest-changed"},
    ),
    ids=("arguments", "recipient", "lineage", "manifest"),
)
def test_execution_permit_binds_every_security_dimension(tampering: dict[str, Any]) -> None:
    store = ExecutionPermitStore(key=PERMIT_KEY, clock=lambda: 10.0)
    exact = _permit_values()
    permit = store.issue(**exact)

    assert not store.consume(permit.permit_id, **_permit_values(**tampering))
    # A mismatch must not burn the permit; only the exact reviewed action may consume it.
    assert store.consume(permit.permit_id, **exact)


def test_execution_permit_is_single_use() -> None:
    store = ExecutionPermitStore(key=PERMIT_KEY, clock=lambda: 10.0)
    exact = _permit_values()
    permit = store.issue(**exact)

    assert store.consume(permit.permit_id, **exact)
    assert not store.consume(permit.permit_id, **exact)
    assert store.get(permit.permit_id).status == "CONSUMED"  # type: ignore[union-attr]


def test_execution_permit_is_expired_at_its_expiry_boundary() -> None:
    clock = _Clock(10.0)
    store = ExecutionPermitStore(key=PERMIT_KEY, ttl_seconds=5.0, clock=clock)
    exact = _permit_values()
    permit = store.issue(**exact)

    clock.value = permit.expires_at

    assert not store.consume(permit.permit_id, **exact)
    assert store.get(permit.permit_id).status == "EXPIRED"  # type: ignore[union-attr]


def test_security_review_blocks_intent_tool_operation_mismatch() -> None:
    engine, tool, lineage = _review_engine()
    context = engine.context

    review = engine.preflight(tool, _http_arguments(), context, _intent(context, operation=IntentOperation.READ))

    assert not review.allowed
    assert review.code == "OPERATION_NOT_ALLOWED"
    assert review.permit is None
    assert not lineage.prepared


def test_security_review_blocks_injection_tainted_lineage_from_external_egress() -> None:
    engine, tool, lineage = _review_engine(tainted=True)
    context = engine.context

    review = engine.preflight(tool, _http_arguments(), context, _intent(context))

    assert not review.allowed
    assert "INJECTION" in review.code
    assert review.permit is None
    assert not lineage.prepared


def test_security_review_rejects_invalid_lineage_chain_before_preparing_action() -> None:
    engine, tool, lineage = _review_engine()
    lineage.chain_valid = False
    context = engine.context

    review = engine.preflight(tool, _http_arguments(), context, _intent(context))

    assert not review.allowed
    assert review.code == "LINEAGE_UNAVAILABLE"
    assert not lineage.prepared


def test_security_review_binds_authenticated_lineage_head_until_consumption() -> None:
    engine, tool, lineage = _review_engine()
    context = engine.context
    arguments = _http_arguments()
    intent = _intent(context)
    review = engine.preflight(tool, arguments, context, intent)
    assert review.allowed
    lineage.head = "b" * 64

    assert not engine.consume(review, tool, arguments, context, intent)
    assert lineage.aborted == [review.operation_id]


@pytest.mark.parametrize(
    "scope",
    (
        {"allowed_capabilities": ("different_capability",)},
        {"denied_capabilities": ("custom_internal",)},
        {"denied_operations": ("execute",)},
        {"denied_destinations": ("internal",)},
    ),
)
def test_custom_internal_capability_honors_explicit_host_scope(scope: dict[str, Any]) -> None:
    authorization = _Authorization()
    context = PrivacyContext(
        task="Use one internal host capability",
        purpose="offline custom capability scope test",
        destination="internal",
        run_id="custom-scope-review",
        **scope,
    )
    tool = _CustomInternalTool(authorization, context)
    lineage = _Lineage()
    engine = SecurityReviewEngine(
        router=PrivacyRouter(key=ROUTING_KEY),
        intent_guard=IntentGuard(clock=lambda: 100.0),
        manifests=CapabilityManifestRegistry(),
        permits=ExecutionPermitStore(key=PERMIT_KEY, clock=lambda: 100.0),
        lineage_tracker=lineage,
        audit_logger=_Audit(),
        gateway=tool.gateway,
        context=context,
    )
    engine.register_tools([tool])

    review = engine.preflight(tool, {"value": "safe"}, context, _intent(context))

    assert not review.allowed
    assert review.code == "CUSTOM_CAPABILITY_OUTSIDE_HOST_SCOPE"
    assert not lineage.prepared


def test_security_review_fails_closed_if_registered_manifest_changes_after_preflight() -> None:
    engine, tool, lineage = _review_engine()
    context = engine.context
    arguments = _http_arguments()
    intent = _intent(context)
    review = engine.preflight(tool, arguments, context, intent)
    assert review.allowed

    original = engine.manifests.get(tool.name)
    engine.manifests.register(replace(original, schema_digest="schema_changed"), replace=True)

    assert not engine.consume(review, tool, arguments, context, intent)
    assert lineage.aborted == [review.operation_id]


def test_security_review_fails_closed_if_tool_schema_changes_after_preflight() -> None:
    engine, tool, lineage = _review_engine()
    context = engine.context
    arguments = _http_arguments()
    intent = _intent(context)
    review = engine.preflight(tool, arguments, context, intent)
    assert review.allowed

    tool.inputs = {**tool.inputs, "unreviewed_argument": {"type": "string"}}

    assert not engine.consume(review, tool, arguments, context, intent)
    assert lineage.aborted == [review.operation_id]


def test_custom_capability_cannot_bypass_signed_intent_envelope() -> None:
    clock = _Clock(100.0)
    resolver = IntentResolver(key=b"intent-envelope-review-key-32bytes", clock=clock)
    authorization = _Authorization()
    context = PrivacyContext(
        task="Execute the approved internal capability",
        purpose="signed custom capability test",
        destination="internal",
        allowed_operations=("EXECUTE",),
        allowed_capabilities=("custom_internal",),
        run_id="signed-custom-review",
    )
    tool = _CustomInternalTool(authorization, context)
    lineage = _Lineage()
    engine = SecurityReviewEngine(
        router=PrivacyRouter(key=ROUTING_KEY),
        intent_guard=resolver.intent_guard(),
        manifests=CapabilityManifestRegistry(),
        permits=ExecutionPermitStore(key=PERMIT_KEY, clock=clock),
        lineage_tracker=lineage,
        audit_logger=_Audit(),
        gateway=tool.gateway,
        context=context,
    )
    engine.register_tools([tool])
    forged = replace(resolver.resolve(context), intent_id="intent_forged_unsigned")

    review = engine.preflight(tool, {"value": "safe"}, context, forged)

    assert not review.allowed
    assert review.code == "INVALID_INTENT_SIGNATURE"
    assert not lineage.prepared


def test_review_revalidates_intent_expiry_before_permit_consumption() -> None:
    clock = _Clock(100.0)
    resolver = IntentResolver(key=b"intent-expiry-review-key-32bytes", clock=clock, ttl_seconds=5.0)
    engine, tool, lineage = _review_engine()
    engine.intent_guard = resolver.intent_guard()
    engine.permits = ExecutionPermitStore(key=PERMIT_KEY, clock=clock)
    context = engine.context
    intent = resolver.resolve(
        context.with_overrides(
            allowed_operations=("SEND",),
            allowed_capabilities=("safe_http_post",),
            allowed_effects=("EXTERNAL", "NETWORK", "WRITE"),
        )
    )
    review = engine.preflight(tool, _http_arguments(), context, intent)
    assert review.allowed
    clock.value = intent.expires_at

    assert not engine.consume(review, tool, _http_arguments(), context, intent)
    assert lineage.aborted == [review.operation_id]


@pytest.mark.parametrize(
    ("name", "operation", "destination"),
    (
        ("safe_llm_call", IntentOperation.ANALYZE, "external_llm"),
        ("safe_http_post", IntentOperation.SEND, "http:api.example.test"),
        ("safe_run_command", IntentOperation.EXECUTE, "local_process"),
        ("scan_file", IntentOperation.SCAN, "internal_file"),
        ("remediate_sensitive_file", IntentOperation.WRITE, "internal_file"),
        ("sanitize_text", IntentOperation.TRANSFORM, "internal"),
        ("verify_sanitized_file", IntentOperation.DETECT, "internal_file"),
    ),
)
def test_standard_manifest_operations_and_effects_match_resolved_intent(
    name: str,
    operation: IntentOperation,
    destination: str,
) -> None:
    resolver = IntentResolver(key=b"intent-manifest-review-key-32byt", clock=lambda: 100.0)
    context = PrivacyContext(
        task=f"Perform the approved {operation.value.lower()} operation",
        purpose="manifest and intent compatibility test",
        destination=destination,
        allowed_operations=(operation.value,),
        allowed_capabilities=(name,),
        run_id=f"manifest-{name}",
    )
    intent = resolver.resolve(context)
    manifest = CapabilityManifest.from_tool(SimpleNamespace(name=name, inputs={}, output_type="object"))
    request = ActionRequest(
        request_id=f"action-{name}",
        run_id=intent.run_id,
        intent_id=intent.intent_id,
        version=intent.version,
        operation=operation,
        capability=name,
        effects=tuple(Effect(value.upper()) for value in manifest.effects),
        destination=destination,
    )

    decision = resolver.intent_guard().evaluate(intent, request)

    assert decision.allowed, decision.code


def test_audit_logger_never_persists_raw_canary_from_free_form_fields(tmp_path: Any) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, key=b"audit-review-tests-fixed-key-32byt")
    finding = {
        "label": RAW_CANARY,
        "start": 0,
        "end": len(RAW_CANARY),
        "score": 1.0,
        "severity": "critical",
        "detector": RAW_CANARY,
        "value": RAW_CANARY,
    }

    event = logger.log(
        run_id=RAW_CANARY,
        event_type=RAW_CANARY,
        stage=RAW_CANARY,
        tool=RAW_CANARY,
        destination=RAW_CANARY,
        detection={"findings": [finding]},
        decisions={
            "decisions": [
                {
                    "finding": finding,
                    "decision": RAW_CANARY,
                    "reason": RAW_CANARY,
                    "policy_id": RAW_CANARY,
                }
            ]
        },
        status="BLOCKED",
        reason=RAW_CANARY,
        sensitive_labels=(RAW_CANARY,),
        policy_id=RAW_CANARY,
        transformations=(
            {
                "label": RAW_CANARY,
                "action": RAW_CANARY,
                "policy_id": RAW_CANARY,
                "value": RAW_CANARY,
            },
        ),
        risk=1.0,
        metadata={RAW_CANARY: RAW_CANARY, "content": RAW_CANARY},
    )

    persisted = repr(event) + _persisted_audit(logger, path, RAW_CANARY)
    assert RAW_CANARY not in persisted


def test_direct_audit_event_constructor_reduces_unknown_detection_and_decision_fields() -> None:
    event = AuditEvent(
        run_id=RAW_CANARY,
        step_id=1,
        timestamp=1.0,
        event_type=RAW_CANARY,
        status="BLOCKED",
        detection={"findings": [], "note": RAW_CANARY},
        decisions={"decisions": [], "note": RAW_CANARY},
        metadata={"note": RAW_CANARY},
    )

    assert RAW_CANARY not in repr(event)
    assert RAW_CANARY not in json.dumps(event.to_dict(), ensure_ascii=False)


def test_audit_identifier_prefixes_cannot_smuggle_raw_values(tmp_path: Any) -> None:
    path = tmp_path / "audit-identifiers.jsonl"
    logger = AuditLogger(path, key=b"audit-identifier-review-key-32bytes")

    event = logger.log(
        run_id="audit-identifiers",
        status="BLOCKED",
        tool=f"tool_{IDENTIFIER_CANARY}",
        destination=f"internal_{IDENTIFIER_CANARY}",
    )

    persisted = repr(event) + _persisted_audit(logger, path, "audit-identifiers")
    assert IDENTIFIER_CANARY not in persisted


def test_audit_logger_rejects_unknown_raw_status_without_persisting_it(tmp_path: Any) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, key=b"audit-review-tests-fixed-key-32byt")

    with pytest.raises(ValueError, match="Unsupported audit status"):
        logger.log(run_id="audit-invalid-status", status=RAW_CANARY)

    assert not path.exists()


@pytest.mark.parametrize(
    ("metadata_key", "metadata_value"),
    (
        ("artifact_ref", f"artifact_{RAW_CANARY}"),
        ("intent_id", f"intent_{RAW_CANARY}"),
        ("manifest_digest", f"manifest_{RAW_CANARY}"),
        ("permit_id", f"permit_{RAW_CANARY}"),
        ("entity_fingerprint", RAW_CANARY),
        ("value_fingerprint", RAW_CANARY),
        ("value_hash", RAW_CANARY),
        ("masked_preview", RAW_CANARY),
        ("policy_id", RAW_CANARY),
        ("error_code", RAW_CANARY),
        (
            "transformations",
            [{"label": RAW_CANARY, "action": RAW_CANARY, "policy_id": RAW_CANARY}],
        ),
    ),
)
def test_audit_logger_does_not_trust_pseudo_safe_metadata_names(
    tmp_path: Any, metadata_key: str, metadata_value: Any
) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, key=b"audit-review-tests-fixed-key-32byt")

    event = logger.log(
        run_id="audit-pseudo-safe-metadata",
        status="BLOCKED",
        metadata={metadata_key: metadata_value},
    )

    persisted = repr(event) + _persisted_audit(logger, path, "audit-pseudo-safe-metadata")
    assert RAW_CANARY not in persisted


@pytest.mark.parametrize(
    "obfuscated",
    (
        "138\u200b0013\u20608000",
        "１３８００１３８０００",
    ),
    ids=("zero-width", "nfkc-fullwidth"),
)
def test_normalization_detector_finds_obfuscated_sensitive_value(obfuscated: str) -> None:
    result = NormalizationDetector(RegexDetector()).detect(obfuscated)

    assert result.contains_sensitive_data
    assert any(finding.label == "MOBILE" for finding in result.findings)
    mobile = next(finding for finding in result.findings if finding.label == "MOBILE")
    assert mobile.value == obfuscated
    assert mobile.start == 0
    assert mobile.end == len(obfuscated)
    assert mobile.detector.startswith("normalized:")


@pytest.mark.parametrize(
    ("codec", "encode"),
    (
        ("base64", lambda value: base64.b64encode(value.encode()).decode()),
        ("url", lambda value: "".join(f"%{byte:02X}" for byte in value.encode())),
        ("hex", lambda value: value.encode().hex()),
    ),
)
def test_encoded_detector_finds_base64_percent_and_hex_variants(codec: str, encode: Any) -> None:
    encoded = encode("mobile=13800138000")

    result = EncodedPayloadDetector(RegexDetector()).detect(f"prefix {encoded} suffix")

    assert result.contains_sensitive_data
    finding = next(item for item in result.findings if item.label == "MOBILE")
    assert finding.value == encoded
    assert finding.detector.startswith(f"encoded:{codec}:")
