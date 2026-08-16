"""Offline regression tests for the SensitiveGuard runtime security core."""

from __future__ import annotations

import itertools
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from sensitiveguard.audit import AuditLogger, AuditWriteError
from sensitiveguard.models import (
    Action,
    DecisionSet,
    DetectionResult,
    Finding,
    GuardStage,
    GuardStatus,
    PolicyDecision,
    RiskAssessment,
    Severity,
)
from sensitiveguard.privacy import DisclosureLedger, PrivacyContext
from sensitiveguard.runtime import AuthorizationError, AuthorizationPolicy, SafeToolGateway
from sensitiveguard.transform import (
    InvalidSpanError,
    Pseudonymizer,
    TokenResolutionDisabled,
    TokenVault,
    TransformationEngine,
)


AUDIT_CANARY = "SG-AUDIT-CANARY-440101199001011234"
GATEWAY_VALUE = "13800138000"


def _finding(
    text: str,
    value: str,
    label: str,
    *,
    start: int | None = None,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    offset = text.index(value) if start is None else start
    return Finding(
        label=label,
        start=offset,
        end=offset + len(value),
        score=0.99,
        severity=severity,
        detector="offline-test",
        value=value,
    )


def _decision(
    finding: Finding,
    action: Action,
    *,
    risk_score: float | None = None,
    policy_id: str = "SG-TEST-001",
    reason: str = "Matched an offline test policy",
) -> PolicyDecision:
    risk = None
    if risk_score is not None:
        risk = RiskAssessment(
            score=risk_score,
            sensitivity=1.0,
            destination=1.0,
            non_necessity=1.0,
            exposure=1.0,
            combination=0.0,
        )
    return PolicyDecision(
        finding=finding,
        action=action,
        reason=reason,
        policy_id=policy_id,
        severity=finding.severity,
        allowed_after_transform=action not in {Action.BLOCK, Action.REQUIRE_APPROVAL},
        necessary=False,
        risk=risk,
    )


class TransformationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TransformationEngine(
            pseudonymizer=Pseudonymizer(b"p" * 32),
            token_vault=TokenVault(b"t" * 32),
        )

    def test_applies_all_five_transformations_in_reverse_span_order(self) -> None:
        name = "张三"
        mobile = "13800138000"
        identity = "440101199001011234"
        bank_account = "6222020200001234567"
        address = "北京市海淀区中关村"
        text = f"姓名={name}; 手机={mobile}; 身份证={identity}; 银行卡={bank_account}; 地址={address}"
        decisions = DecisionSet(
            (
                _decision(_finding(text, mobile, "MOBILE"), Action.MASK),
                _decision(_finding(text, address, "ADDRESS"), Action.GENERALIZE),
                _decision(_finding(text, name, "NAME"), Action.PSEUDONYMIZE),
                _decision(_finding(text, bank_account, "BANKACCOUNT"), Action.TOKENIZE),
                _decision(_finding(text, identity, "IDCARD"), Action.REDACT),
            )
        )

        result = self.engine.apply_with_report(text, decisions, "run-transform")

        self.assertIn("姓名=PERSON_0001", result.content)
        self.assertIn("手机=138****8000", result.content)
        self.assertIn("身份证=[REDACTED:IDCARD]", result.content)
        self.assertIn("银行卡=BANKACCOUNT_TOKEN_", result.content)
        self.assertIn("地址=北京市", result.content)
        for raw_value in (name, mobile, identity, bank_account, address):
            self.assertNotIn(raw_value, result.content)
        self.assertEqual(
            {item.action for item in result.transformations},
            {Action.MASK, Action.REDACT, Action.PSEUDONYMIZE, Action.TOKENIZE, Action.GENERALIZE},
        )
        self.assertEqual(self.engine.apply(text, decisions, "run-transform"), result.content)

    def test_overlap_resolution_is_order_independent_and_covers_the_union(self) -> None:
        text = "0123456789"
        decisions = (
            _decision(_finding(text, "012345", "MOBILE", start=0), Action.MASK, policy_id="MASK"),
            _decision(_finding(text, "34567", "BANKACCOUNT", start=3), Action.TOKENIZE, policy_id="TOKEN"),
            _decision(_finding(text, "789", "IDCARD", start=7), Action.REDACT, policy_id="REDACT"),
        )

        outputs = {
            self.engine.apply(text, DecisionSet(tuple(permutation)), "run-overlap")
            for permutation in itertools.permutations(decisions)
        }

        self.assertEqual(outputs, {"[REDACTED:IDCARD]"})

    def test_rejects_stale_or_out_of_bounds_original_spans(self) -> None:
        stale = Finding("IDCARD", 0, 3, 1.0, Severity.CRITICAL, "offline-test", "999")
        stale_decision = DecisionSet((_decision(stale, Action.REDACT),))
        with self.assertRaises(InvalidSpanError):
            self.engine.apply("123", stale_decision, "run-invalid")

        outside = Finding("IDCARD", 2, 5, 1.0, Severity.CRITICAL, "offline-test", "345")
        outside_decision = DecisionSet((_decision(outside, Action.REDACT),))
        with self.assertRaises(InvalidSpanError):
            self.engine.apply("1234", outside_decision, "run-invalid")


class TokenVaultTests(unittest.TestCase):
    def test_default_vault_is_stable_one_way_and_does_not_retain_raw(self) -> None:
        vault = TokenVault(b"v" * 32)

        token = vault.tokenize(AUDIT_CANARY, "PASSWD", "run-token")

        self.assertEqual(token, vault.tokenize(AUDIT_CANARY, "PASSWD", "run-token"))
        self.assertNotEqual(token, vault.tokenize(AUDIT_CANARY, "PASSWD", "other-run"))
        self.assertNotIn(AUDIT_CANARY, token)
        self.assertFalse(vault.stores_raw)
        self.assertIsNone(vault._raw_values)
        self.assertNotIn(AUDIT_CANARY, repr(vault))
        with self.assertRaises(TokenResolutionDisabled):
            vault.resolve(token)
        with self.assertRaises(TokenResolutionDisabled):
            vault.detokenize(token)


class DisclosureLedgerTests(unittest.TestCase):
    @staticmethod
    def _risk_decisions(score: float) -> DecisionSet:
        finding = Finding("IDCARD", 0, 1, 1.0, Severity.CRITICAL, "offline-test", "X")
        return DecisionSet((_decision(finding, Action.ALLOW, risk_score=score),))

    def test_budget_equality_is_allowed_and_excess_does_not_mutate(self) -> None:
        ledger = DisclosureLedger(default_budget=100, fingerprint_key=b"l" * 32)
        decisions = self._risk_decisions(50)

        preview = ledger.preflight("run-equality", "external", decisions)
        first = ledger.reserve("run-equality", "external", decisions)
        second = ledger.reserve("run-equality", "external", decisions)
        denied = ledger.reserve("run-equality", "external", decisions)

        self.assertTrue(preview)
        self.assertEqual(ledger.cumulative_risk("run-equality", "external"), 100)
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertEqual(second.remaining_budget, 0)
        self.assertFalse(denied)
        self.assertEqual(denied.cumulative_risk, 100)
        self.assertEqual(len(ledger.entries("run-equality", "external")), 2)
        self.assertEqual(ledger.cumulative_risk("run-equality", "another-destination"), 0)

    def test_concurrent_reservations_atomically_share_one_budget(self) -> None:
        ledger = DisclosureLedger(default_budget=100, fingerprint_key=b"c" * 32)
        decisions = self._risk_decisions(10)
        worker_count = 20
        barrier = Barrier(worker_count)

        def reserve_once(_: int):
            barrier.wait()
            return ledger.reserve("run-concurrent", "external", decisions)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            reservations = tuple(executor.map(reserve_once, range(worker_count)))

        self.assertEqual(sum(bool(reservation) for reservation in reservations), 10)
        self.assertEqual(ledger.cumulative_risk("run-concurrent", "external"), 100)
        self.assertEqual(len(ledger.entries("run-concurrent", "external")), 10)

    def test_post_policy_representation_reduces_disclosure_charge(self) -> None:
        ledger = DisclosureLedger(default_budget=1_000, fingerprint_key=b"e" * 32)
        finding = _finding("13800138000", "13800138000", "MOBILE", severity=Severity.HIGH)

        risks = {
            action: ledger.preflight(
                "run-representation-risk",
                action.value,
                DecisionSet((_decision(finding, action, risk_score=100),)),
            ).requested_risk
            for action in (
                Action.ALLOW,
                Action.MASK,
                Action.GENERALIZE,
                Action.PSEUDONYMIZE,
                Action.TOKENIZE,
                Action.REDACT,
            )
        }

        self.assertGreater(risks[Action.ALLOW], risks[Action.MASK])
        self.assertGreater(risks[Action.MASK], risks[Action.GENERALIZE])
        self.assertGreater(risks[Action.GENERALIZE], risks[Action.PSEUDONYMIZE])
        self.assertGreater(risks[Action.PSEUDONYMIZE], risks[Action.TOKENIZE])
        self.assertEqual(risks[Action.REDACT], 0)


class AuditLoggerTests(unittest.TestCase):
    def test_memory_jsonl_and_report_never_contain_raw_canary(self) -> None:
        finding = Finding(
            "IDCARD",
            0,
            len(AUDIT_CANARY),
            1.0,
            Severity.CRITICAL,
            "offline-test",
            AUDIT_CANARY,
        )
        decision = _decision(
            finding,
            Action.BLOCK,
            risk_score=90,
            reason=f"blocked raw value {AUDIT_CANARY}",
        )
        detection = DetectionResult((finding,))
        decisions = DecisionSet((decision,))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "privacy.jsonl"
            logger = AuditLogger(path)
            first = logger.log(
                run_id="run-audit",
                stage=GuardStage.TOOL_INPUT,
                destination="external",
                detection=detection,
                decisions=decisions,
                status=GuardStatus.BLOCKED,
                reason=f"blocked {AUDIT_CANARY}",
                metadata={"raw_value": AUDIT_CANARY, "note": f"contains {AUDIT_CANARY}"},
            )
            second = logger.log(run_id="run-audit", status=GuardStatus.ALLOWED)

            self.assertEqual((first.step_id, second.step_id), (1, 2))
            serialized_event = json.dumps(first.to_dict(), ensure_ascii=False)
            serialized_events = json.dumps([event.to_dict() for event in logger.events()], ensure_ascii=False)
            serialized_report = json.dumps(logger.report("run-audit"), ensure_ascii=False)
            persisted = path.read_text(encoding="utf-8")
            for serialized in (serialized_event, serialized_events, serialized_report, persisted, repr(first)):
                self.assertNotIn(AUDIT_CANARY, serialized)
            self.assertEqual(len(persisted.splitlines()), 2)
            self.assertEqual(logger.metrics("run-audit").total_events, 2)

    def test_free_text_reason_and_metadata_are_not_persisted(self) -> None:
        logger = AuditLogger(default_run_id="run-free-text")

        event = logger.log(
            status=GuardStatus.ALLOWED,
            reason=f"operator note contains {AUDIT_CANARY}",
            metadata={"note": f"unclassified {AUDIT_CANARY}"},
        )

        serialized = json.dumps(event.to_dict(), ensure_ascii=False)
        self.assertNotIn(AUDIT_CANARY, serialized)
        self.assertEqual(event.reason, "[REDACTED:REASON]")
        self.assertEqual(event.to_dict()["metadata"]["redacted_field_1"], "[REDACTED]")

    def test_audit_write_error_drops_raw_exception_context_and_frame_locals(self) -> None:
        finding = Finding(
            "IDCARD",
            0,
            len(AUDIT_CANARY),
            1.0,
            Severity.CRITICAL,
            "offline-test",
            AUDIT_CANARY,
        )
        with tempfile.TemporaryDirectory() as directory:
            logger = AuditLogger(Path(directory))
            with self.assertRaises(AuditWriteError) as captured:
                logger.log(
                    run_id="run-audit-failure",
                    status=GuardStatus.BLOCKED,
                    detection=DetectionResult((finding,)),
                    reason=AUDIT_CANARY,
                    metadata={"note": AUDIT_CANARY},
                )

        error = captured.exception
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        frame_values = []
        traceback = error.__traceback__
        while traceback is not None:
            frame_values.extend(repr(value) for value in traceback.tb_frame.f_locals.values())
            traceback = traceback.tb_next
        self.assertNotIn(AUDIT_CANARY, "".join(frame_values))


class AuthorizationPolicyTests(unittest.TestCase):
    def test_path_traversal_symlink_and_source_overwrite_are_rejected(self) -> None:
        # macOS exposes /var as a symlink to /private/var. AuthorizationPolicy
        # intentionally rejects any symlink ancestor, so use the checked-out
        # workspace rather than tempfile's platform default for this test.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            workspace = Path(directory)
            allowed_root = workspace / "allowed"
            allowed_root.mkdir()
            source = allowed_root / "source.txt"
            source.write_text("safe", encoding="utf-8")
            outside = workspace / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            policy = AuthorizationPolicy(allowed_roots=(allowed_root,))

            self.assertEqual(policy.authorize_path(source), source.resolve())
            with self.assertRaises(AuthorizationError):
                policy.authorize_path(allowed_root / ".." / "outside.txt")
            with self.assertRaises(AuthorizationError):
                policy.authorize_copy(source, source)
            self.assertEqual(
                policy.authorize_path(allowed_root / "sanitized.txt", write=True, must_exist=False),
                (allowed_root / "sanitized.txt").resolve(),
            )

            link = allowed_root / "outside-link"
            try:
                link.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"Symbolic links are unavailable: {error}")
            with self.assertRaises(AuthorizationError):
                policy.authorize_path(link)

    def test_url_allowlist_is_exact_and_private_networks_are_denied_by_default(self) -> None:
        policy = AuthorizationPolicy(
            allowed_http_hosts=frozenset({"api.example.test"}),
            allow_private_networks=True,
        )

        allowed = "https://api.example.test/v1"
        self.assertEqual(policy.authorize_url(allowed), allowed)
        with self.assertRaises(AuthorizationError):
            policy.authorize_url("http://api.example.test/v1")
        with self.assertRaises(AuthorizationError):
            policy.authorize_url("https://api.example.test.attacker.invalid/v1")
        with self.assertRaises(AuthorizationError):
            policy.authorize_url("https://user:password@api.example.test/v1")

        private_policy = AuthorizationPolicy(allowed_http_hosts=frozenset({"127.0.0.1"}))
        with self.assertRaises(AuthorizationError):
            private_policy.authorize_url("https://127.0.0.1/private")

    def test_database_projection_rejects_wildcards_and_scope_expansion(self) -> None:
        policy = AuthorizationPolicy(
            allowed_database_tables={
                "customers": frozenset({"purchase_amount", "name"}),
            }
        )

        self.assertEqual(
            policy.authorize_projection(
                "customers",
                ["purchase_amount"],
                context_scope=["purchase_amount"],
            ),
            ("purchase_amount",),
        )
        for fields, scope in (
            (["*"], ["purchase_amount"]),
            (["bank_account"], ["bank_account"]),
            (["name"], ["purchase_amount"]),
        ):
            with self.assertRaises(AuthorizationError):
                policy.authorize_projection("customers", fields, context_scope=scope)
        with self.assertRaises(AuthorizationError):
            policy.authorize_projection("unknown", ["purchase_amount"])


class _StaticDetector:
    def __init__(self, raw_value: str = GATEWAY_VALUE) -> None:
        self.raw_value = raw_value
        self.calls = 0

    def detect(self, content: str, context=None) -> DetectionResult:
        del context
        self.calls += 1
        if self.raw_value not in content:
            return DetectionResult()
        finding = _finding(content, self.raw_value, "MOBILE", severity=Severity.HIGH)
        return DetectionResult((finding,))


class _RaisingDetector:
    def __init__(self) -> None:
        self.calls = 0

    def detect(self, content: str, context=None) -> DetectionResult:
        del content, context
        self.calls += 1
        raise RuntimeError(f"detector echoed {AUDIT_CANARY}")


class _MaskPolicy:
    def __init__(self) -> None:
        self.calls = 0

    def evaluate(self, findings, context, stage, destination=None, recipient=None) -> DecisionSet:
        del context, stage, destination, recipient
        self.calls += 1
        return DecisionSet(
            tuple(_decision(finding, Action.MASK, risk_score=10, policy_id="SG-GATEWAY-MASK") for finding in findings)
        )


class _NonReleasableMaskPolicy:
    def evaluate(self, findings, context, stage, destination=None, recipient=None) -> DecisionSet:
        del context, stage, destination, recipient
        return DecisionSet(
            tuple(
                PolicyDecision(
                    finding=finding,
                    action=Action.MASK,
                    reason="Transformation is permitted only for local processing",
                    policy_id="SG-NO-RELEASE",
                    severity=finding.severity,
                    allowed_after_transform=False,
                    necessary=False,
                )
                for finding in findings
            )
        )


class _RaisingTransformer:
    def __init__(self) -> None:
        self.calls = 0

    def apply(self, text, decisions, run_id):
        del text, decisions, run_id
        self.calls += 1
        raise RuntimeError(f"transformer echoed {AUDIT_CANARY}")


class _RaisingAuditLogger:
    def __init__(self) -> None:
        self.calls = 0

    def log(self, **kwargs):
        del kwargs
        self.calls += 1
        raise RuntimeError(f"audit sink echoed {AUDIT_CANARY}")


class SafeToolGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = PrivacyContext(
            task="send a minimized customer summary",
            purpose="analytics",
            destination="external",
            trust_level="external",
            run_id="run-gateway",
        )

    @staticmethod
    def _gateway(detector, transformer, ledger, audit_logger, policy=None) -> SafeToolGateway:
        return SafeToolGateway(
            detector=detector,
            policy_engine=policy or _MaskPolicy(),
            transformer=transformer,
            ledger=ledger,
            audit_logger=audit_logger,
        )

    def test_normal_path_detects_transforms_reserves_and_audits(self) -> None:
        detector = _StaticDetector()
        policy = _MaskPolicy()
        ledger = DisclosureLedger(default_budget=100, fingerprint_key=b"g" * 32)
        audit = AuditLogger()
        gateway = self._gateway(detector, TransformationEngine(), ledger, audit, policy)

        result = gateway.guard_text(
            f"contact={GATEWAY_VALUE}",
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
            tool_name="safe_send_message",
        )

        self.assertEqual(result.status, GuardStatus.TRANSFORMED)
        self.assertEqual(result.content, "contact=138****8000")
        self.assertEqual(detector.calls, 1)
        self.assertEqual(policy.calls, 1)
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 4)
        self.assertEqual(audit.events("run-gateway")[0].status, GuardStatus.TRANSFORMED.value)
        self.assertNotIn(GATEWAY_VALUE, json.dumps(audit.report("run-gateway"), ensure_ascii=False))

    def test_privacy_budget_denial_does_not_return_transformed_content(self) -> None:
        ledger = DisclosureLedger(default_budget=3, fingerprint_key=b"b" * 32)
        audit = AuditLogger()
        gateway = self._gateway(_StaticDetector(), TransformationEngine(), ledger, audit)

        result = gateway.guard_text(
            GATEWAY_VALUE,
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
        )

        self.assertEqual(result.status, GuardStatus.BLOCKED)
        self.assertIsNone(result.content)
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 0)
        self.assertEqual(audit.events("run-gateway")[-1].status, GuardStatus.BLOCKED.value)

    def test_policy_can_forbid_release_even_when_it_selects_a_transformation(self) -> None:
        ledger = DisclosureLedger(default_budget=100, fingerprint_key=b"n" * 32)
        audit = AuditLogger()
        gateway = self._gateway(
            _StaticDetector(),
            TransformationEngine(),
            ledger,
            audit,
            policy=_NonReleasableMaskPolicy(),
        )

        result = gateway.guard_text(
            GATEWAY_VALUE,
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
        )

        self.assertEqual(result.status, GuardStatus.BLOCKED)
        self.assertIsNone(result.content)
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 0)

    def test_detector_failure_is_closed_and_error_canary_is_not_audited(self) -> None:
        detector = _RaisingDetector()
        policy = _MaskPolicy()
        ledger = DisclosureLedger(fingerprint_key=b"d" * 32)
        audit = AuditLogger()
        gateway = self._gateway(detector, TransformationEngine(), ledger, audit, policy)

        result = gateway.guard_text(
            GATEWAY_VALUE,
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
        )

        self.assertEqual(result.status, GuardStatus.BLOCKED)
        self.assertIsNone(result.content)
        self.assertEqual(policy.calls, 0)
        self.assertNotIn(AUDIT_CANARY, result.reason or "")
        self.assertNotIn(AUDIT_CANARY, json.dumps(audit.report("run-gateway"), ensure_ascii=False))
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 0)

    def test_transform_failure_is_closed_before_ledger_reservation(self) -> None:
        transformer = _RaisingTransformer()
        ledger = DisclosureLedger(fingerprint_key=b"r" * 32)
        audit = AuditLogger()
        gateway = self._gateway(_StaticDetector(), transformer, ledger, audit)

        result = gateway.guard_text(
            GATEWAY_VALUE,
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
        )

        self.assertEqual(result.status, GuardStatus.BLOCKED)
        self.assertIsNone(result.content)
        self.assertEqual(transformer.calls, 1)
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 0)
        self.assertNotIn(AUDIT_CANARY, result.reason or "")
        self.assertNotIn(AUDIT_CANARY, json.dumps(audit.report("run-gateway"), ensure_ascii=False))

    def test_audit_failure_is_closed_after_conservative_ledger_debit(self) -> None:
        ledger = DisclosureLedger(fingerprint_key=b"a" * 32)
        audit = _RaisingAuditLogger()
        gateway = self._gateway(_StaticDetector(), TransformationEngine(), ledger, audit)

        result = gateway.guard_text(
            GATEWAY_VALUE,
            self.context,
            GuardStage.TOOL_INPUT,
            destination="external",
        )

        self.assertEqual(result.status, GuardStatus.BLOCKED)
        self.assertIsNone(result.content)
        self.assertEqual(audit.calls, 1)
        self.assertEqual(ledger.cumulative_risk("run-gateway", "external"), 4)
        self.assertNotIn(AUDIT_CANARY, result.reason or "")


if __name__ == "__main__":
    unittest.main()
