"""In-memory and optional JSONL privacy audit logger."""

from __future__ import annotations

import json
import math
import os
import secrets
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from threading import RLock
from typing import Any

from sensitiveguard.models import (
    Action,
    DecisionSet,
    DetectionResult,
    Finding,
    GuardStage,
    GuardStatus,
    PolicyDecision,
)

from .event import AuditEvent
from .metrics import AuditMetrics, compute_metrics
from .sanitize import (
    audit_fingerprint,
    collect_raw_values,
    safe_event_type,
    safe_json_value,
    safe_label,
    safe_metadata_token,
    safe_run_id,
    safe_stage,
)
from .trajectory import build_trajectory_report


class AuditWriteError(RuntimeError):
    """Raised when a fail-closed audit sink cannot persist an event."""


class AuditLogger:
    """Record security decisions without retaining raw sensitive values."""

    def __init__(
        self,
        jsonl_path: str | os.PathLike[str] | None = None,
        *,
        default_run_id: str | None = None,
        fail_closed: bool = True,
        fsync: bool = False,
        key: bytes | None = None,
    ) -> None:
        self.jsonl_path = Path(jsonl_path) if jsonl_path is not None else None
        self.default_run_id = default_run_id
        self.fail_closed = fail_closed
        self.fsync = fsync
        self._key = key or secrets.token_bytes(32)
        if len(self._key) < 32:
            raise ValueError("AuditLogger key must contain at least 32 bytes")
        self._events: list[AuditEvent] = []
        self._next_steps: dict[str, int] = {}
        self._lock = RLock()

    def log(
        self,
        run_id: str | None = None,
        *,
        event_type: str = "guard",
        stage: GuardStage | str | None = None,
        tool: str | None = None,
        destination: str | None = None,
        detection: DetectionResult | Finding | Iterable[Finding] | Mapping[str, Any] | None = None,
        decisions: DecisionSet | PolicyDecision | Iterable[PolicyDecision] | Mapping[str, Any] | None = None,
        status: GuardStatus | Action | str | None = None,
        reason: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        # Compatibility aliases used by the architecture document and wrappers.
        action: str | None = None,
        decision: str | None = None,
        findings: DetectionResult | Finding | Iterable[Finding] | Mapping[str, Any] | None = None,
        sensitive_labels: Iterable[str] | None = None,
        policy_id: str | None = None,
        transformations: Iterable[Any] | None = None,
        risk: float | None = None,
    ) -> AuditEvent:
        raw_run_id = run_id or self.default_run_id
        if not raw_run_id:
            raise ValueError("run_id must be provided either to AuditLogger or log()")
        resolved_run_id = safe_run_id(str(raw_run_id), key=self._key)
        if findings is not None:
            if detection is not None:
                raise ValueError("Use either detection or findings, not both")
            detection = findings
        if action is not None and event_type == "guard":
            event_type = action
        resolved_status = self._normalize_status(status if status is not None else decision)

        if detection is not None and not isinstance(detection, (DetectionResult, Finding, Mapping)):
            detection = tuple(detection)
        if decisions is not None and not isinstance(decisions, (DecisionSet, PolicyDecision, Mapping)):
            decisions = tuple(decisions)
        transformation_values = tuple(transformations) if transformations is not None else None
        explicit_labels = tuple(sensitive_labels) if sensitive_labels is not None else None

        raw_values = collect_raw_values(detection, decisions, metadata, transformation_values)
        safe_detection = self._safe_detection(detection, raw_values)
        safe_decisions = self._safe_decisions(decisions, raw_values)
        labels = self._labels(safe_detection, safe_decisions, explicit_labels)
        event_risk = self._risk(safe_decisions, risk)

        extra_metadata = dict(metadata or {})
        if policy_id is not None:
            extra_metadata["policy_id"] = policy_id
        if transformation_values is not None:
            extra_metadata["transformations"] = self._transformation_summaries(transformation_values, raw_values)
        with self._lock:
            step_id = self._next_steps.get(resolved_run_id, 1)
            event = AuditEvent(
                run_id=str(raw_run_id),
                step_id=step_id,
                timestamp=time.time(),
                event_type=safe_event_type(str(event_type)),
                stage=self._normalize_stage(stage, raw_values),
                tool=tool,
                destination=destination,
                sensitive_labels=labels,
                detection=safe_detection,
                decisions=safe_decisions,
                status=resolved_status,
                reason="[REDACTED:REASON]" if reason is not None else None,
                risk=event_risk,
                metadata=extra_metadata,
                _sanitization_key=self._key,
            )
            write_failed = False
            try:
                self._append_jsonl(event)
            except Exception:
                write_failed = True
            if write_failed and self.fail_closed:
                # Do not let the exception traceback retain the raw Finding
                # objects or scrub list held by this frame.
                detection = decisions = findings = metadata = transformations = None
                raw_values = ()
                transformation_values = explicit_labels = None
                extra_metadata = {}
                run_id = raw_run_id = event_type = stage = tool = destination = None
                action = decision = sensitive_labels = policy_id = risk = reason = None
                raise AuditWriteError("Could not persist the privacy audit event.") from None
            self._events.append(event)
            self._next_steps[resolved_run_id] = step_id + 1
            return event

    def events(self, run_id: str | None = None) -> tuple[AuditEvent, ...]:
        with self._lock:
            if run_id is None:
                return tuple(self._events)
            resolved = safe_run_id(str(run_id), key=self._key)
            return tuple(event for event in self._events if event.run_id == resolved)

    def metrics(self, run_id: str | None = None) -> AuditMetrics:
        return compute_metrics(self.events(run_id))

    def report(self, run_id: str) -> dict[str, Any]:
        resolved = safe_run_id(str(run_id), key=self._key)
        return build_trajectory_report(self.events(run_id), resolved).to_dict()

    def clear_memory(self, run_id: str | None = None) -> None:
        """Clear the memory sink only; an existing JSONL audit trail is immutable."""

        with self._lock:
            if run_id is None:
                self._events.clear()
                return
            resolved = safe_run_id(str(run_id), key=self._key)
            self._events = [event for event in self._events if event.run_id != resolved]

    def _append_jsonl(self, event: AuditEvent) -> None:
        if self.jsonl_path is None:
            return
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        descriptor = os.open(self.jsonl_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()
            if self.fsync:
                os.fsync(stream.fileno())

    @staticmethod
    def _transformation_summaries(values: tuple[Any, ...], raw_values: tuple[str, ...]) -> list[dict[str, Any]]:
        summaries = []
        for value in values:
            if isinstance(value, Mapping):
                serialized = value
            else:
                to_dict = getattr(value, "to_dict", None)
                serialized = to_dict() if callable(to_dict) else {}
            summary = {
                key: safe_json_value(serialized[key], raw_values, key=key)
                for key in ("label", "action", "start", "end", "policy_id")
                if key in serialized
            }
            summaries.append(summary)
        return summaries

    def _safe_detection(
        self,
        detection: DetectionResult | Finding | Iterable[Finding] | Mapping[str, Any] | None,
        raw_values: tuple[str, ...],
    ) -> dict[str, Any] | None:
        if detection is None:
            return None
        if isinstance(detection, DetectionResult):
            value: Any = detection.to_dict()
        elif isinstance(detection, Finding):
            value = DetectionResult((detection,)).to_dict()
        elif isinstance(detection, Mapping):
            value = detection
        else:
            findings = tuple(detection)
            if not all(isinstance(finding, Finding) for finding in findings):
                raise TypeError("detection iterable must contain only Finding objects")
            value = DetectionResult(findings).to_dict()
        serialized = safe_json_value(value, raw_values)
        if not isinstance(serialized, dict):
            raise TypeError("detection must serialize to an object")
        findings: list[dict[str, Any]] = []
        for item in serialized.get("findings", ()):
            if not isinstance(item, Mapping):
                continue
            label = safe_label(str(item.get("label", "UNKNOWN")))
            finding: dict[str, Any] = {"label": label}
            for field_name in ("start", "end"):
                field_value = item.get(field_name)
                if isinstance(field_value, int) and not isinstance(field_value, bool) and field_value >= 0:
                    finding[field_name] = field_value
            score = item.get("score")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(float(score)):
                finding["score"] = max(0.0, min(float(score), 1.0))
            severity = str(item.get("severity", "unknown")).lower()
            finding["severity"] = severity if severity in {"low", "medium", "high", "critical"} else "unknown"
            finding["detector"] = audit_fingerprint(item.get("detector", "unknown"), key=self._key, prefix="detector")
            findings.append(finding)
        counts: dict[str, int] = {}
        for finding in findings:
            label = finding["label"]
            counts[label] = counts.get(label, 0) + 1
        return {
            "contains_sensitive_data": bool(findings),
            "findings": findings,
            "counts": dict(sorted(counts.items())),
        }

    def _safe_decisions(
        self,
        decisions: DecisionSet | PolicyDecision | Iterable[PolicyDecision] | Mapping[str, Any] | None,
        raw_values: tuple[str, ...],
    ) -> dict[str, Any] | None:
        if decisions is None:
            return None
        if isinstance(decisions, DecisionSet):
            value: Any = decisions.to_dict()
        elif isinstance(decisions, PolicyDecision):
            value = DecisionSet((decisions,)).to_dict()
        elif isinstance(decisions, Mapping):
            value = decisions
        else:
            policy_decisions = tuple(decisions)
            if not all(isinstance(item, PolicyDecision) for item in policy_decisions):
                raise TypeError("decisions iterable must contain only PolicyDecision objects")
            value = DecisionSet(policy_decisions).to_dict()
        serialized = safe_json_value(value, raw_values)
        if not isinstance(serialized, dict):
            raise TypeError("decisions must serialize to an object")
        safe_decisions: list[dict[str, Any]] = []
        allowed_actions = {item.value for item in Action}
        for item in serialized.get("decisions", ()):
            if not isinstance(item, Mapping):
                continue
            raw_finding = item.get("finding")
            finding_container = {"findings": [raw_finding]} if isinstance(raw_finding, Mapping) else {"findings": []}
            finding_values = self._safe_detection(finding_container, raw_values)["findings"]
            if not finding_values:
                continue
            action_value = str(item.get("decision", "BLOCK")).upper()
            safe_item: dict[str, Any] = {
                "finding": finding_values[0],
                "decision": action_value if action_value in allowed_actions else Action.BLOCK.value,
                "reason": "[REDACTED:REASON]",
                "policy_id": safe_metadata_token(item.get("policy_id", "unknown"), key=self._key, kind="policy_id"),
                "severity": finding_values[0].get("severity", "unknown"),
                "allowed_after_transform": bool(item.get("allowed_after_transform", False)),
                "necessary": bool(item.get("necessary", False)),
            }
            raw_risk = item.get("risk")
            if isinstance(raw_risk, Mapping):
                risk_values = {}
                for key in ("score", "sensitivity", "destination", "non_necessity", "exposure", "combination"):
                    number = raw_risk.get(key)
                    if (
                        isinstance(number, (int, float))
                        and not isinstance(number, bool)
                        and math.isfinite(float(number))
                    ):
                        risk_values[key] = max(0.0, float(number))
                safe_item["risk"] = risk_values
            safe_decisions.append(safe_item)
        return {
            "decisions": safe_decisions,
            "has_block": any(item["decision"] == Action.BLOCK.value for item in safe_decisions),
            "requires_approval": any(item["decision"] == Action.REQUIRE_APPROVAL.value for item in safe_decisions),
        }

    @staticmethod
    def _labels(
        detection: dict[str, Any] | None,
        decisions: dict[str, Any] | None,
        explicit: Iterable[str] | None,
    ) -> tuple[str, ...]:
        labels = {safe_label(str(label)) for label in (explicit or ())}
        if detection:
            labels.update(
                safe_label(str(finding["label"]))
                for finding in detection.get("findings", ())
                if isinstance(finding, dict) and finding.get("label")
            )
        if decisions:
            labels.update(
                safe_label(str(decision["finding"]["label"]))
                for decision in decisions.get("decisions", ())
                if isinstance(decision, dict)
                and isinstance(decision.get("finding"), dict)
                and decision["finding"].get("label")
            )
        return tuple(sorted(labels))

    @staticmethod
    def _risk(decisions: dict[str, Any] | None, explicit: float | None) -> float:
        if explicit is not None:
            if isinstance(explicit, bool) or not isinstance(explicit, (int, float)):
                raise TypeError("risk must be numeric")
            if not math.isfinite(float(explicit)) or explicit < 0:
                raise ValueError("risk must be finite and non-negative")
            return float(explicit)
        if not decisions:
            return 0.0
        scores = []
        for decision in decisions.get("decisions", ()):
            if not isinstance(decision, dict) or not isinstance(decision.get("risk"), dict):
                continue
            score = decision["risk"].get("score")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(float(score)):
                scores.append(max(0.0, float(score)))
        return math.fsum(scores)

    @staticmethod
    def _normalize_status(status: GuardStatus | Action | str | None) -> str:
        if status is None:
            raise ValueError("status is required")
        value = status.value if isinstance(status, (GuardStatus, Action)) else str(status).upper()
        aliases = {
            "ALLOW": GuardStatus.ALLOWED.value,
            "ALLOWED": GuardStatus.ALLOWED.value,
            "PERMITTED": GuardStatus.ALLOWED.value,
            "SENT": GuardStatus.ALLOWED.value,
            "SUCCESS": GuardStatus.ALLOWED.value,
            "BLOCK": GuardStatus.BLOCKED.value,
            "BLOCKED": GuardStatus.BLOCKED.value,
            "DENIED": GuardStatus.BLOCKED.value,
            "REJECTED": GuardStatus.BLOCKED.value,
            "GENERALIZE": GuardStatus.TRANSFORMED.value,
            "MASK": GuardStatus.TRANSFORMED.value,
            "MASKED": GuardStatus.TRANSFORMED.value,
            "PSEUDONYMIZE": GuardStatus.TRANSFORMED.value,
            "REDACT": GuardStatus.TRANSFORMED.value,
            "SANITIZED": GuardStatus.TRANSFORMED.value,
            "TOKENIZE": GuardStatus.TRANSFORMED.value,
            "TRANSFORMED": GuardStatus.TRANSFORMED.value,
            "APPROVAL_REQUIRED": GuardStatus.APPROVAL_REQUIRED.value,
            "REQUIRE_APPROVAL": GuardStatus.APPROVAL_REQUIRED.value,
        }
        if value not in aliases:
            raise ValueError(f"Unsupported audit status: {value}")
        return aliases[value]

    @staticmethod
    def _normalize_stage(stage: GuardStage | str | None, raw_values: tuple[str, ...]) -> str | None:
        del raw_values
        if stage is None:
            return None
        value = stage.value if isinstance(stage, GuardStage) else str(stage)
        return safe_stage(value)
