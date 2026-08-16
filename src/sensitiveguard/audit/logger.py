"""In-memory and optional JSONL privacy audit logger."""

from __future__ import annotations

import json
import math
import os
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
from .sanitize import collect_raw_values, safe_json_value, scrub_string
from .trajectory import build_trajectory_report


_SAFE_METADATA_KEYS = frozenset(
    {
        "artifact_ref",
        "entity_fingerprint",
        "error_code",
        "masked_preview",
        "policy_id",
        "value_fingerprint",
        "value_hash",
    }
)


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
    ) -> None:
        self.jsonl_path = Path(jsonl_path) if jsonl_path is not None else None
        self.default_run_id = default_run_id
        self.fail_closed = fail_closed
        self.fsync = fsync
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
        resolved_run_id = run_id or self.default_run_id
        if not resolved_run_id:
            raise ValueError("run_id must be provided either to AuditLogger or log()")
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
        safe_metadata = self._safe_metadata(extra_metadata, raw_values)

        with self._lock:
            step_id = self._next_steps.get(resolved_run_id, 1)
            event = AuditEvent(
                run_id=scrub_string(resolved_run_id, raw_values) or "[REDACTED]",
                step_id=step_id,
                timestamp=time.time(),
                event_type=scrub_string(str(event_type), raw_values) or "guard",
                stage=self._normalize_stage(stage, raw_values),
                tool=scrub_string(tool, raw_values),
                destination=scrub_string(destination, raw_values),
                sensitive_labels=labels,
                detection=safe_detection,
                decisions=safe_decisions,
                status=resolved_status,
                reason="[REDACTED:REASON]" if reason is not None else None,
                risk=event_risk,
                metadata=safe_metadata,
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
                reason = None
                raise AuditWriteError("Could not persist the privacy audit event.") from None
            self._events.append(event)
            self._next_steps[resolved_run_id] = step_id + 1
            return event

    def events(self, run_id: str | None = None) -> tuple[AuditEvent, ...]:
        with self._lock:
            if run_id is None:
                return tuple(self._events)
            return tuple(event for event in self._events if event.run_id == run_id)

    def metrics(self, run_id: str | None = None) -> AuditMetrics:
        return compute_metrics(self.events(run_id))

    def report(self, run_id: str) -> dict[str, Any]:
        return build_trajectory_report(self.events(run_id), run_id).to_dict()

    def clear_memory(self, run_id: str | None = None) -> None:
        """Clear the memory sink only; an existing JSONL audit trail is immutable."""

        with self._lock:
            if run_id is None:
                self._events.clear()
                return
            self._events = [event for event in self._events if event.run_id != run_id]

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
    def _safe_metadata(metadata: Mapping[str, Any], raw_values: tuple[str, ...]) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        redacted_index = 0
        for raw_key, value in metadata.items():
            key = str(raw_key)
            normalized = key.strip().lower()
            if normalized == "transformations":
                safe[normalized] = value
            elif normalized in _SAFE_METADATA_KEYS:
                safe[normalized] = safe_json_value(value, raw_values, key=normalized)
            else:
                redacted_index += 1
                safe[f"redacted_field_{redacted_index}"] = "[REDACTED]"
        return safe

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

    @staticmethod
    def _safe_detection(
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
        safe = safe_json_value(value, raw_values)
        if not isinstance(safe, dict):
            raise TypeError("detection must serialize to an object")
        return safe

    @staticmethod
    def _safe_decisions(
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
        safe = safe_json_value(value, raw_values)
        if not isinstance(safe, dict):
            raise TypeError("decisions must serialize to an object")
        return safe

    @staticmethod
    def _labels(
        detection: dict[str, Any] | None,
        decisions: dict[str, Any] | None,
        explicit: Iterable[str] | None,
    ) -> tuple[str, ...]:
        labels = {str(label).upper() for label in (explicit or ())}
        if detection:
            labels.update(
                str(finding["label"]).upper()
                for finding in detection.get("findings", ())
                if isinstance(finding, dict) and finding.get("label")
            )
        if decisions:
            labels.update(
                str(decision["finding"]["label"]).upper()
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
        if stage is None:
            return None
        value = stage.value if isinstance(stage, GuardStage) else str(stage)
        return scrub_string(value, raw_values)
