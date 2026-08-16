"""Strict conversion of audit payloads to safe JSON primitives."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from collections.abc import Mapping
from enum import Enum
from typing import Any


_FORBIDDEN_KEYS = {
    "api_key",
    "arguments",
    "authorization",
    "body",
    "content",
    "cookie",
    "credentials",
    "input",
    "output",
    "password",
    "passwd",
    "private_key",
    "prompt",
    "raw",
    "raw_text",
    "raw_value",
    "reason",
    "secret",
    "text",
    "value",
}
_SAFE_SENSITIVE_SUFFIXES = ("_hash", "_fingerprint", "_masked", "_preview", "_ref")
_PROCESS_AUDIT_KEY = secrets.token_bytes(32)
_SAFE_EVENT_TYPES = {
    "command_preflight",
    "command_result",
    "custom_event",
    "guard",
    "guard_error",
    "intent",
    "lineage",
    "security_review",
}
_SAFE_STAGES = {
    "data_acquisition",
    "final_output",
    "handoff",
    "mcp_input",
    "mcp_output",
    "memory",
    "tool_input",
    "tool_output",
}
_KNOWN_TOOLS = {
    "agent_additional_args",
    "agent_task",
    "audit_privacy_trajectory",
    "detect_sensitive_data",
    "evaluate_data_policy",
    "final_answer",
    "final_output",
    "mask_text",
    "max_steps_final_answer",
    "model_output",
    "pseudonymize_text",
    "redact_text",
    "remediate_sensitive_file",
    "safe_http_post",
    "safe_llm_call",
    "safe_query_database",
    "safe_read_file",
    "safe_retrieve_rag",
    "safe_run_command",
    "safe_send_email",
    "safe_send_message",
    "sanitize_file",
    "sanitize_text",
    "scan_directory",
    "scan_file",
    "tokenize_sensitive_data",
    "trace_data_lineage",
    "verify_sanitized_file",
}
_INTERNAL_DESTINATIONS = {
    "agent_memory",
    "database",
    "external_llm",
    "internal",
    "internal_database",
    "internal_file",
    "local",
    "local_process",
    "memory",
    "rag",
    "requester",
    "unknown",
}
_SAFE_ACTIONS = {
    "ALLOW",
    "BLOCK",
    "GENERALIZE",
    "MASK",
    "PSEUDONYMIZE",
    "REDACT",
    "REQUIRE_APPROVAL",
    "TOKENIZE",
}
_AUDIT_REFERENCE_KEYS = {
    "arguments_digest",
    "artifact_ref",
    "command_id",
    "entity_fingerprint",
    "intent_id",
    "lineage_event_id",
    "manifest_digest",
    "permit_id",
    "review_id",
    "route_id",
    "value_fingerprint",
    "value_hash",
}
_AUDIT_NUMERIC_KEYS = {
    "call_count",
    "duration_ms",
    "exit_code",
    "stderr_bytes",
    "stdout_bytes",
    "timed_out",
}


def collect_raw_values(*objects: Any) -> tuple[str, ...]:
    """Collect in-process values solely for scrubbing; callers must discard the result."""

    found: set[str] = set()

    def visit(value: Any) -> None:
        if value is None:
            return
        if all(hasattr(value, attribute) for attribute in ("detector", "end", "label", "start", "value")):
            finding_value = getattr(value, "value", None)
            if isinstance(finding_value, str) and finding_value:
                found.add(finding_value)
        findings = getattr(value, "findings", None)
        if findings is not None:
            for finding in findings:
                visit(finding)
        decisions = getattr(value, "decisions", None)
        if decisions is not None and not isinstance(decisions, Mapping):
            for decision in decisions:
                visit(decision)
        finding = getattr(value, "finding", None)
        if finding is not None:
            visit(finding)
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized_key = str(key).strip().lower()
                if _key_is_forbidden(normalized_key) and isinstance(child, str) and child:
                    found.add(child)
                else:
                    visit(child)
        elif isinstance(value, (tuple, list, set, frozenset)):
            for child in value:
                visit(child)

    for item in objects:
        visit(item)
    return tuple(sorted(found, key=lambda item: (-len(item), item)))


def scrub_string(value: str | None, raw_values: tuple[str, ...]) -> str | None:
    if value is None:
        return None
    result = value
    for raw_value in raw_values:
        if raw_value:
            result = result.replace(raw_value, "[REDACTED]")
    return result


def audit_fingerprint(value: Any, *, key: bytes | None = None, prefix: str = "audit") -> str:
    """Return a keyed, non-enumerable identifier for an audit field."""

    secret = key or _PROCESS_AUDIT_KEY
    payload = str(value).encode("utf-8", errors="replace")
    digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()[:32]
    return f"{prefix}_{digest}"


def safe_run_id(value: str, *, key: bytes | None = None) -> str:
    return audit_fingerprint(value, key=key, prefix="run")


def safe_event_type(value: str) -> str:
    normalized = str(value).strip().lower()
    return normalized if normalized in _SAFE_EVENT_TYPES else "custom_event"


def safe_stage(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return normalized if normalized in _SAFE_STAGES else None


def safe_tool_name(value: str | None, *, key: bytes | None = None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized in _KNOWN_TOOLS:
        return normalized
    return audit_fingerprint(normalized, key=key, prefix="tool")


def safe_destination(value: str | None, *, key: bytes | None = None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().casefold()
    if normalized in _INTERNAL_DESTINATIONS:
        return normalized
    for category in ("http", "message", "mcp", "agent"):
        marker = f"{category}:"
        if normalized.startswith(marker):
            target = normalized[len(marker) :]
            return marker + audit_fingerprint(target, key=key, prefix="dest")
    return audit_fingerprint(normalized, key=key, prefix="dest")


def safe_label(value: str) -> str:
    from sensitiveguard.detector.labels import (
        INJECTION_LABEL,
        NORMALIZED_PII_LABELS,
        SECRET_LABELS,
    )

    normalized = str(value).strip().upper()
    allowed = NORMALIZED_PII_LABELS | SECRET_LABELS | {INJECTION_LABEL}
    return normalized if normalized in allowed else "UNKNOWN"


def safe_metadata_token(value: Any, *, key: bytes, kind: str) -> str:
    """Never trust caller-provided values merely because a key says hash/ref."""

    text = str(value)
    if kind == "masked_preview":
        return "[REDACTED:PREVIEW]"
    return audit_fingerprint(text, key=key, prefix=kind)


def safe_audit_metadata(metadata: Mapping[str, Any], *, key: bytes | None = None) -> dict[str, Any]:
    secret = key or _PROCESS_AUDIT_KEY
    safe: dict[str, Any] = {}
    redacted_index = 0
    for raw_key, value in metadata.items():
        normalized = str(raw_key).strip().lower()
        if normalized in _AUDIT_REFERENCE_KEYS:
            safe[normalized] = safe_metadata_token(value, key=secret, kind=normalized)
        elif normalized in {"error_code", "policy_id"}:
            safe[normalized] = safe_metadata_token(value, key=secret, kind=normalized)
        elif normalized == "masked_preview":
            safe[normalized] = "[REDACTED:PREVIEW]"
        elif normalized in _AUDIT_NUMERIC_KEYS and isinstance(value, (bool, int, float)):
            safe[normalized] = value if not isinstance(value, float) or math.isfinite(value) else "non_finite"
        elif normalized == "transformations" and isinstance(value, (tuple, list)):
            summaries = []
            for item in value:
                if not isinstance(item, Mapping):
                    continue
                summary: dict[str, Any] = {}
                for field_name in ("label", "action", "start", "end"):
                    if field_name in item:
                        child = item[field_name]
                        if field_name in {"start", "end"} and isinstance(child, int) and not isinstance(child, bool):
                            summary[field_name] = child
                        elif field_name == "label":
                            summary[field_name] = safe_label(str(child))
                        elif field_name == "action":
                            normalized_action = str(child).strip().upper()
                            summary[field_name] = normalized_action if normalized_action in _SAFE_ACTIONS else "BLOCK"
                if "policy_id" in item:
                    summary["policy_id"] = safe_metadata_token(item["policy_id"], key=secret, kind="policy_id")
                summaries.append(summary)
            safe[normalized] = summaries
        else:
            redacted_index += 1
            safe[f"redacted_field_{redacted_index}"] = "[REDACTED]"
    return safe


def safe_detection_summary(value: Mapping[str, Any] | None, *, key: bytes | None = None) -> dict[str, Any] | None:
    """Reduce an arbitrary detection mapping to the fixed audit schema."""

    if value is None:
        return None
    secret = key or _PROCESS_AUDIT_KEY
    findings: list[dict[str, Any]] = []
    raw_findings = value.get("findings", ())
    if isinstance(raw_findings, (tuple, list)):
        for item in raw_findings:
            if not isinstance(item, Mapping):
                continue
            finding: dict[str, Any] = {"label": safe_label(str(item.get("label", "UNKNOWN")))}
            for field_name in ("start", "end"):
                field_value = item.get(field_name)
                if isinstance(field_value, int) and not isinstance(field_value, bool) and field_value >= 0:
                    finding[field_name] = field_value
            score = item.get("score")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(float(score)):
                finding["score"] = max(0.0, min(float(score), 1.0))
            severity = str(item.get("severity", "unknown")).strip().lower()
            finding["severity"] = severity if severity in {"low", "medium", "high", "critical"} else "unknown"
            finding["detector"] = audit_fingerprint(item.get("detector", "unknown"), key=secret, prefix="detector")
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


def safe_decisions_summary(value: Mapping[str, Any] | None, *, key: bytes | None = None) -> dict[str, Any] | None:
    """Reduce an arbitrary decision mapping to the fixed audit schema."""

    if value is None:
        return None
    secret = key or _PROCESS_AUDIT_KEY
    decisions: list[dict[str, Any]] = []
    raw_decisions = value.get("decisions", ())
    if isinstance(raw_decisions, (tuple, list)):
        for item in raw_decisions:
            if not isinstance(item, Mapping):
                continue
            raw_finding = item.get("finding")
            finding_container = {"findings": [raw_finding]} if isinstance(raw_finding, Mapping) else {"findings": []}
            safe_findings = safe_detection_summary(finding_container, key=secret)["findings"]
            if not safe_findings:
                continue
            action = str(item.get("decision", "BLOCK")).strip().upper()
            safe_item: dict[str, Any] = {
                "finding": safe_findings[0],
                "decision": action if action in _SAFE_ACTIONS else "BLOCK",
                "reason": "[REDACTED:REASON]",
                "policy_id": safe_metadata_token(item.get("policy_id", "unknown"), key=secret, kind="policy_id"),
                "severity": safe_findings[0].get("severity", "unknown"),
                "allowed_after_transform": bool(item.get("allowed_after_transform", False)),
                "necessary": bool(item.get("necessary", False)),
            }
            raw_risk = item.get("risk")
            if isinstance(raw_risk, Mapping):
                risk: dict[str, float] = {}
                for field_name in ("score", "sensitivity", "destination", "non_necessity", "exposure", "combination"):
                    number = raw_risk.get(field_name)
                    if (
                        isinstance(number, (int, float))
                        and not isinstance(number, bool)
                        and math.isfinite(float(number))
                    ):
                        risk[field_name] = max(0.0, float(number))
                safe_item["risk"] = risk
            decisions.append(safe_item)
    return {
        "decisions": decisions,
        "has_block": any(item["decision"] == "BLOCK" for item in decisions),
        "requires_approval": any(item["decision"] == "REQUIRE_APPROVAL" for item in decisions),
    }


def safe_json_value(value: Any, raw_values: tuple[str, ...], *, key: str | None = None) -> Any:
    """Convert a value to JSON primitives without stringifying unknown objects."""

    normalized_key = key.strip().lower() if key else None
    if normalized_key and _key_is_forbidden(normalized_key):
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return scrub_string(value, raw_values)
    if isinstance(value, Enum):
        return safe_json_value(value.value, raw_values, key=key)
    if isinstance(value, Mapping):
        safe_mapping = {}
        for child_key, child in value.items():
            original_key = str(child_key)
            safe_key = scrub_string(original_key, raw_values) or "[REDACTED_KEY]"
            safe_mapping[safe_key] = safe_json_value(child, raw_values, key=original_key)
        return safe_mapping
    if isinstance(value, (tuple, list, set, frozenset)):
        return [safe_json_value(child, raw_values) for child in value]

    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return safe_json_value(to_dict(), raw_values)
    return f"<{type(value).__name__}>"


def _key_is_forbidden(key: str) -> bool:
    if key.endswith(_SAFE_SENSITIVE_SUFFIXES):
        return False
    return key in _FORBIDDEN_KEYS or key.endswith("_password") or key.endswith("_secret") or key.endswith("_token")
