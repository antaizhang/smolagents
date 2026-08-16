"""Strict conversion of audit payloads to safe JSON primitives."""

from __future__ import annotations

import math
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
