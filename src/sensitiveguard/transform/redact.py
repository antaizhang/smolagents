"""Irreversible redaction helpers."""

from __future__ import annotations


def redact_value(label: str | None = None) -> str:
    """Return a marker that cannot contain any part of the original value."""

    if not label:
        return "[REDACTED]"
    safe_label = "".join(character for character in label.upper() if character.isalnum() or character == "_")
    return f"[REDACTED:{safe_label or 'SENSITIVE'}]"
