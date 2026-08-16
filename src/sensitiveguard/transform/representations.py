"""Recognition of representations emitted by SensitiveGuard itself."""

from __future__ import annotations

import re

from sensitiveguard.models import Finding


_TYPED_MARKER = re.compile(r"\[(?P<kind>REDACTED|GENERALIZED):(?P<label>[A-Z0-9_]+)\]")
_TOKEN = re.compile(r"\b(?P<label>[A-Z][A-Z0-9_]*)_TOKEN_[A-F0-9]{24}\b")
_ALIAS = re.compile(r"\b(?P<prefix>[A-Z][A-Z0-9_]*)_(?P<sequence>\d{4})\b")
_SIMPLE_MARKER = re.compile(r"\[(?P<prefix>PERSON|PHONE_REGION|PHONE|EMAIL_USER)\]")

_PREFIX_LABELS = {
    "EMAIL": frozenset({"EMAIL"}),
    "EMAIL_USER": frozenset({"EMAIL"}),
    "LOCATION": frozenset({"ADDRESS"}),
    "PERSON": frozenset({"NAME"}),
    "PHONE": frozenset({"FAX", "MOBILE", "TEL"}),
    "PHONE_REGION": frozenset({"FAX", "MOBILE", "TEL"}),
}


def is_generated_representation(text: str, finding: Finding) -> bool:
    """Return whether a finding is wholly inside a matching runtime marker.

    Matching the semantic label is essential. For example ``PERSON_0001`` is
    safe as a NAME pseudonym, but remains sensitive when it appears in a field
    classified as PASSWD.
    """

    label = finding.label.upper()
    for match in _TYPED_MARKER.finditer(text):
        if _contains(match, finding) and match.group("label") == label:
            return True
    for match in _TOKEN.finditer(text):
        if _contains(match, finding) and match.group("label") == label:
            return True
    for pattern in (_ALIAS, _SIMPLE_MARKER):
        for match in pattern.finditer(text):
            if not _contains(match, finding):
                continue
            prefix = match.group("prefix")
            allowed_labels = _PREFIX_LABELS.get(prefix, frozenset({prefix}))
            if label in allowed_labels:
                return True
    return False


def _contains(match: re.Match[str], finding: Finding) -> bool:
    return match.start() <= finding.start and finding.end <= match.end()


__all__ = ["is_generated_representation"]
