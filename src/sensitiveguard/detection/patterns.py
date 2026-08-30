"""Tier-0 detectors: cheap, high-precision patterns.

These run on every request and are expected to settle most facts on their own.
Anything they settle never reaches a model, which is the point: a guard hangs
off every tool call, so the common path has to be a regex, not a generation.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..facts import Finding, Span
from .base import Detector


PHONE = "PHONE"
ID_CARD = "ID_CARD"
EMAIL = "EMAIL"
BANK_CARD = "BANK_CARD"
API_KEY = "API_KEY"

#: Every label the built-in detectors can emit. Policies are validated against
#: this set so a typo in a rule fails at load time instead of silently matching
#: nothing at runtime.
KNOWN_LABELS = frozenset({PHONE, ID_CARD, EMAIL, BANK_CARD, API_KEY})

MAINLAND_MOBILE_PATTERN = re.compile(r"(?<!\d)(?:(?:\+?86|0086)[ -]?)?1[3-9]\d(?:[ -]?\d){8}(?!\d)")
_ID_CARD_PATTERN = re.compile(r"(?<![0-9Xx])\d{17}[0-9Xx](?![0-9Xx])")
_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])")
_BANK_CARD_PATTERN = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_API_KEY_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{12,})"
)
_BEARER_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:sk|rk|ghp|gho|xox[baprs])-[A-Za-z0-9_\-]{16,}(?![A-Za-z0-9])")

_ID_CARD_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CARD_CHECKSUM = "10X98765432"


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def validate_id_card(value: str) -> float | None:
    """Return a confidence for a mainland resident id number, or ``None``.

    A valid GB 11643 checksum is a strong signal, so it settles at tier 0. An
    18-character run that fails the checksum is not rejected outright — it is
    downgraded to an ambiguous fact so a later tier can look at it.
    """

    candidate = value.strip()
    if len(candidate) != 18 or not candidate[:17].isdigit():
        return None
    total = sum(int(digit) * weight for digit, weight in zip(candidate[:17], _ID_CARD_WEIGHTS))
    expected = _ID_CARD_CHECKSUM[total % 11]
    if candidate[17].upper() == expected:
        return 0.99
    return 0.45


def validate_luhn(value: str) -> float | None:
    """Return a confidence for a Luhn-valid card number, or ``None``."""

    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return None
    total = 0
    for index, digit in enumerate(reversed(digits)):
        number = int(digit)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return 0.92 if total % 10 == 0 else None


class RegexDetector(Detector):
    """One label, one pattern, one confidence.

    ``validator`` may veto a match by returning ``None`` or override its
    confidence by returning a float, which is how a checksum turns a shape match
    into a settled fact.
    """

    def __init__(
        self,
        name: str,
        label: str,
        pattern: re.Pattern[str],
        confidence: float,
        *,
        validator: Callable[[str], float | None] | None = None,
        group: int = 0,
        tier: int = 0,
    ) -> None:
        self.name = name
        self.label = label
        self.labels = frozenset({label})
        self.pattern = pattern
        self.confidence = confidence
        self.validator = validator
        self.group = group
        self.tier = tier

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if start < 0 or end <= start:
                continue
            confidence = self.confidence
            if self.validator is not None:
                validated = self.validator(match.group(self.group))
                if validated is None:
                    continue
                confidence = validated
            findings.append(
                Finding(
                    span=Span(start, end),
                    label=self.label,
                    confidence=confidence,
                    detector=self.name,
                    tier=self.tier,
                )
            )
        return findings


class AmbiguousNumberDetector(Detector):
    """Tier-1 recall: number-shaped runs that tier 0 could not settle.

    This is the slot a span model such as GLiNER occupies in a production
    deployment. It is kept dependency-free here on purpose — what matters
    architecturally is that it emits low-confidence facts, which is what makes
    the tier above it fire. Swapping in a real model changes the accuracy of
    this tier, not the shape of the cascade.
    """

    name = "ambiguous-number"
    labels = frozenset({PHONE})

    #: Separators tier 0 does not accept. A number written ``138.0013.8000`` or
    #: in full-width digits slips past the high-precision pattern, which is
    #: exactly the kind of span that should cost a second look.
    SEPARATORS = " -._\u00b7\u3000"

    def __init__(self, *, confidence: float = 0.35, min_digits: int = 7, max_digits: int = 13) -> None:
        if min_digits < 2 or max_digits < min_digits:
            raise ValueError("min_digits must be >= 2 and max_digits must be >= min_digits")
        self.confidence = confidence
        self.min_digits = min_digits
        self.max_digits = max_digits
        digit = "[0-9\uff10-\uff19]"
        separator = f"[{re.escape(self.SEPARATORS)}]?"
        self._pattern = re.compile(rf"(?<!\w){digit}(?:{separator}{digit}){{{min_digits - 1},{max_digits - 1}}}(?!\w)")

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in self._pattern.finditer(text):
            findings.append(
                Finding(
                    span=Span(*match.span()),
                    label=PHONE,
                    confidence=self.confidence,
                    detector=self.name,
                    tier=1,
                )
            )
        return findings


def phone_detector() -> RegexDetector:
    return RegexDetector("regex:phone", PHONE, MAINLAND_MOBILE_PATTERN, 0.95)


def id_card_detector() -> RegexDetector:
    return RegexDetector("regex:id-card", ID_CARD, _ID_CARD_PATTERN, 0.99, validator=validate_id_card)


def email_detector() -> RegexDetector:
    return RegexDetector("regex:email", EMAIL, _EMAIL_PATTERN, 0.97)


def bank_card_detector() -> RegexDetector:
    return RegexDetector("regex:bank-card", BANK_CARD, _BANK_CARD_PATTERN, 0.92, validator=validate_luhn)


def api_key_detectors() -> list[RegexDetector]:
    return [
        RegexDetector("regex:api-key-assignment", API_KEY, _API_KEY_PATTERN, 0.9, group=1),
        RegexDetector("regex:api-key-prefixed", API_KEY, _BEARER_PATTERN, 0.94),
    ]


def high_precision_detectors() -> list[Detector]:
    """The tier-0 chain shared by every content kind."""

    return [phone_detector(), id_card_detector(), email_detector(), bank_card_detector()]


__all__ = [
    "API_KEY",
    "BANK_CARD",
    "EMAIL",
    "ID_CARD",
    "KNOWN_LABELS",
    "MAINLAND_MOBILE_PATTERN",
    "PHONE",
    "AmbiguousNumberDetector",
    "RegexDetector",
    "api_key_detectors",
    "bank_card_detector",
    "email_detector",
    "high_precision_detectors",
    "id_card_detector",
    "phone_detector",
    "validate_id_card",
    "validate_luhn",
]
