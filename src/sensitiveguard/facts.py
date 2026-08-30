"""Facts produced by detectors.

A detector answers *what is in the text*. It never answers *what to do about
it*: that is the policy layer's job, and keeping the two apart is what makes a
decision auditable. Everything in this module is therefore inert data.

A :class:`Finding` deliberately does not carry the matched substring. It is a
symbolic reference — a label, a span and a confidence — so facts can travel to
the privileged side of the system without carrying untrusted bytes along with
them. Reading the actual value requires the text, which only the sealed
transformation code holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ContentKind(str, Enum):
    """What kind of content is being inspected.

    The kind is declared by the caller that owns the content. It is never
    inferred from the content itself, because content is untrusted and could
    then choose its own detector chain.
    """

    TEXT = "text"
    CODE = "code"
    JSON = "json"
    IMAGE_OCR = "image_ocr"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class Span:
    """A half-open ``[start, end)`` character range."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"span start must be >= 0, got {self.start}")
        if self.end <= self.start:
            raise ValueError(f"span end must be > start, got [{self.start}, {self.end})")

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: Span) -> bool:
        return self.start <= other.start and other.end <= self.end

    def shift(self, offset: int) -> Span:
        return Span(self.start + offset, self.end + offset)

    def as_list(self) -> list[int]:
        return [self.start, self.end]

    def __repr__(self) -> str:
        return f"[{self.start},{self.end}]"


@dataclass(frozen=True)
class Finding:
    """One fact: ``span=[12,23], label=PHONE, conf=0.87``.

    ``tier`` records which cascade tier settled the fact, so the cost of a
    detection is visible in the audit trail alongside the detection itself.
    """

    span: Span
    label: str
    confidence: float
    detector: str
    tier: int = 0

    def __post_init__(self) -> None:
        if not self.label or self.label != self.label.upper():
            raise ValueError(f"label must be a non-empty upper-case name, got {self.label!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be within [0, 1], got {self.confidence}")
        if not self.detector:
            raise ValueError("detector must be a non-empty name")
        if self.tier < 0:
            raise ValueError(f"tier must be >= 0, got {self.tier}")

    def value_in(self, text: str) -> str:
        """Read the referenced substring out of ``text``.

        This is the one place a fact is turned back into raw content. Only the
        transformation code, which already holds the sealed text, calls it.
        """

        return text[self.span.start : self.span.end]

    def with_confidence(self, confidence: float, *, detector: str | None = None, tier: int | None = None) -> Finding:
        return Finding(
            span=self.span,
            label=self.label,
            confidence=confidence,
            detector=detector or self.detector,
            tier=self.tier if tier is None else tier,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "span": self.span.as_list(),
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "detector": self.detector,
            "tier": self.tier,
        }

    def describe(self) -> str:
        return f"{self.label} span={self.span} conf={self.confidence:.2f} detector={self.detector} tier={self.tier}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by position, then by descending confidence."""

    return sorted(findings, key=lambda f: (f.span.start, f.span.end, -f.confidence, f.label))


def strongest_per_span(findings: list[Finding]) -> list[Finding]:
    """Drop findings whose span is swallowed by a stronger overlapping finding.

    An 18-digit id number and an 11-digit phone number can both match inside the
    same run of characters. Keeping the more confident, longer fact avoids
    transforming the same region twice with two different dispositions.
    """

    ranked = sorted(findings, key=lambda f: (-f.confidence, -len(f.span), f.span.start, f.label))
    kept: list[Finding] = []
    for finding in ranked:
        if any(finding.span.overlaps(other.span) for other in kept):
            continue
        kept.append(finding)
    return sort_findings(kept)


__all__ = ["ContentKind", "Finding", "Span", "sort_findings", "strongest_per_span"]
