"""The reviewer: a second pass over what is about to be released.

Two failures live at the output edge and neither one shows up in the decision
path, because both happen after every rule has already agreed:

* the mask did not actually mask — the value survives somewhere in the output,
  in a different format, in a stretch nobody detected, or because a rewrite
  landed on the wrong offsets;
* the mask masked too much — the output is technically clean and useless,
  because the downstream task needed something that is now a row of asterisks.

Guarding only against the first produces a system that redacts everything and
passes every test. This runs both checks and reports them together.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from .detection.capability import CapabilityRouter
from .facts import ContentKind, Finding
from .policy.model import Decision
from .quarantine import Quarantine
from .transform.router import Disposition


#: How much of the original may be rewritten before the output is more redaction
#: than content. Deliberately permissive: dense contact details are a normal
#: shape for a support message, and a reviewer that cries wolf gets switched
#: off. Tune it per deployment against real traffic.
DEFAULT_MAX_REDACTED_RATIO = 0.65

#: However high the ratio, output this short cannot carry a task.
DEFAULT_MIN_REMAINING_CHARACTERS = 16

#: Confidence a fact must reach in re-scanned output before it counts as residue.
DEFAULT_RESIDUAL_FLOOR = 0.6


def _digits(value: str) -> str:
    return "".join(character for character in unicodedata.normalize("NFKC", value) if character.isdigit())


@dataclass(frozen=True)
class Leak:
    """A value that was supposed to be transformed and is still readable."""

    label: str
    rule_id: str
    span: tuple[int, int]
    form: str

    def describe(self) -> str:
        return f"{self.label} span=[{self.span[0]},{self.span[1]}] survived {self.form} despite rule {self.rule_id}"


@dataclass(frozen=True)
class ReviewReport:
    """The verdict on the output itself."""

    ok: bool
    leaks: tuple[Leak, ...] = ()
    residual: tuple[Finding, ...] = ()
    redacted_ratio: float = 0.0
    over_redacted: bool = False
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "leaks": [
                {"label": leak.label, "rule": leak.rule_id, "span": list(leak.span), "form": leak.form}
                for leak in self.leaks
            ],
            "residual": [finding.as_dict() for finding in self.residual],
            "redacted_ratio": round(self.redacted_ratio, 4),
            "over_redacted": self.over_redacted,
            "notes": list(self.notes),
        }

    def describe(self) -> str:
        lines = [f"review {'ok' if self.ok else 'FAILED'} redacted_ratio={self.redacted_ratio:.2%}"]
        for leak in self.leaks:
            lines.append(f"  leak {leak.describe()}")
        for finding in self.residual:
            lines.append(f"  residual {finding.describe()}")
        if self.over_redacted:
            lines.append("  over-redacted: the output may no longer support the task it was produced for")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


class OutputReviewer:
    """Check released output for both under- and over-redaction."""

    def __init__(
        self,
        router: CapabilityRouter,
        *,
        max_redacted_ratio: float = DEFAULT_MAX_REDACTED_RATIO,
        min_remaining_characters: int = DEFAULT_MIN_REMAINING_CHARACTERS,
        residual_floor: float = DEFAULT_RESIDUAL_FLOOR,
        min_digits_for_leak: int = 6,
    ) -> None:
        if not 0.0 < max_redacted_ratio <= 1.0:
            raise ValueError(f"max_redacted_ratio must be within (0, 1], got {max_redacted_ratio}")
        if min_remaining_characters < 0:
            raise ValueError(f"min_remaining_characters must be >= 0, got {min_remaining_characters}")
        self.router = router
        self.max_redacted_ratio = max_redacted_ratio
        self.min_remaining_characters = min_remaining_characters
        self.residual_floor = residual_floor
        self.min_digits_for_leak = min_digits_for_leak

    def review(self, sealed: Quarantine, disposition: Disposition, decisions: Sequence[Decision]) -> ReviewReport:
        if disposition.text is None:
            return ReviewReport(ok=True, notes=("content was withheld, so there is no output to review",))

        original = sealed.unseal()
        released = disposition.text
        leaks = tuple(self._find_leaks(original, released, decisions))
        residual = tuple(self._find_residual(released, decisions, sealed.kind))

        redacted_characters = sum(item.original_length for item in disposition.applied)
        redacted_ratio = redacted_characters / len(original) if original else 0.0
        surviving = len(original) - redacted_characters
        too_much = redacted_ratio > self.max_redacted_ratio
        too_little_left = bool(disposition.applied) and surviving < self.min_remaining_characters
        over_redacted = too_much or too_little_left

        notes: list[str] = []
        if too_much:
            notes.append(
                f"{redacted_ratio:.0%} of the input was rewritten, above the {self.max_redacted_ratio:.0%} ceiling"
            )
        if too_little_left:
            notes.append(
                f"only {surviving} character(s) survived the rewrite, below the "
                f"{self.min_remaining_characters}-character floor"
            )
        if not disposition.applied and not disposition.allowed:
            notes.append("nothing was transformed and nothing was allowed: check the policy actually matched")

        return ReviewReport(
            ok=not leaks and not residual and not over_redacted,
            leaks=leaks,
            residual=residual,
            redacted_ratio=redacted_ratio,
            over_redacted=over_redacted,
            notes=tuple(notes),
        )

    def _find_leaks(self, original: str, released: str, decisions: Sequence[Decision]) -> Iterable[Leak]:
        released_digits = _digits(released)
        for decision in decisions:
            if not (decision.transforms or decision.withholds):
                continue
            start, end = decision.span
            value = original[start:end]
            if not value:
                continue
            if value in released:
                yield Leak(decision.label, decision.rule_id, decision.span, "verbatim")
                continue
            # A value masked in one place can reappear elsewhere in another
            # format. Comparing digits catches the reformatted copy.
            value_digits = _digits(value)
            if len(value_digits) >= self.min_digits_for_leak and value_digits in released_digits:
                yield Leak(decision.label, decision.rule_id, decision.span, "reformatted")

    def _find_residual(self, released: str, decisions: Sequence[Decision], kind: ContentKind) -> Iterable[Finding]:
        protected = {decision.label for decision in decisions if decision.transforms or decision.withholds}
        exempt = {decision.label for decision in decisions if not (decision.transforms or decision.withholds)}
        watched = protected - exempt
        if not watched:
            return ()
        rescan = self.router.detect(Quarantine(released, kind, origin="released-output"))
        return [
            finding
            for finding in rescan.findings
            if finding.label in watched and finding.confidence >= self.residual_floor
        ]

    def __repr__(self) -> str:
        return f"<OutputReviewer max_redacted_ratio={self.max_redacted_ratio}>"


__all__ = [
    "DEFAULT_MAX_REDACTED_RATIO",
    "DEFAULT_MIN_REMAINING_CHARACTERS",
    "DEFAULT_RESIDUAL_FLOOR",
    "Leak",
    "OutputReviewer",
    "ReviewReport",
]
