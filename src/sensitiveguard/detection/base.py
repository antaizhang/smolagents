"""The detector interface and the report a detection pass produces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..facts import Finding, Span


class Detector(ABC):
    """Produces facts about a text and nothing else.

    A detector may not decide, transform, block, or call a tool. Restricting the
    return type to :class:`~sensitiveguard.facts.Finding` is what lets a
    detector read untrusted content safely: whatever the content says, the only
    thing it can influence is a label, a span and a confidence.
    """

    #: Stable name recorded on every finding this detector produces.
    name: str = "detector"

    #: The labels this detector is able to emit.
    labels: frozenset[str] = frozenset()

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        """Return the facts found in ``text``."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name} labels={sorted(self.labels)}>"


class EscalationDetector(Detector):
    """A detector that can also be asked about specific candidate spans.

    The cascade calls :meth:`review` instead of :meth:`detect` so an expensive
    tier only ever looks at the spans an earlier tier could not settle. This is
    where the cost lever lives: the tier sees a handful of short slices, not the
    whole document.
    """

    @abstractmethod
    def review(self, text: str, candidates: Sequence[Finding]) -> list[Finding]:
        """Return refined facts for ``candidates`` only."""

    def detect(self, text: str) -> list[Finding]:
        del text
        return []


@dataclass(frozen=True)
class DetectionReport:
    """The output of one detection pass, with what it cost to produce."""

    findings: tuple[Finding, ...] = ()
    kind: str = "text"
    chain: tuple[str, ...] = ()
    tiers_run: tuple[str, ...] = ()
    escalated: tuple[Span, ...] = ()
    escalation_calls: int = 0
    notes: tuple[str, ...] = ()

    def labels(self) -> tuple[str, ...]:
        return tuple(sorted({finding.label for finding in self.findings}))

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "chain": list(self.chain),
            "tiers_run": list(self.tiers_run),
            "escalated": [span.as_list() for span in self.escalated],
            "escalation_calls": self.escalation_calls,
            "findings": [finding.as_dict() for finding in self.findings],
            "notes": list(self.notes),
        }

    def describe(self) -> str:
        lines = [
            f"detection kind={self.kind} chain={'>'.join(self.chain) or 'none'} "
            f"tiers_run={'>'.join(self.tiers_run) or 'none'} escalation_calls={self.escalation_calls}"
        ]
        if not self.findings:
            lines.append("  (no findings)")
        for finding in self.findings:
            lines.append(f"  {finding.describe()}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


__all__ = ["DetectionReport", "Detector", "EscalationDetector"]
