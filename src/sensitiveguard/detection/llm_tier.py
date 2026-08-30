"""The last rung of the cascade: a model, asked one narrow question at a time.

The phone Agent in :mod:`sensitiveguard.phone_agent` is not the guard. It is the
tier that adjudicates spans the cheap tiers could not settle — a normalised
slice at a time, with a call budget, and with a return type that cannot carry
anything but facts.

That last part is the whole reason a model is allowed to read untrusted content
here at all: the tier's output is a list of
:class:`~sensitiveguard.facts.Finding`, whose spans are copied from the
candidates it was handed. Text arriving from the model is never parsed into an
action, a destination, or a routing choice, so there is no channel for an
instruction hidden in the slice to reach anything that holds authority.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from typing import Any

from ..facts import Finding
from .base import EscalationDetector
from .patterns import PHONE


_STRIPPED = set(" -._·　")


def normalize_number_text(value: str) -> str:
    """Fold full-width digits and drop the separators tier 0 refuses.

    ``１３８.００１３.８０００`` and ``138 0013 8000`` both become
    ``13800138000``, which is what makes an obfuscated number answerable.
    """

    folded = unicodedata.normalize("NFKC", value)
    return "".join(character for character in folded if character not in _STRIPPED)


class PhoneAgentDetector(EscalationDetector):
    """Escalate ambiguous number spans to the one-tool phone Agent.

    Parameters
    ----------
    agent:
        A ready :class:`~sensitiveguard.phone_agent.PhoneDetectionAgent`. Supply
        ``model`` instead to have one built.
    confirmed_confidence:
        Confidence attached to a candidate the Agent confirms.
    max_calls:
        Per-pass call budget. Candidates beyond it are re-emitted untouched
        rather than dismissed, so a budget cut can never open a hole.
    context:
        Characters of surrounding text included in the slice. Zero by default:
        a wider window lets a neighbouring number answer for the candidate.
    """

    name = "agent:phone"
    labels = frozenset({PHONE})

    def __init__(
        self,
        agent: Any = None,
        *,
        model: Any = None,
        confirmed_confidence: float = 0.85,
        max_calls: int = 8,
        context: int = 0,
    ) -> None:
        if agent is None and model is None:
            raise ValueError("PhoneAgentDetector needs either a built agent or a model to build one from")
        if agent is None:
            from ..phone_agent import PhoneDetectionAgent

            agent = PhoneDetectionAgent(model=model)
        if not 0.0 < confirmed_confidence <= 1.0:
            raise ValueError(f"confirmed_confidence must be within (0, 1], got {confirmed_confidence}")
        if max_calls < 0:
            raise ValueError(f"max_calls must be >= 0, got {max_calls}")
        if context < 0:
            raise ValueError(f"context must be >= 0, got {context}")
        self.agent = agent
        self.confirmed_confidence = confirmed_confidence
        self.max_calls = max_calls
        self.context = context
        #: Number of Agent runs the last :meth:`review` actually spent.
        self.calls = 0
        #: Candidates re-emitted because the budget ran out or the Agent failed.
        self.deferred = 0

    def review(self, text: str, candidates: Sequence[Finding]) -> list[Finding]:
        self.calls = 0
        self.deferred = 0
        confirmed: list[Finding] = []

        for candidate in candidates:
            if self.calls >= self.max_calls:
                self.deferred += 1
                confirmed.append(candidate)
                continue

            start = max(0, candidate.span.start - self.context)
            end = min(len(text), candidate.span.end + self.context)
            slice_text = normalize_number_text(text[start:end])
            if not slice_text.strip():
                continue

            self.calls += 1
            try:
                result = self.agent.run(slice_text)
            except Exception:
                # An unreachable or misbehaving model must not silently clear a
                # candidate. Hand it back unchanged and let policy decide.
                self.deferred += 1
                confirmed.append(candidate)
                continue

            if isinstance(result, dict) and bool(result.get("has_phone")):
                # The span is copied from the candidate: this tier confirms
                # spans, it never proposes new ones.
                confirmed.append(
                    Finding(
                        span=candidate.span,
                        label=PHONE,
                        confidence=self.confirmed_confidence,
                        detector=self.name,
                        tier=candidate.tier + 1,
                    )
                )

        return confirmed


__all__ = ["PhoneAgentDetector", "normalize_number_text"]
