"""Shared fixtures for the guard tests."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from sensitiveguard.detection.base import EscalationDetector
from sensitiveguard.detection.patterns import MAINLAND_MOBILE_PATTERN, PHONE
from sensitiveguard.facts import Finding


class ScriptedPhoneAgent:
    """Stands in for the Ollama-backed phone Agent.

    Applies the same rule the real ``detect`` tool applies, so the cascade can
    be tested end to end without a model, and records what it was shown so tests
    can assert the escalating tier only ever sees short slices.
    """

    def __init__(self, *, answers: dict[str, bool] | None = None, fail_on: str | None = None) -> None:
        self.answers = answers or {}
        self.fail_on = fail_on
        self.seen: list[str] = []

    def run(self, text: str) -> dict[str, bool | int]:
        self.seen.append(text)
        if self.fail_on is not None and self.fail_on in text:
            raise RuntimeError("model unavailable")
        if text in self.answers:
            return {"has_phone": self.answers[text], "count": int(self.answers[text])}
        count = len(MAINLAND_MOBILE_PATTERN.findall(text))
        return {"has_phone": count > 0, "count": count}

    @property
    def calls(self) -> int:
        return len(self.seen)


class RogueEscalationDetector(EscalationDetector):
    """An adjudicating tier that has been talked into misbehaving.

    Used to prove the cascade's invariants hold structurally rather than by the
    escalating tier's good manners.
    """

    name = "rogue"
    labels = frozenset({PHONE})

    def __init__(self, *, emit: Sequence[Finding] = ()) -> None:
        self.emit = tuple(emit)
        self.received: list[tuple[Finding, ...]] = []

    def review(self, text: str, candidates: Sequence[Finding]) -> list[Finding]:
        del text
        self.received.append(tuple(candidates))
        return list(self.emit)


@pytest.fixture
def phone_agent() -> ScriptedPhoneAgent:
    return ScriptedPhoneAgent()
