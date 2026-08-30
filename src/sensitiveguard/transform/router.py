"""Disposition routing: dispatching a verdict to the code that carries it out.

This is control flow, not judgement. Every decision has already been made by the
time a disposition router runs; its job is to send each verdict to its handler,
apply the rewrites in an order that keeps the spans valid, and stop the content
from being released when something says it must not be.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..policy.model import Action, Decision, severity
from ..quarantine import Quarantine
from .handlers import Handler, default_handlers
from .vault import Restoration, TokenVault


@dataclass(frozen=True)
class AppliedTransform:
    """One span that was rewritten, recorded without the value it replaced."""

    decision: Decision
    replacement: str
    original_length: int

    def describe(self) -> str:
        return (
            f"{self.decision.action.value} {self.decision.label} span=[{self.decision.span[0]},"
            f"{self.decision.span[1]}] {self.original_length} char(s) -> {self.replacement!r}"
        )


@dataclass(frozen=True)
class Disposition:
    """What the router did, and whether the content may be released."""

    text: str | None
    applied: tuple[AppliedTransform, ...] = ()
    allowed: tuple[Decision, ...] = ()
    blocked: tuple[Decision, ...] = ()
    held: tuple[Decision, ...] = ()
    superseded: tuple[Decision, ...] = ()
    alerts: tuple[Decision, ...] = ()

    @property
    def released(self) -> bool:
        return self.text is not None

    @property
    def withheld(self) -> bool:
        return bool(self.blocked or self.held)

    def as_dict(self) -> dict[str, Any]:
        return {
            "released": self.released,
            "applied": [
                {"rule": item.decision.rule_id, "action": item.decision.action.value, "label": item.decision.label}
                for item in self.applied
            ],
            "allowed": [decision.rule_id for decision in self.allowed],
            "blocked": [decision.rule_id for decision in self.blocked],
            "held": [decision.rule_id for decision in self.held],
            "superseded": [decision.rule_id for decision in self.superseded],
            "alerts": [decision.rule_id for decision in self.alerts],
        }

    def describe(self) -> str:
        state = "released" if self.released else ("blocked" if self.blocked else "held for review")
        lines = [f"disposition {state}"]
        for item in self.applied:
            lines.append(f"  {item.describe()}")
        for decision in self.allowed:
            lines.append(
                f"  allow {decision.label} span=[{decision.span[0]},{decision.span[1]}] by {decision.rule_id}"
            )
        for decision in self.blocked:
            lines.append(f"  block {decision.label} by {decision.rule_id}: {decision.reason}")
        for decision in self.held:
            lines.append(f"  review {decision.label} by {decision.rule_id}: {decision.reason}")
        for decision in self.superseded:
            lines.append(f"  superseded {decision.label} span=[{decision.span[0]},{decision.span[1]}]")
        for decision in self.alerts:
            lines.append(f"  ALERT {decision.label} by {decision.rule_id}")
        return "\n".join(lines)


class DispositionRouter:
    """Send each verdict to its handler and assemble the result."""

    def __init__(
        self,
        *,
        vault: TokenVault | None = None,
        handlers: Mapping[Action, Handler] | None = None,
        hash_salt: bytes | None = None,
    ) -> None:
        self.vault = vault if vault is not None else TokenVault()
        self.handlers = dict(handlers) if handlers is not None else default_handlers(self.vault, hash_salt=hash_salt)

    def apply(self, sealed: Quarantine, decisions: Iterable[Decision]) -> Disposition:
        """Carry out ``decisions`` against the sealed content."""

        if not isinstance(sealed, Quarantine):
            raise TypeError("disposition routing operates on quarantined content")

        kept, superseded = _resolve_overlaps(list(decisions))
        alerts = tuple(decision for decision in kept if decision.alert)
        blocked = tuple(decision for decision in kept if decision.action is Action.BLOCK)
        held = tuple(decision for decision in kept if decision.action is Action.REVIEW)
        allowed = tuple(decision for decision in kept if decision.action is Action.ALLOW)

        if blocked or held:
            # Nothing is released, so nothing is transformed: running the
            # handlers here would populate the vault with values that no
            # response will ever come back to restore.
            return Disposition(
                text=None,
                allowed=allowed,
                blocked=blocked,
                held=held,
                superseded=tuple(superseded),
                alerts=alerts,
            )

        text = sealed.unseal()
        applied: list[AppliedTransform] = []
        # Right to left, so an earlier span's offsets survive a later rewrite.
        for decision in sorted(
            (decision for decision in kept if decision.transforms),
            key=lambda decision: decision.span[0],
            reverse=True,
        ):
            handler = self.handlers.get(decision.action)
            if handler is None:
                raise KeyError(f"no handler registered for action {decision.action.value}")
            start, end = decision.span
            original = text[start:end]
            replacement = handler.apply(original, decision)
            text = f"{text[:start]}{replacement}{text[end:]}"
            applied.append(AppliedTransform(decision=decision, replacement=replacement, original_length=len(original)))

        applied.reverse()
        return Disposition(
            text=text,
            applied=tuple(applied),
            allowed=allowed,
            superseded=tuple(superseded),
            alerts=alerts,
        )

    def restore(self, text: str) -> Restoration:
        """Seek phase: put restorable values back into a response."""

        return self.vault.restore_text(text)


def _resolve_overlaps(decisions: list[Decision]) -> tuple[list[Decision], list[Decision]]:
    """Keep one verdict per region of text, preferring the more protective one.

    Overlaps are already rare — the cascade collapses competing facts before
    policy sees them — but two rewrites of the same characters would corrupt the
    output, so the tie is broken here rather than left to span arithmetic.
    """

    ranked = sorted(
        decisions,
        key=lambda decision: (
            -severity(decision.action),
            -(decision.span[1] - decision.span[0]),
            -decision.confidence,
            decision.span[0],
        ),
    )
    kept: list[Decision] = []
    superseded: list[Decision] = []
    for decision in ranked:
        start, end = decision.span
        if any(start < other.span[1] and other.span[0] < end for other in kept):
            superseded.append(decision)
            continue
        kept.append(decision)
    kept.sort(key=lambda decision: decision.span)
    superseded.sort(key=lambda decision: decision.span)
    return kept, superseded


__all__ = ["AppliedTransform", "Disposition", "DispositionRouter"]
