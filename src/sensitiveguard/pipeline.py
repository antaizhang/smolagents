"""The guard: detection, policy, disposition and review wired together.

The order is fixed and each stage hands the next one strictly less than it had:

1. content is **sealed** on arrival;
2. the **quarantined** agent reads it and returns facts;
3. the **policy engine** turns each fact into a verdict, deterministically,
   recording the path it took;
4. the **disposition router** carries the verdicts out on the sealed content;
5. the **reviewer** checks the output both ways — did the mask hold, and did it
   take the task down with it.

Restoring a response is stage 4 in reverse and only for the values a rule marked
restorable, which is what makes the round trip a policy decision rather than a
transformer's habit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agents import PrivilegedGuardAgent, QuarantinedDetectorAgent
from .detection.base import DetectionReport, Detector
from .detection.capability import CapabilityRouter
from .facts import ContentKind
from .policy.engine import PolicyEngine
from .policy.loader import default_policy
from .policy.model import Decision, Policy, RequestContext
from .quarantine import Quarantine, quarantine
from .review import OutputReviewer, ReviewReport
from .transform.router import Disposition, DispositionRouter
from .transform.vault import Restoration, TokenVault


@dataclass(frozen=True)
class GuardResult:
    """Everything one pass through the guard produced, including why."""

    ref: str
    kind: str
    context: RequestContext
    detection: DetectionReport
    decisions: tuple[Decision, ...]
    disposition: Disposition
    review: ReviewReport | None = None

    @property
    def released_text(self) -> str | None:
        return self.disposition.text

    @property
    def released(self) -> bool:
        return self.disposition.released

    @property
    def blocked(self) -> bool:
        return bool(self.disposition.blocked)

    @property
    def held_for_review(self) -> bool:
        return bool(self.disposition.held)

    @property
    def alerts(self) -> tuple[Decision, ...]:
        return self.disposition.alerts

    def decision_for(self, rule_id: str) -> Decision | None:
        for decision in self.decisions:
            if decision.rule_id == rule_id:
                return decision
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "kind": self.kind,
            "context": self.context.as_dict(),
            "detection": self.detection.as_dict(),
            "decisions": [decision.as_dict() for decision in self.decisions],
            "disposition": self.disposition.as_dict(),
            "review": self.review.as_dict() if self.review is not None else None,
        }

    def explain(self) -> str:
        """The whole audit trail, from fact to verdict to output."""

        lines = [f"guard pass ref={self.ref} {self.context.describe()}", self.detection.describe()]
        for index, decision in enumerate(self.decisions, start=1):
            lines.append(f"--- decision {index} ---")
            lines.append(decision.explain())
        lines.append(self.disposition.describe())
        if self.review is not None:
            lines.append(self.review.describe())
        return "\n".join(lines)


class SensitiveGuard:
    """One guard, assembled from the four layers.

    Parameters
    ----------
    policy:
        The rule set. Defaults to the policy shipped in
        ``sensitiveguard/policy/default_policy.yaml``.
    escalation:
        An adjudicating detector for the top cascade tier, e.g.
        :class:`~sensitiveguard.detection.llm_tier.PhoneAgentDetector`. Leave it
        out and no model participates at all: ambiguous spans reach policy
        unsettled and the rules decide what an unsettled span is worth.
    review_output:
        Run the output reviewer on every released result. On by default.
    """

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        escalation: Detector | None = None,
        capability_router: CapabilityRouter | None = None,
        vault: TokenVault | None = None,
        dispatcher: DispositionRouter | None = None,
        reviewer: OutputReviewer | None = None,
        hash_salt: bytes | None = None,
        review_output: bool = True,
    ) -> None:
        self.policy = policy if policy is not None else default_policy()
        self.engine = PolicyEngine(self.policy)
        self.capability_router = (
            capability_router if capability_router is not None else CapabilityRouter.build(escalation=escalation)
        )
        self.dispatcher = (
            dispatcher
            if dispatcher is not None
            else DispositionRouter(vault=vault if vault is not None else TokenVault(), hash_salt=hash_salt)
        )
        # Read the vault back off the dispatcher rather than keeping a second
        # reference: a guard whose `restore` looks in a different vault than its
        # tokeniser wrote to would fail silently, one round trip later.
        self.vault = self.dispatcher.vault
        self.detector_agent = QuarantinedDetectorAgent(self.capability_router)
        self.guard_agent = PrivilegedGuardAgent(self.engine, self.dispatcher)
        self.reviewer = reviewer if reviewer is not None else OutputReviewer(self.capability_router)
        self.review_output = review_output

    def inspect(
        self,
        content: str | Quarantine,
        *,
        destination: str,
        caller_role: str,
        purpose: str = "unspecified",
        kind: ContentKind | str = ContentKind.TEXT,
        origin: str = "unspecified",
    ) -> GuardResult:
        """Run one full pass.

        ``destination``, ``caller_role``, ``purpose`` and ``kind`` come from the
        caller that owns the request. They are never read out of ``content``,
        which is the reason a document cannot nominate its own destination and
        talk its way onto a softer rule.
        """

        sealed = quarantine(content, kind, origin=origin)
        context = RequestContext(
            destination=destination,
            caller_role=caller_role,
            purpose=purpose,
            kind=sealed.kind.value,
        )

        report = self.detector_agent.inspect(sealed)
        decisions = self.guard_agent.decide(report, context)
        disposition = self.guard_agent.dispatch(sealed, decisions)
        review = self.reviewer.review(sealed, disposition, decisions) if self.review_output else None

        return GuardResult(
            ref=sealed.ref,
            kind=sealed.kind.value,
            context=context,
            detection=report,
            decisions=decisions,
            disposition=disposition,
            review=review,
        )

    def restore(self, text: str) -> Restoration:
        """Seek phase: put back the values a rule marked restorable."""

        return self.dispatcher.restore(text)

    def self_test(self) -> list[str]:
        """Run the policy's own expectations and report the failures."""

        return [failure.describe() for failure in self.engine.self_test()]

    def describe(self) -> str:
        return "\n".join(
            [
                self.policy.describe(),
                "",
                "capability routes:",
                self.capability_router.describe_routes(),
            ]
        )

    def __repr__(self) -> str:
        return f"<SensitiveGuard policy={self.policy.label} kinds={len(self.capability_router.chains)}>"


__all__ = ["GuardResult", "SensitiveGuard"]
