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
from .audit import AuditBus, Channel
from .detection.base import DetectionReport, Detector
from .detection.capability import CapabilityRouter
from .facts import ContentKind
from .policy.engine import PolicyEngine
from .policy.loader import default_policy
from .policy.model import Action, Decision, Policy, RequestContext
from .quarantine import Quarantine, quarantine
from .review import OutputReviewer, ReviewReport
from .transform.handlers import TokenizeHandler
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
    audit:
        An :class:`~sensitiveguard.audit.AuditBus`. Pass one and every internal
        boundary the content or its facts cross is recorded by digest, which is
        what turns "did the output leak" into the much sharper "which channel
        did it leak on". Leave it out and nothing is recorded.
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
        audit: AuditBus | None = None,
    ) -> None:
        self.policy = policy if policy is not None else default_policy()
        self.audit = audit
        self.engine = PolicyEngine(self.policy)
        self.capability_router = (
            capability_router if capability_router is not None else CapabilityRouter.build(escalation=escalation)
        )
        self.dispatcher = (
            dispatcher
            if dispatcher is not None
            else DispositionRouter(vault=vault if vault is not None else TokenVault(audit=audit), hash_salt=hash_salt)
        )
        # Read the vault back off the dispatcher rather than keeping a second
        # reference: a guard whose `restore` looks in a different vault than its
        # tokeniser wrote to would fail silently, one round trip later.
        self.vault = self.dispatcher.vault
        self.detector_agent = QuarantinedDetectorAgent(self.capability_router, audit=audit)
        self.guard_agent = PrivilegedGuardAgent(self.engine, self.dispatcher, audit=audit)
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
        if self.audit is not None:
            self.audit.record(
                Channel.C1_INGRESS,
                component="SensitiveGuard",
                ref=sealed.ref,
                payload_bytes=len(sealed),
                carries_raw=True,
                note=f"sealed from origin={sealed.origin}",
                destination=destination,
            )
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

    def with_audit(self, audit: AuditBus) -> SensitiveGuard:
        """A guard with the same policy and detectors, recording onto ``audit``.

        One bus per run, so a benchmark can ask where a value went in *this*
        episode without every other episode's crossings in the way. The vault is
        rebuilt with it rather than shared: a vault outliving the run it belongs
        to is a mapping nobody is watching any more.
        """

        vault = TokenVault(audit=audit)
        # Everything but the tokeniser is stateless and can be carried over,
        # salts included so hashed keys stay comparable across runs. The
        # tokeniser holds the vault, so it is the one that has to be rebound —
        # a handler still writing into the previous vault would tokenise into a
        # mapping this guard's `restore` cannot read.
        handlers = dict(self.dispatcher.handlers)
        handlers[Action.TOKENIZE] = TokenizeHandler(vault)
        return SensitiveGuard(
            policy=self.policy,
            capability_router=self.capability_router,
            dispatcher=DispositionRouter(vault=vault, handlers=handlers),
            reviewer=self.reviewer,
            review_output=self.review_output,
            audit=audit,
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
