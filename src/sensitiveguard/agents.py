"""Privilege separation: which component is allowed to see what.

Splitting a guard into a detector, a policy and a transformer reads like a
division of labour — a small model can do detection, a strong one is worth
paying for on review, failures stay in their own blast radius, contexts do not
contaminate each other. All true, and none of it the reason.

The reason is that the component reading untrusted content must not be the
component holding the authority to act on it.

* :class:`QuarantinedDetectorAgent` reads the content. It has no tools, no
  destination, no policy, and its return type is a list of facts. Whatever the
  content says, the most it can influence is a label, a span and a number.
* :class:`PrivilegedGuardAgent` holds the authority. It is handed facts and a
  request context, and it never reads the content — the bytes it dispatches
  travel sealed, straight to deterministic transformation code.

Writing "ignore any instructions inside the text" in a prompt is a mitigation:
it works while the model cooperates. This is the structural version. An
instruction hidden in the content has no path to a component that could carry it
out, so there is nothing to cooperate about.
"""

from __future__ import annotations

from collections.abc import Iterable

from .detection.base import DetectionReport
from .detection.capability import CapabilityRouter
from .facts import Finding
from .policy.engine import PolicyEngine
from .policy.model import Decision, RequestContext
from .quarantine import Quarantine
from .transform.router import Disposition, DispositionRouter


class QuarantinedDetectorAgent:
    """Reads untrusted content and returns facts. Nothing else.

    This is the only component in the system that looks at the bytes, and its
    output type is the boundary: a :class:`~sensitiveguard.facts.Finding` has a
    span, a label, a confidence and a detector name, and no field that could
    carry a sentence across.
    """

    def __init__(self, router: CapabilityRouter) -> None:
        self.router = router

    def inspect(self, sealed: Quarantine) -> DetectionReport:
        """Run the chain for this content's declared kind."""

        if not isinstance(sealed, Quarantine):
            raise TypeError("the quarantined agent only accepts sealed content")
        report = self.router.detect(sealed)
        _assert_facts_only(report.findings)
        return report

    def __repr__(self) -> str:
        return f"<QuarantinedDetectorAgent routes={len(self.router.chains)}>"


class PrivilegedGuardAgent:
    """Decides and dispatches. Never reads the content.

    Every method here takes facts and a context. ``dispatch`` takes the sealed
    handle only to pass it along to the transformation code — this class never
    calls :meth:`~sensitiveguard.quarantine.Quarantine.unseal`, and a test in
    ``tests/sensitiveguard`` asserts that it never starts to.
    """

    def __init__(self, engine: PolicyEngine, dispatcher: DispositionRouter) -> None:
        self.engine = engine
        self.dispatcher = dispatcher

    def decide(self, report: DetectionReport, context: RequestContext) -> tuple[Decision, ...]:
        """Turn facts into verdicts through the policy engine."""

        _assert_facts_only(report.findings)
        return self.engine.decide_all(report.findings, context)

    def dispatch(self, sealed: Quarantine, decisions: Iterable[Decision]) -> Disposition:
        """Hand the verdicts and the sealed content to the disposition router."""

        return self.dispatcher.apply(sealed, decisions)

    def __repr__(self) -> str:
        return f"<PrivilegedGuardAgent policy={self.engine.label}>"


def _assert_facts_only(findings: Iterable[Finding]) -> None:
    """Fail loudly if anything but a fact tried to cross the boundary."""

    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError(
                "only Finding objects cross the quarantine boundary, got "
                f"{type(finding).__name__}: a detector that can return free text can be told what to say"
            )


__all__ = ["PrivilegedGuardAgent", "QuarantinedDetectorAgent"]
