"""Basic aggregate metrics derived from safe audit events."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .event import AuditEvent


@dataclass(frozen=True, slots=True)
class AuditMetrics:
    total_events: int
    unique_runs: int
    unique_destinations: int
    status_counts: dict[str, int]
    event_type_counts: dict[str, int]
    stage_counts: dict[str, int]
    label_counts: dict[str, int]
    policy_action_counts: dict[str, int]
    total_risk: float
    maximum_event_risk: float
    block_rate: float
    transformation_rate: float
    approval_rate: float

    def to_dict(self) -> dict[str, object]:
        return {
            "total_events": self.total_events,
            "unique_runs": self.unique_runs,
            "unique_destinations": self.unique_destinations,
            "status_counts": dict(self.status_counts),
            "event_type_counts": dict(self.event_type_counts),
            "stage_counts": dict(self.stage_counts),
            "label_counts": dict(self.label_counts),
            "policy_action_counts": dict(self.policy_action_counts),
            "total_risk": self.total_risk,
            "maximum_event_risk": self.maximum_event_risk,
            "block_rate": self.block_rate,
            "transformation_rate": self.transformation_rate,
            "approval_rate": self.approval_rate,
        }


def compute_metrics(events: Iterable[AuditEvent]) -> AuditMetrics:
    values = tuple(events)
    status_counts = Counter(event.status for event in values)
    event_type_counts = Counter(event.event_type for event in values)
    stage_counts = Counter(event.stage for event in values if event.stage is not None)
    label_counts = Counter(label for event in values for label in event.sensitive_labels)
    policy_action_counts: Counter[str] = Counter()
    for event in values:
        if not event.decisions:
            continue
        for decision in event.decisions.get("decisions", ()):
            if isinstance(decision, Mapping) and isinstance(decision.get("decision"), str):
                policy_action_counts[decision["decision"]] += 1

    total = len(values)
    total_risk = math.fsum(max(0.0, event.risk) for event in values)
    return AuditMetrics(
        total_events=total,
        unique_runs=len({event.run_id for event in values}),
        unique_destinations=len({event.destination for event in values if event.destination is not None}),
        status_counts=dict(sorted(status_counts.items())),
        event_type_counts=dict(sorted(event_type_counts.items())),
        stage_counts=dict(sorted(stage_counts.items())),
        label_counts=dict(sorted(label_counts.items())),
        policy_action_counts=dict(sorted(policy_action_counts.items())),
        total_risk=total_risk,
        maximum_event_risk=max((event.risk for event in values), default=0.0),
        block_rate=(status_counts.get("BLOCKED", 0) / total if total else 0.0),
        transformation_rate=(status_counts.get("TRANSFORMED", 0) / total if total else 0.0),
        approval_rate=(status_counts.get("APPROVAL_REQUIRED", 0) / total if total else 0.0),
    )
