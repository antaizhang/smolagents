"""Trajectory report construction."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .event import AuditEvent
from .metrics import AuditMetrics, compute_metrics


@dataclass(frozen=True, slots=True)
class TrajectoryReport:
    run_id: str
    event_count: int
    first_timestamp: float | None
    last_timestamp: float | None
    events: tuple[AuditEvent, ...]
    metrics: AuditMetrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "event_count": self.event_count,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "events": [event.to_dict() for event in self.events],
            "metrics": self.metrics.to_dict(),
        }


def build_trajectory_report(events: Iterable[AuditEvent], run_id: str) -> TrajectoryReport:
    if not run_id:
        raise ValueError("run_id must not be empty")
    selected = tuple(sorted((event for event in events if event.run_id == run_id), key=lambda event: event.step_id))
    return TrajectoryReport(
        run_id=run_id,
        event_count=len(selected),
        first_timestamp=selected[0].timestamp if selected else None,
        last_timestamp=selected[-1].timestamp if selected else None,
        events=selected,
        metrics=compute_metrics(selected),
    )
