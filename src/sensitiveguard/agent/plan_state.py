"""Small serializable state model for guarded plans."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PlanState:
    required_data: tuple[str, ...] = ()
    acquired_artifacts: list[str] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    blocked_steps: list[dict[str, str]] = field(default_factory=list)

    def mark_completed(self, step: str) -> None:
        self.completed_steps.append(step)

    def mark_blocked(self, step: str, reason: str) -> None:
        self.blocked_steps.append({"step": step, "reason": reason})

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_data": list(self.required_data),
            "acquired_artifacts": list(self.acquired_artifacts),
            "completed_steps": list(self.completed_steps),
            "blocked_steps": list(self.blocked_steps),
        }
