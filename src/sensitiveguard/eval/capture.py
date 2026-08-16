"""Run instrumentation shared by every benchmark baseline.

Scoring needs two things the production runtime deliberately does not publish:
the raw value behind each policy decision, and the time spent inside the privacy
layer. Both are collected here, in the harness, rather than by widening the
audit surface — the shipped audit log stays scrubbed.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from sensitiveguard.models import Action, DecisionSet, DetectionResult, GuardStage


EGRESS_STAGES: frozenset[GuardStage] = frozenset(
    {
        GuardStage.DATA_ACQUISITION,
        GuardStage.TOOL_INPUT,
        GuardStage.FINAL_OUTPUT,
        GuardStage.HANDOFF,
        GuardStage.MCP_INPUT,
    }
)


class LatencyProbe:
    """Accumulate per-boundary privacy-layer durations in milliseconds.

    Tool bodies and model calls are excluded on purpose: the reported figure is
    the overhead the guard adds, not the cost of the work it protects. A baseline
    with no privacy layer records no samples, which the metrics layer reports as
    a p95 of zero rather than as a missing value.
    """

    def __init__(self) -> None:
        self._samples: list[float] = []

    @contextmanager
    def measure(self) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self._samples.append((time.perf_counter() - start) * 1000.0)

    @property
    def samples_ms(self) -> tuple[float, ...]:
        return tuple(self._samples)

    def __len__(self) -> int:
        return len(self._samples)


@dataclass(frozen=True, slots=True)
class ObservedDecision:
    """The action a baseline actually applied to one concrete raw value."""

    value: str
    label: str
    action: Action
    stage: GuardStage | None = None
    destination: str | None = None

    @property
    def is_egress(self) -> bool:
        return self.stage is None or self.stage in EGRESS_STAGES

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "action": self.action.value,
            "stage": self.stage.value if self.stage else None,
            "destination": self.destination,
        }


@dataclass(slots=True)
class BaselineCapture:
    """Everything a baseline observed about the values it handled."""

    probe: LatencyProbe = field(default_factory=LatencyProbe)
    decisions: list[ObservedDecision] = field(default_factory=list)
    detected_values: set[str] = field(default_factory=set)

    def note_detection(self, detection: DetectionResult) -> None:
        for finding in detection.findings:
            if finding.value:
                self.detected_values.add(finding.value)

    def note_decisions(
        self,
        decisions: DecisionSet,
        *,
        stage: GuardStage | None = None,
        destination: str | None = None,
    ) -> None:
        for decision in decisions.decisions:
            value = decision.finding.value
            if not value:
                continue
            self.detected_values.add(value)
            self.decisions.append(
                ObservedDecision(
                    value=value,
                    label=decision.finding.label,
                    action=decision.action,
                    stage=stage,
                    destination=destination,
                )
            )

    def action_for(self, value: str) -> Action | None:
        """Resolve the action applied to ``value``, preferring egress boundaries.

        A value can be judged more than once during a run — once when it is
        written to memory and again when it crosses a trust boundary. The
        boundary-crossing judgement is the one the benchmark grades, because it
        is the one that determines disclosure.
        """

        matching = [decision for decision in self.decisions if decision.value == value]
        if not matching:
            return None
        egress = [decision for decision in matching if decision.is_egress]
        return (egress or matching)[-1].action


class RecordingDetector:
    """Proxy a detector so findings made outside the guard path are still counted.

    Scan tools call the detector directly rather than through ``guard_*``. Without
    this wrapper their findings would be invisible to the scorer and a runtime
    would be scored as missing entities it actually detected.
    """

    def __init__(self, detector: Any, capture: BaselineCapture) -> None:
        self._detector = detector
        self._capture = capture

    @property
    def name(self) -> str:
        return getattr(self._detector, "name", "detector")

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        with self._capture.probe.measure():
            detection = self._detector.detect(content, context=context)
        self._capture.note_detection(detection)
        return detection

    def __getattr__(self, name: str) -> Any:
        return getattr(self._detector, name)


class RecordingGateway:
    """Proxy a ``SafeToolGateway``, timing and capturing its guard decisions."""

    def __init__(self, gateway: Any, capture: BaselineCapture) -> None:
        self._gateway = gateway
        self._capture = capture

    def _guard(self, method_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        stage = kwargs.get("stage")
        if stage is None and len(args) >= 3:
            stage = args[2]
        with self._capture.probe.measure():
            result = getattr(self._gateway, method_name)(*args, **kwargs)
        # The detector proxy already counted these findings; noting them again
        # is harmless because ``detected_values`` is a set.
        self._capture.note_detection(result.detection)
        self._capture.note_decisions(
            result.decisions,
            stage=stage if isinstance(stage, GuardStage) else None,
            destination=kwargs.get("destination"),
        )
        return result

    def guard_text(self, *args: Any, **kwargs: Any) -> Any:
        return self._guard("guard_text", args, kwargs)

    def guard_payload(self, *args: Any, **kwargs: Any) -> Any:
        return self._guard("guard_payload", args, kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._gateway, name)


__all__ = [
    "EGRESS_STAGES",
    "BaselineCapture",
    "LatencyProbe",
    "ObservedDecision",
    "RecordingDetector",
    "RecordingGateway",
]
