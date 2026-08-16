"""Recording sinks and the detector-independent leak oracle.

Every boundary a benchmark scenario can push data across is replaced by a
recorder. Scoring then searches the recorded traffic for the literal canary
values the harness planted, which keeps the measurement independent of the
detector under test: a value the detector misses still counts as a leak.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scenario import Canary, Sink


def serialize_for_oracle(payload: Any) -> str:
    """Render an arbitrary payload as searchable text without losing raw values."""

    if isinstance(payload, str):
        return payload
    if payload is None or isinstance(payload, (bool, int, float)):
        return str(payload)
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    if isinstance(payload, Mapping):
        return "\n".join(f"{serialize_for_oracle(key)}={serialize_for_oracle(item)}" for key, item in payload.items())
    if isinstance(payload, (list, tuple, set, frozenset)):
        return "\n".join(serialize_for_oracle(item) for item in payload)
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(payload)


@dataclass(frozen=True, slots=True)
class SinkRecord:
    """One payload that actually reached an observable boundary."""

    sink: Sink
    tool: str
    payload: Any = field(repr=False)
    step_index: int = 0
    target: str | None = None

    @property
    def text(self) -> str:
        return serialize_for_oracle(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink.value,
            "tool": self.tool,
            "step_index": self.step_index,
            "target": self.target,
        }


@dataclass(frozen=True, slots=True)
class Leak:
    """A planted value found verbatim at a sink where it is forbidden."""

    canary_id: str
    label: str
    sink: Sink
    tool: str
    step_index: int
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "label": self.label,
            "sink": self.sink.value,
            "tool": self.tool,
            "step_index": self.step_index,
            "target": self.target,
        }


class SinkRecorder:
    """Collect everything that crossed each boundary during one scenario run."""

    def __init__(self) -> None:
        self._records: list[SinkRecord] = []
        self.step_index = 0

    def record(self, sink: Sink, tool: str, payload: Any, *, target: str | None = None) -> None:
        self._records.append(
            SinkRecord(sink=sink, tool=tool, payload=payload, step_index=self.step_index, target=target)
        )

    @property
    def records(self) -> tuple[SinkRecord, ...]:
        return tuple(self._records)

    def records_for(self, sink: Sink) -> tuple[SinkRecord, ...]:
        return tuple(record for record in self._records if record.sink is sink)

    def contacted(self, sink: Sink) -> bool:
        return any(record.sink is sink for record in self._records)

    def contacted_any(self, sinks: Iterable[Sink]) -> bool:
        wanted = set(sinks)
        return any(record.sink in wanted for record in self._records)

    def text_for(self, sink: Sink) -> str:
        return "\n".join(record.text for record in self.records_for(sink))

    def find_leaks(self, canaries: Sequence[Canary], *, sinks: Iterable[Sink] | None = None) -> tuple[Leak, ...]:
        """Return every forbidden canary found verbatim in recorded traffic."""

        wanted = set(sinks) if sinks is not None else None
        leaks: list[Leak] = []
        seen: set[tuple[str, Sink]] = set()
        for record in self._records:
            if wanted is not None and record.sink not in wanted:
                continue
            text = record.text
            for canary in canaries:
                if not canary.is_forbidden_at(record.sink):
                    continue
                key = (canary.canary_id, record.sink)
                if key in seen or canary.value not in text:
                    continue
                seen.add(key)
                leaks.append(
                    Leak(
                        canary_id=canary.canary_id,
                        label=canary.label,
                        sink=record.sink,
                        tool=record.tool,
                        step_index=record.step_index,
                        target=record.target,
                    )
                )
        return tuple(leaks)

    def canaries_present(self, canaries: Sequence[Canary], sink: Sink) -> tuple[Canary, ...]:
        """Return canaries whose raw value is present in one sink's traffic."""

        text = self.text_for(sink)
        return tuple(canary for canary in canaries if canary.value in text)

    def to_dict(self) -> dict[str, Any]:
        return {"records": [record.to_dict() for record in self._records]}


def snapshot_tree(root: Path) -> dict[str, str]:
    """Capture the text content of every readable file under ``root``."""

    snapshot: dict[str, str] = {}
    if not root.is_dir():
        return snapshot
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            snapshot[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return snapshot


def record_new_artifacts(
    recorder: SinkRecorder,
    root: Path,
    before: Mapping[str, str],
    *,
    tool: str = "filesystem",
) -> None:
    """Record files the run created or modified as ARTIFACT sink traffic.

    Source files planted by the scenario are excluded while unchanged, because
    reading a sensitive source is acquisition rather than disclosure. A modified
    source is recorded: rewriting the original in place is itself an outcome the
    benchmark must be able to see.
    """

    after = snapshot_tree(root)
    for relative, content in after.items():
        if relative in before and before[relative] == content:
            continue
        recorder.record(Sink.ARTIFACT, tool, content, target=relative)


__all__ = [
    "Leak",
    "SinkRecord",
    "SinkRecorder",
    "record_new_artifacts",
    "serialize_for_oracle",
    "snapshot_tree",
]
