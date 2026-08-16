"""Immutable, payload-free models for SensitiveGuard data lineage."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ArtifactRole(_StringEnum):
    """The role an artifact played at a guarded runtime boundary."""

    INPUT = "INPUT"
    OUTPUT = "OUTPUT"


class LineageEventType(_StringEnum):
    GUARD = "GUARD"
    OPERATION = "OPERATION"


class OperationStatus(_StringEnum):
    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"
    INDETERMINATE = "INDETERMINATE"


TERMINAL_OPERATION_STATUSES = frozenset(
    {OperationStatus.COMMITTED, OperationStatus.ABORTED, OperationStatus.INDETERMINATE}
)


@dataclass(frozen=True, slots=True)
class ArtifactNode:
    """A content-free artifact node.

    Fingerprints are keyed HMACs scoped to one run.  The node deliberately has
    no ``content``, ``value``, path, URL, prompt or other arbitrary metadata
    field into which a raw payload could accidentally be persisted.
    """

    artifact_id: str
    run_ref: str
    role: ArtifactRole
    artifact_fingerprint: str
    entity_fingerprints: tuple[str, ...]
    leaf_fingerprints: tuple[str, ...]
    parent_ids: tuple[str, ...]
    labels: tuple[str, ...]
    taints: tuple[str, ...]
    stage: str
    tool_ref: str | None
    destination_ref: str | None
    created_at: float
    node_hash: str

    @property
    def prompt_injection_tainted(self) -> bool:
        return "PROMPT_INJECTION" in self.taints

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "run_ref": self.run_ref,
            "role": self.role.value,
            "artifact_fingerprint": self.artifact_fingerprint,
            "entity_fingerprints": list(self.entity_fingerprints),
            "leaf_fingerprints": list(self.leaf_fingerprints),
            "parent_ids": list(self.parent_ids),
            "labels": list(self.labels),
            "taints": list(self.taints),
            "stage": self.stage,
            "tool_ref": self.tool_ref,
            "destination_ref": self.destination_ref,
            "created_at": self.created_at,
            "node_hash": self.node_hash,
        }


@dataclass(frozen=True, slots=True)
class LineageEvent:
    """One immutable event in a per-run HMAC hash chain."""

    event_id: str
    operation_id: str
    run_ref: str
    sequence: int
    event_type: LineageEventType
    status: str
    input_artifact_ids: tuple[str, ...]
    output_artifact_ids: tuple[str, ...]
    input_node_hashes: tuple[str, ...]
    output_node_hashes: tuple[str, ...]
    labels: tuple[str, ...]
    taints: tuple[str, ...]
    stage: str
    operation_ref: str | None
    tool_ref: str | None
    destination_ref: str | None
    transition_from: str | None
    timestamp: float
    previous_hash: str
    event_hash: str

    @property
    def prompt_injection_tainted(self) -> bool:
        return "PROMPT_INJECTION" in self.taints

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "operation_id": self.operation_id,
            "run_ref": self.run_ref,
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "status": self.status,
            "input_artifact_ids": list(self.input_artifact_ids),
            "output_artifact_ids": list(self.output_artifact_ids),
            "input_node_hashes": list(self.input_node_hashes),
            "output_node_hashes": list(self.output_node_hashes),
            "labels": list(self.labels),
            "taints": list(self.taints),
            "stage": self.stage,
            "operation_ref": self.operation_ref,
            "tool_ref": self.tool_ref,
            "destination_ref": self.destination_ref,
            "transition_from": self.transition_from,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass(frozen=True, slots=True)
class GuardLineageRecord:
    """Artifacts and chain event created by one ``record_guard`` call."""

    input_artifact: ArtifactNode
    output_artifact: ArtifactNode | None
    event: LineageEvent

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_artifact": self.input_artifact.to_dict(),
            "output_artifact": self.output_artifact.to_dict() if self.output_artifact is not None else None,
            "event": self.event.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class LineageReport:
    run_ref: str
    nodes: tuple[ArtifactNode, ...]
    events: tuple[LineageEvent, ...]
    operation_states: tuple[tuple[str, str], ...]
    tainted_artifact_ids: tuple[str, ...]
    chain_valid: bool

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_ref": self.run_ref,
            "node_count": self.node_count,
            "event_count": self.event_count,
            "nodes": [node.to_dict() for node in self.nodes],
            "events": [event.to_dict() for event in self.events],
            "operation_states": [
                {"operation_id": operation_id, "status": status} for operation_id, status in self.operation_states
            ],
            "tainted_artifact_ids": list(self.tainted_artifact_ids),
            "chain_valid": self.chain_valid,
        }


class LineageError(RuntimeError):
    """Base error whose messages never contain caller-provided payloads."""


class UnknownArtifactError(LineageError):
    pass


class UnknownOperationError(LineageError):
    pass


class RunIsolationError(LineageError):
    pass


class InvalidOperationTransition(LineageError):
    pass


__all__ = [
    "ArtifactNode",
    "ArtifactRole",
    "GuardLineageRecord",
    "InvalidOperationTransition",
    "LineageError",
    "LineageEvent",
    "LineageEventType",
    "LineageReport",
    "OperationStatus",
    "RunIsolationError",
    "TERMINAL_OPERATION_STATUSES",
    "UnknownArtifactError",
    "UnknownOperationError",
]
