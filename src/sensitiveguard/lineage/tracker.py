"""Thread-safe, run-isolated lineage tracking with no raw-payload retention."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from threading import RLock
from typing import Any

from .models import (
    ArtifactNode,
    ArtifactRole,
    GuardLineageRecord,
    InvalidOperationTransition,
    LineageEvent,
    LineageEventType,
    LineageReport,
    OperationStatus,
    RunIsolationError,
    UnknownArtifactError,
    UnknownOperationError,
)


_GENESIS_HASH = "0" * 64
_SAFE_LABEL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_KNOWN_STAGES = frozenset(
    {
        "data_acquisition",
        "tool_input",
        "tool_output",
        "memory",
        "final_output",
        "handoff",
        "mcp_input",
        "mcp_output",
        "operation",
        "unknown",
    }
)
_KNOWN_GUARD_STATUSES = frozenset({"ALLOWED", "TRANSFORMED", "BLOCKED", "APPROVAL_REQUIRED", "UNKNOWN"})
_KNOWN_LABELS = frozenset(
    {
        "ACCESS_TOKEN",
        "ADDRESS",
        "API_KEY",
        "BANKACCOUNT",
        "CLOUD_SECRET",
        "DATABASE_PASSWORD",
        "DRIVERID",
        "EMAIL",
        "FAX",
        "FINACCOUNT",
        "HEALTHCARD",
        "IDCARD",
        "IMEI",
        "IMSI",
        "INSURANCEID",
        "IPV4",
        "IPV6",
        "JWT",
        "LICENSEPLATE",
        "MAC",
        "MEID",
        "MILITARYID",
        "MOBILE",
        "NAME",
        "OUTPATIENTID",
        "PASSPORTID",
        "PASSWD",
        "PATIENTID",
        "PRIVATE_KEY",
        "PROMPT_INJECTION",
        "RESIDENCEID",
        "SOCIALID",
        "TAXID",
        "TEL",
        "VIN",
        "VISAAUTH",
    }
)


@dataclass(frozen=True, slots=True)
class _PayloadFingerprints:
    artifact: str
    leaves: tuple[str, ...]
    subtrees: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FindingDatum:
    label: str
    value: str


@dataclass(frozen=True, slots=True)
class _OperationState:
    operation_id: str
    run_ref: str
    status: OperationStatus
    input_artifact_ids: tuple[str, ...]
    prepared_event_id: str
    terminal_event_id: str | None
    stage: str
    operation_ref: str
    tool_ref: str | None
    destination_ref: str | None


class LineageTracker:
    """Track guarded artifacts and side-effect operations using keyed HMACs.

    The tracker retains only typed metadata, opaque identifiers and keyed HMAC
    fingerprints. Raw payloads are canonicalized transiently and are never
    assigned to an instance attribute, node, event or report.
    """

    def __init__(self, key: bytes | None = None, *, clock: Any = time.time) -> None:
        hmac_key = key if key is not None else secrets.token_bytes(32)
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 16:
            raise ValueError("LineageTracker key must contain at least 16 bytes")
        if not callable(clock):
            raise TypeError("LineageTracker clock must be callable")
        self._key = hmac_key
        self._clock = clock
        self._lock = RLock()
        self._counter = 0
        self._instance_ref = hmac.new(
            self._key,
            b"lineage-instance\0" + secrets.token_bytes(16),
            hashlib.sha256,
        ).hexdigest()[:16]

        self._nodes: dict[str, ArtifactNode] = {}
        self._nodes_by_run: dict[str, list[str]] = {}
        self._events_by_run: dict[str, list[LineageEvent]] = {}
        self._operations: dict[str, _OperationState] = {}

        self._output_artifacts: dict[tuple[str, str], set[str]] = {}
        self._output_leaves: dict[tuple[str, str], set[str]] = {}
        self._entities: dict[tuple[str, str], set[str]] = {}

    def record_guard(
        self,
        input_payload: Any,
        output_payload: Any,
        context: Any,
        stage: Any,
        tool_name: str | None,
        destination: str | None,
        detection: Any,
        decisions: Any,
        status: Any,
    ) -> GuardLineageRecord:
        """Record one Gateway guard without retaining either payload.

        Parent edges are inferred from prior outputs whose whole artifact,
        nested subtree or scalar-leaf HMAC matches this input, and from matching
        entity HMACs. All indexes are scoped by the context's run identifier.
        """

        run_ref = self._run_ref(context)
        normalized_stage = self._normalize_stage(stage)
        normalized_status = self._normalize_guard_status(status)
        tool_ref = self._opaque_ref("tool", run_ref, tool_name)
        destination_ref = self._opaque_ref("destination", run_ref, destination)

        input_fingerprints = self._payload_fingerprints(input_payload, run_ref)
        input_labels, input_entities = self._classification(
            input_payload,
            detection,
            decisions,
            run_ref,
            include_declared_labels=True,
        )
        output_is_present = output_payload is not None or normalized_status in {"ALLOWED", "TRANSFORMED"}
        output_fingerprints = self._payload_fingerprints(output_payload, run_ref) if output_is_present else None
        output_labels: tuple[str, ...] = ()
        output_entities: tuple[str, ...] = ()
        if output_is_present:
            output_labels, output_entities = self._classification(
                output_payload,
                detection,
                decisions,
                run_ref,
                include_declared_labels=False,
            )

        with self._lock:
            inferred = self._infer_parents_locked(run_ref, input_fingerprints, input_entities)
            input_node = self._create_node_locked(
                run_ref=run_ref,
                role=ArtifactRole.INPUT,
                fingerprints=input_fingerprints,
                entity_fingerprints=input_entities,
                parent_ids=inferred,
                labels=input_labels,
                stage=normalized_stage,
                tool_ref=tool_ref,
                destination_ref=destination_ref,
            )

            output_node = None
            if output_fingerprints is not None:
                output_parents = self._infer_parents_locked(
                    run_ref,
                    output_fingerprints,
                    output_entities,
                    explicit_parent_ids=(input_node.artifact_id,),
                )
                output_node = self._create_node_locked(
                    run_ref=run_ref,
                    role=ArtifactRole.OUTPUT,
                    fingerprints=output_fingerprints,
                    entity_fingerprints=output_entities,
                    parent_ids=output_parents,
                    labels=output_labels,
                    stage=normalized_stage,
                    tool_ref=tool_ref,
                    destination_ref=destination_ref,
                )

            operation_id = self._new_id_locked("operation")
            event = self._append_event_locked(
                run_ref=run_ref,
                operation_id=operation_id,
                event_type=LineageEventType.GUARD,
                status=normalized_status,
                input_ids=(input_node.artifact_id,),
                output_ids=(output_node.artifact_id,) if output_node is not None else (),
                stage=normalized_stage,
                operation_ref=self._opaque_ref("operation", run_ref, "guard"),
                tool_ref=tool_ref,
                destination_ref=destination_ref,
                transition_from=None,
            )
            return GuardLineageRecord(input_node, output_node, event)

    def prepare_operation(
        self,
        input_payload: Any,
        context: Any,
        *,
        operation_name: str = "operation",
        stage: Any = "operation",
        tool_name: str | None = None,
        destination: str | None = None,
        detection: Any = None,
        decisions: Any = None,
        parent_ids: Iterable[str] = (),
    ) -> LineageEvent:
        """Write a PREPARED event before a side effect is attempted."""

        run_ref = self._run_ref(context)
        normalized_stage = self._normalize_stage(stage)
        operation_ref = self._opaque_ref("operation", run_ref, operation_name)
        assert operation_ref is not None
        tool_ref = self._opaque_ref("tool", run_ref, tool_name)
        destination_ref = self._opaque_ref("destination", run_ref, destination)
        fingerprints = self._payload_fingerprints(input_payload, run_ref)
        labels, entities = self._classification(
            input_payload,
            detection,
            decisions,
            run_ref,
            include_declared_labels=True,
        )

        with self._lock:
            parents = self._infer_parents_locked(
                run_ref,
                fingerprints,
                entities,
                explicit_parent_ids=tuple(parent_ids),
            )
            input_node = self._create_node_locked(
                run_ref=run_ref,
                role=ArtifactRole.INPUT,
                fingerprints=fingerprints,
                entity_fingerprints=entities,
                parent_ids=parents,
                labels=labels,
                stage=normalized_stage,
                tool_ref=tool_ref,
                destination_ref=destination_ref,
            )
            operation_id = self._new_id_locked("operation")
            event = self._append_event_locked(
                run_ref=run_ref,
                operation_id=operation_id,
                event_type=LineageEventType.OPERATION,
                status=OperationStatus.PREPARED.value,
                input_ids=(input_node.artifact_id,),
                output_ids=(),
                stage=normalized_stage,
                operation_ref=operation_ref,
                tool_ref=tool_ref,
                destination_ref=destination_ref,
                transition_from=None,
            )
            self._operations[operation_id] = _OperationState(
                operation_id=operation_id,
                run_ref=run_ref,
                status=OperationStatus.PREPARED,
                input_artifact_ids=(input_node.artifact_id,),
                prepared_event_id=event.event_id,
                terminal_event_id=None,
                stage=normalized_stage,
                operation_ref=operation_ref,
                tool_ref=tool_ref,
                destination_ref=destination_ref,
            )
            return event

    def commit_operation(
        self,
        operation_id: str,
        output_payload: Any,
        *,
        context: Any | None = None,
        detection: Any = None,
        decisions: Any = None,
    ) -> LineageEvent:
        """Transition exactly one PREPARED operation to COMMITTED."""

        with self._lock:
            state = self._require_prepared_operation_locked(operation_id, context)
            fingerprints = self._payload_fingerprints(output_payload, state.run_ref)
            labels, entities = self._classification(
                output_payload,
                detection,
                decisions,
                state.run_ref,
                include_declared_labels=True,
            )
            parents = self._infer_parents_locked(
                state.run_ref,
                fingerprints,
                entities,
                explicit_parent_ids=state.input_artifact_ids,
            )
            output_node = self._create_node_locked(
                run_ref=state.run_ref,
                role=ArtifactRole.OUTPUT,
                fingerprints=fingerprints,
                entity_fingerprints=entities,
                parent_ids=parents,
                labels=labels,
                stage=state.stage,
                tool_ref=state.tool_ref,
                destination_ref=state.destination_ref,
            )
            event = self._append_event_locked(
                run_ref=state.run_ref,
                operation_id=operation_id,
                event_type=LineageEventType.OPERATION,
                status=OperationStatus.COMMITTED.value,
                input_ids=state.input_artifact_ids,
                output_ids=(output_node.artifact_id,),
                stage=state.stage,
                operation_ref=state.operation_ref,
                tool_ref=state.tool_ref,
                destination_ref=state.destination_ref,
                transition_from=state.prepared_event_id,
            )
            self._operations[operation_id] = replace(
                state,
                status=OperationStatus.COMMITTED,
                terminal_event_id=event.event_id,
            )
            return event

    def abort_operation(self, operation_id: str, *, context: Any | None = None) -> LineageEvent:
        """Transition exactly one PREPARED operation to ABORTED."""

        return self._finish_without_output(operation_id, OperationStatus.ABORTED, context=context)

    def mark_indeterminate(self, operation_id: str, *, context: Any | None = None) -> LineageEvent:
        """Mark a prepared operation whose external outcome cannot be proven."""

        return self._finish_without_output(operation_id, OperationStatus.INDETERMINATE, context=context)

    def recover_incomplete(self, context: Any | None = None) -> tuple[LineageEvent, ...]:
        """Conservatively mark all selected PREPARED operations INDETERMINATE."""

        run_ref = self._run_ref(context) if context is not None else None
        with self._lock:
            operation_ids = tuple(
                sorted(
                    operation_id
                    for operation_id, state in self._operations.items()
                    if state.status is OperationStatus.PREPARED and (run_ref is None or state.run_ref == run_ref)
                )
            )
            return tuple(
                self._finish_without_output_locked(
                    operation_id,
                    OperationStatus.INDETERMINATE,
                    expected_run_ref=run_ref,
                )
                for operation_id in operation_ids
            )

    mark_incomplete_as_indeterminate = recover_incomplete

    def get_node(self, artifact_id: str, context: Any | None = None) -> ArtifactNode:
        with self._lock:
            node = self._nodes.get(artifact_id)
            if node is None:
                raise UnknownArtifactError("The lineage artifact does not exist.")
            self._assert_context_run(node.run_ref, context)
            return node

    def ancestors(self, artifact_id: str, context: Any | None = None) -> tuple[ArtifactNode, ...]:
        """Return ancestors in parent-before-child order, excluding the node."""

        with self._lock:
            node = self._nodes.get(artifact_id)
            if node is None:
                raise UnknownArtifactError("The lineage artifact does not exist.")
            self._assert_context_run(node.run_ref, context)
            ordered: list[ArtifactNode] = []
            visited: set[str] = set()

            def visit(parent_id: str) -> None:
                if parent_id in visited:
                    return
                parent = self._nodes.get(parent_id)
                if parent is None or parent.run_ref != node.run_ref:
                    raise RunIsolationError("The lineage graph contains an invalid cross-run parent.")
                for grandparent_id in parent.parent_ids:
                    visit(grandparent_id)
                visited.add(parent_id)
                ordered.append(parent)

            for direct_parent_id in node.parent_ids:
                visit(direct_parent_id)
            return tuple(ordered)

    def events(self, context: Any) -> tuple[LineageEvent, ...]:
        run_ref = self._run_ref(context)
        with self._lock:
            return tuple(self._events_by_run.get(run_ref, ()))

    def nodes(self, context: Any) -> tuple[ArtifactNode, ...]:
        run_ref = self._run_ref(context)
        with self._lock:
            return tuple(self._nodes[node_id] for node_id in self._nodes_by_run.get(run_ref, ()))

    def report(self, context: Any) -> LineageReport:
        run_ref = self._run_ref(context)
        with self._lock:
            nodes = tuple(self._nodes[node_id] for node_id in self._nodes_by_run.get(run_ref, ()))
            events = tuple(self._events_by_run.get(run_ref, ()))
            operation_states = tuple(
                sorted(
                    (operation_id, state.status.value)
                    for operation_id, state in self._operations.items()
                    if state.run_ref == run_ref
                )
            )
            tainted = tuple(node.artifact_id for node in nodes if node.prompt_injection_tainted)
            return LineageReport(
                run_ref=run_ref,
                nodes=nodes,
                events=events,
                operation_states=operation_states,
                tainted_artifact_ids=tainted,
                chain_valid=self._verify_chain_locked(run_ref),
            )

    def verify_chain(self, context: Any) -> bool:
        run_ref = self._run_ref(context)
        with self._lock:
            return self._verify_chain_locked(run_ref)

    def _finish_without_output(
        self,
        operation_id: str,
        status: OperationStatus,
        *,
        context: Any | None,
    ) -> LineageEvent:
        expected_run_ref = self._run_ref(context) if context is not None else None
        with self._lock:
            return self._finish_without_output_locked(
                operation_id,
                status,
                expected_run_ref=expected_run_ref,
            )

    def _finish_without_output_locked(
        self,
        operation_id: str,
        status: OperationStatus,
        *,
        expected_run_ref: str | None,
    ) -> LineageEvent:
        if status not in {OperationStatus.ABORTED, OperationStatus.INDETERMINATE}:
            raise ValueError("Only no-output terminal operation statuses are supported here")
        state = self._operations.get(operation_id)
        if state is None:
            raise UnknownOperationError("The lineage operation does not exist.")
        if expected_run_ref is not None and state.run_ref != expected_run_ref:
            raise RunIsolationError("The lineage operation belongs to a different run.")
        if state.status is not OperationStatus.PREPARED:
            raise InvalidOperationTransition("Only a PREPARED lineage operation can transition.")
        event = self._append_event_locked(
            run_ref=state.run_ref,
            operation_id=operation_id,
            event_type=LineageEventType.OPERATION,
            status=status.value,
            input_ids=state.input_artifact_ids,
            output_ids=(),
            stage=state.stage,
            operation_ref=state.operation_ref,
            tool_ref=state.tool_ref,
            destination_ref=state.destination_ref,
            transition_from=state.prepared_event_id,
        )
        self._operations[operation_id] = replace(
            state,
            status=status,
            terminal_event_id=event.event_id,
        )
        return event

    def _require_prepared_operation_locked(self, operation_id: str, context: Any | None) -> _OperationState:
        state = self._operations.get(operation_id)
        if state is None:
            raise UnknownOperationError("The lineage operation does not exist.")
        self._assert_context_run(state.run_ref, context)
        if state.status is not OperationStatus.PREPARED:
            raise InvalidOperationTransition("Only a PREPARED lineage operation can transition.")
        return state

    def _assert_context_run(self, expected_run_ref: str, context: Any | None) -> None:
        if context is not None and self._run_ref(context) != expected_run_ref:
            raise RunIsolationError("The lineage object belongs to a different run.")

    def _create_node_locked(
        self,
        *,
        run_ref: str,
        role: ArtifactRole,
        fingerprints: _PayloadFingerprints,
        entity_fingerprints: tuple[str, ...],
        parent_ids: tuple[str, ...],
        labels: tuple[str, ...],
        stage: str,
        tool_ref: str | None,
        destination_ref: str | None,
    ) -> ArtifactNode:
        validated_parents = self._validate_parents_locked(run_ref, parent_ids)
        inherited_taints = {taint for parent_id in validated_parents for taint in self._nodes[parent_id].taints}
        if "PROMPT_INJECTION" in labels:
            inherited_taints.add("PROMPT_INJECTION")
        taints = tuple(sorted(inherited_taints))
        artifact_id = self._new_id_locked("artifact")
        created_at = self._timestamp()
        body = {
            "artifact_id": artifact_id,
            "run_ref": run_ref,
            "role": role.value,
            "artifact_fingerprint": fingerprints.artifact,
            "entity_fingerprints": list(entity_fingerprints),
            "leaf_fingerprints": list(fingerprints.leaves),
            "parent_ids": list(validated_parents),
            "labels": list(labels),
            "taints": list(taints),
            "stage": stage,
            "tool_ref": tool_ref,
            "destination_ref": destination_ref,
            "created_at": created_at,
        }
        node_hash = self._safe_object_hmac("lineage-node", run_ref, body)
        node = ArtifactNode(
            artifact_id=artifact_id,
            run_ref=run_ref,
            role=role,
            artifact_fingerprint=fingerprints.artifact,
            entity_fingerprints=entity_fingerprints,
            leaf_fingerprints=fingerprints.leaves,
            parent_ids=validated_parents,
            labels=labels,
            taints=taints,
            stage=stage,
            tool_ref=tool_ref,
            destination_ref=destination_ref,
            created_at=created_at,
            node_hash=node_hash,
        )
        self._nodes[artifact_id] = node
        self._nodes_by_run.setdefault(run_ref, []).append(artifact_id)
        for entity_fingerprint in node.entity_fingerprints:
            self._entities.setdefault((run_ref, entity_fingerprint), set()).add(artifact_id)
        if role is ArtifactRole.OUTPUT:
            self._output_artifacts.setdefault((run_ref, node.artifact_fingerprint), set()).add(artifact_id)
            for leaf_fingerprint in node.leaf_fingerprints:
                self._output_leaves.setdefault((run_ref, leaf_fingerprint), set()).add(artifact_id)
        return node

    def _infer_parents_locked(
        self,
        run_ref: str,
        fingerprints: _PayloadFingerprints,
        entity_fingerprints: tuple[str, ...],
        *,
        explicit_parent_ids: Iterable[str] = (),
    ) -> tuple[str, ...]:
        parent_ids = set(explicit_parent_ids)
        for subtree_fingerprint in fingerprints.subtrees:
            parent_ids.update(self._output_artifacts.get((run_ref, subtree_fingerprint), ()))
        for leaf_fingerprint in fingerprints.leaves:
            parent_ids.update(self._output_leaves.get((run_ref, leaf_fingerprint), ()))
        for entity_fingerprint in entity_fingerprints:
            parent_ids.update(self._entities.get((run_ref, entity_fingerprint), ()))
        return self._validate_parents_locked(run_ref, parent_ids)

    def _validate_parents_locked(self, run_ref: str, parent_ids: Iterable[str]) -> tuple[str, ...]:
        validated: set[str] = set()
        for parent_id in parent_ids:
            parent = self._nodes.get(parent_id)
            if parent is None:
                raise UnknownArtifactError("A lineage parent artifact does not exist.")
            if parent.run_ref != run_ref:
                raise RunIsolationError("Cross-run lineage parent edges are forbidden.")
            validated.add(parent_id)
        return tuple(sorted(validated))

    def _append_event_locked(
        self,
        *,
        run_ref: str,
        operation_id: str,
        event_type: LineageEventType,
        status: str,
        input_ids: Iterable[str],
        output_ids: Iterable[str],
        stage: str,
        operation_ref: str | None,
        tool_ref: str | None,
        destination_ref: str | None,
        transition_from: str | None,
    ) -> LineageEvent:
        input_artifact_ids = tuple(input_ids)
        output_artifact_ids = tuple(output_ids)
        referenced_nodes = tuple(
            self._require_event_node_locked(run_ref, artifact_id)
            for artifact_id in (*input_artifact_ids, *output_artifact_ids)
        )
        input_nodes = referenced_nodes[: len(input_artifact_ids)]
        output_nodes = referenced_nodes[len(input_artifact_ids) :]
        labels = tuple(sorted({label for node in referenced_nodes for label in node.labels}))
        taints = tuple(sorted({taint for node in referenced_nodes for taint in node.taints}))
        run_events = self._events_by_run.setdefault(run_ref, [])
        sequence = len(run_events) + 1
        previous_hash = run_events[-1].event_hash if run_events else _GENESIS_HASH
        event_id = self._new_id_locked("event")
        timestamp = self._timestamp()
        body = {
            "event_id": event_id,
            "operation_id": operation_id,
            "run_ref": run_ref,
            "sequence": sequence,
            "event_type": event_type.value,
            "status": status,
            "input_artifact_ids": list(input_artifact_ids),
            "output_artifact_ids": list(output_artifact_ids),
            "input_node_hashes": [node.node_hash for node in input_nodes],
            "output_node_hashes": [node.node_hash for node in output_nodes],
            "labels": list(labels),
            "taints": list(taints),
            "stage": stage,
            "operation_ref": operation_ref,
            "tool_ref": tool_ref,
            "destination_ref": destination_ref,
            "transition_from": transition_from,
            "timestamp": timestamp,
            "previous_hash": previous_hash,
        }
        event_hash = self._safe_object_hmac("lineage-event", run_ref, body)
        event = LineageEvent(
            event_id=event_id,
            operation_id=operation_id,
            run_ref=run_ref,
            sequence=sequence,
            event_type=event_type,
            status=status,
            input_artifact_ids=input_artifact_ids,
            output_artifact_ids=output_artifact_ids,
            input_node_hashes=tuple(node.node_hash for node in input_nodes),
            output_node_hashes=tuple(node.node_hash for node in output_nodes),
            labels=labels,
            taints=taints,
            stage=stage,
            operation_ref=operation_ref,
            tool_ref=tool_ref,
            destination_ref=destination_ref,
            transition_from=transition_from,
            timestamp=timestamp,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        run_events.append(event)
        return event

    def _require_event_node_locked(self, run_ref: str, artifact_id: str) -> ArtifactNode:
        node = self._nodes.get(artifact_id)
        if node is None:
            raise UnknownArtifactError("An event artifact does not exist.")
        if node.run_ref != run_ref:
            raise RunIsolationError("An event cannot reference an artifact from another run.")
        return node

    def _verify_chain_locked(self, run_ref: str) -> bool:
        try:
            nodes = tuple(self._nodes[node_id] for node_id in self._nodes_by_run.get(run_ref, ()))
            for node in nodes:
                if node.run_ref != run_ref:
                    return False
                for parent_id in node.parent_ids:
                    parent = self._nodes.get(parent_id)
                    if parent is None or parent.run_ref != run_ref:
                        return False
                    if not set(parent.taints).issubset(node.taints):
                        return False
                if "PROMPT_INJECTION" in node.labels and "PROMPT_INJECTION" not in node.taints:
                    return False
                if not hmac.compare_digest(node.node_hash, self._expected_node_hash(node)):
                    return False

            events = tuple(self._events_by_run.get(run_ref, ()))
            previous_hash = _GENESIS_HASH
            prepared: dict[str, LineageEvent] = {}
            terminal: set[str] = set()
            referenced_artifacts: set[str] = set()
            for expected_sequence, event in enumerate(events, start=1):
                if event.run_ref != run_ref or event.sequence != expected_sequence:
                    return False
                if event.previous_hash != previous_hash:
                    return False
                input_nodes = tuple(
                    self._require_event_node_locked(run_ref, artifact_id) for artifact_id in event.input_artifact_ids
                )
                output_nodes = tuple(
                    self._require_event_node_locked(run_ref, artifact_id) for artifact_id in event.output_artifact_ids
                )
                if event.input_node_hashes != tuple(node.node_hash for node in input_nodes):
                    return False
                if event.output_node_hashes != tuple(node.node_hash for node in output_nodes):
                    return False
                event_nodes = (*input_nodes, *output_nodes)
                if event.labels != tuple(sorted({label for node in event_nodes for label in node.labels})):
                    return False
                if event.taints != tuple(sorted({taint for node in event_nodes for taint in node.taints})):
                    return False
                if not hmac.compare_digest(event.event_hash, self._expected_event_hash(event)):
                    return False
                referenced_artifacts.update(event.input_artifact_ids)
                referenced_artifacts.update(event.output_artifact_ids)

                if event.event_type is LineageEventType.OPERATION:
                    if event.status == OperationStatus.PREPARED.value:
                        if event.operation_id in prepared:
                            return False
                        prepared[event.operation_id] = event
                    elif event.status in {
                        OperationStatus.COMMITTED.value,
                        OperationStatus.ABORTED.value,
                        OperationStatus.INDETERMINATE.value,
                    }:
                        preparation = prepared.get(event.operation_id)
                        if preparation is None or event.operation_id in terminal:
                            return False
                        if event.transition_from != preparation.event_id:
                            return False
                        terminal.add(event.operation_id)
                    else:
                        return False
                previous_hash = event.event_hash
            return referenced_artifacts == {node.artifact_id for node in nodes}
        except Exception:
            return False

    def _expected_node_hash(self, node: ArtifactNode) -> str:
        body = node.to_dict()
        body.pop("node_hash", None)
        return self._safe_object_hmac("lineage-node", node.run_ref, body)

    def _expected_event_hash(self, event: LineageEvent) -> str:
        body = event.to_dict()
        body.pop("event_hash", None)
        return self._safe_object_hmac("lineage-event", event.run_ref, body)

    def _payload_fingerprints(self, payload: Any, run_ref: str) -> _PayloadFingerprints:
        artifact = self._payload_hmac("artifact", run_ref, payload)
        leaf_fingerprints = {self._payload_hmac("leaf", run_ref, leaf) for leaf in self._iter_leaves(payload)}
        subtree_fingerprints = {
            self._payload_hmac("artifact", run_ref, subtree) for subtree in self._iter_subtrees(payload)
        }
        return _PayloadFingerprints(
            artifact=artifact,
            leaves=tuple(sorted(leaf_fingerprints)),
            subtrees=tuple(sorted(subtree_fingerprints)),
        )

    def _classification(
        self,
        payload: Any,
        detection: Any,
        decisions: Any,
        run_ref: str,
        *,
        include_declared_labels: bool,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        labels: set[str] = set()
        entities: set[str] = set()
        for datum in self._finding_data(detection, decisions, run_ref):
            present = bool(datum.value) and self._payload_contains(payload, datum.value)
            if include_declared_labels or present:
                labels.add(datum.label)
            if present:
                entity_material = json.dumps(
                    [datum.label, datum.value],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                entities.add(self._run_scoped_hmac("entity", run_ref, entity_material))
        return tuple(sorted(labels)), tuple(sorted(entities))

    def _finding_data(self, detection: Any, decisions: Any, run_ref: str) -> tuple[_FindingDatum, ...]:
        values: set[tuple[str, str]] = set()

        def add_finding(finding: Any) -> None:
            if finding is None:
                return
            if isinstance(finding, Mapping):
                label_value = finding.get("label")
                raw_value = finding.get("value", "")
            else:
                label_value = getattr(finding, "label", None)
                raw_value = getattr(finding, "value", "")
            if label_value is None:
                return
            label = self._normalize_label(label_value, run_ref)
            value = raw_value if isinstance(raw_value, str) else ""
            values.add((label, value))

        def visit_detection(value: Any) -> None:
            if value is None:
                return
            findings = value.get("findings") if isinstance(value, Mapping) else getattr(value, "findings", None)
            if findings is not None:
                for finding in findings:
                    add_finding(finding)
                return
            if isinstance(value, (tuple, list)):
                for finding in value:
                    add_finding(finding)
                return
            add_finding(value)

        def visit_decisions(value: Any) -> None:
            if value is None:
                return
            items = value.get("decisions") if isinstance(value, Mapping) else getattr(value, "decisions", None)
            if items is None:
                items = value if isinstance(value, (tuple, list)) else (value,)
            for decision in items:
                finding = (
                    decision.get("finding") if isinstance(decision, Mapping) else getattr(decision, "finding", None)
                )
                add_finding(finding)

        visit_detection(detection)
        visit_decisions(decisions)
        return tuple(_FindingDatum(label, value) for label, value in sorted(values))

    def _normalize_label(self, label: Any, run_ref: str) -> str:
        normalized = str(label).strip().upper()
        if normalized in _KNOWN_LABELS and _SAFE_LABEL.fullmatch(normalized):
            return normalized
        reference = self._run_scoped_hmac("label", run_ref, normalized.encode("utf-8"))
        return f"LABEL_REF_{reference.rsplit(':', 1)[-1][:16].upper()}"

    @classmethod
    def _payload_contains(cls, payload: Any, raw_value: str) -> bool:
        if isinstance(payload, str):
            return raw_value in payload
        if isinstance(payload, bytes):
            try:
                return raw_value.encode("utf-8") in payload
            except UnicodeEncodeError:
                return False
        if payload is None or isinstance(payload, bool):
            return False
        if isinstance(payload, (int, float)):
            return str(payload) == raw_value
        if isinstance(payload, Mapping):
            return any(
                raw_value in str(key) or cls._payload_contains(value, raw_value) for key, value in payload.items()
            )
        if isinstance(payload, (list, tuple)):
            return any(cls._payload_contains(value, raw_value) for value in payload)
        return False

    @classmethod
    def _iter_leaves(cls, value: Any) -> Iterable[Any]:
        if isinstance(value, Mapping):
            for key in sorted(value):
                if not isinstance(key, str):
                    raise TypeError("Lineage payload mappings must use string keys")
                yield key
                yield from cls._iter_leaves(value[key])
            return
        if isinstance(value, (list, tuple)):
            for child in value:
                yield from cls._iter_leaves(child)
            return
        yield value

    @classmethod
    def _iter_subtrees(cls, value: Any) -> Iterable[Any]:
        yield value
        if isinstance(value, Mapping):
            for key in sorted(value):
                if not isinstance(key, str):
                    raise TypeError("Lineage payload mappings must use string keys")
                yield key
                yield from cls._iter_subtrees(value[key])
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from cls._iter_subtrees(child)

    def _payload_hmac(self, domain: str, run_ref: str, payload: Any) -> str:
        return self._run_scoped_hmac(domain, run_ref, self._canonical_bytes(payload))

    @classmethod
    def _canonical_bytes(cls, value: Any) -> bytes:
        def normalize(item: Any) -> Any:
            if item is None:
                return ["null"]
            if isinstance(item, bool):
                return ["bool", item]
            if isinstance(item, int):
                return ["int", str(item)]
            if isinstance(item, float):
                if not math.isfinite(item):
                    raise ValueError("Lineage payload numbers must be finite")
                return ["float", item.hex()]
            if isinstance(item, str):
                return ["str", item]
            if isinstance(item, bytes):
                return ["bytes", base64.b64encode(item).decode("ascii")]
            if isinstance(item, Enum):
                return ["enum", normalize(item.value)]
            if isinstance(item, Mapping):
                normalized_items = []
                for key in sorted(item):
                    if not isinstance(key, str):
                        raise TypeError("Lineage payload mappings must use string keys")
                    normalized_items.append([key, normalize(item[key])])
                return ["mapping", normalized_items]
            if isinstance(item, list):
                return ["list", [normalize(child) for child in item]]
            if isinstance(item, tuple):
                return ["tuple", [normalize(child) for child in item]]
            raise TypeError("Lineage payload contains an unsupported value type")

        return json.dumps(
            normalize(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _run_ref(self, context: Any) -> str:
        if isinstance(context, str):
            run_id = context
        elif isinstance(context, Mapping):
            run_id = context.get("run_id")
        else:
            run_id = getattr(context, "run_id", None)
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("A non-empty context run_id is required for lineage tracking")
        digest = hmac.new(
            self._key,
            b"run\0" + run_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def _run_scoped_hmac(self, domain: str, run_ref: str, material: bytes) -> str:
        digest = hmac.new(
            self._key,
            domain.encode("ascii") + b"\0" + run_ref.encode("ascii") + b"\0" + material,
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def _safe_object_hmac(self, domain: str, run_ref: str, value: Mapping[str, Any]) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self._run_scoped_hmac(domain, run_ref, encoded)

    def _opaque_ref(self, domain: str, run_ref: str, value: Any | None) -> str | None:
        if value is None:
            return None
        text = value.value if isinstance(value, Enum) else str(value)
        return self._run_scoped_hmac(domain, run_ref, text.encode("utf-8"))

    @staticmethod
    def _normalize_stage(stage: Any) -> str:
        value = stage.value if isinstance(stage, Enum) else str(stage)
        normalized = value.strip().casefold()
        return normalized if normalized in _KNOWN_STAGES else "unknown"

    @staticmethod
    def _normalize_guard_status(status: Any) -> str:
        value = status.value if isinstance(status, Enum) else str(status)
        normalized = value.strip().upper()
        return normalized if normalized in _KNOWN_GUARD_STATUSES else "UNKNOWN"

    def _new_id_locked(self, kind: str) -> str:
        self._counter += 1
        return f"sgl-{self._instance_ref}-{kind}-{self._counter:020d}"

    def _timestamp(self) -> float:
        value = float(self._clock())
        if not math.isfinite(value):
            raise ValueError("LineageTracker clock returned a non-finite value")
        return value


__all__ = ["LineageTracker"]
