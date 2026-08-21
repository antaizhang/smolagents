"""Immutable host manifests for tools exposed to a SensitiveGuard agent."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from threading import RLock
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()


# Capability-name prefixes whose effective route is the internal filesystem.
# The privacy router must classify exactly the same names, otherwise every
# affected call fails review with a route/manifest mismatch, so both layers read
# this tuple instead of duplicating a heuristic.
FILESYSTEM_CAPABILITY_PREFIXES: tuple[str, ...] = (
    "remediate_",
    "safe_read_",
    "sanitize_file",
    "scan_",
    "verify_",
)


def _trusted_tool_profile(tool: Any) -> tuple[str, tuple[str, ...], tuple[str, ...], bool, bool] | None:
    """Read a capability profile attached by trusted host adapter code.

    Third-party benchmark tools keep their native names so native scorers can
    inspect the trajectory. Their route/effect semantics therefore cannot be
    inferred from SensitiveGuard's built-in naming convention. A host adapter
    may attach the five ``sensitiveguard_*`` attributes below before the tool is
    registered. They are covered by the manifest digest and checked again at
    execution time, so a later mutation is rejected as an implementation change.
    """

    operation = getattr(tool, "sensitiveguard_operation", None)
    if operation is None:
        return None
    operation_value = str(operation).strip().lower()
    if not operation_value:
        raise ValueError("sensitiveguard_operation must not be empty")
    effects = tuple(str(item).strip().upper() for item in (getattr(tool, "sensitiveguard_effects", ()) or ()))
    destinations = tuple(
        str(item).strip().casefold() for item in (getattr(tool, "sensitiveguard_destinations", ()) or ()) if str(item).strip()
    )
    side_effect = getattr(tool, "sensitiveguard_side_effect", False)
    explicit = getattr(tool, "sensitiveguard_requires_explicit_intent", True)
    if not isinstance(side_effect, bool) or not isinstance(explicit, bool):
        raise TypeError("trusted tool side-effect and explicit-intent flags must be booleans")
    return operation_value, effects, destinations or ("internal",), side_effect, explicit


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    name: str
    operation: str
    effects: tuple[str, ...]
    destinations: tuple[str, ...]
    side_effect: bool
    requires_explicit_intent: bool
    max_calls_per_run: int = 100
    allow_injection_taint: bool = False
    implementation_digest: str = ""
    schema_digest: str = ""

    def __post_init__(self) -> None:
        name = str(self.name).strip()
        operation = str(self.operation).strip().lower()
        if not name or not operation:
            raise ValueError("Capability name and operation must not be empty")
        if isinstance(self.max_calls_per_run, bool) or self.max_calls_per_run < 1:
            raise ValueError("max_calls_per_run must be a positive integer")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "effects", tuple(sorted({str(item).strip().lower() for item in self.effects})))
        object.__setattr__(
            self,
            "destinations",
            tuple(sorted({str(item).strip().casefold() for item in self.destinations if str(item).strip()})),
        )

    @property
    def digest(self) -> str:
        serialized = {
            "name": self.name,
            "operation": self.operation,
            "effects": self.effects,
            "destinations": self.destinations,
            "side_effect": self.side_effect,
            "requires_explicit_intent": self.requires_explicit_intent,
            "max_calls_per_run": self.max_calls_per_run,
            "allow_injection_taint": self.allow_injection_taint,
            "implementation_digest": self.implementation_digest,
            "schema_digest": self.schema_digest,
        }
        return "manifest_" + hashlib.sha256(_canonical(serialized)).hexdigest()

    @classmethod
    def from_tool(cls, tool: Any) -> "CapabilityManifest":
        """Build a conservative manifest from a host-supplied tool instance."""

        name = str(getattr(tool, "name", "")).strip()
        profile = _trusted_tool_profile(tool) or _profile_for_name(name)
        operation, effects, destinations, side_effect, explicit = profile
        implementation = f"{type(tool).__module__}.{type(tool).__qualname__}"
        implementation_digest = "impl_" + hashlib.sha256(implementation.encode()).hexdigest()
        schema = {
            "inputs": getattr(tool, "inputs", None),
            "output_type": getattr(tool, "output_type", None),
            "operation": operation,
            "effects": effects,
            "destinations": destinations,
            "side_effect": side_effect,
            "requires_explicit_intent": explicit,
            "route_kind": getattr(tool, "sensitiveguard_route_kind", None),
            "destination": getattr(tool, "sensitiveguard_destination", None),
            "recipient_argument": getattr(tool, "sensitiveguard_recipient_argument", None),
        }
        schema_digest = "schema_" + hashlib.sha256(_canonical(schema)).hexdigest()
        return cls(
            name=name,
            operation=operation,
            effects=effects,
            destinations=destinations,
            side_effect=side_effect,
            requires_explicit_intent=explicit,
            max_calls_per_run=25 if side_effect else 100,
            allow_injection_taint=False,
            implementation_digest=implementation_digest,
            schema_digest=schema_digest,
        )

    def matches_tool(self, tool: Any) -> bool:
        current = type(self).from_tool(tool)
        return (
            current.name == self.name
            and current.operation == self.operation
            and current.effects == self.effects
            and current.destinations == self.destinations
            and current.side_effect == self.side_effect
            and current.requires_explicit_intent == self.requires_explicit_intent
            and current.implementation_digest == self.implementation_digest
            and current.schema_digest == self.schema_digest
        )


def _profile_for_name(name: str) -> tuple[str, tuple[str, ...], tuple[str, ...], bool, bool]:
    profiles: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], bool, bool]] = {
        "safe_llm_call": ("analyze", ("MODEL", "EXTERNAL"), ("external_llm",), True, True),
        "safe_http_post": ("send", ("NETWORK", "EXTERNAL", "WRITE"), ("http:*",), True, True),
        "safe_send_message": ("send", ("MESSAGE", "NETWORK", "EXTERNAL", "WRITE"), ("message:*",), True, True),
        "safe_send_email": ("send", ("MESSAGE", "NETWORK", "EXTERNAL", "WRITE"), ("message:*",), True, True),
        "safe_query_database": ("query", ("READ",), ("database",), False, True),
        "safe_retrieve_rag": ("retrieve", ("READ",), ("rag",), False, True),
        "safe_run_command": ("execute", ("EXECUTE", "READ"), ("local_process",), True, True),
        "final_answer": ("summarize", (), ("requester",), False, False),
        "audit_privacy_trajectory": ("analyze", (), ("internal",), False, False),
        "trace_data_lineage": ("analyze", (), ("internal",), False, False),
    }
    if name in profiles:
        return profiles[name]
    if name.startswith("scan_"):
        return "scan", ("READ",), ("internal_file",), False, True
    if name.startswith("safe_read_"):
        return "read", ("READ",), ("internal_file",), False, True
    if name.startswith("verify_"):
        return "detect", ("READ",), ("internal_file",), False, True
    if name.startswith("sanitize_file"):
        return "transform", ("READ", "WRITE"), ("internal_file",), True, True
    if name.startswith("remediate_"):
        return "write", ("READ", "WRITE"), ("internal_file",), True, True
    if name.startswith(("sanitize_", "mask_", "redact_", "pseudonymize_", "tokenize_")):
        return "transform", ("READ",), ("internal",), False, False
    if name.startswith(("detect_", "evaluate_")):
        return "detect", ("READ",), ("internal",), False, False
    return "execute", (), ("internal",), True, True


class CapabilityManifestRegistry:
    """Thread-safe manifest registry with per-run quotas."""

    def __init__(self) -> None:
        self._manifests: dict[str, CapabilityManifest] = {}
        self._calls: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    def register(self, manifest: CapabilityManifest, *, replace: bool = False) -> None:
        if not isinstance(manifest, CapabilityManifest):
            raise TypeError("manifest must be a CapabilityManifest")
        with self._lock:
            if manifest.name in self._manifests and not replace:
                if self._manifests[manifest.name] == manifest:
                    return
                raise ValueError(f"Capability manifest {manifest.name!r} is already registered")
            self._manifests[manifest.name] = manifest

    def register_tool(self, tool: Any, *, replace: bool = False) -> CapabilityManifest:
        manifest = CapabilityManifest.from_tool(tool)
        self.register(manifest, replace=replace)
        return manifest

    def get(self, name: str) -> CapabilityManifest:
        with self._lock:
            try:
                return self._manifests[name]
            except KeyError:
                raise KeyError("The tool has no host capability manifest") from None

    def reserve_call(self, run_id: str, name: str) -> bool:
        with self._lock:
            manifest = self.get(name)
            key = (str(run_id), name)
            current = self._calls.get(key, 0)
            if current >= manifest.max_calls_per_run:
                return False
            self._calls[key] = current + 1
            return True

    def call_count(self, run_id: str, name: str) -> int:
        with self._lock:
            return self._calls.get((str(run_id), name), 0)

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._manifests))


__all__ = ["FILESYSTEM_CAPABILITY_PREFIXES", "CapabilityManifest", "CapabilityManifestRegistry"]
