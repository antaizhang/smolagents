"""Single-use, content-bound execution permits."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    permit_id: str
    run_id: str
    intent_id: str
    intent_version: int
    capability: str
    manifest_digest: str
    arguments_digest: str
    destination_digest: str
    lineage_digest: str
    policy_version: str
    issued_at: float
    expires_at: float
    status: str = "ISSUED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit_id": self.permit_id,
            "run_id": self.run_id,
            "intent_id": self.intent_id,
            "intent_version": self.intent_version,
            "capability": self.capability,
            "manifest_digest": self.manifest_digest,
            "arguments_digest": self.arguments_digest,
            "destination_digest": self.destination_digest,
            "lineage_digest": self.lineage_digest,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "status": self.status,
        }


class ExecutionPermitStore:
    """Issue and atomically consume HMAC-bound permits."""

    def __init__(
        self,
        *,
        key: bytes | None = None,
        ttl_seconds: float = 30.0,
        clock: Any = time.monotonic,
    ) -> None:
        self._key = key or secrets.token_bytes(32)
        if len(self._key) < 32:
            raise ValueError("Execution permit key must contain at least 32 bytes")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise TypeError("Execution permit TTL must be numeric")
        if not math.isfinite(float(ttl_seconds)) or ttl_seconds <= 0:
            raise ValueError("Execution permit TTL must be positive")
        if not callable(clock):
            raise TypeError("Execution permit clock must be callable")
        self.ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._permits: dict[str, ExecutionPermit] = {}
        self._lock = RLock()

    def issue(
        self,
        *,
        run_id: str,
        intent_id: str,
        intent_version: int,
        capability: str,
        manifest_digest: str,
        arguments: Any,
        destination: str,
        recipient: str | None,
        lineage_ids: tuple[str, ...] = (),
        policy_version: str = "unknown",
    ) -> ExecutionPermit:
        now = self._now()
        nonce = secrets.token_hex(16)
        binding = {
            "run_id": run_id,
            "intent_id": intent_id,
            "intent_version": intent_version,
            "capability": capability,
            "manifest_digest": manifest_digest,
            "arguments_digest": self._digest(arguments),
            "destination_digest": self._digest((destination, recipient)),
            "lineage_digest": self._digest(tuple(sorted(lineage_ids))),
            "policy_version": policy_version,
            "nonce": nonce,
        }
        permit_id = "permit_" + hmac.new(self._key, _canonical(binding), hashlib.sha256).hexdigest()[:32]
        permit = ExecutionPermit(
            permit_id=permit_id,
            run_id=str(run_id),
            intent_id=str(intent_id),
            intent_version=int(intent_version),
            capability=str(capability),
            manifest_digest=str(manifest_digest),
            arguments_digest=binding["arguments_digest"],
            destination_digest=binding["destination_digest"],
            lineage_digest=binding["lineage_digest"],
            policy_version=str(policy_version),
            issued_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._permits[permit_id] = permit
        return permit

    def consume(
        self,
        permit_id: str,
        *,
        run_id: str,
        intent_id: str,
        intent_version: int,
        capability: str,
        manifest_digest: str,
        arguments: Any,
        destination: str,
        recipient: str | None,
        lineage_ids: tuple[str, ...] = (),
        policy_version: str = "unknown",
    ) -> bool:
        with self._lock:
            permit = self._permits.get(permit_id)
            if permit is None or permit.status != "ISSUED" or self._now() >= permit.expires_at:
                if permit is not None and permit.status == "ISSUED":
                    self._permits[permit_id] = replace(permit, status="EXPIRED")
                return False
            expected = (
                str(run_id),
                str(intent_id),
                int(intent_version),
                str(capability),
                str(manifest_digest),
                self._digest(arguments),
                self._digest((destination, recipient)),
                self._digest(tuple(sorted(lineage_ids))),
                str(policy_version),
            )
            actual = (
                permit.run_id,
                permit.intent_id,
                permit.intent_version,
                permit.capability,
                permit.manifest_digest,
                permit.arguments_digest,
                permit.destination_digest,
                permit.lineage_digest,
                permit.policy_version,
            )
            if len(expected) != len(actual) or any(
                not hmac.compare_digest(str(left), str(right)) for left, right in zip(expected, actual, strict=True)
            ):
                return False
            self._permits[permit_id] = replace(permit, status="CONSUMED")
            return True

    def get(self, permit_id: str) -> ExecutionPermit | None:
        with self._lock:
            return self._permits.get(permit_id)

    def _digest(self, value: Any) -> str:
        return hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest()

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("Execution permit clock must return a numeric timestamp")
        result = float(value)
        if not math.isfinite(result) or result < 0:
            raise ValueError("Execution permit clock returned an invalid timestamp")
        return result


__all__ = ["ExecutionPermit", "ExecutionPermitStore"]
