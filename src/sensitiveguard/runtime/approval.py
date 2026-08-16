"""Single-use, content-bound approval workflow for REQUIRE_APPROVAL decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any

from sensitiveguard.models import DecisionSet, GuardStage


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    request_id: str
    run_id: str
    destination: str
    decision_digest: str
    created_at: float
    expires_at: float
    status: str = "PENDING"
    approver: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "run_id": self.run_id,
            "destination": self.destination,
            "decision_digest": self.decision_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "approver": self.approver,
        }


class ApprovalStore:
    """Create pending requests and consume exact approved disclosures once."""

    def __init__(self, *, key: bytes | None = None, ttl_seconds: float = 300.0, clock: Any = time.time) -> None:
        approval_key = key or secrets.token_bytes(32)
        if not isinstance(approval_key, bytes) or len(approval_key) < 16:
            raise ValueError("ApprovalStore key must contain at least 16 bytes")
        if ttl_seconds <= 0:
            raise ValueError("Approval TTL must be positive")
        self._key = approval_key
        self.ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = RLock()

    def request(
        self,
        decisions: DecisionSet,
        context: Any,
        destination: str,
        *,
        stage: GuardStage | str | None = None,
        recipient: str | None = None,
        policy_version: str | None = None,
        tool_name: str | None = None,
    ) -> ApprovalRequest:
        digest = self._digest(
            decisions,
            context,
            destination,
            stage=stage,
            recipient=recipient,
            policy_version=policy_version,
            tool_name=tool_name,
        )
        now = float(self._clock())
        run_id = str(context.run_id)
        with self._lock:
            for request in self._requests.values():
                if (
                    request.run_id == run_id
                    and request.destination == destination
                    and request.decision_digest == digest
                    and request.status in {"PENDING", "APPROVED"}
                    and request.expires_at >= now
                ):
                    return request
            request = ApprovalRequest(
                request_id=f"approval_{secrets.token_hex(12)}",
                run_id=run_id,
                destination=destination,
                decision_digest=digest,
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._requests[request.request_id] = request
            return request

    def approve(self, request_id: str, *, approver: str) -> ApprovalRequest:
        if not approver.strip():
            raise ValueError("An approver identity is required")
        with self._lock:
            request = self._require_current(request_id, expected_status="PENDING")
            updated = replace(request, status="APPROVED", approver=approver.strip())
            self._requests[request_id] = updated
            return updated

    def deny(self, request_id: str, *, approver: str) -> ApprovalRequest:
        if not approver.strip():
            raise ValueError("An approver identity is required")
        with self._lock:
            request = self._require_current(request_id, expected_status="PENDING")
            updated = replace(request, status="DENIED", approver=approver.strip())
            self._requests[request_id] = updated
            return updated

    def consume(
        self,
        decisions: DecisionSet,
        context: Any,
        destination: str,
        *,
        stage: GuardStage | str | None = None,
        recipient: str | None = None,
        policy_version: str | None = None,
        tool_name: str | None = None,
    ) -> bool:
        digest = self._digest(
            decisions,
            context,
            destination,
            stage=stage,
            recipient=recipient,
            policy_version=policy_version,
            tool_name=tool_name,
        )
        now = float(self._clock())
        run_id = str(context.run_id)
        with self._lock:
            for request_id, request in self._requests.items():
                if (
                    request.run_id == run_id
                    and request.destination == destination
                    and request.decision_digest == digest
                    and request.status == "APPROVED"
                    and request.expires_at >= now
                ):
                    self._requests[request_id] = replace(request, status="CONSUMED")
                    return True
            self.request(
                decisions,
                context,
                destination,
                stage=stage,
                recipient=recipient,
                policy_version=policy_version,
                tool_name=tool_name,
            )
            return False

    __call__ = consume

    def pending(self, run_id: str | None = None) -> tuple[ApprovalRequest, ...]:
        now = float(self._clock())
        with self._lock:
            return tuple(
                request
                for request in self._requests.values()
                if request.status == "PENDING"
                and request.expires_at >= now
                and (run_id is None or request.run_id == run_id)
            )

    def get(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._requests.get(request_id)

    def _require_current(self, request_id: str, *, expected_status: str) -> ApprovalRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise KeyError("Unknown approval request")
        if request.expires_at < float(self._clock()):
            self._requests[request_id] = replace(request, status="EXPIRED")
            raise ValueError("Approval request has expired")
        if request.status != expected_status:
            raise ValueError(f"Approval request is {request.status.lower()}, not {expected_status.lower()}")
        return request

    def _digest(
        self,
        decisions: DecisionSet,
        context: Any,
        destination: str,
        *,
        stage: GuardStage | str | None,
        recipient: str | None,
        policy_version: str | None,
        tool_name: str | None,
    ) -> str:
        items = []
        for decision in decisions.decisions:
            value_digest = hmac.new(
                self._key,
                decision.finding.value.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            items.append(
                {
                    "label": decision.finding.label,
                    "start": decision.finding.start,
                    "end": decision.finding.end,
                    "value_digest": value_digest,
                    "action": decision.action.value,
                    "policy_id": decision.policy_id,
                }
            )
        payload = json.dumps(
            {
                "run_id": str(context.run_id),
                "destination": destination,
                "recipient": recipient if recipient is not None else getattr(context, "recipient", None),
                "requester": getattr(context, "requester", None),
                "purpose": getattr(context, "purpose", None),
                "stage": stage.value if isinstance(stage, GuardStage) else stage,
                "policy_version": policy_version,
                "tool_name": tool_name,
                "decisions": items,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()
