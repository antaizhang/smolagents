"""Explicit guarded dispatch instead of smolagents' raw managed-agent handoff."""

from __future__ import annotations

from typing import Any

from sensitiveguard.models import GuardStage

from .handoff_guard import HandoffGuard
from .worker import GuardedWorker


class GuardedAgentManager:
    def __init__(self, gateway: Any, workers: list[GuardedWorker] | tuple[GuardedWorker, ...]) -> None:
        self.gateway = gateway
        self.handoff_guard = HandoffGuard(gateway)
        if len({worker.name for worker in workers}) != len(workers):
            raise ValueError("Guarded worker names must be unique")
        self._workers = {worker.name: worker for worker in workers}

    def dispatch(self, worker_name: str, payload: dict[str, Any], context: Any) -> dict[str, Any]:
        worker = self._workers.get(worker_name)
        if worker is None:
            return {"status": "BLOCKED", "reason": "The requested worker is not registered."}
        handoff = self.handoff_guard.guard(
            payload,
            context=context,
            allowed_fields=worker.allowed_fields,
            allowed_artifacts=worker.allowed_artifacts,
            destination=f"agent:{worker.name}",
            recipient=worker.name,
        )
        if not handoff.allowed:
            return handoff.to_dict(include_content=False)
        try:
            result = worker.handler(handoff.content)
        except Exception:
            return {"status": "FAILED", "reason": "The guarded worker failed without exposing its payload."}
        guarded_result = self.gateway.guard_payload(
            result,
            context,
            GuardStage.HANDOFF,
            destination="agent_memory",
            recipient="manager",
            tool_name=f"worker_result:{worker.name}",
            record_disclosure=False,
        )
        response = guarded_result.to_dict(include_content=guarded_result.allowed)
        response["worker"] = worker.name
        return response

    @property
    def worker_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._workers))
