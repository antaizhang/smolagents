"""Minimize and guard payloads passed between agents."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any

from sensitiveguard.models import DecisionSet, DetectionResult, GuardResult, GuardStage, GuardStatus


_DROP = object()
_ARTIFACT_PREFIX = "artifact://"


class HandoffGuard:
    """Enforce least-data handoffs before a managed agent sees a payload."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    def guard(
        self,
        payload: Mapping[str, Any],
        *,
        context: Any,
        allowed_fields: Iterable[str] | None = None,
        allowed_artifacts: Iterable[str] | None = None,
        forbidden_fields: Iterable[str] | None = None,
        destination: str = "managed_agent",
        recipient: str | None = None,
    ) -> GuardResult:
        if not isinstance(payload, Mapping):
            return self._blocked("Handoff payload must be an object")

        try:
            allowed = self._resolve_allowed_fields(context, allowed_fields)
            artifacts = self._resolve_values(context, allowed_artifacts, "allowed_artifacts")
            forbidden = self._resolve_forbidden_fields(context, forbidden_fields)
        except (TypeError, ValueError):
            return self._blocked("Handoff scope configuration is invalid")

        matches = self._find_forbidden_paths(payload, forbidden)
        if matches:
            labels = ", ".join(sorted({path.rsplit(".", 1)[-1] for path in matches}))
            return self._blocked(f"Handoff contains forbidden fields: {labels}")

        minimized: dict[str, Any] = {}
        try:
            for key, value in payload.items():
                if not isinstance(key, str):
                    return self._blocked("Handoff field names must be strings")
                if key.casefold() not in allowed:
                    continue
                filtered = self._filter_artifacts(value, artifacts)
                if filtered is not _DROP:
                    minimized[key] = filtered

            # Artifact references are a separate capability and are only retained
            # when explicitly present in the context allow-list.
            if "artifacts" in payload and "artifacts" not in minimized and artifacts:
                filtered = self._filter_artifacts(payload["artifacts"], artifacts)
                if filtered is not _DROP and filtered not in ([], (), {}):
                    minimized["artifacts"] = filtered
        except Exception:
            return self._blocked("Handoff payload could not be minimized safely")

        changed_by_minimization = minimized != dict(payload)
        try:
            result = self.gateway.guard_payload(
                minimized,
                context=context,
                stage=GuardStage.HANDOFF,
                destination=destination,
                recipient=recipient,
                tool_name="agent_handoff",
                record_disclosure=True,
            )
        except Exception:
            return self._blocked("Handoff guard failed")

        if not getattr(result, "allowed", False):
            return result
        if changed_by_minimization and result.status is GuardStatus.ALLOWED:
            return GuardResult(
                status=GuardStatus.TRANSFORMED,
                content=deepcopy(result.content),
                detection=result.detection,
                decisions=result.decisions,
                reason=result.reason or "Handoff minimized to the authorized scope",
            )
        return result

    prepare_handoff = guard
    prepare = guard

    @staticmethod
    def _context_value(context: Any, name: str, default: Any = None) -> Any:
        if isinstance(context, Mapping):
            return context.get(name, default)
        return getattr(context, name, default)

    def _resolve_allowed_fields(self, context: Any, explicit: Iterable[str] | None) -> set[str]:
        context_values = self._as_values(self._context_value(context, "allowed_scope", ()))
        context_values.extend(self._as_values(self._context_value(context, "required_fields", ())))
        context_allowed = {str(value).casefold() for value in context_values if str(value)}
        if explicit is None:
            return context_allowed
        requested = {str(value).casefold() for value in self._as_values(explicit) if str(value)}
        return requested & context_allowed if context_allowed else requested

    def _resolve_forbidden_fields(self, context: Any, explicit: Iterable[str] | None) -> set[str]:
        values = self._as_values(self._context_value(context, "forbidden_fields", ()))
        values.extend(self._as_values(self._context_value(context, "forbidden_labels", ())))
        if explicit is not None:
            values.extend(self._as_values(explicit))
        return {str(value).casefold() for value in values if str(value)}

    def _resolve_values(self, context: Any, explicit: Iterable[str] | None, context_name: str) -> set[str]:
        values = explicit if explicit is not None else self._context_value(context, context_name, ())
        values = self._as_values(values)
        return {str(value).strip() for value in values if str(value).strip()}

    @staticmethod
    def _as_values(values: Any) -> list[Any]:
        if values is None:
            return []
        if isinstance(values, str):
            return [values]
        return list(values)

    def _find_forbidden_paths(self, payload: Any, forbidden: set[str], *, path: str = "$") -> tuple[str, ...]:
        if not forbidden:
            return ()
        matches: list[str] = []
        if isinstance(payload, Mapping):
            for key, value in payload.items():
                key_string = str(key)
                child_path = f"{path}.{key_string}"
                if key_string.casefold() in forbidden:
                    matches.append(child_path)
                matches.extend(self._find_forbidden_paths(value, forbidden, path=child_path))
        elif isinstance(payload, (list, tuple)):
            for index, value in enumerate(payload):
                matches.extend(self._find_forbidden_paths(value, forbidden, path=f"{path}[{index}]"))
        return tuple(matches)

    def _filter_artifacts(self, value: Any, allowed_artifacts: set[str]) -> Any:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate.casefold().startswith(_ARTIFACT_PREFIX):
                return candidate if candidate in allowed_artifacts else _DROP
            return value
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                filtered = self._filter_artifacts(item, allowed_artifacts)
                if filtered is not _DROP:
                    result[key] = filtered
            return result
        if isinstance(value, list):
            return [
                filtered
                for item in value
                if (filtered := self._filter_artifacts(item, allowed_artifacts)) is not _DROP
            ]
        if isinstance(value, tuple):
            return tuple(
                filtered
                for item in value
                if (filtered := self._filter_artifacts(item, allowed_artifacts)) is not _DROP
            )
        return deepcopy(value)

    @staticmethod
    def _blocked(reason: str) -> GuardResult:
        return GuardResult(
            status=GuardStatus.BLOCKED,
            detection=DetectionResult(),
            decisions=DecisionSet(),
            reason=reason,
        )
