"""Deterministic local-first routing for models and protected tools."""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import secrets
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from sensitiveguard.models import DetectionResult, Severity
from sensitiveguard.runtime.capability_manifest import FILESYSTEM_CAPABILITY_PREFIXES

from .models import EndpointDescriptor, RouteDecision, RouteKind, RouteStatus


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
_INTERNAL_DESTINATIONS = {
    "agent_memory",
    "database",
    "internal",
    "internal_benchmark",
    "internal_database",
    "internal_file",
    "local",
    "local_process",
    "memory",
    "rag",
    "requester",
}


def _trusted_route_kind(value: Any) -> RouteKind | None:
    if isinstance(value, RouteKind):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().lower()
    try:
        return RouteKind(normalized)
    except ValueError:
        return None


class PrivacyRouter:
    """Resolve an effective route exclusively from trusted runtime objects."""

    def __init__(
        self,
        endpoints: Iterable[EndpointDescriptor] = (),
        *,
        key: bytes | None = None,
    ) -> None:
        self._key = key or secrets.token_bytes(32)
        if len(self._key) < 32:
            raise ValueError("PrivacyRouter key must contain at least 32 bytes")
        endpoint_values = tuple(endpoints)
        if any(not isinstance(endpoint, EndpointDescriptor) for endpoint in endpoint_values):
            raise TypeError("endpoints must contain EndpointDescriptor values")
        if len({endpoint.endpoint_id for endpoint in endpoint_values}) != len(endpoint_values):
            raise ValueError("Endpoint ids must be unique")
        self._endpoints = {endpoint.endpoint_id: endpoint for endpoint in endpoint_values}

    def endpoints(self) -> tuple[EndpointDescriptor, ...]:
        return tuple(sorted(self._endpoints.values(), key=lambda item: (item.priority, item.endpoint_id)))

    def route_model(
        self,
        detection: DetectionResult,
        *,
        operation: str,
        preferred_endpoint: str | None = None,
        allow_external_fallback: bool = False,
    ) -> RouteDecision:
        """Select a registered endpoint, preferring local for sensitive data.

        A requested local endpoint never silently degrades to external unless
        both the endpoint and this call explicitly permit fallback.
        """

        if not isinstance(detection, DetectionResult):
            raise TypeError("route_model expects a DetectionResult")
        candidates = [endpoint for endpoint in self.endpoints() if endpoint.available and endpoint.supports(operation)]
        preferred = self._endpoints.get(preferred_endpoint) if preferred_endpoint else None
        if preferred_endpoint and preferred is None:
            return self._blocked(RouteKind.MODEL, "unknown", "ROUTE_UNKNOWN_ENDPOINT")
        maximum = max(
            (finding.severity for finding in detection.findings), key=_SEVERITY_RANK.get, default=Severity.LOW
        )
        candidates = [
            endpoint for endpoint in candidates if _SEVERITY_RANK[maximum] <= _SEVERITY_RANK[endpoint.max_sensitivity]
        ]
        if preferred is not None and preferred.available and preferred in candidates:
            selected = preferred
        else:
            local_candidates = [endpoint for endpoint in candidates if endpoint.is_local]
            if local_candidates:
                selected = local_candidates[0]
            elif preferred is not None and preferred.is_local:
                if not (allow_external_fallback and preferred.allow_fallback):
                    return self._blocked(RouteKind.MODEL, preferred.destination, "ROUTE_EXTERNAL_FALLBACK_DENIED")
                selected = candidates[0] if candidates else None
            else:
                selected = candidates[0] if candidates else None
        if selected is None:
            return self._blocked(RouteKind.MODEL, "unknown", "ROUTE_NO_CAPABLE_ENDPOINT")
        return RouteDecision(
            status=RouteStatus.ALLOW,
            route_kind=RouteKind.MODEL,
            destination=selected.destination,
            endpoint_id=selected.endpoint_id,
            reason_code="ROUTE_LOCAL_PREFERRED" if selected.is_local else "ROUTE_EXTERNAL_SELECTED",
            external=not selected.is_local,
        )

    def route_tool(
        self,
        tool: Any,
        arguments: Mapping[str, Any] | Any,
        context: Any,
        *,
        operation: str,
        destination_hint: str | None = None,
    ) -> RouteDecision:
        """Resolve a tool route without trusting model-provided route labels.

        Built-in tools use fixed name-based routes. Third-party application and
        benchmark adapters may attach ``sensitiveguard_route_kind`` and
        ``sensitiveguard_destination`` to a host-created SensitiveGuardTool.
        Those attributes are part of its capability-manifest schema digest, so
        they remain trusted host metadata rather than model-controlled input.
        """

        name = str(getattr(tool, "name", "unknown"))
        mapping = arguments if isinstance(arguments, Mapping) else {}
        recipient: str | None = None

        trusted_kind = _trusted_route_kind(getattr(tool, "sensitiveguard_route_kind", None))
        trusted_destination = getattr(tool, "sensitiveguard_destination", None)
        if trusted_kind is not None and isinstance(trusted_destination, str) and trusted_destination.strip():
            destination = trusted_destination.strip().casefold()
            kind = trusted_kind
            recipient_argument = getattr(tool, "sensitiveguard_recipient_argument", None)
            if isinstance(recipient_argument, str) and recipient_argument:
                raw_recipient = mapping.get(recipient_argument)
                if raw_recipient is not None:
                    recipient = str(raw_recipient).strip() or None
        elif name == "safe_http_post":
            url = mapping.get("url")
            if not isinstance(url, str):
                return self._blocked(RouteKind.NETWORK, "unknown", "ROUTE_INVALID_URL")
            try:
                tool.gateway.authorization.authorize_url(url)
            except Exception:
                return self._blocked(RouteKind.NETWORK, "unknown", "ROUTE_URL_NOT_AUTHORIZED")
            host = (urlsplit(url).hostname or "unknown").lower().rstrip(".")
            destination = f"http:{host}"
            kind = RouteKind.NETWORK
        elif name in {"safe_send_message", "safe_send_email"}:
            value = mapping.get("recipient")
            if not isinstance(value, str):
                return self._blocked(RouteKind.MESSAGE, "unknown", "ROUTE_INVALID_RECIPIENT")
            recipient = value
            allowed = getattr(tool, "allowed_recipients", frozenset())
            if value.casefold() not in allowed:
                return self._blocked(RouteKind.MESSAGE, "unknown", "ROUTE_RECIPIENT_NOT_AUTHORIZED")
            domain = value.rsplit("@", 1)[-1].casefold() if "@" in value else "configured_recipient"
            destination = f"message:{domain}"
            kind = RouteKind.MESSAGE
        elif name == "safe_llm_call":
            destination = str(getattr(tool, "destination", destination_hint or "external_llm"))
            kind = RouteKind.MODEL
        elif name in {"safe_query_database"}:
            destination, kind = "database", RouteKind.DATABASE
        elif name in {"safe_retrieve_rag"}:
            destination, kind = "rag", RouteKind.RETRIEVAL
        elif name == "safe_run_command":
            destination, kind = "local_process", RouteKind.PROCESS
        elif name == "final_answer":
            destination, kind = "requester", RouteKind.REQUESTER
        elif name.startswith(FILESYSTEM_CAPABILITY_PREFIXES):
            destination, kind = "internal_file", RouteKind.FILESYSTEM
        else:
            destination, kind = "internal", RouteKind.LOCAL

        allowed_destinations = tuple(getattr(context, "allowed_destinations", ()) or ())
        if allowed_destinations and not any(
            fnmatch.fnmatchcase(destination.casefold(), pattern.casefold()) for pattern in allowed_destinations
        ):
            return self._blocked(kind, destination, "ROUTE_DESTINATION_OUTSIDE_INTENT")
        external = destination.casefold() not in _INTERNAL_DESTINATIONS and not destination.startswith("internal_")
        return RouteDecision(
            status=RouteStatus.ALLOW,
            route_kind=kind,
            destination=destination,
            reason_code=f"ROUTE_{operation.upper()}_AUTHORIZED",
            external=external,
            recipient_fingerprint=self._fingerprint(recipient) if recipient else None,
            recipient=recipient,
        )

    def _fingerprint(self, value: str) -> str:
        return "recipient_" + hmac.new(self._key, value.casefold().encode(), hashlib.sha256).hexdigest()[:24]

    @staticmethod
    def _blocked(kind: RouteKind, destination: str, reason: str) -> RouteDecision:
        return RouteDecision(
            status=RouteStatus.BLOCK,
            route_kind=kind,
            destination=destination,
            reason_code=reason,
            external=True,
        )


__all__ = ["PrivacyRouter"]
