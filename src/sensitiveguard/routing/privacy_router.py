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
    "internal_database",
    "internal_file",
    "local",
    "local_process",
    "memory",
    "rag",
    "requester",
}


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
        """Resolve a tool route without trusting model-provided route labels."""

        name = str(getattr(tool, "name", "unknown"))
        mapping = arguments if isinstance(arguments, Mapping) else {}
        recipient: str | None = None
        if name == "safe_http_post":
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
            # Matching on the capability-name prefixes the host manifest uses,
            # never on a substring: an unrelated tool such as ``customer_profile``
            # merely contains "file" and must keep its internal route instead of
            # failing review with a route/manifest mismatch.
            destination, kind = "internal_file", RouteKind.FILESYSTEM
        else:
            # Unknown/custom tools are host-registered internal capabilities.
            # A task-level destination describes the user's data flow, not the
            # effective route of an arbitrary tool, so it must not relabel an
            # internal capability as an external sink.
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
