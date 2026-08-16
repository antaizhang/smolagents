"""Host-side builder for validated privacy contexts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitiveguard.privacy.context import PrivacyContext


@dataclass(frozen=True, slots=True)
class PrivacyContextBuilder:
    requester: str | None = None
    source: str | None = None
    destination: str | None = None
    trust_level: str = "untrusted"

    def build(
        self,
        *,
        task: str,
        purpose: str,
        recipient: str | None = None,
        required_fields: tuple[str, ...] | list[str] = (),
        optional_fields: tuple[str, ...] | list[str] = (),
        forbidden_fields: tuple[str, ...] | list[str] = (),
        allowed_scope: tuple[str, ...] | list[str] = (),
        allowed_operations: tuple[str, ...] | list[str] = (),
        denied_operations: tuple[str, ...] | list[str] = (),
        allowed_capabilities: tuple[str, ...] | list[str] = (),
        denied_capabilities: tuple[str, ...] | list[str] = (),
        allowed_effects: tuple[str, ...] | list[str] = (),
        denied_effects: tuple[str, ...] | list[str] = (),
        allowed_destinations: tuple[str, ...] | list[str] = (),
        denied_destinations: tuple[str, ...] | list[str] = (),
        allowed_recipients: tuple[str, ...] | list[str] = (),
        denied_recipients: tuple[str, ...] | list[str] = (),
        intent_version: int = 1,
        intent_expires_at: float | None = None,
        **overrides: Any,
    ) -> PrivacyContext:
        return PrivacyContext(
            task=task,
            purpose=purpose,
            requester=overrides.pop("requester", self.requester),
            recipient=recipient,
            source=overrides.pop("source", self.source),
            destination=overrides.pop("destination", self.destination),
            trust_level=overrides.pop("trust_level", self.trust_level),
            required_fields=required_fields,
            optional_fields=optional_fields,
            forbidden_fields=forbidden_fields,
            allowed_scope=allowed_scope,
            allowed_operations=allowed_operations,
            denied_operations=denied_operations,
            allowed_capabilities=allowed_capabilities,
            denied_capabilities=denied_capabilities,
            allowed_effects=allowed_effects,
            denied_effects=denied_effects,
            allowed_destinations=allowed_destinations,
            denied_destinations=denied_destinations,
            allowed_recipients=allowed_recipients,
            denied_recipients=denied_recipients,
            intent_version=intent_version,
            intent_expires_at=intent_expires_at,
            **overrides,
        )
