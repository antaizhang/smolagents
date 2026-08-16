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
            **overrides,
        )
