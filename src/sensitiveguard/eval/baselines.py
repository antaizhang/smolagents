"""B0-B4 baseline configurations used for SensitiveGuard comparisons."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


class Baseline(str, Enum):
    B0 = "B0"
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B4 = "B4"

    def __str__(self) -> str:
        return self.value


BaselineName = Baseline


@dataclass(frozen=True, slots=True)
class BaselineConfig:
    baseline: Baseline
    display_name: str
    description: str
    detection: bool
    uniform_redaction: bool
    privacy_context: bool
    necessity_checker: bool
    context_aware_policy: bool
    safe_tool_gateway: bool
    memory_guard: bool
    disclosure_ledger: bool
    dynamic_intent: bool = False
    guarded_planning: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.baseline, Baseline):
            try:
                object.__setattr__(self, "baseline", Baseline(self.baseline))
            except (TypeError, ValueError):
                raise ValueError("BaselineConfig.baseline must be B0, B1, B2, B3, or B4") from None
        for name in ("display_name", "description"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"BaselineConfig.{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())
        for name in (
            "detection",
            "uniform_redaction",
            "privacy_context",
            "necessity_checker",
            "context_aware_policy",
            "safe_tool_gateway",
            "memory_guard",
            "disclosure_ledger",
            "dynamic_intent",
            "guarded_planning",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"BaselineConfig.{name} must be a boolean")
        if self.guarded_planning and not self.dynamic_intent:
            raise ValueError("guarded_planning requires dynamic_intent")
        if self.dynamic_intent and not self.safe_tool_gateway:
            raise ValueError("dynamic_intent requires safe_tool_gateway")

    @property
    def capabilities(self) -> tuple[str, ...]:
        names = (
            "detection",
            "uniform_redaction",
            "privacy_context",
            "necessity_checker",
            "context_aware_policy",
            "safe_tool_gateway",
            "memory_guard",
            "disclosure_ledger",
            "dynamic_intent",
            "guarded_planning",
        )
        return tuple(name for name in names if getattr(self, name))

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.value,
            "display_name": self.display_name,
            "description": self.description,
            "detection": self.detection,
            "uniform_redaction": self.uniform_redaction,
            "privacy_context": self.privacy_context,
            "necessity_checker": self.necessity_checker,
            "context_aware_policy": self.context_aware_policy,
            "safe_tool_gateway": self.safe_tool_gateway,
            "memory_guard": self.memory_guard,
            "disclosure_ledger": self.disclosure_ledger,
            "dynamic_intent": self.dynamic_intent,
            "guarded_planning": self.guarded_planning,
            "capabilities": list(self.capabilities),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BaselineConfig:
        if not isinstance(value, Mapping):
            raise TypeError("BaselineConfig.from_dict expects a mapping")
        fields = dict(value)
        fields.pop("capabilities", None)
        return cls(**fields)


BASELINES = MappingProxyType(
    {
        Baseline.B0: BaselineConfig(
            baseline=Baseline.B0,
            display_name="Raw smolagents",
            description="smolagents with raw tools and no sensitive-data protection.",
            detection=False,
            uniform_redaction=False,
            privacy_context=False,
            necessity_checker=False,
            context_aware_policy=False,
            safe_tool_gateway=False,
            memory_guard=False,
            disclosure_ledger=False,
        ),
        Baseline.B1: BaselineConfig(
            baseline=Baseline.B1,
            display_name="Detection only",
            description="Sensitive entity detection without transformation or enforcement.",
            detection=True,
            uniform_redaction=False,
            privacy_context=False,
            necessity_checker=False,
            context_aware_policy=False,
            safe_tool_gateway=False,
            memory_guard=False,
            disclosure_ledger=False,
        ),
        Baseline.B2: BaselineConfig(
            baseline=Baseline.B2,
            display_name="Detection plus uniform redaction",
            description="Detection followed by uniform redaction without context-aware policy.",
            detection=True,
            uniform_redaction=True,
            privacy_context=False,
            necessity_checker=False,
            context_aware_policy=False,
            safe_tool_gateway=False,
            memory_guard=False,
            disclosure_ledger=False,
        ),
        Baseline.B3: BaselineConfig(
            baseline=Baseline.B3,
            display_name="Full SensitiveGuard (static intent)",
            description="The complete context-aware runtime using the trusted host intent without request-level narrowing.",
            detection=True,
            uniform_redaction=False,
            privacy_context=True,
            necessity_checker=True,
            context_aware_policy=True,
            safe_tool_gateway=True,
            memory_guard=True,
            disclosure_ledger=True,
        ),
        Baseline.B4: BaselineConfig(
            baseline=Baseline.B4,
            display_name="Full SensitiveGuard (dynamic intent + guarded planning)",
            description="B3 plus signed request-intent narrowing and planning guarded before memory exposure.",
            detection=True,
            uniform_redaction=False,
            privacy_context=True,
            necessity_checker=True,
            context_aware_policy=True,
            safe_tool_gateway=True,
            memory_guard=True,
            disclosure_ledger=True,
            dynamic_intent=True,
            guarded_planning=True,
        ),
    }
)


def get_baseline(name: Baseline | str) -> BaselineConfig:
    try:
        normalized = name if isinstance(name, Baseline) else Baseline(name)
    except (TypeError, ValueError):
        raise KeyError(f"Unknown SensitiveGuard baseline: {name}") from None
    return BASELINES[normalized]


def list_baselines() -> tuple[BaselineConfig, ...]:
    return tuple(BASELINES[name] for name in Baseline)
