"""Ground-truth scenario model for the SensitiveGuard benchmark harness.

A scenario declares three things that the runtime under test never sees:

1. the exact raw sensitive values planted in the world (``Canary``),
2. where each of those values is forbidden to appear (``Canary.forbidden_sinks``),
3. the sequence of tool calls a naive or compromised planner attempts.

Scoring therefore never asks the runtime whether it behaved correctly. It
compares recorded sink traffic against values the harness planted itself, so a
detector miss is measured as a leak rather than hidden by the detector that
caused it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from sensitiveguard.models import Action

from .benchmarks import BenchmarkName


class Sink(str, Enum):
    """An observable location a sensitive value can end up in."""

    EXTERNAL_LLM = "external_llm"
    HTTP = "http"
    MESSAGE = "message"
    AGENT_MEMORY = "agent_memory"
    TOOL_ARGUMENTS = "tool_arguments"
    FINAL_ANSWER = "final_answer"
    ARTIFACT = "artifact"

    def __str__(self) -> str:
        return self.value


EXTERNAL_SINKS: frozenset[Sink] = frozenset({Sink.EXTERNAL_LLM, Sink.HTTP, Sink.MESSAGE})
ALL_SINKS: tuple[Sink, ...] = tuple(Sink)

# A plan of this many steps or more is treated as long-horizon: enough turns for
# context handling and cross-step state to be exercised rather than assumed.
LONG_HORIZON_STEPS = 6


def _clean_str(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    cleaned = value.strip()
    if not cleaned and not allow_empty:
        raise ValueError(f"{name} must not be empty")
    return cleaned


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _string_tuple(name: str, values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    if not isinstance(values, Iterable):
        raise TypeError(f"{name} must be an iterable of strings")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must contain non-empty strings")
        result.append(value.strip())
    return tuple(result)


def _sink_tuple(name: str, values: Any) -> tuple[Sink, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, Sink)):
        values = (values,)
    result: list[Sink] = []
    for value in values:
        try:
            sink = value if isinstance(value, Sink) else Sink(str(value).strip())
        except ValueError:
            raise ValueError(f"{name} contains an unknown sink: {value!r}") from None
        if sink not in result:
            result.append(sink)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class Canary:
    """One planted raw value together with its ground-truth handling.

    ``value`` is the literal string the harness writes into the world. The leak
    oracle searches recorded sink traffic for exactly this string, so masked,
    tokenized, pseudonymized and redacted representations never count as leaks
    while a raw pass-through always does.
    """

    canary_id: str
    label: str
    value: str
    necessary: bool = False
    forbidden_sinks: tuple[Sink, ...] = ALL_SINKS
    expected_action: Action | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "canary_id", _clean_str("canary_id", self.canary_id))
        object.__setattr__(self, "label", _clean_str("label", self.label).upper())
        value = _clean_str("value", self.value)
        if len(value) < 3:
            # Short values invite incidental substring matches, which would be
            # scored as leaks. Three characters is the floor that still admits
            # realistic Chinese personal names.
            raise ValueError("Canary.value must be at least 3 characters so the oracle cannot match by accident")
        object.__setattr__(self, "value", value)
        if not isinstance(self.necessary, bool):
            raise TypeError("Canary.necessary must be a boolean")
        object.__setattr__(self, "forbidden_sinks", _sink_tuple("forbidden_sinks", self.forbidden_sinks))
        if self.expected_action is not None:
            action = self.expected_action
            if not isinstance(action, Action):
                try:
                    action = Action(str(action).strip().upper())
                except ValueError:
                    raise ValueError(f"Unknown expected_action: {self.expected_action!r}") from None
            object.__setattr__(self, "expected_action", action)

    def is_forbidden_at(self, sink: Sink) -> bool:
        return sink in self.forbidden_sinks

    def to_dict(self) -> dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "label": self.label,
            "value": self.value,
            "necessary": self.necessary,
            "forbidden_sinks": [sink.value for sink in self.forbidden_sinks],
            "expected_action": self.expected_action.value if self.expected_action else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Canary:
        if not isinstance(value, Mapping):
            raise TypeError("Canary.from_dict expects a mapping")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    """One tool call the modelled planner attempts.

    The harness replays these through a scripted model, so every baseline runs
    the identical planner behaviour and the measured difference is attributable
    to the runtime rather than to model variance.
    """

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool", _clean_str("tool", self.tool))
        if not isinstance(self.arguments, Mapping):
            raise TypeError("ScenarioStep.arguments must be a mapping")
        if any(not isinstance(key, str) for key in self.arguments):
            raise TypeError("ScenarioStep.arguments must use string keys")
        object.__setattr__(self, "arguments", dict(self.arguments))
        object.__setattr__(self, "note", _clean_str("note", self.note, allow_empty=True))

    def resolved_arguments(self, substitutions: Mapping[str, str]) -> dict[str, Any]:
        """Expand ``{placeholder}`` markers, e.g. the per-run scenario root."""

        return {key: _substitute(value, substitutions) for key, value in self.arguments.items()}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool": self.tool, "arguments": dict(self.arguments)}
        if self.note:
            payload["note"] = self.note
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScenarioStep:
        if not isinstance(value, Mapping):
            raise TypeError("ScenarioStep.from_dict expects a mapping")
        return cls(**dict(value))


def _substitute(value: Any, substitutions: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        for key, replacement in substitutions.items():
            value = value.replace("{" + key + "}", replacement)
        return value
    if isinstance(value, Mapping):
        return {key: _substitute(item, substitutions) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_substitute(item, substitutions) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class Scenario:
    """A complete, self-contained benchmark case.

    Every field is data: the harness materializes the world, wires recording
    sinks, replays ``steps`` and scores the result. Nothing here reaches the
    network and nothing requires a model provider.
    """

    scenario_id: str
    benchmark: BenchmarkName
    task: str
    purpose: str
    steps: tuple[ScenarioStep, ...]
    canaries: tuple[Canary, ...] = ()

    # World contents.
    files: Mapping[str, str] = field(default_factory=dict)
    database: Mapping[str, tuple[Mapping[str, Any], ...]] = field(default_factory=dict)
    rag_chunks: tuple[Mapping[str, Any], ...] = ()
    llm_response: str = "Analysis complete."
    http_response: Mapping[str, Any] = field(default_factory=lambda: {"status": "ok"})

    # Privacy context.
    requester: str | None = None
    recipient: str | None = None
    source: str | None = None
    destination: str | None = None
    trust_level: str = "unknown"
    required_fields: tuple[str, ...] = ()
    optional_fields: tuple[str, ...] = ()
    forbidden_fields: tuple[str, ...] = ()
    allowed_scope: tuple[str, ...] = ()

    # Host authorization.
    allowed_http_hosts: tuple[str, ...] = ()
    allowed_message_recipients: tuple[str, ...] = ()
    known_external_destinations: tuple[str, ...] = ()
    allowed_database_tables: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    allow_http: bool = True
    privacy_budget: float = 100.0
    destination_budgets: Mapping[str, float] = field(default_factory=dict)

    # Layer 2 ground truth: which tools the task legitimately needs, which it
    # must never touch, and what its arguments have to satisfy.
    expected_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    argument_expectations: tuple[Mapping[str, Any], ...] = ()
    minimum_steps: int = 0

    # Layer 3 ground truth: whether this scenario is long-horizon, and whether a
    # refused or failed step has a correct recovery path within the plan.
    long_horizon: bool = False
    recovery_expected: bool = False
    failing_tools: tuple[str, ...] = ()
    step_budget: int = 0

    # Outcome oracles. ``success_markers`` applies to legitimate scenarios only:
    # a task that must not be carried out is scored on whether disclosure was
    # actually prevented, not on what the answer claims.
    success_markers: tuple[str, ...] = ()
    utility_markers: tuple[str, ...] = ()
    necessary_data_fields: tuple[str, ...] = ()
    legitimate: bool = True
    attack: bool = False
    attack_sinks: tuple[Sink, ...] = ()
    attack_succeeds_on_contact: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _clean_str("scenario_id", self.scenario_id))
        benchmark = self.benchmark
        if not isinstance(benchmark, BenchmarkName):
            try:
                benchmark = BenchmarkName(str(benchmark).strip())
            except ValueError:
                raise ValueError(f"Unknown benchmark: {self.benchmark!r}") from None
        object.__setattr__(self, "benchmark", benchmark)
        object.__setattr__(self, "task", _clean_str("task", self.task))
        object.__setattr__(self, "purpose", _clean_str("purpose", self.purpose))

        steps = tuple(
            step if isinstance(step, ScenarioStep) else ScenarioStep.from_dict(step) for step in self.steps or ()
        )
        if not steps:
            raise ValueError("Scenario.steps must contain at least one step")
        if steps[-1].tool != "final_answer":
            raise ValueError("Scenario.steps must end with a final_answer step so the output guard is exercised")
        if any(step.tool == "final_answer" for step in steps[:-1]):
            raise ValueError("Only the last scenario step may be final_answer")
        object.__setattr__(self, "steps", steps)

        canaries = tuple(
            canary if isinstance(canary, Canary) else Canary.from_dict(canary) for canary in self.canaries or ()
        )
        identifiers = [canary.canary_id for canary in canaries]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Scenario.canaries must have unique canary_id values")
        values = [canary.value for canary in canaries]
        if len(values) != len(set(values)):
            raise ValueError("Scenario.canaries must have unique values so the leak oracle stays unambiguous")
        object.__setattr__(self, "canaries", canaries)

        files = dict(self.files or {})
        if any(not isinstance(key, str) or not isinstance(item, str) for key, item in files.items()):
            raise TypeError("Scenario.files must map relative paths to text content")
        for relative in files:
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError("Scenario.files paths must be relative and must not escape the scenario root")
        object.__setattr__(self, "files", files)

        database = {str(table): tuple(dict(row) for row in rows) for table, rows in dict(self.database or {}).items()}
        object.__setattr__(self, "database", database)
        object.__setattr__(self, "rag_chunks", tuple(dict(chunk) for chunk in self.rag_chunks or ()))
        object.__setattr__(self, "llm_response", _clean_str("llm_response", self.llm_response, allow_empty=True))
        object.__setattr__(self, "http_response", dict(self.http_response or {}))

        for name in ("requester", "recipient", "source", "destination"):
            object.__setattr__(self, name, _clean_optional(getattr(self, name)))
        object.__setattr__(self, "trust_level", _clean_str("trust_level", self.trust_level or "unknown").lower())
        for name in (
            "required_fields",
            "optional_fields",
            "forbidden_fields",
            "allowed_scope",
            "allowed_http_hosts",
            "allowed_message_recipients",
            "known_external_destinations",
            "expected_tools",
            "forbidden_tools",
            "failing_tools",
            "success_markers",
            "utility_markers",
            "necessary_data_fields",
        ):
            object.__setattr__(self, name, _string_tuple(name, getattr(self, name)))
        if not self.utility_markers:
            object.__setattr__(self, "utility_markers", self.success_markers)
        if self.legitimate and not self.success_markers:
            raise ValueError("A legitimate scenario must declare success_markers, otherwise it cannot be scored")
        if not self.legitimate and self.success_markers:
            raise ValueError("An illegitimate scenario is scored on prevented disclosure; remove its success_markers")

        object.__setattr__(
            self,
            "allowed_database_tables",
            {
                str(table): _string_tuple("allowed_database_tables", fields)
                for table, fields in dict(self.allowed_database_tables or {}).items()
            },
        )
        for name in (
            "allow_http",
            "legitimate",
            "attack",
            "attack_succeeds_on_contact",
            "long_horizon",
            "recovery_expected",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"Scenario.{name} must be a boolean")

        expectations = tuple(dict(item) for item in self.argument_expectations or ())
        for expectation in expectations:
            if "tool" not in expectation or "argument" not in expectation:
                raise ValueError("Each argument_expectation needs a 'tool' and an 'argument'")
            checks = {key for key in expectation if key not in {"tool", "argument", "description"}}
            if not checks & {"equals", "contains", "excludes", "matches", "absent"}:
                raise ValueError("Each argument_expectation needs one of equals/contains/excludes/matches/absent")
        object.__setattr__(self, "argument_expectations", expectations)

        budget = int(self.step_budget or 0)
        if budget < 0:
            raise ValueError("Scenario.step_budget must be non-negative")
        object.__setattr__(self, "step_budget", budget)
        minimum = int(self.minimum_steps or 0)
        if minimum < 0:
            raise ValueError("Scenario.minimum_steps must be non-negative")
        if not minimum:
            # An unset ideal defaults to the scripted plan length, which makes
            # trajectory efficiency 1.0 under the scripted planner and only
            # meaningful once a real planner can wander.
            minimum = len(self.steps)
        object.__setattr__(self, "minimum_steps", minimum)
        # A scenario is long-horizon when it needs enough turns for context
        # handling and step-to-step state to actually be exercised.
        if not self.long_horizon and len(self.steps) >= LONG_HORIZON_STEPS:
            object.__setattr__(self, "long_horizon", True)
        budget = float(self.privacy_budget)
        if budget <= 0:
            raise ValueError("Scenario.privacy_budget must be positive")
        object.__setattr__(self, "privacy_budget", budget)
        object.__setattr__(
            self,
            "destination_budgets",
            {str(key): float(item) for key, item in dict(self.destination_budgets or {}).items()},
        )

        object.__setattr__(self, "attack_sinks", _sink_tuple("attack_sinks", self.attack_sinks))
        if self.attack and not self.attack_sinks:
            object.__setattr__(self, "attack_sinks", tuple(sorted(EXTERNAL_SINKS, key=lambda sink: sink.value)))
        if not self.attack and self.attack_sinks:
            raise ValueError("attack_sinks requires attack=True")
        if self.attack_succeeds_on_contact and not self.attack:
            raise ValueError("attack_succeeds_on_contact requires attack=True")
        object.__setattr__(self, "description", _clean_str("description", self.description, allow_empty=True))

    @property
    def max_steps(self) -> int:
        """The agent's step budget.

        The scripted planner needs its plan length plus a fallback answer. A
        model planner needs headroom to retry after a refusal, so the default
        leaves room rather than scoring a truncated run as a capability failure.
        """

        return self.step_budget or len(self.steps) + 4

    @property
    def forbidden_canaries(self) -> tuple[Canary, ...]:
        return tuple(canary for canary in self.canaries if canary.forbidden_sinks)

    def canary_for_value(self, value: str) -> Canary | None:
        return next((canary for canary in self.canaries if canary.value == value), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "benchmark": self.benchmark.value,
            "task": self.task,
            "purpose": self.purpose,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "canaries": [canary.to_dict() for canary in self.canaries],
            "files": dict(self.files),
            "database": {table: [dict(row) for row in rows] for table, rows in self.database.items()},
            "rag_chunks": [dict(chunk) for chunk in self.rag_chunks],
            "llm_response": self.llm_response,
            "http_response": dict(self.http_response),
            "requester": self.requester,
            "recipient": self.recipient,
            "source": self.source,
            "destination": self.destination,
            "trust_level": self.trust_level,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "forbidden_fields": list(self.forbidden_fields),
            "allowed_scope": list(self.allowed_scope),
            "allowed_http_hosts": list(self.allowed_http_hosts),
            "allowed_message_recipients": list(self.allowed_message_recipients),
            "known_external_destinations": list(self.known_external_destinations),
            "expected_tools": list(self.expected_tools),
            "forbidden_tools": list(self.forbidden_tools),
            "argument_expectations": [dict(item) for item in self.argument_expectations],
            "minimum_steps": self.minimum_steps,
            "long_horizon": self.long_horizon,
            "recovery_expected": self.recovery_expected,
            "failing_tools": list(self.failing_tools),
            "step_budget": self.step_budget,
            "allowed_database_tables": {table: list(fields) for table, fields in self.allowed_database_tables.items()},
            "allow_http": self.allow_http,
            "privacy_budget": self.privacy_budget,
            "destination_budgets": dict(self.destination_budgets),
            "success_markers": list(self.success_markers),
            "utility_markers": list(self.utility_markers),
            "necessary_data_fields": list(self.necessary_data_fields),
            "legitimate": self.legitimate,
            "attack": self.attack,
            "attack_sinks": [sink.value for sink in self.attack_sinks],
            "attack_succeeds_on_contact": self.attack_succeeds_on_contact,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Scenario:
        if not isinstance(value, Mapping):
            raise TypeError("Scenario.from_dict expects a mapping")
        return cls(**dict(value))


def load_scenarios(source: str | Path | Iterable[Mapping[str, Any]]) -> tuple[Scenario, ...]:
    """Load scenarios from a JSONL path, a JSON array path, or in-memory mappings."""

    if isinstance(source, (str, Path)):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        records: list[Mapping[str, Any]] = []
        stripped = text.lstrip()
        if stripped.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                raise ValueError(f"{path} must contain a JSON array of scenario objects")
            records = parsed
        else:
            for number, line in enumerate(text.splitlines(), start=1):
                if not line.strip() or line.lstrip().startswith("//"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{number} is not valid JSON: {error.msg}") from None
        return tuple(Scenario.from_dict(record) for record in records)

    if isinstance(source, Mapping):
        raise TypeError("load_scenarios expects a path or an iterable of scenario mappings")
    return tuple(item if isinstance(item, Scenario) else Scenario.from_dict(item) for item in source)


def scenarios_by_benchmark(scenarios: Sequence[Scenario]) -> dict[BenchmarkName, tuple[Scenario, ...]]:
    grouped: dict[BenchmarkName, list[Scenario]] = {}
    for scenario in scenarios:
        grouped.setdefault(scenario.benchmark, []).append(scenario)
    return {name: tuple(items) for name, items in grouped.items()}


__all__ = [
    "ALL_SINKS",
    "EXTERNAL_SINKS",
    "Canary",
    "Scenario",
    "ScenarioStep",
    "Sink",
    "load_scenarios",
    "scenarios_by_benchmark",
]
