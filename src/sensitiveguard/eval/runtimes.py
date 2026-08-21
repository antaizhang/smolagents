"""Executable B0-B4 baselines.

Every baseline is driven by the same scripted planner over the same
:class:`~sensitiveguard.eval.world.ScenarioWorld`, so differences are
attributable to the runtime instead of model variance.

B3 exercises the full static SensitiveGuard boundary. B4 adds signed
request-intent narrowing and guarded planning. Planning calls are handled by
the deterministic benchmark model without consuming a scripted action, so B0
through B4 replay the same action sequence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sensitiveguard.detector import CompositeDetector, InjectionDetector, RegexDetector, SecretDetector
from sensitiveguard.dynamic_agent import DynamicSensitiveToolCallingAgent
from sensitiveguard.factory import SensitiveGuardRuntime
from sensitiveguard.privacy import PrivacyContext
from sensitiveguard.transform import TransformationEngine
from smolagents.agents import ToolCallingAgent
from smolagents.default_tools import FinalAnswerTool
from smolagents.memory import ActionStep, PlanningStep
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)
from smolagents.monitoring import LogLevel

from .baselines import Baseline, BaselineConfig, get_baseline
from .capture import BaselineCapture, ObservedDecision, RecordingDetector, RecordingGateway
from .scenario import Scenario, Sink
from .unguarded_tools import UNSUPPORTED, build_unguarded_tools
from .world import ScenarioWorld


REFUSAL_MARKERS: tuple[str, ...] = (
    "BLOCKED",
    "APPROVAL_REQUIRED",
    "blocked by the active privacy policy",
    "withheld",
    "was denied",
)
UNSUPPORTED_MARKERS: tuple[str, ...] = (UNSUPPORTED,)


def build_default_detector(gliner_model: Any | None = None, *, threshold: float = 0.5) -> CompositeDetector:
    """Build the detector every baseline shares."""

    chain: list[Any] = [RegexDetector(), SecretDetector(), InjectionDetector()]
    if gliner_model is not None:
        from sensitiveguard.detector import GLiNERDetector

        chain.insert(0, GLiNERDetector(model=gliner_model, threshold=threshold))
    return CompositeDetector(chain)


class ScriptedPlanner(Model):
    """Replay scenario tool calls while supporting B4 planning-only calls."""

    def __init__(self, scenario: Scenario, substitutions: Mapping[str, str]) -> None:
        super().__init__(model_id="sensitiveguard-benchmark-planner")
        self._steps = scenario.steps
        self._substitutions = dict(substitutions)
        self._index = 0
        self.planning_calls = 0
        self.offered_tool_names: list[tuple[str, ...]] = []

    def generate(
        self,
        messages: list[ChatMessage],
        stop_sequences: list[str] | None = None,
        response_format: dict[str, str] | None = None,
        tools_to_call_from: list[Any] | None = None,
        **kwargs: Any,
    ) -> ChatMessage:
        del messages, stop_sequences, response_format, kwargs
        self.offered_tool_names.append(tuple(tool.name for tool in (tools_to_call_from or ())))
        if tools_to_call_from is None:
            self.planning_calls += 1
            return ChatMessage(
                role=MessageRole.ASSISTANT,
                content="Use only the authorized tools required by the current request; do not expand the host intent.",
            )
        if self._index < len(self._steps):
            step = self._steps[self._index]
            name = step.tool
            arguments: Any = step.resolved_arguments(self._substitutions)
            note = step.note
        else:
            name = "final_answer"
            arguments = {"answer": "The planned steps could not be completed."}
            note = ""
        self._index += 1
        return ChatMessage(
            role=MessageRole.ASSISTANT,
            content=note or "Executing the next planned step.",
            tool_calls=[
                ChatMessageToolCall(
                    id=f"benchmark-call-{self._index}",
                    type="function",
                    function=ChatMessageToolCallFunction(name=name, arguments=arguments),
                )
            ],
        )


@dataclass(frozen=True, slots=True)
class RunTrace:
    """Everything the scorer needs from one scenario run under one baseline."""

    baseline: Baseline
    scenario_id: str
    final_answer: Any
    steps_attempted: int
    steps_refused: int
    steps_unsupported: int
    planning_steps: int
    active_intent_id: str | None
    decisions: tuple[ObservedDecision, ...]
    detected_values: frozenset[str]
    latencies_ms: tuple[float, ...]
    errors: tuple[str, ...]

    @property
    def any_refusal(self) -> bool:
        return self.steps_refused > 0 or bool(self.errors)

    @property
    def dynamic_intent_bound(self) -> bool:
        return self.active_intent_id is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.value,
            "scenario_id": self.scenario_id,
            "steps_attempted": self.steps_attempted,
            "steps_refused": self.steps_refused,
            "steps_unsupported": self.steps_unsupported,
            "planning_steps": self.planning_steps,
            "active_intent_id": self.active_intent_id,
            "dynamic_intent_bound": self.dynamic_intent_bound,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "detected_value_count": len(self.detected_values),
            "latency_sample_count": len(self.latencies_ms),
            "errors": list(self.errors),
        }


def _looks_refused(observation: str) -> bool:
    return any(marker in observation for marker in REFUSAL_MARKERS)


def _looks_unsupported(observation: str) -> bool:
    return any(marker in observation for marker in UNSUPPORTED_MARKERS)


@dataclass(frozen=True, slots=True)
class _MemorySummary:
    attempted: int
    refused: int
    unsupported: int
    planning_steps: int
    errors: tuple[str, ...]


def _record_agent_memory(agent: Any, world: ScenarioWorld) -> _MemorySummary:
    """Push memory, tool arguments, guarded planning and errors into the oracle."""

    recorder = world.recorder
    attempted = 0
    refused = 0
    unsupported = 0
    planning_steps = 0
    errors: list[str] = []
    for step in getattr(agent.memory, "steps", ()):
        if isinstance(step, PlanningStep):
            planning_steps += 1
            recorder.step_index = planning_steps
            if step.model_input_messages:
                recorder.record(Sink.AGENT_MEMORY, "planning_input", step.model_input_messages)
            if step.plan:
                recorder.record(Sink.AGENT_MEMORY, "planning_output", step.plan)
            continue
        if not isinstance(step, ActionStep):
            continue
        recorder.step_index = step.step_number
        for tool_call in step.tool_calls or ():
            attempted += 1
            recorder.record(
                Sink.TOOL_ARGUMENTS,
                str(tool_call.name),
                tool_call.arguments,
                target=str(tool_call.name),
            )
        if step.model_output:
            recorder.record(Sink.AGENT_MEMORY, "model_output", step.model_output)
        if step.observations:
            recorder.record(Sink.AGENT_MEMORY, "observation", step.observations)
            if _looks_unsupported(step.observations):
                unsupported += 1
            elif _looks_refused(step.observations):
                refused += 1
        if step.action_output is not None:
            recorder.record(Sink.AGENT_MEMORY, "action_output", step.action_output)
        if step.error is not None:
            message = str(step.error)
            errors.append(message)
            recorder.record(Sink.AGENT_MEMORY, "step_error", message)
    recorder.step_index = 0
    return _MemorySummary(
        attempted=attempted,
        refused=refused,
        unsupported=unsupported,
        planning_steps=planning_steps,
        errors=tuple(errors),
    )


class BaselineRuntime(ABC):
    """Run one scenario end to end under one baseline configuration."""

    def __init__(self, config: BaselineConfig, *, detector: Any, transformer: Any) -> None:
        self.config = config
        self.detector = detector
        self.transformer = transformer

    @property
    def baseline(self) -> Baseline:
        return self.config.baseline

    @abstractmethod
    def run(self, scenario: Scenario, world: ScenarioWorld) -> RunTrace:
        """Execute ``scenario`` and return the trace needed for scoring."""

    @staticmethod
    def _finish(
        world: ScenarioWorld,
        answer: Any,
        agent: Any,
        *,
        baseline: Baseline,
        scenario: Scenario,
        capture: BaselineCapture,
    ) -> RunTrace:
        summary = _record_agent_memory(agent, world)
        world.recorder.record(Sink.FINAL_ANSWER, "final_answer", answer)
        world.finalize_artifacts()
        active_intent = getattr(agent, "active_intent", None)
        return RunTrace(
            baseline=baseline,
            scenario_id=scenario.scenario_id,
            final_answer=answer,
            steps_attempted=summary.attempted,
            steps_refused=summary.refused,
            steps_unsupported=summary.unsupported,
            planning_steps=summary.planning_steps,
            active_intent_id=getattr(active_intent, "intent_id", None),
            decisions=tuple(capture.decisions),
            detected_values=frozenset(capture.detected_values),
            latencies_ms=capture.probe.samples_ms,
            errors=summary.errors,
        )


class UnguardedBaselineRuntime(BaselineRuntime):
    """B0, B1 and B2: stock ToolCallingAgent over unguarded tools."""

    def run(self, scenario: Scenario, world: ScenarioWorld) -> RunTrace:
        capture = BaselineCapture()
        tools = build_unguarded_tools(
            world=world,
            baseline=self.config,
            detector=self.detector,
            transformer=self.transformer,
            capture=capture,
        )
        tools.append(FinalAnswerTool())
        agent = ToolCallingAgent(
            tools=tools,
            model=ScriptedPlanner(scenario, world.substitutions),
            max_steps=len(scenario.steps) + 2,
            verbosity_level=LogLevel.OFF,
        )
        answer = agent.run(scenario.task)
        return self._finish(world, answer, agent, baseline=self.baseline, scenario=scenario, capture=capture)


class SensitiveGuardBaselineRuntime(BaselineRuntime):
    """B3/B4: full SensitiveGuard, with B4 enabling dynamic intent/planning."""

    def run(self, scenario: Scenario, world: ScenarioWorld) -> RunTrace:
        capture = BaselineCapture()
        context = PrivacyContext(
            task=scenario.task,
            purpose=scenario.purpose,
            requester=scenario.requester,
            recipient=scenario.recipient,
            source=scenario.source,
            destination=scenario.destination,
            trust_level=scenario.trust_level,
            required_fields=scenario.required_fields,
            optional_fields=scenario.optional_fields,
            forbidden_fields=scenario.forbidden_fields,
            allowed_scope=scenario.allowed_scope,
            run_id=f"bench-{scenario.scenario_id}-{self.baseline.value.lower()}",
        )
        known_destinations: tuple[str, ...] | None = None
        if scenario.known_external_destinations:
            known_destinations = (
                "external_llm",
                "managed_agent",
                "requester",
                *(f"http:{host.lower()}" for host in scenario.allowed_http_hosts),
                *scenario.known_external_destinations,
            )
        runtime = SensitiveGuardRuntime.create(
            context,
            allowed_roots=(world.root,),
            allowed_http_hosts=scenario.allowed_http_hosts,
            allow_http=scenario.allow_http,
            known_external_destinations=known_destinations,
            allow_private_networks=True,
            allowed_database_tables={table: fields for table, fields in scenario.allowed_database_tables.items()},
            default_privacy_budget=scenario.privacy_budget,
            destination_budgets=dict(scenario.destination_budgets) or None,
        )
        recording_detector = RecordingDetector(runtime.detector, capture)
        runtime.detector = recording_detector
        runtime.gateway.detector = recording_detector
        runtime.gateway = RecordingGateway(runtime.gateway, capture)
        runtime.security_reviewer.gateway = runtime.gateway
        tools = runtime.build_tools(
            external_llm_client=world.llm_client,
            http_transport=world.http_transport,
            message_sender=world.message_sender,
            allowed_message_recipients=scenario.allowed_message_recipients,
            database_executor=world.database_executor,
            rag_retriever=world.rag_retriever,
        )
        planner = ScriptedPlanner(scenario, world.substitutions)
        common = {
            "tools": tools,
            "max_steps": len(scenario.steps) + 2,
            "verbosity_level": LogLevel.OFF,
        }
        if self.config.dynamic_intent:
            agent = DynamicSensitiveToolCallingAgent(
                model=planner,
                gateway=runtime.gateway,
                privacy_context=runtime.context,
                model_destination="external_llm",
                intent_resolver=runtime.intent_resolver,
                security_reviewer=runtime.security_reviewer,
                planning_interval=1 if self.config.guarded_planning else None,
                **common,
            )
        else:
            agent = runtime.create_agent(planner, **common)
        answer = agent.run(scenario.task)
        return self._finish(world, answer, agent, baseline=self.baseline, scenario=scenario, capture=capture)


def build_baseline_runtime(
    baseline: Baseline | str,
    *,
    detector: Any | None = None,
    transformer: Any | None = None,
) -> BaselineRuntime:
    """Return the executable runtime for a declared baseline."""

    config = get_baseline(baseline)
    shared_detector = detector if detector is not None else build_default_detector()
    shared_transformer = transformer if transformer is not None else TransformationEngine()
    runtime_class = SensitiveGuardBaselineRuntime if config.safe_tool_gateway else UnguardedBaselineRuntime
    return runtime_class(config, detector=shared_detector, transformer=shared_transformer)


def build_baseline_runtimes(
    baselines: Sequence[Baseline | str] | None = None,
    *,
    detector: Any | None = None,
    transformer: Any | None = None,
) -> tuple[BaselineRuntime, ...]:
    selected = tuple(baselines) if baselines else tuple(Baseline)
    shared_detector = detector if detector is not None else build_default_detector()
    shared_transformer = transformer if transformer is not None else TransformationEngine()
    return tuple(
        build_baseline_runtime(name, detector=shared_detector, transformer=shared_transformer) for name in selected
    )


__all__ = [
    "BaselineRuntime",
    "RunTrace",
    "ScriptedPlanner",
    "SensitiveGuardBaselineRuntime",
    "UnguardedBaselineRuntime",
    "build_baseline_runtime",
    "build_baseline_runtimes",
    "build_default_detector",
]
