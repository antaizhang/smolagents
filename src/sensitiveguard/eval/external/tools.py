"""Trusted bridges between native benchmark tools and smolagents/SensitiveGuard.

A benchmark must keep its original tool names and scorer-visible trajectory.
This module therefore wraps native callables without renaming them while the
trusted host declares each capability's operation, effects and effective route.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sensitiveguard.factory import SensitiveGuardRuntime
from sensitiveguard.intent import Effect, IntentOperation
from sensitiveguard.models import GuardStage, GuardStatus
from sensitiveguard.privacy import PrivacyContext
from sensitiveguard.routing import RouteKind
from sensitiveguard.tools import SensitiveGuardTool
from smolagents import Tool


_JSON_TO_SMOL_TYPE = {
    "string": "string",
    "integer": "integer",
    "number": "number",
    "boolean": "boolean",
    "array": "array",
    "object": "object",
    "null": "null",
}


@dataclass(frozen=True, slots=True)
class ExternalToolSpec:
    """Host-authored security description for one native benchmark tool."""

    name: str
    description: str
    inputs: Mapping[str, Mapping[str, Any]]
    operation: str
    effects: tuple[str, ...] = ()
    destination: str = "internal_benchmark"
    route_kind: str = RouteKind.LOCAL.value
    side_effect: bool = False
    requires_explicit_intent: bool = True
    recipient_argument: str | None = None

    def __post_init__(self) -> None:
        name = str(self.name).strip()
        description = str(self.description).strip()
        operation = str(self.operation).strip().lower()
        destination = str(self.destination).strip().casefold()
        route_kind = str(getattr(self.route_kind, "value", self.route_kind)).strip().lower()
        if not name or not description or not operation or not destination:
            raise ValueError("ExternalToolSpec name, description, operation and destination must not be empty")
        if route_kind not in {item.value for item in RouteKind}:
            raise ValueError(f"Unknown route kind: {self.route_kind}")
        try:
            IntentOperation(operation.upper())
        except ValueError:
            raise ValueError(f"Unknown intent operation: {self.operation}") from None
        for effect in self.effects:
            try:
                Effect(str(effect).strip().upper())
            except ValueError:
                raise ValueError(f"Unknown effect: {effect}") from None
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "destination", destination)
        object.__setattr__(self, "route_kind", route_kind)
        object.__setattr__(self, "effects", tuple(sorted({str(item).strip().upper() for item in self.effects})))
        object.__setattr__(self, "inputs", {str(key): dict(value) for key, value in self.inputs.items()})

    @property
    def external(self) -> bool:
        return self.route_kind in {RouteKind.MESSAGE.value, RouteKind.NETWORK.value, RouteKind.MODEL.value}


@dataclass(slots=True)
class ExternalCallRecorder:
    """Record the arguments that actually crossed the native tool boundary."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    def record(self, name: str, arguments: Mapping[str, Any], result: Any = None) -> None:
        self.calls.append({"name": name, "arguments": dict(arguments), "result": result})


class RawExternalTool(Tool):
    """Unprotected B0 wrapper that executes the benchmark callable verbatim."""

    skip_forward_signature_validation = True

    def __init__(self, spec: ExternalToolSpec, executor: Callable[[dict[str, Any]], Any], recorder=None) -> None:
        self.name = spec.name
        self.description = spec.description
        self.inputs = dict(spec.inputs)
        self.output_type = "any"
        self.spec = spec
        self.executor = executor
        self.recorder = recorder
        super().__init__()

    def forward(self, **kwargs: Any) -> Any:
        result = self.executor(dict(kwargs))
        if self.recorder is not None:
            self.recorder.record(self.name, kwargs, result)
        return result


class SensitiveExternalTool(SensitiveGuardTool):
    """Native benchmark tool executed behind the normal SensitiveGuard permit path."""

    skip_forward_signature_validation = True
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        spec: ExternalToolSpec,
        executor: Callable[[dict[str, Any]], Any],
        gateway: Any,
        context: PrivacyContext,
        recorder: ExternalCallRecorder | None = None,
    ) -> None:
        self.name = spec.name
        self.description = spec.description
        self.inputs = dict(spec.inputs)
        self.output_type = "any"
        self.spec = spec
        self.executor = executor
        self.recorder = recorder

        # Trusted host metadata consumed by CapabilityManifest and PrivacyRouter.
        self.sensitiveguard_operation = spec.operation
        self.sensitiveguard_effects = spec.effects
        self.sensitiveguard_destinations = (spec.destination,)
        self.sensitiveguard_side_effect = spec.side_effect
        self.sensitiveguard_requires_explicit_intent = spec.requires_explicit_intent
        self.sensitiveguard_route_kind = spec.route_kind
        self.sensitiveguard_destination = spec.destination
        self.sensitiveguard_recipient_argument = spec.recipient_argument
        super().__init__(gateway=gateway, context=context)
        self._tracks_execution_outcome = spec.side_effect

    def forward(self, **kwargs: Any) -> Any:
        arguments: Any = dict(kwargs)
        if self.spec.external:
            recipient = None
            if self.spec.recipient_argument:
                raw_recipient = arguments.get(self.spec.recipient_argument)
                recipient = None if raw_recipient is None else str(raw_recipient)
            guarded = self.gateway.guard_payload(
                arguments,
                self.context,
                GuardStage.TOOL_INPUT,
                destination=self.spec.destination,
                recipient=recipient,
                tool_name=self.name,
                record_disclosure=True,
            )
            if not guarded.allowed:
                return self.safe_block(
                    guarded.reason or "The benchmark tool call was blocked by privacy policy.",
                    status=guarded.status,
                )
            arguments = guarded.content
            if not isinstance(arguments, Mapping):
                return self.safe_block(
                    "The protected benchmark arguments are not a mapping.", status=GuardStatus.BLOCKED
                )
            arguments = dict(arguments)

        self.mark_execution_started()
        result = self.executor(dict(arguments))
        self.mark_execution_completed()
        if self.recorder is not None:
            self.recorder.record(self.name, arguments, result)
        return result


def json_schema_to_smol_inputs(schema: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Convert an OpenAI/Pydantic object schema to smolagents Tool.inputs."""

    schema = dict(schema or {})
    properties = schema.get("properties") if isinstance(schema.get("properties"), Mapping) else {}
    required = {str(item) for item in (schema.get("required") or ())}
    result: dict[str, dict[str, Any]] = {}
    for name, raw in properties.items():
        item = dict(raw) if isinstance(raw, Mapping) else {}
        raw_type = item.get("type", "any")
        if isinstance(raw_type, list):
            types = [_JSON_TO_SMOL_TYPE.get(str(value), "any") for value in raw_type]
            smol_type: Any = list(dict.fromkeys(types))
        else:
            smol_type = _JSON_TO_SMOL_TYPE.get(str(raw_type), "any")
        entry: dict[str, Any] = {
            "type": smol_type,
            "description": str(item.get("description") or name),
        }
        if name not in required:
            entry["nullable"] = True
        result[str(name)] = entry
    return result


def callable_to_inputs(function: Callable[..., Any]) -> dict[str, dict[str, Any]]:
    """Best-effort input schema for lightweight benchmark callables."""

    result: dict[str, dict[str, Any]] = {}
    signature = inspect.signature(function)
    for name, parameter in signature.parameters.items():
        if name in {"self", "env", "state"}:
            continue
        annotation = parameter.annotation
        if annotation is str:
            type_name = "string"
        elif annotation is int:
            type_name = "integer"
        elif annotation is float:
            type_name = "number"
        elif annotation is bool:
            type_name = "boolean"
        else:
            type_name = "any"
        entry: dict[str, Any] = {"type": type_name, "description": name}
        if parameter.default is not inspect.Parameter.empty:
            entry["nullable"] = True
        result[name] = entry
    return result


def infer_external_tool_spec(
    name: str,
    description: str,
    inputs: Mapping[str, Mapping[str, Any]],
    *,
    external_names: Sequence[str] = (),
    recipient_argument: str | None = None,
) -> ExternalToolSpec:
    """Conservative host-side profile for common benchmark tool verbs."""

    key = name.casefold()
    external = key in {item.casefold() for item in external_names}
    if external or key.startswith(("send_", "email_", "message_", "post_", "upload_", "publish_", "share_")):
        route = RouteKind.MESSAGE if recipient_argument or "message" in key or "email" in key else RouteKind.NETWORK
        return ExternalToolSpec(
            name=name,
            description=description,
            inputs=inputs,
            operation="send",
            effects=("WRITE", "NETWORK", "EXTERNAL", "MESSAGE")
            if route is RouteKind.MESSAGE
            else ("WRITE", "NETWORK", "EXTERNAL"),
            destination="benchmark_external",
            route_kind=route.value,
            side_effect=True,
            recipient_argument=recipient_argument,
        )
    if key.startswith(("delete_", "remove_", "erase_")):
        return ExternalToolSpec(name, description, inputs, "delete", ("DELETE",), side_effect=True)
    if key.startswith(("read_", "get_", "list_", "lookup_", "fetch_", "search_", "find_")):
        return ExternalToolSpec(name, description, inputs, "read", ("READ",), side_effect=False)
    if key.startswith(("query_", "select_")):
        return ExternalToolSpec(name, description, inputs, "query", ("READ",), side_effect=False)
    if key.startswith(("retrieve_", "rag_")):
        return ExternalToolSpec(name, description, inputs, "retrieve", ("READ",), side_effect=False)
    if key.startswith(("create_", "update_", "set_", "add_", "draft_", "categorize_", "resolve_", "book_", "write_")):
        return ExternalToolSpec(name, description, inputs, "write", ("READ", "WRITE"), side_effect=True)
    return ExternalToolSpec(name, description, inputs, "execute", ("EXECUTE", "READ"), side_effect=True)


def build_external_context(
    task: str,
    specs: Sequence[ExternalToolSpec],
    *,
    purpose: str,
    run_id: str,
    requester: str = "benchmark_harness",
) -> PrivacyContext:
    operations = {spec.operation.upper() for spec in specs}
    capabilities = {spec.name for spec in specs}
    effects = {effect for spec in specs for effect in spec.effects}
    destinations = {"local", "internal", "internal_benchmark", "agent_memory", "requester"}
    destinations.update(spec.destination for spec in specs)
    # final_answer is mandatory infrastructure and not granted by user text.
    return PrivacyContext(
        task=task,
        purpose=purpose,
        requester=requester,
        trust_level="internal",
        allowed_operations=tuple(sorted(operations)),
        allowed_capabilities=tuple(sorted(capabilities)),
        allowed_effects=tuple(sorted(effects)),
        allowed_destinations=tuple(sorted(destinations)),
        run_id=run_id,
    )


def build_external_runtime(context: PrivacyContext, specs: Sequence[ExternalToolSpec]) -> SensitiveGuardRuntime:
    known_destinations = {"external_llm", "requester", "benchmark_external"}
    known_destinations.update(spec.destination for spec in specs if spec.external)
    return SensitiveGuardRuntime.create(context, known_external_destinations=tuple(sorted(known_destinations)))


def build_sensitive_external_tools(
    runtime: SensitiveGuardRuntime,
    bindings: Sequence[tuple[ExternalToolSpec, Callable[[dict[str, Any]], Any]]],
    *,
    recorder: ExternalCallRecorder | None = None,
) -> list[SensitiveExternalTool]:
    return [
        SensitiveExternalTool(
            spec=spec, executor=executor, gateway=runtime.gateway, context=runtime.context, recorder=recorder
        )
        for spec, executor in bindings
    ]


__all__ = [
    "ExternalCallRecorder",
    "ExternalToolSpec",
    "RawExternalTool",
    "SensitiveExternalTool",
    "build_external_context",
    "build_external_runtime",
    "build_sensitive_external_tools",
    "callable_to_inputs",
    "infer_external_tool_spec",
    "json_schema_to_smol_inputs",
]
