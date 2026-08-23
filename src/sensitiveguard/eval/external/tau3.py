"""tau3/tau2 half-duplex Agent bridge preserving the native orchestrator.

Unlike a normal smolagents run, tau3 must execute tools itself so its trajectory
and action evaluator see every action. This adapter therefore uses the
smolagents model for *one next action at a time*, applies SensitiveGuard
preflight/argument guards, returns a native tau2 ToolCall, and commits the
pending lineage operation when tau2 returns the ToolMessage on the next turn.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from sensitiveguard.dynamic_agent import resolve_request_intent
from sensitiveguard.llm import build_ollama_model
from sensitiveguard.models import GuardStage
from smolagents.models import ChatMessage, MessageRole, parse_json_if_needed

from .tools import (
    RawExternalTool,
    build_external_context,
    build_external_runtime,
    build_sensitive_external_tools,
    infer_external_tool_spec,
    json_schema_to_smol_inputs,
)


@dataclass
class _TauState:
    native_messages: list[Any] = field(default_factory=list)
    safe_history: list[tuple[str, str]] = field(default_factory=list)
    runtime: Any = None
    guarded_tools: dict[str, Any] = field(default_factory=dict)
    specs: dict[str, Any] = field(default_factory=dict)
    active_intent: Any = None
    pending_reviews: dict[str, tuple[Any, Any]] = field(default_factory=dict)


def _content_text(message: Any) -> str:
    value = getattr(message, "content", None)
    return "" if value is None else str(value)


def _schema_tools(tau_tools: list[Any]):
    schema_tools = []
    specs = []
    for tool in tau_tools:
        function = tool.openai_schema.get("function", {})
        name = str(function.get("name") or tool.name)
        description = str(function.get("description") or name)
        inputs = json_schema_to_smol_inputs(function.get("parameters") or {})
        spec = infer_external_tool_spec(name, description, inputs)
        specs.append(spec)
        schema_tools.append(RawExternalTool(spec, lambda arguments: arguments))
    return schema_tools, specs


def build_tau_agent_class():
    """Create the tau2 HalfDuplexAgent subclass lazily (tau2 is optional)."""

    try:
        from tau2.agent.base_agent import HalfDuplexAgent
        from tau2.data_model.message import AssistantMessage, MultiToolMessage, ToolCall, ToolMessage, UserMessage
    except ImportError as error:
        raise RuntimeError("tau3 integration requires a tau2-bench v1.0.1 environment (Python 3.12+)") from error

    class SensitiveGuardTauAgent(HalfDuplexAgent[_TauState]):
        def __init__(self, tools, domain_policy, *, runtime_label="B4", model=None, **kwargs):
            del kwargs
            super().__init__(tools=tools, domain_policy=domain_policy)
            self.runtime_label = str(runtime_label).upper()
            if self.runtime_label not in {"B0", "B3", "B4"}:
                raise ValueError("tau3 runtime must be B0, B3, or B4")
            self.model = model or build_ollama_model()
            self.schema_tools, self.tool_specs = _schema_tools(tools)

        @property
        def system_prompt(self) -> str:
            return (
                "You are a customer service agent. In each turn either reply to the user or call tools, not both. "
                "Follow the domain policy exactly.\n\n<policy>\n" + self.domain_policy + "\n</policy>"
            )

        def get_init_state(self, message_history=None):
            state = _TauState()
            for message in message_history or []:
                state.native_messages.append(message)
                state.safe_history.append((str(getattr(message, "role", "unknown")), _content_text(message)))
            return state

        def _ensure_runtime(self, state: _TauState, user_request: str) -> None:
            if self.runtime_label == "B0" or state.runtime is not None:
                return
            context = build_external_context(
                user_request,
                self.tool_specs,
                purpose="tau3_agent_utility_evaluation",
                run_id=f"tau3-{self.runtime_label.lower()}-{id(state)}",
            )
            runtime = build_external_runtime(context, self.tool_specs)
            bindings = [(spec, lambda arguments: arguments) for spec in self.tool_specs]
            guarded = build_sensitive_external_tools(runtime, bindings)
            runtime.security_reviewer.register_tools(guarded)
            state.runtime = runtime
            state.guarded_tools = {tool.name: tool for tool in guarded}
            state.specs = {spec.name: spec for spec in self.tool_specs}
            parent = runtime.intent_resolver.resolve(context)
            if self.runtime_label == "B4":
                state.active_intent = resolve_request_intent(
                    runtime.intent_resolver,
                    context,
                    user_request,
                    parent=parent,
                    capability_operations={spec.name: spec.operation for spec in self.tool_specs},
                )
            else:
                state.active_intent = parent

        def _ingest_tool_message(self, state: _TauState, message: Any) -> str:
            content = _content_text(message)
            if self.runtime_label == "B0" or state.runtime is None:
                return content
            pending = state.pending_reviews.pop(str(message.id), None)
            if pending is not None:
                review, tool = pending
                if getattr(message, "error", False):
                    state.runtime.security_reviewer.fail(
                        review,
                        state.runtime.context,
                        indeterminate=bool(getattr(tool.spec, "side_effect", False)),
                    )
                else:
                    state.runtime.security_reviewer.complete(review, content, state.runtime.context)
            guarded = state.runtime.gateway.guard_text(
                content,
                state.runtime.context,
                GuardStage.TOOL_OUTPUT,
                destination="agent_memory",
                tool_name="tau3_tool_output",
                record_disclosure=False,
            )
            return str(guarded.content) if guarded.allowed else "[Tool output withheld by SensitiveGuard]"

        def _safe_user_text(self, state: _TauState, text: str) -> str:
            if self.runtime_label == "B0" or state.runtime is None:
                return text
            guarded = state.runtime.gateway.guard_text(
                text,
                state.runtime.context,
                GuardStage.TOOL_INPUT,
                destination="local",
                tool_name="tau3_user_message",
                record_disclosure=False,
            )
            return str(guarded.content) if guarded.allowed else "[User message blocked by SensitiveGuard]"

        def _model_messages(self, state: _TauState) -> list[ChatMessage]:
            transcript = "\n".join(f"{role.upper()}: {text}" for role, text in state.safe_history)
            return [
                ChatMessage(role=MessageRole.SYSTEM, content=self.system_prompt),
                ChatMessage(role=MessageRole.USER, content=transcript + "\n\nReturn the next response or tool call."),
            ]

        def _guard_tool_call(self, state: _TauState, chat_call: Any):
            name = str(chat_call.function.name)
            arguments = parse_json_if_needed(chat_call.function.arguments or {})
            if not isinstance(arguments, dict):
                return None, "Tool arguments were not a JSON object."
            call_id = str(chat_call.id or f"sg-tau-{len(state.pending_reviews) + 1}")
            if self.runtime_label == "B0":
                return ToolCall(id=call_id, name=name, arguments=arguments, requestor="assistant"), None
            tool = state.guarded_tools.get(name)
            spec = state.specs.get(name)
            if tool is None or spec is None:
                return None, "The model requested an unregistered tool."
            destination = spec.destination if spec.external else "internal_benchmark"
            guarded = state.runtime.gateway.guard_payload(
                arguments,
                state.runtime.context,
                GuardStage.TOOL_INPUT,
                destination=destination,
                recipient=str(arguments.get(spec.recipient_argument))
                if spec.recipient_argument and arguments.get(spec.recipient_argument)
                else None,
                tool_name=name,
                record_disclosure=spec.external,
            )
            if not guarded.allowed or not isinstance(guarded.content, dict):
                return None, guarded.reason or "SensitiveGuard blocked the tool arguments."
            safe_arguments = dict(guarded.content)
            review = state.runtime.security_reviewer.preflight(
                tool,
                safe_arguments,
                state.runtime.context,
                state.active_intent,
            )
            if not review.allowed or not state.runtime.security_reviewer.consume(
                review,
                tool,
                safe_arguments,
                state.runtime.context,
                state.active_intent,
            ):
                return None, "SensitiveGuard deterministic security review blocked the tool call."
            state.pending_reviews[call_id] = (review, tool)
            return ToolCall(id=call_id, name=name, arguments=safe_arguments, requestor="assistant"), None

        def generate_next_message(self, message, state):
            if isinstance(message, MultiToolMessage):
                for tool_message in message.tool_messages:
                    state.native_messages.append(tool_message)
                    state.safe_history.append(("tool", self._ingest_tool_message(state, tool_message)))
            elif isinstance(message, ToolMessage):
                state.native_messages.append(message)
                state.safe_history.append(("tool", self._ingest_tool_message(state, message)))
            else:
                assert isinstance(message, UserMessage)
                text = _content_text(message)
                self._ensure_runtime(state, text)
                state.native_messages.append(message)
                state.safe_history.append(("user", self._safe_user_text(state, text)))

            response = self.model.generate(self._model_messages(state), tools_to_call_from=self.schema_tools)
            if response.tool_calls:
                native_calls = []
                block_reason = None
                for call in response.tool_calls:
                    native, reason = self._guard_tool_call(state, call)
                    if native is not None:
                        native_calls.append(native)
                    elif block_reason is None:
                        block_reason = reason
                if native_calls:
                    assistant = AssistantMessage(role="assistant", content=None, tool_calls=native_calls)
                else:
                    assistant = AssistantMessage(
                        role="assistant", content=block_reason or "The requested action was blocked."
                    )
            else:
                candidate = _content_text(response)
                if self.runtime_label != "B0" and state.runtime is not None:
                    guarded = state.runtime.gateway.guard_text(
                        candidate,
                        state.runtime.context,
                        GuardStage.FINAL_OUTPUT,
                        destination="requester",
                        tool_name="tau3_final_answer",
                        record_disclosure=True,
                    )
                    candidate = (
                        str(guarded.content) if guarded.allowed else "The answer was withheld by privacy policy."
                    )
                assistant = AssistantMessage(role="assistant", content=candidate)
            state.native_messages.append(assistant)
            state.safe_history.append(
                ("assistant", _content_text(assistant) if not assistant.tool_calls else "[tool call]")
            )
            return assistant, state

    return SensitiveGuardTauAgent


def create_tau_agent(tools, domain_policy, **kwargs):
    """tau2 registry-compatible agent factory."""

    runtime_label = kwargs.pop("sensitiveguard_runtime", os.environ.get("SG_TAU_RUNTIME", "B4"))
    kwargs.pop("llm", None)
    kwargs.pop("llm_args", None)
    cls = build_tau_agent_class()
    return cls(tools, domain_policy, runtime_label=runtime_label, model=build_ollama_model(), **kwargs)


def register_tau_agent(name: str = "sensitiveguard") -> None:
    try:
        from tau2.registry import registry
    except ImportError as error:
        raise RuntimeError("tau3 integration requires tau2-bench v1.0.1") from error
    if registry.get_agent_factory(name) is None:
        registry.register_agent_factory(create_tau_agent, name)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    args, remainder = parser.parse_known_args()
    os.environ["SG_TAU_RUNTIME"] = args.runtime
    register_tau_agent()
    from tau2.cli import main as tau_main

    sys.argv = ["tau2", *remainder]
    tau_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_tau_agent_class", "create_tau_agent", "register_tau_agent"]
