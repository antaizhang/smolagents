"""A smolagents ToolCallingAgent whose observable channels are guarded first."""

from __future__ import annotations

import re
import time
from collections.abc import Generator, Mapping
from typing import Any

from sensitiveguard.memory import MemoryGuard
from sensitiveguard.models import GuardStage
from sensitiveguard.runtime.error_model import SensitiveGuardError
from sensitiveguard.tools import FinalAnswerGuardTool, SensitiveGuardTool
from sensitiveguard.tools.base import ToolExecutionOutcome
from smolagents.agents import ActionOutput, ToolCallingAgent, ToolOutput
from smolagents.memory import ActionStep, FinalAnswerStep, ToolCall
from smolagents.models import ChatMessage, MessageRole, parse_json_if_needed
from smolagents.monitoring import LogLevel, Timing
from smolagents.tools import validate_tool_arguments
from smolagents.utils import (
    AgentExecutionError,
    AgentGenerationError,
    AgentMaxStepsError,
    AgentParsingError,
    AgentToolCallError,
    AgentToolExecutionError,
)

from .prompts import SENSITIVEGUARD_INSTRUCTIONS


_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")


class _AgentMemoryGuard(MemoryGuard):
    """Avoid reclassifying trusted messages already guarded before model I/O."""

    def sanitize_step(self, memory_step: Any, *, context: Any | None = None, agent: Any | None = None) -> Any:
        model_inputs = getattr(memory_step, "model_input_messages", None)
        if hasattr(memory_step, "model_input_messages"):
            memory_step.model_input_messages = None
        try:
            return super().sanitize_step(memory_step, context=context, agent=agent)
        finally:
            if hasattr(memory_step, "model_input_messages"):
                memory_step.model_input_messages = model_inputs


class SensitiveToolCallingAgent(ToolCallingAgent):
    """ToolCallingAgent with pre-log task, call, observation and answer guards.

    Model token streaming and unmanaged sub-agents are deliberately disabled:
    partial tokens and raw handoffs cannot be reliably classified before they
    become observable. The outer ``run(stream=True)`` API remains supported and
    yields only sanitized events.
    """

    def __init__(
        self,
        *,
        model: Any,
        tools: list[SensitiveGuardTool],
        gateway: Any,
        privacy_context: Any,
        model_destination: str = "external_llm",
        model_endpoint_id: str | None = None,
        intent_resolver: Any | None = None,
        security_reviewer: Any | None = None,
        instructions: str | None = None,
        **kwargs: Any,
    ) -> None:
        if kwargs.pop("stream_outputs", False):
            raise ValueError("Model token streaming is unsafe because partial deltas cannot be pre-scanned")
        managed_agents = kwargs.pop("managed_agents", None)
        if managed_agents:
            raise ValueError("Use SensitiveGuard HandoffGuard instead of unguarded managed_agents")
        planning_interval = kwargs.pop("planning_interval", None)
        if planning_interval is not None:
            raise ValueError("Periodic planning output is disabled until it can be guarded before streaming")
        if kwargs.pop("add_base_tools", False):
            raise ValueError("Base tools cannot be added to SensitiveToolCallingAgent")
        if kwargs.pop("max_tool_threads", 1) not in {None, 1}:
            raise ValueError("SensitiveToolCallingAgent executes guarded calls sequentially")
        if intent_resolver is None or security_reviewer is None:
            raise ValueError(
                "SensitiveToolCallingAgent requires the runtime intent resolver and security reviewer; "
                "construct it through SensitiveGuardRuntime.create_agent()."
            )
        if getattr(security_reviewer, "gateway", None) is not gateway:
            raise ValueError("The security reviewer is bound to a different SensitiveGuard gateway")
        if getattr(security_reviewer, "context", None) is not privacy_context:
            raise ValueError("The security reviewer is bound to a different privacy context")
        if any(not isinstance(tool, SensitiveGuardTool) for tool in tools):
            raise TypeError("Every exposed tool must inherit SensitiveGuardTool")
        if any(tool.gateway is not gateway or tool.context is not privacy_context for tool in tools):
            raise ValueError("Every exposed tool must be bound to this Agent's exact gateway and privacy context")
        if any(tool.name == "final_answer" and not isinstance(tool, FinalAnswerGuardTool) for tool in tools):
            raise TypeError("The final_answer tool must be FinalAnswerGuardTool")

        memory_guard = _AgentMemoryGuard(gateway, privacy_context)
        user_callbacks = kwargs.pop("step_callbacks", None)
        callback_map: dict[type, list[Any]] = {
            ActionStep: [memory_guard],
            FinalAnswerStep: [memory_guard],
        }
        if isinstance(user_callbacks, list):
            callback_map[ActionStep].extend(user_callbacks)
        elif isinstance(user_callbacks, dict):
            for step_type, callbacks in user_callbacks.items():
                callback_map.setdefault(step_type, []).extend(
                    callbacks if isinstance(callbacks, list) else [callbacks]
                )
        elif user_callbacks is not None:
            raise TypeError("step_callbacks must be a list or a mapping by memory-step type")

        guarded_tools = list(tools)
        if not any(tool.name == "final_answer" for tool in guarded_tools):
            guarded_tools.append(FinalAnswerGuardTool(gateway=gateway, context=privacy_context))
        secure_instructions = SENSITIVEGUARD_INSTRUCTIONS
        if instructions:
            secure_instructions += f"\n\nAdditional trusted host instructions:\n{instructions}"

        self.gateway = gateway
        self.privacy_context = privacy_context
        self.model_destination = model_destination
        self.model_endpoint_id = model_endpoint_id
        self.intent_resolver = intent_resolver
        self.security_reviewer = security_reviewer
        self._active_intent = None
        if self.security_reviewer is not None:
            self.security_reviewer.register_tools(guarded_tools)
        super().__init__(
            tools=guarded_tools,
            model=model,
            instructions=secure_instructions,
            stream_outputs=False,
            max_tool_threads=1,
            add_base_tools=False,
            managed_agents=None,
            planning_interval=None,
            step_callbacks=callback_map,
            **kwargs,
        )

    def run(
        self,
        task: str,
        stream: bool = False,
        reset: bool = True,
        images: list[Any] | None = None,
        additional_args: dict[str, Any] | None = None,
        max_steps: int | None = None,
        return_full_result: bool | None = None,
    ) -> Any:
        if images:
            raise ValueError("SensitiveToolCallingAgent requires an OCR/vision guard before accepting images")
        if self.intent_resolver is not None:
            self._active_intent = None
            try:
                self._active_intent = self.intent_resolver.resolve(
                    self.privacy_context,
                    version=getattr(self.privacy_context, "intent_version", 1),
                )
            except Exception:
                return self._blocked_run_result(stream, "The trusted intent could not be established.")
        guarded_task = self.gateway.guard_text(
            task,
            self.privacy_context,
            GuardStage.TOOL_INPUT,
            destination=self.model_destination,
            tool_name="agent_task",
            record_disclosure=self.model_destination != "local",
        )
        if not guarded_task.allowed:
            return self._blocked_run_result(stream, guarded_task.reason)
        if self.model_endpoint_id is not None:
            if self.security_reviewer is None:
                return self._blocked_run_result(stream, "The configured model route cannot be verified.")
            route = self.security_reviewer.router.route_model(
                guarded_task.detection,
                operation="model_inference",
                preferred_endpoint=self.model_endpoint_id,
                allow_external_fallback=False,
            )
            if (
                not route.allowed
                or route.endpoint_id != self.model_endpoint_id
                or route.destination != self.model_destination
            ):
                return self._blocked_run_result(stream, "The configured model route is not authorized.")

        safe_args = None
        if additional_args:
            guarded_args = self.gateway.guard_payload(
                additional_args,
                self.privacy_context,
                GuardStage.TOOL_INPUT,
                destination=self.model_destination,
                tool_name="agent_additional_args",
                record_disclosure=self.model_destination != "local",
            )
            if not guarded_args.allowed:
                return self._blocked_run_result(stream, guarded_args.reason)
            safe_args = guarded_args.content

        return super().run(
            guarded_task.content,
            stream=stream,
            reset=reset,
            images=None,
            additional_args=safe_args,
            max_steps=max_steps,
            return_full_result=return_full_result,
        )

    @staticmethod
    def _blocked_run_result(stream: bool, reason: str | None) -> Any:
        answer = reason or "The task was blocked by the active privacy policy."
        if stream:
            return iter((FinalAnswerStep(output=answer),))
        return answer

    def _step_stream(self, memory_step: ActionStep) -> Generator[ToolCall | ToolOutput | ActionOutput, None, None]:
        input_messages = self.write_memory_to_messages().copy()
        memory_step.model_input_messages = input_messages
        generation_failed = False
        try:
            chat_message: ChatMessage = self.model.generate(
                input_messages,
                stop_sequences=["Observation:", "Calling tools:"],
                tools_to_call_from=self.tools_and_managed_agents,
            )
        except Exception:
            generation_failed = True
        if generation_failed:
            raise AgentGenerationError("Protected model generation failed.", self.logger) from None

        parsing_failed = False
        try:
            if not chat_message.tool_calls:
                chat_message = self.model.parse_tool_calls(chat_message)
            if not chat_message.tool_calls:
                raise ValueError("No structured tool call")
            for tool_call in chat_message.tool_calls:
                tool_call.function.arguments = parse_json_if_needed(tool_call.function.arguments)
        except Exception:
            # Provider messages can contain raw tool arguments. Drop the local
            # reference before creating the public exception traceback.
            chat_message = None  # type: ignore[assignment]
            parsing_failed = True
        if parsing_failed:
            raise AgentParsingError(
                "The model did not return a valid structured safe-tool call.",
                self.logger,
            ) from None

        guarded_rationale = self.gateway.guard_payload(
            chat_message.content or "",
            self.privacy_context,
            GuardStage.MEMORY,
            destination="agent_memory",
            tool_name="model_output",
            record_disclosure=False,
        )
        safe_rationale: Any = (
            guarded_rationale.content if guarded_rationale.allowed else "[Model output withheld by privacy policy]"
        )
        memory_step.model_output = safe_rationale
        memory_step.model_output_message = ChatMessage(
            role=MessageRole.ASSISTANT,
            content=safe_rationale,
            tool_calls=None,
            raw=None,
            token_usage=chat_message.token_usage,
        )
        memory_step.token_usage = chat_message.token_usage
        self.logger.log_markdown(
            content=str(safe_rationale),
            title="Guarded output message of the LLM:",
            level=LogLevel.DEBUG,
        )

        final_answer: Any = None
        got_final_answer = False
        for output in self.process_tool_calls(chat_message, memory_step):
            yield output
            if isinstance(output, ToolOutput) and output.is_final_answer:
                if len(chat_message.tool_calls) != 1 or got_final_answer:
                    raise AgentExecutionError(
                        "A final answer must be the only safe-tool call in its step.", self.logger
                    )
                final_answer = output.output
                got_final_answer = True
        yield ActionOutput(output=final_answer, is_final_answer=got_final_answer)

    def process_tool_calls(
        self, chat_message: ChatMessage, memory_step: ActionStep
    ) -> Generator[ToolCall | ToolOutput, None, None]:
        assert chat_message.tool_calls is not None
        public_calls: list[ToolCall] = []
        observations: list[str] = []

        for index, chat_tool_call in enumerate(chat_message.tool_calls, start=1):
            raw_name = chat_tool_call.function.name
            known_safe = raw_name in self.tools and isinstance(self.tools[raw_name], SensitiveGuardTool)
            public_name = raw_name if known_safe and _SAFE_TOOL_NAME.fullmatch(raw_name) else "rejected_tool"
            public_id = f"sg_call_{memory_step.step_number}_{index}"
            raw_arguments = chat_tool_call.function.arguments or {}
            recorded_arguments = self.gateway.guard_payload(
                raw_arguments,
                self.privacy_context,
                GuardStage.MEMORY,
                destination="agent_memory",
                tool_name=public_name,
                record_disclosure=False,
            )
            safe_arguments = (
                recorded_arguments.content
                if recorded_arguments.allowed
                else {"status": "WITHHELD", "reason": "Tool arguments contain non-persistable data."}
            )
            public_call = ToolCall(name=public_name, arguments=safe_arguments, id=public_id)
            public_calls.append(public_call)
            memory_step.tool_calls = public_calls
            yield public_call

            if not known_safe:
                memory_step.tool_calls = public_calls
                raise AgentToolExecutionError("An unknown or unsafe tool call was rejected.", self.logger)

            tool = self.tools[raw_name]
            is_final_answer = raw_name == "final_answer"
            if is_final_answer:
                # ``final_answer`` is constructor-enforced to be a
                # FinalAnswerGuardTool. Clear the prior decision so a reused
                # agent cannot accidentally trust a result from an older run.
                assert isinstance(tool, FinalAnswerGuardTool)
                tool.last_guard_result = None
            result = self.execute_tool_call(raw_name, raw_arguments)
            if is_final_answer:
                # FinalAnswerGuardTool already guarded the complete recursive
                # payload at FINAL_OUTPUT. A second generic TOOL_OUTPUT pass can
                # reinterpret generated placeholders (for example PERSON_0001)
                # as fresh PII and fail transformation verification.
                if tool.last_guard_result is None:
                    raise AgentToolExecutionError("The final answer guard did not produce a decision.", self.logger)
                safe_result = result
            else:
                guarded_result = self.gateway.guard_payload(
                    result,
                    self.privacy_context,
                    GuardStage.TOOL_OUTPUT,
                    destination="agent_memory",
                    tool_name=raw_name,
                    record_disclosure=False,
                )
                safe_result = (
                    guarded_result.content
                    if guarded_result.allowed
                    else {
                        "status": guarded_result.status.value,
                        "reason": guarded_result.reason or "Tool output was withheld by privacy policy.",
                    }
                )
            observation = str(safe_result).strip()
            observations.append(observation)
            tool_output = ToolOutput(
                id=public_id,
                output=safe_result,
                is_final_answer=is_final_answer,
                observation=observation,
                tool_call=public_call,
            )
            yield tool_output

        memory_step.tool_calls = public_calls
        memory_step.observations = "\n".join(observations) if observations else None

    def execute_tool_call(self, tool_name: str, arguments: dict[str, Any] | str) -> Any:
        tool = self.tools.get(tool_name)
        if not isinstance(tool, SensitiveGuardTool):
            raise AgentToolExecutionError("An unknown or unsafe tool call was rejected.", self.logger)
        try:
            self.gateway.authorization.authorize_tool(tool_name)
        except SensitiveGuardError:
            raise AgentToolExecutionError("The safe tool is outside the host-authorized scope.", self.logger) from None
        safe_state_arguments = self._substitute_state_variables(arguments)
        invalid_arguments = False
        try:
            validate_tool_arguments(tool, safe_state_arguments)
        except Exception:
            invalid_arguments = True
        if invalid_arguments:
            arguments = {}
            safe_state_arguments = {}
            raise AgentToolCallError(
                "The safe-tool arguments did not match its declared schema.",
                self.logger,
            ) from None

        if not tool.handles_sensitive_input:
            guarded_arguments = self.gateway.guard_payload(
                safe_state_arguments,
                self.privacy_context,
                GuardStage.TOOL_INPUT,
                destination="internal",
                tool_name=tool_name,
                record_disclosure=False,
            )
            if not guarded_arguments.allowed:
                arguments = {}
                safe_state_arguments = {}
                raise AgentToolExecutionError(
                    "Safe-tool arguments were blocked before execution.",
                    self.logger,
                ) from None
            safe_state_arguments = guarded_arguments.content

        review = None
        if self.security_reviewer is not None:
            if self._active_intent is None:
                arguments = {}
                safe_state_arguments = {}
                raise AgentToolExecutionError(
                    "The tool call has no active trusted intent.",
                    self.logger,
                ) from None
            try:
                review = self.security_reviewer.preflight(
                    tool,
                    safe_state_arguments,
                    self.privacy_context,
                    self._active_intent,
                )
                permitted = review.allowed and self.security_reviewer.consume(
                    review,
                    tool,
                    safe_state_arguments,
                    self.privacy_context,
                    self._active_intent,
                )
            except Exception:
                permitted = False
            if not permitted:
                arguments = {}
                safe_state_arguments = {}
                raise AgentToolExecutionError(
                    "The tool call failed deterministic security review.",
                    self.logger,
                ) from None

        execution_failed = False
        tool_result: Any = None
        tool.reset_execution_outcome()
        try:
            if isinstance(safe_state_arguments, dict):
                tool_result = tool(**safe_state_arguments, sanitize_inputs_outputs=False)
            else:
                tool_result = tool(safe_state_arguments, sanitize_inputs_outputs=False)
        except Exception:
            execution_failed = True
        if execution_failed:
            if review is not None:
                try:
                    manifest = self.security_reviewer.manifests.get(tool_name)
                    self.security_reviewer.fail(review, self.privacy_context, indeterminate=manifest.side_effect)
                except Exception:
                    pass
            arguments = {}
            safe_state_arguments = {}
            tool_result = None
            raise AgentToolExecutionError(
                "A protected tool failed without exposing its arguments.",
                self.logger,
            ) from None
        if review is not None:
            result_status = self._protected_result_status(tool_result)
            if result_status in {
                "APPROVAL_REQUIRED",
                "BLOCKED",
                "FAILED",
                "INCOMPLETE",
                "SKIPPED",
                "WITHHELD",
            }:
                manifest = self.security_reviewer.manifests.get(tool_name)
                outcome = tool.execution_outcome
                if outcome is ToolExecutionOutcome.COMPLETED:
                    recorded = self.security_reviewer.complete(review, tool_result, self.privacy_context)
                else:
                    possibly_started = manifest.side_effect and (
                        outcome in {ToolExecutionOutcome.STARTED, ToolExecutionOutcome.UNKNOWN}
                        or (
                            result_status not in {"APPROVAL_REQUIRED", "SKIPPED"} and not tool.tracks_execution_outcome
                        )
                    )
                    recorded = self.security_reviewer.fail(
                        review,
                        self.privacy_context,
                        indeterminate=possibly_started,
                    )
            else:
                recorded = self.security_reviewer.complete(review, tool_result, self.privacy_context)
            if not recorded:
                arguments = {}
                safe_state_arguments = {}
                tool_result = None
                raise AgentToolExecutionError(
                    "The protected tool outcome could not be committed to data lineage.",
                    self.logger,
                ) from None
        return tool_result

    @staticmethod
    def _protected_result_status(result: Any) -> str | None:
        if not isinstance(result, Mapping):
            return None
        value = result.get("status")
        if value is None:
            return None
        return str(getattr(value, "value", value)).strip().upper()

    def _handle_max_steps_reached(self, task: str) -> Any:
        start_time = time.time()
        try:
            message = super().provide_final_answer(task)
            candidate = message.content
            token_usage = message.token_usage
        except Exception:
            candidate = "The agent reached its step limit without a safe final answer."
            token_usage = None
        guarded = self.gateway.guard_payload(
            candidate,
            self.privacy_context,
            GuardStage.FINAL_OUTPUT,
            destination="requester",
            recipient=self.privacy_context.requester,
            tool_name="max_steps_final_answer",
            record_disclosure=True,
        )
        final_answer = (
            guarded.content
            if guarded.allowed
            else "The fallback answer was withheld because it violates the active privacy policy."
        )
        final_memory_step = ActionStep(
            step_number=self.step_number,
            error=AgentMaxStepsError("Reached max steps.", self.logger),
            timing=Timing(start_time=start_time, end_time=time.time()),
            token_usage=token_usage,
            action_output=final_answer,
        )
        self._finalize_step(final_memory_step)
        self.memory.steps.append(final_memory_step)
        return final_answer


SensitiveDataAgent = SensitiveToolCallingAgent
