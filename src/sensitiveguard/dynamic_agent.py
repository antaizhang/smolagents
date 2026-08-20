"""Dynamic request-intent binding and guarded explicit planning for SensitiveGuard."""

from __future__ import annotations

import re
import time
from typing import Any

from sensitiveguard.agent.sensitive_agent import SensitiveToolCallingAgent
from sensitiveguard.intent import IntentOperation, IntentSpec
from sensitiveguard.intent.resolver import _CAPABILITIES_BY_OPERATION, _EFFECTS_BY_OPERATION
from sensitiveguard.models import GuardStage
from smolagents.agents import ToolCallingAgent, populate_template
from smolagents.memory import FinalAnswerStep, PlanningStep
from smolagents.models import ChatMessage, MessageRole
from smolagents.monitoring import LogLevel, Timing
from smolagents.utils import AgentGenerationError


_TRANSFORM_FORMS = re.compile(r"\b(masked|masking|redacted|redacting|sanitized|sanitizing)\b", re.IGNORECASE)


def resolve_request_intent(
    resolver: Any,
    context: Any,
    request_text: str,
    *,
    parent: IntentSpec | None = None,
) -> IntentSpec:
    """Bind the current user request to a signed child intent.

    The trusted host intent remains the authorization ceiling. The user prompt
    can only narrow that ceiling; it can never grant a new operation,
    capability, effect, field, destination, or recipient.
    """

    if not isinstance(request_text, str) or not request_text.strip():
        raise ValueError("request_text must be a non-empty string")

    host_intent = parent or resolver.resolve(
        context,
        version=getattr(context, "intent_version", 1),
    )
    requested_operations = set(resolver._infer_operations(request_text))
    if _TRANSFORM_FORMS.search(request_text):
        requested_operations.add(IntentOperation.TRANSFORM)

    # If the request has no recognizable operation, preserve compatibility by
    # creating a signed child with exactly the same host ceiling.
    if not requested_operations:
        return resolver.narrow(host_intent)

    effective_operations = tuple(
        sorted(
            requested_operations & set(host_intent.allowed_operations),
            key=lambda item: item.value,
        )
    )

    requested_capabilities: set[str] = set()
    requested_effects: set[Any] = set()
    for operation in requested_operations:
        requested_capabilities.update(_CAPABILITIES_BY_OPERATION[operation])
        requested_effects.update(_EFFECTS_BY_OPERATION[operation])

    effective_capabilities = tuple(
        sorted(set(host_intent.allowed_capabilities) & requested_capabilities)
    )
    effective_effects = tuple(
        sorted(
            set(host_intent.allowed_effects) & requested_effects,
            key=lambda item: item.value,
        )
    )

    return resolver.narrow(
        host_intent,
        allowed_operations=effective_operations,
        allowed_capabilities=effective_capabilities,
        allowed_effects=effective_effects,
    )


class DynamicSensitiveToolCallingAgent(SensitiveToolCallingAgent):
    """SensitiveGuard Agent with prompt-bound intent and guarded PlanningStep.

    Security model:

        trusted host intent (ceiling)
              INTERSECT
        operations inferred from current guarded user request
              -> signed child intent
              -> guarded explicit plan
              -> normal SensitiveGuard tool preflight/permit/lineage path
    """

    def __init__(self, *, planning_interval: int | None = 1, **kwargs: Any) -> None:
        if planning_interval is not None and (
            isinstance(planning_interval, bool)
            or not isinstance(planning_interval, int)
            or planning_interval < 1
        ):
            raise ValueError("planning_interval must be a positive integer or None")

        # The base SensitiveGuard class intentionally rejects periodic planning.
        # Build it in its safe default mode first, then enable only this class's
        # guarded _generate_planning_step implementation.
        super().__init__(planning_interval=None, **kwargs)
        self.planning_interval = planning_interval
        self._host_intent: IntentSpec | None = None

    @property
    def host_intent(self) -> IntentSpec | None:
        return self._host_intent

    @property
    def active_intent(self) -> IntentSpec | None:
        return self._active_intent

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
            raise ValueError("DynamicSensitiveToolCallingAgent requires an OCR/vision guard before accepting images")

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

        self._host_intent = None
        self._active_intent = None
        try:
            self._host_intent = self.intent_resolver.resolve(
                self.privacy_context,
                version=getattr(self.privacy_context, "intent_version", 1),
            )
            self._active_intent = resolve_request_intent(
                self.intent_resolver,
                self.privacy_context,
                str(guarded_task.content),
                parent=self._host_intent,
            )
        except Exception:
            return self._blocked_run_result(stream, "The trusted request intent could not be established.")

        if self.model_endpoint_id is not None:
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

        # Bypass SensitiveToolCallingAgent.run(), because that method would
        # replace the child intent with the broader host intent. All action/tool
        # execution still goes through this class's inherited guarded methods.
        return ToolCallingAgent.run(
            self,
            guarded_task.content,
            stream=stream,
            reset=reset,
            images=None,
            additional_args=safe_args,
            max_steps=max_steps,
            return_full_result=return_full_result,
        )

    def _generate_planning_step(self, task: str, is_first_step: bool, step: int):
        """Generate a real PlanningStep and guard it before log/memory exposure."""

        start_time = time.time()
        if is_first_step:
            input_messages = [
                ChatMessage(
                    role=MessageRole.USER,
                    content=[
                        {
                            "type": "text",
                            "text": populate_template(
                                self.prompt_templates["planning"]["initial_plan"],
                                variables={
                                    "task": task,
                                    "tools": self.tools,
                                    "managed_agents": self.managed_agents,
                                },
                            ),
                        }
                    ],
                )
            ]
        else:
            memory_messages = self.write_memory_to_messages(summary_mode=True)
            plan_update_pre = ChatMessage(
                role=MessageRole.SYSTEM,
                content=[
                    {
                        "type": "text",
                        "text": populate_template(
                            self.prompt_templates["planning"]["update_plan_pre_messages"],
                            variables={"task": task},
                        ),
                    }
                ],
            )
            plan_update_post = ChatMessage(
                role=MessageRole.USER,
                content=[
                    {
                        "type": "text",
                        "text": populate_template(
                            self.prompt_templates["planning"]["update_plan_post_messages"],
                            variables={
                                "task": task,
                                "tools": self.tools,
                                "managed_agents": self.managed_agents,
                                "remaining_steps": self.max_steps - step,
                            },
                        ),
                    }
                ],
            )
            input_messages = [plan_update_pre] + memory_messages + [plan_update_post]

        try:
            plan_message = self.model.generate(input_messages, stop_sequences=["<end_plan>"])
        except Exception:
            raise AgentGenerationError("Protected planning generation failed.", self.logger) from None

        guarded_plan = self.gateway.guard_payload(
            plan_message.content or "",
            self.privacy_context,
            GuardStage.MEMORY,
            destination="agent_memory",
            tool_name="planning_output",
            record_disclosure=False,
        )
        safe_plan_content = (
            guarded_plan.content
            if guarded_plan.allowed
            else "[Planning output withheld by privacy policy]"
        )

        if is_first_step:
            plan = f"Here is the guarded plan of action:\n```\n{safe_plan_content}\n```"
            title = "Guarded initial plan"
        else:
            plan = f"Here is the guarded updated plan of action:\n```\n{safe_plan_content}\n```"
            title = "Guarded updated plan"

        self.logger.log_markdown(content=plan, title=title, level=LogLevel.INFO)
        yield PlanningStep(
            model_input_messages=input_messages,
            plan=plan,
            model_output_message=ChatMessage(
                role=MessageRole.ASSISTANT,
                content=safe_plan_content,
                raw=None,
                token_usage=plan_message.token_usage,
            ),
            token_usage=plan_message.token_usage,
            timing=Timing(start_time=start_time, end_time=time.time()),
        )


def create_dynamic_agent(runtime: Any, model: Any, *, planning_interval: int | None = 1, **agent_kwargs: Any):
    """Create a dynamic SensitiveGuard agent from an existing runtime."""

    return DynamicSensitiveToolCallingAgent(
        model=model,
        tools=runtime.build_tools(),
        gateway=runtime.gateway,
        privacy_context=runtime.context,
        model_destination=agent_kwargs.pop("model_destination", "external_llm"),
        model_endpoint_id=agent_kwargs.pop("model_endpoint_id", None),
        intent_resolver=runtime.intent_resolver,
        security_reviewer=runtime.security_reviewer,
        planning_interval=planning_interval,
        **agent_kwargs,
    )


__all__ = [
    "DynamicSensitiveToolCallingAgent",
    "create_dynamic_agent",
    "resolve_request_intent",
]
