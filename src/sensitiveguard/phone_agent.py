"""A single-purpose Agent for detecting mainland China mobile numbers."""

from __future__ import annotations

import re
from collections.abc import Generator
from typing import Any

from smolagents.agents import ActionOutput, ToolCallingAgent, ToolOutput
from smolagents.memory import ActionStep
from smolagents.monitoring import LogLevel
from smolagents.tools import Tool, tool
from smolagents.utils import AgentGenerationError, AgentParsingError


_MAINLAND_MOBILE_PATTERN = re.compile(r"(?<!\d)(?:(?:\+?86|0086)[ -]?)?1[3-9]\d(?:[ -]?\d){8}(?!\d)")

_PHONE_PROMPT_TEMPLATES = {
    "system_prompt": """
You are a phone-number detection agent.

Call the provided `detect` tool exactly once. Pass the complete user input in
the `text` argument without rewriting, shortening, masking, or summarizing it.
The tool result is the final answer. Do not call any other tool.

Available tool:
{%- for tool in tools.values() %}
- {{ tool.to_tool_calling_prompt() }}
{%- endfor %}
""".strip(),
    "planning": {
        "initial_plan": "",
        "update_plan_pre_messages": "",
        "update_plan_post_messages": "",
    },
    "managed_agent": {"task": "", "report": ""},
    "final_answer": {"pre_messages": "", "post_messages": ""},
}


@tool
def detect(text: str) -> dict[str, Any]:
    """Detect mainland China mobile numbers without returning their raw values.

    Args:
        text: Complete user input to inspect.

    Returns:
        Whether at least one phone number was found and the number of matches.
    """

    count = sum(1 for _ in _MAINLAND_MOBILE_PATTERN.finditer(text))
    return {"has_phone": count > 0, "count": count}


class PhoneDetectionAgent(ToolCallingAgent):
    """A one-step Agent that exposes only the :data:`detect` tool."""

    def __init__(self, *, model: Any, **kwargs: Any) -> None:
        self._source_text = ""
        fixed_options = {
            "add_base_tools",
            "managed_agents",
            "max_steps",
            "max_tool_threads",
            "planning_interval",
            "prompt_templates",
            "stream_outputs",
            "tools",
        }
        conflicts = fixed_options.intersection(kwargs)
        if conflicts:
            names = ", ".join(sorted(conflicts))
            raise TypeError(f"PhoneDetectionAgent fixes these options internally: {names}")
        kwargs.setdefault("verbosity_level", LogLevel.OFF)
        super().__init__(
            tools=[detect],
            model=model,
            prompt_templates=_PHONE_PROMPT_TEMPLATES,
            stream_outputs=False,
            max_tool_threads=1,
            add_base_tools=False,
            managed_agents=None,
            planning_interval=None,
            max_steps=1,
            **kwargs,
        )

    def _setup_tools(self, tools: list[Tool], add_base_tools: bool) -> None:
        if add_base_tools or len(tools) != 1 or tools[0].name != "detect":
            raise ValueError("The phone Agent exposes exactly one tool named detect")
        self.tools = {"detect": tools[0]}

    def run(self, text: str) -> dict[str, bool | int]:
        """Run one model-selected detection call against the complete input text."""

        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        self._source_text = text
        return ToolCallingAgent.run(self, text, max_steps=1)

    def _step_stream(self, memory_step: ActionStep) -> Generator[Any, None, None]:
        input_messages = self.write_memory_to_messages().copy()
        memory_step.model_input_messages = input_messages
        try:
            chat_message = self.model.generate(
                input_messages,
                stop_sequences=["Observation:", "Calling tools:"],
                tools_to_call_from=[detect],
                tool_choice="required",
            )
        except Exception as error:
            raise AgentGenerationError(f"Phone detector model generation failed: {error}", self.logger) from error

        if not chat_message.tool_calls:
            try:
                chat_message = self.model.parse_tool_calls(chat_message)
            except Exception as error:
                raise AgentParsingError("The model did not call detect.", self.logger) from error

        if len(chat_message.tool_calls or ()) != 1 or chat_message.tool_calls[0].function.name != "detect":
            raise AgentParsingError("The model must call detect exactly once.", self.logger)

        # The model chooses the tool, but it cannot rewrite the text being checked.
        chat_message.tool_calls[0].function.arguments = {"text": self._source_text}
        memory_step.model_output_message = chat_message
        memory_step.model_output = chat_message.content
        memory_step.token_usage = chat_message.token_usage

        result: dict[str, bool | int] | None = None
        for output in self.process_tool_calls(chat_message, memory_step):
            yield output
            if isinstance(output, ToolOutput):
                result = output.output
        yield ActionOutput(output=result, is_final_answer=True)

    def _handle_max_steps_reached(self, task: str) -> Any:
        """Fail loudly instead of asking the model for an untrusted fallback answer."""

        del task
        for step in reversed(self.memory.steps):
            if getattr(step, "error", None) is not None:
                raise step.error
        raise AgentParsingError("The model did not complete the detect tool call.", self.logger)


__all__ = ["PhoneDetectionAgent", "detect"]
