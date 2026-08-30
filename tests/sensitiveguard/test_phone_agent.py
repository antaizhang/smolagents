"""Tests for the single-purpose phone detection Agent."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from sensitiveguard import PhoneDetectionAgent, build_ollama_model, detect
from smolagents.memory import ActionStep
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)
from smolagents.monitoring import LogLevel
from smolagents.tools import Tool
from smolagents.utils import AgentParsingError


def _tool_call_message(
    name: str = "detect",
    arguments: dict[str, Any] | None = None,
    *,
    call_id: str = "detect-call",
) -> ChatMessage:
    return ChatMessage(
        role=MessageRole.ASSISTANT,
        content="",
        tool_calls=[
            ChatMessageToolCall(
                id=call_id,
                type="function",
                function=ChatMessageToolCallFunction(name=name, arguments=arguments or {"text": "placeholder"}),
            )
        ],
    )


class ScriptedModel(Model):
    def __init__(self, responses: list[ChatMessage]) -> None:
        super().__init__(model_id="scripted-phone-model")
        self.responses = list(responses)
        self.received_messages: list[list[ChatMessage]] = []
        self.offered_tools: list[tuple[str, ...]] = []
        self.generation_kwargs: list[dict[str, Any]] = []

    def generate(
        self,
        messages: list[ChatMessage],
        stop_sequences: list[str] | None = None,
        response_format: dict[str, str] | None = None,
        tools_to_call_from: list[Tool] | None = None,
        **kwargs: Any,
    ) -> ChatMessage:
        del stop_sequences, response_format
        self.received_messages.append(deepcopy(messages))
        self.offered_tools.append(tuple(tool.name for tool in (tools_to_call_from or ())))
        self.generation_kwargs.append(dict(kwargs))
        if not self.responses:
            raise AssertionError("unexpected model call")
        return self.responses.pop(0)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("客户希望下周再次联系", {"has_phone": False, "count": 0}),
        ("请联系13800138000", {"has_phone": True, "count": 1}),
        ("主号 +86 13800138000，备用 139-0013-9000", {"has_phone": True, "count": 2}),
        ("国际前缀 0086 137 0013 8000", {"has_phone": True, "count": 1}),
        ("非法号段 12800138000", {"has_phone": False, "count": 0}),
        ("长数字 1138001380009", {"has_phone": False, "count": 0}),
    ],
)
def test_detect(text: str, expected: dict[str, bool | int]) -> None:
    result = detect(text=text)
    assert result == expected
    assert "13800138000" not in repr(result)


def test_agent_exposes_one_tool_and_checks_the_complete_original_text() -> None:
    text = "客户完整输入：请联系 13800138000"
    model = ScriptedModel([_tool_call_message(arguments={"text": "模型改写后的错误内容"})])
    agent = PhoneDetectionAgent(model=model, verbosity_level=LogLevel.OFF)

    assert agent.run(text) == {"has_phone": True, "count": 1}
    assert tuple(agent.tools) == ("detect",)
    assert model.offered_tools == [("detect",)]
    assert model.generation_kwargs == [{"tool_choice": "required"}]
    assert len(model.received_messages) == 1
    action_step = next(step for step in agent.memory.steps if isinstance(step, ActionStep))
    assert action_step.tool_calls[0].arguments == {"text": text}


@pytest.mark.parametrize("text", ["", "   "])
def test_agent_rejects_empty_text(text: str) -> None:
    agent = PhoneDetectionAgent(model=ScriptedModel([]), verbosity_level=LogLevel.OFF)
    with pytest.raises(ValueError, match="non-empty"):
        agent.run(text)


@pytest.mark.parametrize(
    "response",
    [
        _tool_call_message(name="final_answer"),
        ChatMessage(
            role=MessageRole.ASSISTANT,
            content="",
            tool_calls=[
                _tool_call_message(call_id="first").tool_calls[0],
                _tool_call_message(call_id="second").tool_calls[0],
            ],
        ),
    ],
)
def test_agent_fails_on_wrong_or_multiple_tool_calls(response: ChatMessage) -> None:
    model = ScriptedModel([response])
    agent = PhoneDetectionAgent(model=model, verbosity_level=LogLevel.OFF)

    with pytest.raises(AgentParsingError, match="detect exactly once"):
        agent.run("请联系 13800138000")
    assert len(model.received_messages) == 1


def test_agent_fails_when_the_model_omits_the_tool_call() -> None:
    response = ChatMessage(role=MessageRole.ASSISTANT, content="I will answer without a tool.")
    model = ScriptedModel([response])
    agent = PhoneDetectionAgent(model=model, verbosity_level=LogLevel.OFF)

    with pytest.raises(AgentParsingError, match="did not call detect"):
        agent.run("请联系 13800138000")
    assert len(model.received_messages) == 1


def test_agent_configuration_cannot_add_tools_or_steps() -> None:
    with pytest.raises(TypeError, match="max_steps, tools"):
        PhoneDetectionAgent(model=ScriptedModel([]), tools=[], max_steps=3)


def test_ollama_defaults_target_the_server_port(monkeypatch: pytest.MonkeyPatch) -> None:
    class StubLiteLLMModel:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    monkeypatch.setattr("smolagents.models.LiteLLMModel", StubLiteLLMModel)
    for name in ("SG_OLLAMA_MODEL", "SG_OLLAMA_API_BASE", "SG_OLLAMA_NUM_CTX", "SG_OLLAMA_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    model = build_ollama_model()

    assert model.kwargs == {
        "model_id": "ollama_chat/qwen3.5:9b",
        "api_base": "http://127.0.0.1:11436",
        "api_key": "ollama",
        "num_ctx": 8192,
    }
