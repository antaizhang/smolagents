"""Inspect AgentThreatBench integration with its native dual-metric scorer.

The official dataset loader, store initialization, tools and scorer remain
unchanged. This module replaces only Inspect's ``generate(tool_calls='loop')``
solver with a smolagents/SensitiveGuard solver and writes executed tool calls
back to ``TaskState.messages`` for the native scorer.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

from sensitiveguard.dynamic_agent import create_dynamic_agent
from sensitiveguard.llm import build_ollama_model
from smolagents import ToolCallingAgent
from smolagents.default_tools import FinalAnswerTool
from smolagents.monitoring import LogLevel

from .tools import (
    ExternalCallRecorder,
    RawExternalTool,
    build_external_context,
    build_external_runtime,
    build_sensitive_external_tools,
    infer_external_tool_spec,
    json_schema_to_smol_inputs,
)


def _message_text(message: Any) -> str:
    value = getattr(message, "text", None)
    if isinstance(value, str):
        return value
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    return str(content)


def build_agent_threat_solver(model: Any, *, runtime_label: str = "B4"):
    """Build an Inspect Solver that executes AgentThreatBench with SensitiveGuard."""

    try:
        from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelOutput
        from inspect_ai.solver import solver
        from inspect_ai.tool import ToolCall, parse_tool_info
    except ImportError as error:
        raise RuntimeError("AgentThreatBench integration requires `pip install inspect-ai inspect-evals`") from error

    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("AgentThreatBench runtime must be B0, B3, or B4")

    @solver
    def sensitiveguard_solver():
        async def solve(state, generate):
            del generate
            task = next((_message_text(item) for item in reversed(state.messages) if item.role == "user"), "Run task")
            instructions = "\n\n".join(_message_text(item) for item in state.messages if item.role == "system")
            recorder = ExternalCallRecorder()
            bindings = []
            raw_tools = []
            for native_tool in state.tools:
                info = parse_tool_info(native_tool)
                schema = info.parameters.model_dump(exclude_none=True)
                inputs = json_schema_to_smol_inputs(schema)
                recipient = "recipient" if "recipient" in inputs else None
                spec = infer_external_tool_spec(
                    info.name,
                    info.description or info.name,
                    inputs,
                    recipient_argument=recipient,
                )

                def execute(arguments, *, _tool=native_tool):
                    return asyncio.run(_tool(**arguments))

                bindings.append((spec, execute))
                raw_tools.append(RawExternalTool(spec, execute, recorder=recorder))

            def run_agent():
                if label == "B0":
                    agent = ToolCallingAgent(
                        tools=[*raw_tools, FinalAnswerTool()],
                        model=model,
                        instructions=instructions or None,
                        max_steps=12,
                        verbosity_level=LogLevel.OFF,
                    )
                else:
                    specs = [spec for spec, _ in bindings]
                    context = build_external_context(
                        task,
                        specs,
                        purpose="agent_threat_bench_security_evaluation",
                        run_id=f"agent-threat-{label.lower()}-{state.sample_id}",
                    )
                    runtime = build_external_runtime(context, specs)
                    tools = build_sensitive_external_tools(runtime, bindings, recorder=recorder)
                    if label == "B4":
                        agent = create_dynamic_agent(
                            runtime,
                            model,
                            tools=tools,
                            planning_interval=1,
                            model_destination="local",
                            instructions=instructions or None,
                            max_steps=12,
                            verbosity_level=LogLevel.OFF,
                        )
                    else:
                        agent = runtime.create_agent(
                            model,
                            tools=tools,
                            model_destination="local",
                            instructions=instructions or None,
                            max_steps=12,
                            verbosity_level=LogLevel.OFF,
                        )
                return agent.run(task)

            answer = await asyncio.to_thread(run_agent)
            if recorder.calls:
                calls = [
                    ToolCall(
                        id=f"sg-{index}",
                        function=str(call["name"]),
                        arguments=dict(call["arguments"]),
                    )
                    for index, call in enumerate(recorder.calls, start=1)
                ]
                state.messages.append(ChatMessageAssistant(content=None, tool_calls=calls))
            final_message = ChatMessageAssistant(content=str(answer))
            state.messages.append(final_message)
            state.output = ModelOutput(
                model=f"sensitiveguard/{label.lower()}",
                choices=[ChatCompletionChoice(message=final_message)],
            )
            return state

        return solve

    return sensitiveguard_solver()


def build_agent_threat_tasks(model: Any, *, runtime_label: str = "B4", difficulty: str | None = None):
    """Return the three official AgentThreatBench Tasks with our solver swapped in."""

    try:
        from inspect_ai import Task
        from inspect_ai.solver import system_message
        from inspect_evals.agent_threat_bench.agent_threat_bench import (
            AUTONOMY_HIJACK_SYSTEM_PROMPT,
            DATA_EXFIL_SYSTEM_PROMPT,
            EVAL_VERSION,
            MEMORY_POISON_SYSTEM_PROMPT,
        )
        from inspect_evals.agent_threat_bench.dataset import load_agent_threat_bench_dataset
        from inspect_evals.agent_threat_bench.scorer import agent_threat_bench_scorer
        from inspect_evals.agent_threat_bench.tools import use_agent_threat_bench_tools
    except ImportError as error:
        raise RuntimeError("AgentThreatBench integration requires `pip install inspect-ai inspect-evals`") from error

    guarded_solver = build_agent_threat_solver(model, runtime_label=runtime_label)
    definitions = (
        ("memory_poison", MEMORY_POISON_SYSTEM_PROMPT),
        ("autonomy_hijack", AUTONOMY_HIJACK_SYSTEM_PROMPT),
        ("data_exfil", DATA_EXFIL_SYSTEM_PROMPT),
    )
    return [
        Task(
            dataset=load_agent_threat_bench_dataset(task_name=name, difficulty=difficulty),
            solver=[system_message(prompt), use_agent_threat_bench_tools(task_name=name), guarded_solver],
            scorer=agent_threat_bench_scorer(),
            max_messages=20,
            version=EVAL_VERSION.comparability_version,
            metadata=EVAL_VERSION.to_metadata(),
        )
        for name, prompt in definitions
    ]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external.agent_threat_bench")
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    parser.add_argument("--difficulty", choices=("easy", "medium", "hard"), default=None)
    parser.add_argument("--log-dir", type=Path, default=Path("reports/agent-threat-bench"))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        from inspect_ai import eval_set
    except ImportError as error:
        raise RuntimeError("AgentThreatBench integration requires `pip install inspect-ai inspect-evals`") from error
    tasks = build_agent_threat_tasks(build_ollama_model(), runtime_label=args.runtime, difficulty=args.difficulty)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    # The Inspect model is not used by our solver. mockllm supplies TaskState's
    # model contract while qwen3.5:9b is invoked through smolagents/LiteLLM.
    eval_set(tasks, model="mockllm/model", log_dir=str(args.log_dir))
    print(f"AgentThreatBench native Inspect logs: {args.log_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_agent_threat_solver", "build_agent_threat_tasks"]
