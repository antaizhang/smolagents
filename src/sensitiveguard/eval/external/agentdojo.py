"""AgentDojo integration that keeps AgentDojo's native task suite and scorer.

The only component replaced is the agent pipeline under test. AgentDojo still
owns environment construction, attack injection, utility checks and security
checks. Tool names are preserved so its native trajectory scorer remains valid.
"""

from __future__ import annotations

import argparse
import json
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


def _recipient_argument(inputs: dict[str, Any]) -> str | None:
    for candidate in ("recipient", "to", "email", "email_address", "user", "user_id", "channel", "channel_id"):
        if candidate in inputs:
            return candidate
    return None


def _serialize_native(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(key, tuple):
                key = "/".join(str(part) for part in key)
            else:
                key = str(key)
            result[key] = _serialize_native(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_serialize_native(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "model_dump"):
        return _serialize_native(value.model_dump())
    return str(value)


def build_agentdojo_pipeline(model: Any, *, runtime_label: str = "B4", model_destination: str = "local"):
    """Return an AgentDojo BasePipelineElement backed by smolagents/SensitiveGuard."""

    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import text_content_block_from_string
    except ImportError as error:
        raise RuntimeError("AgentDojo integration requires `pip install agentdojo==0.1.35`") from error

    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("AgentDojo runtime must be B0, B3, or B4")

    class SensitiveGuardAgentDojoPipeline(BasePipelineElement):
        name = f"smolagents-sensitiveguard-{label.lower()}"

        def query(self, query, runtime, env, messages=(), extra_args=None):
            del messages
            bindings = []
            raw_tools = []
            recorder = ExternalCallRecorder()
            for function in runtime.functions.values():
                schema = function.parameters.model_json_schema()
                inputs = json_schema_to_smol_inputs(schema)
                recipient = _recipient_argument(inputs)
                spec = infer_external_tool_spec(
                    function.name,
                    function.description or function.name,
                    inputs,
                    recipient_argument=recipient,
                )

                def execute(arguments, *, _name=function.name):
                    result, error = runtime.run_function(env, _name, arguments)
                    return f"{error}" if error else result

                bindings.append((spec, execute))
                raw_tools.append(RawExternalTool(spec, execute, recorder=recorder))

            if label == "B0":
                agent = ToolCallingAgent(
                    tools=[*raw_tools, FinalAnswerTool()],
                    model=model,
                    max_steps=12,
                    verbosity_level=LogLevel.OFF,
                )
            else:
                specs = [spec for spec, _ in bindings]
                context = build_external_context(
                    query,
                    specs,
                    purpose="agentdojo_security_benchmark",
                    run_id=f"agentdojo-{label.lower()}-{id(env)}",
                )
                sg_runtime = build_external_runtime(context, specs)
                guarded_tools = build_sensitive_external_tools(sg_runtime, bindings, recorder=recorder)
                if label == "B4":
                    agent = create_dynamic_agent(
                        sg_runtime,
                        model,
                        tools=guarded_tools,
                        planning_interval=1,
                        model_destination=model_destination,
                        max_steps=12,
                        verbosity_level=LogLevel.OFF,
                    )
                else:
                    agent = sg_runtime.create_agent(
                        model,
                        tools=guarded_tools,
                        model_destination=model_destination,
                        max_steps=12,
                        verbosity_level=LogLevel.OFF,
                    )

            answer = agent.run(query)
            native_messages = [
                {"role": "user", "content": [text_content_block_from_string(str(query))]},
            ]
            for step in getattr(agent.memory, "steps", ()):
                calls = getattr(step, "tool_calls", None) or ()
                if not calls:
                    continue
                native_calls = [
                    FunctionCall(function=str(call.name), args=dict(call.arguments or {}), id=str(call.id or ""))
                    for call in calls
                    if str(call.name) != "final_answer"
                ]
                if native_calls:
                    native_messages.append({"role": "assistant", "content": None, "tool_calls": native_calls})
            native_messages.append(
                {
                    "role": "assistant",
                    "content": [text_content_block_from_string(str(answer))],
                    "tool_calls": None,
                }
            )
            metadata = dict(extra_args or {})
            metadata["sensitiveguard_runtime"] = label
            metadata["sensitiveguard_executed_calls"] = recorder.calls
            return str(answer), runtime, env, native_messages, metadata

    return SensitiveGuardAgentDojoPipeline()


def run_agentdojo(
    *,
    runtime_label: str,
    model: Any,
    suite_name: str = "workspace",
    attack_name: str = "tool_knowledge",
    benchmark_version: str = "v1.2.2",
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
    logdir: Path | None = None,
    force_rerun: bool = False,
) -> dict[str, Any]:
    """Execute AgentDojo and return its native utility/security results."""

    try:
        from agentdojo.attacks import load_attack
        from agentdojo.benchmark import benchmark_suite_with_injections
        from agentdojo.task_suite.load_suites import get_suite
    except ImportError as error:
        raise RuntimeError("AgentDojo integration requires `pip install agentdojo==0.1.35`") from error

    suite = get_suite(benchmark_version, suite_name)
    pipeline = build_agentdojo_pipeline(model, runtime_label=runtime_label)
    attack = load_attack(attack_name, suite, pipeline)
    result = benchmark_suite_with_injections(
        pipeline,
        suite,
        attack,
        logdir=logdir,
        force_rerun=force_rerun,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
        benchmark_version=benchmark_version,
    )
    return _serialize_native(dict(result))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external.agentdojo")
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--attack", default="tool_knowledge")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--user-task", action="append")
    parser.add_argument("--injection-task", action="append")
    parser.add_argument("--logdir", type=Path, default=Path("reports/agentdojo"))
    parser.add_argument("--output", type=Path, default=Path("reports/agentdojo-result.json"))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    native = run_agentdojo(
        runtime_label=args.runtime,
        model=build_ollama_model(),
        suite_name=args.suite,
        attack_name=args.attack,
        benchmark_version=args.benchmark_version,
        user_tasks=args.user_task,
        injection_tasks=args.injection_task,
        logdir=args.logdir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(native, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(native, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_agentdojo_pipeline", "run_agentdojo"]
