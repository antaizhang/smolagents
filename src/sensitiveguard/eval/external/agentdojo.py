"""AgentDojo integration that keeps AgentDojo's native task suite and scorer.

The only component replaced is the agent pipeline under test. AgentDojo still
owns environment construction, attack injection, utility checks and security
checks. Tool names are preserved so its native trajectory scorer remains valid.
"""

from __future__ import annotations

import argparse
import json
import os
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
    for candidate in (
        "recipient",
        "recipients",
        "to",
        "email",
        "email_address",
        "user",
        "user_id",
        "channel",
        "channel_id",
    ):
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


def _build_agent_trace(agent: Any, recorder: ExternalCallRecorder, *, runtime_label: str, query: Any, answer: Any):
    """Build a small serializable trace for examples without replacing AgentDojo's native log."""

    steps = []
    proposed_calls = []
    for step in getattr(getattr(agent, "memory", None), "steps", ()):
        calls = []
        for call in getattr(step, "tool_calls", None) or ():
            serialized = {
                "name": str(getattr(call, "name", "")),
                "arguments": _serialize_native(getattr(call, "arguments", None) or {}),
                "id": str(getattr(call, "id", "") or ""),
            }
            calls.append(serialized)
            proposed_calls.append(serialized)
        steps.append(
            {
                "type": type(step).__name__,
                "plan": _serialize_native(getattr(step, "plan", None)),
                "model_output": _serialize_native(getattr(step, "model_output", None)),
                "tool_calls": calls,
                "observations": _serialize_native(getattr(step, "observations", None)),
                "action_output": _serialize_native(getattr(step, "action_output", None)),
                "error": _serialize_native(getattr(step, "error", None)),
            }
        )

    host_intent = getattr(agent, "host_intent", None)
    active_intent = getattr(agent, "active_intent", None)
    return {
        "runtime": runtime_label,
        "query": str(query),
        "host_intent": _serialize_native(host_intent.to_dict()) if host_intent is not None else None,
        "active_intent": _serialize_native(active_intent.to_dict()) if active_intent is not None else None,
        "steps": steps,
        "proposed_calls": proposed_calls,
        "executed_calls": _serialize_native(recorder.calls),
        "final_answer": _serialize_native(answer),
    }


def build_agentdojo_pipeline(model: Any, *, runtime_label: str = "B4", model_destination: str = "local"):
    """Return an AgentDojo BasePipelineElement backed by smolagents/SensitiveGuard."""

    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.logging import Logger
        from agentdojo.types import text_content_block_from_string
    except ImportError as error:
        raise RuntimeError("AgentDojo integration requires `pip install agentdojo==0.1.35`") from error

    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("AgentDojo runtime must be B0, B3, or B4")

    class SensitiveGuardAgentDojoPipeline(BasePipelineElement):
        name = f"smolagents-sensitiveguard-{label.lower()}"
        last_trace: dict[str, Any] | None = None

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
            self.last_trace = _build_agent_trace(agent, recorder, runtime_label=label, query=query, answer=answer)
            Logger.get().log(native_messages)
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
    attacked_model_name: str = "Local model",
) -> dict[str, Any]:
    """Execute AgentDojo and return its native utility/security results."""

    try:
        from agentdojo.attacks import load_attack
        from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
        from agentdojo.logging import OutputLogger
        from agentdojo.models import MODEL_NAMES
        from agentdojo.task_suite.load_suites import get_suite
    except ImportError as error:
        raise RuntimeError("AgentDojo integration requires `pip install agentdojo==0.1.35`") from error

    suite = get_suite(benchmark_version, suite_name)
    pipeline = build_agentdojo_pipeline(model, runtime_label=runtime_label)

    # ImportantInstructions / ToolKnowledge 攻击会拿 pipeline.name 去 MODEL_NAMES 里做子串匹配，
    # 取出注入文本中 {model} 占位符的值。自定义 pipeline 名不在表里，所以先登记一次。
    # MODEL_NAMES 是模块级 dict，base_attacks 和 important_instructions_attacks 绑定的是同一个对象，
    # 原地修改对两边都生效，且不改动 pipeline.name，日志目录和断点续跑不受影响。
    MODEL_NAMES.setdefault("smolagents-sensitiveguard", attacked_model_name)

    # AgentDojo 的 TraceLogger 从当前 logger 上下文里取 logdir 决定轨迹落盘位置。
    # 官方 CLI 用 OutputLogger 建立这个上下文；直接调 benchmark 时必须自己建，
    # 否则 Logger.get() 返回未初始化的 NullLogger，取 .logdir 会 AttributeError。
    # 这里传的路径必须与下方 logdir= 一致，否则轨迹写到一处、断点续跑的检查读另一处。
    with OutputLogger(str(logdir) if logdir is not None else None):
        if attack_name in (None, "none"):
            # 无攻击基线：报表里"无攻击 utility"那一列，用于衡量 B3/B4 的防护代价。
            # 轨迹落在 logdir/pipeline/suite/<user_task>/none/none.json，与受攻击的跑法不冲突。
            result = benchmark_suite_without_injections(
                pipeline,
                suite,
                logdir=logdir,
                force_rerun=force_rerun,
                user_tasks=user_tasks,
                benchmark_version=benchmark_version,
            )
        else:
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
    parser.add_argument(
        "--attack",
        default="tool_knowledge",
        help="AgentDojo 攻击名；传 none 则跑无攻击基线（只出 utility）",
    )
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--user-task", action="append")
    parser.add_argument("--injection-task", action="append")
    parser.add_argument("--logdir", type=Path, default=Path("reports/agentdojo"))
    parser.add_argument("--output", type=Path, default=Path("reports/agentdojo-result.json"))
    parser.add_argument(
        "--attacked-model-name",
        default="Local model",
        help="注入文本中 {model} 占位符的取值，默认与 AgentDojo 官方本地模型一档一致",
    )
    parser.add_argument(
        "--think",
        action="store_true",
        help="开启模型自带推理模式，默认关闭以保证 B0/B3/B4 对比干净",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    # 固定采样：ollama 默认 temperature 0.8 会让 B0/B3/B4 之间的差异被噪声淹没。
    # think 默认关闭：模型自带的推理会与 B4 的 planning 重叠，并显著拉长耗时。
    model_kwargs: dict[str, Any] = {"temperature": 0.0, "think": args.think}

    native = run_agentdojo(
        runtime_label=args.runtime,
        model=build_ollama_model(**model_kwargs),
        suite_name=args.suite,
        attack_name=args.attack,
        benchmark_version=args.benchmark_version,
        user_tasks=args.user_task,
        injection_tasks=args.injection_task,
        logdir=args.logdir,
        attacked_model_name=args.attacked_model_name,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(native, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 把解析后的实验条件写一份 sidecar，避免几十小时后对不上当时的参数。
    config_path = args.output.parent / (args.output.stem + ".config.json")
    config_path.write_text(
        json.dumps(
            {
                "runtime": args.runtime,
                "suite": args.suite,
                "attack": args.attack,
                "benchmark_version": args.benchmark_version,
                "attacked_model_name": args.attacked_model_name,
                "user_tasks": args.user_task,
                "injection_tasks": args.injection_task,
                "model_kwargs": model_kwargs,
                "sg_ollama_model": os.environ.get("SG_OLLAMA_MODEL"),
                "sg_ollama_api_base": os.environ.get("SG_OLLAMA_API_BASE"),
                "sg_ollama_num_ctx": os.environ.get("SG_OLLAMA_NUM_CTX"),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps(native, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_agentdojo_pipeline", "run_agentdojo"]
