#!/usr/bin/env python3
"""Replay one public sample through SensitiveGuard baselines B0-B4.

This is an offline teaching walkthrough.  It uses the deterministic fixture
runner in ``sensitiveguard.eval.external.walkthrough``; it does not replace the
benchmarks' native runners or official scorers.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from sensitiveguard.eval.baselines import get_baseline
from sensitiveguard.eval.external.walkthrough import BASELINES, WalkthroughCase, load_cases, run_case


BENCHMARKS = ("agentdojo", "privacylens", "bfcl", "tau3")


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _canonical_benchmark(value: str) -> str:
    return value.casefold().replace("τ", "tau").replace("³", "3").replace("-", "")


def _event(kind: str, **payload: Any) -> dict[str, Any]:
    return {"event": kind, **_jsonable(payload)}


def _events_for(case: WalkthroughCase, baseline: str) -> list[dict[str, Any]]:
    result = run_case(case, baseline)
    events = [
        _event(
            "sample",
            benchmark=case.benchmark,
            benchmark_version=case.benchmark_version,
            sample_id=case.sample_id,
            source_url=case.source_url,
            license=case.license,
            task=case.task,
            purpose=case.purpose,
        ),
        _event("oracle", oracle=case.oracle),
        _event("baseline_config", baseline=baseline, config=get_baseline(baseline).to_dict()),
        _event("plan", baseline=baseline, plan=case.plan),
        _event(
            "intent",
            baseline=baseline,
            intent_binding=result.intent_binding,
            host_intent=result.host_intent,
            request_intent=result.request_intent,
        ),
    ]

    detections_by_tool: dict[str, list[dict[str, Any]]] = {}
    for detection in result.detections:
        detections_by_tool.setdefault(str(detection.get("tool", "")), []).append(detection)
    transforms_by_tool: dict[str, list[dict[str, Any]]] = {}
    for transformation in result.transformations:
        transforms_by_tool.setdefault(str(transformation.get("tool", "")), []).append(transformation)
    memory_actions = [step for step in result.memory_steps if step.get("tool_calls")]

    remaining_executed = list(result.executed_calls)
    count = max(len(case.steps), len(result.proposed_calls))
    for index in range(count):
        fixture_step = case.steps[index] if index < len(case.steps) else None
        proposed = result.proposed_calls[index] if index < len(result.proposed_calls) else None
        tool_name = ""
        if proposed:
            tool_name = str(proposed.get("name", ""))
        elif fixture_step is not None:
            tool_name = fixture_step.tool
        executed = next(
            (call for call in remaining_executed if str(call.get("name", "")) == tool_name),
            None,
        )
        if executed is not None:
            remaining_executed.remove(executed)
        memory_step = memory_actions[index] if index < len(memory_actions) else None
        memory_call = None if memory_step is None else memory_step["tool_calls"][0]
        native_result = None if executed is None else executed.get("result")
        events.append(
            _event(
                "tool_step",
                baseline=baseline,
                step=index + 1,
                tool=tool_name,
                proposed_arguments=None if proposed is None else proposed.get("arguments"),
                detections=detections_by_tool.get(tool_name, []),
                transformations=transforms_by_tool.get(tool_name, []),
                executed_arguments=None if executed is None else executed.get("arguments"),
                memory_arguments=None if memory_call is None else memory_call.get("arguments"),
                native_result=native_result,
                observation=native_result if memory_step is None else memory_step.get("observations"),
                memory_error=None if memory_step is None else memory_step.get("error"),
                expected_observation=None if fixture_step is None else fixture_step.observation,
                executed=executed is not None,
                note="" if fixture_step is None else fixture_step.note,
            )
        )

    for executed in remaining_executed:
        events.append(
            _event(
                "unexpected_execution",
                baseline=baseline,
                tool=executed.get("name"),
                executed_arguments=executed.get("arguments"),
                native_result=executed.get("result"),
            )
        )

    events.append(_event("memory_trace", baseline=baseline, steps=result.memory_steps))
    events.extend(
        _event("guard_decision", baseline=baseline, decision=decision) for decision in result.guard_decisions
    )
    events.extend(
        [
            _event(
                "final_output",
                baseline=baseline,
                output=result.final_answer,
                detections=detections_by_tool.get("final_answer", []),
                transformations=transforms_by_tool.get("final_answer", []),
            ),
            _event("score", baseline=baseline, score=result.score),
        ]
    )
    return events


def _pause() -> None:
    if not sys.stdin.isatty():
        return
    sys.stderr.write("按 Enter 查看下一事件…")
    sys.stderr.flush()
    sys.stdin.readline()


def _print_human(event: Mapping[str, Any]) -> None:
    title = str(event["event"]).replace("_", " ").upper()
    baseline = event.get("baseline")
    suffix = f" · {baseline}" if baseline else ""
    print(f"\n{'=' * 78}\n{title}{suffix}\n{'=' * 78}")
    body = {key: value for key, value in event.items() if key not in {"event", "baseline"}}
    print(json.dumps(body, ensure_ascii=False, indent=2, sort_keys=False))


def _select_cases(cases: Iterable[WalkthroughCase], benchmark: str) -> list[WalkthroughCase]:
    selected = list(cases)
    if benchmark != "all":
        wanted = _canonical_benchmark(benchmark)
        selected = [case for case in selected if _canonical_benchmark(case.benchmark) == wanted]
    if not selected:
        raise SystemExit(f"没有找到 benchmark={benchmark!r} 的固定样本")
    return selected


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="逐事件回放 AgentDojo、PrivacyLens、BFCL 或 tau3 的单样本 B0-B4 评估。"
    )
    parser.add_argument(
        "--benchmark",
        choices=(*BENCHMARKS, "all"),
        default="all",
        help="选择评估集；默认 all。",
    )
    parser.add_argument(
        "--baseline",
        action="append",
        choices=BASELINES,
        help="选择基线，可重复传入；未指定时依次运行 B0-B4。",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="交互终端中每个事件后等待按 Enter；非交互输入时自动忽略。",
    )
    parser.add_argument(
        "--json-output",
        metavar="PATH",
        type=Path,
        help="将所有样本和基线的完整事件数组写入一个 JSON 文件。",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    baselines = list(dict.fromkeys(args.baseline or BASELINES))
    cases = _select_cases(load_cases(), args.benchmark)
    all_events: list[dict[str, Any]] = []

    for case in cases:
        comparison_rows = []
        for baseline in baselines:
            events = _events_for(case, baseline)
            all_events.extend(events)
            tool_events = [event for event in events if event["event"] == "tool_step"]
            score_event = next(event for event in events if event["event"] == "score")
            comparison_rows.append(
                {
                    "baseline": baseline,
                    "executed_tools": [event["tool"] for event in tool_events if event["executed"]],
                    "blocked_tools": [event["tool"] for event in tool_events if not event["executed"]],
                    "score": score_event["score"],
                }
            )
            for event in events:
                _print_human(event)
                if args.pause:
                    _pause()
        comparison = _event(
            "case_comparison",
            benchmark=case.benchmark,
            sample_id=case.sample_id,
            rows=comparison_rows,
        )
        all_events.append(comparison)
        _print_human(comparison)
        if args.pause:
            _pause()

    if args.json_output is not None:
        output = args.json_output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            json.dump(all_events, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        print(f"\nJSON 事件已写入: {output}")


if __name__ == "__main__":
    main()
