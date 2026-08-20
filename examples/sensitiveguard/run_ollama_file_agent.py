"""End-to-end SensitiveGuard run with dynamic intent and guarded planning.

Flow:
    prompt + input file
        -> trusted host PrivacyContext
        -> prompt-derived request intent (host ceiling ∩ current request)
        -> guarded PlanningStep
        -> guarded tool action
        -> guarded observation
        -> repeat until guarded final answer
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

from smolagents.memory import ActionStep, FinalAnswerStep, PlanningStep

from sensitiveguard import SensitiveGuardRuntime, build_ollama_model
from sensitiveguard.dynamic_agent import create_dynamic_agent
from sensitiveguard.privacy import PrivacyContext

SAMPLE_NOTE = (
    "工单备注\n"
    "客户: 张三\n"
    "手机: 13800138000\n"
    "身份证: 440101199001011234\n"
    "银行卡: 6222020200001234567\n"
    "登录口令: demo-secret-\n"
    "购买商品: MacBook Pro\n"
    "诉求: 申请发票并寄送到公司前台。\n"
)


def _prepare_input_file(root: Path, override: str | None) -> Path:
    if override:
        path = Path(override).resolve()
        if not path.is_file():
            raise SystemExit(f"input file not found: {path}")
        return path
    path = root / "ticket_note.txt"
    path.write_text(SAMPLE_NOTE, encoding="utf-8")
    return path


def _print_intent(agent: Any) -> None:
    print("\n" + "=" * 78)
    print("动态意图 (host ceiling -> request intent)")
    print("=" * 78)
    if agent.host_intent is not None:
        print("HOST operations:", [item.value for item in agent.host_intent.allowed_operations])
        print("HOST capabilities:", list(agent.host_intent.allowed_capabilities))
    if agent.active_intent is not None:
        print("REQUEST operations:", [item.value for item in agent.active_intent.allowed_operations])
        print("REQUEST capabilities:", list(agent.active_intent.allowed_capabilities))
        print("parent_intent_id:", agent.active_intent.parent_intent_id)


def _print_trajectory(agent: Any) -> None:
    print("\n" + "=" * 78)
    print("完整轨迹 (plan -> act -> observation)")
    print("=" * 78)
    step_no = 0
    for step in agent.memory.steps:
        if isinstance(step, PlanningStep):
            print(f"\n[计划 PLAN]\n{step.plan.strip()}")
            continue
        if isinstance(step, ActionStep):
            step_no += 1
            print(f"\n───── 第 {step_no} 步 ─────")
            if step.model_output:
                print(f"[推理/计划]\n{str(step.model_output).strip()}")
            for call in step.tool_calls or []:
                print(f"[行动 ACT] 调用工具: {call.name}  参数: {call.arguments}")
            if step.observations:
                print(f"[观察 OBSERVATION]\n{str(step.observations).strip()}")
            continue
        if isinstance(step, FinalAnswerStep):
            print(f"\n[最终答案 FINAL]\n{step.output}")


def main() -> None:
    override = sys.argv[1] if len(sys.argv) > 1 else None

    with tempfile.TemporaryDirectory(prefix="sg-file-agent-", dir=Path.cwd()) as tmp:
        root = Path(tmp)
        input_file = _prepare_input_file(root, override)

        # Trusted host ceiling. User wording may only narrow these permissions.
        context = PrivacyContext(
            task="Read, scan, analyze, sanitize and summarize one authorized local file.",
            purpose="ticket_note_privacy_triage",
            requester="support_agent",
            trust_level="internal",
            allowed_scope=("ticket_note", "customers"),
            allowed_operations=("READ", "SCAN", "DETECT", "ANALYZE", "SUMMARIZE", "TRANSFORM"),
            allowed_destinations=("internal_file", "internal", "agent_memory", "requester"),
        )

        runtime = SensitiveGuardRuntime.create(context, allowed_roots=(root,))
        model = build_ollama_model()
        agent = create_dynamic_agent(runtime, model, max_steps=6, planning_interval=2, verbosity_level=2)

        task = (
            f"There is a customer ticket note saved at the local path: {input_file}\n"
            "1) Scan that file for sensitive data.\n"
            "2) Read it through the safe reader.\n"
            "3) Produce a short, masked summary that is safe to paste back into the ticket system "
            "(no raw ID card, phone, bank number, or password).\n"
            "Use only the provided tools."
        )

        print(f"输入文件: {input_file}")
        print(f"Prompt:\n{task}\n")
        result = agent.run(task)

        _print_intent(agent)
        _print_trajectory(agent)

        report = runtime.lineage_tracker.report(context)
        print("\n" + "=" * 78)
        print("血缘报告 (raw-free)")
        print("=" * 78)
        print(f"chain_valid={report.chain_valid}  nodes={len(report.nodes)}  events={len(report.events)}")

        print("\n=== 最终返回 ===")
        print(result)


if __name__ == "__main__":
    main()
