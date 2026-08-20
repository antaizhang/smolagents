"""End-to-end SensitiveGuard run: prompt + input file -> plan/act/observation.

Unlike ``offline_demo.py`` (which calls tools directly, no LLM) and
``run_ollama_agent.py`` (which feeds sensitive text inline in the prompt),
this example wires the *whole* agent loop together:

    prompt + an input file on disk
        -> the LLM plans (per-step reasoning)
        -> it acts   (guarded SensitiveGuard tools: scan_file / safe_read_file / mask ...)
        -> it observes (guarded tool observations)
        -> repeat until a guarded final answer

Every model I/O and every tool call passes through the SensitiveGuard gateway
(detection, policy, minimization, one-use permits, raw-free lineage). After the
run we replay the full trajectory from the agent's memory so you can see the
plan -> act -> observation chain, and print the raw-free lineage report.

Prerequisites
-------------
    pip install -e ".[litellm]"
    ollama list                              # confirm the model tag
    curl http://127.0.0.1:11436/api/tags     # confirm Ollama is up on 11436

Configuration (optional; defaults to port 11436 / qwen3.5:9b):
    SG_OLLAMA_MODEL, SG_OLLAMA_API_BASE, SG_OLLAMA_NUM_CTX, SG_OLLAMA_API_KEY

Run
---
    python examples/sensitiveguard/run_ollama_file_agent.py
    python examples/sensitiveguard/run_ollama_file_agent.py /path/to/your/file.txt
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

from smolagents.memory import ActionStep, FinalAnswerStep, PlanningStep

from sensitiveguard import SensitiveGuardRuntime, build_ollama_model
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
    """Return the file the agent will be asked to process."""
    if override:
        path = Path(override).resolve()
        if not path.is_file():
            raise SystemExit(f"input file not found: {path}")
        return path
    path = root / "ticket_note.txt"
    path.write_text(SAMPLE_NOTE, encoding="utf-8")
    return path


def _print_trajectory(agent: Any) -> None:
    """Replay the plan -> act -> observation chain from agent memory."""
    print("\n" + "=" * 78)
    print("完整轨迹 (plan -> act -> observation)")
    print("=" * 78)
    step_no = 0
    for step in agent.memory.steps:
        if isinstance(step, PlanningStep):
            # SensitiveGuard disables periodic planning, so this usually won't
            # appear; handled here for completeness.
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

        # The privacy contract: the agent may read + sanitize files under `root`
        # and mask sensitive data, but nothing is authorized to leave the host.
        context = PrivacyContext(
            task="Read one authorized local file, find sensitive data, and return a masked summary.",
            purpose="ticket_note_privacy_triage",
            requester="support_agent",
            trust_level="internal",
            allowed_scope=("ticket_note", "customers"),
            allowed_operations=("QUERY", "ANALYZE", "SUMMARIZE", "READ", "MASK", "REDACT", "SANITIZE"),
        )

        # allowed_roots is what turns on the file tools (scan_file / safe_read_file
        # / sanitize_file / verify_sanitized_file ...).
        runtime = SensitiveGuardRuntime.create(context, allowed_roots=(root,))
        model = build_ollama_model()
        agent = runtime.create_agent(model, max_steps=6, verbosity_level=2)

        # The prompt: it names the input file; the agent must plan how to inspect
        # it, act via the guarded tools, observe, and answer. The file content is
        # never trusted to grant authority — the PrivacyContext above is.
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

        _print_trajectory(agent)

        # Raw-free lineage: proves the whole chain was tracked without storing payloads.
        report = runtime.lineage_tracker.report(context)
        print("\n" + "=" * 78)
        print("血缘报告 (raw-free)")
        print("=" * 78)
        print(f"chain_valid={report.chain_valid}  nodes={len(report.nodes)}  events={len(report.events)}")

        print("\n=== 最终返回 ===")
        print(result)


if __name__ == "__main__":
    main()
