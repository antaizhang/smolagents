"""PrivacyLens bridge that emits the official ``name,final_action`` CSV.

Run this inside an environment where the official PrivacyLens repository and
its dependencies are available. Prompt construction and post-processing are
loaded from PrivacyLens itself; its leakage/helpfulness evaluator remains the
only scorer.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sensitiveguard.dynamic_agent import resolve_request_intent
from sensitiveguard.factory import SensitiveGuardRuntime
from sensitiveguard.llm import build_ollama_model
from sensitiveguard.models import GuardStage
from sensitiveguard.privacy import PrivacyContext
from smolagents.models import ChatMessage, MessageRole


@contextmanager
def _working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _load_official_helpers(root: Path):
    evaluation = root / "evaluation"
    script = evaluation / "get_final_action.py"
    if not script.is_file():
        raise FileNotFoundError(f"PrivacyLens get_final_action.py not found under {root}")
    for path in (root / "data_construction", root / "helper", evaluation):
        sys.path.insert(0, str(path))
    spec = importlib.util.spec_from_file_location("sensitiveguard_privacylens_official", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load PrivacyLens official action generator")
    module = importlib.util.module_from_spec(spec)
    with _working_directory(evaluation):
        spec.loader.exec_module(module)
    return module.prepare_agent_prompt, module.post_process


def _content_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(content)


def _generate_text(model: Any, prompt: str) -> str:
    message = model.generate([ChatMessage(role=MessageRole.USER, content=prompt)])
    return _content_text(message).strip()


def run_privacylens_actions(
    *,
    root: Path,
    data_path: Path,
    output_path: Path,
    model: Any,
    runtime_label: str = "B4",
    prompt_type: str = "naive",
    start_index: int = 0,
    num: int = -1,
) -> Path:
    """Generate PrivacyLens final actions while preserving its native format."""

    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("PrivacyLens runtime must be B0, B3, or B4")
    prepare_prompt, post_process = _load_official_helpers(root.resolve())
    data = json.loads(data_path.read_text(encoding="utf-8"))
    end = len(data) if num < 0 else min(len(data), start_index + num)
    rows: list[dict[str, str]] = []

    for index in range(start_index, end):
        case = data[index]
        trajectory = case["trajectory"]
        prompt = prepare_prompt(
            prompt_type=prompt_type,
            user_name=trajectory["user_name"],
            user_email=trajectory["user_email"],
            user_instruction=trajectory["user_instruction"],
            toolkits=trajectory["toolkits"],
            executable_trajectory=trajectory["executable_trajectory"],
            final_action=trajectory["final_action"],
        )
        candidate = post_process(_generate_text(model, prompt))

        if label != "B0":
            context = PrivacyContext(
                task=trajectory["user_instruction"],
                purpose="privacylens_action_evaluation",
                requester="privacylens_harness",
                trust_level="internal",
                allowed_operations=("READ", "ANALYZE", "SEND"),
                allowed_effects=("READ", "NETWORK", "MESSAGE", "EXTERNAL", "WRITE"),
                allowed_destinations=("local", "requester", "benchmark_external"),
                run_id=f"privacylens-{label.lower()}-{case['name']}",
            )
            runtime = SensitiveGuardRuntime.create(
                context,
                known_external_destinations=("benchmark_external", "requester"),
            )
            if label == "B4":
                # Bind the request even though PrivacyLens evaluates only the
                # next action rather than executing a complete tool loop.
                parent = runtime.intent_resolver.resolve(context)
                resolve_request_intent(runtime.intent_resolver, context, trajectory["user_instruction"], parent=parent)
            guarded = runtime.gateway.guard_text(
                candidate,
                context,
                GuardStage.TOOL_INPUT,
                destination="benchmark_external",
                tool_name="privacylens_final_action",
                record_disclosure=True,
            )
            candidate = (
                str(guarded.content)
                if guarded.allowed
                else "[Action] Refuse\n[Action Input] Privacy policy blocked this disclosure."
            )
        rows.append({"name": str(case["name"]), "final_action": candidate})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("name", "final_action"))
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external.privacylens")
    parser.add_argument("--root", type=Path, required=True, help="Checkout of SALT-NLP/PrivacyLens")
    parser.add_argument("--data", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("reports/privacylens-actions.csv"))
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    parser.add_argument("--prompt-type", choices=("naive", "privacy_enhanced"), default="naive")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--num", type=int, default=-1)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    data_path = args.data or args.root / "data" / "main_data.json"
    output = run_privacylens_actions(
        root=args.root,
        data_path=data_path,
        output_path=args.output,
        model=build_ollama_model(),
        runtime_label=args.runtime,
        prompt_type=args.prompt_type,
        start_index=args.start_index,
        num=args.num,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["run_privacylens_actions"]
