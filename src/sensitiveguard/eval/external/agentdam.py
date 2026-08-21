"""AgentDAM launcher that preserves its native VisualWebArena evaluation loop.

The official agent is wrapped at ``next_action``. SensitiveGuard sees only the
same user intent/agent action available in a real deployment; the wrapper never
reads AgentDAM's ``sensitive_data`` ground truth. AgentDAM's own
PrivacyEvaluator and performance evaluator therefore remain independent oracles.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from sensitiveguard.dynamic_agent import resolve_request_intent
from sensitiveguard.factory import SensitiveGuardRuntime
from sensitiveguard.models import GuardStage
from sensitiveguard.privacy import PrivacyContext


class AgentDAMGuardedAgent:
    """Transparent wrapper around an official AgentDAM/WebArena agent."""

    def __init__(self, inner: Any, *, runtime_label: str) -> None:
        self.inner = inner
        self.runtime_label = runtime_label.upper()
        self.runtime = None
        self.active_intent = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def reset(self, config_file: str) -> Any:
        # Deliberately do not read sensitive_data from the benchmark config.
        self.runtime = None
        self.active_intent = None
        return self.inner.reset(config_file)

    def _ensure_runtime(self, intent: str) -> None:
        if self.runtime_label == "B0" or self.runtime is not None:
            return
        context = PrivacyContext(
            task=intent,
            purpose="agentdam_web_agent_privacy_evaluation",
            requester="agentdam_harness",
            trust_level="internal",
            allowed_operations=("READ", "ANALYZE", "WRITE", "SEND", "EXECUTE"),
            allowed_effects=("READ", "WRITE", "NETWORK", "EXTERNAL", "EXECUTE"),
            allowed_destinations=("local", "agent_memory", "requester", "benchmark_external"),
            run_id=f"agentdam-{self.runtime_label.lower()}-{id(self)}",
        )
        self.runtime = SensitiveGuardRuntime.create(
            context,
            known_external_destinations=("benchmark_external", "requester"),
        )
        parent = self.runtime.intent_resolver.resolve(context)
        self.active_intent = (
            resolve_request_intent(self.runtime.intent_resolver, context, intent, parent=parent)
            if self.runtime_label == "B4"
            else parent
        )

    def next_action(self, trajectory, intent, *, images=None, meta_data=None):
        action = self.inner.next_action(trajectory, intent, images=images, meta_data=meta_data)
        if self.runtime_label == "B0":
            return action
        self._ensure_runtime(str(intent))
        guarded = self.runtime.gateway.guard_payload(
            action,
            self.runtime.context,
            GuardStage.TOOL_INPUT,
            destination="benchmark_external",
            tool_name="agentdam_browser_action",
            record_disclosure=True,
        )
        if guarded.allowed and isinstance(guarded.content, dict):
            return guarded.content

        # Preserve AgentDAM's native action type instead of inventing a scorer
        # bypass. Its own environment/evaluator will treat the stop as lost
        # utility while its PrivacyEvaluator observes no forbidden disclosure.
        from browser_env import create_stop_action

        return create_stop_action("SensitiveGuard blocked a privacy-unsafe browser action.")


def _load_agentdam(root: Path):
    agentdam_dir = root.resolve() / "agentdam"
    visual_dir = root.resolve() / "visualwebarena"
    if not (agentdam_dir / "run_agentdam.py").is_file():
        raise FileNotFoundError(f"AgentDAM checkout not found: {root}")
    sys.path.insert(0, str(agentdam_dir))
    sys.path.insert(0, str(visual_dir))
    os.chdir(agentdam_dir)
    return importlib.import_module("run_agentdam")


def run_agentdam_native(root: Path, *, runtime_label: str, argv: list[str]) -> None:
    """Run official AgentDAM after wrapping only its constructed agent."""

    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("AgentDAM runtime must be B0, B3, or B4")
    module = _load_agentdam(root)
    original_construct = module.construct_agent

    def construct_guarded_agent(*args, **kwargs):
        return AgentDAMGuardedAgent(original_construct(*args, **kwargs), runtime_label=label)

    module.construct_agent = construct_guarded_agent
    sys.argv = ["run_agentdam.py", *argv]
    args = module.config()
    args.sleep_after_execution = 2.5
    module.prepare(args)

    test_file_list = []
    for index in range(args.test_start_idx, args.test_end_idx):
        path = os.path.join(args.test_config_base_dir, f"{index}.json")
        if os.path.exists(path):
            test_file_list.append(path)
    print(f"Total {len(test_file_list)} tasks left")
    args.render = False
    args.render_screenshot = True
    args.save_trace_enabled = True
    args.current_viewport_only = True
    module.dump_config(args)
    module.test(args, test_file_list)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    args, remainder = parser.parse_known_args()
    run_agentdam_native(args.root, runtime_label=args.runtime, argv=remainder)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["AgentDAMGuardedAgent", "run_agentdam_native"]
