"""Run the SensitiveGuard demo corpus offline and gate on the results.

    python run_cases.py                      # full corpus, table on stdout
    python run_cases.py --group 外发命令检测   # one group
    python run_cases.py --case cmd-curl-post-passwd --verbose
    python run_cases.py --json report.json   # machine-readable report
    python run_cases.py --no-gate            # never exit non-zero

Needs no model, no network and no subprocess, so it doubles as a CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent))

import probes  # noqa: E402


CASES_PATH = Path(__file__).resolve().parent / "cases.jsonl"


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            cases.append(json.loads(stripped))
        except json.JSONDecodeError as error:
            raise SystemExit(f"{path}:{number}: 用例不是合法 JSON: {error}") from None
    return cases


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    probe = case["probe"]
    payload = dict(case.get("input", {}))
    if probe == "detect":
        return probes.detect_probe(payload["text"])
    if probe == "command":
        return probes.command_probe(payload["command"])
    if probe == "structured":
        return probes.structured_probe(
            payload.get("argv"),
            capability=payload.get("capability", probes.DEMO_CAPABILITY),
        )
    if probe == "egress":
        return probes.egress_probe(
            payload["channel"],
            payload.get("target", ""),
            payload.get("payload", ""),
            allow_private_networks=bool(payload.get("allow_private_networks", False)),
        )
    raise SystemExit(f"未知的 probe 类型: {probe!r}")


def check(case: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    """Return one message per unmet expectation; an empty list means PASS."""
    expect = case.get("expect", {})
    probe = case["probe"]
    failures: list[str] = []

    if probe == "detect":
        if "contains" in expect and observed["contains_sensitive_data"] != expect["contains"]:
            failures.append(
                f"contains_sensitive_data={observed['contains_sensitive_data']}，期望 {expect['contains']}"
            )
        for label in expect.get("labels_include", []):
            if label not in observed["labels"]:
                failures.append(f"缺少标签 {label}（实际 {observed['labels']}）")
        if expect.get("labels_empty") and observed["labels"]:
            failures.append(f"期望零误报，实际命中 {observed['labels']}")
        for severity in expect.get("severities_include", []):
            if severity not in observed["severities"]:
                failures.append(f"缺少严重级 {severity}（实际 {observed['severities']}）")
        for detector in expect.get("detectors_include", []):
            if detector not in observed["detectors"]:
                failures.append(f"缺少检测器 {detector}（实际 {observed['detectors']}）")
        rewritten = " ".join(
            str(observed.get(key) or "") for key in ("masked_text", "redacted_text", "pseudonymized_text")
        )
        for literal in expect.get("absent_from_output", []):
            if literal in rewritten:
                failures.append(f"脱敏输出仍包含原值 {literal!r}")

    elif probe == "command":
        inspection = observed["inspection"]
        rules = [finding["rule_id"] for finding in inspection["findings"]]
        if "verdict" in expect and inspection["verdict"] != expect["verdict"]:
            failures.append(f"verdict={inspection['verdict']}，期望 {expect['verdict']}")
        for rule in expect.get("rules_include", []):
            if rule not in rules:
                failures.append(f"缺少规则 {rule}（实际 {rules}）")
        if expect.get("findings_empty") and rules:
            failures.append(f"期望零告警，实际命中 {rules}")
        if "exfiltration" in expect and inspection["exfiltration_suspected"] != expect["exfiltration"]:
            failures.append(
                f"exfiltration_suspected={inspection['exfiltration_suspected']}，期望 {expect['exfiltration']}"
            )
        for label in expect.get("labels_include", []):
            if label not in inspection["data_labels"]:
                failures.append(f"命令内敏感标签缺少 {label}（实际 {inspection['data_labels']}）")
        if observed["structured_api"]["accepted"]:
            failures.append("结构化命令接口不应接受任意 shell 字符串")

    elif probe == "egress":
        status = observed["tool_result"].get("status")
        if "status" in expect and status != expect["status"]:
            failures.append(f"status={status}，期望 {expect['status']}")
        if "wire_calls" in expect and observed["wire_call_count"] != expect["wire_calls"]:
            failures.append(f"传输层被调用 {observed['wire_call_count']} 次，期望 {expect['wire_calls']}")
        if expect.get("no_leak") and observed["leaked_values"]:
            failures.append(f"原值泄漏到出网流量: {observed['leaked_values']}")

    elif probe == "structured":
        status = observed["tool_result"].get("status")
        if "status" in expect and status != expect["status"]:
            failures.append(f"status={status}，期望 {expect['status']}")
        if "executor_invocations" in expect and observed["executor_invocations"] != expect["executor_invocations"]:
            failures.append(
                f"执行器被调用 {observed['executor_invocations']} 次，期望 {expect['executor_invocations']}"
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="SensitiveGuard 敏感数据识别 / 外发命令检测 演示用例")
    parser.add_argument("--cases", type=Path, default=CASES_PATH, help="用例文件（JSONL）")
    parser.add_argument("--group", action="append", default=[], help="只跑指定分组，可重复")
    parser.add_argument("--case", action="append", default=[], help="只跑指定用例 id，可重复")
    parser.add_argument("--json", type=Path, help="把完整报告写入 JSON 文件")
    parser.add_argument("--verbose", action="store_true", help="打印每个用例的完整探针输出")
    parser.add_argument("--no-gate", action="store_true", help="即使有用例失败也返回 0")
    arguments = parser.parse_args()

    cases = load_cases(arguments.cases)
    if arguments.group:
        wanted = set(arguments.group)
        cases = [case for case in cases if case.get("group") in wanted]
    if arguments.case:
        wanted = set(arguments.case)
        cases = [case for case in cases if case.get("id") in wanted]
    if not cases:
        print("没有匹配的用例。", file=sys.stderr)
        return 2

    results: list[dict[str, Any]] = []
    current_group = None
    started = time.perf_counter()
    for case in cases:
        group = case.get("group", "-")
        if group != current_group:
            current_group = group
            print(f"\n## {group}")
        case_started = time.perf_counter()
        try:
            observed = run_case(case)
            failures = check(case, observed)
            error = None
        except Exception as exception:  # a probe crash is a failed case, not a crashed run
            observed = {}
            failures = [f"探针异常: {type(exception).__name__}: {exception}"]
            error = type(exception).__name__
        elapsed_ms = (time.perf_counter() - case_started) * 1000

        status = "PASS" if not failures else "FAIL"
        marker = "✅" if not failures else "❌"
        print(f"  {marker} {status}  {case['id']:<32} {case.get('title', '')}  ({elapsed_ms:.0f} ms)")
        for failure in failures:
            print(f"       └─ {failure}")
        if arguments.verbose and observed:
            print(_indent(json.dumps(observed, ensure_ascii=False, indent=2)))
        results.append(
            {
                "id": case["id"],
                "group": group,
                "title": case.get("title", ""),
                "probe": case["probe"],
                "status": status,
                "failures": failures,
                "error": error,
                "duration_ms": round(elapsed_ms, 2),
                "observed": observed,
            }
        )

    passed = sum(1 for result in results if result["status"] == "PASS")
    failed = len(results) - passed
    total_ms = (time.perf_counter() - started) * 1000
    print(f"\n合计 {len(results)} 个用例：通过 {passed}，失败 {failed}，耗时 {total_ms:.0f} ms")

    if arguments.json:
        report = {
            "passed": passed,
            "failed": failed,
            "total": len(results),
            "duration_ms": round(total_ms, 2),
            "results": results,
        }
        arguments.json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"报告已写入 {arguments.json}")

    if failed and not arguments.no_gate:
        return 1
    return 0


def _indent(block: str, prefix: str = "       ") -> str:
    return "\n".join(prefix + line for line in block.splitlines())


if __name__ == "__main__":
    raise SystemExit(main())
