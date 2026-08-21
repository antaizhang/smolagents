"""Normalize a native third-party benchmark result into SensitiveGuard JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import get_result_adapter, list_result_adapters


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external")
    parser.add_argument("--list", action="store_true", help="List supported result adapters and exit")
    parser.add_argument(
        "--benchmark",
        help="Adapter name: agentdojo, agent-threat-bench, privacylens, agentdam, bfcl, or tau3",
    )
    parser.add_argument("--runtime", default="B3", help="Runtime label recorded in the normalized result (default: B3)")
    parser.add_argument("--model", help="Model identifier used for the benchmark run")
    parser.add_argument("--benchmark-version", default="unknown", help="Native benchmark version/tag")
    parser.add_argument("--native-json", type=Path, help="JSON file emitted by the native benchmark/scorer wrapper")
    parser.add_argument("--output", type=Path, default=None, help="Optional normalized JSON output path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.list:
        for adapter in list_result_adapters():
            print(f"{adapter.name:20} {adapter.description}")
        return 0
    if not args.benchmark or not args.model or args.native_json is None:
        raise SystemExit("--benchmark, --model and --native-json are required unless --list is used")
    native = json.loads(args.native_json.read_text(encoding="utf-8"))
    if not isinstance(native, dict):
        raise SystemExit("native benchmark result must be a JSON object")
    result = get_result_adapter(args.benchmark).normalize(
        native,
        runtime=args.runtime,
        model=args.model,
        benchmark_version=args.benchmark_version,
    )
    rendered = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
