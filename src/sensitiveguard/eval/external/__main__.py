"""External benchmark registry and native-result normalizer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import get_result_adapter, list_result_adapters


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external")
    parser.add_argument("--list", action="store_true", help="List supported benchmark adapters and runner modules")
    parser.add_argument("--benchmark", help="agentdojo, agent-threat-bench, privacylens, tau3, bfcl, or agentdam")
    parser.add_argument("--runtime", default="B4", help="Runtime label recorded in normalized output (default: B4)")
    parser.add_argument("--model", help="Model identifier used for the benchmark run")
    parser.add_argument("--benchmark-version", default="unknown", help="Native benchmark version/tag")
    parser.add_argument("--native-json", type=Path, help="JSON emitted by the benchmark's native scorer/aggregation")
    parser.add_argument("--output", type=Path, default=None, help="Optional normalized JSON output path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.list:
        for adapter in list_result_adapters():
            print(f"{adapter.name:20} {adapter.description}")
            print(f"{'':20} run: {adapter.module_command}")
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
