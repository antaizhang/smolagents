"""Turning a suite run into something a person reads, and a machine diffs.

Two renderings. The text one is for the terminal at the end of a run. The dict
one is for pinning a result in a test or checking it into a report directory, so
a regression shows up as a diff rather than as a memory of what the number was
last week.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .metrics import BenchmarkResult


def _rate_line(result: BenchmarkResult, name: str) -> str:
    return result.rate(name).describe()


def render_result(result: BenchmarkResult) -> str:
    lines = [f"  [{result.runtime}]"]
    for name in result.headline or tuple(result.rates):
        if name in result.rates:
            lines.append(f"    {_rate_line(result, name)}")
        elif name in result.counters:
            lines.append(f"    {name}: {result.counters[name]:.2f}")
    if result.confusion is not None:
        lines.append(f"    {result.confusion.describe()}")
    for note in result.notes:
        lines.append(f"    - {note}")
    return "\n".join(lines)


def render(results: Sequence[BenchmarkResult]) -> str:
    """Group by benchmark, print each runtime under it."""

    grouped: dict[str, list[BenchmarkResult]] = {}
    order: list[str] = []
    for result in results:
        if result.benchmark not in grouped:
            order.append(result.benchmark)
        grouped.setdefault(result.benchmark, []).append(result)

    blocks: list[str] = []
    for name in order:
        block = [name]
        for result in grouped[name]:
            block.append(render_result(result))
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def headline_table(results: Sequence[BenchmarkResult]) -> str:
    """The one-screen summary: each benchmark's own headline metrics, both runtimes."""

    rows: list[str] = ["benchmark        runtime      metric                 value"]
    rows.append("-" * 68)
    for result in results:
        for name in result.headline:
            if name in result.rates:
                rate = result.rate(name)
                value = rate.describe().split(": ", 1)[1] if rate.measured else "n/a"
            elif name in result.counters:
                value = f"{result.counters[name]:.2f}"
            else:
                continue
            rows.append(f"{result.benchmark:<16} {result.runtime:<12} {name:<22} {value}")
    return "\n".join(rows)


def to_json(results: Sequence[BenchmarkResult], *, indent: int = 2) -> str:
    payload: dict[str, Any] = {"results": [result.as_dict() for result in results]}
    return json.dumps(payload, ensure_ascii=False, indent=indent, sort_keys=True)


__all__ = ["headline_table", "render", "render_result", "to_json"]
