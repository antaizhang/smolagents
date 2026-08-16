"""Benchmark datasets shipped with SensitiveGuard.

``seed_suite.jsonl`` is the acceptance suite: one JSON object per line, in the
shape accepted by :meth:`sensitiveguard.eval.scenario.Scenario.from_dict`. Add
scenarios by appending lines, or point ``load_scenarios`` at your own file to
run a private suite instead.
"""

from __future__ import annotations

from pathlib import Path

from ..scenario import Scenario, load_scenarios


DATASET_DIR = Path(__file__).parent
SEED_SUITE_PATH = DATASET_DIR / "seed_suite.jsonl"


def load_seed_suite() -> tuple[Scenario, ...]:
    """Load the shipped acceptance suite covering all eight benchmarks."""

    return load_scenarios(SEED_SUITE_PATH)


def available_datasets() -> tuple[Path, ...]:
    return tuple(sorted(DATASET_DIR.glob("*.jsonl")))


__all__ = ["DATASET_DIR", "SEED_SUITE_PATH", "available_datasets", "load_seed_suite"]
