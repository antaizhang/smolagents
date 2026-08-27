"""External benchmark integration for SensitiveGuard.

Third-party datasets, environments and scorers stay authoritative. This package
provides B0/B3/B4 execution bridges, a common normalized result model, and an
offline B0-B4 single-case walkthrough for teaching and debugging.
"""

from .adapters import BenchmarkResultAdapter, get_result_adapter, list_result_adapters
from .base import BenchmarkAdapter
from .models import ExternalBenchmarkComparison, ExternalBenchmarkResult
from .tools import ExternalCallRecorder, ExternalToolSpec, RawExternalTool, SensitiveExternalTool
from .walkthrough import (
    BASELINES,
    DEFAULT_CASES_DIR,
    ReplayModel,
    ReplayStep,
    WalkthroughCase,
    WalkthroughResult,
    WalkthroughTool,
    load_case,
    load_cases,
    run_all_baselines,
    run_case,
)


__all__ = [
    "BenchmarkAdapter",
    "BenchmarkResultAdapter",
    "BASELINES",
    "DEFAULT_CASES_DIR",
    "ExternalBenchmarkComparison",
    "ExternalBenchmarkResult",
    "ExternalCallRecorder",
    "ExternalToolSpec",
    "RawExternalTool",
    "ReplayModel",
    "ReplayStep",
    "SensitiveExternalTool",
    "WalkthroughCase",
    "WalkthroughResult",
    "WalkthroughTool",
    "get_result_adapter",
    "load_case",
    "load_cases",
    "list_result_adapters",
    "run_all_baselines",
    "run_case",
]
