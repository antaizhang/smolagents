"""External benchmark integration for SensitiveGuard.

Third-party datasets, environments and scorers stay authoritative. This package
provides B0/B3/B4 execution bridges plus a common normalized result model.
"""

from .adapters import BenchmarkResultAdapter, get_result_adapter, list_result_adapters
from .base import BenchmarkAdapter
from .models import ExternalBenchmarkComparison, ExternalBenchmarkResult
from .tools import ExternalCallRecorder, ExternalToolSpec, RawExternalTool, SensitiveExternalTool


__all__ = [
    "BenchmarkAdapter",
    "BenchmarkResultAdapter",
    "ExternalBenchmarkComparison",
    "ExternalBenchmarkResult",
    "ExternalCallRecorder",
    "ExternalToolSpec",
    "RawExternalTool",
    "SensitiveExternalTool",
    "get_result_adapter",
    "list_result_adapters",
]
