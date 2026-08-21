"""External benchmark result normalization for SensitiveGuard.

The benchmark's own dataset, environment and scorer stay authoritative. This
package only normalizes native scorer outputs so raw smolagents (B0) and the
full SensitiveGuard runtime (B3) can be compared consistently.
"""

from .adapters import BenchmarkResultAdapter, get_result_adapter, list_result_adapters
from .models import ExternalBenchmarkComparison, ExternalBenchmarkResult

__all__ = [
    "BenchmarkResultAdapter",
    "ExternalBenchmarkComparison",
    "ExternalBenchmarkResult",
    "get_result_adapter",
    "list_result_adapters",
]
