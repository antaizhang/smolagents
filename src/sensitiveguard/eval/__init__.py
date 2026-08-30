"""The benchmarks: six edges of the system, each measured on its own terms.

The order is the one the work was planned in, and each step needs what the step
before it built:

1. **AirGapAgent-R** — the policy engine on a contextual-integrity grid. No
   trajectory, no agent: just ``field x scenario -> share?``, which is one
   ``decide_label`` call per cell. Needs the label vocabulary to be open, so a
   twenty-six-field benchmark is not forced through five detector labels.
2. **PrivacyLens** — the same decisions inside a trajectory that ends in an
   outward action. Needs a way out of the pipeline, which is what the runtime
   added: a destination to leak *to*.
3. **AgentDAM** — a web agent, and the routing cost of guarding one, because a
   web agent's per-action price is multiplied by a long trajectory.
4. **AgentLeak** — more than one agent, so there are internal channels to probe.
   Needs the audit bus: it scores which boundary a secret crossed, not the last
   hop.
5. **AgentDojo** — injection through a tool result, against a no-defence
   baseline. Needs the reader/planner split the runtime provides.
6. **ASB** — the same injection across attack families, reported per family, so
   a structural defence shows up as a flat chart.

Everything here runs without a network. Where a real upstream dataset exists, the
runner takes ``--data`` and each benchmark's ``normalize_*`` maps the upstream
records onto the internal shape; the bundled datasets are small, legible stand-ins
that exercise the same code paths.
"""

from .harness import Benchmark, Suite, benchmark_policy, get, registry, run_trajectories, score_trajectories
from .metrics import BenchmarkResult, Confusion, Rate
from .runtime import EpisodeOutcome, GuardedRuntime, RoutingCost, ToolSurface, UnguardedRuntime
from .scenario import Action, Directive, Document, Episode, load_episodes


def run_all(*, limit: int | None = None) -> list[BenchmarkResult]:
    """Run every registered benchmark, in the planned order."""

    from .benchmarks import ORDER

    results: list[BenchmarkResult] = []
    for name in ORDER:
        results.extend(get(name).run(limit=limit))
    return results


__all__ = [
    "Action",
    "Benchmark",
    "BenchmarkResult",
    "Confusion",
    "Directive",
    "Document",
    "Episode",
    "EpisodeOutcome",
    "GuardedRuntime",
    "Rate",
    "RoutingCost",
    "Suite",
    "ToolSurface",
    "UnguardedRuntime",
    "benchmark_policy",
    "get",
    "load_episodes",
    "registry",
    "run_all",
    "run_trajectories",
    "score_trajectories",
]
