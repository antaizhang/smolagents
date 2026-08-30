"""AgentDAM: a web agent, and the price of guarding one.

Same failure as PrivacyLens with the form filled in by a browser instead of an
email client, which changes one thing that matters: the page is untrusted input
and it is also the thing telling the agent which boxes to fill. A page that adds
an ``id number`` field with ``required for fraud checks`` next to it is asking
the agent to accept a justification written by the party collecting the data.

The reason this benchmark is worth running third rather than skipping is the
cost column. A web agent takes many small actions rather than one large one, so
whatever a guard spends per action is multiplied by the length of the episode.
So this reports, alongside leak and completion:

``policy_lookups_per_case``
    rule evaluations. Deterministic, no model, and the number that scales with
    trajectory length.
``escalation_calls_per_case``
    how often the cascade had to ask its expensive tier. This is the one that
    would show up on a bill, and on this dataset it should be zero: the
    high-precision patterns settle what they find, and nothing else escalates.
``characters_inspected_per_case``
    what the detectors actually read, which is not the same as the size of the
    page — only quoted content is inspected, because only quoted content leaves.
"""

from __future__ import annotations

from pathlib import Path

from ...policy.model import Policy
from ..harness import RUNTIMES, Benchmark, benchmark_policy, register, run_trajectories, score_trajectories
from ..metrics import BenchmarkResult
from ..scenario import DATA_ROOT, load_episodes


BUNDLED = DATA_ROOT / "agentdam.jsonl"


def run(
    *, data: str | Path | None = None, policy: Policy | None = None, limit: int | None = None
) -> list[BenchmarkResult]:
    episodes = load_episodes(data or BUNDLED)
    if limit is not None:
        episodes = episodes[:limit]
    resolved = policy if policy is not None else benchmark_policy("agent_egress")

    results: list[BenchmarkResult] = []
    for runtime in RUNTIMES:
        run_result = run_trajectories(episodes, policy=resolved, runtime=runtime)
        scored = score_trajectories("agentdam", run_result)
        scored.rates.pop("attack_success", None)
        scored.headline = ("leak_rate", "task_completion", "policy_lookups_per_case")
        results.append(scored)

    guarded, baseline = results[1], results[0]
    overhead = guarded.counters["policy_lookups_per_case"] - baseline.counters["policy_lookups_per_case"]
    guarded.counters["policy_lookups_over_baseline"] = round(overhead, 2)
    guarded.notes = (
        f"policy {resolved.label} fingerprint={resolved.fingerprint()}",
        "routing cost is deterministic rule evaluation: no model call is on the guarded path",
    )
    return results


register(
    Benchmark(
        name="agentdam",
        summary="web-agent form filling, plus what the guard costs per action",
        upstream="AgentDAM (data minimisation for web agents)",
        run=run,
        dataset=str(BUNDLED),
        tags=("trajectory", "web", "cost"),
    )
)


__all__ = ["BUNDLED", "run"]
