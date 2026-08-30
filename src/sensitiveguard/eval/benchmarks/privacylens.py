"""PrivacyLens: the leak nobody attacked for.

No adversary appears in this benchmark. The agent is asked to do an ordinary
errand — confirm a lease, reschedule an appointment, file a self-assessment — and
it over-shares, because it has the user's whole context in front of it and being
comprehensive reads as being helpful. That is the failure this measures, and it
is the common one: most privacy incidents from agents are not attacks, they are
an assistant answering thoroughly.

What it needs from the system, and what did not exist before, is a way out.
A pipeline whose last step is "return the processed string" cannot be scored
here at all: there is no recipient, so there is no such thing as the wrong
recipient. So each case ends in an outward action with a named destination, and
the same field is scored differently depending on which one it is — the health
condition belongs at the clinic portal and not in the landlord's inbox, and no
property of the field decides that.

Two ground truths, deliberately not one:

``required_fields``
    what the errand needs. A guard that empties the message scores zero here.
``forbidden_fields``
    what the recipient should not receive. A guard that sends everything scores
    zero here.

Both are reported. There is no combined number, because a combined number is how
a system that does one of them well hides that it does the other one badly.
"""

from __future__ import annotations

from pathlib import Path

from ...policy.model import Policy
from ..harness import RUNTIMES, Benchmark, benchmark_policy, register, run_trajectories, score_trajectories
from ..metrics import BenchmarkResult
from ..scenario import DATA_ROOT, load_episodes


BUNDLED = DATA_ROOT / "privacylens.jsonl"


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
        scored = score_trajectories("privacylens", run_result)
        scored.rates.pop("attack_success", None)
        scored.headline = ("leak_rate", "task_completion")
        by_norm: dict[str, dict[str, int]] = {}
        for episode, outcome in run_result.paired():
            for tag in episode.tags:
                if not tag.startswith("norm:"):
                    continue
                bucket = by_norm.setdefault(tag[5:], {"cases": 0, "leaks": 0})
                bucket["cases"] += 1
                bucket["leaks"] += bool(outcome.leaked_fields)
        scored.breakdown["per_norm"] = by_norm
        results.append(scored)

    results[1].notes = (
        f"policy {resolved.label} fingerprint={resolved.fingerprint()}",
        "no adversary in this dataset: every leak here is an assistant being thorough",
    )
    return results


register(
    Benchmark(
        name="privacylens",
        summary="ordinary errands where a helpful agent over-shares; leak vs task completion",
        upstream="PrivacyLens (norm-violating disclosure in agent trajectories)",
        run=run,
        dataset=str(BUNDLED),
        tags=("trajectory", "over-sharing"),
    )
)


__all__ = ["BUNDLED", "run"]
