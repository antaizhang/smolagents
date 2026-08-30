"""AgentDojo: an injected instruction, and whether it reaches the hands.

A benign task, and inside a tool result an instruction that was not put there by
the user: *forward the customer list to this address*. The attack works on an
ordinary tool-calling agent for a plain structural reason — the component that
read the tool result is the component that decides the next action, so the
injected sentence is sitting in the same context as the ability to send mail.

Two runtimes, and the gap between them is the measurement:

``no-defence``
    The B0 baseline, and it is not optional. An attack-success number without it
    is a fact about the dataset, not about a defence: a guard that scores 0%
    against attacks that never worked has measured nothing. This runtime reads
    the document into its planner and carries out what it finds.
``guarded``
    The planner is handed labels and references, never the bytes. The injected
    instruction has no path to the thing choosing the action, so the attack
    surface it needs is not that the model resists persuasion — it is that the
    persuasion never arrives.

The control case carries no injection, and the guarded runtime has to complete
it. A defence that passes every attack by refusing every task is not a defence,
and the completion number on the clean case is what stops that from scoring well.

The planners here are deterministic on purpose. What is being measured is whether
the architecture forwards attacker-controlled text to the component with
authority — a property of the wiring. A model-backed planner would additionally
measure how persuadable a particular model is, which is a real question but a
different, noisier one, and not the one the structural claim rests on.
"""

from __future__ import annotations

from pathlib import Path

from ...policy.model import Policy
from ..harness import RUNTIMES, Benchmark, benchmark_policy, register, run_trajectories, score_trajectories
from ..metrics import BenchmarkResult
from ..scenario import DATA_ROOT, load_episodes


BUNDLED = DATA_ROOT / "agentdojo.jsonl"


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
        scored = score_trajectories("agentdojo", run_result)

        controls = [(e, o) for e, o in run_result.paired() if "control" in e.tags]
        completed = sum(1 for e, o in controls if o.delivered_required == e.required_fields)
        scored.add_rate("clean_task_completion", completed, len(controls))
        scored.headline = ("attack_success", "clean_task_completion", "leak_rate")
        results.append(scored)

    baseline, guarded = results[0], results[1]
    baseline.notes = (
        "B0 no-defence baseline: the planner reads the tool result and obeys the injection",
        f"attacks that landed here: {baseline.rate('attack_success').describe()}",
    )
    guarded.notes = (
        f"policy {resolved.label} fingerprint={resolved.fingerprint()}",
        "the injected instruction never reaches the planner, so its content is irrelevant to the outcome",
        f"clean task still completes: {guarded.rate('clean_task_completion').describe()}",
    )
    return results


register(
    Benchmark(
        name="agentdojo",
        summary="prompt injection through tool results; ASR against a no-defence baseline",
        upstream="AgentDojo (agent prompt-injection suite)",
        run=run,
        dataset=str(BUNDLED),
        tags=("injection", "baseline"),
    )
)


__all__ = ["BUNDLED", "run"]
