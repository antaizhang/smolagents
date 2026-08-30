"""Run the six external benchmarks the guard is evaluated against.

    python examples/sensitiveguard/run_external_benchmarks.py

Everything here runs offline against the small bundled datasets, so this is a
demonstration of the *shape* of each result — a baseline that loses and a guarded
runtime that wins — rather than a leaderboard number. To run against a real
upstream release, pass its path to the matching benchmark's ``run(data=...)`` or
to ``python -m sensitiveguard.eval run <name> --data <path>``; each benchmark's
``normalize_*`` helper maps the upstream records onto the internal shape.

The order is the one the benchmarks are meant to be run in. Each needs something
the previous one established:

    AirGapAgent-R   the policy engine on a field x scenario grid — one decision
                    per cell, no trajectory, no adapter.
    PrivacyLens     the same decisions inside a trajectory that ends in an
                    outward action — a destination to leak to.
    AgentDAM        a web agent, and what guarding one costs per action.
    AgentLeak       a multi-agent chain, scored by which internal channel a
                    secret crossed rather than by the last hop.
    AgentDojo       injection through a tool result, against a no-defence
                    baseline that has to actually be attackable.
    ASB             the same injection across attack families, reported per
                    family, so a structural defence shows up as a flat chart.
"""

from __future__ import annotations

from sensitiveguard.eval import run_all
from sensitiveguard.eval.report import headline_table, render


def main() -> int:
    results = run_all()
    print(render(results))
    print("\n" + "=" * 68)
    print(headline_table(results))
    print("=" * 68)
    print(
        "\nBaselines lose, the guard wins, and each win is the structural one:\n"
        "  - the injected instruction never reaches the planner (AgentDojo, ASB)\n"
        "  - the secret never crosses the agent-to-agent channel (AgentLeak)\n"
        "  - the over-shared field is not authorised for the recipient (PrivacyLens, AgentDAM)\n"
        "  - the adversarial pretext cannot move the verdict (AirGapAgent-R)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
