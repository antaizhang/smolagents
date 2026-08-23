# Session Progress Log

## Current State

**Last Updated:** 2026-08-23
**Active Feature:** None — four requested remote branches integrated into the latest `main` candidate.

## Status

### What's Done

- [x] Added the five Harness Engineering subsystems to the repo (Instructions, State, Verification, Scope, Lifecycle).
- [x] Rewrote `AGENTS.md` from a 3-line stub into the full Instructions subsystem (startup workflow, working rules, security invariants, DoD, verification, escalation).
- [x] Added `feature_list.json` (State/Scope) mapping the shipped SensitiveGuard subsystems to features with dependencies and evidence.
- [x] Added `init.sh` (Verification) — a validated, runnable install + quality + test path that is green from a clean checkout.
- [x] Added `progress.md` and `session-handoff.md` (Lifecycle).
- [x] Fixed a real security bug: `resolve_request_intent` leaked capabilities/effects when no requested operation survived the host-ceiling intersection.
- [x] Fixed 3 pre-existing quality errors in the security code (2× I001 import sort, 1× F401 unused import).
- [x] Confirmed the dynamic-intent and sensitive-data-detection branches were already ancestors of `main`.
- [x] Merged the agent-runtime branch, preserving B4 dynamic intent/guarded planning while adding five-layer evaluation, model-planner, recovery, stability, and token metrics.
- [x] Merged the Harness Engineering branch and applied its authority-narrowing fix to host-registered capabilities.
- [x] Repaired stale `main` lint/format issues and updated the baseline catalog test for B4.

### What's In Progress

- [ ] None. Integration baseline is green.

### What's Next

1. feat-011: extend the green baseline from the sensitiveguard scope to the full repo (`make quality && make test`), so the harness matches CI exactly.

## Blockers / Risks

- [ ] The smolagents `[dev]`/`[test]` extras fail to build in this environment (helium, Wikipedia-API) and pull the heavyweight `[all]` set. `init.sh` deliberately installs only core + pytest + ruff. Full-repo `make test` may need those extras and is not yet covered by the harness (tracked as feat-011).

## Decisions Made

- **Scope `init.sh` to `src/sensitiveguard` + `tests/sensitiveguard`**: the security features are the subject of this work, and the repo-wide test deps don't build here. Repo-wide gate is documented in `AGENTS.md` for when those deps are available.
  - Alternatives considered: installing `.[test]` (fails to build); skipping verification (violates the spec's evidence requirement).
- **Fix the failing security test rather than record it as a blocker**: the spec requires baseline verification to pass before adding scope, and the failure was a genuine capability-expansion bug.
- **Preserve B4 as the default release gate**: when only a smaller baseline set is selected, grade the strongest selected baseline instead of producing an empty acceptance report.
- **Combine both sides of the runtime conflict**: retain dynamic intent and guarded planning from `main`, plus the runtime branch's five evaluation layers and model-planner metrics.

## Files Modified This Session

- Merge commits preserve both unmerged remote branch tips in history.
- Evaluation runtime/CLI/report/scenario files now combine B4 and five-layer evaluation behavior.
- Harness artifacts are present and updated to the current verification result.
- External benchmark files received formatting/import cleanup required by the harness gate.
- `tests/sensitiveguard/test_evaluation.py` now validates the shipped B4 baseline.

## Evidence of Completion

- [x] Tests pass: `python -m pytest tests/sensitiveguard -q` → `310 passed`.
- [x] Quality clean: `ruff check src/sensitiveguard tests/sensitiveguard` → `All checks passed!`; `ruff format --check ...` → clean.
- [x] Full harness: `./init.sh` → "Verification Complete (baseline is GREEN)".
- [x] Acceptance: `PYTHONPATH=src python -m sensitiveguard.eval` → B4 `PASS` across 30 scenarios / 150 runs.

## Notes for Next Session

The authority-narrowing regression remains encoded in
`tests/sensitiveguard/test_dynamic_agent.py::test_user_prompt_cannot_expand_host_authority`.
Full-repo CI parity remains tracked as feat-011.
