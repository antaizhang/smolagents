# Session Progress Log

## Current State

**Last Updated:** 2026-08-29
**Active Feature:** None — the original agent's local detect-only phone mode is complete and verified.

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
- [x] Replaced `examples/sensitiveguard/README.md` with a detailed Chinese evaluation manual covering the built-in gate, real-model and custom-data runs, plus AgentDojo, AgentThreatBench, PrivacyLens, AgentDAM, BFCL, and tau3.
- [x] Documented which external component is replaced by each bridge, where the authoritative scorer runs, how native results are normalized, and which integrations remain constrained or unverified.
- [x] Pinned one public sample each from AgentDojo, PrivacyLens, BFCL, and tau3 and added a deterministic walkthrough that replays the same raw candidate through B0-B4.
- [x] Added observable sample/oracle, plan, intent, proposed and executed tool arguments, memory, guard decision, final-output, and transparent local-score events with interactive pause and JSON export modes.
- [x] Removed the separate `run_ollama_phone_agent.py` path and put phone detection directly into the existing `SensitiveToolCallingAgent`.
- [x] Made `create_sensitive_agent()` and `run_ollama_agent.py` expose exactly one business tool, `detect`, with no planning, `final_answer`, task guard, model route, or deterministic security review on that local path.
- [x] Forced `tool_choice="required"`, executed detection against the complete original task, and returned only `has_phone`/`count`.
- [x] Repaired `init.sh` so installed Ruff is invoked through the selected Python interpreter instead of relying on `PATH`.

### What's In Progress

- [ ] None. Integration baseline is green.

### What's Next

1. feat-011: extend the green baseline from the sensitiveguard scope to the full repo (`make quality && make test`), so the harness matches CI exactly.

## Blockers / Risks

- [ ] The smolagents `[dev]`/`[test]` extras fail to build in this environment (helium, Wikipedia-API) and pull the heavyweight `[all]` set. `init.sh` deliberately installs only core + pytest + ruff. Full-repo `make test` may need those extras and is not yet covered by the harness (tracked as feat-011).
- [ ] PrivacyLens is not currently zero-config runnable: its pinned OpenAI 0.28/Pydantic 1.10 helper conflicts with the current LiteLLM/OpenAI stack. The runbook marks action generation as blocked until a compatible loader or isolated image is verified.
- [ ] The external benchmark packages and their expensive native environments were audited but not installed or run end to end in this workspace. Their official scorers remain the source of truth.
- [ ] The local Torch build emits a non-blocking NumPy 1.x versus NumPy 2.4.6 compatibility warning; all focused tests still pass.

## Decisions Made

- **Scope `init.sh` to `src/sensitiveguard` + `tests/sensitiveguard`**: the security features are the subject of this work, and the repo-wide test deps don't build here. Repo-wide gate is documented in `AGENTS.md` for when those deps are available.
  - Alternatives considered: installing `.[test]` (fails to build); skipping verification (violates the spec's evidence requirement).
- **Fix the failing security test rather than record it as a blocker**: the spec requires baseline verification to pass before adding scope, and the failure was a genuine capability-expansion bug.
- **Preserve B4 as the default release gate**: when only a smaller baseline set is selected, grade the strongest selected baseline instead of producing an empty acceptance report.
- **Combine both sides of the runtime conflict**: retain dynamic intent and guarded planning from `main`, plus the runtime branch's five evaluation layers and model-planner metrics.
- **Keep official external scorers authoritative**: `sensitiveguard.eval.external` only normalizes their numeric outputs; bridge startup or normalized JSON alone is not evidence that a benchmark completed.
- **Disclose adapter coverage, not just commands**: the runbook calls out PrivacyLens/AgentDAM B3-B4 equivalence, BFCL endpoint/history limitations, and tau3's text-only utility focus.
- **Separate the teaching walkthrough from official benchmark claims**: the four single-case scorers are deterministic, transparent diagnostics (`official: false`); upstream harnesses and scorers remain authoritative.
- **Replay an identical raw proposal across B0-B4**: baseline differences are applied only after proposal capture, making detection, redaction, intent narrowing, memory visibility, and execution decisions directly comparable.
- **Keep one existing Agent class**: detect-only behavior is a mode of `SensitiveToolCallingAgent`; no second phone Agent is added. The guarded runtime remains available only through the explicit `SensitiveGuardRuntime.create_agent()` compatibility path.

## Files Modified This Session

- Merge commits preserve both unmerged remote branch tips in history.
- Evaluation runtime/CLI/report/scenario files now combine B4 and five-layer evaluation behavior.
- Harness artifacts are present and updated to the current verification result.
- External benchmark files received formatting/import cleanup required by the harness gate.
- `tests/sensitiveguard/test_evaluation.py` now validates the shipped B4 baseline.
- `examples/sensitiveguard/README.md` is now the detailed evaluation runbook.
- `examples/sensitiveguard/external_eval_cases/` contains the four pinned fixtures and a step-by-step Chinese guide.
- `examples/sensitiveguard/run_external_eval_walkthrough.py` provides interactive and JSON walkthrough output.
- `src/sensitiveguard/eval/external/walkthrough.py` implements deterministic B0-B4 replay and transparent scoring; the external AgentDojo bridge and metric normalization were corrected alongside it.
- `tests/sensitiveguard/test_external_eval_walkthrough.py` covers the four samples and all 20 sample/baseline combinations.
- `src/sensitiveguard/agent/sensitive_agent.py` now owns the single `detect` tool and detect-only execution path.
- `examples/sensitiveguard/run_ollama_agent.py` is the only Ollama phone-detection entry; the separate phone Agent/module/test files were removed.
- `tests/sensitiveguard/test_agent_runtime.py` covers direct detection and the one-tool model/factory paths.
- `init.sh` invokes Ruff through the selected Python interpreter.
- `feature_list.json`, `progress.md`, and `session-handoff.md` record the documentation and verification evidence.

## Evidence of Completion

- [x] Tests pass: `python -m pytest tests/sensitiveguard -q` → `327 passed`.
- [x] Quality clean: `ruff check src/sensitiveguard tests/sensitiveguard` → `All checks passed!`; `ruff format --check ...` → clean.
- [x] Full harness: `./init.sh` → "Verification Complete (baseline is GREEN)".
- [x] Walkthrough-focused tests: `pytest tests/sensitiveguard/test_external_eval_walkthrough.py tests/sensitiveguard/test_external_eval_adapters.py` → `20 passed`.
- [x] Walkthrough CLI smoke: BFCL B0 JSON output contains all observable event kinds and reports a non-official exact-match diagnostic.
- [x] Acceptance: `PYTHONPATH=src python -m sensitiveguard.eval` → B4 `PASS` across 30 scenarios / 150 runs.
- [x] External adapter unit tests: `pytest tests/sensitiveguard/test_external_eval_adapters.py` → 3 passed.
- [x] External CLI inventory: `python -m sensitiveguard.eval.external --list` → all six adapters registered.
- [x] README checks: local links exist, 146 fenced-code delimiters are balanced, and `git diff --check` is clean.
- [x] Detect-only focused tests: `pytest tests/sensitiveguard/test_agent_runtime.py` → 23 passed.
- [x] Current full harness: `./init.sh` → Ruff/format/compileall clean and 332 passed (2026-08-29).

## Notes for Next Session

The authority-narrowing regression remains encoded in
`tests/sensitiveguard/test_dynamic_agent.py::test_user_prompt_cannot_expand_host_authority`.
Full-repo CI parity remains tracked as feat-011.
External benchmark runs require their upstream datasets, model services, scorer credentials/GPU, and isolated environments;
the README intentionally does not claim those expensive runs were executed locally.
