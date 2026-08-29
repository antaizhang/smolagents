# AGENTS.md — SensitiveGuard Harness

This repository extends `smolagents` with the **SensitiveGuard** security
runtime (`src/sensitiveguard/`). It follows the
[Harness Engineering](https://walkinglabs.github.io/learn-harness-engineering/zh/)
spec so any agent (or human) can start, work, verify, and hand off safely.

## Startup Workflow

Before writing code:

1. **Confirm working directory** with `pwd` (repo root).
2. **Read this file** completely.
3. **Read project docs if relevant**: `SensitiveGuard_Complete_Architecture_and_Design.md`,
   `docs/source/zh/tutorials/sensitiveguard.md`, `doc/sensitiveguard-运行指南.md`.
4. **Run `./init.sh`** to install the toolchain and verify the environment is healthy.
5. **Read `feature_list.json`** to see current feature state (source of truth).
6. **Read `progress.md`** for the live session log, then review recent commits with `git log --oneline -5`.

If baseline verification (`./init.sh`) is failing, repair that first before adding new scope.

## Working Rules

- **One feature at a time**: pick exactly one unfinished feature from `feature_list.json`.
- **Verification required**: never claim done without running the verification commands.
- **Update artifacts**: before ending a session, update `progress.md` and `feature_list.json`.
- **Stay in scope**: don't modify files unrelated to the current feature.
- **Leave clean state**: the next session must be able to run `./init.sh` immediately.
- **Security invariants (SensitiveGuard-specific), never regress:**
  - A user prompt can only *narrow* the trusted host intent ceiling — never expand
    operations, capabilities, effects, fields, destinations, or recipients.
  - The legacy guarded runtime runs guards before model input, before egress, and before memory/log exposure.
  - The explicit local `detect_only` mode is a narrow demo exception: it exposes only `detect`, performs no egress,
    and must not be configured with an external model destination.
  - Failures are fail-closed and never echo raw sensitive input or private canaries.

## Contributor Guidelines

- Follow OOP principles.
- Be Pythonic: follow Python best practices and idiomatic patterns.
- Write unit tests for new functionality.

## Required Artifacts

- `feature_list.json` — feature state tracker (source of truth).
- `progress.md` — session continuity log.
- `init.sh` — standard startup and verification path.
- `session-handoff.md` — for larger / multi-session work.

## Verification Commands

```bash
# Full harness verification (recommended)
./init.sh
```

Required checks (what `./init.sh` runs):

- `ruff check src/sensitiveguard tests/sensitiveguard`
- `ruff format --check src/sensitiveguard tests/sensitiveguard`
- `python -m pytest tests/sensitiveguard -q`
- `python -m compileall -q src/sensitiveguard`

Repo-wide gate (matches CI, wider than the harness baseline): `make quality && make test`.

## Definition of Done

A feature is done only when ALL of the following are true:

- [ ] Target behavior is implemented.
- [ ] `./init.sh` was run and is green (tests + quality actually ran).
- [ ] Evidence is recorded in `feature_list.json` and/or `progress.md`.
- [ ] No SensitiveGuard security invariant regressed.
- [ ] Repository remains restartable from `./init.sh`.

## End of Session

1. Update `progress.md` with current state and evidence.
2. Update `feature_list.json` with new feature status.
3. Record unresolved risks or blockers.
4. Commit with a descriptive message once work is in a safe state.
5. Leave the repo clean enough for the next session to run `./init.sh` immediately.

## Escalation

- **Architecture decisions** → consult `SensitiveGuard_Complete_Architecture_and_Design.md`, else ask the user.
- **Unclear requirements** → check the tutorial docs, else ask the user.
- **Repeated test failures** → update `progress.md`, flag for human review.
- **Scope ambiguity** → re-read `feature_list.json` for the definition of done.
