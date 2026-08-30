# AGENTS.md — SensitiveGuard

This repository contains a guard for sensitive content in `src/sensitiveguard/`,
built on smolagents. It started as a one-tool phone detector and now carries the
three layers around it: policy, routing, and privilege separation.

## Architecture

The seams are the design. Keep them.

| Layer | Package | Answers | Never does |
|---|---|---|---|
| Facts | `facts`, `detection` | what is in the content | decide anything |
| Policy | `policy` | what to do about a fact | call a model |
| Disposition | `transform` | carry a verdict out | choose a verdict |
| Separation | `agents` | who may see what | let the reader hold authority |
| Review | `review` | did the output hold up | change a verdict |

Four invariants hold the whole thing up. Breaking one is a design change, not a
refactor:

1. **Detectors emit facts, never actions.** A `Finding` is a span, a label, a
   confidence and a detector name — there is no field a sentence can cross in.
2. **The policy decision is deterministic and model-free.** `policy/engine.py`
   and `policy/model.py` import nothing that generates. A verdict depends on the
   rule file and nothing else, and prints the path it took.
3. **No tier may weaken a settled fact, and an adjudicating tier may only speak
   about the spans it was handed.** An adjudicating tier may dismiss an
   *unsettled* candidate; that is the job it was escalated for.
4. **Routing is a control-plane decision.** Destination, caller role, purpose
   and content kind come from the caller. Nothing is ever parsed out of the
   content, so content cannot choose its own rule or its own detector chain.

## Scope

- Keep each module small and readable, and keep the layers separate.
- Add capability to a layer, not across layers. A new label is a detector plus a
  policy rule; a new action is a handler plus a rule; a new content kind is a
  chain in `detection/capability.py`.
- Policy changes go in `policy/default_policy.yaml`, with an expectation
  covering the new behaviour. `PolicyEngine.self_test()` runs them.
- Do not add external benchmark bridges, file tools, HTTP tools, database tools,
  MCP, or a memory or lineage runtime unless the user explicitly asks for one
  feature at a time.
- Do not modify the upstream `src/smolagents/` package unless a requested
  feature requires it.

## Startup

1. Read this file.
2. Read `examples/sensitiveguard/README.md`.
3. Run `./init.sh`.

## Verification

```bash
./init.sh
```

The script runs Ruff, the focused tests, and a compile check. The tests cover the
four invariants above directly — including source-level assertions that the
privileged component never opens the envelope and that the policy layer imports
no model — so a change that quietly erodes the architecture fails the build
rather than the review.
