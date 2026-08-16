# SensitiveGuard offline demos

Run from the repository root:

```bash
PYTHONPATH=src python examples/sensitiveguard/offline_demo.py
```

The script exercises the three acceptance paths from the architecture document:

1. scan a directory, create a separate sanitized copy, verify it, and keep the source byte-for-byte unchanged;
2. pass customer purchase data through `safe_llm_call` and show the exact minimized prompt received by an injected client;
3. simulate an indirect prompt-injection exfiltration attempt and prove that the injected HTTP transport is never called.

It uses the deterministic regex, secret, and injection detectors, so it does not download a model. Production code can
add a preloaded GLiNER model or a local-only model path through `SensitiveGuardRuntime.create(...)`.

Real LLM, HTTP, database, RAG, email, and MCP clients must be injected by trusted host code. Never expose those raw
clients as smolagents tools.

## Benchmark suite

The demos show three paths. The benchmark suite measures all eight of them across four baselines:

```bash
PYTHONPATH=src python -m sensitiveguard.eval
```

This runs 26 scenarios under B0 (raw smolagents), B1 (detection only), B2 (uniform redaction) and B3 (full
SensitiveGuard), prints the comparison table, and exits non-zero if a graded baseline misses the acceptance bar — so
the same command works as a CI gate. It needs no model and no network, and finishes in a few seconds.

Useful flags:

```bash
python -m sensitiveguard.eval --benchmark PII-Injection --baseline B0 --baseline B3
python -m sensitiveguard.eval --json report.json --no-gate
python -m sensitiveguard.eval --dataset my_scenarios.jsonl
python -m sensitiveguard.eval --repeat 5                       # metric stability across runs
python -m sensitiveguard.eval --model ollama/qwen3:8b          # grade a real planner
```

Leakage is judged by searching recorded sink traffic for the literal canary values the harness planted, not by asking
the detector under test. A value the detector misses is therefore reported as a leak rather than hidden by the miss.

## Five evaluation layers

The report is organized the way a release decision is made, not as one number:

| Layer | What it answers |
| --- | --- |
| L1 task | Did the task finish, and is the answer still useful after minimization? |
| L2 tool | Did the agent pick the right tool, with arguments that satisfy the task's constraints? |
| L3 robustness | Does it recover from a refused or failed step, and hold up over long trajectories? |
| L4 safety | Did anything leak, and did an attack succeed? |
| L5 operations | Guard latency and token cost. |

Thresholds are tiered. **P0 is a veto**: every metric that means "sensitive data actually escaped" fails the build on
its own, no matter how good the rest of the table looks. P1 blocks as an ordinary regression. P2 is reported without
blocking. `forbidden_tool_call_rate` is deliberately P1, not P0 — a planner that gets tricked into reaching for the
wrong tool is a capability defect, and treating it as a breach would collapse the distinction this runtime exists to
maintain.

Layers 2 and 3 grade the planner's own choices. Under the default scripted planner those choices come from the dataset,
so they are reported but not gated, and the report says so at the top. Pass `--model` to grade them against a real
planner, or `--grade-planner-layers` to force them into the gate — which immediately surfaces the compromised planner
written into the injection scenarios.

The Coverage section states how many scenarios sit behind each layer, and warns when a layer would otherwise pass
vacuously.
