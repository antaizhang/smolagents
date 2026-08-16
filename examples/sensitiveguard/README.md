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
```

Leakage is judged by searching recorded sink traffic for the literal canary values the harness planted, not by asking
the detector under test. A value the detector misses is therefore reported as a leak rather than hidden by the miss.
