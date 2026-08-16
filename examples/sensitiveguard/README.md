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
