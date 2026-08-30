# Progress

## Current state

The repository keeps one custom Agent only: mainland-China mobile-number detection through one `detect(text)` Tool Call.

## Kept

- `src/sensitiveguard/phone_agent.py`
- `src/sensitiveguard/llm.py`
- `examples/sensitiveguard/run_ollama_agent.py`
- Focused tests in `tests/sensitiveguard/`

## Removed

The previous general SensitiveGuard runtime, policies, routing, review, transformation, memory, lineage, MCP, multi-agent support, external evaluations, demos, and unrelated tools were removed so features can be added back one at a time.

## Verification

- `./init.sh`: Ruff and formatting clean.
- `tests/sensitiveguard`: 14 passed.
- Tool-call omission, wrong-tool calls, and multiple calls fail after one model request without a fallback generation.
