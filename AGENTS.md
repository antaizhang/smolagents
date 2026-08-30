# AGENTS.md — Phone Detection Agent

This repository contains one custom Agent in `src/sensitiveguard/`: a one-tool mainland-China mobile-number detector.

## Scope

- Keep the Agent small and readable.
- The only business tool is `detect(text)`.
- Do not add privacy runtimes, routing, policy engines, external benchmark bridges, file tools, HTTP tools, database tools, MCP, or multi-agent features unless the user explicitly asks for one feature at a time.
- Do not modify the upstream `src/smolagents/` package unless a requested feature requires it.

## Startup

1. Read this file.
2. Read `examples/sensitiveguard/README.md`.
3. Run `./init.sh`.

## Verification

```bash
./init.sh
```

The script runs Ruff, the focused phone-Agent tests, and a compile check.
