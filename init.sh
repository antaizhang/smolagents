#!/bin/bash
set -euo pipefail

PY="$(command -v python3 || command -v python)"

if ! "$PY" -c "import sensitiveguard" 2>/dev/null; then
  "$PY" -m pip install -e . -q
fi
if ! "$PY" -c "import pytest" 2>/dev/null; then
  "$PY" -m pip install -q "pytest>=8.1.0"
fi
if ! "$PY" -c "import ruff" 2>/dev/null; then
  "$PY" -m pip install -q "ruff>=0.9.0"
fi

"$PY" -m ruff check src/sensitiveguard tests/sensitiveguard examples/sensitiveguard
"$PY" -m ruff format --check src/sensitiveguard tests/sensitiveguard examples/sensitiveguard
"$PY" -m pytest tests/sensitiveguard -q -p no:cacheprovider
"$PY" -m compileall -q src/sensitiveguard examples/sensitiveguard

# The benchmark policies must pass the structural lint, and the six external
# benchmarks must run end to end (no network, well under a second).
"$PY" -m sensitiveguard.eval lint
"$PY" -m sensitiveguard.eval run >/dev/null

echo "Phone detection Agent and benchmark verification passed."
