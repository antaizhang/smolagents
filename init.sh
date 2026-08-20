#!/bin/bash
# SensitiveGuard harness — standard startup and verification path.
#
# This script must be runnable from a clean checkout and must leave behind
# real evidence (not claims). It installs the minimum needed to exercise the
# SensitiveGuard security features and then runs the exact quality + test
# commands an agent must pass before claiming a feature done.
#
# Scope note: the smolagents `[dev]`/`[test]` extras pull heavyweight example
# dependencies (helium, Wikipedia-API, mlx, ...) that do not build in every
# environment and are unrelated to the security code. This harness therefore
# installs the core package plus just pytest + ruff, which is all the
# SensitiveGuard suite and quality gate require.
set -euo pipefail

echo "=== SensitiveGuard Harness Initialization ==="

PY="$(command -v python3 || command -v python)"
echo "Using interpreter: $PY"

# --- Install (idempotent; skip anything already present) ---
if ! "$PY" -c "import sensitiveguard" 2>/dev/null; then
  echo "=== Installing core package (editable) ==="
  "$PY" -m pip install -e . -q
fi
if ! "$PY" -c "import pytest" 2>/dev/null; then
  echo "=== Installing pytest ==="
  "$PY" -m pip install -q "pytest>=8.1.0" pytest-timeout
fi
if ! command -v ruff >/dev/null 2>&1; then
  echo "=== Installing ruff ==="
  "$PY" -m pip install -q "ruff>=0.9.0"
fi

# --- Verification (must pass before any feature is 'done') ---
SG_SRC="src/sensitiveguard"
SG_TESTS="tests/sensitiveguard"

echo "=== Quality: ruff check ==="
ruff check "$SG_SRC" "$SG_TESTS"

echo "=== Quality: ruff format --check ==="
ruff format --check "$SG_SRC" "$SG_TESTS"

echo "=== Tests: SensitiveGuard suite ==="
"$PY" -m pytest "$SG_TESTS" -q -p no:cacheprovider

echo "=== Compile check ==="
"$PY" -m compileall -q "$SG_SRC"

echo ""
echo "=== Verification Complete (baseline is GREEN) ==="
echo ""
echo "Next steps:"
echo "1. Read feature_list.json to see current feature state"
echo "2. Read progress.md for the live session log"
echo "3. Pick ONE unfinished feature to work on"
echo "4. Implement only that feature, then re-run ./init.sh before claiming done"
