#!/usr/bin/env bash
set -euo pipefail

# Inputs arrive as INPUT_* env vars from action.yml.
ROOT="${INPUT_ROOT:-.}"
LOCK="${INPUT_LOCK:-instruction-guard.lock.json}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
SARIF="${INPUT_SARIF:-instruction-guard.sarif}"
NO_LOCK="${INPUT_NO_LOCK:-false}"

ARGS=(scan --root "$ROOT" --lock "$LOCK" --fail-on "$FAIL_ON" --sarif "$SARIF")
if [ "$NO_LOCK" = "true" ]; then
  ARGS+=(--no-lock)
fi

set +e
instruction-guard "${ARGS[@]}"
CODE=$?
set -e

# Expose the sarif path as a step output for later upload.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "sarif=$SARIF" >> "$GITHUB_OUTPUT"
fi

exit "$CODE"
