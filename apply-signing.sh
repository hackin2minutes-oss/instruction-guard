#!/usr/bin/env bash
#
# apply-signing.sh
# Copies the new signing feature + README/diagram updates into your clone,
# commits, pushes, and moves the release tags to v0.2.0.
#
# Usage: extract the signing bundle so these files sit next to your repo, then
#   bash apply-signing.sh
#
set -euo pipefail

if [ ! -f "pyproject.toml" ] || [ ! -d "instruction_guard" ]; then
  echo "ERROR: run this from the instruction-guard repo root." >&2
  exit 1
fi

git add -A

if git diff --cached --quiet; then
  echo "Nothing to commit - already up to date."
else
  git commit -m "feat: offline Ed25519 lockfile signing (keygen/sign/verify); docs and v0.2.0"
  git push
fi

# Move release tags forward to the signed release.
git tag -a v0.2.0 -m "v0.2.0" 2>/dev/null || git tag -f v0.2.0 -m "v0.2.0"
git tag -f v1
git push origin v0.2.0 || true
git push -f origin v1

echo
echo "Done. v0.2.0 pushed and v1 moved to it."
echo "Try the new flow locally:"
echo "  pip install -e \".[sign]\""
echo "  instruction-guard keygen && instruction-guard sign && instruction-guard verify"
