"""Lockfile create / load / diff.

The lockfile pins the sha256 of every approved instruction artifact. A change
to any pinned file, a new unlocked file, or a removed file is reported as
drift so a human must re-approve it.
"""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .scanner import FileRecord, Finding

LOCK_VERSION = 1
LOCK_NAME = "instruction-guard.lock.json"


def build_lock(records: list[FileRecord]) -> dict:
    return {
        "lockfileVersion": LOCK_VERSION,
        "generator": "instruction-guard",
        "files": {
            r.path: {"sha256": r.sha256, "bytes": r.bytes}
            for r in sorted(records, key=lambda x: x.path)
        },
    }


def write_lock(path: Path, records: list[FileRecord]) -> None:
    path.write_text(json.dumps(build_lock(records), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_lock(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_against_lock(records: list[FileRecord], lock: dict) -> list[Finding]:
    """Compare current scan to a lockfile and return drift findings."""
    findings: list[Finding] = []
    locked = lock.get("files", {})
    current = {r.path: r for r in records}

    for path, rec in sorted(current.items()):
        if path not in locked:
            findings.append(Finding(
                path=path, rule="unlocked", kind="new-file", severity="high", line=0,
                message="Instruction file is not in the lockfile - never reviewed/approved.",
            ))
        elif locked[path]["sha256"] != rec.sha256:
            findings.append(Finding(
                path=path, rule="drift", kind="content-changed", severity="high", line=0,
                message=(
                    f"Content changed since approval. "
                    f"locked={locked[path]['sha256'][:12]} current={rec.sha256[:12]}."
                ),
            ))

    for path in sorted(locked):
        if path not in current:
            findings.append(Finding(
                path=path, rule="drift", kind="removed-file", severity="medium", line=0,
                message="Instruction file in the lockfile no longer exists.",
            ))

    return findings
