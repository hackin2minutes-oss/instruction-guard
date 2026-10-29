"""Command-line entry point.

Usage:
  instruction-guard init  [--root .] [--lock instruction-guard.lock.json]
  instruction-guard scan  [--root .] [--lock ...] [--sarif out.sarif]
                          [--fail-on high|medium|low] [--no-lock]
"""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import scan_tree, DEFAULT_INCLUDE, DEFAULT_EXCLUDE
from .lockfile import write_lock, load_lock, diff_against_lock, LOCK_NAME
from .report import render_text, render_sarif
from .scanner import Finding

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", default=".", help="Directory to scan (default: .)")
    p.add_argument("--lock", default=LOCK_NAME, help=f"Lockfile path (default: {LOCK_NAME})")


def cmd_init(args) -> int:
    root = Path(args.root).resolve()
    records = scan_tree(root, DEFAULT_INCLUDE, DEFAULT_EXCLUDE)
    lock_path = Path(args.lock)
    write_lock(lock_path, records)

    # Surface content findings at init time so you don't lock in a bad file.
    content_findings = [f for r in records for f in r.findings]
    print(f"Wrote {lock_path} pinning {len(records)} instruction file(s).")
    for r in records:
        print(f"  + {r.path}  ({r.sha256[:12]})")
    if content_findings:
        print("\nWARNING: content findings exist in files you just locked:")
        print(render_text(content_findings, len(records)))
    return 0


def cmd_scan(args) -> int:
    root = Path(args.root).resolve()
    records = scan_tree(root, DEFAULT_INCLUDE, DEFAULT_EXCLUDE)

    findings: list[Finding] = [f for r in records for f in r.findings]

    if not args.no_lock:
        lock_path = Path(args.lock)
        if not lock_path.exists():
            print(f"ERROR: lockfile {lock_path} not found. Run 'instruction-guard init' first, "
                  f"or pass --no-lock to scan content only.", file=sys.stderr)
            return 2
        lock = load_lock(lock_path)
        findings.extend(diff_against_lock(records, lock))

    print(render_text(findings, len(records)))

    if args.sarif:
        Path(args.sarif).write_text(render_sarif(findings), encoding="utf-8")
        print(f"\nSARIF written to {args.sarif}")

    threshold = SEVERITY_RANK[args.fail_on]
    gating = [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]
    return 1 if gating else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="instruction-guard",
        description="Govern the instruction artifacts AI agents obey: inventory, scan, lock, detect drift.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a lockfile pinning current instruction files.")
    _add_common(p_init)
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="Scan and fail on findings / drift.")
    _add_common(p_scan)
    p_scan.add_argument("--sarif", help="Write SARIF 2.1.0 to this path.")
    p_scan.add_argument("--fail-on", choices=["high", "medium", "low"], default="high",
                        help="Minimum severity that fails the run (default: high).")
    p_scan.add_argument("--no-lock", action="store_true",
                        help="Skip lockfile drift check; scan content only.")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
