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


def _sig_paths(lock: str):
    return Path(f"{lock}.pub"), Path(f"{lock}.sig")


def cmd_keygen(args) -> int:
    from .signing import keygen, SigningUnavailable
    pub_path, _ = _sig_paths(args.lock)
    priv_path = Path(args.private_key)
    try:
        keygen(priv_path, pub_path)
    except SigningUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Private key written to {priv_path}  (keep secret - do NOT commit)")
    print(f"Public key written to  {pub_path}  (commit this)")
    return 0


def cmd_sign(args) -> int:
    from .signing import sign_file, SigningUnavailable
    lock_path = Path(args.lock)
    if not lock_path.exists():
        print(f"ERROR: lockfile {lock_path} not found. Run 'instruction-guard init' first.",
              file=sys.stderr)
        return 2
    _, sig_path = _sig_paths(args.lock)
    try:
        sign_file(lock_path, Path(args.private_key), sig_path)
    except SigningUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Signed {lock_path} -> {sig_path}  (commit the .sig)")
    return 0


def cmd_verify(args) -> int:
    from .signing import verify_file, SigningUnavailable
    lock_path = Path(args.lock)
    pub_path, sig_path = _sig_paths(args.lock)
    for p in (lock_path, pub_path, sig_path):
        if not p.exists():
            print(f"FAIL: required file missing: {p}", file=sys.stderr)
            return 1
    try:
        ok = verify_file(lock_path, pub_path, sig_path)
    except SigningUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if ok:
        print(f"PASS: signature valid - {lock_path} is authentic and unchanged.")
        return 0
    print(f"FAIL: signature INVALID for {lock_path}. The lockfile was changed or "
          f"signed with a different key.", file=sys.stderr)
    return 1


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

    p_keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing the lockfile.")
    p_keygen.add_argument("--lock", default=LOCK_NAME, help=f"Lockfile path (default: {LOCK_NAME})")
    p_keygen.add_argument("--private-key", default="instruction-guard.key",
                          help="Where to write the private key (keep secret).")
    p_keygen.set_defaults(func=cmd_keygen)

    p_sign = sub.add_parser("sign", help="Sign the lockfile with a private key (offline).")
    p_sign.add_argument("--lock", default=LOCK_NAME, help=f"Lockfile path (default: {LOCK_NAME})")
    p_sign.add_argument("--private-key", default="instruction-guard.key",
                        help="Private key to sign with.")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify the lockfile signature (offline, no key secret needed).")
    p_verify.add_argument("--lock", default=LOCK_NAME, help=f"Lockfile path (default: {LOCK_NAME})")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
