"""Core scanning logic: discovery, hashing, and content checks.

Pure standard library. No network, no secrets, deterministic output.
"""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# What counts as an "instruction artifact"
# ---------------------------------------------------------------------------
# These are files whose *text* is consumed by an AI agent as instructions:
# system prompts, agent rule files, skill definitions, MCP tool manifests,
# and prompt templates. Globs are matched against the POSIX path relative to
# the scan root.
DEFAULT_INCLUDE = [
    "**/AGENTS.md",
    "**/CLAUDE.md",
    "**/.cursorrules",
    "**/.cursor/rules/**",
    "**/.windsurfrules",
    "**/*.mcp.json",
    "**/mcp.json",
    "**/.mcp.json",
    "**/*.prompt",
    "**/*.prompt.md",
    "**/*.prompt.txt",
    "**/system_prompt*.md",
    "**/system-prompt*.md",
    "**/prompts/**/*.md",
    "**/prompts/**/*.txt",
    "**/skills/**/SKILL.md",
    "**/.github/copilot-instructions.md",
]

DEFAULT_EXCLUDE = [
    "**/.git/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/instruction-guard.lock.json",  # never scan the lockfile itself
]

# ---------------------------------------------------------------------------
# Suspicious-content signatures
# ---------------------------------------------------------------------------
# Invisible / formatting Unicode that has no business in a plain instruction
# file. These are the classic smuggling characters for hidden prompt text.
INVISIBLE_CODEPOINTS = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
}

# Unicode Tags block (U+E0000-U+E007F): used to hide ASCII inside a single
# visually-empty span. Strong signal of smuggled instructions.
TAGS_BLOCK = range(0xE0000, 0xE0080)

# Directive patterns: imperative phrasing aimed at the model, plus data-exfil
# and permission-escalation cues. Case-insensitive, matched line by line.
DIRECTIVE_PATTERNS = [
    (r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b", "override", "high"),
    (r"\bdisregard\s+(all\s+)?(previous|prior|the\s+above)\b", "override", "high"),
    (r"\byou\s+are\s+now\s+(an?\s+)?(admin|administrator|root|developer\s+mode)\b", "escalation", "high"),
    (r"\b(act|behave)\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(admin|root|dan)\b", "escalation", "high"),
    (r"\bdo\s+not\s+(tell|mention|inform|warn)\s+(the\s+)?(user|human)\b", "concealment", "high"),
    (r"\bwithout\s+(telling|informing|notifying)\s+(the\s+)?(user|human|anyone)\b", "concealment", "high"),
    (r"(read|cat|print|exfiltrate|send|leak|upload)\b.{0,40}\b(\.ssh|id_rsa|\.env|secret|credential|api[_-]?key|token|password)", "exfiltration", "high"),
    (r"\b(curl|wget|fetch|http[s]?://)\b.{0,60}\b(post|upload|exfil|attacker|webhook)", "exfiltration", "high"),
    (r"\benv(ironment)?\s+variables?\b.{0,30}\b(send|include|return|output)\b", "exfiltration", "medium"),
    (r"\bbase64\s+(decode|encode)\b.{0,30}\b(and\s+)?(run|exec|eval)\b", "obfuscation", "medium"),
    (r"<!--.*?(ignore|instruction|prompt|system).*?-->", "hidden-comment", "medium"),
]

COMPILED_DIRECTIVES = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), kind, sev)
    for p, kind, sev in DIRECTIVE_PATTERNS
]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    path: str
    rule: str          # e.g. "invisible-unicode", "directive", "drift", "unlocked"
    kind: str          # sub-type, e.g. "exfiltration", "ZERO WIDTH SPACE"
    severity: str      # low | medium | high
    line: int          # 1-based; 0 when not line-specific
    message: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class FileRecord:
    path: str
    sha256: str
    bytes: int
    findings: list[Finding] = field(default_factory=list)


def _posix(p: Path, root: Path) -> str:
    return p.relative_to(root).as_posix()


def _matches_any(rel: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.lstrip("**/")) for g in globs)


def discover(root: Path, include: list[str], exclude: list[str]) -> list[Path]:
    """Return instruction files under root, sorted for deterministic output."""
    found: set[Path] = set()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = _posix(p, root)
        if _matches_any(rel, exclude):
            continue
        if _matches_any(rel, include):
            found.add(p)
    return sorted(found)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_content(rel: str, text: str) -> list[Finding]:
    """Run invisible-unicode and directive checks over one file's text."""
    findings: list[Finding] = []

    # 1) Invisible / bidi / tag codepoints, reported with line numbers.
    for lineno, line in enumerate(text.splitlines(), start=1):
        for ch in line:
            cp = ord(ch)
            if cp in INVISIBLE_CODEPOINTS:
                findings.append(Finding(
                    path=rel, rule="invisible-unicode", kind=INVISIBLE_CODEPOINTS[cp],
                    severity="high", line=lineno,
                    message=f"Invisible/formatting character U+{cp:04X} ({INVISIBLE_CODEPOINTS[cp]}) found.",
                ))
            elif cp in TAGS_BLOCK:
                decoded = chr(cp - 0xE0000) if 0x20 <= cp - 0xE0000 < 0x7F else "?"
                findings.append(Finding(
                    path=rel, rule="invisible-unicode", kind="UNICODE TAG",
                    severity="high", line=lineno,
                    message=f"Unicode Tag char U+{cp:05X} (hides ASCII '{decoded}') found - smuggled text.",
                ))
            elif unicodedata.category(ch) == "Cf" and cp not in INVISIBLE_CODEPOINTS:
                findings.append(Finding(
                    path=rel, rule="invisible-unicode", kind="FORMAT CHAR",
                    severity="medium", line=lineno,
                    message=f"Format control character U+{cp:04X} found.",
                ))

    # 2) Injected directives, matched per line to keep line numbers useful.
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rx, kind, sev in COMPILED_DIRECTIVES:
            if rx.search(line):
                findings.append(Finding(
                    path=rel, rule="directive", kind=kind, severity=sev, line=lineno,
                    message=f"Suspicious {kind} directive detected.",
                ))

    return findings


def scan_file(p: Path, root: Path) -> FileRecord:
    rel = _posix(p, root)
    data = p.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    rec = FileRecord(path=rel, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    rec.findings = scan_content(rel, text)
    return rec


def scan_tree(root: Path, include: list[str], exclude: list[str]) -> list[FileRecord]:
    return [scan_file(p, root) for p in discover(root, include, exclude)]
