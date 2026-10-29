"""Output renderers: human-readable text, and SARIF 2.1.0 for GitHub."""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from __future__ import annotations

import json
from .scanner import Finding

TOOL_NAME = "instruction-guard"
TOOL_URI = "https://github.com/hackin2minutes-oss/instruction-guard"

# Map our rule ids to a stable SARIF ruleId + OWASP LLM Top 10 tag.
RULE_META = {
    "invisible-unicode": ("IG001", "Hidden/invisible Unicode in instruction file", "LLM01-Prompt-Injection"),
    "directive":         ("IG002", "Injected directive in instruction file", "LLM01-Prompt-Injection"),
    "drift":             ("IG003", "Instruction file changed since approval", "LLM03-Supply-Chain"),
    "unlocked":          ("IG004", "Unapproved instruction file (not in lockfile)", "LLM03-Supply-Chain"),
}

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def render_text(findings: list[Finding], scanned: int) -> str:
    lines = []
    lines.append(f"Instruction Supply Chain Guard - scanned {scanned} instruction file(s).")
    if not findings:
        lines.append("PASS: no findings.")
        return "\n".join(lines)

    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    lines.append(
        f"FAIL: {len(findings)} finding(s) - "
        f"{by_sev['high']} high, {by_sev['medium']} medium, {by_sev['low']} low.\n"
    )
    for f in sorted(findings, key=lambda x: (x.path, x.line)):
        loc = f"{f.path}:{f.line}" if f.line else f.path
        rule_id = RULE_META.get(f.rule, (f.rule.upper(), "", ""))[0]
        lines.append(f"  [{f.severity.upper():6}] {rule_id} {loc}")
        lines.append(f"           {f.kind}: {f.message}")
    return "\n".join(lines)


def render_sarif(findings: list[Finding]) -> str:
    rules = []
    seen = set()
    for rule_key, (rid, name, owasp) in RULE_META.items():
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({
            "id": rid,
            "name": name.replace(" ", ""),
            "shortDescription": {"text": name},
            "properties": {"tags": ["security", "ai", owasp]},
        })

    results = []
    for f in findings:
        rid, name, _ = RULE_META.get(f.rule, (f.rule.upper(), f.rule, ""))
        region = {"startLine": f.line} if f.line and f.line > 0 else {"startLine": 1}
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.kind}: {f.message}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": region,
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "version": "0.1.0",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
