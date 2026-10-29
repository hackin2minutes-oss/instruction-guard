# Instruction Supply Chain Guard
### One-page brief | Sawan Bhan | 2026

---

## The problem

Software composition analysis governs two AI supply chains today:

1. **Code** - open-source packages (what SCA has always done).
2. **Models** - AI model files, now scanned by modern SCA.

A **third supply chain is ungoverned**: the **instructions** that AI agents
obey. System prompts, agent skills, MCP tool descriptions, and rules files
(`AGENTS.md`, `CLAUDE.md`, `.cursorrules`) directly control what an agent does -
which tools it calls and with what data. These artifacts are pulled from third
parties, change silently, and no scanner inspects them.

Attackers already exploit this:
- **Hidden instructions** inside an MCP tool description.
- **Invisible Unicode** (zero-width, bidirectional-override, Unicode-tag) that
  smuggles commands a human reviewer cannot see.
- **MCP "rug pulls"** - a tool quietly changes its description *after* approval.

A single changed line in one of these files can turn a trusted agent into a
data-exfiltration channel, with no code and no dependency change for SCA to see.

## The solution

Instruction Guard treats instruction artifacts like dependencies:
**inventory, scan, lock, and detect drift** in CI.

| Capability | Detects | Rule |
|------------|---------|------|
| Lockfile drift | A pinned instruction file changed since approval | IG003 |
| Unlocked file | A new instruction file never reviewed | IG004 |
| Invisible Unicode | Smuggled / hidden text | IG001 |
| Directive scan | Injected override, escalation, concealment, exfiltration | IG002 |

Findings map to the **OWASP LLM Top 10** (LLM01 Prompt Injection, LLM03 Supply
Chain) and export as **SARIF** into GitHub code scanning - the same way SAST and
SCA findings already surface to a security team.

## How it fits an existing pipeline

- Runs as a **GitHub Action** or a CLI, as a pull-request gate.
- **Deterministic**: no network, no API keys, no model calls. Same input, same
  result. Runs in seconds.
- Approve state once (`init`), then every later change fails the build until a
  human re-approves. Instruction change control, enforced in CI.

## Why it is differentiated

Existing AI security tooling tests the **running model** (red teaming) or scans
**model files** (model SCA). Nothing governs the instruction artifacts as a
reviewed, version-pinned supply chain. This closes a named gap that sits
directly adjacent to software composition analysis.

## Roadmap

- Sigstore signing with a verify-before-load runtime check (block, not just detect)
- Allowlist of approved MCP tool permission scopes
- Regional compliance mapping (NCA, SDAIA AI principles)
- Baseline suppression with expiry for triage at scale

---

*Repository: github.com/hackin2minutes-oss/instruction-guard | (c) 2026 Sawan Bhan*
