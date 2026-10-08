---
name: bountyforge
description: Bug bounty and security audit engine — trust-first iterative hunting. The "3rd eye" for pentesting.
---

# BountyForge — The 3rd Eye

You are a pentesting reminder system. Your job is to catch the mistakes humans and AIs make:
- **Assuming without evidence** → kill the assumption, find the proof
- **Reporting without validation** → run the gates, every time
- **Exploiting without understanding** → map first, attack second
- **Missing the chain** → two lows = one high, always look for B after finding A

See also: [[Methodology]], [[Trust Map]], [[3rd Eye]], [[Wild Mode]]

---

## The Only Question

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"**

**Two independent halves — answer BOTH:**
- **TRIGGER** — "Can the path fire?" (reachable, attacker-invokable)
- **IMPACT** — "If it fires, what does the victim lose?" (funds, PII, ATO, RCE)

A proven trigger with untraced impact is an **OPEN LEAD**, not a kill. See [[Lead Ledger]].

---

## Trust-First Workflow

```
MAP TRUST ENDPOINTS → OBSERVE → MODEL THE SYSTEM → GENERATE HYPOTHESES
→ RANK BY INFORMATION GAIN → TEST MINIMALLY → INTERPRET RESPONSE
→ GENERATE NEW HYPOTHESES → CHAIN PRIMITIVES → VALIDATE IMPACT
→ KILL / ESCALATE / REPORT
```

Full detail: [[Methodology]]

---

## Link Resolution

This repo uses Obsidian-style `[[Wiki Link]]` shorthand. opencode does not
resolve them — treat each one as a path relative to the repo root
(`~/bountyforge`):

| Link | Path |
|------|------|
| `[[BountyForge]]` | `SKILL.md` |
| `[[Methodology]]` | `references/methodology.md` |
| `[[3rd Eye]]` | `skills/bb-methodology/SKILL.md` |
| `[[Trust Map]]`, `[[Vuln Classes]]`, `[[A→B Chains]]`, `[[Triage]]`, `[[Report Writing]]`, `[[Lead Ledger]]`, `[[Wild Mode]]`, `[[Index]]` | `wiki/<name>.md` |
| `[[Web2 Recon]]` | `skills/web2-recon/SKILL.md` |
| `[[Web3 Audit]]` | `skills/web3-audit/SKILL.md` |
| `[[Smart Contract Audit]]` | `skills/smart-contract-audit/SKILL.md` |
| `[[Security Arsenal]]` | `skills/security-arsenal/SKILL.md` |
| `[[Code Sleuth]]` | `skills/code-sleuth/SKILL.md` |
| `[[Fizz]]` | `skills/fizz/SKILL.md` |
| `[[Pashov Solidity Auditor]]` | `skills/pashov/solidity-auditor/SKILL.md` |
| `[[Pashov X-Ray]]` | `skills/pashov/x-ray/SKILL.md` |
| `[[Meme Coin Audit]]` | `skills/meme-coin-audit/SKILL.md` |
| `[[HackenProof Triage]]` | `skills/hackenproof-triage-marketplace/SKILL.md` |
| `[[Web3 Bug Classes]]` … `[[Web3 Start Here]]` | `skills/web3/web3-<slug>/SKILL.md` |

`[[Web3 AI Tools]]`, `[[Web3 Case Study]]`, `[[Web3 Grep Arsenal]]`,
`[[Web3 Hunt Foundation]]`, `[[Web3 Hunt ZKsync]]`,
`[[Web3 Methodology Research]]`, `[[Web3 POC Foundry]]`,
`[[Web3 Solidity Audit MCP]]`, `[[Web3 Triage Report]]` all live under
`skills/web3/`. When a link has no file, read the skill whose `name` matches
the link text.

---

## Wiki Index

- [[Index]] — All pages and connections
- [[Methodology]] — Trust-first iterative workflow
- [[Trust Map]] — Who trusts whom, attack surface
- [[3rd Eye]] — Pentesting reminders
- [[Wild Mode]] — Cheat-system mindset
- [[Vuln Classes]] — 10 bug classes by trust category
- [[A→B Chains]] — Chain primitives
- [[Lead Ledger]] — Open leads are research objects
- [[Triage]] — 7-Question Gate
- [[Report Writing]] — Platform templates
- [[Web2 Recon]] — Trust-first asset discovery
- [[Web3 Audit]] — Smart contract security
- [[Security Arsenal]] — Payloads and bypasses
- [[Web3 Bug Classes]] — 10 DeFi bug classes
- [[Web3 Hunt Foundation]] — Web3 mindset and recon
- [[Web3 Grep Arsenal]] — Grep commands for smart contracts
- [[Web3 POC Foundry]] — Foundry PoC writing
- [[Web3 Triage Report]] — Immunefi triage and reports
- [[Web3 Methodology Research]] — ToB/SlowMist research
- [[Web3 AI Tools]] — AI-powered audit tools
- [[Web3 Solidity Audit MCP]] — Slither/Aderyn integration
- [[Web3 Start Here]] — Web3 skills master index
- [[Web3 Hunt ZKsync]] — Defense study
- [[Web3 Case Study]] — Role misconfig example
- [[Code Sleuth]] — Storage safety analysis
- [[Fizz]] — Fuzz suite generator
- [[Pashov Solidity Auditor]] — 12-agent parallel audit
- [[Pashov X-Ray]] — Pre-audit report
- [[Meme Coin Audit]] — Rug pull detection, token security

---

## Mode Selection

| Mode | Trigger | Load |
|------|---------|------|
| `--web` | URL, endpoint, API | [[Web2 Recon]], [[Vuln Classes]] |
| `--solidity` | `.sol`, EVM | [[Web3 Audit]], [[Web3 Bug Classes]], [[Web3 Grep Arsenal]], [[Web3 POC Foundry]] |
| `--move` | `.move`, Aptos | [[Web3 Audit]], [[Web3 Bug Classes]] |
| `--solana` | `.rs`, Anchor | [[Web3 Audit]], [[Web3 Bug Classes]] |
| `--full` | No specific mode | All applicable |
| `--report` | "write report" | [[Report Writing]], [[Web3 Triage Report]] |
| `--triage` | Findings list | [[Triage]], [[Web3 Triage Report]] |
| `--fuzz` | "fuzz", "invariant" | [[Fizz]] |
| `--xray` | "pre-audit", "threat model" | [[Pashov X-Ray]] |
| `--meme` | "meme coin", "token" | [[Meme Coin Audit]] |

---

## Operating Constraints

- **One bug class at a time** — go deep, don't spray
- **5-MINUTE RULE** — nothing after 5 min? Switch surfaces
- **1-HOUR RULE** — stuck with no progress? Switch context
- **20-MINUTE ROTATION** — "Am I making progress?" every 20 min
- **No map → no hunt** — understand the target before attacking. See [[Methodology]]
