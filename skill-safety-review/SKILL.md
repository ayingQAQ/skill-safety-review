---
name: skill-safety-review
description: Statically review a newly downloaded local Codex skill for safety risks before enabling, installing, or trusting it. Use when Codex needs to vet an unfamiliar skill folder, inspect third-party skill contents after downloading them, review a local unpacked skill before use, or decide whether a skill appears safe, needs manual review, or looks unsafe.
---

# Skill Safety Review

Review a local unpacked skill directory without executing its code. Start with the bundled scanner, inspect the flagged snippets manually, and finish with a short evidence-based verdict.

## Quick Start

1. Confirm the target is a local unpacked directory. Do not use this skill on remote URLs or zip files in v1.
2. Run `python scripts/audit_skill.py <skill_dir>` from this skill directory.
3. Prefer `--format json` for machine-readable output and `--format markdown` when pasting a human-readable report.
4. Read `references/risk-rubric.md` only when the findings need extra interpretation.

## Workflow

### 1. Validate The Target

- Require a local directory path.
- Expect an unpacked skill folder that should contain `SKILL.md`.
- Do not install, modify, or execute anything inside the target directory.

### 2. Run The Static Scanner

- Run `python scripts/audit_skill.py <skill_dir>`.
- Let the scanner inventory files, flag opaque files, and detect risky patterns in text and code-bearing files.
- Treat the scanner as the first pass, not the final authority.

### 3. Inspect The Findings

- Read the highest-severity findings first.
- Inspect the surrounding file content before making a recommendation.
- Use `references/risk-rubric.md` to separate clearly dangerous behavior from ambiguous or explainable patterns.

### 4. Produce The Report

Always include:

- Target path
- Verdict
- Risk level
- Key findings
- Suspicious files and snippets
- Limits of static review

Use verdicts as follows:

- `appears-safe`: No suspicious patterns were found. State clearly that this is static-only and not a guarantee.
- `needs-manual-review`: Ambiguous patterns, opaque files, malformed structure, or anything that needs a human decision.
- `unsafe`: Clear evidence of dangerous execution, exfiltration, persistence, or instructions to bypass safeguards.

## Review Boundaries

- Do not execute scripts from the target skill.
- Do not fetch repo metadata, Git history, or network context in v1.
- Do not silently ignore opaque binaries or oversized files. Surface them as review items.
- Do not claim a skill is fully trustworthy. Limit the conclusion to what the static evidence supports.

## Scanner Output Contract

The bundled scanner returns:

- `verdict`
- `risk_level`
- `findings[]`
- `opaque_files[]`
- `notes`

When presenting the result to the user, summarize the verdict in plain language and cite the most important findings by file and line when available.
