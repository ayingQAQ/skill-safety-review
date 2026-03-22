# Risk Rubric

Use this rubric after running `scripts/audit_skill.py`. The scanner is intentionally conservative, so the final recommendation should combine the structured findings with a short manual review of the flagged snippets.

## Verdicts

### `unsafe`

Use when the skill contains clear evidence of behavior that should not be trusted without a major rewrite.

Common signals:

- Explicit command execution such as `subprocess`, `os.system`, `Start-Process`, or `Invoke-Expression`
- Network or download behavior such as `requests`, `urllib`, `socket`, `curl`, `wget`, or `Invoke-WebRequest`
- Dynamic execution such as `eval`, `exec`, `compile`, `importlib`, or decoded payload execution
- Persistence or profile modification such as writing to shell profiles, startup folders, scheduled tasks, or other skill directories
- Instructions that ask the agent to bypass safeguards, reveal secrets, skip confirmation, or run destructive commands

### `needs-manual-review`

Use when the skill may be acceptable, but the static evidence is incomplete or ambiguous.

Common signals:

- Missing or malformed `SKILL.md`
- Hidden files or symlinks
- Opaque binaries, archives, or oversized files that were not scanned as text
- Broad trigger language that could cause unsafe implicit use
- Encoded blobs, unusual loaders, or other patterns that require human interpretation

### `appears-safe`

Use only when the scanner found no suspicious patterns and the directory structure is consistent with a normal skill.

Required caveat:

- State that the result is based on static inspection only and is not a full trust guarantee.

## Severity Guidance

### High

- Dangerous execution
- Exfiltration or download behavior
- Persistence or privilege escalation
- Strong prompt red flags

High severity findings usually justify an `unsafe` verdict unless there is a very clear benign explanation.

### Medium

- Symlinks
- Hidden files
- Encoded payload hints
- Broad or overly aggressive trigger language
- Malformed skill structure

Medium severity findings usually justify `needs-manual-review`.

### Low

- Informational structure issues
- Mildly suspicious but explainable wording

Low severity findings should still be surfaced, but they should not by themselves force an `unsafe` verdict.

## Acceptable Patterns

These patterns are usually acceptable when used plainly and without risky companions:

- Normal markdown guidance in `SKILL.md`
- Local helper scripts that parse files without command execution or networking
- Static references and documentation
- Non-executable image assets

## False Positive Checks

Before finalizing a warning:

1. Check whether the flagged string appears inside explanatory prose rather than executable code.
2. Check whether the file is part of the reviewed skill itself, not a copied sample or test artifact.
3. Check whether a risky-looking token is referenced defensively, for example warning against `eval` instead of using it.
