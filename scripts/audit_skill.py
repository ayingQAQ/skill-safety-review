#!/usr/bin/env python3
"""Static safety review helper for local Codex skills."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_SCAN_BYTES = 256_000
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}
TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".ps1",
    ".psm1",
    ".psd1",
    ".sh",
    ".bash",
    ".zsh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".bat",
    ".cmd",
}
SUSPICIOUS_BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".jar",
    ".com",
    ".msi",
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
}
LIKELY_TEXT_FILES = {"SKILL.md", "openai.yaml"}
FRONTMATTER_RE = re.compile(r"^---\r?\n(.*?)\r?\n---", re.DOTALL)
DESCRIPTION_RE = re.compile(r"^description:\s*(.+)$", re.MULTILINE)
ALLOW_IMPLICIT_RE = re.compile(r"allow_implicit_invocation:\s*true", re.IGNORECASE)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    file: str
    line: int | None
    snippet: str
    reason: str


PATTERNS = (
    {
        "category": "command-execution",
        "severity": "high",
        "title": "Command execution primitive",
        "reason": "The file appears to invoke shell or process execution.",
        "regex": re.compile(
            r"\b(subprocess\.(run|Popen|call)|os\.system|Start-Process|Invoke-Expression|"
            r"cmd(?:\.exe)?\b|powershell(?:\.exe)?\b|bash\s+-c)\b",
            re.IGNORECASE,
        ),
    },
    {
        "category": "network-activity",
        "severity": "high",
        "title": "Network or download behavior",
        "reason": "The file appears to contact the network or download content.",
        "regex": re.compile(
            r"\b(requests\.(get|post|put|delete|request)|urllib\.(request|parse)|"
            r"socket\.(socket|create_connection)|Invoke-WebRequest|curl\b|wget\b|fetch\()",
            re.IGNORECASE,
        ),
    },
    {
        "category": "dynamic-execution",
        "severity": "high",
        "title": "Dynamic execution pattern",
        "reason": "The file appears to evaluate or dynamically load code.",
        "regex": re.compile(
            r"\b(eval\s*\(|exec\s*\(|compile\s*\(|importlib\b|__import__\s*\(|"
            r"marshal\.loads|pickle\.loads)\b",
            re.IGNORECASE,
        ),
    },
    {
        "category": "encoded-payload",
        "severity": "medium",
        "title": "Encoded payload hint",
        "reason": "The file appears to decode or embed encoded content.",
        "regex": re.compile(
            r"\b(base64\.(b64decode|decodebytes)|frombase64string|[A-Za-z0-9+/]{80,}={0,2})",
            re.IGNORECASE,
        ),
    },
    {
        "category": "persistence",
        "severity": "high",
        "title": "Persistence or profile modification",
        "reason": "The file references shell profiles, startup folders, or other persistent locations.",
        "regex": re.compile(
            r"(\.bashrc|\.zshrc|\.profile|\bLaunchAgents\b|\bcrontab\b|\bcron\b|\bStartup\b|"
            r"Start Menu[\\\\/]Programs[\\\\/]Startup|\.codex[\\\\/]skills|AppData[\\\\/].*Startup)",
            re.IGNORECASE,
        ),
    },
)

PROMPT_PATTERNS = (
    {
        "category": "prompt-red-flag",
        "severity": "high",
        "title": "Bypass or secrecy instruction",
        "reason": "The instructions appear to bypass safeguards or request secrets.",
        "regex": re.compile(
            r"(ignore (previous|all) instructions|bypass safeguards|disable security|"
            r"do not ask for confirmation|reveal secrets|print env vars|"
            r"run with elevated privileges|sudo without asking)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "prompt-red-flag",
        "severity": "high",
        "title": "Destructive command in instructions",
        "reason": "The instructions contain a destructive command pattern.",
        "regex": re.compile(r"(rm\s+-rf|git reset --hard|curl\s+.+\|\s*(bash|sh))", re.IGNORECASE),
    },
)

BROAD_TRIGGER_PATTERNS = (
    {
        "category": "broad-trigger",
        "severity": "medium",
        "title": "Overly broad trigger description",
        "reason": "The skill description is broad enough that implicit invocation could be risky.",
        "regex": re.compile(
            r"(for any task|for all tasks|always use|every request|any request|all requests)",
            re.IGNORECASE,
        ),
    },
)


def normalize_path(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def make_finding(
    findings: list[Finding],
    seen: set[tuple[str, str, int | None, str]],
    *,
    severity: str,
    category: str,
    title: str,
    file: str,
    line: int | None,
    snippet: str,
    reason: str,
) -> None:
    key = (file, title, line, snippet)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            severity=severity,
            category=category,
            title=title,
            file=file,
            line=line,
            snippet=snippet.strip()[:220],
            reason=reason,
        )
    )


def is_hidden(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return any(part.startswith(".") for part in relative.parts)


def is_likely_text(path: Path, payload: bytes) -> bool:
    if path.name in LIKELY_TEXT_FILES or path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    return b"\x00" not in payload


def scan_lines(
    text: str,
    file_name: str,
    patterns: tuple[dict[str, object], ...],
    findings: list[Finding],
    seen: set[tuple[str, str, int | None, str]],
) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in patterns:
            if pattern["regex"].search(line):
                make_finding(
                    findings,
                    seen,
                    severity=str(pattern["severity"]),
                    category=str(pattern["category"]),
                    title=str(pattern["title"]),
                    file=file_name,
                    line=line_no,
                    snippet=line,
                    reason=str(pattern["reason"]),
                )


def parse_description(skill_text: str) -> str | None:
    match = FRONTMATTER_RE.match(skill_text)
    if not match:
        return None
    frontmatter = match.group(1)
    description = DESCRIPTION_RE.search(frontmatter)
    if not description:
        return None
    return description.group(1).strip()


def build_report(root: Path) -> dict[str, object]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, int | None, str]] = set()
    opaque_files: list[dict[str, str]] = []
    notes = [
        "This report is based on static inspection only.",
        "No code from the reviewed skill was executed.",
    ]
    inventory = {
        "total_files": 0,
        "text_files_scanned": 0,
        "opaque_files": 0,
        "skipped_directories": sorted(SKIP_DIRS),
    }

    skill_md_path = root / "SKILL.md"
    if not skill_md_path.exists():
        make_finding(
            findings,
            seen,
            severity="medium",
            category="structure",
            title="Missing SKILL.md",
            file="SKILL.md",
            line=None,
            snippet="",
            reason="A valid skill should include SKILL.md at the root.",
        )

    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir():
            continue

        inventory["total_files"] += 1
        relative = normalize_path(path, root)

        if path.is_symlink():
            make_finding(
                findings,
                seen,
                severity="medium",
                category="filesystem",
                title="Symlink present",
                file=relative,
                line=None,
                snippet="",
                reason="Symlinks can obscure what the skill really contains.",
            )
            continue

        if is_hidden(path, root):
            make_finding(
                findings,
                seen,
                severity="medium",
                category="filesystem",
                title="Hidden file present",
                file=relative,
                line=None,
                snippet="",
                reason="Hidden files deserve manual review in downloaded skills.",
            )

        if path.suffix.lower() in SUSPICIOUS_BINARY_EXTENSIONS:
            opaque_files.append({"file": relative, "reason": "suspicious binary or archive"})
            inventory["opaque_files"] += 1
            if path.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".jar", ".msi", ".com"}:
                make_finding(
                    findings,
                    seen,
                    severity="high",
                    category="binary",
                    title="Executable binary present",
                    file=relative,
                    line=None,
                    snippet="",
                    reason="Downloaded skills normally should not require embedded executables.",
                )
            continue

        try:
            file_size = path.stat().st_size
        except OSError:
            opaque_files.append({"file": relative, "reason": "file metadata could not be read"})
            inventory["opaque_files"] += 1
            continue

        if file_size > MAX_SCAN_BYTES:
            opaque_files.append({"file": relative, "reason": "oversized file not scanned as text"})
            inventory["opaque_files"] += 1
            continue

        try:
            payload = path.read_bytes()
        except OSError:
            opaque_files.append({"file": relative, "reason": "file contents could not be read"})
            inventory["opaque_files"] += 1
            continue

        if not is_likely_text(path, payload):
            opaque_files.append({"file": relative, "reason": "binary or non-text file"})
            inventory["opaque_files"] += 1
            continue

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = payload.decode("utf-8-sig")
            except UnicodeDecodeError:
                opaque_files.append({"file": relative, "reason": "text decoding failed"})
                inventory["opaque_files"] += 1
                continue

        inventory["text_files_scanned"] += 1

        if path.suffix.lower() in TEXT_EXTENSIONS and path.suffix.lower() not in {".md", ".txt"}:
            scan_lines(text, relative, PATTERNS, findings, seen)

        if path.name == "SKILL.md" or path.suffix.lower() in {".md", ".txt"}:
            scan_lines(text, relative, PROMPT_PATTERNS, findings, seen)

        if path.name == "SKILL.md":
            description = parse_description(text)
            if description is None:
                make_finding(
                    findings,
                    seen,
                    severity="medium",
                    category="structure",
                    title="Malformed SKILL.md frontmatter",
                    file=relative,
                    line=None,
                    snippet="",
                    reason="The root SKILL.md is missing readable YAML frontmatter.",
                )
            else:
                for pattern in BROAD_TRIGGER_PATTERNS:
                    if pattern["regex"].search(description):
                        make_finding(
                            findings,
                            seen,
                            severity=str(pattern["severity"]),
                            category=str(pattern["category"]),
                            title=str(pattern["title"]),
                            file=relative,
                            line=2,
                            snippet=description,
                            reason=str(pattern["reason"]),
                        )

        if path.name == "openai.yaml" and ALLOW_IMPLICIT_RE.search(text):
            description_text = ""
            if skill_md_path.exists():
                try:
                    description_text = skill_md_path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    description_text = ""
            description = parse_description(description_text) or ""
            for pattern in BROAD_TRIGGER_PATTERNS:
                if pattern["regex"].search(description):
                    make_finding(
                        findings,
                        seen,
                        severity="medium",
                        category="broad-trigger",
                        title="Broad trigger with implicit invocation",
                        file=relative,
                        line=None,
                        snippet="allow_implicit_invocation: true",
                        reason="A broadly triggered skill should not be implicitly invoked without extra review.",
                    )

    findings.sort(key=lambda item: (severity_rank(item.severity), item.file, item.line or 0, item.title))

    has_high = any(item.severity == "high" for item in findings)
    has_any_review_item = bool(findings or opaque_files)
    if has_high:
        verdict = "unsafe"
        risk_level = "high"
    elif has_any_review_item:
        verdict = "needs-manual-review"
        risk_level = "medium"
    else:
        verdict = "appears-safe"
        risk_level = "low"

    if opaque_files:
        notes.append("Opaque files should be reviewed manually before trusting the skill.")

    report = {
        "target_path": str(root.resolve()),
        "verdict": verdict,
        "risk_level": risk_level,
        "key_findings": summarize_findings(findings, opaque_files),
        "findings": [asdict(item) for item in findings],
        "opaque_files": opaque_files,
        "notes": notes,
        "inventory": inventory,
    }
    return report


def severity_rank(severity: str) -> int:
    order = {"high": 0, "medium": 1, "low": 2}
    return order.get(severity, 3)


def summarize_findings(findings: list[Finding], opaque_files: list[dict[str, str]]) -> list[str]:
    summaries: list[str] = []
    for item in findings[:5]:
        location = f"{item.file}:{item.line}" if item.line else item.file
        summaries.append(f"[{item.severity}] {item.title} at {location}")
    if not summaries and opaque_files:
        summaries.append(f"Opaque files present: {len(opaque_files)}")
    if not summaries:
        summaries.append("No suspicious patterns were found in scanned text files.")
    return summaries


def format_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Skill Safety Review Report",
        "",
        f"- Target path: `{report['target_path']}`",
        f"- Verdict: `{report['verdict']}`",
        f"- Risk level: `{report['risk_level']}`",
        "",
        "## Key Findings",
    ]

    for summary in report["key_findings"]:
        lines.append(f"- {summary}")

    lines.extend(["", "## Findings"])
    findings = report["findings"]
    if findings:
        for finding in findings:
            location = f"{finding['file']}:{finding['line']}" if finding["line"] else finding["file"]
            lines.append(
                f"- [{finding['severity']}] {finding['title']} at `{location}`: {finding['reason']}"
            )
            if finding["snippet"]:
                lines.append(f"  - Snippet: `{finding['snippet']}`")
    else:
        lines.append("- No findings.")

    lines.extend(["", "## Opaque Files"])
    if report["opaque_files"]:
        for item in report["opaque_files"]:
            lines.append(f"- `{item['file']}`: {item['reason']}")
    else:
        lines.append("- None.")

    lines.extend(["", "## Notes"])
    for note in report["notes"]:
        lines.append(f"- {note}")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Statically review a local Codex skill directory for safety risks."
    )
    parser.add_argument("skill_dir", help="Path to the unpacked local skill directory")
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format. Defaults to json.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.skill_dir).resolve()

    if not root.exists():
        print(json.dumps({"error": f"Path not found: {root}"}, indent=2), file=sys.stderr)
        return 1
    if not root.is_dir():
        print(json.dumps({"error": f"Path is not a directory: {root}"}, indent=2), file=sys.stderr)
        return 1

    report = build_report(root)
    if args.format == "markdown":
        print(format_markdown(report))
    else:
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
