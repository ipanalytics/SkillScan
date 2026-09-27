#!/usr/bin/env python3
"""skillscan — static analysis for agent skill folders.

Scans every SKILL.md (and the scripts bundled next to it) for the classes of
problem that make a skill library unsafe or unmaintainable:

  * broken frontmatter and duplicate skill names across the tree,
  * skills whose body grew past what a skill loader will read comfortably,
  * dangerous shell inside instructions or bundled scripts,
  * prompt-injection markers phrased at the agent reading the skill,
  * credentials and host-specific paths that should never be published,
  * references to files that no longer exist.

Standard library only, no installation step beyond copying one file.

Usage:
    python3 skillscan.py [PATH ...] [--json FILE] [--fail-on LEVEL]
                         [--max-skill-chars N] [--exclude GLOB] [--quiet]
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SKILL_FILE = "SKILL.md"
DEFAULT_MAX_SKILL_CHARS = 24000
SKIP_DIRS = {".git", ".hub", ".archive", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".rb", ".pl", ".ps1"}
SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# --- line rules -----------------------------------------------------------------
# (rule id, severity, compiled pattern, message)
LINE_RULES = [
    ("SS040", "high", re.compile(r"\b(curl|wget)\b[^\n|;&]*\|\s*(sudo\s+)?(ba|z|d)?sh\b"),
     "pipes a download straight into a shell"),
    ("SS040", "high", re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(/|\$HOME|\*)(\s|$)"),
     "recursive delete of a root, home or glob path"),
    ("SS041", "high", re.compile(r"\bmkfs(\.\w+)?\b|\bdd\s+if="),
     "writes raw filesystems"),
    ("SS041", "high", re.compile(r"\bchmod\s+(-R\s+)?777\b"),
     "grants world-writable permissions"),
    ("SS042", "high", re.compile(r":\(\)\s*\{.*\};\s*:"),
     "fork bomb"),
    ("SS043", "high", re.compile(r"\b(eval|exec)\s*\(|os\.system\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"),
     "executes strings or shells out without inspection"),
    ("SS044", "medium", re.compile(r"\bbase64\s+(-d|--decode)\b|\bb64decode\(|\batob\("),
     "decodes base64 — hidden payloads are invisible to review"),
    ("SS045", "medium", re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*~?/?\.bash_history"),
     "clears shell history"),
    ("SS050", "high", re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions", re.I),
     "prompt-injection marker aimed at the agent reading this skill"),
    ("SS050", "high", re.compile(r"disregard\s+(the\s+)?(system|previous|earlier)", re.I),
     "prompt-injection marker aimed at the agent reading this skill"),
    ("SS051", "high", re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention\s+to|ask)\s+(the\s+)?(user|owner|human)", re.I),
     "instructs the agent to keep the user uninformed"),
    ("SS051", "high", re.compile(r"without\s+(asking|telling|informing)\s+(the\s+)?(user|owner|human)", re.I),
     "instructs the agent to act without consent"),
    ("SS052", "high", re.compile(r"\bexfiltrat|send\s+(it|them|the\s+data|the\s+content)\s+to\s+(https?://|a\s+remote)", re.I),
     "describes sending data out of the machine"),
    ("SS060", "high", re.compile(r"\b(?:sk|rk)-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{18,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}"),
     "looks like a credential"),
    ("SS061", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "embedded private key"),
    ("SS070", "low", re.compile(r"/home/(?!<|\$|\*)[a-z0-9_.-]{2,}/"),
     "absolute home path — host-specific, misleading for anyone else"),
    ("SS070", "low", re.compile(r"/Users/(?!<|\$|\*)[A-Za-z0-9_.-]{2,}/"),
     "absolute macOS home path — host-specific"),
    ("SS071", "low", re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
     "private network address — publish only if it is the point of the skill"),
    ("SS072", "low", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "email address — check it is a role address, not a person"),
]

NETWORK_IN_SCRIPT = re.compile(r"\b(requests\.|urllib|httpx|socket\.|curl\s|wget\s|fetch\()")
FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n?", re.S)
PATH_REF_RE = re.compile(r"`([~/][^\s`'\"]{3,})`")
IGNORE_RE = re.compile(r"skillscan:\s*ignore(?:\s+([A-Z]{2}\d{3}(?:\s*,\s*[A-Z]{2}\d{3})*))?", re.I)


def ignore_directive(line: str) -> set[str] | None:
    """Inline suppression: `skillscan:ignore` or `skillscan:ignore SS040,SS043`.

    Returns None when the line carries no directive, an empty set when it
    suppresses every rule on that line, or the set of rule ids to suppress.
    """
    match = IGNORE_RE.search(line)
    if not match:
        return None
    rules = match.group(1)
    return set() if not rules else {r.strip().upper() for r in rules.split(",")}


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    snippet: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass
class Summary:
    skills: int = 0
    scripts: int = 0
    findings: list[Finding] = field(default_factory=list)
    duplicates: dict[str, list[str]] = field(default_factory=dict)

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


def parse_frontmatter(text: str) -> dict[str, str]:
    """Minimal frontmatter reader: top-level `key: value` pairs only."""
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}
    data: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw[:1] in (" ", "\t", "-"):
            continue
        key, sep, value = raw.partition(":")
        if sep:
            data[key.strip()] = value.strip().strip("'\"")
    return data


def iter_skill_files(root: Path, excludes: list[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        if any(fnmatch.fnmatch(str(here), pattern) or fnmatch.fnmatch(here.name, pattern)
               for pattern in excludes):
            dirnames[:] = []
            continue
        if SKILL_FILE in filenames:
            yield here / SKILL_FILE


def scan_text(path: str, text: str, sink: list[Finding], rules=LINE_RULES) -> int:
    hits = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line:
            continue
        ignored = ignore_directive(line)
        if ignored is not None and not ignored:
            continue  # whole line suppressed
        for rule, severity, pattern, message in rules:
            if ignored and rule in ignored:
                continue
            if pattern.search(line):
                sink.append(Finding(rule, severity, path, number, message, line.strip()[:160]))
                hits += 1
    return hits


def path_exists(candidate: Path) -> bool:
    """exists() that never raises: unreadable parents (e.g. /root) are not crashes."""
    try:
        return candidate.exists()
    except OSError:
        return False


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def check_references(skill_path: Path, text: str, sink: list[Finding]) -> None:
    """Flag backticked absolute paths that do not exist on this machine."""
    for number, raw in enumerate(text.splitlines(), start=1):
        for ref in PATH_REF_RE.findall(raw):
            if any(ch in ref for ch in "<>$*{}"):
                continue
            candidate = Path(os.path.expanduser(ref.split(":")[0]))
            if candidate.is_absolute() and not path_exists(candidate):
                sink.append(Finding("SS030", "info", str(skill_path), number,
                                    f"referenced path does not exist: {ref}", raw.strip()[:160]))


def scan_skill(skill_path: Path, summary: Summary, max_chars: int) -> None:
    text = read_text(skill_path)
    if text is None:
        summary.findings.append(Finding("SS090", "medium", str(skill_path), 0, "file is not readable"))
        return
    summary.skills += 1
    folder = skill_path.parent
    rel = str(skill_path)

    front = parse_frontmatter(text)
    front_match = FRONTMATTER_RE.match(text)
    body = text[front_match.end():] if front_match else text
    if not front:
        summary.findings.append(Finding("SS001", "medium", rel, 1, "no YAML frontmatter"))
    else:
        if not front.get("name"):
            summary.findings.append(Finding("SS002", "medium", rel, 1, "frontmatter has no `name`"))
        elif front["name"] != folder.name:
            summary.findings.append(Finding(
                "SS003", "medium", rel, 1,
                f"`name: {front['name']}` does not match the folder `{folder.name}`",
            ))
        if not front.get("description"):
            summary.findings.append(Finding("SS004", "medium", rel, 1, "frontmatter has no `description`"))
        if front.get("name"):
            summary.duplicates.setdefault(front["name"], []).append(str(skill_path))

    if len(body) > max_chars:
        summary.findings.append(Finding(
            "SS020", "medium", rel, 1,
            f"body is {len(body)} chars, over the {max_chars}-char budget — split into references/",
        ))

    scan_text(rel, text, summary.findings)
    check_references(skill_path, text, summary.findings)

    for script in sorted(folder.rglob("*")):
        if not script.is_file() or script.suffix not in SCRIPT_SUFFIXES or script == skill_path:
            continue
        if any(part in SKIP_DIRS for part in script.parts):
            continue
        summary.scripts += 1
        content = read_text(script)
        if content is None:
            continue
        scan_text(str(script), content, summary.findings)
        for number, raw in enumerate(content.splitlines(), start=1):
            if NETWORK_IN_SCRIPT.search(raw):
                summary.findings.append(Finding(
                    "SS080", "info", str(script), number,
                    "bundled script calls the network — review before installing",
                    raw.strip()[:160],
                ))
                break


def scan(roots: list[Path], excludes: list[str], max_chars: int) -> Summary:
    summary = Summary()
    for root in roots:
        if not root.exists():
            continue
        for skill in iter_skill_files(root, excludes):
            scan_skill(skill, summary, max_chars)
    for name, paths in summary.duplicates.items():
        if len(paths) > 1:
            for path in paths:
                summary.findings.append(Finding(
                    "SS010", "high", path, 0,
                    f"skill name `{name}` is used by {len(paths)} folders: "
                    + ", ".join(sorted(p.rsplit('/SKILL.md', 1)[0] for p in paths)),
                ))
    summary.findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line))
    return summary


def render_text(summary: Summary, quiet: bool) -> str:
    out: list[str] = []
    if not quiet:
        for finding in summary.findings:
            head = f"{finding.path}:{finding.line} [{finding.severity}] {finding.rule} {finding.message}"
            out.append(head)
            if finding.snippet:
                out.append(f"    {finding.snippet}")
    counts = ", ".join(f"{s}={summary.count(s)}" for s in reversed(SEVERITIES))
    out.append(f"{summary.skills} skills, {summary.scripts} bundled scripts scanned — {counts}")
    return "\n".join(out)


def render_annotations(summary: Summary) -> str:
    """GitHub Actions annotations; informational findings stay in the log."""
    level = {"high": "error", "medium": "warning", "low": "notice", "info": "notice"}
    lines = []
    for finding in summary.findings:
        if finding.severity == "info":
            continue
        lines.append(
            f"::{level[finding.severity]} file={finding.path},line={max(finding.line, 1)},"
            f"title={finding.rule}::{finding.message}"
        )
    return "\n".join(lines)


def fingerprint(finding: Finding) -> str:
    """Stable id for a finding: rule + folder/file + the offending line."""
    path = Path(finding.path)
    key = f"{finding.rule}|{path.parent.name}/{path.name}|{finding.snippet}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read baseline {path}: {exc}") from exc
    return set(data.get("fingerprints", []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skillscan", description="Static scan of agent skill folders.")
    parser.add_argument("paths", nargs="*", default=["."], help="folders to scan (default: current)")
    parser.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    parser.add_argument("--annotations", action="store_true", help="emit GitHub Actions annotations")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high",
                        help="lowest severity that makes the run fail (default: high)")
    parser.add_argument("--max-skill-chars", type=int, default=DEFAULT_MAX_SKILL_CHARS,
                        help=f"body size budget (default: {DEFAULT_MAX_SKILL_CHARS})")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip paths matching the glob (repeatable)")
    parser.add_argument("--baseline", metavar="FILE",
                        help="ignore findings recorded in FILE (fail only on new ones)")
    parser.add_argument("--write-baseline", metavar="FILE",
                        help="record the current findings as a baseline for --baseline")
    parser.add_argument("--quiet", action="store_true", help="print only the summary line")
    args = parser.parse_args(argv)

    roots = [Path(p) for p in (args.paths or ["."])]
    missing = [str(r) for r in roots if not r.exists()]
    if missing and len(missing) == len(roots):
        parser.error("nothing to scan: " + ", ".join(missing))

    summary = scan(roots, args.exclude, args.max_skill_chars)

    if args.write_baseline:
        payload = {
            "generated_from": [str(r) for r in roots],
            "fingerprints": sorted({fingerprint(f) for f in summary.findings}),
        }
        Path(args.write_baseline).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"baseline written: {args.write_baseline} ({len(payload['fingerprints'])} findings)")

    known: set[str] = load_baseline(Path(args.baseline)) if args.baseline else set()
    if known:
        before = len(summary.findings)
        summary.findings = [f for f in summary.findings if fingerprint(f) not in known]
        suppressed = before - len(summary.findings)
        if suppressed and not args.quiet:
            print(f"{suppressed} finding(s) suppressed by baseline")

    print(render_text(summary, args.quiet))
    if args.annotations:
        annotations = render_annotations(summary)
        if annotations:
            print(annotations)

    if args.json:
        Path(args.json).write_text(json.dumps({
            "skills": summary.skills,
            "scripts": summary.scripts,
            "counts": {s: summary.count(s) for s in SEVERITIES},
            "findings": [f.as_dict() for f in summary.findings],
        }, indent=2, ensure_ascii=False), encoding="utf-8")

    threshold = SEVERITY_RANK[args.fail_on]
    if args.write_baseline:
        # Recording a baseline is not a gate: the run's job was to write the file.
        return 0
    worst = max((SEVERITY_RANK[f.severity] for f in summary.findings), default=-1)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
