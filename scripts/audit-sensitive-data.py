#!/usr/bin/env python3
"""Reject prospective repository files containing private or unsafe material."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def joined(*parts: str) -> str:
    return "".join(parts)


PATTERNS = (
    ("macOS user home", re.compile(re.escape(joined("/", "Users/")) + r"[^\s\"'<>`]+")),
    ("Linux user home", re.compile(re.escape(joined("/", "home/")) + r"[^\s\"'<>`]+")),
    ("Windows user home", re.compile(r"[A-Za-z]:\\" + joined("Us", "ers") + r"\\[^\s\"'<>`]+")),
    ("mounted host volume", re.compile(re.escape(joined("/Vol", "umes/")) + r"[^\s\"'<>`]+")),
    (
        "personal cache or workspace",
        re.compile(r"~/" + r"(?:Projects|Library|Desktop|Documents|Downloads|\.cursor|\.codex|\.kimi-code)/[^\s\"'<>`]*"),
    ),
    ("host temporary path", re.compile(re.escape(joined("/private/var/", "folders/")) + r"[^\s\"'<>`]+")),
    ("local file URL", re.compile(joined("fi", "le://"), re.IGNORECASE)),
    ("workstation identity", re.compile(joined("byte", "dance"), re.IGNORECASE)),
    ("internal user metadata", re.compile(joined("user-", 'id="ou_'), re.IGNORECASE)),
    (
        "internal collaboration URL",
        re.compile(
            joined(
                r"https?://[^\s\)\]>]*(?:",
                "byte",
                "dance|lark",
                "office|fei",
                r"shu\.cn|byte",
                r"d\.org|tiktok-row)[^\s\)\]>]*",
            ),
            re.IGNORECASE,
        ),
    ),
    ("private key", re.compile(joined("-----BEGIN ", "PRIVATE KEY-----"))),
    ("private key", re.compile(joined("-----BEGIN ", "OPENSSH PRIVATE KEY-----"))),
    ("AWS access key", re.compile(joined("AK", "IA") + r"[0-9A-Z]{16}")),
    ("GitHub token", re.compile(joined("gh", r"[opusr]_") + r"[A-Za-z0-9_]{20,}")),
    ("GitHub token", re.compile(joined("github_", "pat_") + r"[A-Za-z0-9_]{20,}")),
    ("Slack credential", re.compile(joined(r"\bxox", r"[aboprs]-[A-Za-z0-9-]{20,}"))),
    ("npm credential", re.compile(joined(r"\bnpm_", r"[A-Za-z0-9]{30,}"))),
    ("Google API credential", re.compile(joined(r"\bAI", r"za[0-9A-Za-z_-]{30,}"))),
    ("Stripe credential", re.compile(joined(r"\b(?:sk|rk)_", r"(?:live|test)_[0-9A-Za-z]{16,}"))),
    ("generic PEM private key", re.compile(joined("-----BEGIN ", r"(?:RSA |EC |DSA )?PRIVATE KEY-----"))),
)

FORBIDDEN_NAMES = (
    ("private analysis artifact", re.compile(joined("detec", "tion-surface|reverse-engineer|private-notes"), re.IGNORECASE)),
    (
        "private assessment target",
        re.compile(
            joined(
                r"(?:^|[-_/])(?:mo", "mo|hun", "ter|maho", "shojo|zhen", "xi|kan", "xue|her", "dr|risk", r"hider)(?:[-_.\\/]|$)"
            ),
            re.IGNORECASE,
        ),
    ),
)

FORBIDDEN_DISCLOSURES = (
    (
        "private assessment target",
        re.compile(
            joined(
                r"\b(?:mo", "mo|hun", "ter|maho", "shojo|zhen", "xi|kan", "xue|her", "dr|risk", r"hider)\b"
            ),
            re.IGNORECASE,
        ),
    ),
    (
        "development analysis disclosure",
        re.compile(
            joined(
                r"\b(?:reverse[- ]engineer", "ing|analysis[- ]only|later ", "milestone|phase[- ]?1|tempor",
                r"ary workaround|priv", r"ate research notes)\b",
            ),
            re.IGNORECASE,
        ),
    ),
    ("bearer credential", re.compile(joined(r"\bBearer\s+", r"[A-Za-z0-9._~+/-]{20,}"))),
    ("JWT credential", re.compile(joined(r"\beyJ", r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\."))),
    ("OpenAI credential", re.compile(joined(r"\bsk", r"-[A-Za-z0-9_-]{20,}"))),
    (
        "embedded credential assignment",
        re.compile(
            joined(
                r"\b(?:password|passwd|secret|access[_-]?token|api[_-]?key)\s*[:=]\s*",
                r"[\"'][^\"'\s]{16,}[\"']",
            ),
            re.IGNORECASE,
        ),
    ),
)

CJK = re.compile(r"[\u3400-\u9fff]")
NON_ENGLISH_EXEMPT = {"README_CN.md"}


def candidate_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    files = candidate_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        for label, pattern in FORBIDDEN_NAMES:
            if pattern.search(relative):
                findings.append((relative, 0, label))
        try:
            data = path.read_bytes()
        except OSError:
            continue
        try:
            text = data.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            # Native artifacts may embed source paths, credentials, or private
            # labels even when the surrounding bytes are not UTF-8.
            text = data.decode("ascii", errors="ignore")
            is_text = False
        for line_number, line in enumerate(text.splitlines(), 1):
            for label, pattern in (*PATTERNS, *FORBIDDEN_DISCLOSURES):
                if pattern.search(line):
                    findings.append((relative, line_number, label))
            if is_text and relative not in NON_ENGLISH_EXEMPT and CJK.search(line):
                findings.append((relative, line_number, "non-English public text"))

    if findings:
        for path, line_number, label in findings:
            location = f"{path}:{line_number}" if line_number else path
            print(f"{location}: {label}")
        print(f"sensitive-data audit failed: {len(findings)} finding(s)")
        return 1

    print(f"sensitive-data audit passed: {len(files)} prospective files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
