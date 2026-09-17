#!/usr/bin/env python3
"""Reject prospective repository files containing private or unsafe material."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from xenoid.google_services import registered_metadata_files
from xenoid.sensitive import scan_sensitive_bytes
from xenoid.process import run_bounded

REGISTERED_GOOGLE_METADATA = registered_metadata_files()


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

# Byte-applicable privacy rules are owned by xenoid.sensitive.
PATTERNS = ()
FORBIDDEN_DISCLOSURES = ()

CJK = re.compile(r"[\u3400-\u9fff]")
NON_ENGLISH_EXEMPT = {"README_CN.md", "CHANGELOG_CN.md"}


class InventoryError(RuntimeError):
    pass


def _candidate_names() -> tuple[list[str], bytes]:
    captured = bytearray()
    result = run_bounded(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        deadline=time.monotonic() + 60.0,
        project_root=ROOT,
        stdout_consumer=captured.extend,
    )
    if not result.ok:
        raise InventoryError("sensitive_inventory_unavailable")
    names: list[str] = []
    for item in bytes(captured).split(b"\0"):
        if not item:
            continue
        try:
            relative = item.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("sensitive_inventory_invalid") from exc
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative != candidate.as_posix():
            raise InventoryError("sensitive_inventory_invalid")
        names.append(relative)
    if len(names) != len(set(names)):
        raise InventoryError("sensitive_inventory_invalid")
    names.sort(key=lambda value: value.encode())
    return names, bytes(captured)


def candidate_inventory() -> list[tuple[Path, bytes | None, int]]:
    names, before_inventory = _candidate_names()
    entries: list[tuple[Path, bytes | None, int]] = []
    missing: list[Path] = []
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    for relative in names:
        path = ROOT / relative
        try:
            before = path.lstat()
        except FileNotFoundError:
            missing.append(path)
            continue
        except OSError as exc:
            raise InventoryError("sensitive_candidate_unreadable") from exc
        mode = stat.S_IMODE(before.st_mode)
        if stat.S_ISLNK(before.st_mode):
            entries.append((path, None, mode))
            continue
        if not stat.S_ISREG(before.st_mode):
            entries.append((path, None, mode))
            continue
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise InventoryError("sensitive_candidate_changed")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise InventoryError("sensitive_candidate_unreadable") from exc
        try:
            current = path.lstat()
        except OSError as exc:
            raise InventoryError("sensitive_candidate_changed") from exc
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or identity != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ):
            raise InventoryError("sensitive_candidate_changed")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise InventoryError("sensitive_candidate_changed")
        entries.append((path, data, mode))
    for path in missing:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InventoryError("sensitive_candidate_changed") from exc
        raise InventoryError("sensitive_candidate_changed")
    _, after_inventory = _candidate_names()
    if after_inventory != before_inventory:
        raise InventoryError("sensitive_inventory_changed")
    return entries


def inventory_evidence(entries: list[tuple[Path, bytes | None, int]]) -> dict[str, object]:
    digest = hashlib.sha256()
    for path, data, mode in entries:
        relative = path.relative_to(ROOT).as_posix()
        record = {
            "path": relative,
            "mode": mode,
            "type": "file" if data is not None else "unsafe",
            "size": len(data) if data is not None else 0,
            "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
        }
        digest.update(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return {"sha256": digest.hexdigest(), "count": len(entries)}


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    try:
        inventory = candidate_inventory()
    except InventoryError as exc:
        print(str(exc))
        return 1
    for path, data, _mode in inventory:
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(".xenoid/"):
            findings.append((relative, 0, "private runtime state path"))
        if Path(relative).suffix.lower() in {".zip", ".pem"}:
            findings.append((relative, 0, "proprietary import payload"))
        if relative.startswith("data/google-services/"):
            expected = REGISTERED_GOOGLE_METADATA.get(relative)
            if expected is None:
                findings.append((relative, 0, "unregistered Google release metadata"))
        for label, pattern in FORBIDDEN_NAMES:
            if pattern.search(relative):
                findings.append((relative, 0, label))
        if data is None:
            findings.append((relative, 0, "unsafe prospective file type"))
            continue
        for label in scan_sensitive_bytes(data):
            findings.append((relative, 0, label))
        if relative in REGISTERED_GOOGLE_METADATA and (
            hashlib.sha256(data).hexdigest()
            != REGISTERED_GOOGLE_METADATA[relative]
        ):
            findings.append((relative, 0, "Google release metadata hash mismatch"))
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

    print(f"sensitive-data audit passed: {len(inventory)} prospective files")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory-digest", action="store_true")
    arguments = parser.parse_args()
    if arguments.inventory_digest:
        try:
            print(
                json.dumps(
                    inventory_evidence(candidate_inventory()),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        except InventoryError as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(main())
