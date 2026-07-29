#!/usr/bin/env python3
"""Validate lowercase English Angular-style commit messages."""

from __future__ import annotations

import re
import sys
from pathlib import Path

TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
HEADER = re.compile(
    rf"^(?:{'|'.join(TYPES)})(?:\([a-z0-9][a-z0-9._/-]*\))?!?: [a-z0-9][a-z0-9 .,/'`+_:-]*$"
)
MAX_HEADER_LENGTH = 100


def validate(message: str) -> list[str]:
    header = message.splitlines()[0].strip() if message.splitlines() else ""
    errors: list[str] = []
    if not header:
        errors.append("commit header must not be empty")
        return errors
    if len(header) > MAX_HEADER_LENGTH:
        errors.append(f"commit header must be at most {MAX_HEADER_LENGTH} characters")
    if not header.isascii():
        errors.append("commit header must use English ASCII characters")
    if header != header.lower():
        errors.append("commit header must be lowercase")
    if header.endswith("."):
        errors.append("commit header must not end with a period")
    if not HEADER.fullmatch(header):
        errors.append("commit header must match lowercase Angular format: type(scope): subject")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <commit-message-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    errors = validate(path.read_text(encoding="utf-8"))
    if not errors:
        return 0
    print("invalid commit message:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    print(f"allowed types: {', '.join(TYPES)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
