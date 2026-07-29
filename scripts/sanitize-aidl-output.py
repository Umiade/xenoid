#!/usr/bin/env python3
"""Remove host-specific AIDL invocation provenance from generated sources."""

from __future__ import annotations

from pathlib import Path
import sys

PROVENANCE_PREFIX = " * Using: "


def sanitize(path: Path) -> bool:
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        return False
    lines = text.splitlines(keepends=True)
    filtered = [line for line in lines if not line.startswith(PROVENANCE_PREFIX)]
    if filtered == lines:
        return False
    path.write_text("".join(filtered))
    return True


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} PATH [PATH ...]")

    changed = 0
    for argument in sys.argv[1:]:
        root = Path(argument)
        candidates = [root] if root.is_file() else root.rglob("*")
        for candidate in candidates:
            if candidate.is_file() and sanitize(candidate):
                changed += 1
    print(f"sanitized AIDL provenance in {changed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
