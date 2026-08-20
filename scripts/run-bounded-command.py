#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.process import run_bounded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", required=True, type=float)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if not arguments.command:
        raise SystemExit(64)
    result = run_bounded(
        arguments.command,
        cwd=ROOT,
        deadline=arguments.deadline,
        project_root=ROOT,
    )
    if result.stdout_tail:
        print(result.stdout_tail)
    if not result.ok:
        print(result.error_code or "release_process_failed", file=sys.stderr)
        if result.stderr_tail:
            print(result.stderr_tail, file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
