#!/usr/bin/env python3
"""Run one shared host-protection operation under a portable advisory lock."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import subprocess
import sys

LOCK_PATH = Path(os.environ.get("XENOID_SHARED_PROTECTION_LOCK", "/tmp/xenoid-shared-protection.lock"))
LOCKED_ENV = "XENOID_SHARED_PROTECTION_LOCKED"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: with-shared-protection-lock.py COMMAND [ARG ...]", file=sys.stderr)
        return 2
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        environment = os.environ.copy()
        environment[LOCKED_ENV] = "1"
        return subprocess.run(sys.argv[1:], env=environment, check=False).returncode
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
