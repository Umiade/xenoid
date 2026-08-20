#!/usr/bin/env python3
"""Run the JVM-only ProxyStateStore transaction and recovery contracts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "daemon"
TEST_CLASS = "dev.xenoid.daemon.ProxyStateStoreTest"
sys.path.insert(0, str(ROOT / "src"))
from xenoid.process import run_bounded  # noqa: E402


def _gradle_command() -> list[str] | None:
    wrapper = DAEMON / "gradlew"
    if wrapper.is_file() and os.access(wrapper, os.X_OK):
        return [str(wrapper)]
    gradle = shutil.which("gradle")
    return [gradle] if gradle else None


def main() -> int:
    command = _gradle_command()
    if command is None:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "gradle_unavailable",
                    "testClass": TEST_CLASS,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    completed = run_bounded(
        [
            *command,
            "--no-daemon",
            "--console=plain",
            ":app:testDebugUnitTest",
            "--tests",
            TEST_CLASS,
        ],
        cwd=DAEMON,
        deadline=time.monotonic() + 300.0,
        env={
            **os.environ,
            "LC_ALL": "C",
            "TZ": "UTC",
        },
        project_root=ROOT,
    )
    ok = completed.ok
    print(
        json.dumps(
            {
                "ok": ok,
                "error": (
                    None
                    if ok
                    else completed.error_code
                    or "proxy_state_contract_failed"
                ),
                "returncode": completed.returncode,
                **(
                    {}
                    if ok
                    else {
                        "detail": (
                            completed.stderr_tail
                            or completed.stdout_tail
                        )[-1024:]
                    }
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
