#!/usr/bin/env python3
"""Runtime-free smoke for actionable macOS installer failures."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "xenoid"


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_brew_failure(*, docker_completion_installed: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="xenoid-install-runtime-") as temp_dir:
        temp = Path(temp_dir)
        fake_bin = temp / "bin"
        fake_bin.mkdir()
        write_executable(
            fake_bin / "uname",
            """#!/bin/sh
case "${1:-}" in
  -s) printf '%s\\n' Darwin ;;
  -m) printf '%s\\n' arm64 ;;
  *) exit 64 ;;
esac
""",
        )
        completion_status = 0 if docker_completion_installed else 1
        write_executable(
            fake_bin / "brew",
            f"""#!/bin/sh
if [ "${{1:-}}" = install ]; then
  printf '%s\\n' 'synthetic brew link failure'
  exit 37
fi
if [ "${{1:-}}" = list ] && [ "${{2:-}}" = --formula ] && [ "${{3:-}}" = docker-completion ]; then
  exit {completion_status}
fi
printf '%s\\n' "unexpected brew invocation: $*" >&2
exit 64
""",
        )
        env = {
            **os.environ,
            "HOME": str(temp / "home"),
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        }
        proc = subprocess.run(
            [str(CLI), "install-runtime"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        payload = json.loads(proc.stdout)
        return {
            "returncode": proc.returncode,
            "scriptReturncode": payload.get("returncode"),
            "stdout": payload.get("stdout"),
            "stderr": payload.get("stderr"),
            "cliStderr": proc.stderr,
        }




def main() -> int:
    conflict = run_brew_failure(docker_completion_installed=True)
    unrelated = run_brew_failure(docker_completion_installed=False)
    dry_run = subprocess.run(
        [str(CLI), "install-runtime", "--dry-run"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        dry_run_result = json.loads(dry_run.stdout)
        dry_run_script_result = json.loads(dry_run_result.get("stdout", ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        dry_run_result = {}
        dry_run_script_result = {}
    required_guidance = (
        "Xenoid detected the deprecated Homebrew docker-completion formula.",
        "brew uninstall docker-completion",
        "brew link docker",
        "type -a docker",
        "./xenoid install-runtime",
        "Avoid `brew link --overwrite docker`",
    )
    cases = {
        "dockerCompletionConflict": {
            "ok": conflict["returncode"] == 1
            and conflict["scriptReturncode"] == 37
            and conflict["stdout"] == "synthetic brew link failure"
            and conflict["cliStderr"] == ""
            and all(text in conflict["stderr"] for text in required_guidance),
            **conflict,
        },
        "unrelatedBrewFailure": {
            "ok": unrelated["returncode"] == 1
            and unrelated["scriptReturncode"] == 37
            and unrelated["stdout"] == "synthetic brew link failure"
            and unrelated["cliStderr"] == ""
            and "Xenoid detected" not in unrelated["stderr"],
            **unrelated,
        },
        "installRuntimeDryRunIsObservational": {
            "ok": dry_run.returncode == 0
            and dry_run_result.get("ok") is True
            and dry_run_script_result.get("dryRun") is True
            and dry_run.stderr == "",
            "returncode": dry_run.returncode,
            "stdout": dry_run.stdout,
            "stderr": dry_run.stderr,
        },
    }
    result = {"ok": all(case["ok"] for case in cases.values()), "cases": cases}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
