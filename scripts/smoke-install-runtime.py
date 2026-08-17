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


def run_up_host_runtime(*, local_colima: bool, dry_run: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="xenoid-up-host-runtime-") as temp_dir:
        temp = Path(temp_dir)
        project = temp / "project"
        scripts = project / "scripts"
        fake_bin = temp / "bin"
        scripts.mkdir(parents=True)
        fake_bin.mkdir()
        (scripts / "xenoid-up.sh").write_bytes((ROOT / "scripts" / "xenoid-up.sh").read_bytes())
        (scripts / "xenoid-up.sh").chmod(0o755)
        log_path = temp / "calls.log"
        write_executable(
            fake_bin / "python3",
            """#!/bin/sh
if [ "${1:-}" = - ]; then
  cat >/dev/null
  [ "${XENOID_TEST_LOCAL_COLIMA:-0}" = 1 ]
  exit $?
fi
exec "$XENOID_TEST_REAL_PYTHON" "$@"
""",
        )
        write_executable(
            fake_bin / "colima",
            """#!/bin/sh
printf 'colima:%s\\n' "$*" >>"$XENOID_TEST_CALL_LOG"
exit 0
""",
        )
        write_executable(
            project / "xenoid",
            """#!/bin/sh
printf 'xenoid:%s\\n' "$*" >>"$XENOID_TEST_CALL_LOG"
case " $* " in
  *' build all '*) exit 37 ;;
  *) exit 0 ;;
esac
""",
        )
        env = {
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "XENOID_TEST_CALL_LOG": str(log_path),
            "XENOID_TEST_LOCAL_COLIMA": "1" if local_colima else "0",
            "XENOID_TEST_REAL_PYTHON": os.environ.get("PYTHON", os.sys.executable),
            "XENOID_UP_LOCKED": "1",
        }
        args = [str(scripts / "xenoid-up.sh"), "--instance", "contract"]
        if dry_run:
            args.append("--dry-run")
        proc = subprocess.run(
            args,
            cwd=project,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        calls = log_path.read_text().splitlines() if log_path.exists() else []
        return {
            "returncode": proc.returncode,
            "calls": calls,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }


def main() -> int:
    conflict = run_brew_failure(docker_completion_installed=True)
    unrelated = run_brew_failure(docker_completion_installed=False)
    local_up = run_up_host_runtime(local_colima=True)
    remote_up = run_up_host_runtime(local_colima=False)
    dry_run = run_up_host_runtime(local_colima=True, dry_run=True)
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
            and conflict["stdout"] == "synthetic brew link failure\n"
            and conflict["cliStderr"] == ""
            and all(text in conflict["stderr"] for text in required_guidance),
            **conflict,
        },
        "unrelatedBrewFailure": {
            "ok": unrelated["returncode"] == 1
            and unrelated["scriptReturncode"] == 37
            and unrelated["stdout"] == "synthetic brew link failure\n"
            and unrelated["cliStderr"] == ""
            and "Xenoid detected" not in unrelated["stderr"],
            **unrelated,
        },
        "upStartsLocalColimaBeforeBuild": {
            "ok": local_up["returncode"] == 37
            and local_up["calls"][:2]
            == [
                "colima:start --arch aarch64 --vm-type vz --memory 8 --cpu 8",
                "xenoid:--instance contract build all",
            ],
            **local_up,
        },
        "upDoesNotStartColimaForRemoteBackend": {
            "ok": remote_up["returncode"] == 37
            and not any(call.startswith("colima:") for call in remote_up["calls"])
            and remote_up["calls"][:1] == ["xenoid:--instance contract build all"],
            **remote_up,
        },
        "upDryRunDoesNotStartColima": {
            "ok": dry_run["returncode"] == 0
            and dry_run["calls"] == []
            and "colima start --arch aarch64 --vm-type vz --memory 8 --cpu 8"
            in dry_run["stdout"],
            **dry_run,
        },
    }
    result = {"ok": all(case["ok"] for case in cases.values()), "cases": cases}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
