#!/usr/bin/env python3
"""Runtime-free smoke for actionable macOS installer failures."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "xenoid"


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


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




def run_plugin_install(*, occupied: bool = False, broken: bool = False) -> dict[str, Any]:
    """Run the real installer with isolated package-manager and engine boundaries."""
    with tempfile.TemporaryDirectory(prefix="xenoid-buildx-install-") as temp_dir:
        temp = Path(temp_dir)
        fake_bin = temp / "bin"
        fake_bin.mkdir()
        home = temp / "home"
        docker_config = home / "docker-config"
        link = docker_config / "cli-plugins/docker-buildx"
        link.parent.mkdir(parents=True)
        if occupied:
            link.write_text("operator-owned plugin")
        else:
            link.symlink_to(temp / "removed-Docker.app/docker-buildx")
        prefix = temp / "brew"
        java_bin = prefix / "libexec/openjdk.jdk/Contents/Home/bin"
        java_bin.mkdir(parents=True)
        for command in ("java", "javac", "keytool", "jarsigner"):
            write_executable(java_bin / command, "#!/bin/sh\nexit 0\n")
        plugin = prefix / "bin/docker-buildx"
        plugin.parent.mkdir()
        sdk = temp / "sdk"
        for name in ("build-tools/35.0.0/aapt2", "build-tools/35.0.0/apksigner",
                     "cmake/3.22.1/bin/cmake", "cmake/3.22.1/bin/ninja",
                     "ndk/27.2.12479018/toolchains/llvm/prebuilt/test/bin/aarch64-linux-android21-clang"):
            tool = sdk / name
            tool.parent.mkdir(parents=True, exist_ok=True)
            write_executable(tool, "#!/bin/sh\nexit 0\n")
        (sdk / "platforms/android-35").mkdir(parents=True)
        (sdk / "platforms/android-35/android.jar").touch()
        write_executable(fake_bin / "uname", "#!/bin/sh\ncase $1 in -s) echo Darwin;; -m) echo arm64;; esac\n")
        write_executable(fake_bin / "brew", """#!/bin/sh
if [ "$1" = --prefix ]; then printf '%s\n' "$TEST_PREFIX"; exit 0; fi
if [ "$1" = install ]; then
  for arg in "$@"; do
    if [ "$arg" = docker-buildx ]; then
      printf '#!/bin/sh\nexit %s\n' "$TEST_PLUGIN_EXIT" > "$TEST_PREFIX/bin/docker-buildx"
      chmod +x "$TEST_PREFIX/bin/docker-buildx"
    fi
  done
fi
"""
        )
        write_executable(fake_bin / "docker", """#!/bin/sh
if [ "$1" != --context ] || [ "$2" != colima ]; then exit 91; fi
shift 2
case "$1 $2" in
  'buildx version') exec "$DOCKER_CONFIG/cli-plugins/docker-buildx" version ;;
  'image inspect')
    if [ "$3" = --format ]; then printf '%s\n' "$TEST_BASE_ID"; fi ;;
esac
"""
        )
        write_executable(fake_bin / "rustup", """#!/bin/sh
if [ "$1 $2" = 'target list' ]; then echo aarch64-linux-android; fi
exit 0
""")
        for command in ("colima", "sdkmanager", "adb", "scrcpy"):
            write_executable(fake_bin / command, "#!/bin/sh\nexit 0\n")
        # The expected base identity belongs to configuration, not this test.
        import sys
        sys.path.insert(0, str(ROOT / "src"))
        from xenoid.config import DEFAULT_IMAGE_ID

        env = {
            **os.environ, "HOME": str(home), "DOCKER_CONFIG": str(docker_config),
            "DOCKER_CONTEXT": "desktop-linux", "ANDROID_HOME": str(sdk),
            "XENOID_NDK_VERSION": "27.2.12479018", "TEST_PREFIX": str(prefix),
            "TEST_BASE_ID": DEFAULT_IMAGE_ID, "TEST_PLUGIN_EXIT": "42" if broken else "0",
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        }
        proc = subprocess.run(["bash", str(ROOT / "scripts/install-macos-runtime.sh")],
                              cwd=ROOT, env=env, capture_output=True, text=True, check=False)
        return {
            "returncode": proc.returncode,
            "registered": link.is_symlink() and link.resolve() == plugin.resolve(),
            "preserved": occupied and link.read_text() == "operator-owned plugin",
        }


def main() -> int:
    conflict = run_brew_failure(docker_completion_installed=True)
    unrelated = run_brew_failure(docker_completion_installed=False)
    installed = run_plugin_install()
    occupied = run_plugin_install(occupied=True)
    broken = run_plugin_install(broken=True)
    with tempfile.TemporaryDirectory(prefix="xenoid-install-dry-run-") as temp_dir:
        home = Path(temp_dir) / "home"
        home.mkdir()
        dry_run = subprocess.run(
            [str(CLI), "install-runtime", "--dry-run"], cwd=ROOT,
            env={**os.environ, "HOME": str(home)},
            text=True, capture_output=True, check=False,
        )
        dry_result = json.loads(dry_run.stdout)
        dry_script = json.loads(dry_result["stdout"])
        untouched = not list(home.iterdir())
    cases = {
        "packageFailurePreservesExitCode": {
            "ok": all(result["returncode"] == 1 and result["scriptReturncode"] == 37
                      for result in (conflict, unrelated)),
        },
        "replacesRemovedDesktopPluginAndUsesColima": {
            "ok": installed["returncode"] == 0 and installed["registered"], **installed,
        },
        "preservesUnmanagedPluginFile": {
            "ok": occupied["returncode"] != 0 and occupied["preserved"], **occupied,
        },
        "rejectsUnusablePlugin": {
            "ok": broken["returncode"] == 42, **broken,
        },
        "installRuntimeDryRunIsObservational": {
            "ok": dry_run.returncode == 0 and dry_result.get("ok") is True
            and dry_script.get("dryRun") is True and untouched,
        },
    }
    result = {"ok": all(case["ok"] for case in cases.values()), "cases": cases}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
