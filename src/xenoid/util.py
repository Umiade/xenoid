from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, Union


_RELEASE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_COMMAND_DEADLINE: ContextVar[Optional[float]] = ContextVar(
    "xenoid_command_deadline",
    default=None,
)


def validate_release_version(value: Any) -> str:
    """Return one path-safe release/OTA version or raise a stable error."""
    if not isinstance(value, str) or _RELEASE_VERSION_RE.fullmatch(value) is None:
        raise ValueError("release_version_invalid")
    return value


def android_sdk_dir() -> Optional[Path]:
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(key)
        if val and Path(val).exists():
            return Path(val)
    default = Path.home() / "Library" / "Android" / "sdk"
    if default.exists():
        return default
    linux_default = Path.home() / "Android" / "Sdk"
    if linux_default.exists():
        return linux_default
    return None


def which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    extra = {
        "brew": [Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew")],
        "docker": [Path("/Applications/Docker.app/Contents/Resources/bin/docker"), Path("/opt/homebrew/bin/docker"), Path("/usr/local/bin/docker")],
        "colima": [Path("/opt/homebrew/bin/colima"), Path("/usr/local/bin/colima")],
        "scrcpy": [Path("/opt/homebrew/bin/scrcpy"), Path("/usr/local/bin/scrcpy")],
    }
    for c in extra.get(name, []):
        if c.exists() and os.access(c, os.X_OK):
            return str(c)
    sdk = android_sdk_dir()
    if sdk:
        candidates = {
            "adb": [sdk / "platform-tools" / "adb"],
            "aapt2": sorted((sdk / "build-tools").glob("*/aapt2"), reverse=True) if (sdk / "build-tools").exists() else [],
            "d8": sorted((sdk / "build-tools").glob("*/d8"), reverse=True) if (sdk / "build-tools").exists() else [],
            "zipalign": sorted((sdk / "build-tools").glob("*/zipalign"), reverse=True) if (sdk / "build-tools").exists() else [],
            "apksigner": sorted((sdk / "build-tools").glob("*/apksigner"), reverse=True) if (sdk / "build-tools").exists() else [],
        }
        if name == "aarch64-linux-android21-clang" and (sdk / "ndk").exists():
            ndks = sorted([p for p in (sdk / "ndk").iterdir() if p.is_dir()], reverse=True)
            arr = []
            for ndk in ndks:
                arr.extend(ndk.glob("toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang"))
            candidates[name] = arr
        for c in candidates.get(name, []):
            if c.exists() and os.access(c, os.X_OK):
                return str(c)
    return None


@contextmanager
def command_timeout(seconds: float) -> Iterator[None]:
    """Apply one absolute command deadline to the current request context."""

    if seconds <= 0:
        raise ValueError("command_timeout_invalid")
    deadline = time.monotonic() + seconds
    inherited = _COMMAND_DEADLINE.get()
    if inherited is not None:
        deadline = min(deadline, inherited)
    token = _COMMAND_DEADLINE.set(deadline)
    try:
        yield
    finally:
        _COMMAND_DEADLINE.reset(token)


def bounded_timeout(timeout: Optional[float] = None) -> Optional[float]:
    """Cap a subprocess/socket timeout by the active absolute deadline."""

    deadline = _COMMAND_DEADLINE.get()
    if deadline is None:
        return timeout
    remaining = max(0.001, deadline - time.monotonic())
    if timeout is None:
        return remaining
    return min(float(timeout), remaining)


def run(cmd: list[str], *, check: bool = False, capture: bool = True, timeout=None, stdin=None, env=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, timeout=bounded_timeout(timeout), stdin=stdin, env=env)


def host_info() -> dict[str, str]:
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def json_dumps(obj: Any) -> str:
    if is_dataclass(obj):
        obj = asdict(obj)
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True, default=lambda o: asdict(o) if is_dataclass(o) else getattr(o, "__dict__", str(o)))


def read_json_file(path: Union[str, Path]) -> Any:
    return json.loads(Path(path).read_text())


def write_json_file(path: Union[str, Path], data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return p
