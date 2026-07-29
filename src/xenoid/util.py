from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional, Union


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


def run(cmd: list[str], *, check: bool = False, capture: bool = True, timeout=None, stdin=None, env=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, timeout=timeout, stdin=stdin, env=env)


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
