from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union


DEFAULT_IMAGE = "redroid/redroid:13.0.0-latest"
# Apple Silicon (and other arm64 hosts like ARM ECS/Graviton) lack AArch32, so the
# stock redroid image fails at boringssl_self_test32 (Exec format error). The
# 64only variant is the only viable base on arm64 hosts.
DEFAULT_IMAGE_64ONLY = "redroid/redroid:13.0.0_64only-latest"
DEFAULT_NAME = "xenoid-android"
DEFAULT_ADB_PORT = 5555
DEFAULT_ANDROID_ADB_PORT = 62111
DEFAULT_DAEMON_PORT = 18765
DEFAULT_RUNTIME_TAG = "xenoid/redroid:local"


def default_image_for_host(machine: str | None = None) -> str:
    """Pick the stock image appropriate for the host CPU.

    arm64/aarch64 hosts (Apple Silicon, ARM ECS) cannot execute 32-bit ARM, so
    they must use the 64only redroid variant; x86_64 keeps the standard image.
    """
    if machine is None:
        import platform
        machine = platform.machine()
    if machine in {"arm64", "aarch64"}:
        return DEFAULT_IMAGE_64ONLY
    return DEFAULT_IMAGE


@dataclass
class XenoidConfig:
    backend: str = "colima-docker"
    image: str = DEFAULT_IMAGE
    container_name: str = DEFAULT_NAME
    adb_port: int = DEFAULT_ADB_PORT
    android_adb_port: int = DEFAULT_ANDROID_ADB_PORT
    daemon_port: int = DEFAULT_DAEMON_PORT
    data_dir: str = "~/.xenoid"
    android_data_volume: str = "xenoid-data"
    extra_docker_args: list[str] = field(default_factory=list)
    runtime_image_tag: str = DEFAULT_RUNTIME_TAG
    auto_build_runtime_image: bool = False
    docker_context: str = ""
    network_enabled: bool = False
    network_name: str = "xenoid-net"
    network_subnet: str = "172.31.0.0/24"
    network_gateway: str = "172.31.0.1"
    network_ip: str = "172.31.0.10"
    network_mac: str = "02:11:22:33:44:55"

    @property
    def expanded_data_dir(self) -> Path:
        return Path(os.path.expanduser(self.data_dir)).resolve()


def default_config_path() -> Path:
    return Path.cwd() / ".xenoid" / "config.json"


def load_config(path: Optional[Union[str, Path]] = None) -> XenoidConfig:
    cfg_path = Path(path) if path else default_config_path()
    if not cfg_path.exists():
        return XenoidConfig()
    data = json.loads(cfg_path.read_text())
    return XenoidConfig(**data)


def save_config(cfg: XenoidConfig, path: Optional[Union[str, Path]] = None) -> Path:
    cfg_path = Path(path) if path else default_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False) + "\n")
    return cfg_path


def merge_config(overrides: dict[str, Any], path: Optional[Union[str, Path]] = None) -> XenoidConfig:
    cfg = load_config(path)
    data = asdict(cfg)
    data.update({k: v for k, v in overrides.items() if v is not None})
    return XenoidConfig(**data)
