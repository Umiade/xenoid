#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = json.loads(
    (ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text()
)
STORAGE = PROFILE["storage"]
BUILD = ROOT / "scripts/build-native-overlay.sh"

checks: dict[str, bool] = {
    "profile_capacity_equation": (
        STORAGE["capacityBytes"]
        == STORAGE["sectorSizeBytes"] * STORAGE["sectorCount"]
    ),
    "profile_block_device": STORAGE["blockDevice"] == "sda",
    "profile_mount_source": (
        STORAGE["mountSource"]
        == "/dev/block/platform/14700000.ufs/by-name/userdata"
    ),
    "profile_partition_geometry": (
        STORAGE["capacityBytes"] // 1024 == 125_000_000
        and STORAGE["sectorCount"] == 250_000_000
    ),
    "profile_sparse_ufs": (
        STORAGE["technology"] == "UFS 3.1"
        and STORAGE["filesystem"] == "f2fs"
        and STORAGE["sparse"] is True
        and STORAGE["removable"] is False
    ),
}

build_result = subprocess.run(
    [str(BUILD), "arm64"], cwd=ROOT, text=True, capture_output=True
)
checks["overlay_android_build"] = build_result.returncode == 0

result = {
    "ok": all(checks.values()),
    "checks": checks,
    "buildStderr": build_result.stderr.strip(),
}
print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(0 if result["ok"] else 1)
