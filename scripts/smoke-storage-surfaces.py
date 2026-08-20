#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.artifacts import TARGETS

PROFILE = json.loads(
    (ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text()
)
STORAGE = PROFILE["storage"]
overlay = TARGETS["overlay"]
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
    "overlay_artifact_owner": (
        overlay.command == ("scripts/build-native-overlay.sh", "arm64")
        and tuple(output.path for output in overlay.outputs)
        == ("native/xenoid-hide/xenoid-overlay",)
        and "native/xenoid-hide/xenoid_overlay.c" in overlay.sources
        and "native/xenoid-hide/xenoid_power_supply.c" in overlay.sources
    ),
}
result = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
sys.exit(0 if result["ok"] else 1)
