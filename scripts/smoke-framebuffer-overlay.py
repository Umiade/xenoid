#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid.artifacts import TARGETS
profile = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
checks = {
    "hwcomposer_artifact_owner": tuple(
        output.path for output in TARGETS["hwcomposer"].outputs
    ) == ("native/xenoid-hwcomposer/hwcomposer.raven.so",),
    "template_display": profile.get("display") == {
        "width": 1440,
        "height": 3120,
        "densityDpi": 560,
        "physicalPpi": 512,
        "defaultRefreshRateHz": 120,
        "peakRefreshRateHz": 120,
        "supportedRefreshRatesHz": [60, 120],
        "modes": [
            {"id": 1, "width": 1440, "height": 3120, "refreshRateHz": 60},
            {"id": 2, "width": 1440, "height": 3120, "refreshRateHz": 120},
        ],
    },
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
