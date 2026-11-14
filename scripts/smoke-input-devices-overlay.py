#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
profile = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
checks = {
    "profile_input_name": profile.get("input", {}).get("name") == "sec_touchscreen",
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
