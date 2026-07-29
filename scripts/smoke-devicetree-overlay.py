#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_devicetree_identity" in src,
    "proc_dt": "/proc/device-tree/model" in src and "/proc/device-tree/compatible" in src,
    "fw_dt": "/sys/firmware/devicetree/base/model" in src and "/sys/firmware/devicetree/base/compatible" in src,
    "pixel_model": "Google Pixel 6 Pro" in src,
    "tensor_compatible": "google,raven" in src and "google,gs101" in src,
    "serial": "serial-number" in src and "PROFILE_DIR \"/serial\"" in src,
    "bootargs": "androidboot.hardware=gs101" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "devicetree=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
