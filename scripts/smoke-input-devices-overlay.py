#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
checks = {
    "overlay_function": "overlay_input_devices" in src,
    "proc_target": "/proc/bus/input/devices" in src,
    "touch_name": "sec_touchscreen" in src,
    "key_devices": "gpio-keys" in src and "qpnp_pon" in src,
    "optional_mount": "overlay_text_optional" in src,
    "profile_input_name": "input_name" in src and profile.get("input_name") == "sec_touchscreen",
    "apply_calls": "input_devices=ok" in src,
}
# Keep input-helper marker smoke here too because this overlay is meant to hide enumeration-level markers.
binp = ROOT / "native/xenoid-input/xenoid-input"
if binp.exists():
    import subprocess
    st = subprocess.run(["strings", str(binp)], text=True, capture_output=True)
    bad = [x for x in ["xenoid-uinput-touch", "minitouch", "frida", "dev.xenoid.input", "xenoid-profile"] if x in st.stdout]
    checks["input_binary_no_static_markers"] = not bad
else:
    bad = []
out = {"ok": all(checks.values()), "checks": checks, "badStaticMarkers": bad}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
