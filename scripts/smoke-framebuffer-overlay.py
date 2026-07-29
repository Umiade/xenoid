#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
checks = {
    "overlay_function": "overlay_framebuffer" in src,
    "proc_fb": "/proc/fb" in src and "msmfb" in src,
    "fb0_virtual_size": "/sys/class/graphics/fb0/virtual_size" in src,
    "fb0_name": "/sys/class/graphics/fb0/name" in src,
    "fb0_bpp": "/sys/class/graphics/fb0/bits_per_pixel" in src,
    "fb0_modes": "/sys/class/graphics/fb0/modes" in src,
    "profile_width_height": "display_width" in src and "display_height" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "framebuffer=ok" in src,
    "daemon_display": "display.width" in daemon and "display_height" in daemon,
    "template_display": profile.get("display_width") == 1344 and profile.get("display_height") == 2992,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
