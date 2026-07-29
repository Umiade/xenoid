#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
checks = {
    "overlay_function": "overlay_usb_identity" in src,
    "gadget_serial": "/config/usb_gadget/g1/strings/0x409/serialnumber" in src,
    "gadget_manufacturer": "/config/usb_gadget/g1/strings/0x409/manufacturer" in src,
    "gadget_product": "/config/usb_gadget/g1/strings/0x409/product" in src,
    "id_vendor_product": "idVendor" in src and "idProduct" in src,
    "android_usb": "/sys/class/android_usb/android0/iSerial" in src,
    "profile_serial": "PROFILE_DIR \"/serial\"" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "usb_identity=ok" in src,
    "daemon_serial": "pixelSerial" in daemon and "usb.manufacturer" in daemon,
    "template_usb": (profile.get("usb") or {}).get("manufacturer") == "Google" and (profile.get("ids") or {}).get("serial") == "REGENERATE",
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
