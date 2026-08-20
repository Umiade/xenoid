#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid.artifacts import TARGETS
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
gralloc = (ROOT / "native/xenoid-gralloc/framebuffer.cpp").read_text()
hwcomposer = (ROOT / "native/xenoid-hwcomposer/hwcomposer_wrapper.c").read_text()
backend = (ROOT / "src/xenoid/backend.py").read_text()
runtime_context = (ROOT / "scripts/make-runtime-context.sh").read_text()
profile = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
checks = {
    "overlay_function": "overlay_framebuffer" in src,
    "proc_fb": "/proc/fb" in src and "msmfb" in src,
    "fb0_virtual_size": "/sys/class/graphics/fb0/virtual_size" in src,
    "fb0_name": "/sys/class/graphics/fb0/name" in src,
    "fb0_bpp": "/sys/class/graphics/fb0/bits_per_pixel" in src,
    "fb0_modes": "/sys/class/graphics/fb0/modes" in src
        and "p-60" in src and "p-120" in src,
    "fb0_refresh_rate": "/sys/class/graphics/fb0/refresh_rate" in src,
    "profile_width_height": "display_width" in src and "display_height" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "framebuffer=ok" in src,
    "daemon_atomic_metrics": "applyDisplayMetrics(" in daemon
        and "wm size " in daemon and "wm density " in daemon,
    "gralloc_profile": "display_defaultRefreshRateHz" in gralloc
        and "display_physicalPpi" in gralloc,
    "hwcomposer_dynamic_modes": "HWC_DEVICE_API_VERSION_1_4" in hwcomposer
        and "RAVEN_PERIOD_60HZ_NS" in hwcomposer
        and "RAVEN_PERIOD_120HZ_NS" in hwcomposer
        and "raven_get_active_config" in hwcomposer
        and "raven_set_active_config" in hwcomposer
        and "base_vsync" in hwcomposer,
    "hwcomposer_artifact_owner": tuple(
        output.path for output in TARGETS["hwcomposer"].outputs
    ) == ("native/xenoid-hwcomposer/hwcomposer.raven.so",),
    "hwcomposer_runtime": "androidboot.redroid_fps=120" in backend
        and "payload/hwcomposer.raven.so /vendor/lib64/hw/hwcomposer.raven.so"
            in runtime_context,
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
