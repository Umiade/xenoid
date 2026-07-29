#!/usr/bin/env python3
"""Static gate for production app- and system-layer hook surfaces."""
from __future__ import annotations
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

frida_js = (ROOT / "frida/scripts/xenoid-default.js").read_text() if (ROOT / "frida/scripts/xenoid-default.js").exists() else ""
ebpf_bpf = (ROOT / "native/xenoid-ebpf/xenoid_pathhide.bpf.c").read_text() if (ROOT / "native/xenoid-ebpf/xenoid_pathhide.bpf.c").exists() else ""
ebpf_loader = (ROOT / "native/xenoid-ebpf/loader.c").read_text() if (ROOT / "native/xenoid-ebpf/loader.c").exists() else ""
zygote = (ROOT / "native/xenoid-zygote/xenoid_zygote.c").read_text() if (ROOT / "native/xenoid-zygote/xenoid_zygote.c").exists() else ""
cli = (ROOT / "src/xenoid/cli.py").read_text()
backend = (ROOT / "src/xenoid/backend.py").read_text()

checks = {
    # Frida app-layer surface (deployed).
    "frida_script_exists": len(frida_js) > 0,
    "frida_hooks_file_exists": "File.exists" in frida_js,
    "frida_hooks_runtime_exec": "Runtime" in frida_js and "exec" in frida_js,
    "frida_hooks_system_properties": "SystemProperties" in frida_js,
    # Sensors are supplied by the AIDL HAL/FMQ service.
    "frida_no_fake_sensor_injection": "Sensor.$new" not in frida_js and "sensorEvent" not in frida_js.replace(" ", ""),
    # eBPF system-layer surface (source + loader).
    "ebpf_bpf_source": "file_open" in ebpf_bpf,
    "ebpf_loader": len(ebpf_loader) > 0,
    "ebpf_scripts": (ROOT / "scripts/build-ebpf.sh").exists() and (ROOT / "scripts/load-ebpf.sh").exists(),
    # Deployed zygote preload Build spoof.
    "zygote_build_spoof": "raven" in zygote or "TP1A.221005.002" in zygote or "ro.build" in zygote,
    # Production wiring: frida/ebpf subcommands present.
    "cli_has_frida": '"frida"' in cli or "add_parser(\"frida\"" in cli or "add_parser('frida'" in cli,
    "cli_has_ebpf": '"ebpf"' in cli or "add_parser(\"ebpf\"" in cli or "add_parser('ebpf'" in cli,
    # Unsupported control-plane routes must stay absent.
    "cli_no_dead_zygisk_magisk": all(
        token not in cli
        for token in ("cmd_build_zygisk", "cmd_package_magisk", "cmd_hook_backend", "cmd_magisk_status", "cmd_magisk_install_module")
    ),
    "backend_no_dead_magisk_hooks": all(
        token not in backend
        for token in ("hook_backend_status", "hook_backend_set", "magisk_status", "magisk_install_module")
    ),
}
missing = [k for k, v in checks.items() if not v]
print({"ok": not missing, "missing": missing, "checks": checks})
sys.exit(0 if not missing else 1)
