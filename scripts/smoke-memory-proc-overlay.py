#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.backend import RuntimeManager
PROFILE = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
IMPORTER = ROOT / "scripts/import-pixel-template.py"


def import_profile(profile: dict[str, object]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="xenoid-memory-profile-") as temporary:
        root = pathlib.Path(temporary)
        source = root / "source.json"
        output = root / "output"
        source.write_text(json.dumps(profile))
        return subprocess.run(
            [sys.executable, str(IMPORTER), str(source), "--out-dir", str(output), "--overwrite"],
            text=True,
            capture_output=True,
            cwd=ROOT,
        )


memory = PROFILE["memory"]
total_kib = memory["totalKiB"]
total_pages = total_kib // 4
free_kib = total_kib // 2
available_kib = total_kib * 2 // 3
active_anon_kib = total_kib // 8
inactive_anon_kib = total_kib // 24
active_file_kib = total_kib // 12
inactive_file_kib = total_kib // 12
commit_limit_kib = total_kib // 2 + memory["swapBytes"] // 1024
committed_kib = total_kib * 5 // 12

buddy = [0] * 11
remaining_pages = free_kib // 4
target_small_pages = remaining_pages // 64
for order in range(10):
    buddy[order] = target_small_pages >> order
    remaining_pages -= buddy[order] << order
for order in range(10, -1, -1):
    count = remaining_pages >> order
    buddy[order] += count
    remaining_pages -= count << order

bad_profile = copy.deepcopy(PROFILE)
bad_profile["memory"]["totalBytes"] += 1
canonical_import = import_profile(PROFILE)
rejected_import = import_profile(bad_profile)
overlay = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
shim = (ROOT / "native/xenoid-shim/xenoid_shim.c").read_text()
kmod = (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text()
daemon = (
    ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java"
).read_text()
manager = object.__new__(RuntimeManager)
manager._engine_host_shell = lambda *_args, **_kwargs: subprocess.CompletedProcess(
    [],
    0,
    stdout="MemTotal:        8388608 kB\nMemAvailable:     262144 kB\n",
    stderr="",
)
pressure_status = manager.runtime_memory_status({"State": {"OOMKilled": False}})
oom_status = manager.runtime_memory_status({"State": {"OOMKilled": True}})
backend = (ROOT / "src/xenoid/backend.py").read_text()
checks = {
    "canonical_import": canonical_import.returncode == 0,
    "rejects_byte_kib_mismatch": rejected_import.returncode != 0
    and "totalBytes must equal totalKiB" in (rejected_import.stdout + rejected_import.stderr),
    "twelve_gibibytes": memory == {
        "totalBytes": 12 * 1024**3,
        "totalKiB": 12 * 1024**2,
        "swapBytes": 0,
    },
    "page_conversion": total_pages == 3_145_728 and free_kib // 4 == 1_572_864,
    "active_equation": active_anon_kib + active_file_kib == total_kib * 5 // 24
    and inactive_anon_kib + inactive_file_kib == total_kib // 8,
    "availability_and_commit": available_kib == 8 * 1024**2
    and committed_kib <= commit_limit_kib
    and commit_limit_kib == 6 * 1024**2,
    "buddy_equation": remaining_pages == 0
    and sum(count << order for order, count in enumerate(buddy)) == free_kib // 4,
    "daemon_materializes_profile": "memory_profile_inconsistent" in daemon
    and "memory_totalBytes" in daemon,
    "profile_driven_proc_views": "load_memory_profile" in overlay
    and "memory.total_kib" in overlay,
    "mount_view_uses_total": "size=%lluk" in overlay,
    "libc_views_use_profile": "profile_total_memory_bytes" in shim
    and "_SC_AVPHYS_PAGES" in shim,
    "raw_sysinfo_view": "sysinfo_kprobes" in kmod
    and "XENOID_MEMORY_TOTAL_BYTES" in kmod,
    "host_budget_stays_eight_gib": '\"--memory\", \"8\"' in backend,
    "host_pressure_warns_without_failing": pressure_status.get("ok") is True
    and pressure_status.get("pressure") is True
    and "warning" in pressure_status,
    "oom_is_diagnostic_failure": oom_status.get("ok") is False
    and oom_status.get("error") == "runtime_oom_killed",
}
out = {
    "ok": all(checks.values()),
    "checks": checks,
    "buddyOrders": buddy,
    "canonicalImport": canonical_import.stdout,
    "rejectedImport": rejected_import.stderr,
}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
