#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
IMPORTER = ROOT / "scripts/import-pixel-template.py"


def import_profile(profile: dict[str, object]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="xenoid-cpu-profile-") as temporary:
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


cores = PROFILE["cpu"]["cores"]
cluster_views = [
    (core["part"], core["model"], core["minimumFrequencyKhz"], core["maximumFrequencyKhz"])
    for core in cores
]
bad_profile = copy.deepcopy(PROFILE)
bad_profile["cpu"]["cores"][5]["maximumFrequencyKhz"] += 1
canonical_import = import_profile(PROFILE)
rejected_import = import_profile(bad_profile)

checks = {
    "canonical_import": canonical_import.returncode == 0,
    "rejects_cluster_mismatch": rejected_import.returncode != 0
    and "cluster values are inconsistent" in (rejected_import.stdout + rejected_import.stderr),
    "eight_contiguous_cores": [core["processor"] for core in cores] == list(range(8)),
    "raven_cluster_shape": cluster_views[:4] == [("0xd05", "Cortex-A55", 300000, 1800000)] * 4
    and cluster_views[4:6] == [("0xd0b", "Cortex-A76", 400000, 2253000)] * 2
    and cluster_views[6:] == [("0xd44", "Cortex-X1", 500000, 2802000)] * 2,
}
out = {
    "ok": all(checks.values()),
    "checks": checks,
    "canonicalImport": canonical_import.stdout,
    "rejectedImport": rejected_import.stdout,
    "rejectedImportStderr": rejected_import.stderr,
}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
