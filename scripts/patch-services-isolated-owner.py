#!/usr/bin/env python3
"""Patch Android 13 PackageManager to resolve isolated UIDs to their owner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

EXPECTED_INPUT_SHA256 = "c90ba95645f1b4685d1c0740b03a8d2dd06d98604ab8962b061c7b35cc366498"

ORIGINAL = """    .line 2215
    :cond_1
    invoke-static {p1}, Landroid/os/UserHandle;->getAppId(I)I
"""

REPLACEMENT = """    .line 2215
    :cond_1
    invoke-static {p1}, Landroid/os/Process;->isIsolated(I)Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {p0, p1}, Lcom/android/server/pm/ComputerEngine;->getIsolatedOwner(I)I

    move-result p1

    :cond_2
    invoke-static {p1}, Landroid/os/UserHandle;->getAppId(I)I
"""


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} INPUT_SERVICES_JAR OUTPUT_SERVICES_JAR")

    source = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual_hash != EXPECTED_INPUT_SHA256:
        raise SystemExit(
            f"SHA256 mismatch for {source}: expected {EXPECTED_INPUT_SHA256}, got {actual_hash}"
        )

    apktool = os.environ.get("APKTOOL") or shutil.which("apktool")
    if not apktool:
        raise SystemExit("apktool is required to patch services.jar")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xenoid-services-") as temporary:
        decoded = Path(temporary) / "decoded"
        run([apktool, "d", "-f", "-o", str(decoded), str(source)])
        smali = decoded / "smali_classes2/com/android/server/pm/ComputerEngine.smali"
        text = smali.read_text()
        occurrences = text.count(ORIGINAL)
        if occurrences != 1:
            raise SystemExit(
                f"expected one isolated-UID patch point in {smali}, found {occurrences}"
            )
        smali.write_text(text.replace(ORIGINAL, REPLACEMENT, 1))
        run([apktool, "b", "-o", str(output), str(decoded)])

    with zipfile.ZipFile(output) as archive:
        if "classes2.dex" not in archive.namelist():
            raise SystemExit(f"patched services jar has no classes2.dex: {output}")
    print(f"patched isolated UID ownership in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
