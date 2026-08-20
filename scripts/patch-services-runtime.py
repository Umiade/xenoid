#!/usr/bin/env python3
"""Patch Android 13 PackageManager for Xenoid runtime ownership and data semantics."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import zipfile

from xenoid_archive import canonicalize_zip, publish_file_atomic, run_apktool

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

APP_DATA_ORIGINAL = """    .line 396
    iget v8, v6, Landroid/os/CreateAppDataResult;->exceptionCode:I

    if-nez v8, :cond_1

    .line 397
    iget-wide v8, v6, Landroid/os/CreateAppDataResult;->ceDataInode:J

    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    invoke-virtual {v7, v6}, Ljava/util/concurrent/CompletableFuture;->complete(Ljava/lang/Object;)Z

    goto :goto_3

    .line 399
    :cond_1
    new-instance v8, Lcom/android/server/pm/Installer$InstallerException;

    iget-object v6, v6, Landroid/os/CreateAppDataResult;->exceptionMessage:Ljava/lang/String;

    invoke-direct {v8, v6}, Lcom/android/server/pm/Installer$InstallerException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, v8}, Ljava/util/concurrent/CompletableFuture;->completeExceptionally(Ljava/lang/Throwable;)Z
"""

APP_DATA_REPLACEMENT = """    .line 396
    iget v8, v6, Landroid/os/CreateAppDataResult;->exceptionCode:I

    if-nez v8, :cond_restorecon_error

    .line 397
    iget-wide v8, v6, Landroid/os/CreateAppDataResult;->ceDataInode:J

    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    invoke-virtual {v7, v6}, Ljava/util/concurrent/CompletableFuture;->complete(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_restorecon_error
    iget-object v8, v6, Landroid/os/CreateAppDataResult;->exceptionMessage:Ljava/lang/String;

    if-eqz v8, :cond_1

    const-string v9, "Failed to restorecon /data/"

    invoke-virtual {v8, v9}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v8

    if-eqz v8, :cond_1


    const-wide/16 v8, -0x1

    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    invoke-virtual {v7, v6}, Ljava/util/concurrent/CompletableFuture;->complete(Ljava/lang/Object;)Z

    goto :goto_3

    .line 399
    :cond_1
    new-instance v8, Lcom/android/server/pm/Installer$InstallerException;

    iget-object v6, v6, Landroid/os/CreateAppDataResult;->exceptionMessage:Ljava/lang/String;

    invoke-direct {v8, v6}, Lcom/android/server/pm/Installer$InstallerException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, v8}, Ljava/util/concurrent/CompletableFuture;->completeExceptionally(Ljava/lang/Throwable;)Z
"""




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

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xenoid-services-") as temporary:
        work = Path(temporary)
        decoded = work / "decoded"
        staged = work / "services.apktool.jar"
        canonical = work / "services.canonical.jar"
        run_apktool(["d", "-f", "-o", str(decoded), str(source)])
        ownership_smali = decoded / "smali_classes2/com/android/server/pm/ComputerEngine.smali"
        ownership_text = ownership_smali.read_text()
        ownership_occurrences = ownership_text.count(ORIGINAL)
        if ownership_occurrences != 1:
            raise SystemExit(
                f"expected one isolated-UID patch point in {ownership_smali}, found {ownership_occurrences}"
            )
        ownership_smali.write_text(ownership_text.replace(ORIGINAL, REPLACEMENT, 1))

        data_smali = decoded / "smali_classes2/com/android/server/pm/Installer$Batch.smali"
        data_text = data_smali.read_text()
        data_occurrences = data_text.count(APP_DATA_ORIGINAL)
        if data_occurrences != 1:
            raise SystemExit(
                f"expected one app-data recovery patch point in {data_smali}, found {data_occurrences}"
            )
        data_smali.write_text(
            data_text.replace(APP_DATA_ORIGINAL, APP_DATA_REPLACEMENT, 1)
        )
        run_apktool(["b", "-f", "-o", str(staged), str(decoded)])
        canonicalize_zip(staged, canonical)
        with zipfile.ZipFile(canonical) as archive:
            if archive.namelist().count("classes2.dex") != 1:
                raise SystemExit("patched_services_dex_layout_mismatch")
            dex = archive.read("classes2.dex")
        if (
            b"getIsolatedOwner" not in dex
            or b"Failed to restorecon /data/" not in dex
        ):
            raise SystemExit("patched_services_verification_failed")
        publish_file_atomic(canonical, output)
    print(f"patched runtime PackageManager contracts in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
