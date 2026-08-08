#!/usr/bin/env python3
"""Patch the pinned Android 13 telephony-common legacy HIDL LTE conversion.

Legacy HIDL 1.0/1.1 cell identities carry EARFCN but omit bands and bandwidth,
and their card status has no physical slot mapping. Android 13 also allocates a
SET_DATA_PROFILE request before filtering non-persistent legacy profiles, then
leaks that request when the filtered list is empty. This pinned source-layer
bridge derives the standardized LTE band, supplies the canonical 10 MHz profile
bandwidth, initializes the one legacy slot mapping, and forwards empty legacy
profile lists so the modem can erase old profiles and complete the request.
Modern AIDL/V1_5 conversion is untouched.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_JAR_SHA256 = "3751dc61bde64590638904407f03a95c9ebe7078ea964a0133d47137ac794a8e"
APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar"
APKTOOL_SHA256 = "c0350abbab5314248dfe2ee0c907def4edd14f6faef1f5d372d3d4abd28f0431"
APKTOOL_MAX_BYTES = 32 * 1024 * 1024

OLD_V10 = """    new-array v9, v3, [I

    const v10, 0x7fffffff
"""
OLD_V12 = """    new-array v9, v3, [I

    iget v10, v0, Landroid/hardware/radio/V1_2/CellIdentityLte;->bandwidth:I
"""
OLD_LEGACY_CARD_MAPPING = """    :cond_4
    if-eqz p0, :cond_7
"""
OLD_EMPTY_LEGACY_PROFILE_GUARD = """    :cond_8
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_9

    .line 242
"""
EMPTY_LEGACY_PROFILE_CALL = """    :cond_8
    .line 242
"""
LEGACY_CARD_MAPPING = """    :cond_4
    if-nez p0, :xenoid_v15_card_status

    new-instance v1, Lcom/android/internal/telephony/uicc/IccSlotPortMapping;

    invoke-direct {v1}, Lcom/android/internal/telephony/uicc/IccSlotPortMapping;-><init>()V

    const/4 v5, -0x1

    iput v5, v1, Lcom/android/internal/telephony/uicc/IccSlotPortMapping;->mPhysicalSlotIndex:I

    iput v3, v1, Lcom/android/internal/telephony/uicc/IccSlotPortMapping;->mPortIndex:I

    iput-object v1, v0, Lcom/android/internal/telephony/uicc/IccCardStatus;->mSlotPortMapping:Lcom/android/internal/telephony/uicc/IccSlotPortMapping;

    goto :cond_7

    :xenoid_v15_card_status
"""
BRIDGE = """    const/4 v3, 0x1

    new-array v9, v3, [I

    invoke-static {v8}, Landroid/telephony/AccessNetworkUtils;->getOperatingBandForEarfcn(I)I

    move-result v3

    const/4 v4, 0x0

    aput v3, v9, v4

    const-string v4, "persist.xenoid.radio.lte_band"

    const/4 v10, -0x1

    invoke-static {v4, v10}, Landroid/os/SystemProperties;->getInt(Ljava/lang/String;I)I

    move-result v4

    if-ne v3, v4, :xenoid_lte_unavailable

    const-string v4, "persist.xenoid.radio.lte_bandwidth_khz"

    const v10, 0x7fffffff

    invoke-static {v4, v10}, Landroid/os/SystemProperties;->getInt(Ljava/lang/String;I)I

    move-result v10

    const/16 v4, 0x578

    if-eq v10, v4, :xenoid_lte_ready

    const/16 v4, 0xbb8

    if-eq v10, v4, :xenoid_lte_ready

    const/16 v4, 0x1388

    if-eq v10, v4, :xenoid_lte_ready

    const/16 v4, 0x2710

    if-eq v10, v4, :xenoid_lte_ready

    const/16 v4, 0x3a98

    if-eq v10, v4, :xenoid_lte_ready

    const/16 v4, 0x4e20

    if-eq v10, v4, :xenoid_lte_ready

    :xenoid_lte_unavailable
    const/4 v3, 0x0

    new-array v9, v3, [I

    const v10, 0x7fffffff

    :xenoid_lte_ready
"""
BRIDGE_V10 = BRIDGE.replace("xenoid_lte_unavailable", "xenoid_lte_v10_unavailable").replace(
    "xenoid_lte_ready", "xenoid_lte_v10_ready"
)
BRIDGE_V12 = BRIDGE.replace("xenoid_lte_unavailable", "xenoid_lte_v12_unavailable").replace(
    "xenoid_lte_ready", "xenoid_lte_v12_ready"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apktool() -> Path:
    cache = ROOT / ".xenoid" / "cache" / "tooling" / "apktool_2.10.0.jar"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.is_file() and sha256(cache) == APKTOOL_SHA256:
        return cache
    temporary = cache.with_suffix(".download")
    temporary.unlink(missing_ok=True)
    with urllib.request.urlopen(APKTOOL_URL, timeout=120) as response, temporary.open("xb") as output:
        length = 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            length += len(chunk)
            if length > APKTOOL_MAX_BYTES:
                raise RuntimeError("apktool_download_too_large")
            output.write(chunk)
    if sha256(temporary) != APKTOOL_SHA256:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("apktool_sha256_mismatch")
    temporary.replace(cache)
    return cache


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT_JAR OUTPUT_JAR", file=sys.stderr)
        return 2
    source = Path(sys.argv[1]).resolve()
    destination = Path(sys.argv[2]).resolve()
    if not source.is_file() or sha256(source) != EXPECTED_JAR_SHA256:
        raise RuntimeError("telephony_common_sha256_mismatch")
    with zipfile.ZipFile(source) as archive:
        dex_names = [name for name in archive.namelist() if name.endswith(".dex")]
    if dex_names != ["classes.dex"]:
        raise RuntimeError("telephony_common_dex_layout_mismatch")
    tool = apktool()
    with tempfile.TemporaryDirectory(prefix="xenoid-telephony-") as directory:
        work = Path(directory)
        decoded = work / "decoded"
        staged = work / "telephony-common.jar"
        subprocess.run(
            ["java", "-jar", str(tool), "d", "-f", "-o", str(decoded), str(source)],
            check=True,
        )
        matches = list(decoded.glob("smali*/com/android/internal/telephony/RILUtils.smali"))
        if len(matches) != 1:
            raise RuntimeError("rilutils_smali_layout_mismatch")
        smali = matches[0]
        text = smali.read_text()
        if (text.count(OLD_V10) != 1 or text.count(OLD_V12) != 1
                or text.count(OLD_LEGACY_CARD_MAPPING) != 1):
            raise RuntimeError("legacy_radio_conversion_mismatch")
        text = (text.replace(OLD_V10, BRIDGE_V10, 1)
                .replace(OLD_V12, BRIDGE_V12, 1)
                .replace(OLD_LEGACY_CARD_MAPPING, LEGACY_CARD_MAPPING, 1))
        smali.write_text(text)

        profile_matches = list(decoded.glob(
            "smali*/com/android/internal/telephony/RadioDataProxy.smali"
        ))
        if len(profile_matches) != 1:
            raise RuntimeError("radio_data_proxy_smali_layout_mismatch")
        profile_smali = profile_matches[0]
        profile_text = profile_smali.read_text()
        if profile_text.count(OLD_EMPTY_LEGACY_PROFILE_GUARD) != 1:
            raise RuntimeError("legacy_empty_profile_guard_mismatch")
        profile_smali.write_text(profile_text.replace(
            OLD_EMPTY_LEGACY_PROFILE_GUARD, EMPTY_LEGACY_PROFILE_CALL, 1
        ))
        subprocess.run(
            ["java", "-jar", str(tool), "b", "-f", "-o", str(staged), str(decoded)],
            check=True,
        )
        with zipfile.ZipFile(staged) as archive:
            dex = archive.read("classes.dex")
        if (dex.count(b"getOperatingBandForEarfcn") != 1
                or b"AccessNetworkUtils" not in dex
                or b"persist.xenoid.radio.lte_band" not in dex
                or b"persist.xenoid.radio.lte_bandwidth_khz" not in dex):
            raise RuntimeError("patched_telephony_verification_failed")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged, destination)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
