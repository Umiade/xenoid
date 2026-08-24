#!/usr/bin/env python3
"""Patch Android 13 PackageManager for Xenoid runtime ownership and data semantics.

With ``--google-provider microg`` this additionally ports the restricted
signature-spoofing behavior of LineageOS commits
``6d2955f0bd55e9938d5d49415182c27b50900b95`` and
``53e2f4b85ce836360dd58bdb2f0d7f42dc796443`` into the pinned redroid
``services.jar``. The port deliberately narrows the upstream predicate from
two packages to exactly ``com.google.android.gms``, requires the installed
package signer to equal the pinned official microG certificate and the
manifest ``fake-signature`` metadata to equal the pinned Google certificate,
and replaces both ``PackageInfo.signatures`` and ``PackageInfo.signingInfo``
plus ``forceQueryable`` handling. Xenoid intentionally ships a
``user``/``ro.debuggable=0`` Raven identity, so the upstream debug-build gate
is omitted; the immutable provider image and the exact-signer predicate are
the enforcement boundary. No general ``FAKE_PACKAGE_SIGNATURE`` permission is
defined or granted.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
import tempfile
import zipfile

from xenoid_archive import canonicalize_zip, publish_file_atomic, run_apktool

EXPECTED_INPUT_SHA256 = "c90ba95645f1b4685d1c0740b03a8d2dd06d98604ab8962b061c7b35cc366498"

# Pinned certificate identities from the v2 Google services release metadata.
# ``MICROG_REAL_HEX`` is the official microG release certificate (the on-disk
# signer); ``GOOGLE_FAKE_HEX`` is the Google Android certificate that official
# microG GmsCore requests through its ``fake-signature`` metadata.
MICROG_REAL_HEX = "308202ed308201d5a003020102020426ffa009300d06092a864886f70d01010b05003027310b300906035504061302444531183016060355040a130f4e4f47415050532050726f6a656374301e170d3132313030363132303533325a170d3337303933303132303533325a3027310b300906035504061302444531183016060355040a130f4e4f47415050532050726f6a65637430820122300d06092a864886f70d01010105000382010f003082010a02820101009a8d2a5336b0eaaad89ce447828c7753b157459b79e3215dc962ca48f58c2cd7650df67d2dd7bda0880c682791f32b35c504e43e77b43c3e4e541f86e35a8293a54fb46e6b16af54d3a4eda458f1a7c8bc1b7479861ca7043337180e40079d9cdccb7e051ada9b6c88c9ec635541e2ebf0842521c3024c826f6fd6db6fd117c74e859d5af4db04448965ab5469b71ce719939a06ef30580f50febf96c474a7d265bb63f86a822ff7b643de6b76e966a18553c2858416cf3309dd24278374bdd82b4404ef6f7f122cec93859351fc6e5ea947e3ceb9d67374fe970e593e5cd05c905e1d24f5a5484f4aadef766e498adf64f7cf04bddd602ae8137b6eea40722d0203010001a321301f301d0603551d0e04160414110b7aa9ebc840b20399f69a431f4dba6ac42a64300d06092a864886f70d01010b0500038201010007c32ad893349cf86952fb5a49cfdc9b13f5e3c800aece77b2e7e0e9c83e34052f140f357ec7e6f4b432dc1ed542218a14835acd2df2deea7efd3fd5e8f1c34e1fb39ec6a427c6e6f4178b609b369040ac1f8844b789f3694dc640de06e44b247afed11637173f36f5886170fafd74954049858c6096308fc93c1bc4dd5685fa7a1f982a422f2a3b36baa8c9500474cf2af91c39cbec1bc898d10194d368aa5e91f1137ec115087c31962d8f76cd120d28c249cf76f4c70f5baa08c70a7234ce4123be080cee789477401965cfe537b924ef36747e8caca62dfefdd1a6288dcb1c4fd2aaa6131a7ad254e9742022cfd597d2ca5c660ce9e41ff537e5a4041e37"
GOOGLE_FAKE_HEX = "308204433082032ba003020102020900c2e08746644a308d300d06092a864886f70d01010405003074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f6964301e170d3038303832313233313333345a170d3336303130373233313333345a3074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f696430820120300d06092a864886f70d01010105000382010d00308201080282010100ab562e00d83ba208ae0a966f124e29da11f2ab56d08f58e2cca91303e9b754d372f640a71b1dcb130967624e4656a7776a92193db2e5bfb724a91e77188b0e6a47a43b33d9609b77183145ccdf7b2e586674c9e1565b1f4c6a5955bff251a63dabf9c55c27222252e875e4f8154a645f897168c0b1bfc612eabf785769bb34aa7984dc7e2ea2764cae8307d8c17154d7ee5f64a51a44a602c249054157dc02cd5f5c0e55fbef8519fbe327f0b1511692c5a06f19d18385f5c4dbc2d6b93f68cc2979c70e18ab93866b3bd5db8999552a0e3b4c99df58fb918bedc182ba35e003c1b4b10dd244a8ee24fffd333872ab5221985edab0fc0d0b145b6aa192858e79020103a381d93081d6301d0603551d0e04160414c77d8cc2211756259a7fd382df6be398e4d786a53081a60603551d2304819e30819b8014c77d8cc2211756259a7fd382df6be398e4d786a5a178a4763074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f6964820900c2e08746644a308d300c0603551d13040530030101ff300d06092a864886f70d010104050003820101006dd252ceef85302c360aaace939bcff2cca904bb5d7a1661f8ae46b2994204d0ff4a68c7ed1a531ec4595a623ce60763b167297a7ae35712c407f208f0cb109429124d7b106219c084ca3eb3f9ad5fb871ef92269a8be28bf16d44c8d9a08e6cb2f005bb3fe2cb96447e868e731076ad45b33f6009ea19c161e62641aa99271dfd5228c5c587875ddb7f452758d661f6cc0cccb7352e424cc4365c523532f7325137593c4ae341f4db41edda0d0b1071a7c440f0fe9ea01cb627ca674369d084bd2fd911ff06cdbf2cfa10dc0f893ae35762919048c7efc64c7144178342f70581c9de573af55b390dd7fdb9418631895d5f759f30112687ff621410c069308a"

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

GENERATE_PACKAGE_INFO_ANCHOR = """    iput-object v0, v2, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    iput-object v0, v1, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    return-object v1
"""

GENERATE_PACKAGE_INFO_PATCHED = """    iput-object v0, v2, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    iput-object v0, v1, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    invoke-static {v14}, Lcom/android/server/pm/ComputerEngine;->xenoidFakeSignature(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Landroid/content/pm/Signature;

    move-result-object v0

    if-eqz v0, :cond_xenoid_spoof_done

    const/4 v2, 0x1

    new-array v2, v2, [Landroid/content/pm/Signature;

    const/4 v3, 0x0

    aput-object v0, v2, v3

    iput-object v2, v1, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    :try_start_xenoid
    new-instance v3, Landroid/content/pm/SigningDetails;

    const/4 v4, 0x3

    invoke-static {v2}, Landroid/content/pm/SigningDetails;->toSigningKeys([Landroid/content/pm/Signature;)Landroid/util/ArraySet;

    move-result-object v5

    const/4 v6, 0x0

    invoke-direct {v3, v2, v4, v5, v6}, Landroid/content/pm/SigningDetails;-><init>([Landroid/content/pm/Signature;ILandroid/util/ArraySet;[Landroid/content/pm/Signature;)V

    new-instance v2, Landroid/content/pm/SigningInfo;

    invoke-direct {v2, v3}, Landroid/content/pm/SigningInfo;-><init>(Landroid/content/pm/SigningDetails;)V

    iput-object v2, v1, Landroid/content/pm/PackageInfo;->signingInfo:Landroid/content/pm/SigningInfo;
    :try_end_xenoid
    .catch Ljava/security/cert/CertificateException; {:try_start_xenoid .. :try_end_xenoid} :cond_xenoid_spoof_done

    :cond_xenoid_spoof_done
    return-object v1
"""

APPS_FILTER_ANCHOR = """    if-nez v3, :cond_5

    .line 525
    invoke-interface {p1}, Lcom/android/server/pm/pkg/PackageState;->isSystem()Z
"""

APPS_FILTER_PATCHED = """    if-nez v3, :cond_5

    invoke-static {v0}, Lcom/android/server/pm/ComputerEngine;->xenoidIsMicrogGmsForceQueryable(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Z

    move-result v3

    if-nez v3, :cond_5

    .line 525
    invoke-interface {p1}, Lcom/android/server/pm/pkg/PackageState;->isSystem()Z
"""

MICROG_HELPER_METHODS = """
.method public static xenoidIsMicrogGms(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Z
    .locals 4

    invoke-interface {p0}, Lcom/android/server/pm/pkg/parsing/PkgWithoutStatePackageInfo;->getPackageName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "com.google.android.gms"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/4 v2, 0x0

    if-nez v0, :cond_xenoid_pkg_ok

    return v2

    :cond_xenoid_pkg_ok
    invoke-interface {p0}, Lcom/android/server/pm/pkg/parsing/ParsingPackageRead;->getSigningDetails()Landroid/content/pm/SigningDetails;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/pm/SigningDetails;->getSignatures()[Landroid/content/pm/Signature;

    move-result-object v0

    if-nez v0, :cond_xenoid_signed

    return v2

    :cond_xenoid_signed
    new-instance v1, Landroid/content/pm/Signature;

    const-string v3, "308202ed308201d5a003020102020426ffa009300d06092a864886f70d01010b05003027310b300906035504061302444531183016060355040a130f4e4f47415050532050726f6a656374301e170d3132313030363132303533325a170d3337303933303132303533325a3027310b300906035504061302444531183016060355040a130f4e4f47415050532050726f6a65637430820122300d06092a864886f70d01010105000382010f003082010a02820101009a8d2a5336b0eaaad89ce447828c7753b157459b79e3215dc962ca48f58c2cd7650df67d2dd7bda0880c682791f32b35c504e43e77b43c3e4e541f86e35a8293a54fb46e6b16af54d3a4eda458f1a7c8bc1b7479861ca7043337180e40079d9cdccb7e051ada9b6c88c9ec635541e2ebf0842521c3024c826f6fd6db6fd117c74e859d5af4db04448965ab5469b71ce719939a06ef30580f50febf96c474a7d265bb63f86a822ff7b643de6b76e966a18553c2858416cf3309dd24278374bdd82b4404ef6f7f122cec93859351fc6e5ea947e3ceb9d67374fe970e593e5cd05c905e1d24f5a5484f4aadef766e498adf64f7cf04bddd602ae8137b6eea40722d0203010001a321301f301d0603551d0e04160414110b7aa9ebc840b20399f69a431f4dba6ac42a64300d06092a864886f70d01010b0500038201010007c32ad893349cf86952fb5a49cfdc9b13f5e3c800aece77b2e7e0e9c83e34052f140f357ec7e6f4b432dc1ed542218a14835acd2df2deea7efd3fd5e8f1c34e1fb39ec6a427c6e6f4178b609b369040ac1f8844b789f3694dc640de06e44b247afed11637173f36f5886170fafd74954049858c6096308fc93c1bc4dd5685fa7a1f982a422f2a3b36baa8c9500474cf2af91c39cbec1bc898d10194d368aa5e91f1137ec115087c31962d8f76cd120d28c249cf76f4c70f5baa08c70a7234ce4123be080cee789477401965cfe537b924ef36747e8caca62dfefdd1a6288dcb1c4fd2aaa6131a7ad254e9742022cfd597d2ca5c660ce9e41ff537e5a4041e37"

    invoke-direct {v1, v3}, Landroid/content/pm/Signature;-><init>(Ljava/lang/String;)V

    const/4 v3, 0x1

    new-array v3, v3, [Landroid/content/pm/Signature;

    aput-object v1, v3, v2

    invoke-static {v0, v3}, Landroid/content/pm/Signature;->areExactMatch([Landroid/content/pm/Signature;[Landroid/content/pm/Signature;)Z

    move-result v0

    return v0
.end method

.method public static xenoidIsMicrogGmsForceQueryable(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Z
    .locals 1

    invoke-interface {p0}, Lcom/android/server/pm/pkg/parsing/ParsingPackageRead;->isForceQueryable()Z

    move-result v0

    if-nez v0, :cond_xenoid_fq

    const/4 v0, 0x0

    return v0

    :cond_xenoid_fq
    invoke-static {p0}, Lcom/android/server/pm/ComputerEngine;->xenoidIsMicrogGms(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Z

    move-result v0

    return v0
.end method

.method private static xenoidFakeSignature(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Landroid/content/pm/Signature;
    .locals 4

    invoke-static {p0}, Lcom/android/server/pm/ComputerEngine;->xenoidIsMicrogGms(Lcom/android/server/pm/parsing/pkg/AndroidPackage;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_xenoid_microg

    return-object v1

    :cond_xenoid_microg
    invoke-interface {p0}, Lcom/android/server/pm/pkg/parsing/ParsingPackageRead;->getMetaData()Landroid/os/Bundle;

    move-result-object v0

    if-nez v0, :cond_xenoid_metadata

    return-object v1

    :cond_xenoid_metadata
    const-string v2, "fake-signature"

    invoke-virtual {v0, v2}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_xenoid_have_fake

    return-object v1

    :cond_xenoid_have_fake
    new-instance v2, Landroid/content/pm/Signature;

    invoke-direct {v2, v0}, Landroid/content/pm/Signature;-><init>(Ljava/lang/String;)V

    new-instance v0, Landroid/content/pm/Signature;

    const-string v3, "308204433082032ba003020102020900c2e08746644a308d300d06092a864886f70d01010405003074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f6964301e170d3038303832313233313333345a170d3336303130373233313333345a3074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f696430820120300d06092a864886f70d01010105000382010d00308201080282010100ab562e00d83ba208ae0a966f124e29da11f2ab56d08f58e2cca91303e9b754d372f640a71b1dcb130967624e4656a7776a92193db2e5bfb724a91e77188b0e6a47a43b33d9609b77183145ccdf7b2e586674c9e1565b1f4c6a5955bff251a63dabf9c55c27222252e875e4f8154a645f897168c0b1bfc612eabf785769bb34aa7984dc7e2ea2764cae8307d8c17154d7ee5f64a51a44a602c249054157dc02cd5f5c0e55fbef8519fbe327f0b1511692c5a06f19d18385f5c4dbc2d6b93f68cc2979c70e18ab93866b3bd5db8999552a0e3b4c99df58fb918bedc182ba35e003c1b4b10dd244a8ee24fffd333872ab5221985edab0fc0d0b145b6aa192858e79020103a381d93081d6301d0603551d0e04160414c77d8cc2211756259a7fd382df6be398e4d786a53081a60603551d2304819e30819b8014c77d8cc2211756259a7fd382df6be398e4d786a5a178a4763074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f6964820900c2e08746644a308d300c0603551d13040530030101ff300d06092a864886f70d010104050003820101006dd252ceef85302c360aaace939bcff2cca904bb5d7a1661f8ae46b2994204d0ff4a68c7ed1a531ec4595a623ce60763b167297a7ae35712c407f208f0cb109429124d7b106219c084ca3eb3f9ad5fb871ef92269a8be28bf16d44c8d9a08e6cb2f005bb3fe2cb96447e868e731076ad45b33f6009ea19c161e62641aa99271dfd5228c5c587875ddb7f452758d661f6cc0cccb7352e424cc4365c523532f7325137593c4ae341f4db41edda0d0b1071a7c440f0fe9ea01cb627ca674369d084bd2fd911ff06cdbf2cfa10dc0f893ae35762919048c7efc64c7144178342f70581c9de573af55b390dd7fdb9418631895d5f759f30112687ff621410c069308a"

    invoke-direct {v0, v3}, Landroid/content/pm/Signature;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Landroid/content/pm/Signature;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_xenoid_fake_ok

    return-object v1

    :cond_xenoid_fake_ok
    return-object v2
.end method
"""


def _replace_once(path: Path, original: str, replacement: str, label: str) -> None:
    text = path.read_text()
    occurrences = text.count(original)
    if occurrences != 1:
        raise SystemExit(f"expected one {label} patch point in {path}, found {occurrences}")
    path.write_text(text.replace(original, replacement, 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--google-provider", choices=("none", "microg"), required=True)
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.destination).resolve()
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
        _replace_once(ownership_smali, ORIGINAL, REPLACEMENT, "isolated-UID")

        data_smali = decoded / "smali_classes2/com/android/server/pm/Installer$Batch.smali"
        _replace_once(data_smali, APP_DATA_ORIGINAL, APP_DATA_REPLACEMENT, "app-data recovery")

        if args.google_provider == "microg":
            _replace_once(
                ownership_smali,
                GENERATE_PACKAGE_INFO_ANCHOR,
                GENERATE_PACKAGE_INFO_PATCHED,
                "restricted signature-spoofing",
            )
            ownership_smali.write_text(ownership_smali.read_text() + MICROG_HELPER_METHODS)
            _replace_once(
                decoded / "smali_classes2/com/android/server/pm/AppsFilterImpl.smali",
                APPS_FILTER_ANCHOR,
                APPS_FILTER_PATCHED,
                "forceQueryable signature predicate",
            )

        run_apktool(["b", "-f", "-o", str(staged), str(decoded)])
        canonicalize_zip(staged, canonical)
        with zipfile.ZipFile(canonical) as archive:
            if archive.namelist().count("classes2.dex") != 1:
                raise SystemExit("patched_services_dex_layout_mismatch")
            dex = archive.read("classes2.dex")
        checks = (
            b"getIsolatedOwner" in dex,
            b"Failed to restorecon /data/" in dex,
        )
        if args.google_provider == "microg":
            checks += (
                b"xenoidFakeSignature" in dex,
                b"xenoidIsMicrogGmsForceQueryable" in dex,
                b"fake-signature" in dex,
                MICROG_REAL_HEX[:32].encode("ascii") in dex,
                GOOGLE_FAKE_HEX[:32].encode("ascii") in dex,
            )
        if not all(checks):
            raise SystemExit("patched_services_verification_failed")
        publish_file_atomic(canonical, output)
    print(f"patched runtime PackageManager contracts in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
