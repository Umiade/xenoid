#!/usr/bin/env python3
"""Bake the selected canonical device profile into every Android build.prop."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "examples/fingerprints/pixel-raven-android13.json"
PARTITIONS = {
    "system_build.prop": ("system/build.prop", "system"),
    "vendor_build.prop": ("vendor/build.prop", "vendor"),
    "product_build.prop": ("system/product/etc/build.prop", "product"),
    "system_ext_build.prop": ("system/system_ext/etc/build.prop", "system_ext"),
    "system_dlkm_build.prop": ("system/system_dlkm/etc/build.prop", "system_dlkm"),
    "odm_build.prop": ("vendor/odm/etc/build.prop", "odm"),
    "vendor_dlkm_build.prop": ("vendor/vendor_dlkm/etc/build.prop", "vendor_dlkm"),
    "odm_dlkm_build.prop": ("vendor/odm_dlkm/etc/build.prop", "odm_dlkm"),
}


def _string(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"profile.build.{key} is required")
    return value


def load_build(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    profile = document.get("profile", document)
    if not isinstance(profile, dict) or profile.get("schema") != "dev.xenoid.fingerprint/v1":
        raise ValueError("unsupported device profile schema")
    build = profile.get("build")
    if not isinstance(build, dict):
        raise ValueError("profile.build is required")
    for key in (
        "brand", "manufacturer", "model", "device", "product", "board", "platform",
        "hardware", "soc_manufacturer", "soc_model", "release", "sdk", "id",
        "incremental", "description", "fingerprint", "bootloader", "security_patch",
        "first_api_level", "sku", "tags", "type", "abi", "abilist", "abilist64",
        "bionic_arch", "dalvik_isa_arm64",
    ):
        _string(build, key)
    for key in ("abilist32", "dalvik_isa_arm"):
        if not isinstance(build.get(key), str):
            raise ValueError(f"profile.build.{key} is required")
    return build


def _partition_identity(build: dict[str, Any], scope: str) -> list[str]:
    product_prefix = f"ro.product.{scope}"
    build_prefix = f"ro.{scope}.build"
    cpu_prefix = f"ro.{scope}.product.cpu"
    return [
        f"{product_prefix}.brand={build['brand']}",
        f"{product_prefix}.device={build['device']}",
        f"{product_prefix}.manufacturer={build['manufacturer']}",
        f"{product_prefix}.model={build['model']}",
        f"{product_prefix}.name={build['product']}",
        f"{cpu_prefix}.abilist={build['abilist']}",
        f"{cpu_prefix}.abilist32={build['abilist32']}",
        f"{cpu_prefix}.abilist64={build['abilist64']}",
        f"{build_prefix}.fingerprint={build['fingerprint']}",
        f"{build_prefix}.id={build['id']}",
        f"{build_prefix}.tags={build['tags']}",
        f"{build_prefix}.type={build['type']}",
        f"{build_prefix}.version.incremental={build['incremental']}",
        f"{build_prefix}.version.release={build['release']}",
        f"{build_prefix}.version.release_or_codename={build['release']}",
        f"{build_prefix}.version.sdk={build['sdk']}",
    ]


def generated_partition_lines(build: dict[str, Any]) -> dict[str, list[str]]:
    generated = {
        name: _partition_identity(build, scope)
        for name, (_, scope) in PARTITIONS.items()
    }
    generated["system_build.prop"] += [
        f"ro.product.brand={build['brand']}",
        f"ro.product.device={build['device']}",
        f"ro.product.manufacturer={build['manufacturer']}",
        f"ro.product.model={build['model']}",
        f"ro.product.name={build['product']}",
        f"ro.product.cpu.abi={build['abi']}",
        f"ro.product.cpu.abilist={build['abilist']}",
        f"ro.product.cpu.abilist32={build['abilist32']}",
        f"ro.product.cpu.abilist64={build['abilist64']}",
        f"ro.build.fingerprint={build['fingerprint']}",
        f"ro.build.id={build['id']}",
        f"ro.build.display.id={build['id']}",
        f"ro.build.version.incremental={build['incremental']}",
        f"ro.build.version.release={build['release']}",
        f"ro.build.version.release_or_codename={build['release']}",
        f"ro.build.version.sdk={build['sdk']}",
        f"ro.build.version.security_patch={build['security_patch']}",
        f"ro.build.tags={build['tags']}",
        f"ro.build.type={build['type']}",
        f"ro.build.product={build['product']}",
        f"ro.build.description={build['description']}",
        f"ro.bootloader={build['bootloader']}",
        f"ro.product.first_api_level={build['first_api_level']}",
        f"ro.bionic.arch={build['bionic_arch']}",
        f"ro.dalvik.vm.isa.arm64={build['dalvik_isa_arm64']}",
        f"ro.dalvik.vm.isa.arm={build['dalvik_isa_arm']}",
        "ro.bootmode=normal",
        "ro.telephony.default_network=9",
        "ro.telephony.sim.count=1",
        # Present in every stock raven build.prop; redroid's build system
        # does not emit it, and its absence is itself a platform anomaly.
        "ro.build.selinux=1",
    ]
    generated["vendor_build.prop"] += [
        f"ro.hardware={build['hardware']}",
        f"ro.boot.hardware={build['hardware']}",
        f"ro.product.board={build['board']}",
        f"ro.board.platform={build['platform']}",
        f"ro.soc.manufacturer={build['soc_manufacturer']}",
        f"ro.soc.model={build['soc_model']}",
        f"ro.boot.hardware.sku={build['sku']}",
        f"ro.hardware.sku={build['sku']}",
        f"ro.product.first_api_level={build['first_api_level']}",
        f"ro.vendor.build.security_patch={build['security_patch']}",
        f"ro.bionic.arch={build['bionic_arch']}",
        "ro.radio.noril=no",
        "vendor.rild.libpath=/vendor/lib64/libxenoid-ril.so",
    ]
    return generated


def patch_file(stock: str, append: list[str]) -> str:
    drop_keys = {line.split("=", 1)[0] for line in append}
    forbidden_markers = ("redroid", "userdebug", "test-keys", "x86_64")
    kept = []
    for line in stock.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or line.split("=", 1)[0] in drop_keys
            or any(marker in stripped.casefold() for marker in forbidden_markers)
        ):
            continue
        kept.append(line)
    return "\n".join(kept + append) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stock_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE))
    parser.add_argument("--expect-build-product")
    parser.add_argument("--setupwizard-mode", choices=["DISABLED"])
    args = parser.parse_args()
    stock_dir = Path(args.stock_dir)
    out_dir = Path(args.out_dir)
    try:
        build = load_build(Path(args.profile))
        if args.expect_build_product and build["product"] != args.expect_build_product:
            raise ValueError(
                f"generated build product {build['product']} does not match {args.expect_build_product}"
            )
        generated = generated_partition_lines(build)
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, (relative, _) in PARTITIONS.items():
            append = list(generated[name])
            if name == "system_build.prop" and args.setupwizard_mode:
                append.append(f"ro.setupwizard.mode={args.setupwizard_mode}")
            stock = (stock_dir / relative).read_text(encoding="utf-8")
            (out_dir / name).write_text(patch_file(stock, append), encoding="utf-8")
            print(f"patched {name}: appended={len(append)}")
    except (OSError, ValueError, json.JSONDecodeError) as failure:
        print(f"patch-runtime-props: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
