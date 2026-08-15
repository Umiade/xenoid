#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {
    "kmod": (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text(),
    "shim": (ROOT / "native/xenoid-shim/xenoid_shim.c").read_text(),
    "zygote": (ROOT / "native/xenoid-zygote/xenoid_zygote.c").read_text(),
}
pivot = (ROOT / "native/xenoid-pivot/xenoid_pivot.c").read_text()


def define(source: str, name: str) -> str | None:
    match = re.search(rf"^#define {re.escape(name)} ([^\n]+)$", source, re.MULTILINE)
    return match.group(1).strip() if match else None


constant_names = (
    "XENOID_DATA_BLOCK_SIZE",
    "XENOID_DATA_BLOCKS",
    "XENOID_DATA_NAME_MAX",
    "XENOID_DATA_STATFS_FLAGS",
)
constant_tables = {
    producer: {name: define(source, name) for name in constant_names}
    for producer, source in SOURCES.items()
}
expected_table = {
    "XENOID_DATA_BLOCK_SIZE": "4096ULL",
    "XENOID_DATA_BLOCKS": "31250000ULL",
    "XENOID_DATA_NAME_MAX": "255ULL",
    "XENOID_DATA_STATFS_FLAGS": "0x426ULL",
}

kmod_shape = SOURCES["kmod"].partition("static void shape_data_statfs")[2].partition(
    "static bool statfs_cloned_abi"
)[0]
shim_shape = SOURCES["shim"].partition("#define XENOID_SHAPE_DATA_STATFS")[2].partition(
    "int statfs(const char *path"
)[0]
zygote_shape = SOURCES["zygote"].partition("#define XENOID_SHAPE_DATA_STATFS")[2].partition(
    "static int fd_is_data_device"
)[0]
shape_blocks = {"kmod": kmod_shape, "shim": shim_shape, "zygote": zygote_shape}
ratio_fields = ("f_bfree", "f_bavail", "f_files", "f_ffree")
normalized_fields = (
    "f_type",
    "f_bsize",
    "f_blocks",
    "f_bfree",
    "f_bavail",
    "f_files",
    "f_ffree",
    "f_namelen",
    "f_flags",
)

checks = {
    "constant_tables_byte_identical": (
        all(table == expected_table for table in constant_tables.values())
        and len({tuple(table.items()) for table in constant_tables.values()}) == 1
    ),
    "f2fs_magic_all_producers": all("0xF2F52010" in source for source in SOURCES.values()),
    "all_fields_normalized": all(
        all(field in block for field in normalized_fields)
        for block in shape_blocks.values()
    ),
    "free_and_inode_ratios_scaled": all(
        all(
            f"scale_data_statfs_value(real_{field[2:]},real_blocks)" in block.replace(" ", "")
            for field in ratio_fields
        )
        for block in shape_blocks.values()
    ),
    "zero_blocks_pass_through": (
        "if (!real_blocks)" in kmod_shape
        and "if(real_blocks)" in shim_shape
        and "if(real_blocks)" in zygote_shape
    ),
    "fsid_passes_through": all("f_fsid" not in block for block in shape_blocks.values()),
    "overflow_safe_ratio": (
        "mul_u64_u32_div" in SOURCES["kmod"]
        and all(
            "quotient=value/total" in SOURCES[name]
            and "remainder=value%total" in SOURCES[name]
            for name in ("shim", "zygote")
        )
    ),
    "shim_all_statfs_entrypoints": all(
        token in SOURCES["shim"]
        for token in (
            "int statfs(const char *path",
            "int statfs64(const char *path",
            "int fstatfs(int fd",
            "int fstatfs64(int fd",
        )
    )
    and SOURCES["shim"].count("XENOID_SHAPE_DATA_STATFS(buf);") == 4,
    "zygote_raw_statfs_and_fstatfs": (
        "number == __NR_statfs" in SOURCES["zygote"]
        and "number == __NR_fstatfs" in SOURCES["zygote"]
        and "fd_is_data_device((int)args[0])" in SOURCES["zygote"]
        and SOURCES["zygote"].count("XENOID_SHAPE_DATA_STATFS(buf);") == 3
    ),
    "uid_scopes_preserved": (
        "current_is_android_app()" in SOURCES["kmod"]
        and "current_net_is_xenoid_android_runtime()" in SOURCES["kmod"]
        and "xenoid_reader_is_app_uid()" in SOURCES["shim"]
        and SOURCES["zygote"].count("getuid() >= 10000") >= 4
    ),
    "flags_match_data_mount_owner": (
        "MS_NOSUID | MS_NODEV | MS_NOATIME" in pivot
        and expected_table["XENOID_DATA_STATFS_FLAGS"] == "0x426ULL"
    ),
}

out = {
    "ok": all(checks.values()),
    "checks": checks,
    "fieldTables": constant_tables,
}
print(json.dumps(out, indent=2, sort_keys=True))
sys.exit(0 if out["ok"] else 1)
