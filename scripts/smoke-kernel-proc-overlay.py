#!/usr/bin/env python3
from __future__ import annotations
import ast, json, pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
kmod = (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text()
vfs_xattr = kmod.partition("static int vfs_xattr_post")[2].partition(
    "static struct kretprobe vfs_xattr_kp"
)[0]
mount_seq = kmod.partition("static int mount_seq_pre")[2].partition(
    "static struct kretprobe mountstats_seq_kp"
)[0]
mountinfo_seq = kmod.partition("static int mountinfo_seq_post")[2].partition(
    "static int mounts_seq_post"
)[0]
mounts_seq = kmod.partition("static int mounts_seq_post")[2].partition(
    "static int mountstats_seq_post"
)[0]
mountstats_seq = kmod.partition("static int mountstats_seq_post")[2].partition(
    "static struct kretprobe mountinfo_seq_kp"
)[0]
def macro_string(name: str) -> str:
    lines = kmod.splitlines()
    marker = f"#define {name} "
    for index, line in enumerate(lines):
        if not line.startswith(marker):
            continue
        body = line[len(marker):]
        while body.endswith("\\"):
            index += 1
            body = body[:-1] + lines[index].strip()
        return "".join(
            ast.literal_eval(token)
            for token in re.findall(r'"(?:\\.|[^"\\])*"', body)
        )
    return ""


mount_source = macro_string("XENOID_DATA_MOUNT_SOURCE")
mount_options = macro_string("XENOID_DATA_MOUNT_OPTIONS")
f2fs_options = macro_string("XENOID_DATA_F2FS_OPTIONS")
checks = {
    "overlay_function": "overlay_kernel_proc_misc" in src,
    "proc_uptime_native": 'overlay_text_optional("proc_uptime"' not in src
    and '"/proc/uptime"' in src,
    "proc_loadavg": "/proc/loadavg" in src,
    "proc_filesystems": "/proc/filesystems" in src and "f2fs" in src and "binder" in src,
    "proc_swaps": "/proc/swaps" in src,
    "kernel_osrelease": "/proc/sys/kernel/osrelease" in src and "android13" in src,
    "kernel_ostype": "/proc/sys/kernel/ostype" in src,
    "optional_mount": "overlay_text_optional" in src,
    "app_hooks_runtime_scoped": kmod.count("current_is_xenoid_android_app()") >= 4,
    "selinux_hooks_runtime_scoped": kmod.count(
        "android_runtime = current_net_is_xenoid_android_runtime();"
    ) == 3
    and "if (!c->android_runtime || !c->value" in kmod,
    "selinux_xattr_nul_sized": "len = strlen(label) + 1;" in vfs_xattr,
    "readlink_preserves_anonymous_fds": "deny_memfd" not in kmod
    and "explicit Frida inspection" in kmod,
    "mount_handlers_runtime_scoped": (
        "current_is_android_app()" in mount_seq
        and "current_net_is_xenoid_android_runtime()" in mount_seq
    ),
    "mount_markers_still_dropped": (
        '" /overlay.d/"' in mount_seq
        and '" /data/system/.core/"' in mount_seq
        and "seq->count = ctx->count;" in mount_seq
    ),
    "mountinfo_data_record": all(
        value in mountinfo_seq
        for value in (
            "parse_mountinfo_identity",
            '"%u %u %u:%u / /data "',
            '" - f2fs "',
            "XENOID_DATA_MOUNT_SOURCE",
            "XENOID_DATA_SUPER_OPTIONS",
            "mount_id, parent_id, dev_major, dev_minor",
        )
    ),
    "mounts_data_record": all(
        value in mounts_seq
        for value in (
            "vfsmnt_record_is_data",
            'XENOID_DATA_MOUNT_SOURCE " /data f2fs "',
            "XENOID_DATA_MOUNT_OPTIONS",
            "XENOID_DATA_F2FS_OPTIONS",
        )
    ),
    "mountstats_data_record": all(
        value in mountstats_seq
        for value in (
            '" mounted on /data "',
            '"device " XENOID_DATA_MOUNT_SOURCE',
            '" mounted on /data with fstype f2fs\\n"',
        )
    ),
    "mount_records_seq_bounded": (
        mountinfo_seq.count("seq_printf(seq,") == 1
        and mounts_seq.count("seq_printf(seq,") == 1
        and mountstats_seq.count("seq_printf(seq,") == 1
    ),
    "mount_record_contract_matches_overlay": all(
        value in src and value in kmod
        for value in (
            "/dev/block/platform/14700000.ufs/by-name/userdata",
            "rw,seclabel,nosuid,nodev,noatime",
            "discard,inlinecrypt,atgc,checkpoint_merge,reserve_root=32768",
            "resgid=1065,fsync_mode=nobarrier",
        )
    ),
    "mount_macro_contract_exact": (
        mount_source == "/dev/block/platform/14700000.ufs/by-name/userdata"
        and mount_options == "rw,seclabel,nosuid,nodev,noatime"
        and f2fs_options
        == (
            "discard,inlinecrypt,atgc,checkpoint_merge,reserve_root=32768,"
            "resgid=1065,fsync_mode=nobarrier"
        )
        and '"rw," XENOID_DATA_F2FS_OPTIONS' in kmod
    ),
    "apply_calls": "kernel_proc_misc=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
