#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
hide = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/HideManager.java").read_text()
kmod = (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text()
bpf = (ROOT / "native/xenoid-ebpf/xenoid_pathhide.bpf.c").read_text()
loader = (ROOT / "native/xenoid-ebpf/loader.c").read_text()
context_policy = kmod.partition("static bool selinux_context_authorized")[2].partition(
    "static ssize_t context_store"
)[0]
class_builder = kmod.partition("static int selinux_class_create_dirs")[2].partition(
    "static void selinux_class_remove_dirs"
)[0]
proc_labels = kmod.partition("static const char *proc_label_for_inode")[2].partition(
    "static bool inode_name_has_suffix"
)[0]
vfs_xattr = kmod.partition("static int vfs_xattr_post")[2].partition(
    "/* The /data volume f2fs"
)[0]
data_label = kmod.partition("/* The /data volume f2fs")[2].partition(
    "static struct kretprobe vfs_xattr_kp"
)[0]
access_placeholder = kmod.partition("static ssize_t selinux_access_show")[2].partition(
    "static int selinux_access_create_file"
)[0]
checks = {
    "single_selinux_node_owner": "overlay_selinuxfs" not in src
    and "selinux_enforce" not in src
    and "selinux_policyvers" not in src,
    "kmod_status_nodes": "kobject_create_and_add(\"selinux\", fs_kobj)" in kmod
    and "&enforce_attr.attr" in kmod
    and "&policyvers_attr.attr" in kmod
    and "&mls_attr.attr" in kmod,
    "hide_apply_reapplies_overlay": "xenoid-overlay-helper apply" in hide,
    # Restored stock synthesis: attr/current/exec/prev -> proc_security,
    # per-pid dirs -> owner domain via domain_for_uid, root fallback proc:s0.
    "proc_labels_synthesized_per_domain": proc_labels.count(
        '"u:object_r:proc_security:s0"'
    ) == 2
    and proc_labels.count("domain_for_uid") == 2
    and proc_labels.count('return "u:object_r:proc:s0";') == 2
    and "static bool inode_has_decimal_name" in kmod,
    # /proc/self/exe getxattr returns the process domain, not the proc label.
    "proc_exe_label_uses_process_domain": '!strcmp(c->dentry->d_name.name, "exe")' in vfs_xattr
    and "label = domain_for_uid(uid, tmp, sizeof(tmp));" in vfs_xattr,
    # App-private data is app_data_file; only installed APKs are apk_data_file.
    "app_private_data_uses_app_data_file": data_label.count(
        '"u:object_r:app_data_file:s0"'
    ) == 2
    and data_label.count('"u:object_r:apk_data_file:s0"') == 1,
    "class_index_at_stock_path": '.attr = { .name = "index", .mode = 0444 }'
    in kmod
    and "sysfs_create_file(dir->kobj, dir->index)" in class_builder
    and "selinux_class_index_group" not in kmod,
    "root_context_controls_rejected": '"adbroot"' not in context_policy,
    "access_metadata_without_fake_policy": "return -EOPNOTSUPP;" in access_placeholder
    and "selinux_access_rules" not in kmod
    and "security_compute_av_user" not in kmod,
    "untrusted_app_selinux_access_denied": "#define EACCES 13" in bpf
    and 'contains(path, "/sys/fs/selinux/")' in bpf
    and "inode_is_selinux_control" in bpf
    and "mask & (MAY_READ | MAY_WRITE)" in bpf
    and "security_inode_permission" in bpf
    and "return -EACCES;" in bpf
    and '"selinux_permission_link"' in loader
    and "xenoid_fmod_security_inode_permission" in loader,
    "app_selinux_metadata_reads_denied": "static bool path_selinux_control" in kmod
    and 'strstr(path, "/sys/fs/selinux/")' in kmod
    and "veto = -EACCES;" in kmod
    and "long veto = stash_take();" in kmod
    and "regs_set_return_value(regs, veto);" in kmod,
    # isolated_app has no grant on non-pid procfs files on stock: even
    # getattr (/proc/version stat) is EACCES; pid entries stay reachable.
    "isolated_app_proc_getattr_denied": "static bool path_denied_isolated_proc" in kmod
    and "stash_put_kind(upath, true, false);" in kmod
    and 'current_is_isolated_android_app() && !strcmp(path, "/proc/version")' not in kmod
    and 'path_denied_isolated_proc(path)' in kmod,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
