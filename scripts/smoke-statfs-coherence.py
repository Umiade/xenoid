#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {
    "kmod": (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text(),
    "shim": (ROOT / "native/xenoid-shim/xenoid_shim.c").read_text(),
    "zygote": (ROOT / "native/xenoid-zygote/xenoid_zygote.c").read_text(),
}
pivot = (ROOT / "native/xenoid-pivot/xenoid_pivot.c").read_text()
host_source = (ROOT / "src/xenoid/protection.py").read_text()
kmod_set = SOURCES["kmod"].partition("static int statfs_fsid_set")[2].partition(
    "static int statfs_fsid_get"
)[0]
kmod_get = SOURCES["kmod"].partition("static int statfs_fsid_get")[2].partition(
    "static const struct kernel_param_ops"
)[0]
kmod_exit = SOURCES["kmod"].partition("static void __exit xenoid_kmod_exit")[2]
fsid_init_blocks = {
    name: SOURCES[name].partition("static void initialize_statfs_fsid")[2].partition(
        "static uint64_t load_statfs_fsid"
    )[0]
    for name in ("shim", "zygote")
}
fsid_load_blocks = {
    name: SOURCES[name].partition("static uint64_t load_statfs_fsid")[2].partition(
        "#define XENOID_SHAPE_STATFS_FSID"
    )[0]
    for name in ("shim", "zygote")
}


def define(source: str, name: str) -> str | None:
    match = re.search(rf"^#define {re.escape(name)} ([^\n]+)$", source, re.MULTILINE)
    return match.group(1).strip() if match else None


def run_parallel_first_use_stress() -> dict[str, object]:
    if sys.platform != "linux":
        return {"ok": True, "skipped": "requires Linux statfs ABI"}
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        return {"ok": False, "error": "host C compiler not found"}

    probe_source = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#define THREAD_COUNT 64
#define ITERATIONS 8

typedef int (*statfs_fn_t)(const char *, struct statfs *);
typedef int (*fstatfs_fn_t)(int, struct statfs *);
typedef long (*syscall_fn_t)(long, unsigned long, unsigned long, unsigned long,
                             unsigned long, unsigned long, unsigned long);

struct reader_context {
  pthread_barrier_t *barrier;
  int raw;
  int index;
};

static statfs_fn_t hooked_statfs;
static fstatfs_fn_t hooked_fstatfs;
static syscall_fn_t hooked_syscall;
static const char *data_path;
static const char *fifo_path;
static int data_fd;
static _Atomic int failures;

static void record_failure(void) {
  atomic_fetch_add_explicit(&failures, 1, memory_order_relaxed);
}

static int fsid_matches(const struct statfs *buf) {
  return (uint32_t)buf->f_fsid.__val[0] == UINT32_C(0x01234567)
      && (uint32_t)buf->f_fsid.__val[1] == UINT32_C(0x89abcdef);
}

static void *write_record(void *unused) {
  static const char record[] = "0123456789abcdef\n";
  (void)unused;
  int fd = open(fifo_path, O_WRONLY);
  if (fd < 0) {
    record_failure();
    return NULL;
  }
  usleep(250000);
  if (write(fd, record, sizeof(record) - 1) != (ssize_t)(sizeof(record) - 1))
    record_failure();
  close(fd);
  return NULL;
}

static void *read_statfs(void *opaque) {
  struct reader_context *context = (struct reader_context *)opaque;
  pthread_barrier_wait(context->barrier);
  for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
    struct statfs buf = {0};
    long result;
    if (!context->raw && ((context->index + iteration) & 1)) {
      result = hooked_fstatfs(data_fd, &buf);
    } else if (!context->raw) {
      result = hooked_statfs(data_path, &buf);
    } else if ((context->index + iteration) & 1) {
      result = hooked_syscall(SYS_fstatfs, (unsigned long)data_fd,
                              (unsigned long)&buf, 0, 0, 0, 0);
    } else {
      result = hooked_syscall(SYS_statfs, (unsigned long)data_path,
                              (unsigned long)&buf, 0, 0, 0, 0);
    }
    if (result != 0 || !fsid_matches(&buf))
      record_failure();
  }
  return NULL;
}

static int run_phase(int raw) {
  pthread_t writer;
  pthread_t readers[THREAD_COUNT];
  struct reader_context contexts[THREAD_COUNT];
  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, THREAD_COUNT) != 0)
    return -1;
  if (pthread_create(&writer, NULL, write_record, NULL) != 0)
    return -1;
  for (int i = 0; i < THREAD_COUNT; ++i) {
    contexts[i].barrier = &barrier;
    contexts[i].raw = raw;
    contexts[i].index = i;
    if (pthread_create(&readers[i], NULL, read_statfs, &contexts[i]) != 0)
      return -1;
  }
  for (int i = 0; i < THREAD_COUNT; ++i)
    pthread_join(readers[i], NULL);
  pthread_join(writer, NULL);
  pthread_barrier_destroy(&barrier);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  data_path = argv[2];
  fifo_path = argv[3];
  setenv("XENOID_PROFILE_DIR", argv[2], 1);
  setenv("XENOID_TEST_DATA_PATH", argv[2], 1);
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    return 3;
  hooked_statfs = (statfs_fn_t)dlsym(handle, "statfs");
  hooked_fstatfs = (fstatfs_fn_t)dlsym(handle, "fstatfs");
  hooked_syscall = (syscall_fn_t)dlsym(handle, "syscall");
  if (!hooked_statfs || !hooked_fstatfs || !hooked_syscall)
    return 4;
  if (hooked_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0) != (long)getpid())
    return 5;
  data_fd = open(data_path, O_RDONLY | O_DIRECTORY);
  if (data_fd < 0)
    return 5;
  atomic_init(&failures, 0);
  if (run_phase(0) != 0 || run_phase(1) != 0)
    return 6;
  close(data_fd);
  int observed = atomic_load_explicit(&failures, memory_order_relaxed);
  printf("failures=%d\n", observed);
  return observed ? 7 : 0;
}
"""
    uid_source = r"""
#include <sys/types.h>
uid_t xenoid_test_getuid(void) { return 10000; }
"""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        profile = root / "profile"
        profile.mkdir()
        fifo = profile / "statfs_fsid"
        os.mkfifo(fifo)
        probe_c = root / "probe.c"
        uid_c = root / "uid.c"
        shared_object = root / "libxenoid_statfs_stress.so"
        probe = root / "probe"
        probe_c.write_text(probe_source, encoding="utf-8")
        uid_c.write_text(uid_source, encoding="utf-8")
        build_shared = subprocess.run(
            [
                cc,
                "-std=gnu11",
                "-shared",
                "-fPIC",
                "-O2",
                "-DXENOID_HOST_TEST",
                "-DXENOID_COMBINED_SHIM",
                "-Dgetuid=xenoid_test_getuid",
                str(ROOT / "native/xenoid-shim/xenoid_shim.c"),
                str(ROOT / "native/xenoid-zygote/xenoid_zygote.c"),
                str(uid_c),
                "-o",
                str(shared_object),
                "-ldl",
                "-pthread",
            ],
            text=True,
            capture_output=True,
            timeout=60,
        )
        if build_shared.returncode != 0:
            return {
                "ok": False,
                "stage": "build-shared",
                "stderr": build_shared.stderr,
            }
        build_probe = subprocess.run(
            [
                cc,
                "-std=gnu11",
                "-O2",
                str(probe_c),
                "-o",
                str(probe),
                "-ldl",
                "-pthread",
            ],
            text=True,
            capture_output=True,
            timeout=60,
        )
        if build_probe.returncode != 0:
            return {
                "ok": False,
                "stage": "build-probe",
                "stderr": build_probe.stderr,
            }
        run = subprocess.run(
            [str(probe), str(shared_object), str(profile), str(fifo)],
            text=True,
            capture_output=True,
            timeout=20,
        )
        return {
            "ok": run.returncode == 0 and run.stdout.strip() == "failures=0",
            "returncode": run.returncode,
            "stdout": run.stdout,
            "stderr": run.stderr,
        }


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
    "fsid_shaped_on_every_layer": (
        all("XENOID_SHAPE_STATFS_FSID(buf);" in block
            for block in (shim_shape, zygote_shape))
        and "WRITE_ONCE(buf->f_fsid.val[0], val0);" in kmod_shape
        and "WRITE_ONCE(buf->f_fsid.val[1], val1);" in kmod_shape
    ),
    "fsid_runtime_input_kmod": (
        "module_param_cb(statfs_fsid, &statfs_fsid_ops, NULL, 0600)"
        in SOURCES["kmod"]
    ),
    "fsid_pernet_lifecycle": (
        "register_pernet_subsys(&xenoid_statfs_net_ops)" in SOURCES["kmod"]
        and "unregister_pernet_subsys(&xenoid_statfs_net_ops)" in SOURCES["kmod"]
        and ".id = &xenoid_statfs_net_id" in SOURCES["kmod"]
        and ".size = sizeof(struct xenoid_statfs_net)" in SOURCES["kmod"]
        and "WRITE_ONCE(xnet->fsid, 0);" in SOURCES["kmod"]
        and SOURCES["kmod"].index("register_pernet_subsys(&xenoid_statfs_net_ops)")
        < SOURCES["kmod"].index("ret = register_kretprobe(seclabel_rprobes[i])")
    ),
    "fsid_contextual_callbacks": (
        "current->nsproxy->net_ns" in SOURCES["kmod"]
        and "net_generic(current->nsproxy->net_ns, xenoid_statfs_net_id)" in SOURCES["kmod"]
        and "current_net_is_xenoid_android_runtime()" in kmod_set
        and "-EPERM" in kmod_set
        and "xenoid_statfs_net_state()" in kmod_get
        and "for (i = 0; i < 16; i++)" in kmod_set
        and "hex_to_bin(value[i]) < 0" in kmod_set
        and "!parsed" in kmod_set
    ),
    "fsid_single_aligned_u64_no_global_pair": (
        "u64 fsid __aligned(8);" in SOURCES["kmod"]
        and "WRITE_ONCE(xnet->fsid, (u64)parsed);" in kmod_set
        and "READ_ONCE(xnet->fsid)" in SOURCES["kmod"]
        and "module_param_cb(statfs_fsid_reset, &statfs_fsid_reset_ops, NULL, 0200)" in SOURCES["kmod"]
        and "WRITE_ONCE(xnet->fsid, 0);" in SOURCES["kmod"]
        and "statfs_fsid_lock" not in SOURCES["kmod"]
        and "statfs_fsid_val0" not in SOURCES["kmod"]
        and "statfs_fsid_val1" not in SOURCES["kmod"]
    ),
    "fsid_teardown_no_use_after_free": (
        "kernel_param_lock(THIS_MODULE);" in SOURCES["kmod"]
        and SOURCES["kmod"].count("    unregister_statfs_pernet();") == 2
        and "unregister_protection();" in kmod_exit
        and "unregister_statfs_pernet();" in kmod_exit
        and kmod_exit.index("unregister_protection();")
        < kmod_exit.index("unregister_statfs_pernet();")
    ),
    "fsid_namespace_entered_publication": (
        host_source.count('nsenter --net="$pinned_netns" -- sh -c') == 2
        and "netns=/proc/{pid}/ns/net" in host_source
        and 'exec 9<"$netns"' in host_source
        and "pinned_netns=/proc/self/fd/9" in host_source
        and "grep -q {container_id} /proc/{pid}/cgroup" in host_source
        and '[ "$(readlink "$pinned_netns")" = "{netns}" ]' in host_source
        and '["readlink", "/proc/self/ns/net"]' in host_source
        and "_statfs_fsid_container_exec(" in host_source
        # The exclusivity sweep enumerates every engine container, not only
        # labeled xenoid ones: an unlabeled container sharing the pinned
        # netns must also block publication.
        and "for other in $(docker ps -q --no-trunc); do" in host_source
        and "--filter"
        not in host_source[
            host_source.index("def _set_statfs_fsid_locked") :
            host_source.index("def set_statfs_fsid")
        ]
        and "printf %s 1 > {STATFS_FSID_RESET_PARAM}" in host_source
        and host_source.index('nsenter --net="$pinned_netns" -- sh -c')
        < host_source.index("printf %s {fsid_hex} > {STATFS_FSID_PARAM}")
    ),
    "fsid_staged_leaf_shared": (
        '"statfs_fsid"' in SOURCES["shim"]
        and '"%s/statfs_fsid"' in SOURCES["zygote"]
        and SOURCES["shim"].count("XENOID_SHAPE_STATFS_FSID(buf)") == 2
        and SOURCES["zygote"].count("XENOID_SHAPE_STATFS_FSID(buf)") == 2
    ),
    "fsid_parse_byte_identical": all(
        "text[half * 8 + i]" in SOURCES[name]
        and "(v[half] << 4)" in SOURCES[name]
        and "statfs_fsid_value = ((uint64_t)v[0] << 32) | (uint64_t)v[1];"
        in SOURCES[name]
        and "__val[0] = (int)(uint32_t)(fsid >> 32);" in SOURCES[name]
        and "__val[1] = (int)(uint32_t)fsid;" in SOURCES[name]
        for name in ("shim", "zygote")
    ),
    "fsid_first_use_published_once": all(
        "static pthread_once_t statfs_fsid_once = PTHREAD_ONCE_INIT;"
        in SOURCES[name]
        and "pthread_once(&statfs_fsid_once, initialize_statfs_fsid);"
        in fsid_load_blocks[name]
        and "return statfs_fsid_value;" in fsid_load_blocks[name]
        and "statfs_fsid_ready" not in SOURCES[name]
        and "statfs_fsid_vals" not in SOURCES[name]
        and fsid_init_blocks[name].index("text[half * 8 + i]")
        < fsid_init_blocks[name].index("statfs_fsid_value =")
        for name in ("shim", "zygote")
    ),
    "fsid_parsers_reject_short_or_long_input": (
        "char text[18];" in SOURCES["shim"]
        and "size != 17 || text[16] != '\\n'" in SOURCES["shim"]
        and "char text[32];" in SOURCES["zygote"]
        and "size != 17 || text[16] != '\\n'" in SOURCES["zygote"]
        and all(
            SOURCES[name].index("size != 17")
            < SOURCES[name].index("text[half * 8 + i]")
            for name in ("shim", "zygote")
        )
    ),
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

stress = run_parallel_first_use_stress()
checks["parallel_first_use_libc_raw_statfs"] = stress["ok"]
out = {
    "ok": all(checks.values()),
    "checks": checks,
    "fieldTables": constant_tables,
    "stress": stress,
}
print(json.dumps(out, indent=2, sort_keys=True))
sys.exit(0 if out["ok"] else 1)
