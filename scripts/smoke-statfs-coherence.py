#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


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



checks = {}

stress = run_parallel_first_use_stress()
checks["parallel_first_use_libc_raw_statfs"] = stress["ok"]
out = {
    "ok": all(checks.values()),
    "checks": checks,
    "stress": stress,
}
print(json.dumps(out, indent=2, sort_keys=True))
sys.exit(0 if out["ok"] else 1)
