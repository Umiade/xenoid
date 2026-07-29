#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
CC = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
if not CC:
    print(json.dumps({'ok': False, 'error': 'host C compiler not found'})); sys.exit(1)
source = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/utsname.h>
typedef int (*open_probe_t)(const char*,int);
typedef int (*open2_probe_t)(const char*,int);
typedef int (*access_probe_t)(const char*,int);
typedef struct dirent *(*readdir_probe_t)(DIR*);
typedef int (*uname_probe_t)(struct utsname*);
static open_probe_t xopen;
static open2_probe_t xopen2;
static access_probe_t xaccess;
static readdir_probe_t xreaddir;
static uname_probe_t xuname;
static void dump_file(const char *label, const char *path) {
  int fd = xopen(path, O_RDONLY);
  if (fd < 0) { printf("%s=open_error:%d\n", label, errno); return; }
  char buf[4096]; ssize_t n = read(fd, buf, sizeof(buf)-1); close(fd);
  if (n < 0) { printf("%s=read_error:%d\n", label, errno); return; }
  buf[n] = 0;
  for (ssize_t i=0;i<n;i++) if (buf[i]=='\n') buf[i]='|';
  printf("%s=%s\n", label, buf);
}
int main(void) {
  void *h = dlopen(getenv("XENOID_SHIM_SO"), RTLD_NOW|RTLD_GLOBAL);
  if (!h) { printf("dlopen_error=%s\n", dlerror()); return 2; }
  const char *profile_rename = getenv("XENOID_TEST_PROFILE_RENAME_TO");
  if (profile_rename) rename(getenv("XENOID_PROFILE_DIR"), profile_rename);
  if (getenv("XENOID_TEST_ZYGOTE_CHILD")) setenv("XENOID_TEST_FORCE_APP_UID", "1", 1);
  xopen = (open_probe_t)dlsym(h, "xenoid_open_probe");
  xopen2 = (open2_probe_t)dlsym(h, "__open_2");
  xaccess = (access_probe_t)dlsym(h, "xenoid_access_probe");
  xreaddir = (readdir_probe_t)dlsym(h, "xenoid_readdir_probe");
  xuname = (uname_probe_t)dlsym(h, "uname");
  if (!xopen || !xopen2 || !xaccess || !xreaddir || !xuname) { printf("dlsym_error=%s\n", dlerror()); return 3; }
  dump_file("boot", getenv("XENOID_TEST_BOOT_ID_PATH"));
  dump_file("tcp", getenv("XENOID_TEST_TCP_PATH"));
  dump_file("maps", getenv("XENOID_TEST_MAPS_PATH"));
  dump_file("mac", getenv("XENOID_TEST_MAC_PATH"));
  errno=0; printf("access_frida=%d:%d\n", xaccess("/tmp/frida-marker", F_OK), errno);
  errno=0; int open2_fd=xopen2("/dev/null",O_RDONLY); printf("open2=%d:%d\n",open2_fd>=0?0:-1,errno); if(open2_fd>=0) close(open2_fd);
  DIR *d = opendir("/tmp/xenoid-shim-dir");
  if (d) { struct dirent *e; printf("dir="); while ((e=xreaddir(d))) printf("%s,", e->d_name); printf("\n"); closedir(d); }
  struct utsname uts = {0};
  if (xuname(&uts) == 0) printf("uname=%s\n", uts.release);
  return 0;
}
'''
with tempfile.TemporaryDirectory() as td:
    t = pathlib.Path(td)
    (t/'probe.c').write_text(source)
    prof = t/'profile'; prof.mkdir()
    (prof/'boot_id').write_text('profile-boot-id\n')
    (prof/'mac_address').write_text('02:11:22:33:44:55\n')
    (t/'real_boot').write_text('real-boot-id\n')
    (t/'tcp').write_text('  sl  local_address rem_address st\n   0: 00000000:15B3 00000000:0000 0A\n   1: 00000000:1234 00000000:0000 0A\n')
    (t/'maps').write_text('1000-2000 r-xp /data/local/tmp/frida-server\n3000-4000 r-xp /system/lib64/libc.so\n')
    (t/'address').write_text('de:ad:be:ef:00:01\n')
    os.makedirs('/tmp/xenoid-shim-dir', exist_ok=True)
    pathlib.Path('/tmp/xenoid-shim-dir/frida-server').write_text('x')
    pathlib.Path('/tmp/xenoid-shim-dir/normal').write_text('x')
    pathlib.Path('/tmp/frida-marker').write_text('x')
    shim = ROOT/'native/xenoid-shim/libxenoid_shim-host.so'
    build = subprocess.run([CC, '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-DXENOID_HOST_TEST', '-o', str(shim), str(ROOT/'native/xenoid-shim/xenoid_shim.c'), '-ldl'], text=True, capture_output=True)
    if build.returncode != 0:
        print(json.dumps({'ok': False, 'stage': 'build-host-shim', 'stderr': build.stderr})); sys.exit(1)
    exe = t/'probe'
    subprocess.check_call([CC, '-U_FORTIFY_SOURCE', '-O0', str(t/'probe.c'), '-o', str(exe)])
    env = os.environ.copy()
    env.update({
        'XENOID_SHIM_SO': str(shim),
        'XENOID_PROFILE_DIR': str(prof),
        'XENOID_TEST_BOOT_ID_PATH': str(t/'real_boot'),
        'XENOID_TEST_TCP_PATH': str(t/'tcp'),
        'XENOID_TEST_MAPS_PATH': str(t/'maps'),
        'XENOID_TEST_MAC_PATH': str(t/'address'),
        'XENOID_TEST_HIDE_PATH': '/tmp/frida-marker',
        'XENOID_TEST_HIDE_DIRENT': 'frida-server',
        'XENOID_TEST_FORCE_APP_UID': '1',
    })
    run = subprocess.run([str(exe)], text=True, capture_output=True, env=env, timeout=10)
    out = run.stdout
    checks = {
        'boot_profile': 'boot=profile-boot-id|' in out,
        'tcp_filtered': ':15B3' not in next((l for l in out.splitlines() if l.startswith('tcp=')), ''),
        'mac_profile': 'mac=02:11:22:33:44:55|' in out,
        'frida_access_hidden': 'access_frida=-1:2' in out,
        'fortified_open': 'open2=0:0' in out,
        'dirent_hidden': 'frida-server' not in out and 'normal' in out,
        'maps_filtered': 'frida' not in next((l for l in out.splitlines() if l.startswith('maps=')), ''),
        'uname_fake': 'uname=5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058' in out,
    }
    zygote_env = env.copy()
    zygote_env.pop('XENOID_TEST_FORCE_APP_UID', None)
    zygote_env['ANDROID_SOCKET_zygote'] = '7'
    zygote_env['XENOID_TEST_PROFILE_RENAME_TO'] = str(t/'profile-hidden')
    zygote_env['XENOID_TEST_ZYGOTE_CHILD'] = '1'
    zygote_run = subprocess.run([str(exe)], text=True, capture_output=True, env=zygote_env, timeout=10)
    zygote_checks = {
        'zygote_uname_fake': 'uname=5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058' in zygote_run.stdout,
        'zygote_boot_cached': 'boot=profile-boot-id|' in zygote_run.stdout,
        'zygote_mac_cached': 'mac=02:11:22:33:44:55|' in zygote_run.stdout,
    }
    ok = run.returncode == 0 and all(checks.values()) and zygote_run.returncode == 0 and all(zygote_checks.values())
    print(json.dumps({'ok': ok, 'checks': checks, 'zygoteChecks': zygote_checks, 'stdout': out, 'zygoteStdout': zygote_run.stdout, 'stderr': run.stderr + zygote_run.stderr}, indent=2))
    sys.exit(0 if ok else 1)
