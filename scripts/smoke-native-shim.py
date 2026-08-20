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
#ifdef __linux__
#include <sys/vfs.h>
#endif
typedef int (*open_probe_t)(const char*,int);
typedef int (*open2_probe_t)(const char*,int);
typedef int (*access_probe_t)(const char*,int);
typedef long (*sysconf_probe_t)(int);
typedef struct dirent *(*readdir_probe_t)(DIR*);
typedef int (*uname_probe_t)(struct utsname*);
typedef int (*property_get_probe_t)(const char*,char*);
#ifdef __linux__
typedef int (*statfs_probe_t)(const char*,struct statfs*);
#endif
static open_probe_t xopen;
static open2_probe_t xopen2;
static access_probe_t xaccess;
static readdir_probe_t xreaddir;
static uname_probe_t xuname;
static sysconf_probe_t xsysconf;
static property_get_probe_t xprop;
#ifdef __linux__
static statfs_probe_t xstatfs;
#endif
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
  xsysconf = (sysconf_probe_t)dlsym(h, "sysconf");
  xprop = (property_get_probe_t)dlsym(h, "__system_property_get");
  if (!xopen || !xopen2 || !xaccess || !xreaddir || !xuname || !xsysconf || !xprop) { printf("dlsym_error=%s\n", dlerror()); return 3; }
#ifdef __linux__
  xstatfs = (statfs_probe_t)dlsym(h, "statfs");
  if (!xstatfs) { printf("dlsym_error=%s\n", dlerror()); return 3; }
#endif
  dump_file("boot", getenv("XENOID_TEST_BOOT_ID_PATH"));
  dump_file("tcp", getenv("XENOID_TEST_TCP_PATH"));
  dump_file("maps", getenv("XENOID_TEST_MAPS_PATH"));
  dump_file("mounts", getenv("XENOID_TEST_MOUNTS_PATH"));
  dump_file("mac", getenv("XENOID_TEST_MAC_PATH"));
  dump_file("cpu0max", "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
  dump_file("cpu4min", "/sys/devices/system/cpu/cpu4/cpufreq/cpuinfo_min_freq");
  dump_file("cpu6max", "/sys/devices/system/cpu/cpufreq/policy6/scaling_max_freq");
  dump_file("policy4", "/sys/devices/system/cpu/cpufreq/policy4/affected_cpus");
#ifdef _SC_AVPHYS_PAGES
  printf("pages=%ld available=%ld\n", xsysconf(_SC_PHYS_PAGES), xsysconf(_SC_AVPHYS_PAGES));
#else
  printf("pages=%ld available=unsupported\n", xsysconf(_SC_PHYS_PAGES));
#endif
  char crypto_state[96]={0}, crypto_type[96]={0};
  int crypto_state_len=xprop("ro.crypto.state",crypto_state);
  int crypto_type_len=xprop("ro.crypto.type",crypto_type);
  printf("crypto=%d:%s,%d:%s\n",crypto_state_len,crypto_state,crypto_type_len,crypto_type);
  errno=0; printf("access_frida=%d:%d\n", xaccess("/tmp/frida-marker", F_OK), errno);
  errno=0; int open2_fd=xopen2("/dev/null",O_RDONLY); printf("open2=%d:%d\n",open2_fd>=0?0:-1,errno); if(open2_fd>=0) close(open2_fd);
  DIR *d = opendir("/tmp/xenoid-shim-dir");
  if (d) { struct dirent *e; printf("dir="); while ((e=xreaddir(d))) printf("%s,", e->d_name); printf("\n"); closedir(d); }
  struct utsname uts = {0};
  if (xuname(&uts) == 0) printf("uname=%s\n", uts.release);
#ifdef __linux__
  struct statfs fs = {0};
  if (xstatfs(getenv("XENOID_TEST_DATA_PATH"), &fs) == 0)
    printf("data_magic=0x%lx\n", (unsigned long)fs.f_type);
#endif
  return 0;
}
'''
with tempfile.TemporaryDirectory() as td:
    t = pathlib.Path(td)
    marker = t/'frida-marker'
    hidden_dir = t/'xenoid-shim-dir'
    probe_source = source.replace('/tmp/frida-marker', str(marker)).replace('/tmp/xenoid-shim-dir', str(hidden_dir))
    (t/'probe.c').write_text(probe_source)
    prof = t/'profile'; prof.mkdir()
    (prof/'boot_id').write_text('profile-boot-id\n')
    (prof/'cpu_0_maximumFrequencyKhz').write_text('1800000\n')
    (prof/'cpu_4_minimumFrequencyKhz').write_text('400000\n')
    (prof/'cpu_6_maximumFrequencyKhz').write_text('2802000\n')
    (prof/'memory_totalBytes').write_text(str(12 * 1024**3) + '\n')
    (prof/'memory_totalKiB').write_text(str(12 * 1024**2) + '\n')
    (prof/'memory_swapBytes').write_text('0\n')
    (t/'real_boot').write_text('real-boot-id\n')
    (t/'tcp').write_text('  sl  local_address rem_address st\n   0: 00000000:15B3 00000000:0000 0A\n   1: 00000000:1234 00000000:0000 0A\n')
    (t/'maps').write_text('1000-2000 r-xp /data/local/tmp/frida-server\n3000-4000 r-xp /system/lib64/libc.so\n')
    (t/'address').write_text('de:ad:be:ef:00:01\n')
    (t/'reader').mkdir()
    (t/'canonical').mkdir()
    (t/'reader/mounts').write_text('overlay / overlay rw,lowerdir=/var/lib/docker 0 0\n')
    (t/'canonical/mounts').write_text('/dev/block/platform/14700000.ufs/by-name/userdata /data f2fs rw,nosuid,nodev,noatime 0 0\n')
    hidden_dir.mkdir()
    (hidden_dir/'frida-server').write_text('x')
    (hidden_dir/'normal').write_text('x')
    marker.write_text('x')
    shim = t/'libxenoid_shim-host.so'
    build = subprocess.run([CC, '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-DXENOID_HOST_TEST', '-DXENOID_ENABLE_PROPERTY_GET', '-o', str(shim), str(ROOT/'native/xenoid-shim/xenoid_shim.c'), '-ldl'], text=True, capture_output=True)
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
        'XENOID_TEST_MOUNTS_PATH': str(t/'reader/mounts'),
        'XENOID_TEST_CANONICAL_MOUNTS_PATH': str(t/'canonical/mounts'),
        'XENOID_TEST_DATA_PATH': str(t),
        'XENOID_TEST_HIDE_PATH': str(marker),
        'XENOID_TEST_HIDE_DIRENT': 'frida-server',
        'XENOID_TEST_FORCE_APP_UID': '1',
    })
    run = subprocess.run([str(exe)], text=True, capture_output=True, env=env, timeout=10)
    out = run.stdout
    checks = {
        'boot_profile': 'boot=profile-boot-id|' in out,
        'tcp_filtered': ':15B3' not in next((l for l in out.splitlines() if l.startswith('tcp=')), ''),
        'mac_real': 'mac=de:ad:be:ef:00:01|' in out,
        'frida_access_hidden': 'access_frida=-1:2' in out,
        'fortified_open': 'open2=0:0' in out,
        'dirent_hidden': 'frida-server' not in out and 'normal' in out,
        'maps_filtered': 'frida' not in next((l for l in out.splitlines() if l.startswith('maps=')), ''),
        'mount_view_canonical': (
            'mounts=/dev/block/platform/14700000.ufs/by-name/userdata /data f2fs rw,nosuid,nodev,noatime 0 0|' in out
            and 'lowerdir=' not in next(
                (line for line in out.splitlines() if line.startswith('mounts=')), ''
            )
        ),
        'app_crypto_surface': 'crypto=9:encrypted,4:file' in out,
        'uname_fake': 'uname=5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab9012097' in out,
        'cpu0_profile_max': 'cpu0max=1800000|' in out,
        'cpu4_profile_min': 'cpu4min=400000|' in out,
        'cpu6_policy_max': 'cpu6max=2802000|' in out,
        'cpu_policy_members': 'policy4=4 5|' in out,
        'memory_pages': 'pages=3145728 available=' in out,
        'data_magic': sys.platform != 'linux' or 'data_magic=0xf2f52010' in out.lower(),
    }
    privileged_env = env.copy()
    privileged_env.pop('XENOID_TEST_FORCE_APP_UID', None)
    privileged_run = subprocess.run(
        [str(exe)], text=True, capture_output=True, env=privileged_env, timeout=10
    )
    privileged_checks = {
        'privileged_crypto_unmodified': 'crypto=0:,0:' in privileged_run.stdout,
    }
    zygote_env = env.copy()
    zygote_env.pop('XENOID_TEST_FORCE_APP_UID', None)
    zygote_env['ANDROID_SOCKET_zygote'] = '7'
    zygote_env['XENOID_TEST_PROFILE_RENAME_TO'] = str(t/'profile-hidden')
    zygote_env['XENOID_TEST_ZYGOTE_CHILD'] = '1'
    zygote_run = subprocess.run([str(exe)], text=True, capture_output=True, env=zygote_env, timeout=10)
    zygote_checks = {
        'zygote_uname_fake': 'uname=5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab9012097' in zygote_run.stdout,
        'zygote_boot_cached': 'boot=profile-boot-id|' in zygote_run.stdout,
        'zygote_crypto_surface': 'crypto=9:encrypted,4:file' in zygote_run.stdout,
        'zygote_mac_real': 'mac=de:ad:be:ef:00:01|' in zygote_run.stdout,
    }
    ok = (
        run.returncode == 0
        and all(checks.values())
        and privileged_run.returncode == 0
        and all(privileged_checks.values())
        and zygote_run.returncode == 0
        and all(zygote_checks.values())
    )
    print(json.dumps({'ok': ok, 'checks': checks, 'privilegedChecks': privileged_checks, 'zygoteChecks': zygote_checks, 'stdout': out, 'privilegedStdout': privileged_run.stdout, 'zygoteStdout': zygote_run.stdout, 'stderr': run.stderr + privileged_run.stderr + zygote_run.stderr}, indent=2))
    sys.exit(0 if ok else 1)
