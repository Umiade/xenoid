#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ADB_TARGET="$(python3 - <<'PY'
import os, sys
sys.path.insert(0, 'src')
from pathlib import Path
from xenoid.config import resolve_instance
name = os.environ.get('XENOID_INSTANCE') or 'default'
try:
    context, cfg, lease = resolve_instance(name, project_root=Path.cwd(), env={})
    print(f"127.0.0.1:{lease.host_adb_port}")
except Exception:
    print('127.0.0.1:5555')
PY
)"
ADB_BIN="$(python3 - <<'PY'
import sys; sys.path.insert(0, 'src')
from xenoid.util import which
print(which('adb') or 'adb')
PY
)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
# Runtime ABI → toolchain + shim binary
RUNTIME_ABI="$("$ADB_BIN" -s "$ADB_TARGET" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' || true)"
case "$RUNTIME_ABI" in
  *arm64*|*aarch64*) ARCH=arm64; TOOL=aarch64-linux-android21-clang; SHIM="native/xenoid-shim/libxenoid_shim-arm64.so" ;;
  *) ARCH=x86_64; TOOL=x86_64-linux-android21-clang; SHIM="native/xenoid-shim/libxenoid_shim-x86_64.so" ;;
esac
BIN=""
for ndk in "$SDK"/ndk/*; do for pre in darwin-x86_64 darwin-arm64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
[[ -n "$BIN" ]] || { echo "{\"ok\":false,\"error\":\"$TOOL clang not found\"}"; exit 1; }
TMP=/tmp/xenoid-native-surfaces
rm -rf "$TMP"; mkdir -p "$TMP"
cat > "$TMP/surfaces.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>
static int bad=0;
static void check(int cond, const char*name, const char*detail){ printf("%s=%s %s\n",name,cond?"ok":"bad",detail?detail:""); if(!cond) bad=1; }
static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data){ (void)size; (void)data; const char*n=info->dlpi_name?info->dlpi_name:""; if(strstr(n,"xenoid")||strstr(n,"frida")||strstr(n,"shim")||strstr(n,".fs64")) bad=1; return 0; }
int main(){
  void*h1=dlopen("/apex/com.android.runtime/lib64/bionic/libm.so",RTLD_NOW);
  void*h2=dlopen("/data/system/.core/svc.bin",RTLD_NOW);
  check(h1!=0,"dlopen_normal","libm"); check(h2==0,"dlopen_hidden","frida"); if(h1)dlclose(h1); if(h2)dlclose(h2);
  dl_iterate_phdr(phdr_cb,0); check(!bad,"dl_iterate_phdr","no hidden libs");
  prctl(PR_SET_NAME,"gmain",0,0,0); char nm[16]={0}; prctl(PR_GET_NAME,nm,0,0,0); check(strcmp(nm,"main")==0,"prctl_name",nm);
  check(sysconf(_SC_NPROCESSORS_CONF)==8 && sysconf(_SC_NPROCESSORS_ONLN)==8,"sysconf_cpu","8");
  check(sysconf(_SC_PHYS_PAGES)==2031616,"sysconf_pages","7.75GB");
  unsigned long p=getauxval(AT_PLATFORM); check(p && strcmp((char*)p,"aarch64")==0,"getauxval_platform",p?(char*)p:"null");
  return bad?1:0;
}
C
"$BIN" -O2 -Wall -Wextra -o "$TMP/surfaces" "$TMP/surfaces.c" -ldl
"$ADB_BIN" connect "$ADB_TARGET" >/dev/null 2>&1 || true
"$ADB_BIN" -s "$ADB_TARGET" push "$TMP/surfaces" /data/local/tmp/xenoid-surfaces-smoke >/dev/null
"$ADB_BIN" -s "$ADB_TARGET" push "$SHIM" /data/local/tmp/.ld/core.so >/dev/null
OUT=$("$ADB_BIN" -s "$ADB_TARGET" shell 'chmod 755 /data/local/tmp/xenoid-surfaces-smoke /data/local/tmp/.ld/core.so; XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so /data/local/tmp/xenoid-surfaces-smoke' 2>&1) || { printf '{"ok":false,"stdout":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$OUT")"; exit 1; }
if echo "$OUT" | grep -q '=bad'; then printf '{"ok":false,"stdout":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$OUT")"; exit 1; fi
# Validate recent proc/fd/thread filters against the renamed Frida helper when present.
PROC_OUT=$("$ADB_BIN" -s "$ADB_TARGET" shell 'pid=$(pidof .fs64 || true); if [ -n "$pid" ]; then   bad=0;   for f in /proc/$pid/task/*/comm; do XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so cat $f 2>/dev/null; done | grep -Eiq "gmain|gdbus|fs64|frida|xenoid" && bad=1;   XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so cat /proc/$pid/fdinfo/10 2>/dev/null | grep -Eiq "eventfd|tfd|scm|ino:[[:space:]]*[1-9]" && bad=1;   XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so cat /proc/$pid/net/tcp /proc/$pid/net/tcp6 2>/dev/null | grep -Eiq "15B3|69A2|69A3|494D|494F|90ED|frida|xenoid" && bad=1;   if [ "$bad" = 0 ]; then echo proc_surfaces=ok; else echo proc_surfaces=bad; exit 1; fi; else echo proc_surfaces=skipped_no_fs64; fi' 2>&1) || { OUT="$OUT
$PROC_OUT"; printf '{"ok":false,"stdout":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$OUT")"; exit 1; }
OUT="$OUT
$PROC_OUT"
FILE_OUT=$("$ADB_BIN" -s "$ADB_TARGET" shell 'bad=0; grep -Eiq "redroid|userdebug|test-keys|x86_64" /system/build.prop /vendor/build.prop /system/product/etc/build.prop /system/system_ext/etc/build.prop /vendor/odm/etc/build.prop 2>/dev/null && bad=1; grep -Eiq "AuthenticAMD|EPYC|x86_64|Ubuntu|BOOT_IMAGE|vmlinuz" /proc/cpuinfo /proc/version /proc/cmdline 2>/dev/null && bad=1; grep -Eiq "vda|vdb|virtio|PCI|QEMU|xen|kvm|amd" /proc/diskstats /proc/partitions 2>/dev/null && bad=1; XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so ls /sys/block 2>/dev/null | grep -Eiq "vda|vdb|virtio" && bad=1; XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so cat /sys/class/dmi/id/product_name 2>/dev/null | grep -Eiq "OpenStack|KVM|QEMU" && bad=1; XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so cat /proc/interrupts /proc/iomem /proc/ioports /proc/kallsyms 2>/dev/null | grep -Eiq "virtio|PCI|QEMU|xen|kvm|amd|vbox|vmw" && bad=1; if [ "$bad" = 0 ]; then echo file_sys_surfaces=ok; else echo file_sys_surfaces=bad; exit 1; fi' 2>&1) || { OUT="$OUT
$FILE_OUT"; printf '{"ok":false,"stdout":%s}
' "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$OUT")"; exit 1; }
OUT="$OUT
$FILE_OUT"
printf '{"ok":true,"stdout":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$OUT")"
