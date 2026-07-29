#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif
#include <sys/stat.h>
#include <unistd.h>

#define OVERLAY_DIR "/xenoid/overlay.d"
#define PROFILE_DIR "/data/local/tmp/xenoid-profile"

static int ensure_dir(const char *p) { return mkdir(p, 0777) == 0 || errno == EEXIST ? 0 : -1; }
static char *read_all(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return strdup("");
  size_t cap = 65536, n = 0; char *b = calloc(1, cap + 1);
  if (!b) { close(fd); return strdup(""); }
  for (;;) {
    if (n + 4096 >= cap) { cap *= 2; char *nb = realloc(b, cap + 1); if (!nb) break; b = nb; }
    ssize_t r = read(fd, b + n, 4096); if (r <= 0) break; n += (size_t)r;
  }
  close(fd); b[n] = 0; return b;
}
static int write_bytes(const char *path, const void *data, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) return -1;
  ssize_t w = write(fd, data, n); close(fd); chmod(path, 0644); return w == (ssize_t)n ? 0 : -1;
}
static int write_text(const char *path, const char *s) {
  return write_bytes(path, s, strlen(s));
}
static char *first_or_default(const char *path, const char *fallback) {
  char *s = read_all(path); if (!s || !s[0]) { free(s); return strdup(fallback); }
  size_t n = strcspn(s, "\r\n"); char *o = calloc(1, n + 2); if (!o) { free(s); return strdup(fallback); }
  memcpy(o, s, n); o[n] = '\n'; o[n+1] = 0; free(s); return o;
}



static char *read_mountinfo_limited(void) {
  int fd=open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC); if(fd<0) return strdup("");
  size_t cap=1<<20, n=0; char *b=calloc(1,cap+1); if(!b){close(fd); return strdup("");}
  /* Read to EOF with a growing buffer: a 1 MiB cap silently truncated large
     mount tables and made count_in_mountinfo return 0 for mounted targets,
     which led apply() to stack duplicate bind mounts (~98k after repeats). */
  for(;;){ if(n==cap){ cap*=2; char *nb=realloc(b,cap+1); if(!nb){break;} b=nb; } ssize_t r=read(fd,b+n,cap-n); if(r<=0) break; n+=(size_t)r; }
  close(fd); b[n]=0; return b;
}

static const char *overlay_targets[] = {
  "/vendor/odm_dlkm/etc/build.prop", "/vendor/vendor_dlkm/etc/build.prop", "/vendor/odm/etc/build.prop",
  "/system/system_dlkm/etc/build.prop", "/system/system_ext/etc/build.prop", "/system/product/etc/build.prop",
  "/vendor/build.prop", "/system/build.prop",
  "/sys/block/vdb/queue/rotational", "/sys/block/vda/queue/rotational", "/sys/block/vdb/size", "/sys/block/vda/size",
  "/proc/partitions", "/proc/diskstats", "/proc/modules", "/proc/interrupts", "/proc/iomem", "/proc/ioports", "/proc/kallsyms",
  "/proc/devices", "/proc/misc", "/proc/tty/drivers",
  "/sys/class/rtc/rtc0/name", "/sys/class/rtc/rtc0/hctosys",
  "/sys/devices/system/cpu/present", "/sys/devices/system/cpu/possible", "/sys/devices/system/cpu/online",
  "/sys/devices/system/cpu/cpu0/topology/core_id", "/sys/devices/system/cpu/cpu0/topology/physical_package_id",
  "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", "/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
  "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq",
  "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
  "/sys/devices/system/cpu/cpu7/topology/core_id", "/sys/devices/system/cpu/cpu7/cpufreq/cpuinfo_max_freq",
  "/sys/devices/system/cpu/cpu0", "/sys/devices/system/cpu/cpu1",
  "/sys/devices/system/cpu/cpu2", "/sys/devices/system/cpu/cpu3",
  "/sys/devices/system/cpu/cpu4", "/sys/devices/system/cpu/cpu5",
  "/sys/devices/system/cpu/cpu6", "/sys/devices/system/cpu/cpu7",
  "/proc/filesystems", "/proc/swaps",
  "/proc/cgroups", "/proc/1/status", "/proc/1/uid_map", "/proc/1/gid_map", "/proc/1/attr/current",
  "/proc/1/cgroup", "/proc/1/mounts", "/proc/1/mountinfo", "/proc/1/mountstats",
  /* Reader-relative procfs paths are handled in the process view rather than
     by fixed-path bind mounts. This includes /proc/{self,net}. */
  "/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/version",
  "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict", "/proc/sys/kernel/perf_event_paranoid",
  "/proc/sys/kernel/modules_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/kernel/yama/ptrace_scope",
  "/proc/cmdline", "/proc/version", "/proc/cpuinfo", "/proc/bus/input/devices", "/proc/fb",
  "/sys/class/net/eth0/address", "/sys/class/net/eth0/type", "/sys/class/net/eth0/mtu", "/sys/class/net/eth0/operstate",
  "/sys/class/net/eth0/carrier", "/sys/class/net/eth0/addr_assign_type", "/sys/class/net/eth0/iflink", "/sys/class/net/eth0/ifindex",
  "/proc/sys/kernel/random/boot_id",
  "/proc/sys/kernel/random/uuid", "/proc/sys/kernel/random/entropy_avail", "/proc/sys/kernel/random/poolsize", "/proc/sys/kernel/random/urandom_min_reseed_secs",
  "/sys/class/graphics/fb0/name", "/sys/class/graphics/fb0/virtual_size", "/sys/class/graphics/fb0/bits_per_pixel", "/sys/class/graphics/fb0/modes",
  "/sys/class/backlight/panel0-backlight/brightness", "/sys/class/backlight/panel0-backlight/max_brightness",
  "/sys/class/backlight/panel0-backlight/actual_brightness", "/sys/class/backlight/panel0-backlight/type",
  "/sys/class/leds/vibrator/brightness", "/sys/class/leds/vibrator/max_brightness",
  "/sys/class/leds/white:flash/brightness", "/sys/class/leds/white:flash/max_brightness",
  "/sys/class/leds/lcd-backlight/brightness", "/sys/class/leds/lcd-backlight/max_brightness",
  "/config/usb_gadget/g1/strings/0x409/serialnumber", "/config/usb_gadget/g1/strings/0x409/manufacturer",
  "/config/usb_gadget/g1/strings/0x409/product", "/config/usb_gadget/g1/idVendor", "/config/usb_gadget/g1/idProduct",
  "/sys/class/android_usb/android0/iSerial", "/sys/class/android_usb/android0/iManufacturer", "/sys/class/android_usb/android0/iProduct",
  "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/board_name",
  "/proc/device-tree/model", "/proc/device-tree/compatible", "/proc/device-tree/name", "/proc/device-tree/serial-number", "/proc/device-tree/chosen/bootargs",
  "/sys/firmware/devicetree/base/model", "/sys/firmware/devicetree/base/compatible", "/sys/firmware/devicetree/base/name",
  "/sys/firmware/devicetree/base/serial-number", "/sys/firmware/devicetree/base/chosen/bootargs",
  "/sys/kernel/debug/tracing/available_filter_functions", "/sys/kernel/debug/tracing/enabled_functions", "/sys/kernel/debug/tracing/kprobe_events",
  "/sys/kernel/debug/tracing/uprobe_events", "/sys/kernel/debug/tracing/trace", "/sys/kernel/tracing/available_filter_functions",
  "/sys/kernel/tracing/enabled_functions", "/sys/kernel/tracing/kprobe_events", "/sys/kernel/tracing/uprobe_events", "/sys/kernel/tracing/trace",
  "/sys/fs/selinux/enforce", "/sys/fs/selinux/policyvers", "/sys/fs/selinux/mls",
  "/sys/devices/virtual/dmi/id/product_name", "/sys/devices/virtual/dmi/id/sys_vendor", "/sys/hypervisor/type",
  "/etc/hosts", "/proc/sys/kernel/hostname", "/proc/sys/kernel/domainname", "/proc/sys/kernel/tainted",
  "/sys/class/power_supply/battery/capacity", "/sys/class/power_supply/battery/status",
  "/sys/class/power_supply/battery/health", "/sys/class/power_supply/battery/present",
  "/sys/class/power_supply/battery/temp", "/sys/class/power_supply/battery/voltage_now",
  "/sys/class/power_supply/battery/technology", "/sys/class/power_supply/battery/capacity_level",
  "/sys/class/power_supply/usb/online", "/sys/class/power_supply/ac/online", "/sys/class/power_supply/wireless/online",
  "/sys/class/thermal/thermal_zone0/temp", "/sys/class/thermal/thermal_zone0/type",
  "/sys/class/thermal/thermal_zone1/temp", "/sys/class/thermal/thermal_zone1/type",
  "/sys/class/thermal/thermal_zone2/temp", "/sys/class/thermal/thermal_zone2/type",
  "/sys/class/thermal/thermal_zone3/temp", "/sys/class/thermal/thermal_zone3/type",
  "/sys/class/thermal/thermal_zone4/temp", "/sys/class/thermal/thermal_zone4/type",
  "/sys/class/thermal/thermal_zone5/temp", "/sys/class/thermal/thermal_zone5/type",
  "/sys/class/thermal/thermal_zone6/temp", "/sys/class/thermal/thermal_zone6/type",
  "/sys/class/thermal/thermal_zone7/temp", "/sys/class/thermal/thermal_zone7/type",
  "/sys/class/thermal/thermal_zone8/temp", "/sys/class/thermal/thermal_zone8/type",
  "/sys/class/thermal/thermal_zone9/temp", "/sys/class/thermal/thermal_zone9/type",
  NULL
};
static const char *deprecated_dynamic_targets[] = {
  "/proc/driver/rtc",
  "/sys/class/rtc/rtc0/date", "/sys/class/rtc/rtc0/time", "/sys/class/rtc/rtc0/since_epoch",
  "/proc/meminfo", "/proc/vmstat", "/proc/zoneinfo", "/proc/buddyinfo", "/proc/pagetypeinfo",
  "/proc/stat", "/proc/softirqs", "/proc/schedstat", "/proc/uptime", "/proc/loadavg",
  NULL
};
static int count_in_mountinfo(const char *mi, const char *target) {
  if(!mi || !target) return 0;
  char pat[512]; snprintf(pat,sizeof(pat)," %s ",target);
  int count=0; const char *p=mi;
  while((p=strstr(p,pat))){ count++; p += strlen(pat); }
  return count;
}
static int marker_mounted(const char *target);
static int resolve_overlay_target(const char *target, char *resolved, size_t n) {
  /* /proc/net and /proc/self resolve to /proc/<pid>/...; mounting the pid path
     dies with that process and leaves permanent stale markers. Only resolve
     stable sysfs class symlinks onto /sys/devices/... */
  if (!target || strncmp(target, "/sys/", 5) != 0) return 0;
  if (!realpath(target, resolved)) return 0;
  if (strlen(resolved) >= n) return 0;
  return 1;
}

static int status_json(void) {
  char *mi=read_mountinfo_limited();
  int expected_count=0, active_count=0, missing=0, duplicates=0;
  for(int i=0; overlay_targets[i]; i++){
    char resolved[PATH_MAX];
    const char *t = resolve_overlay_target(overlay_targets[i], resolved, sizeof(resolved)) ? resolved : overlay_targets[i];
    int c=count_in_mountinfo(mi, t);
    int expected=marker_mounted(t) || (t != overlay_targets[i] && marker_mounted(overlay_targets[i]));
    if(expected){ expected_count++; if(c>0) active_count++; else missing++; }
    if(c>1) duplicates++;
  }
  int ok=expected_count>0 && missing==0 && duplicates==0;
  printf("{\"ok\":%s,\"expectedCount\":%d,\"activeCount\":%d,\"missingCount\":%d,\"duplicateCount\":%d,\"targets\":[",
         ok?"true":"false", expected_count, active_count, missing, duplicates);
  for(int i=0; overlay_targets[i]; i++){
    if(i) printf(",");
    char resolved[PATH_MAX];
    const char *t = resolve_overlay_target(overlay_targets[i], resolved, sizeof(resolved)) ? resolved : overlay_targets[i];
    int c=count_in_mountinfo(mi, t);
    int expected=marker_mounted(t) || (t != overlay_targets[i] && marker_mounted(overlay_targets[i]));
    printf("{\"target\":\"%s\",\"mountCount\":%d,\"overlay\":%s,\"expected\":%s}",
           overlay_targets[i], c, c>0?"true":"false", expected?"true":"false");
  }
  free(mi); printf("]}\n"); return ok?0:1;
}
static void unmark_mounted(const char *target);
static int cleanup_legacy_cpu_detail_mounts(const char *mi) {
  static const char *leaves[] = {
    "topology/core_id", "topology/physical_package_id",
    "topology/thread_siblings_list", "topology/core_siblings_list",
    "cpufreq/cpuinfo_max_freq", "cpufreq/cpuinfo_min_freq",
    "cpufreq/scaling_cur_freq", "cpufreq/scaling_governor",
    NULL
  };
  int fail = 0;
  for (int cpu = 0; cpu < 8; cpu++) {
    for (int i = 0; leaves[i]; i++) {
      char target[PATH_MAX];
      snprintf(target, sizeof(target), "/sys/devices/system/cpu/cpu%d/%s", cpu, leaves[i]);
      int count = count_in_mountinfo(mi, target);
      while (count-- > 0) {
        if (umount2(target, MNT_DETACH) && errno != EINVAL) fail++;
      }
      unmark_mounted(target);
    }
  }
  return fail;
}
static int cleanup(void) {
  int fail=0;
  char *mi=read_mountinfo_limited();
  fail += cleanup_legacy_cpu_detail_mounts(mi);
  for(int i=0; overlay_targets[i]; i++){
    char resolved[PATH_MAX];
    const char *t = resolve_overlay_target(overlay_targets[i], resolved, sizeof(resolved)) ? resolved : overlay_targets[i];
    int c=count_in_mountinfo(mi, t);
    while(c-- > 0){ if(umount2(t, MNT_DETACH) && errno != EINVAL) fail++; } unmark_mounted(t);
  }
  for(int i=0; deprecated_dynamic_targets[i]; i++){
    char resolved[PATH_MAX];
    const char *t = resolve_overlay_target(deprecated_dynamic_targets[i], resolved, sizeof(resolved)) ? resolved : deprecated_dynamic_targets[i];
    int c=count_in_mountinfo(mi, t);
    while(c-- > 0){ if(umount2(t, MNT_DETACH) && errno != EINVAL) fail++; } unmark_mounted(t);
  }
  free(mi); printf("{\"ok\":%s,\"fail\":%d}\n", fail?"false":"true", fail); return fail?1:0;
}

static int target_mounted(const char *target) {
  char *mi = read_mountinfo_limited();
  if (!mi || !mi[0]) { free(mi); return 0; }
  char pat[512]; snprintf(pat, sizeof(pat), " %s ", target);
  int found = strstr(mi, pat) != NULL;
  free(mi); return found;
}

static void target_marker_path(const char *target, char *out, size_t n) {
  size_t j = 0;
  snprintf(out, n, "%s/.mounted_", OVERLAY_DIR);
  j = strlen(out);
  for (const char *p = target; *p && j + 2 < n; ++p) {
    char c = *p;
    out[j++] = (c == '/' || c == ' ' || c == '\t') ? '_' : c;
  }
  out[j] = 0;
}
static int marker_mounted(const char *target) {
  char m[512]; target_marker_path(target, m, sizeof(m));
  return access(m, F_OK) == 0;
}
static void mark_mounted(const char *target) {
  char m[512]; target_marker_path(target, m, sizeof(m));
  write_text(m, "1\n");
}
static void unmark_mounted(const char *target) {
  char m[512]; target_marker_path(target, m, sizeof(m));
  unlink(m);
}

static int bind_file(const char *fake, const char *target) {
  /* Canonicalize symlinked sysfs targets (class/net/eth0 -> devices/virtual/net/eth0):
     mountinfo records the resolved path. */
  char resolved[PATH_MAX];
  const char *t = resolve_overlay_target(target, resolved, sizeof(resolved)) ? resolved : target;
  if (target_mounted(t)) {
    mark_mounted(t);
    return 0;
  }
  /* Markers persist on /data across container recreate / sysfs node replace.
     Never treat a marker alone as "already mounted". */
  unmark_mounted(t);
  if (t != target) unmark_mounted(target);
  /* /proc/net -> self/net: plain MS_BIND follows the symlink onto a pid-local
     dentry that vanishes with the helper. Prefer NOSYMFOLLOW for /proc paths. */
  unsigned long flags = MS_BIND;
  if (strncmp(t, "/proc/", 6) == 0) flags |= MS_NOSYMFOLLOW;
  if (mount(fake, t, NULL, flags, NULL) == 0) {
    /* Stop shared-peer-group propagation: /data on redroid sits in a shared
       group, and a bind without MS_PRIVATE propagates into thousands of peer
       mounts (observed 4096 stacked copies per target). */
    mount(NULL, t, NULL, MS_PRIVATE, NULL);
    mark_mounted(t); return 0;
  }
  return -1;
}

static int overlay_text(const char *name, const char *target, const char *content) {
  char fake[256]; snprintf(fake, sizeof(fake), "%s/%s", OVERLAY_DIR, name);
  int rc = write_text(fake, content); if (rc) return -1;
  return bind_file(fake, target);
}
static int overlay_bytes_optional(const char *name, const char *target, const void *content, size_t size) {
  if (access(target, F_OK) != 0) return 0;
  char fake[256]; snprintf(fake, sizeof(fake), "%s/%s", OVERLAY_DIR, name);
  int rc = write_bytes(fake, content, size); if (rc) return -1;
  return bind_file(fake, target);
}
static int overlay_text_optional(const char *name, const char *target, const char *content) {
  if (access(target, F_OK) != 0) return 0;
  return overlay_text(name, target, content);
}
static long read_long_default(const char *path, long fallback) {
  char *s = first_or_default(path, "");
  char *e = NULL; long v = strtol(s, &e, 10);
  free(s); return e && e != s ? v : fallback;
}
static void long_line(char *buf, size_t n, long v) { snprintf(buf, n, "%ld\n", v); }
static const char *battery_status_text(long status, long plugged) {
  if (status == 5) return "Full\n";
  if (status == 2 || plugged > 0) return "Charging\n";
  if (status == 3) return "Discharging\n";
  if (status == 4) return "Not charging\n";
  return "Discharging\n";
}
static const char *battery_health_text(long health) {
  if (health == 2) return "Good\n";
  if (health == 3) return "Overheat\n";
  if (health == 4) return "Dead\n";
  if (health == 5) return "Over voltage\n";
  return "Good\n";
}




static const char *system_build_prop_text(void) {
  return "ro.product.system.brand=google\n"
         "ro.product.system.device=raven\n"
         "ro.product.system.manufacturer=Google\n"
         "ro.product.system.model=Pixel 6 Pro\n"
         "ro.product.system.name=raven\n"
         "ro.system.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\n"
         "ro.system.product.cpu.abilist64=arm64-v8a\n"
         "ro.system.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\n"
         "ro.system.build.tags=release-keys\n"
         "ro.system.build.type=user\n"
         "ro.build.display.id=TP1A.221005.002\n"
         "ro.build.version.security_patch=2022-10-05\n"
         "ro.build.type=user\n"
         "ro.build.tags=release-keys\n"
         "ro.build.flavor=raven-user\n"
         "ro.product.cpu.abi=arm64-v8a\n"
         "ro.product.locale=en-US\n"
         "ro.build.product=raven\n"
         "ro.build.description=raven-user 13 TP1A.221005.002 8977058 release-keys\n"
         "ro.debuggable=0\n"
         "ro.secure=1\n"
         "ro.crypto.state=encrypted\n"
         "ro.adb.secure=1\n";
}
static const char *vendor_build_prop_text(void) {
  return "ro.product.vendor.brand=google\n"
         "ro.product.vendor.device=raven\n"
         "ro.product.vendor.manufacturer=Google\n"
         "ro.product.vendor.model=Pixel 6 Pro\n"
         "ro.product.vendor.name=raven\n"
         "ro.vendor.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\n"
         "ro.vendor.product.cpu.abilist64=arm64-v8a\n"
         "ro.vendor.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\n"
         "ro.vendor.build.tags=release-keys\n"
         "ro.vendor.build.type=user\n"
         "ro.vendor.build.security_patch=2022-10-05\n"
         "ro.hardware=tensor\n"
         "ro.bionic.arch=arm64\n"
         "dalvik.vm.isa.arm64.variant=cortex-a76\n"
         "dalvik.vm.isa.arm64.features=default\n"
         "ro.product.first_api_level=33\n"
         "ro.product.debugfs_restrictions.enabled=true\n"
         "ro.product.board=raven\n";
}
static int overlay_build_props(void) {
  int fail = 0;
  fail += overlay_text("system_build.prop", "/system/build.prop", system_build_prop_text()) != 0;
  fail += overlay_text("vendor_build.prop", "/vendor/build.prop", vendor_build_prop_text()) != 0;
  return fail ? -1 : 0;
}


static int overlay_extra_build_props(void) {
  int fail = 0;
  const char *product =
    "ro.product.product.brand=google\nro.product.product.device=raven\nro.product.product.manufacturer=Google\nro.product.product.model=Pixel 6 Pro\nro.product.product.name=raven\nro.product.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.product.build.tags=release-keys\nro.product.build.type=user\nro.product.vndk.version=33\n";
  const char *system_ext =
    "ro.product.system_ext.brand=google\nro.product.system_ext.device=raven\nro.product.system_ext.manufacturer=Google\nro.product.system_ext.model=Pixel 6 Pro\nro.product.system_ext.name=raven\nro.system_ext.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.system_ext.build.tags=release-keys\nro.system_ext.build.type=user\n";
  const char *system_dlkm =
    "ro.product.system_dlkm.brand=google\nro.product.system_dlkm.device=raven\nro.product.system_dlkm.manufacturer=Google\nro.product.system_dlkm.model=Pixel 6 Pro\nro.product.system_dlkm.name=raven\nro.system_dlkm.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.system_dlkm.build.tags=release-keys\nro.system_dlkm.build.type=user\n";
  const char *odm =
    "ro.product.odm.brand=google\nro.product.odm.device=raven\nro.product.odm.manufacturer=Google\nro.product.odm.model=Pixel 6 Pro\nro.product.odm.name=raven\nro.odm.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\nro.odm.product.cpu.abilist64=arm64-v8a\nro.odm.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.odm.build.tags=release-keys\nro.odm.build.type=user\n";
  const char *vendor_dlkm =
    "ro.product.vendor_dlkm.brand=google\nro.product.vendor_dlkm.device=raven\nro.product.vendor_dlkm.manufacturer=Google\nro.product.vendor_dlkm.model=Pixel 6 Pro\nro.product.vendor_dlkm.name=raven\nro.vendor_dlkm.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.vendor_dlkm.build.tags=release-keys\nro.vendor_dlkm.build.type=user\n";
  const char *odm_dlkm =
    "ro.product.odm_dlkm.brand=google\nro.product.odm_dlkm.device=raven\nro.product.odm_dlkm.manufacturer=Google\nro.product.odm_dlkm.model=Pixel 6 Pro\nro.product.odm_dlkm.name=raven\nro.odm_dlkm.build.fingerprint=google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys\nro.odm_dlkm.build.tags=release-keys\nro.odm_dlkm.build.type=user\n";
  fail += overlay_text("product_build.prop", "/system/product/etc/build.prop", product) != 0;
  fail += overlay_text("system_ext_build.prop", "/system/system_ext/etc/build.prop", system_ext) != 0;
  fail += overlay_text("system_dlkm_build.prop", "/system/system_dlkm/etc/build.prop", system_dlkm) != 0;
  fail += overlay_text("odm_build.prop", "/vendor/odm/etc/build.prop", odm) != 0;
  fail += overlay_text("vendor_dlkm_build.prop", "/vendor/vendor_dlkm/etc/build.prop", vendor_dlkm) != 0;
  fail += overlay_text("odm_dlkm_build.prop", "/vendor/odm_dlkm/etc/build.prop", odm_dlkm) != 0;
  return fail ? -1 : 0;
}


static int overlay_power_supply(void) {
  int fail = 0;
  char buf[64];
  long level = read_long_default(PROFILE_DIR "/battery_level", 83);
  long temp = read_long_default(PROFILE_DIR "/battery_temperature", 310);
  long voltage = read_long_default(PROFILE_DIR "/battery_voltage", 4100);
  long status = read_long_default(PROFILE_DIR "/battery_status", 2);
  long plugged = read_long_default(PROFILE_DIR "/battery_plugged", 0);
  long health = read_long_default(PROFILE_DIR "/battery_health", 2);
  long present = read_long_default(PROFILE_DIR "/battery_present", 1);
  if (voltage > 0 && voltage < 100000) voltage *= 1000;
  if (level < 0) level = 0; if (level > 100) level = 100;
  long_line(buf, sizeof(buf), level); fail += overlay_text_optional("battery_capacity", "/sys/class/power_supply/battery/capacity", buf) != 0;
  long_line(buf, sizeof(buf), temp); fail += overlay_text_optional("battery_temp", "/sys/class/power_supply/battery/temp", buf) != 0;
  long_line(buf, sizeof(buf), voltage); fail += overlay_text_optional("battery_voltage_now", "/sys/class/power_supply/battery/voltage_now", buf) != 0;
  long_line(buf, sizeof(buf), present); fail += overlay_text_optional("battery_present", "/sys/class/power_supply/battery/present", buf) != 0;
  fail += overlay_text_optional("battery_status", "/sys/class/power_supply/battery/status", battery_status_text(status, plugged)) != 0;
  fail += overlay_text_optional("battery_health", "/sys/class/power_supply/battery/health", battery_health_text(health)) != 0;
  fail += overlay_text_optional("battery_technology", "/sys/class/power_supply/battery/technology", "Li-ion\n") != 0;
  fail += overlay_text_optional("battery_capacity_level", "/sys/class/power_supply/battery/capacity_level", level >= 95 ? "Full\n" : (level <= 15 ? "Low\n" : "Normal\n")) != 0;
  long ac = plugged == 1 ? 1 : 0, usb = plugged == 2 ? 1 : 0, wireless = plugged == 4 ? 1 : 0;
  long_line(buf, sizeof(buf), usb); fail += overlay_text_optional("usb_online", "/sys/class/power_supply/usb/online", buf) != 0;
  long_line(buf, sizeof(buf), ac); fail += overlay_text_optional("ac_online", "/sys/class/power_supply/ac/online", buf) != 0;
  long_line(buf, sizeof(buf), wireless); fail += overlay_text_optional("wireless_online", "/sys/class/power_supply/wireless/online", buf) != 0;
  return fail ? -1 : 0;
}

static const char *thermal_type_default(int i) {
  static const char *types[] = {"skin", "battery", "cpu-0", "cpu-1", "gpu", "modem", "quiet-therm", "usb-therm", "xo-therm", "pa-therm"};
  return (i >= 0 && i < 10) ? types[i] : "skin";
}
static long thermal_temp_default(int i) {
  static const long temps[] = {32000, 31000, 36000, 35500, 34000, 33000, 30000, 30500, 31500, 32500};
  return (i >= 0 && i < 10) ? temps[i] : 32000;
}
static int overlay_thermal_zones(void) {
  int fail = 0;
  for (int i = 0; i < 10; i++) {
    char target[128], name[64], profile_key[128], buf[128];
    snprintf(target, sizeof(target), "/sys/class/thermal/thermal_zone%d/temp", i);
    snprintf(name, sizeof(name), "thermal_zone%d_temp", i);
    snprintf(profile_key, sizeof(profile_key), PROFILE_DIR "/thermal_zone%d_temp", i);
    long temp = read_long_default(profile_key, thermal_temp_default(i));
    if (temp > 0 && temp < 1000) temp *= 1000;
    long_line(buf, sizeof(buf), temp);
    fail += overlay_text_optional(name, target, buf) != 0;
    snprintf(target, sizeof(target), "/sys/class/thermal/thermal_zone%d/type", i);
    snprintf(name, sizeof(name), "thermal_zone%d_type", i);
    snprintf(profile_key, sizeof(profile_key), PROFILE_DIR "/thermal_zone%d_type", i);
    char *type = first_or_default(profile_key, "");
    if (!type || !type[0] || type[0] == '\n') {
      free(type);
      snprintf(buf, sizeof(buf), "%s\n", thermal_type_default(i));
      fail += overlay_text_optional(name, target, buf) != 0;
    } else {
      fail += overlay_text_optional(name, target, type) != 0;
      free(type);
    }
  }
  return fail ? -1 : 0;
}


static int overlay_network_identity_files(void) {
  int fail = 0;
  // Keep only files that exist reliably in redroid; binding over absent /etc/hostname or /etc/resolv.conf is noisy.
  fail += overlay_text("etc_hosts", "/etc/hosts", "127.0.0.1       localhost\n::1             ip6-localhost\n") != 0;
  fail += overlay_text("kernel_hostname", "/proc/sys/kernel/hostname", "localhost\n") != 0;
  fail += overlay_text("kernel_domainname", "/proc/sys/kernel/domainname", "localdomain\n") != 0;
  fail += overlay_text("kernel_tainted", "/proc/sys/kernel/tainted", "0\n") != 0;
  return fail ? -1 : 0;
}
static int overlay_usb_identity(void) {
  int fail = 0;
  char *serial = first_or_default(PROFILE_DIR "/serial", "3A4940E5EDFA\n");
  char *manufacturer = first_or_default(PROFILE_DIR "/usb_manufacturer", "Google\n");
  char *product = first_or_default(PROFILE_DIR "/usb_product", "Pixel 6 Pro\n");
  char *vendor = first_or_default(PROFILE_DIR "/usb_vendor_id", "0x18d1\n");
  char *product_id = first_or_default(PROFILE_DIR "/usb_product_id", "0x4ee7\n");
  fail += overlay_text_optional("usb_gadget_serial", "/config/usb_gadget/g1/strings/0x409/serialnumber", serial) != 0;
  fail += overlay_text_optional("usb_gadget_manufacturer", "/config/usb_gadget/g1/strings/0x409/manufacturer", manufacturer) != 0;
  fail += overlay_text_optional("usb_gadget_product", "/config/usb_gadget/g1/strings/0x409/product", product) != 0;
  fail += overlay_text_optional("usb_gadget_idVendor", "/config/usb_gadget/g1/idVendor", vendor) != 0;
  fail += overlay_text_optional("usb_gadget_idProduct", "/config/usb_gadget/g1/idProduct", product_id) != 0;
  fail += overlay_text_optional("android_usb_iSerial", "/sys/class/android_usb/android0/iSerial", serial) != 0;
  fail += overlay_text_optional("android_usb_iManufacturer", "/sys/class/android_usb/android0/iManufacturer", manufacturer) != 0;
  fail += overlay_text_optional("android_usb_iProduct", "/sys/class/android_usb/android0/iProduct", product) != 0;
  free(serial); free(manufacturer); free(product); free(vendor); free(product_id);
  return fail ? -1 : 0;
}

static int overlay_kernel_device_tables(void) {
  int fail = 0;
  fail += overlay_text_optional("proc_devices", "/proc/devices",
    "Character devices:\n"
    "  1 mem\n"
    "  5 /dev/tty\n"
    " 10 misc\n"
    " 13 input\n"
    " 29 fb\n"
    " 81 video4linux\n"
    "254 binder\n\n"
    "Block devices:\n"
    "  7 loop\n"
    "179 mmc\n"
    "253 device-mapper\n") != 0;
  fail += overlay_text_optional("proc_misc", "/proc/misc",
    "200 tun\n"
    " 57 binder\n"
    " 56 hwbinder\n"
    " 55 vndbinder\n"
    " 54 ashmem\n"
    " 53 uinput\n") != 0;
  fail += overlay_text_optional("proc_tty_drivers", "/proc/tty/drivers",
    "/dev/tty             /dev/tty        5       0 system:/dev/tty\n"
    "/dev/console         /dev/console    5       1 system:console\n"
    "msm_serial_hs        /dev/ttyHS      245 0-3 serial\n"
    "pty_slave            /dev/pts      136 0-1048575 pty:slave\n"
    "pty_master           /dev/ptm      128 0-1048575 pty:master\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_selinuxfs(void) {
  int fail = 0;
  fail += overlay_text_optional("selinux_enforce", "/sys/fs/selinux/enforce", "1\n") != 0;
  fail += overlay_text_optional("selinux_policyvers", "/sys/fs/selinux/policyvers", "33\n") != 0;
  fail += overlay_text_optional("selinux_mls", "/sys/fs/selinux/mls", "1\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_rtc_sysfs(void) {
  int fail = 0;
  const char *driver_rtc =
    "rtc_time\t: 00:00:00\n"
    "rtc_date\t: 2024-05-07\n"
    "alrm_time\t: 00:00:00\n"
    "alrm_date\t: 2024-05-07\n"
    "24hr\t\t: yes\n";
  fail += overlay_text_optional("rtc0_name", "/sys/class/rtc/rtc0/name", "rtc-pm8xxx\n") != 0;
  fail += overlay_text_optional("rtc0_hctosys", "/sys/class/rtc/rtc0/hctosys", "1\n") != 0;
  fail += overlay_text_optional("rtc0_date", "/sys/class/rtc/rtc0/date", "2024-05-07\n") != 0;
  fail += overlay_text_optional("rtc0_time", "/sys/class/rtc/rtc0/time", "00:00:00\n") != 0;
  fail += overlay_text_optional("rtc0_since_epoch", "/sys/class/rtc/rtc0/since_epoch", "1715040000\n") != 0;
  fail += overlay_text_optional("proc_driver_rtc", "/proc/driver/rtc", driver_rtc) != 0;
  return fail ? -1 : 0;
}

static int overlay_kallsyms_tracing(void) {
  int fail = 0;
  const char *kallsyms =
    "0000000000000000 T _text\n"
    "0000000000000000 T start_kernel\n"
    "0000000000000000 T rest_init\n"
    "0000000000000000 T cpu_startup_entry\n";
  const char *available =
    "start_kernel\n"
    "rest_init\n"
    "cpu_startup_entry\n"
    "schedule\n"
    "do_sys_openat2\n";
  fail += overlay_text_optional("proc_kallsyms", "/proc/kallsyms", kallsyms) != 0;
  fail += overlay_text_optional("debug_tracing_available_filter_functions", "/sys/kernel/debug/tracing/available_filter_functions", available) != 0;
  fail += overlay_text_optional("debug_tracing_enabled_functions", "/sys/kernel/debug/tracing/enabled_functions", "") != 0;
  fail += overlay_text_optional("debug_tracing_kprobe_events", "/sys/kernel/debug/tracing/kprobe_events", "") != 0;
  fail += overlay_text_optional("debug_tracing_uprobe_events", "/sys/kernel/debug/tracing/uprobe_events", "") != 0;
  fail += overlay_text_optional("debug_tracing_trace", "/sys/kernel/debug/tracing/trace", "# tracer: nop\n#\n") != 0;
  fail += overlay_text_optional("tracing_available_filter_functions", "/sys/kernel/tracing/available_filter_functions", available) != 0;
  fail += overlay_text_optional("tracing_enabled_functions", "/sys/kernel/tracing/enabled_functions", "") != 0;
  fail += overlay_text_optional("tracing_kprobe_events", "/sys/kernel/tracing/kprobe_events", "") != 0;
  fail += overlay_text_optional("tracing_uprobe_events", "/sys/kernel/tracing/uprobe_events", "") != 0;
  fail += overlay_text_optional("tracing_trace", "/sys/kernel/tracing/trace", "# tracer: nop\n#\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_kernel_virtualization_texts(void) {
  int fail = 0;
  fail += overlay_text_optional("proc_modules", "/proc/modules", "");
  fail += overlay_text_optional("proc_interrupts", "/proc/interrupts",
    "           CPU0       CPU1       CPU2       CPU3\n"
    " 16:          0          0          0          0     GICv3  arch_timer\n"
    " 32:       1200       1100       1080       1090     GICv3  kgsl-3d0\n"
    " 48:        300        280        260        270     GICv3  sdhci\n");
  fail += overlay_text_optional("proc_iomem", "/proc/iomem",
    "00000000-00000fff : reserved\n"
    "80000000-ffffffff : System RAM\n"
    "  80200000-82ffffff : Kernel code\n");
  fail += overlay_text_optional("proc_ioports", "/proc/ioports", "");
  return fail ? -1 : 0;
}
static int overlay_devicetree_identity(void) {
  int fail = 0;
  char *serial = first_or_default(PROFILE_DIR "/serial", "3A4940E5EDFA\n");
  const char *model = "Google Pixel 6 Pro\n";
  static const char compatible[] = "google,raven\0google,gs101\0";
  const char *name = "raven\n";
  const char *bootargs = "console=ttyMSM0 androidboot.hardware=gs101 androidboot.verifiedbootstate=green androidboot.veritymode=enforcing\n";
  fail += overlay_text_optional("proc_dt_model", "/proc/device-tree/model", model) != 0;
  fail += overlay_bytes_optional("proc_dt_compatible", "/proc/device-tree/compatible", compatible, sizeof(compatible) - 1) != 0;
  fail += overlay_text_optional("proc_dt_name", "/proc/device-tree/name", name) != 0;
  fail += overlay_text_optional("proc_dt_serial", "/proc/device-tree/serial-number", serial) != 0;
  fail += overlay_text_optional("proc_dt_bootargs", "/proc/device-tree/chosen/bootargs", bootargs) != 0;
  fail += overlay_text_optional("fw_dt_model", "/sys/firmware/devicetree/base/model", model) != 0;
  fail += overlay_bytes_optional("fw_dt_compatible", "/sys/firmware/devicetree/base/compatible", compatible, sizeof(compatible) - 1) != 0;
  fail += overlay_text_optional("fw_dt_name", "/sys/firmware/devicetree/base/name", name) != 0;
  fail += overlay_text_optional("fw_dt_serial", "/sys/firmware/devicetree/base/serial-number", serial) != 0;
  fail += overlay_text_optional("fw_dt_bootargs", "/sys/firmware/devicetree/base/chosen/bootargs", bootargs) != 0;
  free(serial);
  return fail ? -1 : 0;
}

static int overlay_dmi_hypervisor(void) {
  int fail = 0;
  fail += overlay_text_optional("dmi_product_name", "/sys/class/dmi/id/product_name", "Google Pixel 6 Pro\n") != 0;
  fail += overlay_text_optional("dmi_sys_vendor", "/sys/class/dmi/id/sys_vendor", "Google\n") != 0;
  fail += overlay_text_optional("dmi_board_vendor", "/sys/class/dmi/id/board_vendor", "Google\n") != 0;
  fail += overlay_text_optional("dmi_board_name", "/sys/class/dmi/id/board_name", "raven\n") != 0;
  fail += overlay_text_optional("virtual_dmi_product_name", "/sys/devices/virtual/dmi/id/product_name", "Google Pixel 6 Pro\n") != 0;
  fail += overlay_text_optional("virtual_dmi_sys_vendor", "/sys/devices/virtual/dmi/id/sys_vendor", "Google\n") != 0;
  fail += overlay_text_optional("hypervisor_type", "/sys/hypervisor/type", "\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_storage_proc(void) {
  const char *diskstats =
    " 179       0 mmcblk0 1200 0 65536 120 3400 0 262144 520 0 600 640 0 0 0 0 0 0\n"
    " 179       1 mmcblk0p1 100 0 4096 10 0 0 0 0 0 10 10 0 0 0 0 0 0\n"
    " 179       2 mmcblk0p2 1100 0 61440 110 3400 0 262144 520 0 590 630 0 0 0 0 0 0\n";
  const char *parts =
    "major minor  #blocks  name\n\n"
    " 179        0   62500000 mmcblk0\n"
    " 179        1     262144 mmcblk0p1\n"
    " 179        2   62237856 mmcblk0p2\n";
  int fail = 0;
  fail += overlay_text("diskstats", "/proc/diskstats", diskstats) != 0;
  fail += overlay_text("partitions", "/proc/partitions", parts) != 0;
  return fail ? -1 : 0;
}
static int overlay_block_sysfs(void) {
  int fail = 0;
  fail += overlay_text("vda_size", "/sys/block/vda/size", "125000000\n") != 0;
  fail += overlay_text("vdb_size", "/sys/block/vdb/size", "0\n") != 0;
  fail += overlay_text("vda_rotational", "/sys/block/vda/queue/rotational", "0\n") != 0;
  fail += overlay_text("vdb_rotational", "/sys/block/vdb/queue/rotational", "0\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_meminfo(void) {
  const char *mem =
    "MemTotal:        8126464 kB\n"
    "MemFree:         2145320 kB\n"
    "MemAvailable:    5120480 kB\n"
    "Buffers:          128000 kB\n"
    "Cached:          2864000 kB\n"
    "SwapCached:            0 kB\n"
    "Active:          2100000 kB\n"
    "Inactive:        1800000 kB\n"
    "Active(anon):     900000 kB\n"
    "Inactive(anon):   300000 kB\n"
    "Active(file):    1200000 kB\n"
    "Inactive(file):  1500000 kB\n"
    "Unevictable:           0 kB\n"
    "Mlocked:               0 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n"
    "Dirty:               128 kB\n"
    "Writeback:             0 kB\n"
    "AnonPages:       1200000 kB\n"
    "Mapped:           600000 kB\n"
    "Shmem:            120000 kB\n"
    "Slab:             320000 kB\n"
    "SReclaimable:     180000 kB\n"
    "SUnreclaim:       140000 kB\n"
    "KernelStack:       12000 kB\n"
    "PageTables:        20000 kB\n"
    "CommitLimit:     3932160 kB\n"
    "Committed_AS:    3500000 kB\n";
  return overlay_text("meminfo", "/proc/meminfo", mem);
}
static int overlay_memory_proc_details(void) {
  int fail = 0;
  const char *vmstat =
    "nr_free_pages 536330\n"
    "nr_zone_inactive_anon 75000\n"
    "nr_zone_active_anon 225000\n"
    "nr_zone_inactive_file 375000\n"
    "nr_zone_active_file 300000\n"
    "nr_zone_unevictable 0\n"
    "nr_mlock 0\n"
    "nr_anon_pages 300000\n"
    "nr_mapped 150000\n"
    "nr_file_pages 716000\n"
    "nr_dirty 32\n"
    "nr_writeback 0\n"
    "nr_slab_reclaimable 45000\n"
    "nr_slab_unreclaimable 35000\n"
    "pgpgin 120000\n"
    "pgpgout 220000\n"
    "pswpin 0\n"
    "pswpout 0\n"
    "pgfault 500000\n"
    "pgmajfault 120\n";
  const char *zoneinfo =
    "Node 0, zone   Normal\n"
    "  pages free     536330\n"
    "        min      4096\n"
    "        low      8192\n"
    "        high     12288\n"
    "        spanned  1966080\n"
    "        present  1966080\n"
    "        managed  1900000\n"
    "  start_pfn:     0\n";
  const char *buddyinfo =
    "Node 0, zone   Normal  128 256 512 256 128 64 32 16 8 4 2\n";
  const char *pagetypeinfo =
    "Page block order: 9\n"
    "Pages per block:  512\n\n"
    "Free pages count per migrate type at order 0\n"
    "Node    0, zone   Normal, type    Unmovable      128\n"
    "Node    0, zone   Normal, type      Movable      512\n"
    "Node    0, zone   Normal, type  Reclaimable      256\n";
  fail += overlay_text_optional("proc_vmstat", "/proc/vmstat", vmstat) != 0;
  fail += overlay_text_optional("proc_zoneinfo", "/proc/zoneinfo", zoneinfo) != 0;
  fail += overlay_text_optional("proc_buddyinfo", "/proc/buddyinfo", buddyinfo) != 0;
  fail += overlay_text_optional("proc_pagetypeinfo", "/proc/pagetypeinfo", pagetypeinfo) != 0;
  return fail ? -1 : 0;
}

static int overlay_cpu_proc_stats(void) {
  int fail = 0;
  const char *stat =
    "cpu  120000 800 45000 900000 1200 0 4000 0 0 0\n"
    "cpu0 15000 100 5600 112000 150 0 500 0 0 0\n"
    "cpu1 14800 100 5500 113000 140 0 480 0 0 0\n"
    "cpu2 15100 90 5700 111000 160 0 510 0 0 0\n"
    "cpu3 14900 100 5600 112500 150 0 500 0 0 0\n"
    "cpu4 15200 100 5800 111800 150 0 520 0 0 0\n"
    "cpu5 14700 100 5500 113200 140 0 480 0 0 0\n"
    "cpu6 13000 100 5200 116000 150 0 450 0 0 0\n"
    "cpu7 12800 110 5100 116500 160 0 440 0 0 0\n"
    "intr 1234567\n"
    "ctxt 3456789\n"
    "btime 1715040000\n"
    "processes 12345\n"
    "procs_running 1\n"
    "procs_blocked 0\n";
  const char *softirqs =
    "                    CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7\n"
    "          HI:          0          0          0          0          0          0          0          0\n"
    "       TIMER:      10000       9800       9900       9700       9600       9500       9400       9300\n"
    "      NET_TX:        120        118        116        114        112        110        108        106\n"
    "      NET_RX:       1200       1180       1160       1140       1120       1100       1080       1060\n"
    "       BLOCK:        500        490        480        470        460        450        440        430\n"
    "    TASKLET:        300        290        280        270        260        250        240        230\n"
    "      SCHED:       5000       4950       4900       4850       4800       4750       4700       4650\n"
    "        RCU:       9000       8900       8800       8700       8600       8500       8400       8300\n";
  const char *schedstat =
    "version 15\n"
    "timestamp 0\n"
    "cpu0 0 0 0 0 0 0 0 0 0\n"
    "cpu1 0 0 0 0 0 0 0 0 0\n"
    "cpu2 0 0 0 0 0 0 0 0 0\n"
    "cpu3 0 0 0 0 0 0 0 0 0\n"
    "cpu4 0 0 0 0 0 0 0 0 0\n"
    "cpu5 0 0 0 0 0 0 0 0 0\n"
    "cpu6 0 0 0 0 0 0 0 0 0\n"
    "cpu7 0 0 0 0 0 0 0 0 0\n";
  fail += overlay_text_optional("proc_stat", "/proc/stat", stat) != 0;
  fail += overlay_text_optional("proc_softirqs", "/proc/softirqs", softirqs) != 0;
  fail += overlay_text_optional("proc_schedstat", "/proc/schedstat", schedstat) != 0;
  return fail ? -1 : 0;
}

static int overlay_kernel_proc_misc(void) {
  int fail = 0;
  fail += overlay_text_optional("proc_uptime", "/proc/uptime", "86400.00 86000.00\n") != 0;
  fail += overlay_text_optional("proc_loadavg", "/proc/loadavg", "0.42 0.38 0.31 1/812 12345\n") != 0;
  fail += overlay_text_optional("proc_swaps", "/proc/swaps", "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n") != 0;
  fail += overlay_text_optional("proc_filesystems", "/proc/filesystems",
    "nodev\tsysfs\n"
    "nodev\ttmpfs\n"
    "nodev\tproc\n"
    "nodev\tdevpts\n"
    "\text4\n"
    "\tf2fs\n"
    "nodev\tselinuxfs\n"
    "nodev\tbinder\n") != 0;
  fail += overlay_text_optional("kernel_ostype", "/proc/sys/kernel/ostype", "Linux\n") != 0;
  fail += overlay_text_optional("kernel_osrelease", "/proc/sys/kernel/osrelease", "5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058\n") != 0;
  fail += overlay_text_optional("kernel_version", "/proc/sys/kernel/version", "#1 SMP PREEMPT Wed Oct 5 04:00:00 UTC 2022\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_kernel_hardening_sysctls(void) {
  int fail = 0;
  fail += overlay_text_optional("kernel_kptr_restrict", "/proc/sys/kernel/kptr_restrict", "2\n") != 0;
  fail += overlay_text_optional("kernel_dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", "1\n") != 0;
  fail += overlay_text_optional("kernel_perf_event_paranoid", "/proc/sys/kernel/perf_event_paranoid", "3\n") != 0;
  fail += overlay_text_optional("kernel_modules_disabled", "/proc/sys/kernel/modules_disabled", "1\n") != 0;
  fail += overlay_text_optional("kernel_unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", "1\n") != 0;
  fail += overlay_text_optional("kernel_yama_ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope", "2\n") != 0;
  return fail ? -1 : 0;
}

static const char *fake_status_text(const char *name, const char *pid) {
  (void)name; (void)pid;
  return
    "Name:\tinit\n"
    "Umask:\t0022\n"
    "State:\tS (sleeping)\n"
    "Tgid:\t1\n"
    "Ngid:\t0\n"
    "Pid:\t1\n"
    "PPid:\t0\n"
    "TracerPid:\t0\n"
    "Uid:\t0\t0\t0\t0\n"
    "Gid:\t0\t0\t0\t0\n"
    "FDSize:\t64\n"
    "Groups:\t0\n"
    "NStgid:\t1\n"
    "NSpid:\t1\n"
    "NSpgid:\t1\n"
    "NSsid:\t1\n"
    "VmPeak:\t   20480 kB\n"
    "VmSize:\t   20480 kB\n"
    "Threads:\t1\n"
    "SigQ:\t0/32768\n"
    "SigPnd:\t0000000000000000\n"
    "ShdPnd:\t0000000000000000\n"
    "SigBlk:\t0000000000000000\n"
    "SigIgn:\t0000000000000000\n"
    "SigCgt:\t0000000000000000\n"
    "CapInh:\t0000000000000000\n"
    "CapPrm:\t0000003fffffffff\n"
    "CapEff:\t0000003fffffffff\n"
    "CapBnd:\t0000003fffffffff\n"
    "CapAmb:\t0000000000000000\n"
    "NoNewPrivs:\t0\n"
    "Seccomp:\t0\n"
    "Speculation_Store_Bypass:\tvulnerable\n"
    "Cpus_allowed:\tff\n"
    "Cpus_allowed_list:\t0-7\n"
    "Mems_allowed:\t00000000,00000001\n"
    "Mems_allowed_list:\t0\n";
}
static int overlay_proc_identity_tables(void) {
  int fail = 0;
  const char *uidmap = "         0          0 4294967295\n";
  const char *ctx = "u:r:init:s0\n";
  fail += overlay_text_optional("proc_1_status", "/proc/1/status", fake_status_text("init", "1")) != 0;
  fail += overlay_text_optional("proc_1_uid_map", "/proc/1/uid_map", uidmap) != 0;
  fail += overlay_text_optional("proc_1_gid_map", "/proc/1/gid_map", uidmap) != 0;
  fail += overlay_text_optional("proc_1_attr_current", "/proc/1/attr/current", ctx) != 0;
  return fail ? -1 : 0;
}

static int overlay_mount_namespace_texts(void) {
  int fail = 0;
  const char *mounts =
    "tmpfs / tmpfs rw,seclabel,nosuid,nodev,relatime,size=8126464k,mode=755 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0\n"
    "devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,mode=600,ptmxmode=000 0 0\n"
    "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
    "/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0\n"
    "/dev/block/dm-2 /data f2fs rw,seclabel,nosuid,nodev,noatime 0 0\n";
  const char *mountinfo =
    "21 0 0:20 / / rw,seclabel shared:1 - tmpfs tmpfs rw,seclabel,size=8126464k,mode=755\n"
    "22 21 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw\n"
    "23 21 0:7 / /sys rw,seclabel,nosuid,nodev,noexec,relatime shared:3 - sysfs sysfs rw,seclabel\n"
    "24 21 259:0 / /system ro,seclabel,relatime shared:4 - ext4 /dev/block/dm-0 ro\n"
    "25 21 259:1 / /vendor ro,seclabel,relatime shared:5 - ext4 /dev/block/dm-1 ro\n"
    "26 21 259:2 / /data rw,seclabel,nosuid,nodev,noatime shared:6 - f2fs /dev/block/dm-2 rw\n";
  const char *cgroups =
    "#subsys_name\thierarchy\tnum_cgroups\tenabled\n"
    "cpuset\t0\t1\t1\n"
    "cpu\t0\t1\t1\n"
    "cpuacct\t0\t1\t1\n"
    "memory\t0\t1\t1\n"
    "devices\t0\t1\t1\n"
    "freezer\t0\t1\t1\n"
    "pids\t0\t1\t1\n";
  fail += overlay_text_optional("proc_cgroups", "/proc/cgroups", cgroups) != 0;
  fail += overlay_text_optional("proc_1_cgroup", "/proc/1/cgroup", "0::/init.scope\n") != 0;
  fail += overlay_text_optional("proc_1_mounts", "/proc/1/mounts", mounts) != 0;
  fail += overlay_text_optional("proc_1_mountinfo", "/proc/1/mountinfo", mountinfo) != 0;
  fail += overlay_text_optional("proc_1_mountstats", "/proc/1/mountstats", "device tmpfs mounted on / with fstype tmpfs\n") != 0;
  return fail ? -1 : 0;
}


static int overlay_cpu_topology(void) {
  int fail = 0;
  fail += overlay_text("cpu_online", "/sys/devices/system/cpu/online", "0-7\n") != 0;
  fail += overlay_text("cpu_possible", "/sys/devices/system/cpu/possible", "0-7\n") != 0;
  fail += overlay_text("cpu_present", "/sys/devices/system/cpu/present", "0-7\n") != 0;
  return fail ? -1 : 0;
}


static int stage_cpu_sysfs_details(int cpu, long max_freq, long min_freq, long cur_freq) {
  char target[256], topology[256], cpufreq[256], path[320], buf[64];
  snprintf(target, sizeof(target), "/sys/devices/system/cpu/cpu%d", cpu);
  if (access(target, F_OK) != 0) return 0;

  /* Use tmpfs so the mounted view has no overlayfs metadata while retaining
     the original CPU directory contents that are copied below. */
  umount2(target, MNT_DETACH);
  if (mount("tmpfs", target, "tmpfs", 0, "mode=755")) return -1;
  mount(NULL, target, NULL, MS_PRIVATE | MS_REC, NULL);

  snprintf(topology, sizeof(topology), "%s/topology", target);
  snprintf(cpufreq, sizeof(cpufreq), "%s/cpufreq", target);
  if (ensure_dir(topology) || ensure_dir(cpufreq)) return -1;

  snprintf(path, sizeof(path), "%s/core_id", topology);
  long_line(buf, sizeof(buf), cpu);
  if (write_text(path, buf)) return -1;
  snprintf(path, sizeof(path), "%s/physical_package_id", topology);
  if (write_text(path, "0\n")) return -1;
  snprintf(path, sizeof(path), "%s/thread_siblings_list", topology);
  long_line(buf, sizeof(buf), cpu);
  if (write_text(path, buf)) return -1;
  snprintf(path, sizeof(path), "%s/core_siblings_list", topology);
  if (write_text(path, "0-7\n")) return -1;

  snprintf(path, sizeof(path), "%s/cpuinfo_max_freq", cpufreq);
  long_line(buf, sizeof(buf), max_freq);
  if (write_text(path, buf)) return -1;
  snprintf(path, sizeof(path), "%s/cpuinfo_min_freq", cpufreq);
  long_line(buf, sizeof(buf), min_freq);
  if (write_text(path, buf)) return -1;
  snprintf(path, sizeof(path), "%s/scaling_cur_freq", cpufreq);
  long_line(buf, sizeof(buf), cur_freq);
  if (write_text(path, buf)) return -1;
  snprintf(path, sizeof(path), "%s/scaling_governor", cpufreq);
  if (write_text(path, "schedutil\n")) return -1;

  if (cpu > 0) {
    snprintf(path, sizeof(path), "%s/online", target);
    if (write_text(path, "1\n")) return -1;
  }
  snprintf(path, sizeof(path), "%s/uevent", target);
  if (write_text(path, "\n")) return -1;
  mark_mounted(target);
  return 0;
}

static int overlay_cpu_sysfs_details(void) {
  int fail = 0;
  const long max_freqs[8] = {2995000, 2995000, 2995000, 2995000, 2995000, 2995000, 2850000, 2850000};
  const long min_freqs[8] = {300000, 300000, 300000, 300000, 300000, 300000, 300000, 300000};
  for (int cpu = 0; cpu < 8; cpu++) {
    long cur_freq = cpu < 6 ? 1800000 : 1500000;
    fail += stage_cpu_sysfs_details(cpu, max_freqs[cpu], min_freqs[cpu], cur_freq) != 0;
  }
  return fail ? -1 : 0;
}

static int overlay_cpuinfo(void) {
  const char *cpu =
    "Processor\t: AArch64 Processor rev 1 (aarch64)\n"
    "processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0x0d4\nCPU revision\t: 1\n\n"
    "processor\t: 1\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0x0d4\nCPU revision\t: 1\n\n"
    "Hardware\t: tensor\n";
  return overlay_text("cpuinfo", "/proc/cpuinfo", cpu);
}
static int overlay_version(void) {
  return overlay_text("version", "/proc/version", "Linux version 5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058 (android-build@abfarm) (Android (9352603) clang version 14.0.7) #1 SMP PREEMPT Wed Oct 5 04:00:00 UTC 2022\n");
}
static int overlay_cmdline(void) {
  char *serial = first_or_default(PROFILE_DIR "/serial", "3A4940E5EDFA\n");
  serial[strcspn(serial, "\r\n")] = 0;
  char cmdline[1024];
  snprintf(cmdline, sizeof(cmdline),
           "console=ttyMSM0 androidboot.hardware=gs101 "
           "androidboot.verifiedbootstate=green androidboot.veritymode=enforcing "
           "androidboot.serialno=%s\n", serial);
  free(serial);
  return overlay_text("cmdline", "/proc/cmdline", cmdline);
}

static int overlay_framebuffer(void) {
  int fail = 0;
  long width = read_long_default(PROFILE_DIR "/display_width", 1344);
  long height = read_long_default(PROFILE_DIR "/display_height", 2992);
  if (width < 320) width = 1344; if (height < 480) height = 2992;
  char buf[128];
  fail += overlay_text_optional("proc_fb", "/proc/fb", "0 msmfb\n") != 0;
  fail += overlay_text_optional("fb0_name", "/sys/class/graphics/fb0/name", "msmfb\n") != 0;
  snprintf(buf, sizeof(buf), "%ld,%ld\n", width, height);
  fail += overlay_text_optional("fb0_virtual_size", "/sys/class/graphics/fb0/virtual_size", buf) != 0;
  fail += overlay_text_optional("fb0_bits_per_pixel", "/sys/class/graphics/fb0/bits_per_pixel", "32\n") != 0;
  snprintf(buf, sizeof(buf), "U:%ldx%ldp-60\n", width, height);
  fail += overlay_text_optional("fb0_modes", "/sys/class/graphics/fb0/modes", buf) != 0;
  return fail ? -1 : 0;
}

static int overlay_backlight_leds(void) {
  int fail = 0;
  long brightness = read_long_default(PROFILE_DIR "/display_brightness", 512);
  if (brightness < 0) brightness = 0; if (brightness > 1023) brightness = 1023;
  char buf[64]; long_line(buf, sizeof(buf), brightness);
  fail += overlay_text_optional("panel0_brightness", "/sys/class/backlight/panel0-backlight/brightness", buf) != 0;
  fail += overlay_text_optional("panel0_actual_brightness", "/sys/class/backlight/panel0-backlight/actual_brightness", buf) != 0;
  fail += overlay_text_optional("panel0_max_brightness", "/sys/class/backlight/panel0-backlight/max_brightness", "1023\n") != 0;
  fail += overlay_text_optional("panel0_type", "/sys/class/backlight/panel0-backlight/type", "raw\n") != 0;
  fail += overlay_text_optional("lcd_backlight_brightness", "/sys/class/leds/lcd-backlight/brightness", buf) != 0;
  fail += overlay_text_optional("lcd_backlight_max", "/sys/class/leds/lcd-backlight/max_brightness", "1023\n") != 0;
  fail += overlay_text_optional("vibrator_brightness", "/sys/class/leds/vibrator/brightness", "0\n") != 0;
  fail += overlay_text_optional("vibrator_max", "/sys/class/leds/vibrator/max_brightness", "1\n") != 0;
  fail += overlay_text_optional("flash_brightness", "/sys/class/leds/white:flash/brightness", "0\n") != 0;
  fail += overlay_text_optional("flash_max", "/sys/class/leds/white:flash/max_brightness", "255\n") != 0;
  return fail ? -1 : 0;
}

static char *profile_value_line(const char *path, const char *fallback) {
  return first_or_default(path, fallback);
}
static int overlay_input_devices(void) {
  char *touch = profile_value_line(PROFILE_DIR "/input_name", "sec_touchscreen\n");
  size_t n = strcspn(touch, "\r\n"); touch[n] = 0;
  if (!touch[0]) snprintf(touch, 32, "%s", "sec_touchscreen");
  char body[4096];
  snprintf(body, sizeof(body),
    "I: Bus=0018 Vendor=04e8 Product=6860 Version=0100\n"
    "N: Name=\"%s\"\n"
    "P: Phys=i2c/sec_touchscreen/input0\n"
    "S: Sysfs=/devices/platform/soc/soc:i2c/sec_touchscreen/input/input0\n"
    "U: Uniq=\n"
    "H: Handlers=event0 mouse0 \n"
    "B: PROP=2\n"
    "B: EV=b\n"
    "B: KEY=400 0 0 0 0 0\n"
    "B: ABS=661800001000003\n\n"
    "I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
    "N: Name=\"gpio-keys\"\n"
    "P: Phys=gpio-keys/input0\n"
    "S: Sysfs=/devices/platform/gpio-keys/input/input1\n"
    "U: Uniq=\n"
    "H: Handlers=kbd event1 wakeup \n"
    "B: PROP=0\n"
    "B: EV=3\n"
    "B: KEY=100000 0 0 0\n\n"
    "I: Bus=0019 Vendor=0001 Product=0002 Version=0100\n"
    "N: Name=\"qpnp_pon\"\n"
    "P: Phys=qpnp_pon/input0\n"
    "S: Sysfs=/devices/platform/soc/qpnp_pon/input/input2\n"
    "U: Uniq=\n"
    "H: Handlers=kbd event2 wakeup \n"
    "B: PROP=0\n"
    "B: EV=3\n"
    "B: KEY=100000 0 0 0\n\n", touch);
  free(touch);
  return overlay_text_optional("proc_bus_input_devices", "/proc/bus/input/devices", body);
}

static int overlay_boot_id(void) {
  char *boot = first_or_default(PROFILE_DIR "/boot_id", "b9b36666-6eb6-4613-9ad6-edc7bb5630f9\n");
  char fake[256]; snprintf(fake, sizeof(fake), "%s/boot_id", OVERLAY_DIR);
  int rc = write_text(fake, boot); free(boot); if (rc) return -1;
  return bind_file(fake, "/proc/sys/kernel/random/boot_id");
}
static int overlay_random_sysctls(void) {
  int fail = 0;
  char *uuid = first_or_default(PROFILE_DIR "/random_uuid", "8e77f80f-4f61-4f0d-9d1e-123456789abc\n");
  char fake[256]; snprintf(fake, sizeof(fake), "%s/random_uuid", OVERLAY_DIR);
  int rc = write_text(fake, uuid); free(uuid); if (rc) return -1;
  if (access("/proc/sys/kernel/random/uuid", F_OK) == 0) fail += bind_file(fake, "/proc/sys/kernel/random/uuid") != 0;
  fail += overlay_text_optional("random_entropy_avail", "/proc/sys/kernel/random/entropy_avail", "4096\n") != 0;
  fail += overlay_text_optional("random_poolsize", "/proc/sys/kernel/random/poolsize", "4096\n") != 0;
  fail += overlay_text_optional("random_urandom_min_reseed_secs", "/proc/sys/kernel/random/urandom_min_reseed_secs", "60\n") != 0;
  return fail ? -1 : 0;
}


static int overlay_network_interface(void) {
  int fail = 0;
  /* /proc/net is reader-relative; app-process interception handles it. */
  long mtu = read_long_default(PROFILE_DIR "/network_mtu", 1500);
  if (mtu < 576 || mtu > 9000) mtu = 1500;
  char buf[1024];
  long_line(buf, sizeof(buf), mtu); fail += overlay_text_optional("eth0_mtu", "/sys/class/net/eth0/mtu", buf) != 0;
  fail += overlay_text_optional("eth0_type", "/sys/class/net/eth0/type", "1\n") != 0;
  fail += overlay_text_optional("eth0_operstate", "/sys/class/net/eth0/operstate", "up\n") != 0;
  fail += overlay_text_optional("eth0_carrier", "/sys/class/net/eth0/carrier", "1\n") != 0;
  fail += overlay_text_optional("eth0_addr_assign_type", "/sys/class/net/eth0/addr_assign_type", "0\n") != 0;
  fail += overlay_text_optional("eth0_ifindex", "/sys/class/net/eth0/ifindex", "2\n") != 0;
  fail += overlay_text_optional("eth0_iflink", "/sys/class/net/eth0/iflink", "2\n") != 0;
  return fail ? -1 : 0;
}

static int overlay_mac(void) {
  char *mac = first_or_default(PROFILE_DIR "/mac_address", "02:33:44:55:66:77\n");
  char fake[256]; snprintf(fake, sizeof(fake), "%s/eth0_address", OVERLAY_DIR);
  int rc = write_text(fake, mac); free(mac); if (rc) return -1;
  return bind_file(fake, "/sys/class/net/eth0/address");
}
static void status_one(const char *target) {
  char cmd[512]; snprintf(cmd, sizeof(cmd), "grep ' %s ' /proc/self/mountinfo >/dev/null 2>&1", target);
  printf("%s=%s\n", target, system(cmd) == 0 ? "overlay" : "real");
}
static int apply(void) {
  ensure_dir("/data/local/tmp"); if (ensure_dir(OVERLAY_DIR)) return 2;
  /* Stale-marker repair: markers live on the persistent /data volume while
     bind mounts die with each container recreation or sysfs node replace.
     Sweep every .mounted_* marker; bind_file remounts from mountinfo truth. */
  {
    DIR *d = opendir(OVERLAY_DIR);
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, ".mounted_", 9) != 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", OVERLAY_DIR, de->d_name);
        unlink(path);
      }
      closedir(d);
    }
  }
  int fail = 0;
  if (overlay_boot_id()) { printf("boot_id=fail:%s\n", strerror(errno)); fail++; } else printf("boot_id=ok\n");
  if (overlay_random_sysctls()) { printf("random_sysctls=fail:%s\n", strerror(errno)); fail++; } else printf("random_sysctls=ok\n");
  if (overlay_network_interface()) { printf("network_interface=fail:%s\n", strerror(errno)); fail++; } else printf("network_interface=ok\n");
  if (overlay_mac()) { printf("eth0_address=fail:%s\n", strerror(errno)); fail++; } else printf("eth0_address=ok\n");
  if (overlay_cpuinfo()) { printf("cpuinfo=fail:%s\n", strerror(errno)); fail++; } else printf("cpuinfo=ok\n");
  if (overlay_version()) { printf("version=fail:%s\n", strerror(errno)); fail++; } else printf("version=ok\n");
  if (overlay_cmdline()) { printf("cmdline=fail:%s\n", strerror(errno)); fail++; } else printf("cmdline=ok\n");
  if (overlay_meminfo()) { printf("meminfo=fail:%s\n", strerror(errno)); fail++; } else printf("meminfo=ok\n");
  if (overlay_memory_proc_details()) { printf("memory_proc_details=fail:%s\n", strerror(errno)); fail++; } else printf("memory_proc_details=ok\n");
  if (overlay_cpu_proc_stats()) { printf("cpu_proc_stats=fail:%s\n", strerror(errno)); fail++; } else printf("cpu_proc_stats=ok\n");
  if (overlay_kernel_proc_misc()) { printf("kernel_proc_misc=fail:%s\n", strerror(errno)); fail++; } else printf("kernel_proc_misc=ok\n");
  if (overlay_kernel_hardening_sysctls()) { printf("kernel_hardening_sysctls=fail:%s\n", strerror(errno)); fail++; } else printf("kernel_hardening_sysctls=ok\n");
  if (overlay_proc_identity_tables()) { printf("proc_identity_tables=fail:%s\n", strerror(errno)); fail++; } else printf("proc_identity_tables=ok\n");
  if (overlay_mount_namespace_texts()) { printf("mount_namespace=fail:%s\n", strerror(errno)); fail++; } else printf("mount_namespace=ok\n");
  if (overlay_cpu_topology()) { printf("cpu_topology=fail:%s\n", strerror(errno)); fail++; } else printf("cpu_topology=ok\n");
  if (overlay_cpu_sysfs_details()) { printf("cpu_sysfs_details=fail:%s\n", strerror(errno)); fail++; } else printf("cpu_sysfs_details=ok\n");
  if (overlay_storage_proc()) { printf("storage_proc=fail:%s\n", strerror(errno)); fail++; } else printf("storage_proc=ok\n");
  if (overlay_block_sysfs()) { printf("block_sysfs=fail:%s\n", strerror(errno)); fail++; } else printf("block_sysfs=ok\n");
  if (overlay_selinuxfs()) { printf("selinuxfs=fail:%s\n", strerror(errno)); fail++; } else printf("selinuxfs=ok\n");
  if (overlay_kallsyms_tracing()) { printf("kallsyms_tracing=fail:%s\n", strerror(errno)); fail++; } else printf("kallsyms_tracing=ok\n");
  if (overlay_kernel_virtualization_texts()) { printf("virtualization_texts=fail:%s\n", strerror(errno)); fail++; } else printf("virtualization_texts=ok\n");
  if (overlay_kernel_device_tables()) { printf("kernel_device_tables=fail:%s\n", strerror(errno)); fail++; } else printf("kernel_device_tables=ok\n");
  if (overlay_rtc_sysfs()) { printf("rtc_sysfs=fail:%s\n", strerror(errno)); fail++; } else printf("rtc_sysfs=ok\n");
  if (overlay_devicetree_identity()) { printf("devicetree=fail:%s\n", strerror(errno)); fail++; } else printf("devicetree=ok\n");
  if (overlay_dmi_hypervisor()) { printf("dmi_hypervisor=fail:%s\n", strerror(errno)); fail++; } else printf("dmi_hypervisor=ok\n");
  if (overlay_build_props()) { printf("build_props=fail:%s\n", strerror(errno)); fail++; } else printf("build_props=ok\n");
  if (overlay_extra_build_props()) { printf("extra_build_props=fail:%s\n", strerror(errno)); fail++; } else printf("extra_build_props=ok\n");
  if (overlay_power_supply()) { printf("power_supply=fail:%s\n", strerror(errno)); fail++; } else printf("power_supply=ok\n");
  if (overlay_thermal_zones()) { printf("thermal_zones=fail:%s\n", strerror(errno)); fail++; } else printf("thermal_zones=ok\n");
  if (overlay_framebuffer()) { printf("framebuffer=fail:%s\n", strerror(errno)); fail++; } else printf("framebuffer=ok\n");
  if (overlay_backlight_leds()) { printf("backlight_leds=fail:%s\n", strerror(errno)); fail++; } else printf("backlight_leds=ok\n");
  if (overlay_usb_identity()) { printf("usb_identity=fail:%s\n", strerror(errno)); fail++; } else printf("usb_identity=ok\n");
  if (overlay_input_devices()) { printf("input_devices=fail:%s\n", strerror(errno)); fail++; } else printf("input_devices=ok\n");
  if (overlay_network_identity_files()) { printf("network_identity=fail:%s\n", strerror(errno)); fail++; } else printf("network_identity=ok\n");
  return fail ? 1 : 0;
}
static int revert(void) {
  int fail = 0;
  char *mi = read_mountinfo_limited();
  fail += cleanup_legacy_cpu_detail_mounts(mi);
  free(mi);
  for (int i=0; overlay_targets[i]; ++i) { if (umount2(overlay_targets[i], MNT_DETACH) && errno != EINVAL) { printf("%s=umount_fail:%s\n", overlay_targets[i], strerror(errno)); fail++; } else { unmark_mounted(overlay_targets[i]); printf("%s=umount_ok\n", overlay_targets[i]); } }
  return fail ? 1 : 0;
}
int main(int argc, char **argv) {
  const char *cmd = argc > 1 ? argv[1] : "status";
  if (!strcmp(cmd, "apply")) return apply();
  if (!strcmp(cmd, "revert")) return revert();
  if (!strcmp(cmd, "cleanup")) return cleanup();
  if (!strcmp(cmd, "status-json")) return status_json();
  printf("xenoid-overlay status\n");
  status_one("/proc/sys/kernel/random/boot_id"); status_one("/proc/sys/kernel/random/uuid"); status_one("/proc/sys/kernel/random/entropy_avail"); status_one("/sys/class/net/eth0/address"); status_one("/sys/class/net/eth0/mtu"); status_one("/sys/class/dmi/id/product_name"); status_one("/proc/device-tree/model"); status_one("/sys/firmware/devicetree/base/model"); status_one("/sys/fs/selinux/enforce"); status_one("/sys/fs/selinux/policyvers"); status_one("/sys/hypervisor/type"); status_one("/proc/cpuinfo"); status_one("/proc/bus/input/devices"); status_one("/proc/fb"); status_one("/sys/class/graphics/fb0/name"); status_one("/sys/class/power_supply/battery/capacity"); status_one("/sys/class/thermal/thermal_zone0/temp"); status_one("/sys/class/backlight/panel0-backlight/max_brightness");
  return 0;
}
