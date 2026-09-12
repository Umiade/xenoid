#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include "xenoid_power_supply.h"

#define OVERLAY_DIR "/xenoid/overlay.d"
#define PROFILE_DIR "/data/local/tmp/xenoid-profile"

#define XENOID_KERNEL_RELEASE "5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab9012097"

static int ensure_dir(const char *p) {
  if (mkdir(p, 0777) == 0) return 0;
  if (errno != EEXIST) return -1;
  struct stat st;
  if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
  errno = ENOTDIR;
  return -1;
}
static int child_path(char *out, size_t n, const char *parent, const char *child) {
  int written = snprintf(out, n, "%s/%s", parent, child);
  if (written < 0 || (size_t)written >= n) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}
static int write_text(const char *path, const char *s);
static int write_child_text(const char *parent, const char *child, const char *content) {
  char path[PATH_MAX];
  return child_path(path, sizeof(path), parent, child) || write_text(path, content);
}
static int ensure_symlink_value(const char *target, const char *path) {
  char current[PATH_MAX];
  ssize_t size = readlink(path, current, sizeof(current) - 1);
  if (size >= 0) {
    current[size] = 0;
    if (!strcmp(current, target)) return 0;
  }
  struct stat st;
  if (lstat(path, &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
      errno = EISDIR;
      return -1;
    }
    if (unlink(path)) return -1;
  } else if (errno != ENOENT) {
    return -1;
  }
  return symlink(target, path);
}
static int clear_directory_entries(const char *path) {
  DIR *dir = opendir(path);
  if (!dir) return -1;
  int fail = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    char child[PATH_MAX];
    if (child_path(child, sizeof(child), path, entry->d_name) || unlink(child)) fail = 1;
  }
  closedir(dir);
  return fail ? -1 : 0;
}
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

/* Stock procfs exposes read-only nodes at 0444, with the per-pid uid/gid map
 * and attr files writable at 0644. Staging files must carry the stock mode
 * or stat() on the bind-mounted node betrays the overlay. */
static int staging_mode_for(const char *target) {
  if (strncmp(target, "/proc/", 6) != 0) return -1;
  if (strncmp(target, "/proc/sys/", 10) == 0) return -1; /* sysctl: 0644 stock */
  if (strstr(target, "/uid_map") || strstr(target, "/gid_map")) return 0644;
  if (strstr(target, "/attr/")) return 0644;
  return 0444;
}
static char *first_or_default(const char *path, const char *fallback) {
  char *s = read_all(path); if (!s || !s[0]) { free(s); return strdup(fallback); }
  size_t n = strcspn(s, "\r\n"); char *o = calloc(1, n + 2); if (!o) { free(s); return strdup(fallback); }
  memcpy(o, s, n); o[n] = '\n'; o[n+1] = 0; free(s); return o;
}



static char *read_mountinfo(void) {
  int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  size_t cap = 1 << 20, n = 0;
  char *b = calloc(1, cap + 1);
  if (!b) { close(fd); return NULL; }
  for (;;) {
    if (n == cap) {
      if (cap > SIZE_MAX / 2 - 1) { free(b); close(fd); errno = EOVERFLOW; return NULL; }
      cap *= 2;
      char *nb = realloc(b, cap + 1);
      if (!nb) { free(b); close(fd); return NULL; }
      b = nb;
    }
    ssize_t r = read(fd, b + n, cap - n);
    if (r < 0) {
      if (errno == EINTR) continue;
      free(b);
      close(fd);
      return NULL;
    }
    if (r == 0) break;
    n += (size_t)r;
  }
  close(fd);
  b[n] = 0;
  return b;
}

static const char *overlay_targets[] = {
  "/vendor/odm_dlkm/etc/build.prop", "/vendor/vendor_dlkm/etc/build.prop", "/vendor/odm/etc/build.prop",
  "/system/system_dlkm/etc/build.prop", "/system/system_ext/etc/build.prop", "/system/product/etc/build.prop",
  "/vendor/build.prop", "/system/build.prop",
  "/sys/block", "/sys/class/block", "/sys/dev/block", "/sys/devices/virtual/block",
  "/proc/partitions", "/proc/diskstats", "/proc/modules", "/proc/interrupts", "/proc/iomem", "/proc/ioports", "/proc/kallsyms",
  "/proc/devices", "/proc/misc", "/proc/tty/drivers",
  "/sys/class/rtc/rtc0/name", "/sys/class/rtc/rtc0/hctosys",
  "/sys/devices/system/cpu",
  "/proc/filesystems", "/proc/swaps",
  "/proc/cgroups", "/proc/1/status", "/proc/1/uid_map", "/proc/1/gid_map", "/proc/1/attr/current",
  "/proc/1/cgroup", "/proc/1/mounts", "/proc/1/mountinfo", "/proc/1/mountstats",
  /* Reader-relative procfs paths are handled in the process view rather than
     by fixed-path bind mounts. This includes /proc/{self,net}. */
  "/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/version",
  "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict", "/proc/sys/kernel/perf_event_paranoid",
  "/proc/sys/kernel/modules_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/kernel/yama/ptrace_scope",
  "/proc/cmdline", "/proc/version", "/proc/cpuinfo", "/proc/bus/input/devices", "/proc/fb",
  "/proc/sys/kernel/random/boot_id",
  "/proc/sys/kernel/random/uuid", "/proc/sys/kernel/random/entropy_avail", "/proc/sys/kernel/random/poolsize", "/proc/sys/kernel/random/urandom_min_reseed_secs",
  "/sys/class/graphics/fb0/name", "/sys/class/graphics/fb0/virtual_size", "/sys/class/graphics/fb0/bits_per_pixel", "/sys/class/graphics/fb0/modes", "/sys/class/graphics/fb0/refresh_rate",
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
  "/sys/fs/selinux/checkreqprot", "/sys/fs/selinux/status",
  "/sys/devices/virtual/dmi/id/product_name", "/sys/devices/virtual/dmi/id/sys_vendor", "/sys/hypervisor/type",
  "/etc/hosts", "/proc/sys/kernel/hostname", "/proc/sys/kernel/domainname", "/proc/sys/kernel/tainted",
  "/sys/class/power_supply/battery",
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
  "/sys/block/vdb/queue/rotational", "/sys/block/vda/queue/rotational",
  "/sys/block/vdb/size", "/sys/block/vda/size",
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
  char *mi=read_mountinfo();
  if (!mi) { fprintf(stderr, "mountinfo read failed: %s\n", strerror(errno)); return 1; }
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
  char *mi=read_mountinfo();
  if (!mi) { fprintf(stderr, "mountinfo read failed: %s\n", strerror(errno)); return 1; }
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
  char *mi = read_mountinfo();
  if (!mi) return -1;
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
  /* Canonicalize symlinked class paths to device paths; mountinfo records
     the resolved target. */
  char resolved[PATH_MAX];
  const char *t = resolve_overlay_target(target, resolved, sizeof(resolved)) ? resolved : target;
  int mounted = target_mounted(t);
  if (mounted < 0) return -1;
  if (mounted) {
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
  if (mount(fake, t, NULL, flags, NULL) != 0) return -1;
  /* Stop shared-peer-group propagation: /data on redroid sits in a shared
     group, and a bind without MS_PRIVATE propagates into thousands of peer
     mounts (observed 4096 stacked copies per target). */
  if (mount(NULL, t, NULL, MS_PRIVATE, NULL) != 0) {
    int saved_errno = errno;
    umount2(t, MNT_DETACH);
    errno = saved_errno;
    return -1;
  }
  mark_mounted(t);
  return 0;
}

static int overlay_text(const char *name, const char *target, const char *content) {
  char fake[256]; snprintf(fake, sizeof(fake), "%s/%s", OVERLAY_DIR, name);
  int rc = write_text(fake, content); if (rc) return -1;
  { int m = staging_mode_for(target); if (m >= 0) chmod(fake, (mode_t)m); }
  return bind_file(fake, target);
}
static int overlay_bytes_optional(const char *name, const char *target, const void *content, size_t size) {
  if (access(target, F_OK) != 0) return 0;
  char fake[256]; snprintf(fake, sizeof(fake), "%s/%s", OVERLAY_DIR, name);
  int rc = write_bytes(fake, content, size); if (rc) return -1;
  { int m = staging_mode_for(target); if (m >= 0) chmod(fake, (mode_t)m); }
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




static int overlay_existing_file(const char *name, const char *target) {
  char *content = read_all(target);
  if (!content || !content[0]) {
    free(content);
    errno = ENOENT;
    return -1;
  }
  int result = overlay_text(name, target, content);
  free(content);
  return result;
}
static int overlay_build_props(void) {
  int fail = 0;
  fail += overlay_existing_file("system_build.prop", "/system/build.prop") != 0;
  fail += overlay_existing_file("vendor_build.prop", "/vendor/build.prop") != 0;
  return fail ? -1 : 0;
}
static int overlay_extra_build_props(void) {
  int fail = 0;
  fail += overlay_existing_file("product_build.prop", "/system/product/etc/build.prop") != 0;
  fail += overlay_existing_file("system_ext_build.prop", "/system/system_ext/etc/build.prop") != 0;
  fail += overlay_existing_file("system_dlkm_build.prop", "/system/system_dlkm/etc/build.prop") != 0;
  fail += overlay_existing_file("odm_build.prop", "/vendor/odm/etc/build.prop") != 0;
  fail += overlay_existing_file("vendor_dlkm_build.prop", "/vendor/vendor_dlkm/etc/build.prop") != 0;
  fail += overlay_existing_file("odm_dlkm_build.prop", "/vendor/odm_dlkm/etc/build.prop") != 0;
  return fail ? -1 : 0;
}


static int overlay_power_supply(void) {
  const char *target = "/sys/class/power_supply/battery";
  char directory[PATH_MAX], path[PATH_MAX], buf[64];
  struct xenoid_battery_file files[XENOID_BATTERY_FILE_COUNT];
  char *technology = first_or_default(
      PROFILE_DIR "/battery_technology", "Li-ion\n");
  technology[strcspn(technology, "\r\n")] = 0;
  struct xenoid_battery_profile profile = {
    .level = read_long_default(PROFILE_DIR "/battery_level", 83),
    .scale = read_long_default(PROFILE_DIR "/battery_scale", 100),
    .voltage_mv = read_long_default(PROFILE_DIR "/battery_voltage", 4100),
    .temperature_deci_c =
        read_long_default(PROFILE_DIR "/battery_temperature", 310),
    .status = read_long_default(PROFILE_DIR "/battery_status", 3),
    .plugged = read_long_default(PROFILE_DIR "/battery_plugged", 0),
    .health = read_long_default(PROFILE_DIR "/battery_health", 2),
    .present = read_long_default(PROFILE_DIR "/battery_present", 1),
    .technology = technology,
    .capacity_mah =
        read_long_default(PROFILE_DIR "/battery_capacityMah", 5003),
    .minimum_capacity_mah =
        read_long_default(PROFILE_DIR "/battery_minimumCapacityMah", 4905),
    .charge_full_design_uah =
        read_long_default(PROFILE_DIR "/battery_chargeFullDesignUah", 5003000),
    .charge_full_uah =
        read_long_default(PROFILE_DIR "/battery_chargeFullUah", 5003000),
    .charge_counter_uah =
        read_long_default(PROFILE_DIR "/battery_chargeCounterUah", 4152490),
  };
  if (access(target, F_OK) != 0
      || xenoid_render_battery_files(
          &profile, files, XENOID_BATTERY_FILE_COUNT) != 0) {
    free(technology);
    return -1;
  }
  snprintf(directory, sizeof(directory), "%s/power_supply_battery", OVERLAY_DIR);
  if (ensure_dir(directory) || chmod(directory, 0755) != 0) {
    free(technology);
    return -1;
  }
  for (size_t index = 0; index < XENOID_BATTERY_FILE_COUNT; index++) {
    int written = snprintf(
        path, sizeof(path), "%s/%s", directory, files[index].name);
    if (written < 0 || (size_t)written >= sizeof(path)
        || write_text(path, files[index].value)) {
      free(technology);
      return -1;
    }
  }
  free(technology);
  if (bind_file(directory, target)) return -1;

  int fail = 0;
  long_line(buf, sizeof(buf), profile.plugged == 2 ? 1 : 0);
  fail += overlay_text_optional(
      "usb_online", "/sys/class/power_supply/usb/online", buf) != 0;
  long_line(buf, sizeof(buf), profile.plugged == 1 ? 1 : 0);
  fail += overlay_text_optional(
      "ac_online", "/sys/class/power_supply/ac/online", buf) != 0;
  long_line(buf, sizeof(buf), profile.plugged == 4 ? 1 : 0);
  fail += overlay_text_optional(
      "wireless_online", "/sys/class/power_supply/wireless/online", buf) != 0;
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
  const char *bootargs = "console=ttyMSM0 androidboot.hardware=raven androidboot.hardware.sku=G8V0U androidboot.verifiedbootstate=green androidboot.veritymode=enforcing\n";
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

struct storage_profile_view {
  unsigned long long capacity_bytes;
  unsigned long long sector_size_bytes;
  unsigned long long sector_count;
  unsigned int dev_major;
  unsigned int dev_minor;
  char block_device[32];
  char mount_source[128];
  char filesystem[16];
};

static int load_storage_profile(struct storage_profile_view *view) {
  long capacity = read_long_default(
      PROFILE_DIR "/storage_capacityBytes", 128000000000L);
  long sector_size = read_long_default(
      PROFILE_DIR "/storage_sectorSizeBytes", 512);
  long sector_count = read_long_default(
      PROFILE_DIR "/storage_sectorCount", 250000000);
  char *block_device = first_or_default(
      PROFILE_DIR "/storage_blockDevice", "sda\n");
  block_device[strcspn(block_device, "\r\n")] = 0;
  char *mount_source = first_or_default(
      PROFILE_DIR "/storage_mountSource",
      "/dev/block/platform/14700000.ufs/by-name/userdata\n");
  mount_source[strcspn(mount_source, "\r\n")] = 0;
  char *filesystem = first_or_default(
      PROFILE_DIR "/storage_filesystem", "f2fs\n");
  filesystem[strcspn(filesystem, "\r\n")] = 0;
  char block_path[PATH_MAX];
  struct stat block_stat;
  int path_written = snprintf(
      block_path, sizeof(block_path), "/dev/block/%s", block_device);
  int valid = capacity > 0 && sector_size > 0 && sector_count > 0
      && (unsigned long long)sector_count
          <= ~0ULL / (unsigned long long)sector_size
      && (unsigned long long)capacity
          == (unsigned long long)sector_size * (unsigned long long)sector_count
      && capacity == 128000000000L
      && sector_size == 512
      && sector_count == 250000000
      && !strcmp(block_device, "sda")
      && !strcmp(mount_source, "/dev/block/platform/14700000.ufs/by-name/userdata")
      && !strcmp(filesystem, "f2fs")
      && path_written > 0 && (size_t)path_written < sizeof(block_path)
      && stat(block_path, &block_stat) == 0 && S_ISBLK(block_stat.st_mode);
  if (valid) {
    view->capacity_bytes = (unsigned long long)capacity;
    view->sector_size_bytes = (unsigned long long)sector_size;
    view->sector_count = (unsigned long long)sector_count;
    view->dev_major = major(block_stat.st_rdev);
    view->dev_minor = minor(block_stat.st_rdev);
    snprintf(view->block_device, sizeof(view->block_device), "%s", block_device);
    snprintf(view->mount_source, sizeof(view->mount_source), "%s", mount_source);
    snprintf(view->filesystem, sizeof(view->filesystem), "%s", filesystem);
  }
  free(block_device);
  free(mount_source);
  free(filesystem);
  return valid ? 0 : -1;
}

static int overlay_storage_proc(void) {
  struct storage_profile_view view;
  char diskstats[1024], parts[512];
  if (load_storage_profile(&view)) return -1;
  int diskstats_written = snprintf(
      diskstats, sizeof(diskstats),
      "%4u %7u %s 1200 0 65536 120 3400 0 262144 520 0 600 640 0 0 0 0 0 0\n",
      view.dev_major, view.dev_minor, view.block_device);
  int parts_written = snprintf(
      parts, sizeof(parts),
      "major minor  #blocks  name\n\n"
      "%4u %8u %10llu %s\n",
      view.dev_major, view.dev_minor,
      view.capacity_bytes / 1024ULL, view.block_device);
  if (diskstats_written < 0 || (size_t)diskstats_written >= sizeof(diskstats)
      || parts_written < 0 || (size_t)parts_written >= sizeof(parts)) return -1;
  int fail = 0;
  fail += overlay_text("diskstats", "/proc/diskstats", diskstats) != 0;
  fail += overlay_text("partitions", "/proc/partitions", parts) != 0;
  return fail ? -1 : 0;
}

static int overlay_block_sysfs(void) {
  struct storage_profile_view view;
  char stage[PATH_MAX], devices[PATH_MAX], virtual_devices[PATH_MAX];
  char device_root[PATH_MAX], block_root[PATH_MAX], class_root[PATH_MAX];
  char class_block[PATH_MAX], dev_root[PATH_MAX], dev_block[PATH_MAX];
  char sda_root[PATH_MAX], queue_root[PATH_MAX], link_path[PATH_MAX];
  char size[64], sector_size[64], dev_number[64], uevent[256];
  if (load_storage_profile(&view)) return -1;
  if (child_path(stage, sizeof(stage), OVERLAY_DIR, "storage_sysfs")
      || child_path(devices, sizeof(devices), stage, "devices")
      || child_path(virtual_devices, sizeof(virtual_devices), devices, "virtual")
      || child_path(device_root, sizeof(device_root), virtual_devices, "block")
      || child_path(sda_root, sizeof(sda_root), device_root, view.block_device)
      || child_path(queue_root, sizeof(queue_root), sda_root, "queue")
      || child_path(block_root, sizeof(block_root), stage, "block")
      || child_path(class_root, sizeof(class_root), stage, "class")
      || child_path(class_block, sizeof(class_block), class_root, "block")
      || child_path(dev_root, sizeof(dev_root), stage, "dev")
      || child_path(dev_block, sizeof(dev_block), dev_root, "block")) return -1;
  if (ensure_dir(stage) || ensure_dir(devices) || ensure_dir(virtual_devices)
      || ensure_dir(device_root) || ensure_dir(sda_root) || ensure_dir(queue_root)
      || ensure_dir(block_root) || ensure_dir(class_root) || ensure_dir(class_block)
      || ensure_dir(dev_root) || ensure_dir(dev_block)) return -1;
  if (chmod(device_root, 0755) || chmod(sda_root, 0755)
      || chmod(queue_root, 0755) || chmod(block_root, 0755)
      || chmod(class_block, 0755) || chmod(dev_block, 0755)) return -1;
  int size_written = snprintf(size, sizeof(size), "%llu\n", view.sector_count);
  int sector_written = snprintf(
      sector_size, sizeof(sector_size), "%llu\n", view.sector_size_bytes);
  int dev_written = snprintf(
      dev_number, sizeof(dev_number), "%u:%u\n", view.dev_major, view.dev_minor);
  int uevent_written = snprintf(
      uevent, sizeof(uevent),
      "MAJOR=%u\nMINOR=%u\nDEVNAME=%s\nDEVTYPE=disk\n",
      view.dev_major, view.dev_minor, view.block_device);
  if (size_written < 0 || (size_t)size_written >= sizeof(size)
      || sector_written < 0 || (size_t)sector_written >= sizeof(sector_size)
      || dev_written < 0 || (size_t)dev_written >= sizeof(dev_number)
      || uevent_written < 0 || (size_t)uevent_written >= sizeof(uevent)) return -1;
  int fail = 0;
  fail += write_child_text(sda_root, "size", size) != 0;
  fail += write_child_text(sda_root, "dev", dev_number) != 0;
  fail += write_child_text(sda_root, "removable", "0\n") != 0;
  fail += write_child_text(sda_root, "ro", "0\n") != 0;
  fail += write_child_text(sda_root, "range", "16\n") != 0;
  fail += write_child_text(sda_root, "capability", "50\n") != 0;
  fail += write_child_text(sda_root, "inflight", "0 0\n") != 0;
  fail += write_child_text(
      sda_root, "stat", "1200 0 65536 120 3400 0 262144 520 0 600 640 0 0 0 0 0 0\n") != 0;
  fail += write_child_text(sda_root, "uevent", uevent) != 0;
  fail += write_child_text(queue_root, "rotational", "0\n") != 0;
  fail += write_child_text(queue_root, "logical_block_size", sector_size) != 0;
  fail += write_child_text(queue_root, "physical_block_size", sector_size) != 0;
  fail += write_child_text(queue_root, "minimum_io_size", sector_size) != 0;
  fail += write_child_text(queue_root, "optimal_io_size", "0\n") != 0;
  fail += write_child_text(queue_root, "read_ahead_kb", "128\n") != 0;
  fail += write_child_text(queue_root, "nr_requests", "128\n") != 0;
  fail += write_child_text(queue_root, "scheduler", "[none] mq-deadline\n") != 0;
  if (fail) return -1;
  if (child_path(link_path, sizeof(link_path), block_root, view.block_device)
      || ensure_symlink_value("../devices/virtual/block/sda", link_path)
      || child_path(link_path, sizeof(link_path), class_block, view.block_device)
      || ensure_symlink_value("../../devices/virtual/block/sda", link_path)
      || clear_directory_entries(dev_block)) return -1;
  char dev_link_name[64];
  int link_written = snprintf(
      dev_link_name, sizeof(dev_link_name), "%u:%u", view.dev_major, view.dev_minor);
  if (link_written < 0 || (size_t)link_written >= sizeof(dev_link_name)
      || child_path(link_path, sizeof(link_path), dev_block, dev_link_name)
      || ensure_symlink_value("../../devices/virtual/block/sda", link_path)) return -1;
  fail += bind_file(device_root, "/sys/devices/virtual/block") != 0;
  fail += bind_file(block_root, "/sys/block") != 0;
  fail += bind_file(class_block, "/sys/class/block") != 0;
  fail += bind_file(dev_block, "/sys/dev/block") != 0;
  return fail ? -1 : 0;
}

struct memory_profile_view {
  unsigned long long total_kib;
  unsigned long long swap_kib;
  unsigned long long free_kib;
  unsigned long long available_kib;
  unsigned long long buffers_kib;
  unsigned long long cached_kib;
  unsigned long long active_anon_kib;
  unsigned long long inactive_anon_kib;
  unsigned long long active_file_kib;
  unsigned long long inactive_file_kib;
  unsigned long long anon_kib;
  unsigned long long mapped_kib;
  unsigned long long shmem_kib;
  unsigned long long slab_reclaimable_kib;
  unsigned long long slab_unreclaimable_kib;
  unsigned long long kernel_stack_kib;
  unsigned long long page_tables_kib;
};

static void load_memory_profile(struct memory_profile_view *view) {
  const unsigned long long fallback_kib = 12ULL * 1024ULL * 1024ULL;
  long total_kib = read_long_default(PROFILE_DIR "/memory_totalKiB", (long)fallback_kib);
  long total_bytes = read_long_default(
      PROFILE_DIR "/memory_totalBytes", (long)(fallback_kib * 1024ULL));
  long swap_bytes = read_long_default(PROFILE_DIR "/memory_swapBytes", 0);
  if (total_kib < 1048576 || total_kib % 4 != 0
      || total_bytes < 0 || (unsigned long long)total_bytes != (unsigned long long)total_kib * 1024ULL) {
    total_kib = (long)fallback_kib;
  }
  if (swap_bytes < 0 || swap_bytes % 1024 != 0) swap_bytes = 0;
  memset(view, 0, sizeof(*view));
  view->total_kib = (unsigned long long)total_kib;
  view->swap_kib = (unsigned long long)swap_bytes / 1024ULL;
  view->free_kib = view->total_kib / 2ULL;
  view->available_kib = view->total_kib * 2ULL / 3ULL;
  view->buffers_kib = view->total_kib / 96ULL;
  view->cached_kib = view->total_kib / 6ULL;
  view->active_anon_kib = view->total_kib / 8ULL;
  view->inactive_anon_kib = view->total_kib / 24ULL;
  view->active_file_kib = view->total_kib / 12ULL;
  view->inactive_file_kib = view->total_kib / 12ULL;
  view->anon_kib = view->active_anon_kib + view->inactive_anon_kib;
  view->mapped_kib = view->total_kib / 24ULL;
  view->shmem_kib = view->total_kib / 48ULL;
  view->slab_reclaimable_kib = view->total_kib / 48ULL;
  view->slab_unreclaimable_kib = view->total_kib / 96ULL;
  view->kernel_stack_kib = view->total_kib / 768ULL;
  view->page_tables_kib = view->total_kib / 384ULL;
}

static int overlay_meminfo(void) {
  struct memory_profile_view view;
  char meminfo[4096];
  load_memory_profile(&view);
  unsigned long long active_kib = view.active_anon_kib + view.active_file_kib;
  unsigned long long inactive_kib = view.inactive_anon_kib + view.inactive_file_kib;
  unsigned long long slab_kib =
      view.slab_reclaimable_kib + view.slab_unreclaimable_kib;
  unsigned long long commit_limit_kib = view.total_kib / 2ULL + view.swap_kib;
  unsigned long long committed_kib = view.total_kib * 5ULL / 12ULL;
  int written = snprintf(
      meminfo, sizeof(meminfo),
      "MemTotal:       %10llu kB\n"
      "MemFree:        %10llu kB\n"
      "MemAvailable:   %10llu kB\n"
      "Buffers:        %10llu kB\n"
      "Cached:         %10llu kB\n"
      "SwapCached:              0 kB\n"
      "Active:         %10llu kB\n"
      "Inactive:       %10llu kB\n"
      "Active(anon):   %10llu kB\n"
      "Inactive(anon): %10llu kB\n"
      "Active(file):   %10llu kB\n"
      "Inactive(file): %10llu kB\n"
      "Unevictable:             0 kB\n"
      "Mlocked:                 0 kB\n"
      "SwapTotal:      %10llu kB\n"
      "SwapFree:       %10llu kB\n"
      "Dirty:                 128 kB\n"
      "Writeback:               0 kB\n"
      "AnonPages:      %10llu kB\n"
      "Mapped:         %10llu kB\n"
      "Shmem:          %10llu kB\n"
      "Slab:           %10llu kB\n"
      "SReclaimable:   %10llu kB\n"
      "SUnreclaim:     %10llu kB\n"
      "KernelStack:    %10llu kB\n"
      "PageTables:     %10llu kB\n"
      "CommitLimit:    %10llu kB\n"
      "Committed_AS:   %10llu kB\n",
      view.total_kib, view.free_kib, view.available_kib, view.buffers_kib,
      view.cached_kib, active_kib, inactive_kib, view.active_anon_kib,
      view.inactive_anon_kib, view.active_file_kib, view.inactive_file_kib,
      view.swap_kib, view.swap_kib, view.anon_kib, view.mapped_kib,
      view.shmem_kib, slab_kib, view.slab_reclaimable_kib,
      view.slab_unreclaimable_kib, view.kernel_stack_kib,
      view.page_tables_kib, commit_limit_kib, committed_kib);
  if (written < 0 || (size_t)written >= sizeof(meminfo)) return -1;
  return overlay_text("meminfo", "/proc/meminfo", meminfo);
}

static int append_unsigned_column(
    char *buffer, size_t capacity, size_t *used, unsigned long long value) {
  int written = snprintf(buffer + *used, capacity - *used, " %10llu", value);
  if (written < 0 || (size_t)written >= capacity - *used) return -1;
  *used += (size_t)written;
  return 0;
}

static int overlay_memory_proc_details(void) {
  struct memory_profile_view view;
  char vmstat[2048], zoneinfo[1024], buddyinfo[1024], pagetypeinfo[4096];
  unsigned long long buddy[11] = {0};
  load_memory_profile(&view);
  const unsigned long long page_kib = 4ULL;
  unsigned long long total_pages = view.total_kib / page_kib;
  unsigned long long free_pages = view.free_kib / page_kib;
  unsigned long long managed_pages = total_pages - total_pages / 48ULL;
  unsigned long long target_small_pages = free_pages / 64ULL;
  unsigned long long remaining_pages = free_pages;
  for (int order = 0; order < 10; order++) {
    buddy[order] = target_small_pages >> order;
    remaining_pages -= buddy[order] << order;
  }
  for (int order = 10; order >= 0; order--) {
    unsigned long long count = remaining_pages >> order;
    buddy[order] += count;
    remaining_pages -= count << order;
  }
  if (remaining_pages != 0) return -1;

  int written = snprintf(
      vmstat, sizeof(vmstat),
      "nr_free_pages %llu\n"
      "nr_zone_inactive_anon %llu\n"
      "nr_zone_active_anon %llu\n"
      "nr_zone_inactive_file %llu\n"
      "nr_zone_active_file %llu\n"
      "nr_zone_unevictable 0\n"
      "nr_mlock 0\n"
      "nr_anon_pages %llu\n"
      "nr_mapped %llu\n"
      "nr_file_pages %llu\n"
      "nr_shmem %llu\n"
      "nr_dirty 32\n"
      "nr_writeback 0\n"
      "nr_slab_reclaimable %llu\n"
      "nr_slab_unreclaimable %llu\n"
      "nr_kernel_stack %llu\n"
      "nr_page_table_pages %llu\n"
      "pgpgin 120000\n"
      "pgpgout 220000\n"
      "pswpin 0\n"
      "pswpout 0\n"
      "pgfault 500000\n"
      "pgmajfault 120\n",
      free_pages, view.inactive_anon_kib / page_kib,
      view.active_anon_kib / page_kib, view.inactive_file_kib / page_kib,
      view.active_file_kib / page_kib, view.anon_kib / page_kib,
      view.mapped_kib / page_kib, view.cached_kib / page_kib,
      view.shmem_kib / page_kib, view.slab_reclaimable_kib / page_kib,
      view.slab_unreclaimable_kib / page_kib,
      view.kernel_stack_kib / page_kib, view.page_tables_kib / page_kib);
  if (written < 0 || (size_t)written >= sizeof(vmstat)) return -1;

  written = snprintf(
      zoneinfo, sizeof(zoneinfo),
      "Node 0, zone   Normal\n"
      "  pages free     %llu\n"
      "        min      %llu\n"
      "        low      %llu\n"
      "        high     %llu\n"
      "        spanned  %llu\n"
      "        present  %llu\n"
      "        managed  %llu\n"
      "  start_pfn:     0\n",
      free_pages, total_pages / 384ULL, total_pages / 192ULL,
      total_pages / 128ULL, total_pages, total_pages, managed_pages);
  if (written < 0 || (size_t)written >= sizeof(zoneinfo)) return -1;

  size_t used = 0;
  written = snprintf(buddyinfo, sizeof(buddyinfo), "Node 0, zone   Normal");
  if (written < 0 || (size_t)written >= sizeof(buddyinfo)) return -1;
  used = (size_t)written;
  for (int order = 0; order <= 10; order++) {
    if (append_unsigned_column(buddyinfo, sizeof(buddyinfo), &used, buddy[order])) return -1;
  }
  if (used + 2 > sizeof(buddyinfo)) return -1;
  buddyinfo[used++] = '\n';
  buddyinfo[used] = 0;

  written = snprintf(
      pagetypeinfo, sizeof(pagetypeinfo),
      "Page block order: 9\n"
      "Pages per block:  512\n\n"
      "Free pages count per migrate type at order");
  if (written < 0 || (size_t)written >= sizeof(pagetypeinfo)) return -1;
  used = (size_t)written;
  for (int order = 0; order <= 10; order++) {
    if (append_unsigned_column(pagetypeinfo, sizeof(pagetypeinfo), &used, order)) return -1;
  }
  if (used + 2 > sizeof(pagetypeinfo)) return -1;
  pagetypeinfo[used++] = '\n';
  pagetypeinfo[used] = 0;
  static const char *migrate_types[3] = {"Unmovable  ", "Movable    ", "Reclaimable"};
  for (int type = 0; type < 3; type++) {
    written = snprintf(
        pagetypeinfo + used, sizeof(pagetypeinfo) - used,
        "Node    0, zone   Normal, type %s",
        migrate_types[type]);
    if (written < 0 || (size_t)written >= sizeof(pagetypeinfo) - used) return -1;
    used += (size_t)written;
    for (int order = 0; order <= 10; order++) {
      unsigned long long quarter = buddy[order] / 4ULL;
      unsigned long long count = type == 1 ? buddy[order] - 2ULL * quarter : quarter;
      if (append_unsigned_column(
              pagetypeinfo, sizeof(pagetypeinfo), &used, count)) return -1;
    }
    if (used + 2 > sizeof(pagetypeinfo)) return -1;
    pagetypeinfo[used++] = '\n';
    pagetypeinfo[used] = 0;
  }

  int fail = 0;
  fail += overlay_text_optional("proc_vmstat", "/proc/vmstat", vmstat) != 0;
  fail += overlay_text_optional("proc_zoneinfo", "/proc/zoneinfo", zoneinfo) != 0;
  fail += overlay_text_optional("proc_buddyinfo", "/proc/buddyinfo", buddyinfo) != 0;
  fail += overlay_text_optional("proc_pagetypeinfo", "/proc/pagetypeinfo", pagetypeinfo) != 0;
  return fail ? -1 : 0;
}

static int overlay_cpu_proc_stats(void) {
  int fail = 0;
  struct timespec realtime;
  struct timespec boottime;
  char stat[1024];
  long long boot_epoch;
  int written;
  if (clock_gettime(CLOCK_REALTIME, &realtime) ||
      clock_gettime(CLOCK_BOOTTIME, &boottime)) return -1;
  boot_epoch = (long long)realtime.tv_sec - (long long)boottime.tv_sec -
    (realtime.tv_nsec < boottime.tv_nsec);
  written = snprintf(
    stat, sizeof(stat),
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
    "btime %lld\n"
    "processes 12345\n"
    "procs_running 1\n"
    "procs_blocked 0\n",
    boot_epoch);
  if (written < 0 || (size_t)written >= sizeof(stat)) return -1;
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
  fail += overlay_text_optional("kernel_osrelease", "/proc/sys/kernel/osrelease", XENOID_KERNEL_RELEASE "\n") != 0;
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
  struct memory_profile_view memory;
  struct storage_profile_view storage;
  char mounts[2048], mountinfo[2048];
  load_memory_profile(&memory);
  if (load_storage_profile(&storage)) return -1;
  int mounts_written = snprintf(
      mounts, sizeof(mounts),
      "tmpfs / tmpfs rw,seclabel,nosuid,nodev,relatime,size=%lluk,mode=755 0 0\n"
      "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
      "sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0\n"
      "selinuxfs /sys/fs/selinux selinuxfs rw,seclabel,relatime 0 0\n"
      "devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,mode=600,ptmxmode=000 0 0\n"
      "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
      "/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0\n"
      "%s /data %s rw,seclabel,nosuid,nodev,noatime,discard,inlinecrypt,atgc,checkpoint_merge,reserve_root=32768,resgid=1065,fsync_mode=nobarrier 0 0\n",
      memory.total_kib, storage.mount_source, storage.filesystem);
  int mountinfo_written = snprintf(
      mountinfo, sizeof(mountinfo),
      "21 0 0:20 / / rw,seclabel shared:1 - tmpfs tmpfs rw,seclabel,size=%lluk,mode=755\n"
      "22 21 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw\n"
      "23 21 0:7 / /sys rw,seclabel,nosuid,nodev,noexec,relatime shared:3 - sysfs sysfs rw,seclabel\n"
      "24 23 0:16 / /sys/fs/selinux rw,seclabel,relatime shared:6 - selinuxfs selinuxfs rw\n"
      "25 21 259:0 / /system ro,seclabel,relatime shared:4 - ext4 /dev/block/dm-0 ro\n"
      "26 21 259:1 / /vendor ro,seclabel,relatime shared:5 - ext4 /dev/block/dm-1 ro\n"
      "27 21 %u:%u / /data rw,seclabel,nosuid,nodev,noatime - %s %s rw,discard,inlinecrypt,atgc,checkpoint_merge,reserve_root=32768,resgid=1065,fsync_mode=nobarrier\n",
      memory.total_kib, storage.dev_major, storage.dev_minor,
      storage.filesystem, storage.mount_source);
  if (mounts_written < 0 || (size_t)mounts_written >= sizeof(mounts)
      || mountinfo_written < 0 || (size_t)mountinfo_written >= sizeof(mountinfo)) {
    return -1;
  }
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
  {
    char mountstats[512];
    int mountstats_written = snprintf(
        mountstats, sizeof(mountstats),
        "device tmpfs mounted on / with fstype tmpfs\n"
        "device selinuxfs mounted on /sys/fs/selinux with fstype selinuxfs\n"
        "device %s mounted on /data with fstype %s\n",
        storage.mount_source, storage.filesystem);
    if (mountstats_written < 0
        || (size_t)mountstats_written >= sizeof(mountstats)) return -1;
    fail += overlay_text_optional(
        "proc_1_mountstats", "/proc/1/mountstats", mountstats) != 0;
  }
  return fail ? -1 : 0;
}


struct cpu_profile_view {
  char implementer[16];
  char part[8][16];
  char model[8][65];
  long minimum_khz[8];
  long maximum_khz[8];
};

static void profile_line_value(const char *leaf, const char *fallback, char *out, size_t out_size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), PROFILE_DIR "/%s", leaf);
  char *value = first_or_default(path, fallback);
  value[strcspn(value, "\r\n")] = 0;
  snprintf(out, out_size, "%s", value[0] ? value : fallback);
  free(value);
}

static void load_cpu_profile(struct cpu_profile_view *view) {
  static const char *fallback_parts[8] = {
    "0xd05", "0xd05", "0xd05", "0xd05", "0xd0b", "0xd0b", "0xd44", "0xd44"
  };
  static const char *fallback_models[8] = {
    "Cortex-A55", "Cortex-A55", "Cortex-A55", "Cortex-A55",
    "Cortex-A76", "Cortex-A76", "Cortex-X1", "Cortex-X1"
  };
  static const long fallback_minimums[8] = {
    300000, 300000, 300000, 300000, 400000, 400000, 500000, 500000
  };
  static const long fallback_maximums[8] = {
    1800000, 1800000, 1800000, 1800000, 2253000, 2253000, 2802000, 2802000
  };
  char leaf[96];
  memset(view, 0, sizeof(*view));
  profile_line_value("cpu_implementer", "0x41", view->implementer, sizeof(view->implementer));
  for (int cpu = 0; cpu < 8; cpu++) {
    snprintf(leaf, sizeof(leaf), "cpu_%d_part", cpu);
    profile_line_value(leaf, fallback_parts[cpu], view->part[cpu], sizeof(view->part[cpu]));
    snprintf(leaf, sizeof(leaf), "cpu_%d_model", cpu);
    profile_line_value(leaf, fallback_models[cpu], view->model[cpu], sizeof(view->model[cpu]));
    snprintf(leaf, sizeof(leaf), PROFILE_DIR "/cpu_%d_minimumFrequencyKhz", cpu);
    view->minimum_khz[cpu] = read_long_default(leaf, fallback_minimums[cpu]);
    snprintf(leaf, sizeof(leaf), PROFILE_DIR "/cpu_%d_maximumFrequencyKhz", cpu);
    view->maximum_khz[cpu] = read_long_default(leaf, fallback_maximums[cpu]);
    if (view->minimum_khz[cpu] < 1 || view->minimum_khz[cpu] > 10000000) {
      view->minimum_khz[cpu] = fallback_minimums[cpu];
    }
    if (view->maximum_khz[cpu] < view->minimum_khz[cpu]
        || view->maximum_khz[cpu] > 10000000) {
      view->maximum_khz[cpu] = fallback_maximums[cpu];
    }
  }
}

static int write_long_file(const char *path, long value) {
  char line[64];
  long_line(line, sizeof(line), value);
  return write_text(path, line);
}

static int write_cpu_policy(
    const char *directory, const char *cpus, long minimum_khz, long maximum_khz) {
  char path[PATH_MAX], line[128];
  if (ensure_dir(directory)) return -1;
#define WRITE_POLICY_TEXT(name, value) \
  do { snprintf(path, sizeof(path), "%s/" name, directory); if (write_text(path, value)) return -1; } while (0)
#define WRITE_POLICY_LONG(name, value) \
  do { snprintf(path, sizeof(path), "%s/" name, directory); if (write_long_file(path, value)) return -1; } while (0)
  WRITE_POLICY_TEXT("affected_cpus", cpus);
  WRITE_POLICY_TEXT("related_cpus", cpus);
  WRITE_POLICY_LONG("cpuinfo_min_freq", minimum_khz);
  WRITE_POLICY_LONG("cpuinfo_max_freq", maximum_khz);
  WRITE_POLICY_LONG("scaling_min_freq", minimum_khz);
  WRITE_POLICY_LONG("scaling_max_freq", maximum_khz);
  WRITE_POLICY_LONG("cpuinfo_cur_freq", minimum_khz);
  WRITE_POLICY_LONG("scaling_cur_freq", minimum_khz);
  WRITE_POLICY_TEXT("scaling_available_governors", "schedutil performance\n");
  WRITE_POLICY_TEXT("scaling_governor", "schedutil\n");
  snprintf(line, sizeof(line), "%ld %ld\n", minimum_khz, maximum_khz);
  WRITE_POLICY_TEXT("scaling_available_frequencies", line);
  snprintf(path, sizeof(path), "%s/stats", directory);
  if (ensure_dir(path)) return -1;
  snprintf(path, sizeof(path), "%s/stats/time_in_state", directory);
  snprintf(line, sizeof(line), "%ld 1000\n%ld 1000\n", minimum_khz, maximum_khz);
  if (write_text(path, line)) return -1;
#undef WRITE_POLICY_LONG
#undef WRITE_POLICY_TEXT
  return 0;
}

static int overlay_cpu_sysfs(void) {
  static const int policy_leaders[3] = {0, 4, 6};
  static const char *policy_cpu_lists[3] = {"0 1 2 3\n", "4 5\n", "6 7\n"};
  static const char *cluster_ranges[3] = {"0-3\n", "4-5\n", "6-7\n"};
  struct cpu_profile_view view;
  const char *target = "/sys/devices/system/cpu";
  char path[PATH_MAX], directory[PATH_MAX], line[64];
  load_cpu_profile(&view);
  if (access(target, F_OK) != 0) return -1;
  if (umount2(target, MNT_DETACH) != 0 && errno != EINVAL) return -1;
  if (mount("tmpfs", target, "tmpfs", 0, "mode=755")) return -1;
  if (mount(NULL, target, NULL, MS_PRIVATE | MS_REC, NULL)) return -1;
  if (write_text("/sys/devices/system/cpu/online", "0-7\n")
      || write_text("/sys/devices/system/cpu/possible", "0-7\n")
      || write_text("/sys/devices/system/cpu/present", "0-7\n")
      || write_text("/sys/devices/system/cpu/offline", "\n")
      || write_text("/sys/devices/system/cpu/isolated", "\n")
      || write_text("/sys/devices/system/cpu/kernel_max", "7\n")) return -1;

  if (ensure_dir("/sys/devices/system/cpu/cpufreq")) return -1;
  for (int cluster = 0; cluster < 3; cluster++) {
    int leader = policy_leaders[cluster];
    snprintf(directory, sizeof(directory), "/sys/devices/system/cpu/cpufreq/policy%d", leader);
    if (write_cpu_policy(directory, policy_cpu_lists[cluster],
                         view.minimum_khz[leader], view.maximum_khz[leader])) return -1;
  }

  for (int cpu = 0; cpu < 8; cpu++) {
    int cluster = cpu < 4 ? 0 : (cpu < 6 ? 1 : 2);
    int leader = policy_leaders[cluster];
    snprintf(directory, sizeof(directory), "/sys/devices/system/cpu/cpu%d", cpu);
    if (ensure_dir(directory)) return -1;
    snprintf(path, sizeof(path), "%s/topology", directory);
    if (ensure_dir(path)) return -1;
    snprintf(path, sizeof(path), "%s/topology/core_id", directory);
    if (write_long_file(path, cpu)) return -1;
    snprintf(path, sizeof(path), "%s/topology/cluster_id", directory);
    if (write_long_file(path, cluster)) return -1;
    snprintf(path, sizeof(path), "%s/topology/physical_package_id", directory);
    if (write_text(path, "0\n")) return -1;
    snprintf(path, sizeof(path), "%s/topology/thread_siblings_list", directory);
    if (write_long_file(path, cpu)) return -1;
    snprintf(path, sizeof(path), "%s/topology/core_cpus_list", directory);
    if (write_long_file(path, cpu)) return -1;
    snprintf(path, sizeof(path), "%s/topology/cluster_cpus_list", directory);
    if (write_text(path, cluster_ranges[cluster])) return -1;
    snprintf(path, sizeof(path), "%s/topology/core_siblings_list", directory);
    if (write_text(path, "0-7\n")) return -1;
    snprintf(path, sizeof(path), "%s/topology/package_cpus_list", directory);
    if (write_text(path, "0-7\n")) return -1;
    snprintf(path, sizeof(path), "%s/cpu_capacity", directory);
    if (write_long_file(path, cluster == 0 ? 512 : (cluster == 1 ? 768 : 1024))) return -1;
    snprintf(path, sizeof(path), "%s/cpufreq", directory);
    snprintf(line, sizeof(line), "../../cpufreq/policy%d", leader);
    if (symlink(line, path)) return -1;
    if (cpu > 0) {
      snprintf(path, sizeof(path), "%s/online", directory);
      if (write_text(path, "1\n")) return -1;
    }
    snprintf(path, sizeof(path), "%s/uevent", directory);
    if (write_text(path, "\n")) return -1;
  }
  mark_mounted(target);
  return 0;
}

static int overlay_cpuinfo(void) {
  struct cpu_profile_view view;
  char cpuinfo[8192];
  size_t used = 0;
  load_cpu_profile(&view);
  int written = snprintf(cpuinfo, sizeof(cpuinfo),
                         "Processor\t: AArch64 Processor rev 1 (aarch64)\n");
  if (written < 0 || (size_t)written >= sizeof(cpuinfo)) return -1;
  used = (size_t)written;
  for (int cpu = 0; cpu < 8; cpu++) {
    written = snprintf(
        cpuinfo + used, sizeof(cpuinfo) - used,
        "processor\t: %d\n"
        "model name\t: %s\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
        "asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n"
        "CPU implementer\t: %s\n"
        "CPU architecture: 8\n"
        "CPU part\t: %s\n\n",
        cpu, view.model[cpu], view.implementer, view.part[cpu]);
    if (written < 0 || (size_t)written >= sizeof(cpuinfo) - used) return -1;
    used += (size_t)written;
  }
  written = snprintf(cpuinfo + used, sizeof(cpuinfo) - used, "Hardware\t: raven\n");
  if (written < 0 || (size_t)written >= sizeof(cpuinfo) - used) return -1;
  return overlay_text("cpuinfo", "/proc/cpuinfo", cpuinfo);
}
static int overlay_version(void) {
  return overlay_text("version", "/proc/version", "Linux version " XENOID_KERNEL_RELEASE " (android-build@abfarm) (Android (9352603) clang version 14.0.7) #1 SMP PREEMPT Wed Oct 5 04:00:00 UTC 2022\n");
}
static int overlay_cmdline(void) {
  char *serial = first_or_default(PROFILE_DIR "/serial", "3A4940E5EDFA\n");
  serial[strcspn(serial, "\r\n")] = 0;
  char cmdline[1024];
  snprintf(cmdline, sizeof(cmdline),
           "console=ttyMSM0 androidboot.hardware=raven androidboot.hardware.sku=G8V0U "
           "androidboot.verifiedbootstate=green androidboot.veritymode=enforcing "
           "androidboot.serialno=%s\n", serial);
  free(serial);
  return overlay_text("cmdline", "/proc/cmdline", cmdline);
}

static int overlay_framebuffer(void) {
  int fail = 0;
  long width = read_long_default(PROFILE_DIR "/display_width", 1440);
  long height = read_long_default(PROFILE_DIR "/display_height", 3120);
  long default_refresh = read_long_default(PROFILE_DIR "/display_defaultRefreshRateHz", 120);
  if (width < 320) width = 1440;
  if (height < 480) height = 3120;
  if (default_refresh != 60 && default_refresh != 120) default_refresh = 120;
  char buf[128];
  fail += overlay_text_optional("proc_fb", "/proc/fb", "0 msmfb\n") != 0;
  fail += overlay_text_optional("fb0_name", "/sys/class/graphics/fb0/name", "msmfb\n") != 0;
  snprintf(buf, sizeof(buf), "%ld,%ld\n", width, height);
  fail += overlay_text_optional("fb0_virtual_size", "/sys/class/graphics/fb0/virtual_size", buf) != 0;
  fail += overlay_text_optional("fb0_bits_per_pixel", "/sys/class/graphics/fb0/bits_per_pixel", "32\n") != 0;
  snprintf(buf, sizeof(buf), "U:%ldx%ldp-60\nU:%ldx%ldp-120\n", width, height, width, height);
  fail += overlay_text_optional("fb0_modes", "/sys/class/graphics/fb0/modes", buf) != 0;
  long_line(buf, sizeof(buf), default_refresh);
  fail += overlay_text_optional("fb0_refresh_rate", "/sys/class/graphics/fb0/refresh_rate", buf) != 0;
  return fail ? -1 : 0;
}

static int overlay_backlight_leds(void) {
  int fail = 0;
  char *brightness = read_all("/sys/class/backlight/panel0-backlight/brightness");
  char *maximum = read_all("/sys/class/backlight/panel0-backlight/max_brightness");
  if (brightness && brightness[0]) {
    fail += overlay_text_optional(
        "panel0_brightness", "/sys/class/backlight/panel0-backlight/brightness", brightness) != 0;
    fail += overlay_text_optional(
        "panel0_actual_brightness", "/sys/class/backlight/panel0-backlight/actual_brightness", brightness) != 0;
    fail += overlay_text_optional(
        "lcd_backlight_brightness", "/sys/class/leds/lcd-backlight/brightness", brightness) != 0;
  }
  if (maximum && maximum[0]) {
    fail += overlay_text_optional(
        "panel0_max_brightness", "/sys/class/backlight/panel0-backlight/max_brightness", maximum) != 0;
    fail += overlay_text_optional(
        "lcd_backlight_max", "/sys/class/leds/lcd-backlight/max_brightness", maximum) != 0;
  }
  free(brightness);
  free(maximum);
  fail += overlay_text_optional("panel0_type", "/sys/class/backlight/panel0-backlight/type", "raw\n") != 0;
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
  if (!touch[0]) {
    free(touch);
    touch = strdup("sec_touchscreen");
    if (!touch) return -1;
  }
  long bus = read_long_default(PROFILE_DIR "/input_busType", 0x18);
  long vendor = read_long_default(PROFILE_DIR "/input_vendorId", 0x04e8);
  long product = read_long_default(PROFILE_DIR "/input_productId", 0x6860);
  long version = read_long_default(PROFILE_DIR "/input_version", 0x0100);
  char body[4096];
  snprintf(body, sizeof(body),
    "I: Bus=%04lx Vendor=%04lx Product=%04lx Version=%04lx\n"
    "N: Name=\"%s\"\n"
    "P: Phys=i2c/sec_touchscreen/input0\n"
    "S: Sysfs=/devices/platform/soc/soc:i2c/sec_touchscreen/input/input0\n"
    "U: Uniq=\n"
    "H: Handlers=event0 \n"
    "B: PROP=2\n"
    "B: EV=b\n"
    "B: KEY=400 0 0 0 0 0\n"
    "B: ABS=67f800001000003\n\n"
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
    "B: KEY=100000 0 0 0\n\n",
    bus, vendor, product, version, touch);
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
  if (overlay_cpu_sysfs()) { printf("cpu_sysfs=fail:%s\n", strerror(errno)); fail++; } else printf("cpu_sysfs=ok\n");
  if (overlay_storage_proc()) { printf("storage_proc=fail:%s\n", strerror(errno)); fail++; } else printf("storage_proc=ok\n");
  if (overlay_block_sysfs()) { printf("block_sysfs=fail:%s\n", strerror(errno)); fail++; } else printf("block_sysfs=ok\n");
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
  char *mi = read_mountinfo();
  if (!mi) { fprintf(stderr, "mountinfo read failed: %s\n", strerror(errno)); return 1; }
  fail += cleanup_legacy_cpu_detail_mounts(mi);
  free(mi);
  for (int i=0; overlay_targets[i]; ++i) { if (umount2(overlay_targets[i], MNT_DETACH) && errno != EINVAL) { printf("%s=umount_fail:%s\n", overlay_targets[i], strerror(errno)); fail++; } else { unmark_mounted(overlay_targets[i]); printf("%s=umount_ok\n", overlay_targets[i]); } }
  return fail ? 1 : 0;
}
static int isolate_sysfs_mounts(void) {
  /* Android keeps /sys in a shared peer group. Without isolating the parent,
     per-instance identity bind mounts propagate into sibling containers. */
  if (mount(NULL, "/sys", NULL, MS_REC | MS_PRIVATE, NULL) == 0) return 0;
  fprintf(stderr, "make-private /sys: %s\n", strerror(errno));
  return -1;
}
int main(int argc, char **argv) {
  const char *cmd = argc > 1 ? argv[1] : "status";
  if (!strcmp(cmd, "apply")) {
    if (isolate_sysfs_mounts()) return 2;
    return apply();
  }
  if (!strcmp(cmd, "revert")) {
    if (isolate_sysfs_mounts()) return 2;
    return revert();
  }
  if (!strcmp(cmd, "cleanup")) {
    if (isolate_sysfs_mounts()) return 2;
    return cleanup();
  }
  if (!strcmp(cmd, "status-json")) return status_json();
  printf("xenoid-overlay status\n");
  status_one("/proc/sys/kernel/random/boot_id"); status_one("/proc/sys/kernel/random/uuid"); status_one("/proc/sys/kernel/random/entropy_avail"); status_one("/sys/class/dmi/id/product_name"); status_one("/proc/device-tree/model"); status_one("/sys/firmware/devicetree/base/model"); status_one("/sys/fs/selinux/enforce"); status_one("/sys/fs/selinux/policyvers"); status_one("/sys/hypervisor/type"); status_one("/proc/cpuinfo"); status_one("/proc/bus/input/devices"); status_one("/proc/fb"); status_one("/sys/class/graphics/fb0/name"); status_one("/sys/class/power_supply/battery/capacity"); status_one("/sys/class/thermal/thermal_zone0/temp"); status_one("/sys/class/backlight/panel0-backlight/max_brightness");
  return 0;
}
