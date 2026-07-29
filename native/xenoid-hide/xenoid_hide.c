// Native runtime policy helper for filesystem and process surfaces.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int exists(const char *p) { return access(p, F_OK) == 0; }
static void json_bool(const char *k, int v, int comma) { printf("\"%s\":%s%s", k, v ? "true" : "false", comma ? "," : ""); }
static void json_str(const char *k, const char *v, int comma) {
  printf("\"%s\":\"", k);
  for (const char *p = v ? v : ""; *p; ++p) { if (*p == '\\' || *p == '"') putchar('\\'); if (*p == '\n') printf("\\n"); else putchar(*p); }
  printf("\"%s", comma ? "," : "");
}

static int process_contains(const char *needle) {
  DIR *d = opendir("/proc");
  if (!d) return 0;
  struct dirent *e;
  char path[256], buf[512];
  int found = 0;
  while ((e = readdir(d))) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
    snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) continue;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) continue;
    buf[n] = 0;
    for (ssize_t i = 0; i < n; i++) if (buf[i] == 0) buf[i] = ' ';
    if (strstr(buf, needle)) { found = 1; break; }
  }
  closedir(d);
  return found;
}

static int write_file(const char *path, const char *data) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return -1;
  size_t len = strlen(data);
  ssize_t n = write(fd, data, len);
  close(fd);
  return n == (ssize_t)len ? 0 : -1;
}

/* Runtime framework file surfaces. */
static int zygisk_files_present(void) {
  return exists("/data/adb/zygisk")
      || exists("/dev/zygisk")
      || exists("/data/adb/modules/zygisk")
      || exists("/data/adb/modules/.core/zygisk")
      || exists("/data/adb/magisk/zygisk");
}

static int hide_path(const char *path) {
  if (!exists(path)) return 0;
  if (unlink(path) == 0) return 0;
  if (chmod(path, 0) == 0) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) close(fd);
  }
  char bak[512];
  snprintf(bak, sizeof(bak), "/data/local/tmp/xenoid-hide/hidden-%s", strrchr(path, '/') ? strrchr(path, '/') + 1 : "marker");
  if (rename(path, bak) == 0) return 0;
  return exists(path) ? -1 : 0;
}

static int hide_one_su(const char *path) {
  return hide_path(path);
}

static int hide_xbin_su(void) {
  const char *xbin = "/system/xbin";
  const char *su = "/system/xbin/su";
  if (!exists(su) && !exists(xbin)) return 0;
  if (hide_one_su(su) == 0 && !exists(su)) return 0;
  if (exists(su)) chmod(su, 0);
  /* redroid ships only su under /system/xbin — cover the directory with an empty bind. */
  const char *empty = "/data/local/tmp/xenoid-hide/empty-xbin";
  mkdir(empty, 0700);
  if (mount(empty, xbin, NULL, MS_BIND, NULL) != 0) return exists(su) ? -1 : 0;
  mount(NULL, xbin, NULL, MS_PRIVATE, NULL);
  return exists(su) ? -1 : 0;
}


static int hide_root_surfaces(void) {
  int fail = 0;
  fail += hide_xbin_su() != 0;
  static const char *su_paths[] = {
    "/system/bin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su", "/system/bin/.ext/.su", NULL
  };
  for (int i = 0; su_paths[i]; i++) fail += hide_one_su(su_paths[i]) != 0 && exists(su_paths[i]);
  return fail ? -1 : 0;
}

static int status(void) {
  int su_system_bin = exists("/system/bin/su");
  int su_system_xbin = exists("/system/xbin/su");
  int magisk_tmp = exists("/sbin/.magisk") || exists("/debug_ramdisk/.magisk");
  int zygisk = zygisk_files_present();
  int frida = process_contains("frida-server") || process_contains("/frida") || process_contains(".fs64");
  int magisk = process_contains("magiskd") || process_contains("/magisk");
  int zygisk_process = process_contains("zygiskd") || process_contains("libzygisk") || process_contains("zygisk_");
  int clean = !(su_system_bin || su_system_xbin || magisk_tmp || zygisk || frida || magisk || zygisk_process);
  printf("{");
  json_str("schema", "dev.xenoid.hide.status/v1", 1);
  json_bool("ok", clean, 1);
  printf("\"files\":{");
  json_bool("su_system_bin", su_system_bin, 1);
  json_bool("su_system_xbin", su_system_xbin, 1);
  json_bool("magisk_tmp", magisk_tmp, 1);
  json_bool("zygisk", zygisk, 0);
  printf("},");
  printf("\"processes\":{");
  json_bool("frida", frida, 1);
  json_bool("magisk", magisk, 1);
  json_bool("zygisk", zygisk_process, 0);
  printf("}");
  printf("}\n");
  return clean ? 0 : 1;
}

static int apply(const char *policy_path) {
  mkdir("/data/local/tmp/xenoid-hide", 0700);
  if (policy_path && exists(policy_path)) {
    FILE *in = fopen(policy_path, "rb");
    FILE *out = fopen("/data/local/tmp/xenoid-hide/native-policy.json", "wb");
    if (in && out) {
      char buf[4096]; size_t n;
      while ((n = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, n, out);
    }
    if (in) fclose(in); if (out) fclose(out);
  } else {
    write_file("/data/local/tmp/xenoid-hide/native-policy.json", "{\"schema\":\"dev.xenoid.hide/v1\",\"hideRoot\":true,\"hideFrida\":true}\n");
  }
  write_file("/data/local/tmp/xenoid-hide/denylist.txt", "frida\nmagisk\nzygisk\nsu\nlsposed\n");
  int hide_rc = hide_root_surfaces();
  printf("{\"ok\":%s,\"policy\":\"/data/local/tmp/xenoid-hide/native-policy.json\",\"denylist\":\"/data/local/tmp/xenoid-hide/denylist.txt\",\"rootSurfacesHidden\":%s}\n",
         hide_rc == 0 ? "true" : "false", hide_rc == 0 ? "true" : "false");
  return hide_rc == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc < 2 || !strcmp(argv[1], "status")) return status();
  if (!strcmp(argv[1], "apply")) return apply(argc > 2 ? argv[2] : NULL);
  fprintf(stderr, "usage: %s status | apply [policy.json]\n", argv[0]);
  return 64;
}
