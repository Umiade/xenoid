// xenoid-profile: native staged profile reader for future system/service hooks.
// It reads /data/local/tmp/xenoid-profile/effective.json and helper field files
// produced by Xenoid daemon. This provides one native ABI-stable interface for
// later LD_PRELOAD/Zygisk/system_server modules.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROFILE_DIR "/data/local/tmp/xenoid-profile"
#define EFFECTIVE PROFILE_DIR "/effective.json"
#define BOOT_ID PROFILE_DIR "/boot_id"

static char *read_file(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return NULL;
  struct stat st;
  if (fstat(fd, &st) != 0) { close(fd); return NULL; }
  size_t cap = st.st_size > 0 ? (size_t)st.st_size : 4096;
  char *buf = (char *)calloc(1, cap + 1);
  if (!buf) { close(fd); return NULL; }
  ssize_t n = read(fd, buf, cap);
  close(fd);
  if (n < 0) { free(buf); return NULL; }
  buf[n] = 0;
  return buf;
}

static void print_json_string(const char *s) {
  putchar('"');
  if (s) for (const char *p=s; *p; ++p) {
    if (*p == '\\' || *p == '"') { putchar('\\'); putchar(*p); }
    else if (*p == '\n') printf("\\n");
    else if (*p == '\r') printf("\\r");
    else putchar(*p);
  }
  putchar('"');
}

static char *extract_string(const char *json, const char *key) {
  if (!json || !key) return NULL;
  char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  char *p = strstr((char *)json, needle);
  if (!p) return NULL;
  p = strchr(p + strlen(needle), ':');
  if (!p) return NULL;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\n') p++;
  if (*p != '"') return NULL;
  p++;
  char *start = p;
  while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
  size_t len = (size_t)(p - start);
  char *out = (char *)calloc(1, len + 1);
  if (!out) return NULL;
  memcpy(out, start, len);
  return out;
}

static int status(void) {
  printf("{\"ok\":true,\"schema\":\"dev.xenoid.profile.native/v1\",");
  printf("\"profilePath\":\"%s\",\"profileExists\":%s,", EFFECTIVE, access(EFFECTIVE, F_OK)==0 ? "true" : "false");
  printf("\"bootIdPath\":\"%s\",\"bootIdExists\":%s}\n", BOOT_ID, access(BOOT_ID, F_OK)==0 ? "true" : "false");
  return 0;
}

static int dump(void) {
  char *j = read_file(EFFECTIVE);
  if (!j) { printf("{\"ok\":false,\"error\":\"profile not found\",\"path\":\"%s\"}\n", EFFECTIVE); return 1; }
  printf("%s\n", j);
  free(j);
  return 0;
}

static int get_key(const char *key) {
  if (!strcmp(key, "boot_id")) {
    char *b = read_file(BOOT_ID);
    if (b) { printf("%s\n", b); free(b); return 0; }
  }
  char *j = read_file(EFFECTIVE);
  if (!j) return 1;
  char *v = extract_string(j, key);
  if (!v) { free(j); return 2; }
  printf("%s\n", v);
  free(v); free(j);
  return 0;
}

static int env(void) {
  char *j = read_file(EFFECTIVE);
  char *boot = read_file(BOOT_ID);
  char *android_id = extract_string(j, "android_id");
  char *model = extract_string(j, "model");
  char *fingerprint = extract_string(j, "fingerprint");
  printf("{");
  printf("\"ok\":true,");
  printf("\"android_id\":"); print_json_string(android_id); printf(",");
  printf("\"boot_id\":"); print_json_string(boot); printf(",");
  printf("\"model\":"); print_json_string(model); printf(",");
  printf("\"fingerprint\":"); print_json_string(fingerprint); printf("}\n");
  free(j); free(boot); free(android_id); free(model); free(fingerprint);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2 || !strcmp(argv[1], "status")) return status();
  if (!strcmp(argv[1], "dump")) return dump();
  if (!strcmp(argv[1], "env")) return env();
  if (!strcmp(argv[1], "get") && argc > 2) return get_key(argv[2]);
  fprintf(stderr, "usage: %s status | dump | env | get <key>\n", argv[0]);
  return 64;
}
