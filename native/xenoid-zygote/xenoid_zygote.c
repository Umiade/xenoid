// libxenoid_zygote.c — zygote framework and process-surface compatibility.
// The production app_process64 loads this together with xenoid_shim.c as an
// ordinary leading DT_NEEDED dependency. This keeps linker preload state empty
// while preserving one process-wide implementation for zygote descendants.
//
// Layering rule: ro.hardware=raven is correct before zygote startup because the
// runtime image publishes the base graphics implementation under Raven HAL
// names. Apps and system_server therefore share one hardware identity.
//
// Android 13 note: SystemProperties.get (the Build.* path) resolves values via
// __system_property_find + __system_property_read_callback, NOT
// __system_property_get. Both are interposed below, and the staged DRM identity
// property is hidden from app readers on every libc read path (find, get,
// read_callback enumeration, foreach).
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/stat.h>

extern void *dlsym(void *handle, const char *symbol);
#define RTLD_NEXT ((void*)-1)

typedef int (*spg_t)(const char*, char*);
typedef const void *(*spf_t)(const char*);
typedef void (*rcb_cb_t)(void*, const char*, const char*, uint32_t);
typedef void (*rcb_t)(const void*, rcb_cb_t, void*);
typedef void (*foreach_cb_t)(const void*, void*);
typedef int (*foreach_t)(foreach_cb_t, void*);
#ifndef XENOID_COMBINED_SHIM
typedef int (*statfs_t)(const char*, struct statfs*);
#endif
typedef long (*syscall_t)(long, unsigned long, unsigned long, unsigned long,
                          unsigned long, unsigned long, unsigned long);

static spg_t real_get;
static spf_t real_find;
static rcb_t real_rcb;
static foreach_t real_foreach;
#ifndef XENOID_COMBINED_SHIM
static statfs_t real_statfs;
#endif
static syscall_t real_syscall;

static const char *spoof_value(const char *name){
  if (!name) return NULL;
  /* Build.HARDWARE matches the Raven identity. The runtime image provides
     raven-named gralloc/HWC modules before graphics initialization. */
  if (!strcmp(name, "ro.hardware")) return "raven";
  if (!strcmp(name, "ro.boot.hardware")) return "raven";
  if (!strcmp(name, "ro.hardware.sku")) return "G8V0U";
  if (!strcmp(name, "ro.boot.hardware.sku")) return "G8V0U";
  if (!strcmp(name, "ro.board.platform")) return "gs101";
  if (!strcmp(name, "service.adb.tcp.port")) return "-1";
  if (!strcmp(name, "service.adb.tls.port")) return "-1";
  if (!strcmp(name, "init.svc.adbd")) return "stopped";
  if (!strcmp(name, "sys.usb.config")) return "mtp";
  if (!strcmp(name, "sys.usb.state")) return "mtp";
  if (!strcmp(name, "persist.sys.usb.config")) return "mtp";
  if (!strcmp(name, "ro.debuggable")) return "0";
  if (!strcmp(name, "ro.adb.secure")) return "1";
  if (getuid() >= 10000 && !strcmp(name, "ro.crypto.state")) return "encrypted";
  if (getuid() >= 10000 && !strcmp(name, "ro.crypto.type")) return "file";
  /* Identity-only Build strings — safe for framework readers. */
  if (!strcmp(name, "ro.build.flavor")) return "raven-user";
  if (!strcmp(name, "ro.build.product")) return "raven";
  if (!strcmp(name, "ro.build.id")) return "TP1A.221005.002";
  if (!strcmp(name, "ro.build.version.incremental")) return "9012097";
  if (!strcmp(name, "ro.build.fingerprint"))
    return "google/raven/raven:13/TP1A.221005.002/9012097:user/release-keys";
  if (!strcmp(name, "ro.product.board")) return "raven";
  if (!strcmp(name, "ro.build.display.id")) return "TP1A.221005.002";
  if (!strcmp(name, "ro.product.first_api_level")) return "31";
  if (!strcmp(name, "ro.bootloader")) return "slider-1.2-8895132";
  if (!strcmp(name, "ro.build.description"))
    return "raven-user 13 TP1A.221005.002 9012097 release-keys";
  return NULL;
}

/* persist.xenoid.drm.id stages the synthetic Widevine identity and is an
   unmistakable xenoid marker, so inside app processes it behaves as a
   nonexistent property on every libc read path. Non-app contexts are
   unaffected by construction: this interposition exists only in zygote
   descendants, so shell/adbd getprop keeps returning the staged value, and
   the xenoid_drm.c bridge reads it through RTLD_NEXT real symbols, which
   bypasses this interposition entirely. */
static int drm_id_property_hidden(const char *name){
  return name && getuid() >= 10000
      && !strcmp(name, "persist.xenoid.drm.id");
}

int __system_property_get(const char *name, char *value){
  if (!real_get) real_get = (spg_t)dlsym(RTLD_NEXT, "__system_property_get");
  if (drm_id_property_hidden(name)) { if (value) value[0] = 0; return 0; }
  const char *sv = spoof_value(name);
  if (sv) { size_t n = strlen(sv); memcpy(value, sv, n + 1); return (int)n; }
  if (real_get) return real_get(name, value);
  if (value) value[0] = 0;
  return 0;
}

/* Android 13 SystemProperties.get is find → read_callback. Synthesize private
   tokens for values whose real prop_info must remain absent from privileged
   processes; crypto tokens are exposed only after a child enters an app UID. */
static const char xenoid_prop_token_tcp;
static const char xenoid_prop_token_tls;
static const char xenoid_prop_token_tls_enable;
static const char xenoid_prop_token_crypto_state;
static const char xenoid_prop_token_crypto_type;
static const void *synthetic_prop_token(const char *name){
  if (!name) return NULL;
  if (!strcmp(name, "service.adb.tcp.port")) return &xenoid_prop_token_tcp;
  if (!strcmp(name, "service.adb.tls.port")) return &xenoid_prop_token_tls;
  if (!strcmp(name, "persist.adb.tls_server.enable")) return &xenoid_prop_token_tls_enable;
  if (getuid() >= 10000 && !strcmp(name, "ro.crypto.state")) return &xenoid_prop_token_crypto_state;
  if (getuid() >= 10000 && !strcmp(name, "ro.crypto.type")) return &xenoid_prop_token_crypto_type;
  return NULL;
}
const void *__system_property_find(const char *name){
  if (!real_find) real_find = (spf_t)dlsym(RTLD_NEXT, "__system_property_find");
  if (drm_id_property_hidden(name)) return NULL;
  const void *token = synthetic_prop_token(name);
  if (token) return token;
  return real_find ? real_find(name) : NULL;
}

/* Wrap the caller's callback so we see the real (name,value) the system read
   back, then substitute spoofed identity values. Avoids needing
   __system_property_get_name (not reliably resolvable via RTLD_NEXT). */
struct rcb_wrap { rcb_cb_t cb; void *cookie; };
static void rcb_wrap_cb(void *cookie, const char *name, const char *value, uint32_t serial){
  struct rcb_wrap *w = (struct rcb_wrap *)cookie;
  const char *sv = spoof_value(name);
  w->cb(w->cookie, name, sv ? sv : value, sv ? 2u : serial);
}

void __system_property_read_callback(const void *pi, rcb_cb_t cb, void *cookie){
  if (!cb) return;
  if (pi == &xenoid_prop_token_tcp) { cb(cookie, "service.adb.tcp.port", "-1", 2u); return; }
  if (pi == &xenoid_prop_token_tls) { cb(cookie, "service.adb.tls.port", "-1", 2u); return; }
  if (pi == &xenoid_prop_token_tls_enable) { cb(cookie, "persist.adb.tls_server.enable", "", 2u); return; }
  if (pi == &xenoid_prop_token_crypto_state) { cb(cookie, "ro.crypto.state", "encrypted", 2u); return; }
  if (pi == &xenoid_prop_token_crypto_type) { cb(cookie, "ro.crypto.type", "file", 2u); return; }
  if (!real_rcb) real_rcb = (rcb_t)dlsym(RTLD_NEXT, "__system_property_read_callback");
  if (!real_rcb) return;
  struct rcb_wrap w; w.cb = cb; w.cookie = cookie;
  real_rcb(pi, rcb_wrap_cb, &w);
}

/* Legacy enumeration must not surface the hidden DRM identity property
   either. The caller's callback runs only for entries whose real name
   survives the filter; names are read through the REAL read_callback. */
struct foreach_wrap { foreach_cb_t cb; void *cookie; int hidden; };
static void foreach_name_cb(void *cookie, const char *name, const char *value, uint32_t serial){
  (void)value; (void)serial;
  ((struct foreach_wrap *)cookie)->hidden = drm_id_property_hidden(name);
}
static void foreach_wrap_cb(const void *pi, void *cookie){
  struct foreach_wrap *w = (struct foreach_wrap *)cookie;
  w->hidden = 0;
  if (!real_rcb) real_rcb = (rcb_t)dlsym(RTLD_NEXT, "__system_property_read_callback");
  if (real_rcb) real_rcb(pi, foreach_name_cb, w);
  if (w->hidden) return;
  w->cb(pi, w->cookie);
}
int __system_property_foreach(foreach_cb_t propfn, void *cookie){
  if (!real_foreach) real_foreach = (foreach_t)dlsym(RTLD_NEXT, "__system_property_foreach");
  if (!real_foreach) { errno = ENOSYS; return -1; }
  if (!propfn) return real_foreach(propfn, cookie);
  struct foreach_wrap w; w.cb = propfn; w.cookie = cookie; w.hidden = 0;
  return real_foreach(foreach_wrap_cb, &w);
}

static int path_is_data(const char *path){
  if (!path) return 0;
#ifdef XENOID_HOST_TEST
  const char *test_path = getenv("XENOID_TEST_DATA_PATH");
  if (test_path && (!strcmp(path, test_path) ||
                    (!strncmp(path, test_path, strlen(test_path)) &&
                     path[strlen(test_path)] == '/')))
    return 1;
#endif
  return !strcmp(path, "/data") || !strncmp(path, "/data/", 6);
}

#define XENOID_F2FS_SUPER_MAGIC 0xF2F52010L
#define XENOID_DATA_BLOCK_SIZE 4096ULL
#define XENOID_DATA_BLOCKS 31250000ULL
#define XENOID_DATA_NAME_MAX 255ULL
#define XENOID_DATA_STATFS_FLAGS 0x426ULL

static unsigned long long scale_data_statfs_value(
    unsigned long long value, unsigned long long total) {
  unsigned long long quotient;
  unsigned long long remainder;
  while(total > UINT32_MAX) {
    value >>= 1;
    total >>= 1;
  }
  if(!total) return 0;
  quotient=value/total;
  remainder=value%total;
  return quotient*XENOID_DATA_BLOCKS
      + remainder*XENOID_DATA_BLOCKS/total;
}

/* Staged /data filesystem identity shared with the kmod and shim layers.
   Absent or invalid staged content passes the real fsid through, matching
   the kmod's zero/zero default. Loaded once per process; regeneration takes
   effect through the soft reboot that follows it. */
static pthread_once_t statfs_fsid_once = PTHREAD_ONCE_INIT;
static uint64_t statfs_fsid_value;
static int fsid_hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static void initialize_statfs_fsid(void) {
  typedef int (*open_fn_t)(const char*, int, ...);
  typedef ssize_t (*read_fn_t)(int, void*, size_t);
  open_fn_t real_open = (open_fn_t)dlsym(RTLD_NEXT, "open");
  read_fn_t real_read = (read_fn_t)dlsym(RTLD_NEXT, "read");
  if (!real_open || !real_read) return;
  const char *dir = getenv("XENOID_PROFILE_DIR");
  char path[512];
  snprintf(path, sizeof(path), "%s/statfs_fsid",
           (dir && dir[0]) ? dir : "/data/local/tmp/xenoid-profile");
  int fd = real_open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return;
  char text[32];
  ssize_t size = real_read(fd, text, sizeof(text) - 1);
  close(fd);
  if (size != 17 || text[16] != '\n') return;
  text[size] = 0;
  unsigned int v[2] = {0, 0};
  int ok = 1;
  for (int half = 0; half < 2 && ok; ++half) {
    for (int i = 0; i < 8; ++i) {
      int nibble = fsid_hex_nibble(text[half * 8 + i]);
      if (nibble < 0) { ok = 0; break; }
      v[half] = (v[half] << 4) | (unsigned int)nibble;
    }
  }
  if (ok)
    statfs_fsid_value = ((uint64_t)v[0] << 32) | (uint64_t)v[1];
}
static uint64_t load_statfs_fsid(void) {
  pthread_once(&statfs_fsid_once, initialize_statfs_fsid);
  return statfs_fsid_value;
}
#define XENOID_SHAPE_STATFS_FSID(buf) do { \
  uint64_t fsid = load_statfs_fsid(); \
  if (fsid) { \
    (buf)->f_fsid.__val[0] = (int)(uint32_t)(fsid >> 32); \
    (buf)->f_fsid.__val[1] = (int)(uint32_t)fsid; \
  } \
} while(0)
#define XENOID_SHAPE_DATA_STATFS(buf) do { \
  unsigned long long real_blocks=(unsigned long long)(buf)->f_blocks; \
  unsigned long long real_bfree=(unsigned long long)(buf)->f_bfree; \
  unsigned long long real_bavail=(unsigned long long)(buf)->f_bavail; \
  unsigned long long real_files=(unsigned long long)(buf)->f_files; \
  unsigned long long real_ffree=(unsigned long long)(buf)->f_ffree; \
  if(real_blocks) { \
    (buf)->f_type=XENOID_F2FS_SUPER_MAGIC; \
    (buf)->f_bsize=XENOID_DATA_BLOCK_SIZE; \
    (buf)->f_blocks=XENOID_DATA_BLOCKS; \
    (buf)->f_bfree=scale_data_statfs_value(real_bfree,real_blocks); \
    (buf)->f_bavail=scale_data_statfs_value(real_bavail,real_blocks); \
    (buf)->f_files=scale_data_statfs_value(real_files,real_blocks); \
    (buf)->f_ffree=scale_data_statfs_value(real_ffree,real_blocks); \
    (buf)->f_namelen=XENOID_DATA_NAME_MAX; \
    (buf)->f_flags=XENOID_DATA_STATFS_FLAGS; \
    XENOID_SHAPE_STATFS_FSID(buf); \
  } \
} while(0)

static int fd_is_data_device(int fd) {
  struct stat data_stat;
  struct stat fd_stat;
  const char *data_path = "/data";
#ifdef XENOID_HOST_TEST
  const char *test_path = getenv("XENOID_TEST_DATA_PATH");
  if (test_path && test_path[0]) data_path = test_path;
#endif
  return lstat(data_path, &data_stat) == 0 && fstat(fd, &fd_stat) == 0
      && fd_stat.st_dev == data_stat.st_dev;
}

#ifndef XENOID_COMBINED_SHIM
int statfs(const char *path, struct statfs *buf){
  if (!real_statfs) real_statfs = (statfs_t)dlsym(RTLD_NEXT, "statfs");
  if (!real_statfs) { errno = ENOSYS; return -1; }
  int app_data = getuid() >= 10000 && path_is_data(path);
  int rc = real_statfs(path, buf);
  if (rc == 0 && app_data && buf) XENOID_SHAPE_DATA_STATFS(buf);
  return rc;
}
#endif

long syscall(long number, ...){
  __builtin_va_list ap;
  unsigned long args[6] = {0};
  if (!real_syscall) real_syscall = (syscall_t)dlsym(RTLD_NEXT, "syscall");
  if (!real_syscall) { errno = ENOSYS; return -1; }
  __builtin_va_start(ap, number);
  for (unsigned int i = 0; i < 6; ++i) args[i] = __builtin_va_arg(ap, unsigned long);
  __builtin_va_end(ap);
  long rc = real_syscall(number, args[0], args[1], args[2],
                         args[3], args[4], args[5]);
  if (number == __NR_statfs && rc == 0 && getuid() >= 10000) {
    const char *path = (const char *)args[0];
    struct statfs *buf = (struct statfs *)args[1];
    if (buf && path_is_data(path)) XENOID_SHAPE_DATA_STATFS(buf);
  } else if (number == __NR_fstatfs && rc == 0 && getuid() >= 10000) {
    struct statfs *buf = (struct statfs *)args[1];
    if (buf && fd_is_data_device((int)args[0]))
      XENOID_SHAPE_DATA_STATFS(buf);
  }
  return rc;
}


static void apply_zygote_mount_view(void){
  if (getuid() != 0) return;
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/xenoid-overlay-helper", "xenoid-overlay-helper", "apply",
          (char *)NULL);
    _exit(127);
  }
  if (pid < 0) _exit(127);

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    _exit(127);
}

__attribute__((constructor)) static void xenoid_zygote_init(void){
  /* Android creates a private mount namespace for zygote. Mounting only from
     init leaves raw app syscalls on the unmodified proc/sysfs view. Apply the
     same overlays here before app_process forks system_server or app children. */
  apply_zygote_mount_view();
}
