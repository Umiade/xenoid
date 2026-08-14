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
// __system_property_get. Both are interposed below.
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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
#ifndef XENOID_COMBINED_SHIM
typedef int (*statfs_t)(const char*, struct statfs*);
#endif
typedef long (*syscall_t)(long, unsigned long, unsigned long, unsigned long,
                          unsigned long, unsigned long, unsigned long);

static spg_t real_get;
static spf_t real_find;
static rcb_t real_rcb;
#ifndef XENOID_COMBINED_SHIM
static statfs_t real_statfs;
#endif
static syscall_t real_syscall;
static __thread dev_t last_data_statfs_device;
static __thread int data_statfs_device_valid;

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

int __system_property_get(const char *name, char *value){
  if (!real_get) real_get = (spg_t)dlsym(RTLD_NEXT, "__system_property_get");
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

static int path_is_data(const char *path){
  if (!path) return 0;
  return !strcmp(path, "/data") || !strncmp(path, "/data/", 6);
}

#ifndef XENOID_COMBINED_SHIM
int statfs(const char *path, struct statfs *buf){
  if (!real_statfs) real_statfs = (statfs_t)dlsym(RTLD_NEXT, "statfs");
  if (!real_statfs) { errno = ENOSYS; return -1; }
  int app_data = getuid() >= 10000 && path_is_data(path);
  int rc = real_statfs(path, buf);
  if (rc == 0 && app_data) {
    buf->f_type = 0xF2F52010;
    struct stat st;
    data_statfs_device_valid = lstat(path, &st) == 0;
    if (data_statfs_device_valid) last_data_statfs_device = st.st_dev;
  } else {
    data_statfs_device_valid = 0;
  }
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
    if (buf && path_is_data(path)) buf->f_type = 0xF2F52010;
    data_statfs_device_valid = 0;
  } else if (number == __NR_fstatfs && rc == 0 && getuid() >= 10000 &&
             data_statfs_device_valid) {
    struct stat st;
    struct statfs *buf = (struct statfs *)args[1];
    if (buf && fstat((int)args[0], &st) == 0 &&
        st.st_dev == last_data_statfs_device)
      buf->f_type = 0xF2F52010;
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
