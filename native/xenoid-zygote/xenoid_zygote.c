// libxenoid_zygote.c — system-wide framework spoofing injected into zygote via
// LD_PRELOAD (setenv in init.zygote64.rc). Every app forked from zygote inherits
// it. No Magisk, no frida-server, no ptrace — a plain bionic interposition, so
// there is no hook framework artifact for risk SDKs to find.
//
// Layering rule: ro.hardware=tensor is now safe during startup because the
// runtime image copies the redroid gralloc/HWC implementations to their
// tensor HAL names. Apps see the raven identity below; redroid-only graphics
// properties remain untouched for system_server.
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

extern void *dlsym(void *handle, const char *symbol);
#define RTLD_NEXT ((void*)-1)

typedef int (*spg_t)(const char*, char*);
typedef const void *(*spf_t)(const char*);
typedef void (*rcb_cb_t)(void*, const char*, const char*, uint32_t);
typedef void (*rcb_t)(const void*, rcb_cb_t, void*);

static spg_t real_get;
static spf_t real_find;
static rcb_t real_rcb;

static const char *spoof_value(const char *name){
  if (!name) return NULL;
  /* Build.HARDWARE matches the raven identity. The runtime image provides
     tensor-named gralloc/HWC modules, so ro.hardware=tensor is boot-safe.
     Do NOT spoof ro.boot.redroid_* / gralloc / egl / vulkan here: system_server
     inherits this LD_PRELOAD and still needs those values to keep graphics up. */
  if (!strcmp(name, "ro.hardware")) return "tensor";
  if (!strcmp(name, "ro.boot.hardware")) return "gs101";
  if (!strcmp(name, "ro.hardware.sku")) return "G1MNW";
  if (!strcmp(name, "service.adb.tcp.port")) return "-1";
  if (!strcmp(name, "service.adb.tls.port")) return "-1";
  if (!strcmp(name, "init.svc.adbd")) return "stopped";
  if (!strcmp(name, "sys.usb.config")) return "mtp";
  if (!strcmp(name, "sys.usb.state")) return "mtp";
  if (!strcmp(name, "persist.sys.usb.config")) return "mtp";
  if (!strcmp(name, "ro.debuggable")) return "0";
  if (!strcmp(name, "ro.adb.secure")) return "1";
  /* Identity-only Build strings — safe for framework readers. */
  if (!strcmp(name, "ro.build.flavor")) return "raven-user";
  if (!strcmp(name, "ro.build.product")) return "raven";
  if (!strcmp(name, "ro.build.id")) return "TP1A.221005.002";
  if (!strcmp(name, "ro.product.board")) return "raven";
  if (!strcmp(name, "ro.build.display.id")) return "TP1A.221005.002";
  if (!strcmp(name, "ro.build.description"))
    return "raven-user 13 TP1A.221005.002 8977058 release-keys";
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

/* Android 13 SystemProperties.get is find → read_callback. kmod hides
   adbd_config_prop from raw app mmaps, so synthesize a private token for the
   ADB keys whose real prop_info must stay root-only. */
static const char xenoid_prop_token_tcp;
static const char xenoid_prop_token_tls;
static const char xenoid_prop_token_tls_enable;
static const void *synthetic_prop_token(const char *name){
  if (!name) return NULL;
  if (!strcmp(name, "service.adb.tcp.port")) return &xenoid_prop_token_tcp;
  if (!strcmp(name, "service.adb.tls.port")) return &xenoid_prop_token_tls;
  if (!strcmp(name, "persist.adb.tls_server.enable")) return &xenoid_prop_token_tls_enable;
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
  if (!real_rcb) real_rcb = (rcb_t)dlsym(RTLD_NEXT, "__system_property_read_callback");
  if (!real_rcb) return;
  struct rcb_wrap w; w.cb = cb; w.cookie = cookie;
  real_rcb(pi, rcb_wrap_cb, &w);
}

extern char **environ;

static void apply_zygote_mount_view(void){
  if (getuid() != 0) return;
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/xenoid-overlay-helper", "xenoid-overlay-helper", "apply",
          (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
  }
}

__attribute__((constructor)) static void xenoid_zygote_init(void){
  /* /proc/pid/environ dumps the exec-time env region (mm->env_start..env_end),
     so unsetenv() alone cannot hide LD_PRELOAD. Scrub the raw bytes in place,
     then drop it from getenv() too. Children inherit the scrubbed region. */
  for (char **e = environ; e && *e; ++e) {
    if (strncmp(*e, "LD_PRELOAD=", 11) == 0) {
      memset(*e, ' ', strlen(*e));
      break;
    }
  }
  unsetenv("LD_PRELOAD");
  /* Android creates a private mount namespace for zygote. Mounting only from
     init leaves raw app syscalls on the unmodified proc/sysfs view. Apply the
     same overlays here before app_process forks system_server or app children. */
  apply_zygote_mount_view();
}
