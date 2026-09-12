/*
 * Leading DT_NEEDED dependency of the runtime image's servicemanager.
 *
 * Container hosts run without kernel SELinux, so libselinux's
 * selinux_check_access reports the policy as disabled and allows every
 * query: the stock isolated_app service inventory restriction never
 * applies, and isolated processes can enumerate every registered service.
 * servicemanager owns that decision itself (AccessControl::canFind/canAdd
 * call selinux_check_access unconditionally through the PLT), so restore
 * exactly the stock rules here and forward every other query to the real
 * libselinux. Resolution failures fail open: this shim must never block a
 * boot-critical service decision.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef int (*check_access_t)(const char *scon, const char *tcon,
                              const char *tclass, const char *perm,
                              void *auditdata);
typedef void *(*ipct_self_t)(void);
typedef int32_t (*ipct_uid_t)(const void *);

static check_access_t real_check_access;
static ipct_self_t ipct_self;
static ipct_uid_t ipct_uid;

__attribute__((constructor)) static void resolve_real(void) {
  real_check_access = (check_access_t)dlsym(RTLD_NEXT, "selinux_check_access");
  ipct_self = (ipct_self_t)dlsym(RTLD_DEFAULT,
                                 "_ZN7android14IPCThreadState4selfEv");
  ipct_uid = (ipct_uid_t)dlsym(RTLD_DEFAULT,
                               "_ZNK7android14IPCThreadState13getCallingUidEv");
}

/* Stock Android 13 plat_sepolicy.cil: these are the only service_manager
 * types isolated_app may find; it may not add any service. */
static const char *const isolated_find_types[] = {
    "activity_service",
    "display_service",
    "webviewupdate_service",
};

/* The binder caller uid is the only reliable caller signal here: without
 * kernel SELinux the transaction carries no security id, so the context
 * string servicemanager computes is empty. Fail open when the binder state
 * is unavailable so boot-time self-registration can never be blocked. */
static int caller_is_isolated(void) {
  int32_t uid;
  void *state;

  if (!ipct_self || !ipct_uid)
    return 0;
  state = ipct_self();
  if (!state)
    return 0;
  uid = ipct_uid(state);
  return uid >= 90000 && uid <= 99999;
}

/* Match the type field of "u:object_r:<type>:s0[:...]" regardless of any
 * trailing level/categories. */
static int context_has_type(const char *context, const char *type) {
  const char *first;
  const char *second;
  const char *end;
  size_t length;

  if (!context)
    return 0;
  first = strchr(context, ':');
  if (!first)
    return 0;
  second = strchr(first + 1, ':');
  if (!second)
    return 0;
  second++;
  end = strchr(second, ':');
  length = end ? (size_t)(end - second) : strlen(second);
  return strlen(type) == length && memcmp(second, type, length) == 0;
}

int selinux_check_access(const char *scon, const char *tcon,
                         const char *tclass, const char *perm,
                         void *auditdata) {
  size_t i;
  int isolated = caller_is_isolated();


  if (tclass && perm && strcmp(tclass, "service_manager") == 0 && isolated) {
    if (strcmp(perm, "find") == 0) {
      for (i = 0; i < sizeof(isolated_find_types) / sizeof(isolated_find_types[0]);
           i++) {
        if (context_has_type(tcon, isolated_find_types[i]))
          return 0;
      }
      errno = EACCES;
      return -1;
    }
    /* isolated_app has no add and no list in stock plat_sepolicy.cil */
    if (strcmp(perm, "add") == 0 || strcmp(perm, "list") == 0) {
      errno = EACCES;
      return -1;
    }
  }
  if (!real_check_access)
    return 0;
  return real_check_access(scon, tcon, tclass, perm, auditdata);
}
