// xenoid_drm.c — in-process Widevine DRM identity for every app process.
//
// Fingerprint collectors read the Widevine deviceUniqueId through Java
// android.media.MediaDrm and the NDK AMediaDrm_* API. Both paths converge on
// android::DrmUtils::MakeDrm(int*), an ordinary exported cross-DSO symbol in
// libmediadrm.so (verified against the runtime image). This library is already
// a leading DT_NEEDED of app_process64, so defining that symbol here wins
// resolution in every zygote descendant without any hook machinery.
//
// The synthetic IDrm mirrors the exact vtable layout recovered from the
// image's android::DrmHal: a 3-qword vtable header [0x18][0][0], 45 method
// slots, and a RefBase sub-object at +24 with its own 3-header vtable
// [-24][0][0]. Non-Widevine schemes delegate to the real MakeDrm result so
// ClearKey behaves exactly like stock. Every delegated call captures the
// delegate under a per-object lock and holds a strong reference for the
// duration of the call, so a concurrent destroyPlugin can never free it
// mid-call. When no identity is staged, the Widevine scheme reports itself
// unsupported, exactly like a Widevine-less device.
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* ------------------------------------------------------------------ */
/* Constants                                                            */

/* Official Widevine scheme UUID (DASH-IF identifier registry). */
static const uint8_t XENOID_WIDEVINE_UUID[16] = {
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
    0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
};

#define XENOID_DRM_ID_PROP "persist.xenoid.drm.id"
#define XENOID_DRM_STATUS_UNSUPPORTED (-22)
/* DrmPlugin::SecurityLevel tops out at HW_SECURE_ALL=5 on Android 13
   (SW_SECURE_CRYPTO=1 .. HW_SECURE_ALL=5; verified against the guest
   framework dex constants and DrmHalHidl's level compare), which is the
   level Widevine L1 reports. */
#define XENOID_DRM_SECURITY_LEVEL_L1 5

/* Stock Widevine L1 on this device class advertises HDCP_V2_2 for both the
   connected and maximum levels (matching the hdcpLevel property strings).
   DrmPlugin::HdcpLevel is 1-based on Android 13 (HDCP_NONE=1 .. HDCP_V2_3=6,
   matching the framework MediaDrm constants and the JNI identity mapping;
   0 is HDCP_LEVEL_UNKNOWN). Verified against the guest framework dex. */
#define XENOID_DRM_HDCP_LEVEL_V2_2 5
/* Synthetic sessions are tracked per object so numberOfOpenSessions and
   getNumberOfSessions agree with openSession/closeSession reality. */
#define XENOID_DRM_MAX_SESSIONS 64

/* ------------------------------------------------------------------ */
/* Real-symbol resolution                                               */
typedef void (*refbase_ctor_t)(void *);
typedef void (*refbase_dtor_t)(void *);
typedef void (*refbase_inc_strong_t)(const void *, const void *);
typedef void (*refbase_dec_strong_t)(const void *, const void *);
typedef void *make_drm_real_t;
typedef int (*vector_insert_at_t)(void *, size_t, size_t);
typedef void (*vector_clear_t)(void *);
typedef void *(*vector_edit_array_t)(void *);
typedef void (*string8_set_to_t)(void *, const char *);
typedef void *(*operator_new_t)(size_t);
typedef void (*operator_delete_t)(void *);
__attribute__((visibility("hidden")))
extern void *xenoid_drm_call_real(void *factory, int *status, void *sret);

static make_drm_real_t real_make_drm;
static refbase_ctor_t real_refbase_ctor;
static refbase_dtor_t real_refbase_dtor;
static refbase_inc_strong_t real_inc_strong;
static refbase_dec_strong_t real_dec_strong;
static vector_insert_at_t real_vector_insert_at;
static vector_clear_t real_vector_clear;
static vector_edit_array_t real_vector_edit_array;
static string8_set_to_t real_string8_set_to;
static operator_new_t real_operator_new;
static operator_delete_t real_operator_delete;

static pthread_once_t real_symbols_once = PTHREAD_ONCE_INIT;

static void resolve_real_symbols_once(void) {
    /* libmediadrm is reached through MediaDrm's runtime-loaded dependency
       group, which is not guaranteed to be visible to RTLD_NEXT from this
       app_process dependency. An explicit namespace-local handle makes the
       real factory lookup deterministic; keeping it open is bounded to one
       handle for the process lifetime. */
    void *mediadrm = dlopen("libmediadrm.so", RTLD_NOW | RTLD_LOCAL);
    real_make_drm = mediadrm
        ? dlsym(mediadrm, "_ZN7android8DrmUtils7MakeDrmEPi")
        : NULL;
    real_vector_insert_at =
        (vector_insert_at_t)dlsym(RTLD_NEXT, "_ZN7android10VectorImpl8insertAtEmm");
    real_vector_clear =
        (vector_clear_t)dlsym(RTLD_NEXT, "_ZN7android10VectorImpl5clearEv");
    real_vector_edit_array =
        (vector_edit_array_t)dlsym(RTLD_NEXT, "_ZN7android10VectorImpl13editArrayImplEv");
    real_refbase_ctor =
        (refbase_ctor_t)dlsym(RTLD_NEXT, "_ZN7android7RefBaseC1Ev");
    real_refbase_dtor =
        (refbase_dtor_t)dlsym(RTLD_NEXT, "_ZN7android7RefBaseD1Ev");
    real_inc_strong =
        (refbase_inc_strong_t)dlsym(RTLD_NEXT, "_ZNK7android7RefBase9incStrongEPKv");
    real_dec_strong =
        (refbase_dec_strong_t)dlsym(RTLD_NEXT, "_ZNK7android7RefBase9decStrongEPKv");
    real_string8_set_to =
        (string8_set_to_t)dlsym(RTLD_NEXT, "_ZN7android7String85setToEPKc");
    real_operator_new =
        (operator_new_t)dlsym(RTLD_NEXT, "_Znwm");
    real_operator_delete =
        (operator_delete_t)dlsym(RTLD_NEXT, "_ZdlPv");
}

static void resolve_real_symbols(void) {
    /* pthread_once publishes the complete pointer set only after every dlsym
       has returned. A failed or unavailable lookup remains NULL so callers
       retain the existing fail-closed behavior. */
    (void)pthread_once(&real_symbols_once, resolve_real_symbols_once);
}

/* ------------------------------------------------------------------ */
/* Synthetic IDrm object                                                */

struct XenoidDrm {
    void *vptr;                    /* +0: IDrm vtable address point */
    void *delegate;                /* +8: owned real IDrm for non-Widevine */
    void *reserved;                /* +16 */
    void *refbase_vptr;            /* +24: RefBase sub-object vtable */
    void *mRefs;                   /* +32: weakref_impl at this+8 (verified) */
    pthread_mutex_t delegate_lock; /* serializes delegate capture/release */
    pthread_mutex_t session_lock;  /* serializes the synthetic session table */
    pthread_mutex_t listener_lock;
    void *listener;
    void *listener_refbase;
    uint32_t session_count;
    uint8_t sessions[XENOID_DRM_MAX_SESSIONS][16];
};

static void *xenoid_drm_vtable[];
static void *xenoid_refbase_vtable[];
static uint32_t xenoid_drm_random32(void);


/* android::Vector<uint8> out-parameter layout in this build:
   [+0]=vptr [+8]=mArray [+16]=mSize [+24]=mCapacity. Fill it exactly the way
   the JNI consumer expects (itemSize=1). */
static int xenoid_fill_vector(void *vec, const uint8_t *data, size_t size) {
    if (!real_vector_insert_at || !real_vector_edit_array || !real_vector_clear) {
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    real_vector_clear(vec);
    if (size == 0) return 0;
    if (real_vector_insert_at(vec, 0, size) != 0) {
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    void *array = real_vector_edit_array(vec);
    if (!array) return XENOID_DRM_STATUS_UNSUPPORTED;
    memcpy(array, data, size);
    return 0;
}
/* Read the staged 16-byte identity from the identity property, per call, so
   a regeneration takes effect without a restart (properties are world
   readable; the profile directory is root-only). The REAL property getter is
   used so this library's own interposition can never mask the value. */
typedef int (*prop_get_t)(const char *, char *);
static int xenoid_drm_read_identity(uint8_t out[16]) {
    resolve_real_symbols();
    prop_get_t real_get =
        (prop_get_t)dlsym(RTLD_NEXT, "__system_property_get");
    if (!real_get) return -1;
    char text[96];
    int n = real_get(XENOID_DRM_ID_PROP, text);
    if (n != 32) return -1;
    for (int i = 0; i < 16; i++) {
        int hi = text[i * 2], lo = text[i * 2 + 1];
        if (hi >= '0' && hi <= '9') hi -= '0';
        else if (hi >= 'a' && hi <= 'f') hi -= 'a' - 10;
        else if (hi >= 'A' && hi <= 'F') hi -= 'A' - 10;
        else return -1;
        if (lo >= '0' && lo <= '9') lo -= '0';
        else if (lo >= 'a' && lo <= 'f') lo -= 'a' - 10;
        else if (lo >= 'A' && lo <= 'F') lo -= 'A' - 10;
        else return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* std::__1::vector<unsigned char> out-parameter: [begin,end,cap] pointers.
   libc++ allocator<T>::allocate obtains this storage with scalar operator new,
   and vector destruction returns it through the matching scalar delete. */
static int xenoid_fill_std_vector(void *vec, const uint8_t *data, size_t size) {
    if (!real_operator_new) return XENOID_DRM_STATUS_UNSUPPORTED;
    uint8_t *begin = (uint8_t *)real_operator_new(size);
    if (!begin) return XENOID_DRM_STATUS_UNSUPPORTED;
    memcpy(begin, data, size);
    uint8_t **slots = (uint8_t **)vec;
    slots[0] = begin;
    slots[1] = begin + size;
    slots[2] = begin + size;
    return 0;
}

static int xenoid_append_std_vector(
        void *vec, const uint8_t *data, size_t size) {
    if (!vec) return XENOID_DRM_STATUS_UNSUPPORTED;
    uint8_t **slots = (uint8_t **)vec;
    uint8_t *begin = slots[0];
    uint8_t *end = slots[1];
    size_t old_size = 0;
    if (begin || end) {
        if (!begin || !end || end < begin) return XENOID_DRM_STATUS_UNSUPPORTED;
        old_size = (size_t)(end - begin);
        if (old_size > 4096 || old_size % 16 != 0 || !real_operator_delete) {
            return XENOID_DRM_STATUS_UNSUPPORTED;
        }
        for (size_t offset = 0; offset < old_size; offset += 16) {
            if (size == 16 && !memcmp(begin + offset, data, 16)) return 0;
        }
    }
    if (!real_operator_new || size > SIZE_MAX - old_size) {
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    uint8_t *replacement = (uint8_t *)real_operator_new(old_size + size);
    if (!replacement) return XENOID_DRM_STATUS_UNSUPPORTED;
    if (old_size) memcpy(replacement, begin, old_size);
    memcpy(replacement + old_size, data, size);
    if (begin) real_operator_delete(begin);
    slots[0] = replacement;
    slots[1] = replacement + old_size + size;
    slots[2] = replacement + old_size + size;
    return 0;
}

/* android::String8 read-only view: the sole field is `const char* mString`
   pointing directly at the character data (verified against libmedia_jni's
   getPropertyByteArray call path: +24 past the characters lands beyond the
   string and reads as empty). */
static const char *xenoid_string8_cstr(const void *s8) {
    if (!s8) return "";
    const char *text = *(const char *const *)s8;
    return text ? text : "";
}

static void xenoid_string8_assign(void *s8, const char *value) {
    if (real_string8_set_to) real_string8_set_to(s8, value);
}

static struct XenoidDrm *xenoid_self(void *self) {
    return (struct XenoidDrm *)self;
}

static void *xenoid_refbase_from_interface(void *object) {
    if (!object) return NULL;
    void *vtable = *(void **)object;
    if (!vtable) return NULL;
    intptr_t adjust = ((intptr_t *)vtable)[-3];
    return (char *)object + adjust;
}


static void *xenoid_make_real_drm(int *status_out) {
    resolve_real_symbols();
    int status = XENOID_DRM_STATUS_UNSUPPORTED;
    void *real = NULL;
    if (real_make_drm) xenoid_drm_call_real(real_make_drm, &status, &real);
    void *refbase = real ? xenoid_refbase_from_interface(real) : NULL;
    if (status_out) *status_out = status;
    /* The real factory deliberately accepts a partial backend: initCheck
       reports -ENODEV (-19) when one of the AIDL/HIDL backends is absent,
       and MakeDrm still returns the usable object. Mirror that acceptance
       exactly: rejecting -ENODEV would discard every ClearKey-capable
       object on this guest (HIDL-only registration). */
    if (!real || (status != 0 && status != -19)
            || !refbase || !real_dec_strong) {
        if (real && refbase && real_dec_strong) real_dec_strong(refbase, &real);
        return NULL;
    }
    return real;
}
static void xenoid_drm_release_listener(struct XenoidDrm *d) {
    void *listener_refbase;
    pthread_mutex_lock(&d->listener_lock);
    listener_refbase = d->listener_refbase;
    d->listener = NULL;
    d->listener_refbase = NULL;
    pthread_mutex_unlock(&d->listener_lock);
    if (listener_refbase) {
        real_dec_strong(listener_refbase, &d->listener);
    }
}

/* Every delegated call captures the delegate under this lock and holds one
   strong reference for the duration of the call, exactly like the listener
   path: destroy/clear NULLs the field under the lock and only then decStrong,
   so an in-flight call can never dereference freed memory. The asm delegate
   trampolines enter through this acquire/release pair as well. */
__attribute__((visibility("hidden")))
void *xenoid_drm_delegate_acquire(void *self) {
    struct XenoidDrm *d = xenoid_self(self);
    pthread_mutex_lock(&d->delegate_lock);
    void *delegate = d->delegate;
    if (delegate) {
        real_inc_strong(xenoid_refbase_from_interface(delegate), &d->delegate);
    }
    pthread_mutex_unlock(&d->delegate_lock);
    return delegate;
}

__attribute__((visibility("hidden")))
void xenoid_drm_delegate_release(void *self, void *delegate) {
    struct XenoidDrm *d = xenoid_self(self);
    if (delegate) {
        real_dec_strong(xenoid_refbase_from_interface(delegate), &d->delegate);
    }
}

static void xenoid_drm_release_delegate(struct XenoidDrm *d, int destroy_plugin) {
    pthread_mutex_lock(&d->delegate_lock);
    void *delegate = d->delegate;
    d->delegate = NULL;
    pthread_mutex_unlock(&d->delegate_lock);
    if (!delegate) return;
    if (destroy_plugin) {
        int (*destroy)(void *) = (int (*)(void *))(*(void ***)delegate)[5];
        (void)destroy(delegate);
    }
    real_dec_strong(xenoid_refbase_from_interface(delegate), &d->delegate);
}

static void xenoid_drm_complete_dtor_impl(struct XenoidDrm *d) {
    xenoid_drm_release_listener(d);
    xenoid_drm_release_delegate(d, 1);
    pthread_mutex_destroy(&d->listener_lock);
    pthread_mutex_destroy(&d->delegate_lock);
    pthread_mutex_destroy(&d->session_lock);
    real_refbase_dtor((char *)d + 24);
}

static void xenoid_drm_complete_dtor(void *self) {
    xenoid_drm_complete_dtor_impl(xenoid_self(self));
}

static void xenoid_drm_deleting_dtor(void *self) {
    struct XenoidDrm *d = xenoid_self(self);
    xenoid_drm_complete_dtor_impl(d);
    free(d);
}

static void xenoid_refbase_complete_dtor(void *self) {
    xenoid_drm_complete_dtor_impl((struct XenoidDrm *)((char *)self - 24));
}

static void xenoid_refbase_deleting_dtor(void *self) {
    struct XenoidDrm *d = (struct XenoidDrm *)((char *)self - 24);
    xenoid_drm_complete_dtor_impl(d);
    free(d);
}
/* AArch64 delegate trampolines replace synthetic `this` with the owned real
 * plugin, holding a strong reference on it for the duration of the call via
 * xenoid_drm_delegate_acquire/release. Slots with coherent synthetic answers
 * (21, 40, 41) are implemented in C below instead. */
#define XENOID_DECLARE_DELEGATE(slot) \
    extern void xenoid_drm_delegate_##slot(void)
XENOID_DECLARE_DELEGATE(8);
XENOID_DECLARE_DELEGATE(9);
XENOID_DECLARE_DELEGATE(10);
XENOID_DECLARE_DELEGATE(11);
XENOID_DECLARE_DELEGATE(12);
XENOID_DECLARE_DELEGATE(13);
XENOID_DECLARE_DELEGATE(14);
XENOID_DECLARE_DELEGATE(15);
XENOID_DECLARE_DELEGATE(16);
XENOID_DECLARE_DELEGATE(17);
XENOID_DECLARE_DELEGATE(18);
XENOID_DECLARE_DELEGATE(19);
XENOID_DECLARE_DELEGATE(20);
XENOID_DECLARE_DELEGATE(24);
XENOID_DECLARE_DELEGATE(25);
XENOID_DECLARE_DELEGATE(26);
XENOID_DECLARE_DELEGATE(29);
XENOID_DECLARE_DELEGATE(30);
XENOID_DECLARE_DELEGATE(31);
XENOID_DECLARE_DELEGATE(32);
XENOID_DECLARE_DELEGATE(33);
XENOID_DECLARE_DELEGATE(34);
XENOID_DECLARE_DELEGATE(35);
XENOID_DECLARE_DELEGATE(36);
XENOID_DECLARE_DELEGATE(37);
XENOID_DECLARE_DELEGATE(38);
XENOID_DECLARE_DELEGATE(42);
XENOID_DECLARE_DELEGATE(43);
#undef XENOID_DECLARE_DELEGATE

/* ------------------------------------------------------------------ */
/* IDrm method implementations (vtable slot order)                      */

static int xenoid_drm_init_check(void *self) {
    (void)self;
    return 0;
}

static int xenoid_drm_is_crypto_supported(void *self, const uint8_t *uuid,
                                          const void *mime, int32_t level,
                                          uint8_t *result) {
    struct XenoidDrm *d = xenoid_self(self);
    if (uuid && !memcmp(uuid, XENOID_WIDEVINE_UUID, 16)) {
        uint8_t identity[16];
        if (level <= XENOID_DRM_SECURITY_LEVEL_L1
                && xenoid_drm_read_identity(identity) == 0) {
            if (result) *result = 1;
        } else if (result) {
            *result = 0;
        }
        return 0;
    }
    void *delegate = xenoid_drm_delegate_acquire(d);
    int factory_status = 0;
    int transient = 0;
    if (!delegate) {
        delegate = xenoid_make_real_drm(&factory_status);
        transient = delegate != NULL;
    }
    if (!delegate) {
        if (result) *result = 0;
        return 0;
    }
    int (*fn)(void *, const uint8_t *, const void *, int32_t, uint8_t *) =
        (int (*)(void *, const uint8_t *, const void *, int32_t, uint8_t *))
            (*(void ***)delegate)[3];
    int status = fn(delegate, uuid, mime, level, result);
    if (transient) {
        real_dec_strong(xenoid_refbase_from_interface(delegate), &delegate);
    } else {
        xenoid_drm_delegate_release(d, delegate);
    }
    return status;
}

static int xenoid_drm_create_plugin(void *self, const uint8_t *uuid,
                                    const void *package_name) {
    struct XenoidDrm *d = xenoid_self(self);
    (void)package_name;
    if (uuid && !memcmp(uuid, XENOID_WIDEVINE_UUID, 16)) {
        uint8_t identity[16];
        if (xenoid_drm_read_identity(identity) == 0) return 0;
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    pthread_mutex_lock(&d->delegate_lock);
    int already_created = d->delegate != NULL;
    pthread_mutex_unlock(&d->delegate_lock);
    if (already_created) return 0;
    int status = XENOID_DRM_STATUS_UNSUPPORTED;
    void *real = xenoid_make_real_drm(&status);
    if (!real) return status;
    void *real_refbase = xenoid_refbase_from_interface(real);
    int (*create)(void *, const uint8_t *, const void *) =
        (int (*)(void *, const uint8_t *, const void *))(*(void ***)real)[4];
    status = create(real, uuid, package_name);
    if (status != 0) {
        real_dec_strong(real_refbase, &real);
        return status;
    }

    /* Transfer the factory-returned sp<> into a stable per-object strong ref.
       A racing createPlugin may have installed a delegate meanwhile: destroy
       and release the duplicate instead of leaking the overwritten one. */
    pthread_mutex_lock(&d->delegate_lock);
    if (d->delegate) {
        pthread_mutex_unlock(&d->delegate_lock);
        int (*destroy)(void *) = (int (*)(void *))(*(void ***)real)[5];
        (void)destroy(real);
        real_dec_strong(real_refbase, &real);
        return 0;
    }
    real_inc_strong(real_refbase, &d->delegate);
    d->delegate = real;
    pthread_mutex_unlock(&d->delegate_lock);
    real_dec_strong(real_refbase, &real);
    return 0;
}

static int xenoid_drm_destroy_plugin(void *self) {
    struct XenoidDrm *d = xenoid_self(self);
    pthread_mutex_lock(&d->delegate_lock);
    void *delegate = d->delegate;
    d->delegate = NULL;
    pthread_mutex_unlock(&d->delegate_lock);
    int status = 0;
    if (delegate) {
        int (*destroy)(void *) = (int (*)(void *))(*(void ***)delegate)[5];
        status = destroy(delegate);
        real_dec_strong(xenoid_refbase_from_interface(delegate), &d->delegate);
    }
    /* Break the synthetic plugin/JDrm ownership cycle on every close. */
    xenoid_drm_release_listener(d);
    return status;
}

static int xenoid_drm_open_session(void *self, int32_t level, void *session) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, int32_t, void *) =
            (int (*)(void *, int32_t, void *))(*(void ***)delegate)[6];
        int status = fn(delegate, level, session);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    (void)level;
    /* Track synthetic sessions so numberOfOpenSessions/getNumberOfSessions
       agree with reality: a unique id per openSession, fail-closed beyond
       the advertised maximum. */
    uint8_t id[16];
    pthread_mutex_lock(&d->session_lock);
    if (d->session_count >= XENOID_DRM_MAX_SESSIONS) {
        pthread_mutex_unlock(&d->session_lock);
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    int unique = 0;
    for (int attempt = 0; attempt < 8 && !unique; attempt++) {
        uint32_t words[4];
        for (int i = 0; i < 4; i++) words[i] = xenoid_drm_random32();
        memcpy(id, words, sizeof(id));
        unique = 1;
        for (uint32_t s = 0; s < d->session_count; s++) {
            if (!memcmp(d->sessions[s], id, sizeof(id))) {
                unique = 0;
                break;
            }
        }
    }
    if (!unique) {
        pthread_mutex_unlock(&d->session_lock);
        return XENOID_DRM_STATUS_UNSUPPORTED;
    }
    memcpy(d->sessions[d->session_count], id, sizeof(id));
    d->session_count++;
    pthread_mutex_unlock(&d->session_lock);
    return xenoid_fill_vector(session, id, sizeof(id));
}

static int xenoid_drm_close_session(void *self, const void *session) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *) =
            (int (*)(void *, const void *))(*(void ***)delegate)[7];
        int status = fn(delegate, session);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    /* session is an android::Vector<uint8>: [+8]=mArray [+16]=mSize. */
    const uint8_t *id = session
        ? *(const uint8_t *const *)((const char *)session + 8) : NULL;
    size_t id_size = session
        ? *(const size_t *)((const char *)session + 16) : 0;
    if (!id || id_size != 16) return XENOID_DRM_STATUS_UNSUPPORTED;
    pthread_mutex_lock(&d->session_lock);
    for (uint32_t s = 0; s < d->session_count; s++) {
        if (!memcmp(d->sessions[s], id, 16)) {
            d->session_count--;
            if (s < d->session_count) {
                memmove(d->sessions[s], d->sessions[s + 1],
                        (d->session_count - s) * 16);
            }
            pthread_mutex_unlock(&d->session_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&d->session_lock);
    return XENOID_DRM_STATUS_UNSUPPORTED;
}

static int xenoid_drm_get_security_level(void *self, const void *session,
                                         int32_t *level) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *, int32_t *) =
            (int (*)(void *, const void *, int32_t *))(*(void ***)delegate)[23];
        int status = fn(delegate, session, level);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    (void)session;
    if (level) *level = XENOID_DRM_SECURITY_LEVEL_L1;
    return 0;
}

static int xenoid_drm_get_number_of_sessions(void *self, uint32_t *current,
                                             uint32_t *maximum) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, uint32_t *, uint32_t *) =
            (int (*)(void *, uint32_t *, uint32_t *))(*(void ***)delegate)[22];
        int status = fn(delegate, current, maximum);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    if (current) {
        pthread_mutex_lock(&d->session_lock);
        *current = d->session_count;
        pthread_mutex_unlock(&d->session_lock);
    }
    if (maximum) *maximum = XENOID_DRM_MAX_SESSIONS;
    return 0;
}

static int xenoid_drm_get_hdcp_levels(void *self, int32_t *connected,
                                      int32_t *maximum) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, int32_t *, int32_t *) =
            (int (*)(void *, int32_t *, int32_t *))(*(void ***)delegate)[21];
        int status = fn(delegate, connected, maximum);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    /* Coherent with the hdcpLevel/maxHdcpLevel property strings. */
    if (connected) *connected = XENOID_DRM_HDCP_LEVEL_V2_2;
    if (maximum) *maximum = XENOID_DRM_HDCP_LEVEL_V2_2;
    return 0;
}

static int xenoid_drm_get_property_string(void *self, const void *name,
                                          void *value) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *, void *) =
            (int (*)(void *, const void *, void *))(*(void ***)delegate)[27];
        int status = fn(delegate, name, value);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    const char *key = xenoid_string8_cstr(name);
    const char *result = NULL;
    char sessions_text[16];
    if (!strcmp(key, "vendor")) result = "Google";
    else if (!strcmp(key, "version")) result = "16.1.0";
    else if (!strcmp(key, "description")) result = "Widevine CDM";
    else if (!strcmp(key, "algorithms")) result = "";
    else if (!strcmp(key, "securityLevel")) result = "L1";
    else if (!strcmp(key, "hdcpLevel")) result = "HDCP_V2_2";
    else if (!strcmp(key, "maxHdcpLevel")) result = "HDCP_V2_2";
    else if (!strcmp(key, "usageReportingSupport")) result = "False";
    else if (!strcmp(key, "maxSessionCount")) result = "64";
    else if (!strcmp(key, "numberOfOpenSessions")) {
        pthread_mutex_lock(&d->session_lock);
        snprintf(sessions_text, sizeof(sessions_text), "%u",
                 (unsigned int)d->session_count);
        pthread_mutex_unlock(&d->session_lock);
        result = sessions_text;
    }
    if (!result) return XENOID_DRM_STATUS_UNSUPPORTED;
    xenoid_string8_assign(value, result);
    return 0;
}

static int xenoid_drm_get_property_byte_array(void *self, const void *name,
                                              void *value) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *, void *) =
            (int (*)(void *, const void *, void *))(*(void ***)delegate)[28];
        int status = fn(delegate, name, value);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    const char *key = xenoid_string8_cstr(name);
    if (!strcmp(key, "deviceUniqueId")) {
        uint8_t identity[16];
        if (xenoid_drm_read_identity(identity) != 0) {
            return XENOID_DRM_STATUS_UNSUPPORTED;
        }
        return xenoid_fill_vector(value, identity, sizeof(identity));
    }
    return XENOID_DRM_STATUS_UNSUPPORTED;
}

static int xenoid_drm_set_listener(void *self, const void *listener) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *) =
            (int (*)(void *, const void *))(*(void ***)delegate)[39];
        int status = fn(delegate, listener);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }

    /* listener is a const sp<IDrmClient>&. Hold exactly one strong reference,
       replacing and releasing the previous listener just like a real DrmHal. */
    void *client = listener ? *(void * const *)listener : NULL;
    void *client_refbase = xenoid_refbase_from_interface(client);
    if (client && !client_refbase) return XENOID_DRM_STATUS_UNSUPPORTED;
    if (client_refbase) real_inc_strong(client_refbase, &d->listener);

    pthread_mutex_lock(&d->listener_lock);
    void *previous_refbase = d->listener_refbase;
    d->listener = client;
    d->listener_refbase = client_refbase;
    pthread_mutex_unlock(&d->listener_lock);

    if (previous_refbase) {
        real_dec_strong(previous_refbase, &d->listener);
    }
    return 0;
}

/* Stock Widevine L1 runs video entirely in the TEE, so a secure decoder is
   required for video mime types and not for audio. IDrm passes the mime as
   a plain const char* here (unlike getPropertyString's const String8&),
   verified against DrmHal::requiresSecureDecoder(const char*, bool*). */
static int xenoid_secure_decoder_required(const void *mime, uint8_t *required) {
    if (required) {
        const char *text = (const char *)mime;
        *required = text && !strncmp(text, "video/", 6);
    }
    return 0;
}

static int xenoid_drm_requires_secure_decoder(void *self, const void *mime,
                                              uint8_t *required) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *, uint8_t *) =
            (int (*)(void *, const void *, uint8_t *))(*(void ***)delegate)[40];
        int status = fn(delegate, mime, required);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    return xenoid_secure_decoder_required(mime, required);
}

static int xenoid_drm_requires_secure_decoder_level(void *self,
                                                    const void *mime,
                                                    int32_t level,
                                                    uint8_t *required) {
    struct XenoidDrm *d = xenoid_self(self);
    void *delegate = xenoid_drm_delegate_acquire(d);
    if (delegate) {
        int (*fn)(void *, const void *, int32_t, uint8_t *) =
            (int (*)(void *, const void *, int32_t, uint8_t *))
                (*(void ***)delegate)[41];
        int status = fn(delegate, mime, level, required);
        xenoid_drm_delegate_release(d, delegate);
        return status;
    }
    (void)level;
    return xenoid_secure_decoder_required(mime, required);
}

static int xenoid_drm_get_supported_schemes(void *self, void *schemes) {
    struct XenoidDrm *d = xenoid_self(self);
    uint8_t identity[16];
    int identity_available = xenoid_drm_read_identity(identity) == 0;
    void *delegate = xenoid_drm_delegate_acquire(d);
    int factory_status = 0;
    int transient = 0;
    if (!delegate) {
        delegate = xenoid_make_real_drm(&factory_status);
        transient = delegate != NULL;
    }
    int status = factory_status;
    if (delegate) {
        int (*fn)(void *, void *) =
            (int (*)(void *, void *))(*(void ***)delegate)[44];
        status = fn(delegate, schemes);
        if (transient) {
            real_dec_strong(xenoid_refbase_from_interface(delegate), &delegate);
        } else {
            xenoid_drm_delegate_release(d, delegate);
        }
    } else {
        uint8_t **slots = (uint8_t **)schemes;
        slots[0] = NULL;
        slots[1] = NULL;
        slots[2] = NULL;
    }
    if (!identity_available) return status;
    if (status != 0) {
        uint8_t **slots = (uint8_t **)schemes;
        slots[0] = NULL;
        slots[1] = NULL;
        slots[2] = NULL;
        return xenoid_fill_std_vector(schemes, XENOID_WIDEVINE_UUID, 16);
    }
    return xenoid_append_std_vector(schemes, XENOID_WIDEVINE_UUID, 16);
}

/* RefBase lifecycle callbacks beyond destruction need no custom behavior. */
static int xenoid_refbase_noop(void *self) { (void)self; return 0; }

/* ------------------------------------------------------------------ */
/* Vtables: 3-qword header [this-to-RefBase displacement][0][0], then slots */

static void *xenoid_drm_vtable[] = {
    (void *)(uintptr_t)0x18,
    NULL,
    NULL,
    xenoid_drm_complete_dtor,         /*  0 complete dtor */
    xenoid_drm_deleting_dtor,         /*  1 deleting dtor */
    xenoid_drm_init_check,            /*  2 initCheck */
    xenoid_drm_is_crypto_supported,   /*  3 isCryptoSchemeSupported */
    xenoid_drm_create_plugin,         /*  4 createPlugin */
    xenoid_drm_destroy_plugin,        /*  5 destroyPlugin */
    xenoid_drm_open_session,          /*  6 openSession */
    xenoid_drm_close_session,         /*  7 closeSession */
    xenoid_drm_delegate_8,            /*  8 getKeyRequest */
    xenoid_drm_delegate_9,            /*  9 provideKeyResponse */
    xenoid_drm_delegate_10,           /* 10 removeKeys */
    xenoid_drm_delegate_11,           /* 11 restoreKeys */
    xenoid_drm_delegate_12,           /* 12 queryKeyStatus */
    xenoid_drm_delegate_13,           /* 13 getProvisionRequest */
    xenoid_drm_delegate_14,           /* 14 provideProvisionResponse */
    xenoid_drm_delegate_15,           /* 15 getSecureStops */
    xenoid_drm_delegate_16,           /* 16 getSecureStopIds */
    xenoid_drm_delegate_17,           /* 17 getSecureStop */
    xenoid_drm_delegate_18,           /* 18 releaseSecureStops */
    xenoid_drm_delegate_19,           /* 19 removeSecureStop */
    xenoid_drm_delegate_20,           /* 20 removeAllSecureStops */
    xenoid_drm_get_hdcp_levels,       /* 21 getHdcpLevels */
    xenoid_drm_get_number_of_sessions,/* 22 getNumberOfSessions */
    xenoid_drm_get_security_level,    /* 23 getSecurityLevel */
    xenoid_drm_delegate_24,           /* 24 getOfflineLicenseKeySetIds */
    xenoid_drm_delegate_25,           /* 25 removeOfflineLicense */
    xenoid_drm_delegate_26,           /* 26 getOfflineLicenseState */
    xenoid_drm_get_property_string,   /* 27 getPropertyString */
    xenoid_drm_get_property_byte_array,/* 28 getPropertyByteArray */
    xenoid_drm_delegate_29,           /* 29 setPropertyString */
    xenoid_drm_delegate_30,           /* 30 setPropertyByteArray */
    xenoid_drm_delegate_31,           /* 31 getMetrics */
    xenoid_drm_delegate_32,           /* 32 setCipherAlgorithm */
    xenoid_drm_delegate_33,           /* 33 setMacAlgorithm */
    xenoid_drm_delegate_34,           /* 34 encrypt */
    xenoid_drm_delegate_35,           /* 35 decrypt */
    xenoid_drm_delegate_36,           /* 36 sign */
    xenoid_drm_delegate_37,           /* 37 verify */
    xenoid_drm_delegate_38,           /* 38 signRSA */
    xenoid_drm_set_listener,          /* 39 setListener */
    xenoid_drm_requires_secure_decoder,/* 40 requiresSecureDecoder(mime) */
    xenoid_drm_requires_secure_decoder_level,/* 41 requiresSecureDecoder(mime,level) */
    xenoid_drm_delegate_42,           /* 42 setPlaybackId */
    xenoid_drm_delegate_43,           /* 43 getLogMessages */
    xenoid_drm_get_supported_schemes, /* 44 getSupportedSchemes */
};

static void *xenoid_refbase_vtable[] = {
    (void *)(uintptr_t)-24,
    NULL,
    NULL,
    xenoid_refbase_complete_dtor,     /* complete dtor */
    xenoid_refbase_deleting_dtor,     /* deleting dtor */
    xenoid_refbase_noop,              /* onFirstRef */
    xenoid_refbase_noop,              /* onLastStrongRef */
    xenoid_refbase_noop,              /* onIncStrongAttempted */
    xenoid_refbase_noop,              /* onLastWeakRef */
};

/* ------------------------------------------------------------------ */
/* The interposed factory                                               */

static uint32_t xenoid_drm_random32(void) {
    uint32_t value = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, &value, sizeof(value));
        close(fd);
        if (n == (ssize_t)sizeof(value)) return value;
    }
    return (uint32_t)(uintptr_t)&value ^ 0x9e3779b9u;
}

/* The interposed factory is entered through xenoid_drm_sret.S, which hands
   the caller's x8 sret destination over as the second argument (C cannot
   receive x8 reliably after compiler-generated prologue code). */
__attribute__((visibility("hidden")))
void *xenoid_drm_make_impl(int *status, void *sret) {
    if (sret) *(void **)sret = NULL;
    if (!sret) {
        if (status) *status = XENOID_DRM_STATUS_UNSUPPORTED;
        return NULL;
    }
    resolve_real_symbols();
    if (!real_refbase_ctor || !real_refbase_dtor
            || !real_inc_strong || !real_dec_strong) {
        if (status) *status = XENOID_DRM_STATUS_UNSUPPORTED;
        return sret;
    }
    struct XenoidDrm *d = calloc(1, sizeof(*d));
    if (!d) {
        if (status) *status = XENOID_DRM_STATUS_UNSUPPORTED;
        return sret;
    }
    d->vptr = &xenoid_drm_vtable[3];
    /* Construct RefBase before replacing its vptr with the derived table. */
    real_refbase_ctor((char *)d + 24);
    d->refbase_vptr = &xenoid_refbase_vtable[3];
    if (pthread_mutex_init(&d->listener_lock, NULL) != 0
            || pthread_mutex_init(&d->delegate_lock, NULL) != 0
            || pthread_mutex_init(&d->session_lock, NULL) != 0) {
        real_refbase_dtor((char *)d + 24);
        free(d);
        if (status) *status = XENOID_DRM_STATUS_UNSUPPORTED;
        return sret;
    }
    *(void **)sret = d;
    /* Establish the strong ownership represented by the returned sp<IDrm>. */
    real_inc_strong((char *)d + 24, sret);
    if (status) *status = 0;
    return sret;
}
