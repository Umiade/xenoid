// xenoid_drm_sret.S — AArch64 entry shim for android::DrmUtils::MakeDrm.
//
// The real factory returns sp<IDrm>, a non-trivial C++ object, so callers
// pass the sret destination pointer in x8. C cannot declare that convention,
// and an inline-asm read of x8 inside the C body is not guaranteed to see
// the incoming value (the compiler may reuse x8 first). This stub moves x8
// into the second argument register before any compiler-generated code can
// clobber it and tail-calls the C implementation.
    .text
    .globl  _ZN7android8DrmUtils7MakeDrmEPi
    .type   _ZN7android8DrmUtils7MakeDrmEPi, @function
_ZN7android8DrmUtils7MakeDrmEPi:
    mov     x1, x8
    b       xenoid_drm_make_impl
    .size   _ZN7android8DrmUtils7MakeDrmEPi, .-_ZN7android8DrmUtils7MakeDrmEPi

// Call the next MakeDrm implementation with its indirect sp<IDrm> result in
// x8. C passes factory/status/result as x0/x1/x2 to this bridge.
    .globl  xenoid_drm_call_real
    .hidden xenoid_drm_call_real
    .type   xenoid_drm_call_real, @function
xenoid_drm_call_real:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x2, [sp, #16]
    mov     x9, x0
    mov     x0, x1
    mov     x8, x2
    blr     x9
    ldr     x0, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

    .size   xenoid_drm_call_real, .-xenoid_drm_call_real
// Forward one IDrm vtable slot to XenoidDrm::delegate. The C acquire helper
// resolves the delegate under the object's delegate lock and holds a strong
// reference on it for the duration of the call, so a concurrent destroyPlugin
// can never free the plugin mid-call; the release helper drops that reference
// on the way out. IDrm methods take at most seven argument registers (no SIMD
// or stack arguments), so saving x1-x8 across the acquire call preserves every
// method-specific argument, and the delegate method runs with the caller's
// stack untouched and returns through the release stub below.
    .macro  XENOID_DRM_DELEGATE slot
    .globl  xenoid_drm_delegate_\slot
    .hidden xenoid_drm_delegate_\slot
    .type   xenoid_drm_delegate_\slot, @function
xenoid_drm_delegate_\slot:
    stp     x29, x30, [sp, #-128]!
    mov     x29, sp
    stp     x1, x2, [sp, #16]
    stp     x3, x4, [sp, #32]
    stp     x5, x6, [sp, #48]
    stp     x7, x8, [sp, #64]
    str     x0, [sp, #80]
    bl      xenoid_drm_delegate_acquire
    cbz     x0, .Lunsupported_\@
    str     x0, [sp, #88]
    mov     x9, x0
    ldp     x1, x2, [sp, #16]
    ldp     x3, x4, [sp, #32]
    ldp     x5, x6, [sp, #48]
    ldp     x7, x8, [sp, #64]
    ldr     x10, [x9]
    ldr     x10, [x10, #(\slot * 8)]
    mov     x0, x9
    adr     x30, .Lreleased_\@
    br      x10
.Lreleased_\@:
    str     x0, [sp, #96]
    ldr     x0, [sp, #80]
    ldr     x1, [sp, #88]
    bl      xenoid_drm_delegate_release
    ldr     x0, [sp, #96]
    ldp     x29, x30, [sp], #128
    ret
.Lunsupported_\@:
    mov     w0, #-22
    ldp     x29, x30, [sp], #128
    ret
    .size   xenoid_drm_delegate_\slot, .-xenoid_drm_delegate_\slot
    .endm

    .irp slot, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 26, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 42, 43
    XENOID_DRM_DELEGATE \slot
    .endr

// Slot 8 (getKeyRequest) carries this + 8 parameters: AAPCS passes the 9th
// (keyRequestType*) on the stack, not in x8 (the indirect-result register).
// The register-only macro would never forward it, leaving the JNI reading a
// never-written out slot ("unknown key request type"). Copy the incoming
// stack argument into the delegate call's outgoing slot; everything else
// matches the register trampolines.
    .globl  xenoid_drm_delegate_8
    .hidden xenoid_drm_delegate_8
    .type   xenoid_drm_delegate_8, @function
xenoid_drm_delegate_8:
    ldr     x9, [sp]
    sub     sp, sp, #144
    stp     x29, x30, [sp, #128]
    mov     x29, sp
    str     x9, [sp]
    stp     x1, x2, [sp, #16]
    stp     x3, x4, [sp, #32]
    stp     x5, x6, [sp, #48]
    str     x7, [sp, #64]
    str     x0, [sp, #80]
    bl      xenoid_drm_delegate_acquire
    cbz     x0, .Lslot8_unsupported
    str     x0, [sp, #88]
    mov     x9, x0
    ldp     x1, x2, [sp, #16]
    ldp     x3, x4, [sp, #32]
    ldp     x5, x6, [sp, #48]
    ldr     x7, [sp, #64]
    ldr     x10, [x9]
    ldr     x10, [x10, #(8 * 8)]
    mov     x0, x9
    adr     x30, .Lslot8_released
    br      x10
.Lslot8_released:
    str     x0, [sp, #96]
    ldr     x0, [sp, #80]
    ldr     x1, [sp, #88]
    bl      xenoid_drm_delegate_release
    ldr     x0, [sp, #96]
    ldp     x29, x30, [sp, #128]
    add     sp, sp, #144
    ret
.Lslot8_unsupported:
    mov     w0, #-22
    ldp     x29, x30, [sp, #128]
    add     sp, sp, #144
    ret
    .size   xenoid_drm_delegate_8, .-xenoid_drm_delegate_8
    .section .note.GNU-stack,"",%progbits
