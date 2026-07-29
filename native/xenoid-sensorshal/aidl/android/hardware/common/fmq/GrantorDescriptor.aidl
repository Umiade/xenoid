package android.hardware.common.fmq;

/** Shared-memory region used by an FMQ descriptor. @hide */
@VintfStability
parcelable GrantorDescriptor {
    int fdIndex;
    int offset;
    long extent;
}
