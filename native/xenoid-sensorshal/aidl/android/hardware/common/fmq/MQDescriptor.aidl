package android.hardware.common.fmq;
import android.hardware.common.NativeHandle;
import android.hardware.common.fmq.GrantorDescriptor;

@VintfStability
parcelable MQDescriptor<T, flavor> {
    GrantorDescriptor[] grantors;
    NativeHandle handle;
    int quantum;
    int flags;
}
