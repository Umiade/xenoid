/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.common.fmq;

import android.hardware.common.NativeHandle;
import android.hardware.common.fmq.GrantorDescriptor;

/*
 * For use with libfmq. This is created from an instance of AidlMessageQueue,
 * and is used to pass information required to create another instance of that
 * queue for fast communication.
 * T - is used to specify the type of the payload
 * Flavor - is used to specify the type of the queue using
 * android.hardware.common.SynchronizedReadWrite or UnsynchronizedWrite
 * @hide
 */
@VintfStability
parcelable MQDescriptor<T, Flavor> {
    /*
     * Describes each of the grantors for the message queue. They are used to
     * get the readptr, writeptr, dataptr, and the optional EventFlag word
     * for blocking operations in the shared memory.
     */
    GrantorDescriptor[] grantors;
    /*
     * NativeHandle that contains the file descriptors for shared memory used
     * in the message queue
     */
    NativeHandle handle;
    /* Size of each item, T, in bytes */
    int quantum;
    /* EventFlag word for blocking operations */
    int flags;
}
