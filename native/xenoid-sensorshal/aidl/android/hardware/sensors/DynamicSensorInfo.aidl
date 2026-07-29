/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.hardware.sensors;

@VintfStability
@FixedSize
parcelable DynamicSensorInfo {
    boolean connected;

    int sensorHandle;

    /**
     * UUID of a dynamic sensor (using RFC 4122 byte order)
     * For UUID 12345678-90AB-CDEF-1122-334455667788 the uuid field is
     * initialized as:
     *   {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x11, ...}
     */
    Uuid uuid;

    @FixedSize
    @VintfStability
    parcelable Uuid {
        byte[16] values;
    }
}
