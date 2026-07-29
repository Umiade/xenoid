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

/*
 * Included in MQDescriptor, for use with libfmq.
 * @hide
 */
@VintfStability
parcelable GrantorDescriptor {
    /*
     * Index of file descriptor for this grantor
     */
    int fdIndex;
    /*
     * The offset of this descriptor in the shared memory in bytes.
     */
    int offset;
    /*
     * The size of this descriptor in bytes.
     */
    long extent;
}
