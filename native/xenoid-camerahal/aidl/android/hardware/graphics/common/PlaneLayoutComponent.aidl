/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.graphics.common;

import android.hardware.graphics.common.ExtendableType;

/**
 * Used by IAllocator/IMapper (gralloc) to describe the type and location of a component in a
 * buffer's plane.
 *
 * PlaneLayoutComponent uses the following definitions:
 *
 * - Component - a component is one channel of a pixel. For example, an RGBA format has
 *      four components: R, G, B and A.
 * - Sample - a sample is comprised of all the components in a given plane. For example,
 *      a buffer with one Y plane and one CbCr plane has one plane with a sample of Y
 *      and one plane with a sample of CbCr.
 * - Pixel - a pixel is comprised of all the (non-metadata/raw) components in buffer across
 *      all planes. For example, a buffer with a plane of Y and a plane of CbCr has a pixel
 *      of YCbCr.
 * @hide
 */

@VintfStability
parcelable PlaneLayoutComponent {
    /**
     * The type of this plane layout component.
     *
     * android.hardware.graphics.common.PlaneLayoutComponentType defines the standard
     * plane layout component types. Vendors may extend this type to include any
     * non-standard plane layout component types. For instructions on how to
     * create a vendor extension, refer to ExtendableType.aidl.
     */
    ExtendableType type;

    /**
     * Offset in bits to the first instance of this component in the plane.
     * This is relative to the plane's offset (PlaneLayout::offset).
     *
     * If the offset cannot be described using a int64_t, this should be set to -1.
     * For example, if the plane is compressed and the offset is not defined or
     * relevant, return -1.
     */
    long offsetInBits;

    /**
     * The number of bits used per component in the plane.
     *
     * If the plane layout component cannot be described using componentSizeInBits, this
     * should be set to -1. For example, if the component varies in size throughout
     * the plane, return -1.
     */
    long sizeInBits;
}
