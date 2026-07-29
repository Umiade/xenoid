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

import android.hardware.graphics.common.PlaneLayoutComponent;
import android.hardware.graphics.common.Rect;

/**
 * Used by IAllocator/IMapper (gralloc) to describe the plane layout of a buffer.
 *
 * PlaneLayout uses the following definitions:
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
parcelable PlaneLayout {
    /**
     * An list of plane layout components. This list of components should include
     * every component in this plane. For example, a CbCr plane should return a
     * vector of size two with one PlaneLayoutComponent for Cb and one for Cr.
     */
    PlaneLayoutComponent[] components;

    /**
     * Offset to the first byte of the plane (in bytes), from the start of the allocation.
     */
    long offsetInBytes;

    /**
     * Bits per sample increment (aka column increment): describes the distance
     * in bits from one sample to the next sample (to the right) on the same row for the
     * the component plane.
     *
     * The default value is 0. Return the default value if the increment is undefined, unknown,
     * or variable.
     *
     * This can be negative. A negative increment indicates that the samples are read from
     * right to left.
     */
    long sampleIncrementInBits;

    /**
     * Horizontal stride: number of bytes between two vertically adjacent
     * samples in given plane. This can be mathematically described by:
     *
     * strideInBytes = ALIGN(widthInSamples * bps / 8, alignment)
     *
     * where,
     *
     * bps: average bits per sample
     * alignment (in bytes): dependent upon pixel format and usage
     *
     * strideInBytes can contain additional padding beyond the widthInSamples.
     *
     * The default value is 0. Return the default value if the stride is undefined, unknown,
     * or variable.
     *
     * This can be negative. A negative stride indicates that the rows are read from
     * bottom to top.
     */
    long strideInBytes;

    /**
     * Dimensions of plane (in samples).
     *
     * This is the number of samples in the plane, even if subsampled.
     *
     * See 'strideInBytes' for relationship between strideInBytes and widthInSamples.
     */
    long widthInSamples;
    long heightInSamples;

    /**
     * Can be used to get the total size in bytes of any memory used by the plane
     * including extra padding. This should not include any extra metadata used to describe the
     * plane.
     */
    long totalSizeInBytes;

    /**
     * Horizontal and vertical subsampling. Must be a positive power of 2. A value of 1
     * indicates no subsampling.
     *
     * These fields indicate the number of horizontally or vertically adjacent pixels that use
     * the same pixel data.
     */
    long horizontalSubsampling;
    long verticalSubsampling;
}
