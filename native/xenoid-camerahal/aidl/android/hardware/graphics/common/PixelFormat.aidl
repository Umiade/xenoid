/*
 * Copyright 2019 The Android Open Source Project
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

package android.hardware.graphics.common;

/**
 * Pixel formats for graphics buffers.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum PixelFormat {
    /**
     * This value may be used in an operation where the format is optional.
     */
    UNSPECIFIED = 0,
    /**
     * 32-bit format that has 8-bit R, G, B, and A components, in that order,
     * from the lowest memory address to the highest memory address.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    RGBA_8888 = 0x1,

    /**
     * 32-bit format that has 8-bit R, G, B, and unused components, in that
     * order, from the lowest memory address to the highest memory address.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    RGBX_8888 = 0x2,

    /**
     * 24-bit format that has 8-bit R, G, and B components, in that order,
     * from the lowest memory address to the highest memory address.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    RGB_888 = 0x3,

    /**
     * 16-bit packed format that has 5-bit R, 6-bit G, and 5-bit B components,
     * in that order, from the most-sigfinicant bits to the least-significant
     * bits.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    RGB_565 = 0x4,

    /**
     * 32-bit format that has 8-bit B, G, R, and A components, in that order,
     * from the lowest memory address to the highest memory address.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    BGRA_8888 = 0x5,

    /**
     * Legacy formats deprecated in favor of YCBCR_420_888.
     */
    YCBCR_422_SP = 0x10, // NV16
    YCRCB_420_SP = 0x11, // NV21
    YCBCR_422_I = 0x14, // YUY2

    /**
     * 64-bit format that has 16-bit R, G, B, and A components, in that order,
     * from the lowest memory address to the highest memory address.
     *
     * The component values are signed floats, whose interpretation is defined
     * by the dataspace.
     */
    RGBA_FP16 = 0x16,

    /**
     * RAW16 is a single-channel, 16-bit, little endian format, typically
     * representing raw Bayer-pattern images from an image sensor, with minimal
     * processing.
     *
     * The exact pixel layout of the data in the buffer is sensor-dependent, and
     * needs to be queried from the camera device.
     *
     * Generally, not all 16 bits are used; more common values are 10 or 12
     * bits. If not all bits are used, the lower-order bits are filled first.
     * All parameters to interpret the raw data (black and white points,
     * color space, etc) must be queried from the camera device.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     * - strides are specified in pixels, not in bytes
     *
     *   size = stride * height * 2
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::RENDERSCRIPT
     *
     * The mapping of the dataspace to buffer contents for RAW16 is as
     * follows:
     *
     *  Dataspace value               | Buffer contents
     * -------------------------------+-----------------------------------------
     *  Dataspace::ARBITRARY          | Raw image sensor data, layout is as
     *                                | defined above.
     *  Dataspace::DEPTH              | Unprocessed implementation-dependent raw
     *                                | depth measurements, opaque with 16 bit
     *                                | samples.
     *  Other                         | Unsupported
     */
    RAW16 = 0x20,

    /**
     * BLOB is used to carry task-specific data which does not have a standard
     * image structure. The details of the format are left to the two
     * endpoints.
     *
     * A typical use case is for transporting JPEG-compressed images from the
     * Camera HAL to the framework or to applications.
     *
     * Buffers of this format must have a height of 1, and width equal to their
     * size in bytes.
     *
     * The mapping of the dataspace to buffer contents for BLOB is as
     * follows:
     *
     *  Dataspace value               | Buffer contents
     * -------------------------------+-----------------------------------------
     *  Dataspace::JFIF               | An encoded JPEG image
     *  Dataspace::DEPTH              | An android_depth_points buffer
     *  Dataspace::SENSOR             | Sensor event data.
     *  Other                         | Unsupported
     */
    BLOB = 0x21,

    /**
     * A format indicating that the choice of format is entirely up to the
     * allocator.
     *
     * The allocator should examine the usage bits passed in when allocating a
     * buffer with this format, and it should derive the pixel format from
     * those usage flags. This format must never be used with any of the
     * BufferUsage::CPU_* usage flags.
     *
     * Even when the internally chosen format has an alpha component, the
     * clients must assume the alpha vlaue to be 1.0.
     *
     * The interpretation of the component values is defined by the dataspace.
     */
    IMPLEMENTATION_DEFINED = 0x22,

    /**
     * This format allows platforms to use an efficient YCbCr/YCrCb 4:2:0
     * buffer layout, while still describing the general format in a
     * layout-independent manner. While called YCbCr, it can be used to
     * describe formats with either chromatic ordering, as well as
     * whole planar or semiplanar layouts.
     *
     * This format must be accepted by the allocator when BufferUsage::CPU_*
     * are set.
     *
     * Buffers with this format must be locked with IMapper::lockYCbCr.
     * Locking with IMapper::lock must return an error.
     *
     * The interpretation of the component values is defined by the dataspace.
     */
    YCBCR_420_888 = 0x23,

    /**
     * RAW_OPAQUE is a format for unprocessed raw image buffers coming from an
     * image sensor. The actual structure of buffers of this format is
     * implementation-dependent.
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::RENDERSCRIPT
     *
     * The mapping of the dataspace to buffer contents for RAW_OPAQUE is as
     * follows:
     *
     *  Dataspace value               | Buffer contents
     * -------------------------------+-----------------------------------------
     *  Dataspace::ARBITRARY          | Raw image sensor data.
     *  Other                         | Unsupported
     */
    RAW_OPAQUE = 0x24,

    /**
     * RAW10 is a single-channel, 10-bit per pixel, densely packed in each row,
     * unprocessed format, usually representing raw Bayer-pattern images coming from
     * an image sensor.
     *
     * In an image buffer with this format, starting from the first pixel of each
     * row, each 4 consecutive pixels are packed into 5 bytes (40 bits). Each one
     * of the first 4 bytes contains the top 8 bits of each pixel, The fifth byte
     * contains the 2 least significant bits of the 4 pixels, the exact layout data
     * for each 4 consecutive pixels is illustrated below (Pi[j] stands for the jth
     * bit of the ith pixel):
     *
     *          bit 7                                     bit 0
     *          =====|=====|=====|=====|=====|=====|=====|=====|
     * Byte 0: |P0[9]|P0[8]|P0[7]|P0[6]|P0[5]|P0[4]|P0[3]|P0[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 1: |P1[9]|P1[8]|P1[7]|P1[6]|P1[5]|P1[4]|P1[3]|P1[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 2: |P2[9]|P2[8]|P2[7]|P2[6]|P2[5]|P2[4]|P2[3]|P2[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 3: |P3[9]|P3[8]|P3[7]|P3[6]|P3[5]|P3[4]|P3[3]|P3[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 4: |P3[1]|P3[0]|P2[1]|P2[0]|P1[1]|P1[0]|P0[1]|P0[0]|
     *          ===============================================
     *
     * This format assumes
     * - a width multiple of 4 pixels
     * - an even height
     * - a vertical stride equal to the height
     * - strides are specified in bytes, not in pixels
     *
     *   size = stride * height
     *
     * When stride is equal to width * (10 / 8), there will be no padding bytes at
     * the end of each row, the entire image data is densely packed. When stride is
     * larger than width * (10 / 8), padding bytes will be present at the end of each
     * row (including the last row).
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::RENDERSCRIPT
     *
     * The mapping of the dataspace to buffer contents for RAW10 is as
     * follows:
     *
     *  Dataspace value               | Buffer contents
     * -------------------------------+-----------------------------------------
     *  Dataspace::ARBITRARY          | Raw image sensor data.
     *  Other                         | Unsupported
     */
    RAW10 = 0x25,

    /**
     * RAW12 is a single-channel, 12-bit per pixel, densely packed in each row,
     * unprocessed format, usually representing raw Bayer-pattern images coming from
     * an image sensor.
     *
     * In an image buffer with this format, starting from the first pixel of each
     * row, each two consecutive pixels are packed into 3 bytes (24 bits). The first
     * and second byte contains the top 8 bits of first and second pixel. The third
     * byte contains the 4 least significant bits of the two pixels, the exact layout
     * data for each two consecutive pixels is illustrated below (Pi[j] stands for
     * the jth bit of the ith pixel):
     *
     *           bit 7                                            bit 0
     *          ======|======|======|======|======|======|======|======|
     * Byte 0: |P0[11]|P0[10]|P0[ 9]|P0[ 8]|P0[ 7]|P0[ 6]|P0[ 5]|P0[ 4]|
     *         |------|------|------|------|------|------|------|------|
     * Byte 1: |P1[11]|P1[10]|P1[ 9]|P1[ 8]|P1[ 7]|P1[ 6]|P1[ 5]|P1[ 4]|
     *         |------|------|------|------|------|------|------|------|
     * Byte 2: |P1[ 3]|P1[ 2]|P1[ 1]|P1[ 0]|P0[ 3]|P0[ 2]|P0[ 1]|P0[ 0]|
     *          =======================================================
     *
     * This format assumes:
     * - a width multiple of 4 pixels
     * - an even height
     * - a vertical stride equal to the height
     * - strides are specified in bytes, not in pixels
     *
     *   size = stride * height
     *
     * When stride is equal to width * (12 / 8), there will be no padding bytes at
     * the end of each row, the entire image data is densely packed. When stride is
     * larger than width * (12 / 8), padding bytes will be present at the end of
     * each row (including the last row).
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::RENDERSCRIPT
     *
     * The mapping of the dataspace to buffer contents for RAW12 is as
     * follows:
     *
     *  Dataspace value               | Buffer contents
     * -------------------------------+-----------------------------------------
     *  Dataspace::ARBITRARY          | Raw image sensor data.
     *  Other                         | Unsupported
     */
    RAW12 = 0x26,

    /** 0x27 to 0x2A are reserved for flexible formats */

    /**
     * 32-bit packed format that has 2-bit A, 10-bit B, G, and R components,
     * in that order, from the most-sigfinicant bits to the least-significant
     * bits.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    RGBA_1010102 = 0x2B,

    /**
     * 0x100 - 0x1FF
     *
     * This range is reserved for vendor extensions. Formats in this range
     * must support BufferUsage::GPU_TEXTURE. Clients must assume they do not
     * have an alpha component.
     */

    /**
     * Y8 is a YUV planar format comprised of a WxH Y plane, with each pixel
     * being represented by 8 bits. It is equivalent to just the Y plane from
     * YV12.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     *
     *   size = stride * height
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    Y8 = 0x20203859,

    /**
     * Y16 is a YUV planar format comprised of a WxH Y plane, with each pixel
     * being represented by 16 bits. It is just like Y8, but has double the
     * bits per pixel (little endian).
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     * - strides are specified in pixels, not in bytes
     *
     *   size = stride * height * 2
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace. When the dataspace is
     * Dataspace::DEPTH, each pixel is a distance value measured by a depth
     * camera, plus an associated confidence value.
     */
    Y16 = 0x20363159,

    /**
     * YV12 is a 4:2:0 YCrCb planar format comprised of a WxH Y plane followed
     * by (W/2) x (H/2) Cr and Cb planes.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     *
     *   y_size = stride * height
     *   c_stride = ALIGN(stride/2, 16)
     *   c_size = c_stride * height/2
     *   size = y_size + c_size * 2
     *   cr_offset = y_size
     *   cb_offset = y_size + c_size
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::CAMERA_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::GPU_TEXTURE
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    YV12 = 0x32315659, // YCrCb 4:2:0 Planar

    /**
     * 16-bit format that has a single 16-bit depth component.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    DEPTH_16 = 0x30,

    /**
     * 32-bit format that has a single 24-bit depth component and, optionally,
     * 8 bits that are unused.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    DEPTH_24 = 0x31,

    /**
     * 32-bit format that has a 24-bit depth component and an 8-bit stencil
     * component packed into 32-bits.
     *
     * The depth component values are unsigned normalized to the range [0, 1],
     * whose interpretation is defined by the dataspace. The stencil values are
     * unsigned integers, whose interpretation is defined by the dataspace.
     */
    DEPTH_24_STENCIL_8 = 0x32,

    /**
     * 32-bit format that has a single 32-bit depth component.
     *
     * The component values are signed floats, whose interpretation is defined
     * by the dataspace.
     */
    DEPTH_32F = 0x33,

    /**
     * Two-component format that has a 32-bit depth component, an 8-bit stencil
     * component, and optionally 24-bits unused.
     *
     * The depth component values are signed floats, whose interpretation is
     * defined by the dataspace. The stencil bits are unsigned integers, whose
     * interpretation is defined by the dataspace.
     */
    DEPTH_32F_STENCIL_8 = 0x34,

    /**
     * 8-bit format that has a single 8-bit stencil component.
     *
     * The component values are unsigned integers, whose interpretation is
     * defined by the dataspace.
     */
    STENCIL_8 = 0x35,

    /**
     * P010 is a 4:2:0 YCbCr semiplanar format comprised of a WxH Y plane
     * followed by a Wx(H/2) CbCr plane. Each sample is represented by a 16-bit
     * little-endian value, with the lower 6 bits set to zero.
     *
     * This format must be accepted by the allocator when used with the
     * following usage flags:
     *
     *    - BufferUsage::VIDEO_*
     *    - BufferUsage::CPU_*
     *    - BufferUsage::GPU_TEXTURE
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     *
     * This format is appropriate for 10bit video content.
     *
     * Buffers with this format must be locked with IMapper::lockYCbCr
     * or with IMapper::lock.
     */
    YCBCR_P010 = 0x36,

    /**
     * 24-bit format that has 8-bit H, S, and V components, in that order,
     * from the lowest memory address to the highest memory address.
     *
     * The component values are unsigned normalized to the range [0, 1], whose
     * interpretation is defined by the dataspace.
     */
    HSV_888 = 0x37,

    /**
     * 8 bit format with a single 8-bit component.
     *
     * The component values are unsigned normalized to the range [0, 1].
     */
    R_8 = 0x38,
}
