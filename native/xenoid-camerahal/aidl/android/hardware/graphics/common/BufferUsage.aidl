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
 * Buffer usage definitions.
 * @hide
 */
@VintfStability
@Backing(type="long")
enum BufferUsage {
    /** bit 0-3 is an enum */
    CPU_READ_MASK                      = 0xf,
    /** buffer is never read by CPU */
    CPU_READ_NEVER                     = 0,
    /** buffer is rarely read by CPU */
    CPU_READ_RARELY                    = 2,
    /** buffer is often read by CPU */
    CPU_READ_OFTEN                     = 3,

    /** bit 4-7 is an enum */
    CPU_WRITE_MASK                     = 0xf << 4,
    /** buffer is never written by CPU */
    CPU_WRITE_NEVER                    = 0 << 4,
    /** buffer is rarely written by CPU */
    CPU_WRITE_RARELY                   = 2 << 4,
    /** buffer is often written by CPU */
    CPU_WRITE_OFTEN                    = 3 << 4,

    /** buffer is used as a GPU texture */
    GPU_TEXTURE                        = 1 << 8,

    /** buffer is used as a GPU render target */
    GPU_RENDER_TARGET                  = 1 << 9,

    /** bit 10 must be zero */

    /** buffer is used as a composer HAL overlay layer */
    COMPOSER_OVERLAY                   = 1 << 11,
    /** buffer is used as a composer HAL client target */
    COMPOSER_CLIENT_TARGET             = 1 << 12,

    /** bit 13 must be zero */

    /**
     * Buffer is allocated with hardware-level protection against copying the
     * contents (or information derived from the contents) into unprotected
     * memory.
     */
    PROTECTED                          = 1 << 14,

    /** buffer is used as a hwcomposer HAL cursor layer */
    COMPOSER_CURSOR                    = 1 << 15,

    /** buffer is used as a video encoder input */
    VIDEO_ENCODER                      = 1 << 16,

    /** buffer is used as a camera HAL output */
    CAMERA_OUTPUT                      = 1 << 17,

    /** buffer is used as a camera HAL input */
    CAMERA_INPUT                       = 1 << 18,

    /** bit 19 must be zero */

    /** buffer is used as a renderscript allocation */
    RENDERSCRIPT                       = 1 << 20,

    /** bit 21 must be zero */

    /** buffer is used as a video decoder output */
    VIDEO_DECODER                      = 1 << 22,

    /** buffer is used as a sensor direct report output */
    SENSOR_DIRECT_DATA                 = 1 << 23,

    /**
     * buffer is used as as an OpenGL shader storage or uniform
     * buffer object
     */
    GPU_DATA_BUFFER                    = 1 << 24,

    /** buffer is used as a cube map texture */
    GPU_CUBE_MAP                       = 1 << 25,

    /** buffer contains a complete mipmap hierarchy */
    GPU_MIPMAP_COMPLETE                = 1 << 26,

    /**
     * Buffer is used as input for HEIC encoder.
     */
    HW_IMAGE_ENCODER                   = 1 << 27,

    /* Bits 28-31 are reserved for vendor usage */

    /**
    * Buffer is used for front-buffer rendering.
    *
    * To satisfy an allocation with this usage, the resulting buffer
    * must operate as equivalent to shared memory for all targets.
    *
    * For CPU_USAGE_* other than NEVER, this means the buffer must
    * "lock in place". The buffers must be directly accessible via mapping.
    *
    * For GPU_RENDER_TARGET the buffer must behave equivalent to a
    * single-buffered EGL surface. For example glFlush must perform
    * a flush, same as if the default framebuffer was single-buffered.
    *
    * For COMPOSER_* the HWC must not perform any caching for this buffer
    * when submitted for composition. HWCs do not need to do any form
    * of auto-refresh, and they are allowed to cache composition results between
    * presents from SF (such as for panel self-refresh), but for any given
    * present the buffer must be composited from even if it otherwise appears
    * to be the same as a previous composition.
    *
    * If the GPU & HWC supports EGL_SINGLE_BUFFER, then it is recommended that
    * FRONT_BUFFER usage is supported for the same formats as supported by
    * EGL_SINGLE_BUFFER. In particular, it is recommended that the following
    * combination is supported when possible:
    *    Format = RGBA_8888
    *    Usage = FRONT_BUFFER | GPU_RENDER_TARGET | COMPOSER_OVERLAY
    *
    */
    FRONT_BUFFER                       = 1L << 32,

    /** bits 28-31 are reserved for vendor extensions */
    VENDOR_MASK                        = 0xf << 28,

    /** bits 33-47 must be zero and are reserved for future versions */
    /** bits 48-63 are reserved for vendor extensions */
    VENDOR_MASK_HI                     = (1L * 0xffff) << 48,
}
