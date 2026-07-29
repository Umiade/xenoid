/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.hardware.camera.device;

/**
 * HalStream:
 *
 * The camera HAL's response to each requested stream configuration.
 *
 * The HAL may specify the desired format, maximum buffers, usage flags, physical camera id for
 * each stream.
 *
 */
@VintfStability
parcelable HalStream {
    /**
     * Stream ID - a nonnegative integer identifier for a stream.
     *
     * The ID must be one of the stream IDs passed into configureStreams.
     */
    int id;

    /**
     * An override pixel format for the buffers in this stream.
     *
     * The HAL must respect the requested format in Stream unless it is
     * IMPLEMENTATION_DEFINED, in which case the override format here must be
     * used by the client instead, for this stream. This allows cross-platform
     * HALs to use a standard format since IMPLEMENTATION_DEFINED formats often
     * require device-specific information. In all other cases, the
     * overrideFormat must match the requested format.
     *
     * When HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED is used, then the platform
     * gralloc module must select a format based on the usage flags provided by
     * the camera device and the other endpoint of the stream.
     */
    android.hardware.graphics.common.PixelFormat overrideFormat;

    /**
     * The bitfield gralloc usage flags for this stream, as needed by the HAL.
     *
     * For output streams, these are the HAL's producer usage flags. For input
     * streams, these are the HAL's consumer usage flags. The usage flags from
     * the producer and the consumer must be combined together and then passed
     * to the platform graphics allocator HAL for allocating the gralloc buffers
     * for each stream.
     *
     * If the stream's type is INPUT, then producerUsage must be 0, and
     * consumerUsage must be set. For other types, producerUsage must be set,
     * and consumerUsage must be 0.
     */
    android.hardware.graphics.common.BufferUsage producerUsage;

    android.hardware.graphics.common.BufferUsage consumerUsage;

    /**
     * The maximum number of buffers the HAL device may need to have dequeued at
     * the same time. The HAL device may not have more buffers in-flight from
     * this stream than this value.
     */
    int maxBuffers;

    /**
     * A bitfield override dataSpace for the buffers in this stream.
     *
     * The HAL must respect the requested dataSpace in Stream unless it is
     * IMPLEMENTATION_DEFINED, in which case the override dataSpace here must be
     * used by the client instead, for this stream. This allows cross-platform
     * HALs to use a specific dataSpace since IMPLEMENTATION_DEFINED formats often
     * require device-specific information for correct selection. In all other cases, the
     * overrideFormat must match the requested format.
     */
    android.hardware.graphics.common.Dataspace overrideDataSpace;

    /**
     * The physical camera id the current Hal stream belongs to.
     *
     * If current camera device isn't a logical camera, or the Hal stream isn't
     * from a physical camera of the logical camera, this must be an empty
     * string.
     *
     * A logical camera is a camera device backed by multiple physical camera
     * devices.
     *
     * When not empty, this field is the <id> field of one of the full-qualified device
     * instance names returned by getCameraIdList().
     */
    String physicalCameraId;

    /**
     * Whether this stream can be switch to offline mode.
     *
     * For devices that does not support the OFFLINE_PROCESSING capability, this
     * fields will always be false.
     *
     * For backward compatible camera devices that support the
     * OFFLINE_PROCESSING capability: any input stream and any output stream
     * that can be output of the input stream must set this field to true. Also
     * any stream of YUV420_888 format or JPEG format, with CPU_READ usage flag,
     * must set this field to true.
     *
     * For depth only camera devices that support the OFFLINE_PROCESSING
     * capability: any DEPTH16 output stream must set this field to true.
     *
     * All other streams are up to camera HAL to advertise support or not,
     * though it is not recommended to list support for streams with
     * hardware composer or video encoder usage flags as these streams tend
     * to be targeted continuously and can lead to long latency when trying to
     * switch to offline.
     *
     */
    boolean supportOffline;
}
