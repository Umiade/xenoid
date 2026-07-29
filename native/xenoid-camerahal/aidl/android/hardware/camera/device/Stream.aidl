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

import android.hardware.camera.device.StreamRotation;
import android.hardware.camera.device.StreamType;

/**
 * Stream:
 *
 * A descriptor for a single camera input or output stream. A stream is defined
 * by the framework by its buffer resolution and format, and additionally by the
 * HAL with the gralloc usage flags and the maximum in-flight buffer count.
 *
 * Also contains the multi-resolution output surface group Id field, sensor pixel modes and
 * dynamic range profile.
 */
@VintfStability
parcelable Stream {
    /**
     * Stream ID - a nonnegative integer identifier for a stream.
     *
     * The identical stream ID must reference the same stream, with the same
     * width/height/format, across consecutive calls to configureStreams.
     *
     * If previously-used stream ID is not used in a new call to
     * configureStreams, then that stream is no longer active. Such a stream ID
     * may be reused in a future configureStreams with a new
     * width/height/format.
     *
     */
    int id;

    /**
     * The type of the stream (input vs output, etc).
     */
    StreamType streamType;

    /**
     * The width in pixels of the buffers in this stream
     */
    int width;

    /**
     * The height in pixels of the buffers in this stream
     */
    int height;

    /**
     * The pixel format for the buffers in this stream.
     *
     * If IMPLEMENTATION_DEFINED is used, then the platform
     * gralloc module must select a format based on the usage flags provided by
     * the camera device and the other endpoint of the stream.
     *
     */
    android.hardware.graphics.common.PixelFormat format;

    /**
     * The bitfield of gralloc usage flags for this stream, as needed by the consumer of
     * the stream.
     *
     * The usage flags from the producer and the consumer must be combined
     * together and then passed to the platform gralloc HAL module for
     * allocating the gralloc buffers for each stream.
     *
     * The HAL may use these consumer flags to decide stream configuration. For
     * streamType INPUT, the value of this field is always 0. For all streams
     * passed via configureStreams(), the HAL must set its own
     * additional usage flags in its output HalStreamConfiguration.
     *
     * The usage flag for an output stream may be bitwise combination of usage
     * flags for multiple consumers, for the purpose of sharing one camera
     * stream between those consumers. The HAL must fail configureStreams call
     * with ILLEGAL_ARGUMENT if the combined flags cannot be supported due to
     * imcompatible buffer format, dataSpace, or other hardware limitations.
     */
    android.hardware.graphics.common.BufferUsage usage;

    /**
     * A bitfield that describes the contents of the buffer. The format and buffer
     * dimensions define the memory layout and structure of the stream buffers,
     * while dataSpace defines the meaning of the data within the buffer.
     *
     * For most formats, dataSpace defines the color space of the image data.
     * In addition, for some formats, dataSpace indicates whether image- or
     * depth-based data is requested. See
     * android.hardware.graphics.common@1.0::types for details of formats and
     * valid dataSpace values for each format.
     *
     * The HAL must use this dataSpace to configure the stream to the correct
     * colorspace, or to select between color and depth outputs if
     * supported. The dataspace values are set using the V0 dataspace
     * definitions.
     */
    android.hardware.graphics.common.Dataspace dataSpace;

    /**
     * The required output rotation of the stream.
     *
     * This must be inspected by HAL along with stream width and height. For
     * example, if the rotation is 90 degree and the stream width and height is
     * 720 and 1280 respectively, camera service must supply buffers of size
     * 720x1280, and HAL must capture a 1280x720 image and rotate the image by
     * 90 degree counterclockwise. The rotation field must be ignored when the
     * stream type is input.
     *
     * The HAL must inspect this field during stream configuration and return
     * IllegalArgument if HAL cannot perform such rotation. HAL must always
     * support ROTATION_0, so a configureStreams() call must not fail for
     * unsupported rotation if rotation field of all streams is ROTATION_0.
     *
     */
    StreamRotation rotation;

    /**
     * The physical camera id this stream belongs to.
     *
     * If the camera device is not a logical multi camera, or if the camera is a logical
     * multi camera but the stream is not a physical output stream, this field will point to a
     * 0-length string.
     *
     * A logical multi camera is a camera device backed by multiple physical cameras that
     * are also exposed to the application. And for a logical multi camera, a physical output
     * stream is an output stream specifically requested on an underlying physical camera.
     *
     * A logical camera is a camera device backed by multiple physical camera
     * devices. And a physical stream is a stream specifically requested on a
     * underlying physical camera device.
     *
     * For an input stream, this field is guaranteed to be a 0-length string.
     *
     * When not empty, this field is the <id> field of one of the full-qualified device
     * instance names returned by getCameraIdList().
     */
    String physicalCameraId;

    /**
     * The size of a buffer from this Stream, in bytes.
     *
     * For non PixelFormat::BLOB formats, this entry must be 0 and HAL should use
     * android.hardware.graphics.mapper lockYCbCr API to get buffer layout.
     *
     * For BLOB format with dataSpace Dataspace::DEPTH, this must be zero and HAL must
     * determine the buffer size based on ANDROID_DEPTH_MAX_DEPTH_SAMPLES.
     *
     * For BLOB format with dataSpace Dataspace::JFIF, this must be non-zero and represent the
     * maximal size HAL can lock using android.hardware.graphics.mapper lock API.
     *
     */
    int bufferSize;

    /**
     * The surface group id used for multi-resolution output streams.
     *
     * This works similar to the surfaceGroupId of OutputConfiguration in the
     * public API, with the exception that this is for multi-resolution image
     * reader and is used by the camera HAL to choose a target stream within
     * the same group to which images are written. All streams in the same group
     * will have the same image format, data space, and usage flag.
     *
     * The framework must only call processCaptureRequest on at most one of the
     * streams within a surface group. Depending on current active physical
     * camera backing the logical multi-camera, or the pixel mode the camera is
     * running in, the HAL can choose to request and return a buffer from any
     * stream within the same group. -1 means that this stream is an input
     * stream, or is an output stream which doesn't belong to any group.
     *
     * Streams with the same non-negative group id must have the same format and
     * usage flag.
     */
    int groupId;

    /**
     *  The sensor pixel modes used by this stream. This can assist the camera
     *  HAL in decision making about stream combination support.
     *  If this is empty, the HAL must assume that this stream will only be used
     *  with ANDROID_SENSOR_PIXEL_MODE set to ANDROID_SENSOR_PIXEL_MODE_DEFAULT.
     */
    android.hardware.camera.metadata.SensorPixelMode[] sensorPixelModesUsed;

    /**
     * The dynamic range profile for this stream.
     *
     * This field is valid and must only be considered for streams with format
     * android.hardware.graphics.common.PixelFormat.YCBCR_P010 or
     * android.hardware.graphics.common.PixelFormat.IMPLEMENTATION_DEFINED on devices supporting the
     * ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DYNAMIC_RANGE_10_BIT capability.
     *
     */
    android.hardware.camera.metadata.RequestAvailableDynamicRangeProfilesMap dynamicRangeProfile;

    /**
     * The stream use case describing the stream's purpose
     *
     * This flag provides the camera device a hint on what user scenario this
     * stream is intended for. With this flag, the camera device can optimize
     * camera pipeline parameters, such as tuning, sensor mode, and ISP settings,
     * for the intended use case.
     *
     * When this field is set to DEFAULT, the camera device should behave in
     * the same way as in previous HAL versions, and optimize the camera pipeline
     * based on stream format, data space, usage flag, and other stream properties.
     *
     * The HAL reports supported stream use cases in
     * ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES. If the HAL doesn't support
     * setting stream use cases, the camera framework leaves this field as
     * DEFAULT.
     */
    android.hardware.camera.metadata.ScalerAvailableStreamUseCases useCase;
}
