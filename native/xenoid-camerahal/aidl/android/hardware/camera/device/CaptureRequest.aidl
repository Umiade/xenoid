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

import android.hardware.camera.device.CameraMetadata;
import android.hardware.camera.device.PhysicalCameraSetting;
import android.hardware.camera.device.StreamBuffer;

/**
 * CaptureRequest:
 *
 * A single request for image capture/buffer reprocessing, sent to the Camera
 * HAL device by the framework in processCaptureRequest().
 *
 * The request contains the settings to be used for this capture, and the set of
 * output buffers to write the resulting image data in. It may optionally
 * contain an input buffer, in which case the request is for reprocessing that
 * input buffer instead of capturing a new image with the camera sensor. The
 * capture is identified by the frameNumber.
 *
 * In response, the camera HAL device must send a CaptureResult
 * structure asynchronously to the framework, using the processCaptureResult()
 * callback.
 */
@VintfStability
parcelable CaptureRequest {
    /**
     * The frame number is an incrementing integer set by the framework to
     * uniquely identify this capture. It needs to be returned in the result
     * call, and is also used to identify the request in asynchronous
     * notifications sent to ICameraDevice3Callback::notify().
     */
    int frameNumber;

    /**
     * If non-zero, read settings from request queue instead
     * (see ICameraDeviceSession.getCaptureRequestMetadataQueue).
     * If zero, read settings from .settings field.
     */
    long fmqSettingsSize;

    /**
     * If fmqSettingsSize is zero,
     * the settings buffer contains the capture and processing parameters for
     * the request. As a special case, an empty settings buffer indicates that
     * the settings are identical to the most-recently submitted capture
     * request. A empty buffer cannot be used as the first submitted request
     * after a configureStreams() call.
     *
     * This field must be used if fmqSettingsSize is zero. It must not be used
     * if fmqSettingsSize is non-zero.
     */
    CameraMetadata settings;

    /**
     * The input stream buffer to use for this request, if any.
     *
     * An invalid inputBuffer is signified by a null inputBuffer::buffer, in
     * which case the value of all other members of inputBuffer must be ignored.
     *
     * If inputBuffer is invalid, then the request is for a new capture from the
     * imager. If inputBuffer is valid, the request is for reprocessing the
     * image contained in inputBuffer, and the HAL must release the inputBuffer
     * back to the client in a subsequent processCaptureResult call.
     *
     * The HAL is required to wait on the acquire sync fence of the input buffer
     * before accessing it.
     *
     */
    StreamBuffer inputBuffer;
    /**
     * The width and height of the input buffer for this capture request.
     *
     * These fields will be [0, 0] if no input buffer exists in the capture
     * request.
     *
     * If the stream configuration contains an input stream and has the
     * multiResolutionInputImage flag set to true, the camera client may submit a
     * reprocessing request with input buffer size different than the
     * configured input stream size. In that case, the inputWith and inputHeight
     * fields will be the actual size of the input image.
     *
     * If the stream configuration contains an input stream and the
     * multiResolutionInputImage flag is false, the inputWidth and inputHeight must
     * match the input stream size.
     */
    int inputWidth;

    int inputHeight;

    /**
     * An array of at least 1 stream buffers, to be filled with image
     * data from this capture/reprocess. The HAL must wait on the acquire fences
     * of each stream buffer before writing to them.
     *
     * The HAL takes ownership of the handles in outputBuffers; the client
     * must not access them until they are returned in a CaptureResult.
     *
     * Any or all of the buffers included here may be brand new in this
     * request (having never before seen by the HAL).
     */
    StreamBuffer[] outputBuffers;

    /**
     * A vector containing individual camera settings for logical camera backed by multiple physical
     * devices. In case the vector is empty, Hal should use the settings field. The
     * individual settings should only be honored for physical devices that have respective Hal
     * stream. Physical devices that have a corresponding Hal stream but don't have attached
     * settings here should use the settings field.
     * If any of the physical settings in the array are applied on one or more devices, then the
     * visual effect on any Hal streams attached to the logical camera is undefined.
     */
    PhysicalCameraSetting[] physicalCameraSettings;
}
