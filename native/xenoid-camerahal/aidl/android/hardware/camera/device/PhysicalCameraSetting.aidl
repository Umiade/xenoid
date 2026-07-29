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

/**
 * PhysicalCameraSetting:
 *
 * Individual camera settings for logical camera backed by multiple physical devices.
 * Clients are allowed to pass separate settings for each physical device that has
 * corresponding configured HalStream and the respective stream id is present in the
 * output buffers of the capture request.
 */
@VintfStability
parcelable PhysicalCameraSetting {
    /**
     * If non-zero, read settings from request queue instead
     * (see ICameraDeviceSession.getCaptureRequestMetadataQueue).
     * If zero, read settings from .settings field.
     *
     * The logical settings metadata is read first from the FMQ, followed by
     * the physical cameras' settings metadata starting from index 0.
     */
    long fmqSettingsSize;

    /**
     * Contains the physical device camera id. Any settings passed by client here
     * should be applied for this physical device. In case the physical id is invalid or
     * it is not present among the last configured streams, Hal should fail the process
     * request and return Status::ILLEGAL_ARGUMENT.
     */
    String physicalCameraId;

    /**
     * If fmqSettingsSize is zero, the settings buffer contains the capture and
     * processing parameters for the physical device with id 'physicalCameraId'.
     * As a special case, an empty settings buffer indicates that the
     * settings are identical to the most-recently submitted capture request.
     * An empty buffer cannot be used as the first submitted request after
     * a configureStreams() call.
     *
     * This field must be used if fmqSettingsSize is zero. It must not be used
     * if fmqSettingsSize is non-zero.
     */
    CameraMetadata settings;
}
