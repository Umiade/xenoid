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
 * PhysicalCameraMetadata:
 *
 * Individual camera metadata for a physical camera as part of a logical
 * multi-camera. Camera HAL should return one such metadata for each physical
 * camera being requested on.
 */
@VintfStability
parcelable PhysicalCameraMetadata {
    /**
     * If non-zero, read metadata from result metadata queue instead
     * (see ICameraDeviceSession.getCaptureResultMetadataQueue).
     * If zero, read metadata from .metadata field.
     *
     * The logical CaptureResult metadata is read first from the FMQ, followed by
     * the physical cameras' metadata starting from index 0.
     */
    long fmqMetadataSize;

    /**
     * Contains the physical device camera id. As long as the corresponding
     * processCaptureRequest requests on a particular physical camera stream,
     * the metadata for that physical camera should be generated for the capture
     * result.
     */
    String physicalCameraId;

    /**
     * If fmqMetadataSize is zero, the metadata buffer contains the metadata
     * for the physical device with physicalCameraId.
     */
    CameraMetadata metadata;
}
