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
import android.hardware.camera.device.Stream;
import android.hardware.camera.device.StreamConfigurationMode;

/**
 * StreamConfiguration:
 *
 * A structure of stream definitions, used by configureStreams(). This
 * structure defines all the output streams and the reprocessing input
 * stream for the current camera use case.
 */
@VintfStability
parcelable StreamConfiguration {
    /**
     * An array of camera stream pointers, defining the input/output
     * configuration for the camera HAL device.
     */
    Stream[] streams;

    /**
     * The operation mode of streams in this configuration. The HAL can use this
     * mode as an indicator to set the stream property (e.g.,
     * HalStream.maxBuffers) appropriately. For example, if the
     * configuration is
     * CONSTRAINED_HIGH_SPEED_MODE, the HAL may
     * want to set aside more buffers for batch mode operation (see
     * android.control.availableHighSpeedVideoConfigurations for batch mode
     * definition).
     *
     */
    StreamConfigurationMode operationMode;

    /**
     * Session wide camera parameters.
     *
     * The session parameters contain the initial values of any request keys that were
     * made available via ANDROID_REQUEST_AVAILABLE_SESSION_KEYS. The Hal implementation
     * can advertise any settings that can potentially introduce unexpected delays when
     * their value changes during active process requests. Typical examples are
     * parameters that trigger time-consuming HW re-configurations or internal camera
     * pipeline updates. The field is optional, clients can choose to ignore it and avoid
     * including any initial settings. If parameters are present, then hal must examine
     * their values and configure the internal camera pipeline accordingly.
     */
    CameraMetadata sessionParams;

   /**
     * An incrementing counter used for HAL to keep track of the stream
     * configuration and the paired oneway signalStreamFlush call. When the
     * counter in signalStreamFlush call is less than the counter here, that
     * signalStreamFlush call is stale.
     */
    int streamConfigCounter;

    /**
     * If an input stream is configured, whether the input stream is expected to
     * receive variable resolution images.
     *
     * This flag can only be set to true if the camera device supports
     * multi-resolution input streams by advertising input stream configurations in
     * physicalCameraMultiResolutionStreamConfigurations in its physical cameras'
     * characteristics.
     *
     * When this flag is set to true, the input stream's width and height can be
     * any one of the supported multi-resolution input stream sizes.
     */
    boolean multiResolutionInputImage;
}
