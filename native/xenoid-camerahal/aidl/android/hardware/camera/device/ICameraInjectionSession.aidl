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
import android.hardware.camera.device.ICameraDeviceSession;
import android.hardware.camera.device.StreamConfiguration;

/**
 * Camera device active session interface.
 *
 * Obtained via ICameraDevice::open(), this interface contains the methods to
 * configure and request captures from an active camera device.
 */
@VintfStability
interface ICameraInjectionSession {
    /**
     * configureInjectionStreams:
     *
     * Identical to ICameraDeviceSession.configureStreams, except that:
     *
     * @param requestedConfiguration
     *     The current stream configuration of the internal camera session and
     *     the injection camera must follow the configuration without overriding
     *     any part of it.
     * @param characteristics
     *     The characteristics of internal camera contains a list of keys so that
     *     the stream continuity can be maintained after the external camera is
     *     injected.
     *
     * A service specific error will be returned on the following conditions
     *
     *     INTERNAL_ERROR:
     *         If there has been a fatal error and the device is no longer
     *         operational. Only close() can be called successfully by the
     *         framework after this error is returned.
     *     ILLEGAL_ARGUMENT:
     *         If the requested stream configuration is invalid. Some examples
     *         of invalid stream configurations include:
     *           - Not including any OUTPUT streams
     *           - Including streams with unsupported formats, or an unsupported
     *             size for that format.
     *           - Including too many output streams of a certain format.
     *           - Unsupported rotation configuration
     *           - Stream sizes/formats don't satisfy the
     *             StreamConfigurationMode requirements
     *             for non-NORMAL mode, or the requested operation_mode is not
     *             supported by the HAL.
     *           - Unsupported usage flag
     *         The camera service cannot filter out all possible illegal stream
     *         configurations, since some devices may support more simultaneous
     *         streams or larger stream resolutions than the minimum required
     *         for a given camera device hardware level. The HAL must return an
     *         ILLEGAL_ARGUMENT for any unsupported stream set, and then be
     *         ready to accept a future valid stream configuration in a later
     *         configureInjectionStreams call.
     */
    void configureInjectionStreams(
            in StreamConfiguration requestedConfiguration, in CameraMetadata characteristics);

    /**
     * Retrieves the ICameraDeviceSession interface in order for the camera framework to be able
     * to use the injection session for all of the operations that a non-injected
     * ICameraDeviceSession would be able to perform.
     */
    ICameraDeviceSession getCameraDeviceSession();
}
