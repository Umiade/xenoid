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

import android.hardware.camera.device.OfflineRequest;
import android.hardware.camera.device.OfflineStream;

/**
 * CameraOfflineSessionInfo:
 *
 * Information about pending outputs that's being transferred to an offline
 * session from an active session using the
 * ICameraDeviceSession#switchToOffline method.
 *
 */
@VintfStability
parcelable CameraOfflineSessionInfo {
    /**
     * Information on what streams will be preserved in offline session.
     * Streams not listed here will be removed by camera service after
     * switchToOffline call returns.
     */
    OfflineStream[] offlineStreams;

    /**
     * Information for requests that will be handled by offline session
     * Camera service will validate this matches what camera service has on
     * record.
     */
    OfflineRequest[] offlineRequests;
}
