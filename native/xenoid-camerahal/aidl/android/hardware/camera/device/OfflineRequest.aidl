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
 * OfflineRequest:
 *
 * Information about a capture request being switched to offline mode via the
 * ICameraDeviceSession#switchToOffline method.
 *
 */
@VintfStability
parcelable OfflineRequest {
    /**
     * Must match a inflight CaptureRequest sent by camera service
     */
    int frameNumber;

    /**
     * Stream IDs for outputs that will be returned via ICameraDeviceCallback.
     * The stream ID must be within one of offline stream listed in
     * CameraOfflineSessionInfo.
     * Camera service will validate these pending buffers are matching camera
     * service's record to make sure no buffers are leaked during the
     * switchToOffline call.
     */
    int[] pendingStreams;
}
