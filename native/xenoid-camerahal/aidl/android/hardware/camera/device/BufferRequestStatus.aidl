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

@VintfStability
@Backing(type="int")
enum BufferRequestStatus {
    /**
     * Method call succeeded and all requested buffers are returned.
     */
    OK = 0,
    /**
     * Method call failed for some streams. Check per stream status for each
     * returned StreamBufferRet.
     */
    FAILED_PARTIAL = 1,
    /**
     * Method call failed for all streams and no buffers are returned at all.
     * Camera service is about to or is performing configureStreams. HAL must
     * wait until next configureStreams call is finished before requesting
     * buffers again.
     */
    FAILED_CONFIGURING = 2,
    /**
     * Method call failed for all streams and no buffers are returned at all.
     * Failure due to bad BufferRequest input, eg: unknown streamId or repeated
     * streamId.
     */
    FAILED_ILLEGAL_ARGUMENTS = 3,
    /**
     * Method call failed for all streams and no buffers are returned at all.
     * Failure due to unknown reason, or all streams has individual failing
     * reason. For the latter case, check per stream status for each returned
     * StreamBufferRet.
     */
    FAILED_UNKNOWN = 4,
}
