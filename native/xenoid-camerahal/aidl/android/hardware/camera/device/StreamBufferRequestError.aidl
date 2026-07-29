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
enum StreamBufferRequestError {
    /**
     * Get buffer failed due to timeout waiting for an available buffer. This is
     * likely due to the client application holding too many buffers, or the
     * system is under memory pressure.
     * This is not a fatal error. HAL may try to request buffer for this stream
     * later. If HAL cannot get a buffer for certain capture request in time
     * due to this error, HAL can send an ERROR_REQUEST to camera service and
     * drop processing that request.
     */
    NO_BUFFER_AVAILABLE = 1,
    /**
     * Get buffer failed due to HAL has reached its maxBuffer count. This is not
     * a fatal error. HAL may try to request buffer for this stream again after
     * it returns at least one buffer of that stream to camera service.
     */
    MAX_BUFFER_EXCEEDED = 2,
    /**
     * Get buffer failed due to the stream is disconnected by client
     * application, has been removed, or not recognized by camera service.
     * This means application is no longer interested in this stream.
     * Requesting buffer for this stream must never succeed after this error is
     * returned. HAL must safely return all buffers of this stream after
     * getting this error. If HAL gets another capture request later targeting
     * a disconnected stream, HAL must send an ERROR_REQUEST to camera service
     * and drop processing that request.
     */
    STREAM_DISCONNECTED = 3,
    /**
     * Get buffer failed for unknown reasons. This is a fatal error and HAL must
     * send ERROR_DEVICE to camera service and be ready to be closed.
     */
    UNKNOWN_ERROR = 4,
}
