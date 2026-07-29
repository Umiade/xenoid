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

import android.hardware.camera.device.BufferStatus;
import android.hardware.common.NativeHandle;

/**
 * StreamBuffer:
 *
 * A single buffer from a camera HAL stream. It includes a handle to its parent
 * stream, the handle to the gralloc buffer itself, and sync fences
 *
 * The buffer does not specify whether it is to be used for input or output;
 * that is determined by its parent stream type and how the buffer is passed to
 * the HAL device.
 */
@VintfStability
parcelable StreamBuffer {
    /**
     * The ID of the stream this buffer is associated with. -1 indicates an
     * invalid (empty) StreamBuffer, in which case buffer must also point to
     * null and bufferId must be 0.
     */
    int streamId;

    /**
     * The unique ID of the buffer within this StreamBuffer. 0 indicates this
     * StreamBuffer contains no buffer.
     * For StreamBuffers sent to the HAL in a CaptureRequest, this ID uniquely
     * identifies a buffer. When a buffer is sent to HAL for the first time,
     * both bufferId and buffer handle must be filled. HAL must keep track of
     * the mapping between bufferId and corresponding buffer until the
     * corresponding stream is removed from stream configuration or until camera
     * device session is closed. After the first time a buffer is introduced to
     * HAL, in the future camera service must refer to the same buffer using
     * only bufferId, and keep the buffer handle null.
     */
    long bufferId;

    /**
     * The graphics buffer handle to the buffer.
     *
     * For StreamBuffers sent to the HAL in a CaptureRequest, if the bufferId
     * is not seen by the HAL before, this buffer handle is guaranteed to be a
     * valid handle to a graphics buffer, with dimensions and format matching
     * that of the stream. If the bufferId has been sent to the HAL before, this
     * buffer handle must be null and HAL must look up the actual buffer handle
     * to use from its own bufferId to buffer handle map.
     *
     * For StreamBuffers returned in a CaptureResult, this must be null, since
     * the handle to the buffer is already known to the client (since the client
     * sent it in the matching CaptureRequest), and the handle can be identified
     * by the combination of frame number and stream ID.
     */
    NativeHandle buffer;

    /**
     * Current state of the buffer. The framework must not pass buffers to the
     * HAL that are in an error state. In case a buffer could not be filled by
     * the HAL, it must have its status set to ERROR when returned to the
     * framework with processCaptureResult().
     */
    BufferStatus status;

    /**
     * The acquire sync fence for this buffer. The HAL must wait on this fence
     * fd before attempting to read from or write to this buffer.
     *
     * In a buffer included in a CaptureRequest, the client may set this to null
     * to indicate that no waiting is necessary for this buffer.
     *
     * When the HAL returns an input or output buffer to the framework with
     * processCaptureResult(), the acquireFence must be set to null. If the HAL
     * never waits on the acquireFence due to an error in filling or reading a
     * buffer, when calling processCaptureResult() the HAL must set the
     * releaseFence of the buffer to be the acquireFence passed to it by the
     * client. This allows the client to wait on the fence before reusing the
     * buffer.
     */
    NativeHandle acquireFence;

    /**
     * The release sync fence for this buffer. The HAL must set this to a valid
     * fence fd when returning the input buffer or output buffers to the client
     * in a CaptureResult, or set it to null to indicate that no waiting is
     * required for this buffer.
     *
     * The client must set this to be null for all buffers included in a
     * processCaptureRequest call.
     *
     * After signaling the releaseFence for this buffer, the HAL
     * must not make any further attempts to access this buffer as the
     * ownership has been fully transferred back to the client.
     *
     * If this is null, then the ownership of this buffer is transferred back
     * immediately upon the call of processCaptureResult.
     */
    NativeHandle releaseFence;
}
