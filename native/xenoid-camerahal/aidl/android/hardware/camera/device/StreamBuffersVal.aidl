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

import android.hardware.camera.device.StreamBuffer;
import android.hardware.camera.device.StreamBufferRequestError;

/**
 * Per-stream return value for requestStreamBuffers.
 * For each stream, either an StreamBufferRequestError error code, or all
 * requested buffers for this stream is returned, so buffers.size() must be
 * equal to BufferRequest::numBuffersRequested of corresponding stream.
 */
@VintfStability
union StreamBuffersVal {
    StreamBufferRequestError error = StreamBufferRequestError.UNKNOWN_ERROR;

    StreamBuffer[] buffers;
}
