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
 * BufferCache:
 *
 * A bufferId associated with a certain stream.
 * Buffers are passed between camera service and camera HAL via bufferId except
 * the first time a new buffer is being passed to HAL in CaptureRequest. Camera
 * service and camera HAL therefore need to maintain a cached map of bufferId
 * and corresponing native handle.
 *
 */
@VintfStability
parcelable BufferCache {
    /**
     * The ID of the stream this list is associated with.
     */

    int streamId;
    /**
     * A cached buffer ID associated with streamId.
     */
    long bufferId;
}
