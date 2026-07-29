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
 * Defined error codes for the NotifyMsg union in ICameraDeviceCallback.notify callbacks.
 */
@VintfStability
@Backing(type="int")
enum ErrorCode {
    /**
     * A serious failure occurred. No further frames or buffer streams must
     * be produced by the device. Device must be treated as closed. The
     * client must reopen the device to use it again. The frameNumber field
     * is unused.
     */
    ERROR_DEVICE = 1,

    /**
     * An error has occurred in processing a request. No output (metadata or
     * buffers) must be produced for this request. The frameNumber field
     * specifies which request has been dropped. Subsequent requests are
     * unaffected, and the device remains operational.
     */
    ERROR_REQUEST = 2,

    /**
     * An error has occurred in producing an output result metadata buffer
     * for a request, but output stream buffers for it must still be
     * available. Subsequent requests are unaffected, and the device remains
     * operational. The frameNumber field specifies the request for which
     * result metadata won't be available.
     */
    ERROR_RESULT = 3,

    /**
     * An error has occurred in placing an output buffer into a stream for a
     * request. The frame metadata and other buffers may still be
     * available. Subsequent requests are unaffected, and the device remains
     * operational. The frameNumber field specifies the request for which the
     * buffer was dropped, and errorStreamId indicates the stream
     * that dropped the frame.
     */
    ERROR_BUFFER = 4,
}
