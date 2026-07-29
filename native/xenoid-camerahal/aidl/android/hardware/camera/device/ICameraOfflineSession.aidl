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

import android.hardware.camera.device.ICameraDeviceCallback;
import android.hardware.common.fmq.MQDescriptor;
import android.hardware.common.fmq.SynchronizedReadWrite;

/**
 * Camera device offline session interface.
 *
 * Obtained via ICameraDeviceSession::switchToOffline(), this interface contains
 * the methods and callback interfaces that define how camera service interacts
 * with an offline session.
 *
 * An offline session contains some unfinished capture requests that were submitted
 * to the parent ICameraDeviceSession before calling switchToOffline, and is
 * responsible for delivering these capture results back to camera service regardless
 * of whether the parent camera device is still opened or not. An offline session must
 * not have access to the camera device's image sensor. During switchToOffline
 * call, camera HAL must capture all necessary frames from the image sensor that
 * is needed for completing the requests offline later.
 */
@VintfStability
interface ICameraOfflineSession {
    /**
     * Close the offline session and release all resources.
     *
     * Camera service may call this method before or after the offline session
     * has finished all requests it needs to handle. If there are still unfinished
     * requests when close is called, camera HAL must send ERROR_REQUEST for
     * all unfinished requests and return all buffers via
     * ICameraDeviceCallback#processCaptureResult or
     * ICameraDeviceCallback#returnStreamBuffers.
     * Also, all buffer caches maintained by the offline session must be erased
     * before the close call returns.
     */
    void close();

    /**
     * getCaptureResultMetadataQueue:
     *
     * Retrieves the queue used along with
     * ICameraDeviceCallback#processCaptureResult.
     *
     * Clients to ICameraOfflineSession must:
     * - Call getCaptureRequestMetadataQueue to retrieve the fast message queue;
     * - In implementation of ICameraDeviceCallback, test whether
     *   .fmqResultSize field is zero.
     *     - If .fmqResultSize != 0, read result metadata from the fast message
     *       queue;
     *     - otherwise, read result metadata in CaptureResult.result.
     *
     * @return the queue that implementation writes result metadata to.
     */
    MQDescriptor<byte, SynchronizedReadWrite> getCaptureResultMetadataQueue();

    /**
     * Set the callbacks for offline session to communicate with camera service.
     *
     * Offline session is responsible to store all callbacks the camera HAL
     * generated after the return of ICameraDeviceSession::switchToOffline, and
     * send them to camera service once this method is called.
     *
     * Camera service must not call this method more than once, so these
     * callbacks can be assumed to be constant after the first setCallback call.
     */
    void setCallback(in ICameraDeviceCallback cb);
}
