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

import android.hardware.camera.device.BufferRequest;
import android.hardware.camera.device.BufferRequestStatus;
import android.hardware.camera.device.CaptureResult;
import android.hardware.camera.device.NotifyMsg;
import android.hardware.camera.device.StreamBuffer;
import android.hardware.camera.device.StreamBufferRet;

/**
 * Callback methods for the HAL to call into the framework.
 */
@VintfStability
interface ICameraDeviceCallback {
    /**
     * notify:
     *
     * Asynchronous notification callback from the HAL, fired for various
     * reasons. Only for information independent of frame capture, or that
     * require specific timing. Multiple messages may be sent in one call; a
     * message with a higher index must be considered to have occurred after a
     * message with a lower index.
     *
     * Multiple threads may call notify() simultaneously.
     *
     * Buffers delivered to the framework must not be dispatched to the
     * application layer until a start of exposure timestamp (or input image's
     * start of exposure timestamp for a reprocess request) has been received
     * via a SHUTTER notify() call. It is highly recommended to dispatch this
     * call as early as possible.
     *
     * The SHUTTER notify calls for requests with android.control.enableZsl
     * set to TRUE and ANDROID_CONTROL_CAPTURE_INTENT == STILL_CAPTURE may be
     * out-of-order compared to SHUTTER notify for other kinds of requests
     * (including regular, reprocess, or zero-shutter-lag requests with
     * different capture intents).
     *
     * As a result, the capture results of zero-shutter-lag requests with
     * ANDROID_CONTROL_CAPTURE_INTENT == STILL_CAPTURE may be out-of-order
     * compared to capture results for other kinds of requests.
     *
     * Different SHUTTER notify calls for zero-shutter-lag requests with
     * ANDROID_CONTROL_CAPTURE_INTENT == STILL_CAPTURE must be in order between
     * them, as is for other kinds of requests. SHUTTER notify calls for
     * zero-shutter-lag requests with non STILL_CAPTURE intent must be in order
     * with SHUTTER notify calls for regular requests.
     * ------------------------------------------------------------------------
     * Performance requirements:
     *
     * This is a non-blocking call. The framework must handle each message in 5ms.
     * @param msgs List of notification msgs to be processed by camera framework
     */
    void notify(in NotifyMsg[] msgs);

    /**
     * processCaptureResult:
     *
     * Send results from one or more completed or partially completed captures
     * to the framework.
     * processCaptureResult() may be invoked multiple times by the HAL in
     * response to a single capture request. This allows, for example, the
     * metadata and low-resolution buffers to be returned in one call, and
     * post-processed JPEG buffers in a later call, once it is available. Each
     * call must include the frame number of the request it is returning
     * metadata or buffers for. Only one call to processCaptureResult
     * may be made at a time by the HAL although the calls may come from
     * different threads in the HAL.
     *
     * A component (buffer or metadata) of the complete result may only be
     * included in one process_capture_result call. A buffer for each stream,
     * and the result metadata, must be returned by the HAL for each request in
     * one of the processCaptureResult calls, even in case of errors producing
     * some of the output. A call to processCaptureResult() with neither
     * output buffers or result metadata is not allowed.
     *
     * The order of returning metadata and buffers for a single result does not
     * matter, but buffers for a given stream must be returned in FIFO order. So
     * the buffer for request 5 for stream A must always be returned before the
     * buffer for request 6 for stream A. This also applies to the result
     * metadata; the metadata for request 5 must be returned before the metadata
     * for request 6.
     *
     * However, different streams are independent of each other, so it is
     * acceptable and expected that the buffer for request 5 for stream A may be
     * returned after the buffer for request 6 for stream B is. And it is
     * acceptable that the result metadata for request 6 for stream B is
     * returned before the buffer for request 5 for stream A is. If multiple
     * capture results are included in a single call, camera framework must
     * process results sequentially from lower index to higher index, as if
     * these results were sent to camera framework one by one, from lower index
     * to higher index.
     *
     * The HAL retains ownership of result structure, which only needs to be
     * valid to access during this call.
     *
     * The output buffers do not need to be filled yet; the framework must wait
     * on the stream buffer release sync fence before reading the buffer
     * data. Therefore, this method should be called by the HAL as soon as
     * possible, even if some or all of the output buffers are still in
     * being filled. The HAL must include valid release sync fences into each
     * output_buffers stream buffer entry, or -1 if that stream buffer is
     * already filled.
     *
     * If the result buffer cannot be constructed for a request, the HAL must
     * return an empty metadata buffer, but still provide the output buffers and
     * their sync fences. In addition, notify() must be called with an
     * ERROR_RESULT message.
     *
     * If an output buffer cannot be filled, its status field must be set to
     * STATUS_ERROR. In this case, notify() isn't required to be called with
     * an ERROR_BUFFER message. The framework will simply treat the notify()
     * call with ERROR_BUFFER as a no-op, and derive whether and when to notify
     * the application of buffer loss based on the buffer status and whether or not
     * the entire capture has failed.
     *
     * If the entire capture has failed, then this method still needs to be
     * called to return the output buffers to the framework. All the buffer
     * statuses must be STATUS_ERROR, and the result metadata must be an
     * empty buffer. In addition, notify() must be called with a ERROR_REQUEST
     * message. In this case, individual ERROR_RESULT/ERROR_BUFFER messages
     * must not be sent. Note that valid partial results are still allowed
     * as long as the final result metadata fails to be generated.
     *
     * Performance requirements:
     *
     * This is a non-blocking call. The framework must handle each CaptureResult
     * within 5ms.
     *
     * The pipeline latency (see ICameraDeviceSession for definition) should be less than or equal
     * to 4 frame intervals, and must be less than or equal to 8 frame intervals.
     *
     * @param results to be processed by the camera framework
     *
     */
    void processCaptureResult(in CaptureResult[] results);

    /**
     * requestStreamBuffers:
     *
     * Synchronous callback for HAL to ask for output buffers from camera service.
     *
     * This call may be serialized in camera service so it is strongly
     * recommended to only call this method from one thread.
     *
     * When camera device advertises
     * InfoSupportedBufferManagementVersion ==
     * ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION_HIDL_DEVICE_3_5), HAL
     * can use this method to request buffers from camera service.
     *
     * A BufferRequestStatus will be returned
     *     OK: All the requests succeeded
     *     FAILED_PARTIAL: some streams failed while some succeeds. Check
     *             individual StreamBufferRet for details.
     *     FAILED_CONFIGURING: the request failed because camera servicve is
     *             performing configureStreams and no buffers are returned.
     *     FAILED_UNKNOWN: the request failed for unknown reason and no buffers
     *             are returned.
     * A service specific exception will be returned in the following case:
     *
     * ILLEGAL_ARGUMENT: If the buffer requests through bufReqs are not legal, do not correspond
     *                   to a configured stream.
     *
     * Performance requirements:
     * This is a blocking call that takes more time with more buffers requested.
     * HAL must not request large amount of buffers on a latency critical code
     * path. It is highly recommended to use a dedicated thread to perform
     * all requestStreamBuffers calls, and adjust the thread priority and/or
     * timing of making the call in order for buffers to arrive before HAL is
     * ready to fill the buffer.
     * @param bufReqs Buffers requested by the camera HAL
     * @param buffers the buffers returned to the camera HAL by the camera framework
     */
    BufferRequestStatus requestStreamBuffers(
            in BufferRequest[] bufReqs, out StreamBufferRet[] buffers);

    /**
     * returnStreamBuffers:
     *
     * Synchronous callback for HAL to return output buffers to camera service.
     *
     * If this method is called during a configureStreams call, it must be blocked
     * until camera service finishes the ongoing configureStreams call.
     * @param buffers The stream buffers returned to the camera framework
     */
    void returnStreamBuffers(in StreamBuffer[] buffers);
}
