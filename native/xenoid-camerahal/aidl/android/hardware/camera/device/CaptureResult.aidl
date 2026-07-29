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

import android.hardware.camera.device.CameraMetadata;
import android.hardware.camera.device.PhysicalCameraMetadata;
import android.hardware.camera.device.StreamBuffer;

/**
 * CaptureResult:
 *
 * The result of a single capture/reprocess by the camera HAL device. This is
 * sent to the framework asynchronously with processCaptureResult(), in
 * response to a single capture request sent to the HAL with
 * processCaptureRequest(). Multiple processCaptureResult() calls may be
 * performed by the HAL for each request.
 *
 * Each call, all with the same frame
 * number, may contain some subset of the output buffers, and/or the result
 * metadata.
 *
 * The result structure contains the output metadata from this capture, and the
 * set of output buffers that have been/will be filled for this capture. Each
 * output buffer may come with a release sync fence that the framework must wait
 * on before reading, in case the buffer has not yet been filled by the HAL.
 *
 * The metadata may be provided multiple times for a single frame number. The
 * framework must accumulate together the final result set by combining each
 * partial result together into the total result set.
 *
 * If an input buffer is given in a request, the HAL must return it in one of
 * the processCaptureResult calls, and the call may be to just return the
 * input buffer, without metadata and output buffers; the sync fences must be
 * handled the same way they are done for output buffers.
 *
 * Performance considerations:
 *
 * Applications receive these partial results immediately, so sending partial
 * results is a highly recommended performance optimization to avoid the total
 * pipeline latency before sending the results for what is known very early on
 * in the pipeline.
 *
 * A typical use case might be calculating the AF state halfway through the
 * pipeline; by sending the state back to the framework immediately, we get a
 * 50% performance increase and perceived responsiveness of the auto-focus.
 *
 * Physical camera metadata needs to be generated if and only if a
 * request is pending on a stream from that physical camera. For example,
 * if the processCaptureRequest call doesn't request on physical camera
 * streams, the physicalCameraMetadata field of the CaptureResult being returned
 * should be an 0-size vector. If the processCaptureRequest call requests on
 * streams from one of the physical camera, the physicalCameraMetadata field
 * should contain one metadata describing the capture from that physical camera.
 *
 * For a CaptureResult that contains physical camera metadata, its
 * partialResult field must be android.request.partialResultCount. In other
 * words, the physicalCameraMetadata must only be contained in a final capture
 * result.
 */
@VintfStability
parcelable CaptureResult {
    /**
     * The frame number is an incrementing integer set by the framework in the
     * submitted request to uniquely identify this capture. It is also used to
     * identify the request in asynchronous notifications sent to
     * ICameraDevice3Callback::notify().
     */
    int frameNumber;

    /**
     * If non-zero, read result from result queue instead
     * (see ICameraDeviceSession.getCaptureResultMetadataQueue).
     * If zero, read result from .result field.
     */
    long fmqResultSize;

    /**
     * The result metadata for this capture. This contains information about the
     * final capture parameters, the state of the capture and post-processing
     * hardware, the state of the 3A algorithms, if enabled, and the output of
     * any enabled statistics units.
     *
     * If there was an error producing the result metadata, result must be an
     * empty metadata buffer, and notify() must be called with
     * ErrorCode::ERROR_RESULT.
     *
     * Multiple calls to processCaptureResult() with a given frameNumber
     * may include (partial) result metadata.
     *
     * Partial metadata submitted must not include any metadata key returned
     * in a previous partial result for a given frame. Each new partial result
     * for that frame must also set a distinct partialResult value.
     *
     * If notify has been called with ErrorCode::ERROR_RESULT, all further
     * partial results for that frame are ignored by the framework.
     */
    CameraMetadata result;

    /**
     * The completed output stream buffers for this capture.
     *
     * They may not yet be filled at the time the HAL calls
     * processCaptureResult(); the framework must wait on the release sync
     * fences provided by the HAL before reading the buffers.
     *
     * The StreamBuffer::buffer handle must be null for all returned buffers;
     * the client must cache the handle and look it up via the combination of
     * frame number and stream ID.
     *
     * The number of output buffers returned must be less than or equal to the
     * matching capture request's count. If this is less than the buffer count
     * in the capture request, at least one more call to processCaptureResult
     * with the same frameNumber must be made, to return the remaining output
     * buffers to the framework. This may only be zero if the structure includes
     * valid result metadata or an input buffer is returned in this result.
     *
     * The HAL must set the stream buffer's release sync fence to a valid sync
     * fd, or to null if the buffer has already been filled.
     *
     * If the HAL encounters an error while processing the buffer, and the
     * buffer is not filled, the buffer's status field must be set to ERROR. If
     * the HAL did not wait on the acquire fence before encountering the error,
     * the acquire fence must be copied into the release fence, to allow the
     * framework to wait on the fence before reusing the buffer.
     *
     * The acquire fence must be set to null for all output buffers.
     *
     * This vector may be empty; if so, at least one other processCaptureResult
     * call must be made (or have been made) by the HAL to provide the filled
     * output buffers.
     *
     * When processCaptureResult is called with a new buffer for a frame,
     * all previous frames' buffers for that corresponding stream must have been
     * already delivered (the fences need not have yet been signaled).
     *
     * Buffers for a frame may be sent to framework before the corresponding
     * SHUTTER-notify call is made by the HAL.
     *
     * Performance considerations:
     *
     * Buffers delivered to the framework are not dispatched to the
     * application layer until a start of exposure timestamp has been received
     * via a SHUTTER notify() call. It is highly recommended to
     * dispatch that call as early as possible.
     */
    StreamBuffer[] outputBuffers;

    /**
     * The handle for the input stream buffer for this capture, if any.
     *
     * It may not yet be consumed at the time the HAL calls
     * processCaptureResult(); the framework must wait on the release sync fence
     * provided by the HAL before reusing the buffer.
     *
     * The HAL must handle the sync fences the same way they are done for
     * outputBuffers.
     *
     * Only one input buffer is allowed to be sent per request. Similarly to
     * output buffers, the ordering of returned input buffers must be
     * maintained by the HAL.
     *
     * Performance considerations:
     *
     * The input buffer should be returned as early as possible. If the HAL
     * supports sync fences, it can call processCaptureResult to hand it back
     * with sync fences being set appropriately. If the sync fences are not
     * supported, the buffer can only be returned when it is consumed, which
     * may take long time; the HAL may choose to copy this input buffer to make
     * the buffer return sooner.
     */
    StreamBuffer inputBuffer;

    /**
     * In order to take advantage of partial results, the HAL must set the
     * static metadata android.request.partialResultCount to the number of
     * partial results it sends for each frame.
     *
     * Each new capture result with a partial result must set
     * this field to a distinct inclusive value between
     * 1 and android.request.partialResultCount.
     *
     * HALs not wishing to take advantage of this feature must not
     * set an android.request.partialResultCount or partial_result to a value
     * other than 1.
     *
     * This value must be set to 0 when a capture result contains buffers only
     * and no metadata.
     */
    int partialResult;

    /**
     * The physical metadata for logical multi-camera.
     */
    PhysicalCameraMetadata[] physicalCameraMetadata;
}
