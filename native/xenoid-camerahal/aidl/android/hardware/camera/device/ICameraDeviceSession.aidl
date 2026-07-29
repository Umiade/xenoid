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

import android.hardware.camera.device.BufferCache;
import android.hardware.camera.device.CameraMetadata;
import android.hardware.camera.device.CameraOfflineSessionInfo;
import android.hardware.camera.device.CaptureRequest;
import android.hardware.camera.device.HalStream;
import android.hardware.camera.device.ICameraOfflineSession;
import android.hardware.camera.device.RequestTemplate;
import android.hardware.camera.device.StreamConfiguration;
import android.hardware.common.fmq.MQDescriptor;
import android.hardware.common.fmq.SynchronizedReadWrite;

/**
 * Camera device active session interface.
 *
 * Obtained via ICameraDevice::open(), this interface contains the methods to
 * configure and request captures from an active camera device.
 */
@VintfStability
interface ICameraDeviceSession {
    /**
     * close:
     *
     * Shut down the camera device.
     *
     * After this call, all calls to this session instance must set a
     * INTERNAL_ERROR ServiceSpecificException.
     *
     * This method must always succeed, even if the device has encountered a
     * serious error.
     */
    void close();

    /**
     *
     * configureStreams:
     *
     * Reset the HAL camera device processing pipeline and set up new input and
     * output streams. This call replaces any existing stream configuration with
     * the streams defined in the streamList. This method must be called at
     * least once before a request is submitted with processCaptureRequest().
     *
     * The streamList must contain at least one output-capable stream, and may
     * not contain more than one input-capable stream.
     *
     * The streamList may contain streams that are also in the currently-active
     * set of streams (from the previous call to configureStreams()). These
     * streams must already have valid values for usage, maxBuffers, and the
     * private pointer.
     *
     * If the HAL needs to change the stream configuration for an existing
     * stream due to the new configuration, it may rewrite the values of usage
     * and/or maxBuffers during the configure call.
     *
     * The framework must detect such a change, and may then reallocate the
     * stream buffers before using buffers from that stream in a request.
     *
     * If a currently-active stream is not included in streamList, the HAL may
     * safely remove any references to that stream. It must not be reused in a
     * later configureStreams() call by the framework, and all the gralloc
     * buffers for it must be freed after the configureStreams() call returns.
     *
     * If the stream is new, the client must set the consumer usage flags in
     * requestedConfiguration. Upon return, the HAL device must set producerUsage,
     * maxBuffers, and other fields in the configureStreams() return values. These
     * fields are then used by the framework and the platform gralloc module to
     * allocate the gralloc buffers for each stream.
     *
     * Newly allocated buffers may be included in a capture request at any time
     * by the framework. Once a gralloc buffer is returned to the framework
     * with processCaptureResult (and its respective releaseFence has been
     * signaled) the framework may free or reuse it at any time.
     *
     * ------------------------------------------------------------------------
     *
     * Preconditions:
     *
     * The framework must only call this method when no captures are being
     * processed. That is, all results have been returned to the framework, and
     * all in-flight input and output buffers have been returned and their
     * release sync fences have been signaled by the HAL. The framework must not
     * submit new requests for capture while the configureStreams() call is
     * underway.
     *
     * Postconditions:
     *
     * The HAL device must configure itself to provide maximum possible output
     * frame rate given the sizes and formats of the output streams, as
     * documented in the camera device's static metadata.
     *
     * Performance requirements:
     *
     * This call is expected to be heavyweight and possibly take several hundred
     * milliseconds to complete, since it may require resetting and
     * reconfiguring the image sensor and the camera processing pipeline.
     * Nevertheless, the HAL device should attempt to minimize the
     * reconfiguration delay to minimize the user-visible pauses during
     * application operational mode changes (such as switching from still
     * capture to video recording).
     *
     * The HAL should return from this call in 500ms, and must return from this
     * call in 1000ms.
     *
     * A service specific error will be returned on the following conditions
     *
     *     INTERNAL_ERROR:
     *         If there has been a fatal error and the device is no longer
     *         operational. Only close() can be called successfully by the
     *         framework after this error is returned.
     *     ILLEGAL_ARGUMENT:
     *         If the requested stream configuration is invalid. Some examples
     *         of invalid stream configurations include:
     *           - Including more than 1 INPUT stream
     *           - Not including any OUTPUT streams
     *           - Including streams with unsupported formats, or an unsupported
     *             size for that format.
     *           - Including too many output streams of a certain format.
     *           - Unsupported rotation configuration
     *           - Stream sizes/formats don't satisfy the
     *             StreamConfigurationMode requirements for non-NORMAL mode, or
     *             the requested operation_mode is not supported by the HAL.
     *           - Unsupported usage flag
     *         The camera service cannot filter out all possible illegal stream
     *         configurations, since some devices may support more simultaneous
     *         streams or larger stream resolutions than the minimum required
     *         for a given camera device hardware level. The HAL must return an
     *         ILLEGAL_ARGUMENT for any unsupported stream set, and then be
     *         ready to accept a future valid stream configuration in a later
     *         configureStreams call.
     * @param requestedConfiguration The stream configuration requested by the camera framework to
     *        be configured by the camera HAL.
     * @return A list of the stream parameters desired by the HAL for
     *     each stream, including maximum buffers, the usage flags, and the
     *     override format.
     *
     */
    HalStream[] configureStreams(in StreamConfiguration requestedConfiguration);

    /**
     * constructDefaultRequestSettings:
     *
     * Create capture settings for standard camera use cases.
     *
     * The device must return a settings buffer that is configured to meet the
     * requested use case, which must be one of the RequestTemplate enums.
     * All request control fields must be included.
     *
     * Performance requirements:
     *
     * This must be a non-blocking call. The HAL should return from this call
     * in 1ms, and must return from this call in 5ms.
     *
     * A service specific error will be returned on the following conditions
     * Return values:
     *
     *     INTERNAL_ERROR:
     *         An unexpected internal error occurred, and the default settings
     *         are not available.
     *     ILLEGAL_ARGUMENT:
     *         The camera HAL does not support the input template type
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     * @param type The requested template CaptureRequest type to create the default settings for.
     *
     * @return capture settings for the requested use case.
     *
     */

    CameraMetadata constructDefaultRequestSettings(in RequestTemplate type);

    /**
     * flush:
     *
     * Flush all currently in-process captures and all buffers in the pipeline
     * on the given device. Generally, this method is used to dump all state as
     * quickly as possible in order to prepare for a configure_streams() call.
     *
     * No buffers are required to be successfully returned, so every buffer
     * held at the time of flush() (whether successfully filled or not) may be
     * returned with BufferStatus.ERROR. Note the HAL is still allowed
     * to return valid (BufferStatus.OK) buffers during this call,
     * provided they are successfully filled.
     *
     * All requests currently in the HAL are expected to be returned as soon as
     * possible. Not-in-process requests must return errors immediately. Any
     * interruptible hardware blocks must be stopped, and any uninterruptible
     * blocks must be waited on.
     *
     * flush() may be called concurrently to processCaptureRequest(), with the
     * expectation that processCaptureRequest returns quickly and the
     * request submitted in that processCaptureRequest call is treated like
     * all other in-flight requests. Due to concurrency issues, it is possible
     * that from the HAL's point of view, a processCaptureRequest() call may
     * be started after flush has been invoked but has not returned yet. If such
     * a call happens before flush() returns, the HAL must treat the new
     * capture request like other in-flight pending requests (see #4 below).
     *
     * More specifically, the HAL must follow below requirements for various
     * cases:
     *
     * 1. For captures that are too late for the HAL to cancel/stop, and must be
     *    completed normally by the HAL; i.e. the HAL can send shutter/notify
     *    and processCaptureResult and buffers as normal.
     *
     * 2. For pending requests that have not done any processing, the HAL must
     *    call notify with ErrorMsg set, and return all the output
     *    buffers with processCaptureResult in the error state
     *    (BufferStatus.ERROR). The HAL must not place the release
     *    fence into an error state, instead, the release fences must be set to
     *    the acquire fences passed by the framework, or -1 if they have been
     *    waited on by the HAL already. This is also the path to follow for any
     *    captures for which the HAL already called notify() with
     *    ShutterMsg set, but won't be producing any metadata/valid buffers
     *    for. After ErrorMsg is set, for a given frame, only
     *    processCaptureResults with buffers in BufferStatus.ERROR
     *    are allowed. No further notifys or processCaptureResult with
     *    non-empty metadata is allowed.
     *
     * 3. For partially completed pending requests that do not have all the
     *    output buffers or perhaps missing metadata, the HAL must follow
     *    below:
     *
     *    3.1. Call notify with ErrorMsg set with ErrorCode.ERROR_RESULT if some of the expected
     *         result metadata (i.e. one or more partial metadata) won't be
     *         available for the capture.
     *
     *    3.2. Call notify with ErrorMsg set with ErrorCode.ERROR_BUFFER for every buffer that
     *         won't be produced for the capture.
     *
     *    3.3. Call notify with ShutterMsg with the capture timestamp
     *         before any buffers/metadata are returned with
     *         processCaptureResult.
     *
     *    3.4. For captures that will produce some results, the HAL must not
     *         call notify with ErrorCode.ERROR_REQUEST, since that indicates complete
     *         failure.
     *
     *    3.5. Valid buffers/metadata must be passed to the framework as
     *         normal.
     *
     *    3.6. Failed buffers must be returned to the framework as described
     *         for case 2. But failed buffers do not have to follow the strict
     *         ordering valid buffers do, and may be out-of-order with respect
     *         to valid buffers. For example, if buffers A, B, C, D, E are sent,
     *         D and E are failed, then A, E, B, D, C is an acceptable return
     *         order.
     *
     *    3.7. For fully-missing metadata, calling ErrorCode.ERROR_RESULT is
     *         sufficient, no need to call processCaptureResult with empty
     *         metadata or equivalent.
     *
     * 4. If a flush() is invoked while a processCaptureRequest() invocation
     *    is active, that process call must return as soon as possible. In
     *    addition, if a processCaptureRequest() call is made after flush()
     *    has been invoked but before flush() has returned, the capture request
     *    provided by the late processCaptureRequest call must be treated
     *    like a pending request in case #2 above.
     *
     * flush() must only return when there are no more outstanding buffers or
     * requests left in the HAL. The framework may call configure_streams (as
     * the HAL state is now quiesced) or may issue new requests.
     *
     * Note that it's sufficient to only support fully-succeeded and
     * fully-failed result cases. However, it is highly desirable to support
     * the partial failure cases as well, as it could help improve the flush
     * call overall performance.
     *
     * Performance requirements:
     *
     * The HAL should return from this call in 100ms, and must return from this
     * call in 1000ms. And this call must not be blocked longer than pipeline
     * latency (see below for definition).
     *
     * Pipeline Latency:
     * For a given capture request, the duration from the framework calling
     * process_capture_request to the HAL sending capture result and all buffers
     * back by process_capture_result call. To make the Pipeline Latency measure
     * independent of frame rate, it is measured by frame count.
     *
     * For example, when frame rate is 30 (fps), the frame duration (time interval
     * between adjacent frame capture time) is 33 (ms).
     * If it takes 5 frames for framework to get the result and buffers back for
     * a given request, then the Pipeline Latency is 5 (frames), instead of
     * 5 x 33 = 165 (ms).
     *
     * The Pipeline Latency is determined by android.request.pipelineDepth and
     * android.request.pipelineMaxDepth, see their definitions for more details.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         If the camera device has encountered a serious error. After this
     *         error is returned, only the close() method can be successfully
     *         called by the framework.
     */
    void flush();

    /**
     * getCaptureRequestMetadataQueue:
     *
     * Retrieves the queue used along with processCaptureRequest. If
     * client decides to use fast message queue to pass request metadata,
     * it must:
     * - Call getCaptureRequestMetadataQueue to retrieve the fast message queue;
     * - In each of the requests sent in processCaptureRequest, set
     *   fmqSettingsSize field of CaptureRequest to be the size to read from the
     *   fast message queue; leave settings field of CaptureRequest empty.
     *
     * @return the queue that client writes request metadata to.
     */
    MQDescriptor<byte, SynchronizedReadWrite> getCaptureRequestMetadataQueue();

    /**
     * getCaptureResultMetadataQueue:
     *
     * Retrieves the queue used along with
     * ICameraDeviceCallback.processCaptureResult.
     *
     * Clients to ICameraDeviceSession must:
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
     * isReconfigurationRequired:
     *
     * Check whether complete stream reconfiguration is required for possible new session
     * parameter values.
     *
     * This method must be called by the camera framework in case the client changes
     * the value of any advertised session parameters. Depending on the specific values
     * the HAL can decide whether a complete stream reconfiguration is required. In case
     * the HAL returns false, the camera framework must skip the internal reconfiguration.
     * In case Hal returns true, the framework must reconfigure the streams and pass the
     * new session parameter values accordingly.
     * This call may be done by the framework some time before the request with new parameters
     * is submitted to the HAL, and the request may be cancelled before it ever gets submitted.
     * Therefore, the HAL must not use this query as an indication to change its behavior in any
     * way.
     * ------------------------------------------------------------------------
     *
     * Preconditions:
     *
     * The framework can call this method at any time after active
     * session configuration. There must be no impact on the performance of
     * pending camera requests in any way. In particular there must not be
     * any glitches or delays during normal camera streaming.
     *
     * Performance requirements:
     * HW and SW camera settings must not be changed and there must not be
     * a user-visible impact on camera performance.
     *
     * @param oldSessionParams Before session parameters, usually the current session parameters.
     * @param newSessionParams The new session parameters which may be set by client.
     * A service specific error will be returned in the following case:
     *
     *     INTERNAL_ERROR:
     *          The reconfiguration query cannot complete due to internal
     *          error.
     * @return true in case the stream reconfiguration is required, false otherwise.
     */
    boolean isReconfigurationRequired(in CameraMetadata oldSessionParams,
                                      in CameraMetadata newSessionParams);

    /**
     * processCaptureRequest:
     *
     * Send a list of capture requests to the HAL. The HAL must not return from
     * this call until it is ready to accept the next set of requests to
     * process. Only one call to processCaptureRequest() must be made at a time
     * by the framework, and the calls must all be from the same thread. The
     * next call to processCaptureRequest() must be made as soon as a new
     * request and its associated buffers are available. In a normal preview
     * scenario, this means the function is generally called again by the
     * framework almost instantly. If more than one request is provided by the
     * client, the HAL must process the requests in order of lowest index to
     * highest index.
     *
     * The cachesToRemove argument contains a list of buffer caches (see
     * StreamBuffer document for more information on buffer cache) to be removed
     * by camera HAL. Camera HAL must remove these cache entries whether or not
     * this method returns OK.
     *
     * The actual request processing is asynchronous, with the results of
     * capture being returned by the HAL through the processCaptureResult()
     * call. This call requires the result metadata to be available, but output
     * buffers may simply provide sync fences to wait on. Multiple requests are
     * expected to be in flight at once, to maintain full output frame rate.
     *
     * The framework retains ownership of the request structure. It is only
     * guaranteed to be valid during this call. The HAL device must make copies
     * of the information it needs to retain for the capture processing. The HAL
     * is responsible for waiting on and closing the buffers' fences and
     * returning the buffer handles to the framework.
     *
     * The HAL must write the file descriptor for the input buffer's release
     * sync fence into input_buffer->release_fence, if input_buffer is not
     * valid. If the HAL returns -1 for the input buffer release sync fence, the
     * framework is free to immediately reuse the input buffer. Otherwise, the
     * framework must wait on the sync fence before refilling and reusing the
     * input buffer.
     *
     * The input/output buffers provided by the framework in each request
     * may be brand new (having never before seen by the HAL).
     *
     * ------------------------------------------------------------------------
     * Performance considerations:
     *
     * Handling a new buffer should be extremely lightweight and there must be
     * no frame rate degradation or frame jitter introduced.
     *
     * This call must return fast enough to ensure that the requested frame
     * rate can be sustained, especially for streaming cases (post-processing
     * quality settings set to FAST). The HAL should return this call in 1
     * frame interval, and must return from this call in 4 frame intervals.
     *
     * - The capture request can include individual settings for physical camera devices
     *   backing a logical multi-camera.
     *
     * - The capture request can include width and height of the input buffer for
     *   a reprocessing request.
     *
     * A service specific error will be returned on the following conditions
     *     ILLEGAL_ARGUMENT:
     *         If the input is malformed (the settings are empty when not
     *         allowed, the physical camera settings are invalid, there are 0
     *         output buffers, etc) and capture processing
     *         cannot start. Failures during request processing must be
     *         handled by calling ICameraDeviceCallback::notify(). In case of
     *         this error, the framework retains responsibility for the
     *         stream buffers' fences and the buffer handles; the HAL must not
     *         close the fences or return these buffers with
     *         ICameraDeviceCallback::processCaptureResult().
     *         In case of multi-resolution input image, this error must be returned
     *         if the caller passes in a CaptureRequest with an invalid
     *         [inputWith, inputHeight].
     *     INTERNAL_ERROR:
     *         If the camera device has encountered a serious error. After this
     *         error is returned, only the close() method can be successfully
     *         called by the framework.
     *
     * @param requests The capture requests to be processed by the camera HAL
     * @param cachesToRemove list of buffer caches to be removed by the camera HAL
     * @return Number of requests successfully processed by
     *     camera HAL. On success, this must be equal to the size of
     *     requests. When the call fails, this number is the number of requests
     *     that HAL processed successfully before HAL runs into an error and a service specific
     *     error is also set.
     *
     */
    int processCaptureRequest(in CaptureRequest[] requests, in BufferCache[] cachesToRemove);

    /**
     * signalStreamFlush:
     *
     * Signaling to the HAL, camera service is about to perform configureStreams and
     * HAL must return all buffers of designated streams. HAL must finish
     * inflight requests normally and return all buffers that belongs to the
     * designated streams through processCaptureResult or returnStreamBuffer
     * API in a timely manner, or camera service will run into a fatal error.
     *
     * Note that this call serves as an optional hint and camera service may
     * skip sending this call if all buffers are already returned.
     *
     * @param streamIds The ID of streams camera service need all of its
     *     buffers returned.
     *
     * @param streamConfigCounter Note that due to concurrency nature, it is
     *     possible the signalStreamFlush call arrives later than the
     *     corresponding configureStreams() call, HAL must check
     *     streamConfigCounter for such race condition. If the counter is less
     *     than the counter in the last configureStreams() call HAL last
     *     received, the call is stale and HAL should just return this call.
     */
    oneway void signalStreamFlush(in int[] streamIds, in int streamConfigCounter);

    /**
     * switchToOffline:
     *
     * Switch the current running session from actively streaming mode to the
     * offline mode. See ICameraOfflineSession for more details.
     *
     * The streamsToKeep argument contains list of streams IDs where application
     * still needs its output. For all streams application does not need anymore,
     * camera HAL can send ERROR_BUFFER to speed up the transition, or even send
     * ERROR_REQUEST if all output targets of a request is not needed. By the
     * time this call returns, camera HAL must have returned all buffers coming
     * from streams no longer needed and have erased buffer caches of such streams.
     *
     * For all requests that are going to be transferred to offline session,
     * the ICameraDeviceSession is responsible to capture all input buffers from
     * the image sensor before the switchToOffline call returns. Before
     * switchToOffline returns, camera HAL must have completed all requests not
     * switching to offline mode, and collected information on what streams and
     * requests are going to continue in the offline session, in the
     * offlineSessionInfo output argument.
     *
     * If there are no requests qualified to be transferred to offline session,
     * the camera HAL must return a null ICameraOfflineSession object with OK
     * status. In this scenario, the camera HAL still must flush all inflight
     * requests and unconfigure all streams before returning this call.
     *
     * After switchToOffline returns, the ICameraDeviceSession must be back to
     * unconfigured state as if it is just created and no streams are configured.
     * Also, camera HAL must not call any methods in ICameraDeviceCallback since
     * all unfinished requests are now transferred to the offline session.
     * After the call returns, camera service may then call close to close
     * the camera device, or call configureStream* again to reconfigure the
     * camera and then send new capture requests with processCaptureRequest. In
     * the latter case, it is legitimate for camera HAL to call methods in
     * ICameraDeviceCallback again in response to the newly submitted capture
     * requests.
     *
     * A service specific error will be returned on the following conditions
     *     ILLEGAL_ARGUMENT:
     *         If camera does not support offline mode in any one of streams
     *         in streamsToKeep argument. Note that the camera HAL must report
     *         if a stream supports offline mode in HalStreamConfiguration
     *         output of configureStreams_3_6 method. If all streams in
     *         streamsToKeep argument support offline mode, then the camera HAL
     *         must not return this error.
     *
     * @param in streamsToKeep The streamIds of the streams that will continue in the offline
     *        session
     * @param out offlineSessionInfo Information on what streams and requests will
     *     be transferred to offline session to continue processing.
     *
     * @return offlineSession The offline session object camera service will use
     *     to interact with.
     */
    ICameraOfflineSession switchToOffline(
            in int[] streamsToKeep, out CameraOfflineSessionInfo offlineSessionInfo);

    /**
     * repeatingRequestEnd:
     *
     * Notification about the last frame number in a repeating request along with the
     * ids of all streams included in the repeating request.
     *
     * This can be called at any point after 'processCaptureRequest' in response
     * to camera clients disabling an active repeating request.
     *
     * Performance requirements:
     * The call must not be blocked for extensive periods and should be extremely lightweight. There
     * must be no frame rate degradation or frame jitter introduced.
     *
     * This method must always succeed, even if the device has encountered a
     * serious error.
     */
    void repeatingRequestEnd(in int frameNumber, in int[] streamIds);

}
