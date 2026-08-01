package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.TotalCaptureResult;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.view.Surface;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class Camera2ProbeActivity extends Activity {
    private HandlerThread callbacks;
    private Handler handler;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        callbacks = new HandlerThread("camera-runtime-callbacks");
        callbacks.start();
        handler = new Handler(callbacks.getLooper());
        new Thread(this::runProbe, "camera-runtime-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            report.put("probe", "camera2-lifecycle");
            String referencePhoto = getIntent().getStringExtra("referencePhoto");
            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            CameraManager manager = getSystemService(CameraManager.class);
            for (String id : new String[] {"0", "1"}) {
                JSONObject camera = probeCamera(manager, id, referencePhoto);
                cameras.put(camera);
                allOk &= camera.getBoolean("ok");
            }
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("camera2-lifecycle", error);
        }
        ProbeIo.write(this, "camera2.json", report);
        runOnUiThread(() -> {
            callbacks.quitSafely();
            finish();
        });
    }

    private JSONObject probeCamera(CameraManager manager, String id, String referencePhoto)
            throws Exception {
        JSONObject result = new JSONObject();
        result.put("id", id);
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        Integer sensorOrientation = characteristics.get(
                CameraCharacteristics.SENSOR_ORIENTATION);
        int referenceRotation = sensorOrientation == null
                ? 0 : (360 - sensorOrientation) % 360;
        byte[] yuvReference = referencePhoto == null ? null
                : CameraSupport.referencePhotoSample(
                        referencePhoto, 320, 240, referenceRotation);
        boolean jpegSwapsAxes = sensorOrientation != null
                && (sensorOrientation == 90 || sensorOrientation == 270);
        byte[] jpegReference = referencePhoto == null ? null
                : CameraSupport.referencePhotoSample(referencePhoto,
                        jpegSwapsAxes ? 240 : 320,
                        jpegSwapsAxes ? 320 : 240, 0);
        CameraDevice device = CameraSupport.open(manager, id, handler);
        CameraCaptureSession session = null;
        try (CameraSupport.FrameReader yuv = new CameraSupport.FrameReader(
                        320, 240, ImageFormat.YUV_420_888, 16, handler);
                CameraSupport.FrameReader jpeg = new CameraSupport.FrameReader(
                        320, 240, ImageFormat.JPEG, 16, handler);
                CameraSupport.FrameReader opaque = new CameraSupport.FrameReader(
                        320, 240, ImageFormat.PRIVATE, 16, handler)) {
            session = CameraSupport.configure(device,
                    Arrays.asList(yuv.surface(), jpeg.surface(), opaque.surface()), handler);
            CaptureRequest.Builder all = device.createCaptureRequest(
                    CameraDevice.TEMPLATE_STILL_CAPTURE);
            if (sensorOrientation != null) {
                all.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
            }
            all.addTarget(yuv.surface());
            all.addTarget(jpeg.surface());
            all.addTarget(opaque.surface());
            long allTimestamp = CameraSupport.capture(session, all.build(), handler);
            CameraSupport.Frame yuvFrame = yuv.take();
            CameraSupport.Frame jpegFrame = jpeg.take();
            CameraSupport.Frame privateFrame = opaque.take();
            boolean referenceContentMatched = yuvReference == null
                    || (CameraSupport.meanDelta(yuvFrame.sample, yuvReference) <= 32.0
                            && CameraSupport.meanDelta(
                                    jpegFrame.sample, jpegReference) <= 32.0);
            boolean multiOutput = yuvFrame.bytes > 0 && jpegFrame.bytes > 0
                    && jpegFrame.jpegValid && jpegFrame.jpegExifValid
                    && privateFrame.timestamp > 0
                    && yuvFrame.timestamp == allTimestamp
                    && jpegFrame.timestamp == allTimestamp
                    && privateFrame.timestamp == allTimestamp
                    && referenceContentMatched;
            yuv.clear();
            opaque.clear();
            CountDownLatch repeating = new CountDownLatch(4);
            AtomicLong priorTimestamp = new AtomicLong(-1L);
            AtomicBoolean monotonic = new AtomicBoolean(true);
            CaptureRequest.Builder preview = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            preview.addTarget(yuv.surface());
            preview.addTarget(opaque.surface());
            session.setRepeatingRequest(preview.build(), new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureCompleted(CameraCaptureSession value,
                        CaptureRequest request, TotalCaptureResult captureResult) {
                    Long timestamp = captureResult.get(
                            android.hardware.camera2.CaptureResult.SENSOR_TIMESTAMP);
                    long previous = priorTimestamp.getAndSet(timestamp == null ? -1L : timestamp);
                    if (timestamp == null || (previous > 0 && timestamp <= previous)) {
                        monotonic.set(false);
                    }
                    repeating.countDown();
                }
            }, handler);
            boolean repeatingCompleted = repeating.await(10, TimeUnit.SECONDS);
            session.stopRepeating();
            session.abortCaptures();
            int repeatingYuv = 0;
            int repeatingPrivate = 0;
            for (int index = 0; index < 4; ++index) {
                if (yuv.take().bytes > 0) ++repeatingYuv;
                if (opaque.take().timestamp > 0) ++repeatingPrivate;
            }

            yuv.clear();
            CaptureRequest.Builder burstBuilder = device.createCaptureRequest(
                    CameraDevice.TEMPLATE_STILL_CAPTURE);
            burstBuilder.addTarget(yuv.surface());
            List<CaptureRequest> burst = new ArrayList<>();
            for (int index = 0; index < 5; ++index) burst.add(burstBuilder.build());
            CountDownLatch burstCompleted = new CountDownLatch(burst.size());
            AtomicBoolean burstFailed = new AtomicBoolean(false);
            session.captureBurst(burst, new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureCompleted(CameraCaptureSession value,
                        CaptureRequest request, TotalCaptureResult captureResult) {
                    burstCompleted.countDown();
                }
                @Override public void onCaptureFailed(CameraCaptureSession value,
                        CaptureRequest request, CaptureFailure failure) {
                    burstFailed.set(true);
                    burstCompleted.countDown();
                }
            }, handler);
            boolean burstCallbacks = burstCompleted.await(15, TimeUnit.SECONDS);
            int burstImages = 0;
            for (int index = 0; index < burst.size(); ++index) {
                if (yuv.take().bytes > 0) ++burstImages;
            }

            jpeg.clear();
            CaptureRequest.Builder flushBuilder = device.createCaptureRequest(
                    CameraDevice.TEMPLATE_STILL_CAPTURE);
            if (sensorOrientation != null) {
                flushBuilder.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
            }
            flushBuilder.addTarget(jpeg.surface());
            List<CaptureRequest> pending = new ArrayList<>();
            for (int index = 0; index < 12; ++index) pending.add(flushBuilder.build());
            CountDownLatch sequenceTerminal = new CountDownLatch(1);
            FlushAccounting flushAccounting = new FlushAccounting(pending);
            session.captureBurst(pending, new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureCompleted(CameraCaptureSession value,
                        CaptureRequest request, TotalCaptureResult captureResult) {
                    flushAccounting.completed(request, captureResult.get(
                            android.hardware.camera2.CaptureResult.SENSOR_TIMESTAMP));
                }
                @Override public void onCaptureFailed(CameraCaptureSession value,
                        CaptureRequest request, CaptureFailure failure) {
                    flushAccounting.failed(request);
                }
                @Override public void onCaptureBufferLost(CameraCaptureSession value,
                        CaptureRequest request, Surface target, long frameNumber) {
                    flushAccounting.bufferLost(request);
                }
                @Override public void onCaptureSequenceCompleted(CameraCaptureSession value,
                        int sequenceId, long frameNumber) {
                    sequenceTerminal.countDown();
                }
                @Override public void onCaptureSequenceAborted(CameraCaptureSession value,
                        int sequenceId) {
                    sequenceTerminal.countDown();
                }
            }, handler);
            SystemClock.sleep(20L);
            long flushStart = SystemClock.elapsedRealtimeNanos();
            session.abortCaptures();
            boolean flushTerminal = sequenceTerminal.await(1, TimeUnit.SECONDS);
            long flushMs = TimeUnit.NANOSECONDS.toMillis(
                    SystemClock.elapsedRealtimeNanos() - flushStart);
            boolean ownershipCallbacks = flushAccounting.await(
                    CameraSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS);
            FlushSummary flushSummary = flushAccounting.summary();
            List<Long> imageTimestamps = new ArrayList<>(flushSummary.imageTimestamps);
            int flushImagesConsumed = 0;
            boolean completedImagesValid = ownershipCallbacks
                    && flushSummary.ownershipResolved;
            if (completedImagesValid) {
                for (int index = 0; index < flushSummary.completed; ++index) {
                    CameraSupport.Frame frame = jpeg.take();
                    boolean timestampMatched = imageTimestamps.remove(
                            Long.valueOf(frame.timestamp));
                    completedImagesValid &= frame.bytes > 0 && frame.jpegValid
                            && frame.jpegExifValid && timestampMatched;
                    ++flushImagesConsumed;
                }
                completedImagesValid &= imageTimestamps.isEmpty();
            }
            CountDownLatch imageCallbacksSettled = new CountDownLatch(1);
            boolean imageBarrierPosted = handler.post(imageCallbacksSettled::countDown);
            boolean imageQueueSettled = imageBarrierPosted
                    && imageCallbacksSettled.await(1, TimeUnit.SECONDS)
                    && jpeg.frames.isEmpty();
            completedImagesValid &= imageQueueSettled;
            boolean readyForRecovery = flushTerminal && flushMs < 1000L
                    && ownershipCallbacks && flushSummary.ownershipResolved
                    && completedImagesValid;
            if (!readyForRecovery) {
                throw new IllegalStateException("flush ownership unresolved");
            }
            long recoveryTimestamp =
                    CameraSupport.capture(session, flushBuilder.build(), handler);
            CameraSupport.Frame recovery = jpeg.take();
            boolean flushRecovery = recovery.jpegValid && recovery.jpegExifValid
                    && recovery.bytes > 0 && recovery.timestamp == recoveryTimestamp;

            session.close();
            session = null;
            SystemClock.sleep(100L);
            boolean reconfigured;
            try (CameraSupport.FrameReader changed = new CameraSupport.FrameReader(
                    640, 480, ImageFormat.YUV_420_888, 4, handler)) {
                CameraCaptureSession changedSession = CameraSupport.configure(
                        device, Collections.singletonList(changed.surface()), handler);
                try {
                    CaptureRequest.Builder request = device.createCaptureRequest(
                            CameraDevice.TEMPLATE_PREVIEW);
                    request.addTarget(changed.surface());
                    long timestamp = CameraSupport.capture(changedSession, request.build(), handler);
                    CameraSupport.Frame frame = changed.take();
                    reconfigured = frame.bytes > 0 && frame.timestamp == timestamp;
                } finally {
                    changedSession.close();
                }
            }

            device.close();
            device = null;
            SystemClock.sleep(100L);
            boolean reopened = captureAfterReopen(manager, id);
            result.put("multiOutput", multiOutput);
            result.put("jpegExif", jpegFrame.jpegExifValid);
            result.put("referenceContentMatched", referenceContentMatched);
            result.put("repeating", repeatingCompleted && monotonic.get()
                    && repeatingYuv >= 4 && repeatingPrivate >= 4);
            result.put("burst", burstCallbacks && !burstFailed.get()
                    && burstImages == burst.size());
            result.put("reconfigured", reconfigured);
            result.put("flushSubmitted", pending.size());
            result.put("flushCompleted", flushSummary.completed);
            result.put("flushFailed", flushSummary.failed);
            result.put("flushBufferLost", flushSummary.bufferLost);
            result.put("flushResolved", flushSummary.resolved);
            result.put("flushImagesConsumed", flushImagesConsumed);
            result.put("flushUnderOneSecond", flushMs < 1000L);
            result.put("flushTerminal", flushTerminal);
            result.put("flushOwnershipResolved",
                    ownershipCallbacks && flushSummary.ownershipResolved);
            result.put("flushCompletedImagesConsumed", completedImagesValid);
            result.put("flushImageQueueSettled", imageQueueSettled);
            result.put("flushRecovery", flushRecovery);
            result.put("closeReopen", reopened);
            result.put("ok", multiOutput && repeatingCompleted && monotonic.get()
                    && repeatingYuv >= 4 && repeatingPrivate >= 4
                    && burstCallbacks && !burstFailed.get() && burstImages == burst.size()
                    && reconfigured && flushMs < 1000L && flushTerminal
                    && ownershipCallbacks && flushSummary.ownershipResolved
                    && completedImagesValid && flushRecovery && reopened);
            if (!result.getBoolean("ok")) throw new IllegalStateException("camera2 contract failed");
            return result;
        } finally {
            if (session != null) session.close();
            if (device != null) device.close();
        }
    }

    private boolean captureAfterReopen(CameraManager manager, String id) throws Exception {
        CameraDevice device = CameraSupport.open(manager, id, handler);
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                320, 240, ImageFormat.YUV_420_888, 4, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder request = device.createCaptureRequest(
                        CameraDevice.TEMPLATE_PREVIEW);
                request.addTarget(reader.surface());
                long timestamp = CameraSupport.capture(session, request.build(), handler);
                CameraSupport.Frame frame = reader.take();
                return frame.bytes > 0 && frame.timestamp == timestamp;
            } finally {
                session.close();
            }
        } finally {
            device.close();
        }
    }
    private static final class FlushAccounting {
        private final Map<CaptureRequest, FlushRequest> requests = new IdentityHashMap<>();
        private final CountDownLatch ownership;
        private boolean invalidCallback;

        FlushAccounting(List<CaptureRequest> submitted) {
            ownership = new CountDownLatch(submitted.size());
            for (CaptureRequest request : submitted) {
                requests.put(request, new FlushRequest());
            }
            if (requests.size() != submitted.size()) invalidCallback = true;
        }

        synchronized void completed(CaptureRequest request, Long timestamp) {
            FlushRequest state = requests.get(request);
            if (state == null || state.completed || state.failed) {
                invalidCallback = true;
                return;
            }
            boolean unresolved = !state.resolved();
            state.completed = true;
            state.timestamp = timestamp;
            if (timestamp == null) invalidCallback = true;
            if (unresolved) ownership.countDown();
        }

        synchronized void failed(CaptureRequest request) {
            FlushRequest state = requests.get(request);
            if (state == null || state.failed || state.completed || state.bufferLost) {
                invalidCallback = true;
                return;
            }
            boolean unresolved = !state.resolved();
            state.failed = true;
            if (unresolved) ownership.countDown();
        }

        synchronized void bufferLost(CaptureRequest request) {
            FlushRequest state = requests.get(request);
            if (state == null || state.bufferLost || state.failed) {
                invalidCallback = true;
                return;
            }
            boolean unresolved = !state.resolved();
            state.bufferLost = true;
            if (unresolved) ownership.countDown();
        }

        boolean await(long timeout, TimeUnit unit) throws InterruptedException {
            return ownership.await(timeout, unit);
        }

        synchronized FlushSummary summary() {
            int completed = 0;
            int failed = 0;
            int bufferLost = 0;
            int resolved = 0;
            List<Long> timestamps = new ArrayList<>();
            for (FlushRequest state : requests.values()) {
                if (state.resolved()) ++resolved;
                if (state.bufferLost) {
                    ++bufferLost;
                } else if (state.failed) {
                    ++failed;
                } else if (state.completed) {
                    ++completed;
                    if (state.timestamp != null) timestamps.add(state.timestamp);
                }
            }
            boolean ownershipResolved = !invalidCallback
                    && resolved == requests.size()
                    && completed + failed + bufferLost == requests.size()
                    && timestamps.size() == completed;
            return new FlushSummary(completed, failed, bufferLost, resolved,
                    ownershipResolved, timestamps);
        }
    }

    private static final class FlushRequest {
        boolean completed;
        boolean failed;
        boolean bufferLost;
        Long timestamp;

        boolean resolved() { return completed || failed || bufferLost; }
    }

    private static final class FlushSummary {
        final int completed;
        final int failed;
        final int bufferLost;
        final int resolved;
        final boolean ownershipResolved;
        final List<Long> imageTimestamps;

        FlushSummary(int completed, int failed, int bufferLost, int resolved,
                boolean ownershipResolved, List<Long> imageTimestamps) {
            this.completed = completed;
            this.failed = failed;
            this.bufferLost = bufferLost;
            this.resolved = resolved;
            this.ownershipResolved = ownershipResolved;
            this.imageTimestamps = imageTimestamps;
        }
    }
}
