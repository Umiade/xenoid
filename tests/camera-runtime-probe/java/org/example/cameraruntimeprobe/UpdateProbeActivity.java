package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.media.MediaMetadataRetriever;

import org.json.JSONObject;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class UpdateProbeActivity extends Activity {
    private static final double CONTENT_DELTA_LIMIT = 28.0;
    private static final double SOURCE_MARGIN = 4.0;
    private static final double SOURCE_SEPARATION_MINIMUM = 12.0;
    private HandlerThread callbacks;
    private Handler handler;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        callbacks = new HandlerThread("update-probe-callbacks");
        callbacks.start();
        handler = new Handler(callbacks.getLooper());
        new Thread(this::runProbe, "update-on-open-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            String id = getIntent().getStringExtra("cameraId");
            if (!"0".equals(id) && !"1".equals(id)) {
                throw new IllegalArgumentException("invalid camera id");
            }
            String sourceKind = getIntent().getStringExtra("sourceKind");
            if (!"photo".equals(sourceKind) && !"video".equals(sourceKind)) {
                throw new IllegalArgumentException("invalid source kind");
            }
            String referenceBefore = getIntent().getStringExtra("referenceBefore");
            String referenceAfter = getIntent().getStringExtra("referenceAfter");
            if (referenceBefore == null || referenceBefore.isEmpty()
                    || referenceAfter == null || referenceAfter.isEmpty()) {
                throw new IllegalArgumentException("update references required");
            }
            int pauseMs = Math.max(3000, Math.min(30000,
                    getIntent().getIntExtra("pauseMs", 10000)));
            report = probe(id, sourceKind, referenceBefore, referenceAfter, pauseMs);
            report.put("probe", "update-on-next-open");
            report.put("sourceKind", sourceKind);
            report.put("ok", report.getBoolean("sameSessionStable")
                    && report.getBoolean("reopenChanged")
                    && report.getBoolean("beforeMatched")
                    && report.getBoolean("duringMatched")
                    && report.getBoolean("afterMatched")
                    && report.getBoolean("referencesDistinct"));
        } catch (Throwable error) {
            report = ProbeIo.failure("update-on-next-open", error);
        }
        ProbeIo.write(this, "update.json", report);
        runOnUiThread(() -> {
            callbacks.quitSafely();
            finish();
        });
    }

    private JSONObject probe(String id, String sourceKind, String referenceBeforePath,
            String referenceAfterPath, int pauseMs) throws Exception {
        CameraManager manager = getSystemService(CameraManager.class);
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        Integer sensorOrientation =
                characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION);
        int cameraRotation = sensorOrientation == null
                ? 0 : (360 - sensorOrientation) % 360;
        ReferenceSource referenceBefore =
                new ReferenceSource(sourceKind, referenceBeforePath, cameraRotation);
        ReferenceSource referenceAfter = null;
        try {
            referenceAfter =
                    new ReferenceSource(sourceKind, referenceAfterPath, cameraRotation);
        CountDownLatch cameraAvailable = new CountDownLatch(1);
        AtomicBoolean closing = new AtomicBoolean(false);
        CameraManager.AvailabilityCallback availability =
                new CameraManager.AvailabilityCallback() {
                    @Override public void onCameraAvailable(String availableId) {
                        if (closing.get() && id.equals(availableId)) {
                            cameraAvailable.countDown();
                        }
                    }
                };
        manager.registerAvailabilityCallback(availability, handler);

        CameraSupport.Frame before;
        CameraSupport.Frame during;
        CameraSupport.Frame after;
        long beforeOffsetMs;
        long duringOffsetMs;
        long afterOffsetMs;
        try {
            CameraDevice device = CameraSupport.open(manager, id, handler);
            try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                    320, 240, ImageFormat.YUV_420_888, 4, handler)) {
                CameraCaptureSession session = CameraSupport.configure(
                        device, Collections.singletonList(reader.surface()), handler);
                try {
                    CaptureRequest.Builder request = request(
                            device, reader, sourceKind, sensorOrientation);
                    before = capture(session, request, reader);
                    beforeOffsetMs = referenceBefore.bestInitialOffset(before);
                    JSONObject ready = new JSONObject();
                    ready.put("probe", "update-ready");
                    ready.put("cameraId", id);
                    ready.put("sourceKind", sourceKind);
                    ready.put("ok", true);
                    ProbeIo.write(this, "update-ready-" + id + ".json", ready);
                    Thread.sleep(pauseMs);
                    during = capture(session, request, reader);
                    long elapsedMs = Math.max(0L,
                            (during.timestamp - before.timestamp) / 1000000L);
                    duringOffsetMs = beforeOffsetMs + elapsedMs;
                } finally {
                    session.close();
                }
            } finally {
                closing.set(true);
                device.close();
            }
            if (!cameraAvailable.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("camera close timed out");
            }

            CameraDevice reopenedDevice = CameraSupport.open(manager, id, handler);
            try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                    320, 240, ImageFormat.YUV_420_888, 4, handler)) {
                CameraCaptureSession session = CameraSupport.configure(
                        reopenedDevice, Collections.singletonList(reader.surface()), handler);
                try {
                    CaptureRequest.Builder request = request(
                            reopenedDevice, reader, sourceKind, sensorOrientation);
                    after = capture(session, request, reader);
                    afterOffsetMs = referenceAfter.bestInitialOffset(after);
                } finally {
                    session.close();
                }
            } finally {
                reopenedDevice.close();
            }
        } finally {
            manager.unregisterAvailabilityCallback(availability);
        }

            double beforeADelta = referenceBefore.delta(before, beforeOffsetMs);
            double beforeBDelta = referenceAfter.delta(before, beforeOffsetMs);
            double duringADelta = referenceBefore.delta(during, duringOffsetMs);
            double duringBDelta = referenceAfter.delta(during, duringOffsetMs);
            double afterBDelta = referenceAfter.delta(after, afterOffsetMs);
            double afterADelta = referenceBefore.delta(after, afterOffsetMs);
            byte[] beforeReferenceSample = referenceBefore.sampleAt(beforeOffsetMs);
            byte[] afterReferenceSample = referenceAfter.sampleAt(beforeOffsetMs);
            double referenceSeparation =
                    CameraSupport.meanDelta(beforeReferenceSample, afterReferenceSample);
            double sameSessionDelta =
                    CameraSupport.meanDelta(before.sample, during.sample);
            double reopenDelta = CameraSupport.meanDelta(before.sample, after.sample);

            boolean beforeMatched = beforeADelta <= CONTENT_DELTA_LIMIT
                    && beforeADelta + SOURCE_MARGIN <= beforeBDelta;
            boolean duringMatched = duringADelta <= CONTENT_DELTA_LIMIT
                    && duringADelta + SOURCE_MARGIN <= duringBDelta;
            boolean afterMatched = afterBDelta <= CONTENT_DELTA_LIMIT
                    && afterBDelta + SOURCE_MARGIN <= afterADelta;
            boolean referencesDistinct =
                    referenceSeparation >= SOURCE_SEPARATION_MINIMUM;
            boolean sameSessionStable = beforeMatched && duringMatched;
            boolean reopenChanged = afterMatched
                    && before.fingerprint != after.fingerprint
                    && reopenDelta >= SOURCE_MARGIN;

            JSONObject result = new JSONObject();
            result.put("cameraId", id);
            result.put("sameSessionStable", sameSessionStable);
            result.put("reopenChanged", reopenChanged);
            result.put("beforeMatched", beforeMatched);
            result.put("duringMatched", duringMatched);
            result.put("afterMatched", afterMatched);
            result.put("referencesDistinct", referencesDistinct);
            result.put("beforeSourceDelta", beforeADelta);
            result.put("duringSourceDelta", duringADelta);
            result.put("afterSourceDelta", afterBDelta);
            result.put("duringReplacementDelta", duringBDelta);
            result.put("afterPreviousDelta", afterADelta);
            result.put("sameSessionDelta", sameSessionDelta);
            result.put("reopenDelta", reopenDelta);
            result.put("referenceSeparationDelta", referenceSeparation);
            return result;
        } finally {
            referenceBefore.close();
            if (referenceAfter != null) referenceAfter.close();
        }
    }

    private static CaptureRequest.Builder request(CameraDevice device,
            CameraSupport.FrameReader reader, String sourceKind,
            Integer sensorOrientation) throws Exception {
        CaptureRequest.Builder request = device.createCaptureRequest(
                "video".equals(sourceKind)
                        ? CameraDevice.TEMPLATE_RECORD : CameraDevice.TEMPLATE_STILL_CAPTURE);
        request.addTarget(reader.surface());
        if (sensorOrientation != null) {
            request.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
        }
        return request;
    }

    private CameraSupport.Frame capture(CameraCaptureSession session,
            CaptureRequest.Builder request, CameraSupport.FrameReader reader) throws Exception {
        long timestamp = CameraSupport.capture(session, request.build(), handler);
        CameraSupport.Frame frame = reader.take();
        if (frame.bytes <= 0 || frame.timestamp != timestamp
                || frame.sample.length != CameraSupport.SAMPLE_BYTES) {
            throw new IllegalStateException("invalid update frame");
        }
        return frame;
    }

    private static final class ReferenceSource implements AutoCloseable {
        private final boolean video;
        private final int cameraRotation;
        private final byte[] photoSample;
        private final MediaMetadataRetriever retriever;
        private final long durationMs;
        private final int width;
        private final int height;
        private final int rotation;

        ReferenceSource(String sourceKind, String path, int cameraRotation) throws Exception {
            this.video = "video".equals(sourceKind);
            this.cameraRotation = cameraRotation;
            if (!video) {
                photoSample = CameraSupport.referencePhotoSample(
                        path, 320, 240, cameraRotation);
                retriever = null;
                durationMs = 1L;
                width = 0;
                height = 0;
                rotation = 0;
                return;
            }
            photoSample = null;
            retriever = new MediaMetadataRetriever();
            retriever.setDataSource(path);
            durationMs = parseLongMetadata(
                    retriever, MediaMetadataRetriever.METADATA_KEY_DURATION);
            width = (int) parseLongMetadata(
                    retriever, MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH);
            height = (int) parseLongMetadata(
                    retriever, MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT);
            String rotationValue = retriever.extractMetadata(
                    MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION);
            rotation = rotationValue == null ? 0
                    : normalizeRotation(Integer.parseInt(rotationValue));
            if (durationMs < 500L || width <= 0 || height <= 0) {
                throw new IllegalArgumentException("invalid update video reference");
            }
        }

        long bestInitialOffset(CameraSupport.Frame frame) {
            if (!video) return 0L;
            long bestOffset = 0L;
            double bestDelta = Double.POSITIVE_INFINITY;
            long limit = Math.min(400L, durationMs - 1L);
            for (long offset = 0L; offset <= limit; offset += 40L) {
                double delta = frameDelta(frame, offset);
                if (delta < bestDelta) {
                    bestDelta = delta;
                    bestOffset = offset;
                }
            }
            return bestOffset;
        }

        double delta(CameraSupport.Frame frame, long offsetMs) {
            if (!video) return CameraSupport.meanDelta(frame.sample, photoSample);
            double best = Double.POSITIVE_INFINITY;
            for (long adjustment = -60L; adjustment <= 60L; adjustment += 30L) {
                best = Math.min(best, frameDelta(frame, offsetMs + adjustment));
            }
            return best;
        }

        byte[] sampleAt(long offsetMs) {
            if (!video) return photoSample;
            long normalizedOffset = offsetMs % durationMs;
            if (normalizedOffset < 0L) normalizedOffset += durationMs;
            Bitmap bitmap = retriever.getFrameAtTime(normalizedOffset * 1000L,
                    MediaMetadataRetriever.OPTION_CLOSEST);
            if (bitmap == null) {
                throw new IllegalStateException("update video frame unavailable");
            }
            try {
                int transform = bitmapRotation(bitmap);
                return CameraSupport.transformedBitmapSample(
                        bitmap, 320, 240, transform);
            } finally {
                bitmap.recycle();
            }
        }

        private double frameDelta(CameraSupport.Frame frame, long offsetMs) {
            return CameraSupport.meanDelta(frame.sample, sampleAt(offsetMs));
        }

        private int bitmapRotation(Bitmap bitmap) {
            boolean swapsAxes = rotation == 90 || rotation == 270;
            boolean retrieverAppliedRotation = swapsAxes
                    && bitmap.getWidth() == height && bitmap.getHeight() == width;
            return normalizeRotation(cameraRotation
                    + (retrieverAppliedRotation ? 0 : rotation));
        }

        @Override public void close() {
            if (retriever != null) {
                try {
                    retriever.release();
                } catch (java.io.IOException ignored) { }
            }
        }

        private static long parseLongMetadata(
                MediaMetadataRetriever retriever, int key) {
            String value = retriever.extractMetadata(key);
            if (value == null) {
                throw new IllegalArgumentException("update reference metadata missing");
            }
            return Long.parseLong(value);
        }

        private static int normalizeRotation(int value) {
            int normalized = ((value % 360) + 360) % 360;
            if (normalized % 90 != 0) {
                throw new IllegalArgumentException("invalid update reference rotation");
            }
            return normalized;
        }
    }
}
