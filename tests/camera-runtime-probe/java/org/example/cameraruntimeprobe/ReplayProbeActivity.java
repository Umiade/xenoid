package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Bitmap;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.media.MediaMetadataRetriever;
import android.media.MediaExtractor;
import android.media.MediaFormat;

import org.json.JSONObject;

import java.util.Collections;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class ReplayProbeActivity extends Activity {
    private static final double CONTENT_DELTA_LIMIT = 36.0;
    private static final double NATURALIZED_PAIR_DELTA_LIMIT = 12.0;
    private static final double FAITHFUL_PAIR_DELTA_LIMIT = 6.0;
    private static final double ADVANCE_DELTA_MINIMUM = 3.0;
    private HandlerThread callbacks;
    private Handler handler;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        callbacks = new HandlerThread("video-loop-callbacks");
        callbacks.start();
        handler = new Handler(callbacks.getLooper());
        new Thread(this::runProbe, "video-loop-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        MediaMetadataRetriever reference = null;
        String id = getIntent().getStringExtra("cameraId");
        boolean snapshot = getIntent().getBooleanExtra("snapshot", false);
        String probeName = snapshot ? "video-snapshot" : "video-advance-loop";
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            if (!"0".equals(id) && !"1".equals(id)) {
                throw new IllegalArgumentException("invalid camera id");
            }
            String expectedMode = getIntent().getStringExtra("expectedMode");
            if (!"faithful".equals(expectedMode) && !"naturalized".equals(expectedMode)) {
                throw new IllegalArgumentException("invalid expected mode");
            }
            String referenceVideo = getIntent().getStringExtra("referenceVideo");
            if (referenceVideo == null || referenceVideo.isEmpty()) {
                throw new IllegalArgumentException("reference video required");
            }
            reference = new MediaMetadataRetriever();
            reference.setDataSource(referenceVideo);
            ReferenceMetadata metadata = inspectReference(referenceVideo, reference);

            long claimedDurationMs = getIntent().getLongExtra("durationMs", 0L);
            int claimedWidth = getIntent().getIntExtra("videoWidth", 0);
            int claimedHeight = getIntent().getIntExtra("videoHeight", 0);
            int claimedRotation = getIntent().getIntExtra("videoRotation", -1);
            String claimedMime = getIntent().getStringExtra("videoMime");
            boolean metadataCoherent = claimedDurationMs == metadata.durationMs
                    && claimedWidth == metadata.width
                    && claimedHeight == metadata.height
                    && claimedRotation == metadata.rotation
                    && metadata.trackMime.equals(claimedMime);
            if (!metadataCoherent) {
                throw new IllegalArgumentException("video metadata mismatch");
            }

            if (snapshot) {
                report = captureSnapshot(id, metadata, reference);
                report.put("probe", probeName);
                report.put("mode", expectedMode);
                report.put("metadataCoherent", true);
                report.put("ok", report.getBoolean("captureCompleted")
                        && report.getBoolean("contentMatched"));
            } else {
                long minimumWindowMs = metadata.durationMs + 2000L;
                long requestedWindowMs = getIntent().getLongExtra("windowMs", 0L);
                long windowMs = requestedWindowMs == 0L ? minimumWindowMs : requestedWindowMs;
                if (windowMs < minimumWindowMs || windowMs > 300000L) {
                    throw new IllegalArgumentException("invalid replay window");
                }
                report = capture(id, metadata, windowMs, expectedMode, reference);
                report.put("probe", probeName);
                report.put("mode", expectedMode);
                report.put("metadataCoherent", true);
                report.put("ok", report.getBoolean("advancing")
                        && report.getBoolean("loopObserved")
                        && report.getBoolean("timestampsMonotonic")
                        && report.getBoolean("continuedThroughWindow")
                        && report.getBoolean("contentMatched")
                        && report.getBoolean("modeMatched")
                        && report.getBoolean("reopenMatched"));
            }
        } catch (Throwable error) {
            report = ProbeIo.failure(probeName, error);
            try {
                report.put("cameraId", id);
            } catch (Throwable ignored) { }
        } finally {
            if (reference != null) {
                try {
                    reference.release();
                } catch (java.io.IOException ignored) { }
            }
        }
        ProbeIo.write(this, "replay.json", report);
        runOnUiThread(() -> {
            callbacks.quitSafely();
            finish();
        });
    }

    private JSONObject captureSnapshot(String id, ReferenceMetadata metadata,
            MediaMetadataRetriever reference) throws Exception {
        CameraManager manager = getSystemService(CameraManager.class);
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        Integer sensorOrientation =
                characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION);
        int cameraRotation = sensorOrientation == null
                ? 0 : (360 - sensorOrientation) % 360;
        CameraDevice device = CameraSupport.open(manager, id, handler);
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                320, 240, ImageFormat.YUV_420_888, 4, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder builder =
                        recordRequest(device, reader, sensorOrientation);
                captureFrame(session, builder, reader);
                CameraSupport.Frame frame = captureFrame(session, builder, reader);
                long offsetMs = referenceOffset(
                        reference, frame, metadata, cameraRotation);
                double contentDelta = referenceDelta(
                        reference, frame, offsetMs, metadata, cameraRotation);
                JSONObject result = new JSONObject();
                result.put("cameraId", id);
                result.put("captureCompleted", true);
                result.put("contentMatched", contentDelta <= CONTENT_DELTA_LIMIT);
                result.put("contentDelta", contentDelta);
                return result;
            } finally {
                session.close();
            }
        } finally {
            device.close();
        }
    }

    private JSONObject capture(String id, ReferenceMetadata metadata, long windowMs,
            String expectedMode, MediaMetadataRetriever reference) throws Exception {
        CameraManager manager = getSystemService(CameraManager.class);
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        Integer sensorOrientation =
                characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION);
        int cameraRotation = sensorOrientation == null
                ? 0 : (360 - sensorOrientation) % 360;
        long spacingMs = Math.min(250L, Math.max(80L, metadata.durationMs / 10L));
        long advanceOffsetMs = Math.min(metadata.durationMs - 80L,
                Math.max(spacingMs * 3L, metadata.durationMs / 3L));
        long[] sourceOffsets = {0L, spacingMs, spacingMs * 2L, advanceOffsetMs};
        CameraSupport.Frame[] early = new CameraSupport.Frame[sourceOffsets.length];
        CameraSupport.Frame[] loop = new CameraSupport.Frame[sourceOffsets.length];
        long referenceOffsetMs;
        boolean monotonic = true;
        boolean contentMatched = true;
        double maximumContentDelta = 0.0;
        long priorTimestamp = -1L;

        CameraDevice device = CameraSupport.open(manager, id, handler);
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                320, 240, ImageFormat.YUV_420_888, 4, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder builder = recordRequest(
                        device, reader, sensorOrientation);
                CameraSupport.Frame warmup = captureFrame(session, builder, reader);
                priorTimestamp = warmup.timestamp;
                long epoch = SystemClock.elapsedRealtime();
                for (int index = 0; index < sourceOffsets.length; ++index) {
                    sleepUntil(epoch + sourceOffsets[index]);
                    early[index] = captureFrame(session, builder, reader);
                    monotonic &= early[index].timestamp > priorTimestamp;
                    priorTimestamp = early[index].timestamp;
                }
                referenceOffsetMs = referenceOffset(
                        reference, early[0], metadata, cameraRotation);
                for (int index = 0; index < early.length; ++index) {
                    double delta = referenceDelta(reference, early[index],
                            referenceOffsetMs + sourceOffsets[index],
                            metadata, cameraRotation);
                    maximumContentDelta = Math.max(maximumContentDelta, delta);
                    contentMatched &= delta <= CONTENT_DELTA_LIMIT;
                }

                for (int index = 0; index < sourceOffsets.length; ++index) {
                    sleepUntil(epoch + metadata.durationMs + sourceOffsets[index]);
                    loop[index] = captureFrame(session, builder, reader);
                    monotonic &= loop[index].timestamp > priorTimestamp;
                    priorTimestamp = loop[index].timestamp;
                    double delta = referenceDelta(reference, loop[index],
                            referenceOffsetMs + sourceOffsets[index],
                            metadata, cameraRotation);
                    maximumContentDelta = Math.max(maximumContentDelta, delta);
                    contentMatched &= delta <= CONTENT_DELTA_LIMIT;
                }

                sleepUntil(epoch + windowMs);
                CameraSupport.Frame continued = captureFrame(session, builder, reader);
                monotonic &= continued.timestamp > priorTimestamp;
                double continuedDelta = referenceDelta(reference, continued,
                        referenceOffsetMs + windowMs, metadata, cameraRotation);
                maximumContentDelta = Math.max(maximumContentDelta, continuedDelta);
                contentMatched &= continuedDelta <= CONTENT_DELTA_LIMIT;

                double maximumPairDelta = 0.0;
                double minimumPairDelta = Double.POSITIVE_INFINITY;
                int exactPairs = 0;
                int varyingPairs = 0;
                for (int index = 0; index < early.length; ++index) {
                    double pairDelta =
                            CameraSupport.meanDelta(early[index].sample, loop[index].sample);
                    maximumPairDelta = Math.max(maximumPairDelta, pairDelta);
                    minimumPairDelta = Math.min(minimumPairDelta, pairDelta);
                    if (early[index].fingerprint == loop[index].fingerprint
                            && Arrays.equals(early[index].sample, loop[index].sample)) {
                        ++exactPairs;
                    }
                    if (early[index].fingerprint != loop[index].fingerprint
                            && pairDelta > 0.0
                            && pairDelta <= NATURALIZED_PAIR_DELTA_LIMIT) {
                        ++varyingPairs;
                    }
                }
                boolean faithfulPairs = exactPairs >= early.length - 1
                        && maximumPairDelta <= FAITHFUL_PAIR_DELTA_LIMIT;
                boolean naturalizedPairs = varyingPairs == early.length;
                boolean modeMatched = "faithful".equals(expectedMode)
                        ? faithfulPairs : naturalizedPairs;
                double advanceDelta =
                        CameraSupport.meanDelta(early[0].sample,
                                early[early.length - 1].sample);
                double postLoopAdvanceDelta =
                        CameraSupport.meanDelta(loop[0].sample,
                                loop[loop.length - 1].sample);
                boolean advancing = early[0].fingerprint
                        != early[early.length - 1].fingerprint
                        && advanceDelta >= ADVANCE_DELTA_MINIMUM;
                boolean postLoopAdvancing = loop[0].fingerprint
                        != loop[loop.length - 1].fingerprint
                        && postLoopAdvanceDelta >= ADVANCE_DELTA_MINIMUM;

                CameraSupport.Frame firstFrame = early[0];
                session.close();
                device.close();
                waitForAvailable(manager, id);
                CameraSupport.Frame reopened = captureReopened(
                        manager, id, sensorOrientation);
                long reopenOffsetMs = referenceOffset(
                        reference, reopened, metadata, cameraRotation);
                double reopenContentDelta = referenceDelta(reference, reopened,
                        reopenOffsetMs, metadata, cameraRotation);
                contentMatched &= reopenContentDelta <= CONTENT_DELTA_LIMIT;
                maximumContentDelta =
                        Math.max(maximumContentDelta, reopenContentDelta);
                double reopenPairDelta =
                        CameraSupport.meanDelta(firstFrame.sample, reopened.sample);
                boolean faithfulReopen =
                        reopenPairDelta <= FAITHFUL_PAIR_DELTA_LIMIT;
                boolean naturalizedReopen = firstFrame.fingerprint != reopened.fingerprint
                        && reopenPairDelta > 0.0
                        && reopenPairDelta <= NATURALIZED_PAIR_DELTA_LIMIT;
                boolean reopenMatched = "faithful".equals(expectedMode)
                        ? faithfulReopen : naturalizedReopen;

                JSONObject result = new JSONObject();
                result.put("cameraId", id);
                result.put("advancing", advancing);
                result.put("loopObserved", postLoopAdvancing && modeMatched);
                result.put("postLoopAdvancing", postLoopAdvancing);
                result.put("timestampsMonotonic", monotonic);
                result.put("continuedThroughWindow", continued.bytes > 0);
                result.put("contentMatched", contentMatched);
                result.put("modeMatched", modeMatched);
                result.put("reopenMatched", reopenMatched);
                result.put("correspondingPairCount", early.length);
                result.put("exactPairCount", exactPairs);
                result.put("varyingPairCount", varyingPairs);
                result.put("maximumContentDelta", maximumContentDelta);
                result.put("maximumCorrespondingDelta", maximumPairDelta);
                result.put("minimumCorrespondingDelta", minimumPairDelta);
                result.put("reopenDelta", reopenPairDelta);
                result.put("windowSeconds", windowMs / 1000L);
                return result;
            } finally {
                session.close();
            }
        } finally {
            device.close();
        }
    }

    private CameraSupport.Frame captureReopened(CameraManager manager, String id,
            Integer sensorOrientation) throws Exception {
        CameraDevice device = CameraSupport.open(manager, id, handler);
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                320, 240, ImageFormat.YUV_420_888, 4, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder builder =
                        recordRequest(device, reader, sensorOrientation);
                captureFrame(session, builder, reader);
                return captureFrame(session, builder, reader);
            } finally {
                session.close();
            }
        } finally {
            device.close();
        }
    }

    private void waitForAvailable(CameraManager manager, String id) throws Exception {
        CountDownLatch available = new CountDownLatch(1);
        CameraManager.AvailabilityCallback callback =
                new CameraManager.AvailabilityCallback() {
                    @Override public void onCameraAvailable(String availableId) {
                        if (id.equals(availableId)) available.countDown();
                    }
                };
        manager.registerAvailabilityCallback(callback, handler);
        try {
            if (!available.await(5L, TimeUnit.SECONDS)) {
                throw new IllegalStateException("camera reopen timed out");
            }
        } finally {
            manager.unregisterAvailabilityCallback(callback);
        }
    }

    private static CaptureRequest.Builder recordRequest(CameraDevice device,
            CameraSupport.FrameReader reader, Integer sensorOrientation) throws Exception {
        CaptureRequest.Builder builder =
                device.createCaptureRequest(CameraDevice.TEMPLATE_RECORD);
        builder.addTarget(reader.surface());
        if (sensorOrientation != null) {
            builder.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
        }
        return builder;
    }

    private CameraSupport.Frame captureFrame(CameraCaptureSession session,
            CaptureRequest.Builder builder, CameraSupport.FrameReader reader) throws Exception {
        long timestamp = CameraSupport.capture(session, builder.build(), handler);
        CameraSupport.Frame frame = reader.take();
        if (frame.bytes <= 0 || frame.timestamp != timestamp
                || frame.sample.length != CameraSupport.SAMPLE_BYTES) {
            throw new IllegalStateException("invalid video frame");
        }
        return frame;
    }

    private static ReferenceMetadata inspectReference(String path,
            MediaMetadataRetriever retriever) throws Exception {
        long retrieverDurationMs = parseLongMetadata(
                retriever, MediaMetadataRetriever.METADATA_KEY_DURATION);
        int retrieverWidth = (int) parseLongMetadata(
                retriever, MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH);
        int retrieverHeight = (int) parseLongMetadata(
                retriever, MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT);
        String rotationValue = retriever.extractMetadata(
                MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION);
        int retrieverRotation = rotationValue == null ? 0
                : normalizeRotation(Integer.parseInt(rotationValue));
        String sourceMime =
                retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_MIMETYPE);
        if (retrieverDurationMs < 500L || retrieverWidth <= 0 || retrieverHeight <= 0
                || sourceMime == null || !sourceMime.startsWith("video/")) {
            throw new IllegalArgumentException("invalid reference metadata");
        }

        MediaExtractor extractor = new MediaExtractor();
        try {
            extractor.setDataSource(path);
            for (int index = 0; index < extractor.getTrackCount(); ++index) {
                MediaFormat format = extractor.getTrackFormat(index);
                String mime = format.getString(MediaFormat.KEY_MIME);
                if (mime == null || !mime.startsWith("video/")) continue;
                int width = format.getInteger(MediaFormat.KEY_WIDTH);
                int height = format.getInteger(MediaFormat.KEY_HEIGHT);
                long durationUs = format.getLong(MediaFormat.KEY_DURATION);
                long durationMs = Math.max(1L, (durationUs + 999L) / 1000L);
                int rotation = format.containsKey(MediaFormat.KEY_ROTATION)
                        ? normalizeRotation(format.getInteger(MediaFormat.KEY_ROTATION)) : 0;
                long durationToleranceMs = Math.max(250L, durationMs / 100L);
                if (width != retrieverWidth || height != retrieverHeight
                        || rotation != retrieverRotation
                        || Math.abs(durationMs - retrieverDurationMs) > durationToleranceMs) {
                    throw new IllegalArgumentException("inconsistent reference metadata");
                }
                return new ReferenceMetadata(
                        durationMs, width, height, rotation, mime);
            }
            throw new IllegalArgumentException("reference video track missing");
        } finally {
            extractor.release();
        }
    }

    private static long parseLongMetadata(
            MediaMetadataRetriever retriever, int key) {
        String value = retriever.extractMetadata(key);
        if (value == null) throw new IllegalArgumentException("reference metadata missing");
        return Long.parseLong(value);
    }

    private static int normalizeRotation(int value) {
        int rotation = ((value % 360) + 360) % 360;
        if (rotation % 90 != 0) {
            throw new IllegalArgumentException("invalid reference rotation");
        }
        return rotation;
    }

    private static long referenceOffset(MediaMetadataRetriever retriever,
            CameraSupport.Frame frame, ReferenceMetadata metadata, int cameraRotation) {
        long bestOffsetMs = 0L;
        double best = Double.POSITIVE_INFINITY;
        long limitMs = Math.min(400L, metadata.durationMs - 1L);
        for (long candidateMs = 0L; candidateMs <= limitMs; candidateMs += 40L) {
            double delta = referenceFrameDelta(
                    retriever, frame, candidateMs, metadata, cameraRotation);
            if (delta < best) {
                best = delta;
                bestOffsetMs = candidateMs;
            }
        }
        return bestOffsetMs;
    }

    private static double referenceDelta(MediaMetadataRetriever retriever,
            CameraSupport.Frame frame, long offsetMs, ReferenceMetadata metadata,
            int cameraRotation) {
        double best = Double.POSITIVE_INFINITY;
        for (long adjustmentMs = -60L; adjustmentMs <= 60L; adjustmentMs += 30L) {
            long candidateMs = (offsetMs + adjustmentMs) % metadata.durationMs;
            if (candidateMs < 0L) candidateMs += metadata.durationMs;
            best = Math.min(best, referenceFrameDelta(
                    retriever, frame, candidateMs, metadata, cameraRotation));
        }
        return best;
    }

    private static double referenceFrameDelta(MediaMetadataRetriever retriever,
            CameraSupport.Frame frame, long candidateMs, ReferenceMetadata metadata,
            int cameraRotation) {
        Bitmap bitmap = retriever.getFrameAtTime(candidateMs * 1000L,
                MediaMetadataRetriever.OPTION_CLOSEST);
        if (bitmap == null) return Double.POSITIVE_INFINITY;
        try {
            int rotation = referenceBitmapRotation(
                    metadata, bitmap, cameraRotation);
            byte[] sample = CameraSupport.transformedBitmapSample(
                    bitmap, 320, 240, rotation);
            return CameraSupport.meanDelta(frame.sample, sample);
        } finally {
            bitmap.recycle();
        }
    }

    private static int referenceBitmapRotation(ReferenceMetadata metadata,
            Bitmap bitmap, int cameraRotation) {
        boolean swapsAxes = metadata.rotation == 90 || metadata.rotation == 270;
        boolean retrieverAppliedRotation = swapsAxes
                && bitmap.getWidth() == metadata.height
                && bitmap.getHeight() == metadata.width;
        return normalizeRotation(cameraRotation
                + (retrieverAppliedRotation ? 0 : metadata.rotation));
    }

    private static void sleepUntil(long deadlineMs) throws InterruptedException {
        long remaining = deadlineMs - SystemClock.elapsedRealtime();
        if (remaining > 0L) Thread.sleep(remaining);
    }

    private static final class ReferenceMetadata {
        final long durationMs;
        final int width;
        final int height;
        final int rotation;
        final String trackMime;

        ReferenceMetadata(long durationMs, int width, int height,
                int rotation, String trackMime) {
            this.durationMs = durationMs;
            this.width = width;
            this.height = height;
            this.rotation = rotation;
            this.trackMime = trackMime;
        }
    }
}
