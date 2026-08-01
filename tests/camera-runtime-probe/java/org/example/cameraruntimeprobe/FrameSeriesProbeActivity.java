package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class FrameSeriesProbeActivity extends Activity {
    private static final double CONTENT_DELTA_LIMIT = 28.0;
    private static final double ORIENTATION_MARGIN = 4.0;
    private HandlerThread callbacks;
    private Handler handler;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        callbacks = new HandlerThread("frame-series-callbacks");
        callbacks.start();
        handler = new Handler(callbacks.getLooper());
        new Thread(this::runProbe, "frame-series-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            int count = Math.max(2, Math.min(20, getIntent().getIntExtra("count", 4)));
            int delayMs = Math.max(0, Math.min(5000, getIntent().getIntExtra("delayMs", 100)));
            String formatName = getIntent().getStringExtra("format");
            String expectation = getIntent().getStringExtra("expect");
            boolean jpeg = "jpeg".equals(formatName);
            boolean record = getIntent().getBooleanExtra("record", false);
            String referencePhoto = getIntent().getStringExtra("referencePhoto");
            if (expectation == null) expectation = "fallback";
            if (!expectation.equals("fallback") && !expectation.equals("stable")
                    && !expectation.equals("vary")) {
                throw new IllegalArgumentException("invalid expectation");
            }
            if ("vary".equals(expectation)
                    && (referencePhoto == null || referencePhoto.isEmpty())) {
                throw new IllegalArgumentException("vary requires a reference photo");
            }
            report.put("probe", "frame-series");
            report.put("expectation", expectation);
            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            CameraManager manager = getSystemService(CameraManager.class);
            for (String id : new String[] {"0", "1"}) {
                JSONObject camera = capture(manager, id, jpeg, record, count, delayMs,
                        expectation, referencePhoto);
                cameras.put(camera);
                allOk &= camera.getBoolean("ok");
            }
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("frame-series", error);
        }
        ProbeIo.write(this, "frames.json", report);
        runOnUiThread(() -> {
            callbacks.quitSafely();
            finish();
        });
    }

    private JSONObject capture(CameraManager manager, String id, boolean jpeg, boolean record,
            int count, int delayMs, String expectation, String referencePhoto) throws Exception {
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        Integer sensorOrientation =
                characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION);
        int referenceRotation = sensorOrientation == null
                ? 0 : (360 - sensorOrientation) % 360;
        byte[] reference = referencePhoto == null || referencePhoto.isEmpty() ? null
                : CameraSupport.referencePhotoSample(
                        referencePhoto, 320, 240, referenceRotation);
        byte[][] alternatives = reference == null ? new byte[0][]
                : referenceAlternatives(referencePhoto, referenceRotation);

        CaptureBatch initial = captureBatch(
                manager, id, jpeg, record, count, delayMs, sensorOrientation);
        CaptureBatch reopened = null;
        if ("stable".equals(expectation) || "vary".equals(expectation)) {
            int reopenCount = "vary".equals(expectation)
                    ? Math.max(2, Math.min(count, 4)) : 1;
            waitForAvailable(manager, id);
            reopened = captureBatch(
                    manager, id, jpeg, record, reopenCount, delayMs, sensorOrientation);
        }
        int totalFrames = initial.frames.length
                + (reopened == null ? 0 : reopened.frames.length);
        CameraSupport.Frame[] frames = new CameraSupport.Frame[totalFrames];
        System.arraycopy(initial.frames, 0, frames, 0, initial.frames.length);
        if (reopened != null) {
            System.arraycopy(reopened.frames, 0, frames, initial.frames.length,
                    reopened.frames.length);
        }

        Set<Long> fingerprints = new HashSet<>();
        boolean adjacentDifferent = true;
        boolean exactStable = true;
        boolean contentMatched = true;
        boolean orientationMatched = true;
        boolean fallbackMatched = true;
        double maximumContentDelta = 0.0;
        double minimumReferenceDelta = Double.POSITIVE_INFINITY;
        double minimumAlternativeDelta = Double.POSITIVE_INFINITY;
        double minimumOrientationMargin = Double.POSITIVE_INFINITY;
        double maximumFallbackMean = 0.0;
        double minimumFallbackDeviation = Double.POSITIVE_INFINITY;
        double minimumFallbackChroma = Double.POSITIVE_INFINITY;
        double maximumFallbackChroma = 0.0;
        CameraSupport.Frame previous = null;
        CameraSupport.Frame anchor = frames[0];
        for (CameraSupport.Frame frame : frames) {
            fingerprints.add(frame.fingerprint);
            if (previous != null) {
                adjacentDifferent &= frame.fingerprint != previous.fingerprint;
            }
            exactStable &= frame.fingerprint == anchor.fingerprint
                    && Arrays.equals(frame.sample, anchor.sample);
            previous = frame;

            SampleStats stats = sampleStats(frame.sample);
            fallbackMatched &= stats.fallbackLike;
            maximumFallbackMean = Math.max(maximumFallbackMean, stats.meanLuma);
            minimumFallbackDeviation =
                    Math.min(minimumFallbackDeviation, stats.lumaDeviation);
            minimumFallbackChroma = Math.min(minimumFallbackChroma, stats.meanChroma);
            maximumFallbackChroma = Math.max(maximumFallbackChroma, stats.meanChroma);

            if (reference != null) {
                double delta = CameraSupport.meanDelta(frame.sample, reference);
                maximumContentDelta = Math.max(maximumContentDelta, delta);
                minimumReferenceDelta = Math.min(minimumReferenceDelta, delta);
                if (!"fallback".equals(expectation)) {
                    contentMatched &= delta <= CONTENT_DELTA_LIMIT;
                    double alternativeDelta = Double.POSITIVE_INFINITY;
                    for (byte[] alternative : alternatives) {
                        alternativeDelta = Math.min(alternativeDelta,
                                CameraSupport.meanDelta(frame.sample, alternative));
                    }
                    minimumAlternativeDelta =
                            Math.min(minimumAlternativeDelta, alternativeDelta);
                    minimumOrientationMargin =
                            Math.min(minimumOrientationMargin, alternativeDelta - delta);
                    orientationMatched &= delta + ORIENTATION_MARGIN <= alternativeDelta;
                }
            }
        }

        boolean sessionSeedChanged = reopened == null
                || initial.frames[0].fingerprint != reopened.frames[0].fingerprint;
        boolean referenceDifferent = reference == null
                || minimumReferenceDelta >= CONTENT_DELTA_LIMIT;
        boolean expected;
        if ("fallback".equals(expectation)) {
            expected = fallbackMatched && adjacentDifferent && referenceDifferent;
        } else if ("stable".equals(expectation)) {
            expected = exactStable;
        } else {
            expected = adjacentDifferent && sessionSeedChanged;
        }

        boolean monotonic = initial.timestampsMonotonic
                && (reopened == null || reopened.timestampsMonotonic);
        boolean valid = initial.valid && (reopened == null || reopened.valid);
        JSONObject result = new JSONObject();
        result.put("id", id);
        result.put("frames", totalFrames);
        result.put("distinctFrames", fingerprints.size());
        result.put("stable", exactStable);
        result.put("adjacentFramesDifferent", adjacentDifferent);
        result.put("sessionSeedChanged", sessionSeedChanged);
        result.put("timestampsMonotonic", monotonic);
        result.put("contentMatched", contentMatched);
        result.put("orientationMatched", orientationMatched);
        result.put("referenceDifferent", referenceDifferent);
        result.put("fallbackMatched", fallbackMatched);
        result.put("maximumContentDelta", maximumContentDelta);
        result.put("minimumAlternativeDelta",
                Double.isInfinite(minimumAlternativeDelta) ? 0.0 : minimumAlternativeDelta);
        result.put("minimumOrientationMargin",
                Double.isInfinite(minimumOrientationMargin) ? 0.0 : minimumOrientationMargin);
        result.put("maximumFallbackMean", maximumFallbackMean);
        result.put("minimumFallbackDeviation", minimumFallbackDeviation);
        result.put("minimumFallbackChroma", minimumFallbackChroma);
        result.put("maximumFallbackChroma", maximumFallbackChroma);
        result.put("ok", valid && monotonic && expected && contentMatched
                && orientationMatched);
        return result;
    }

    private CaptureBatch captureBatch(CameraManager manager, String id, boolean jpeg,
            boolean record, int count, int delayMs, Integer sensorOrientation) throws Exception {
        CameraDevice device = CameraSupport.open(manager, id, handler);
        int format = jpeg ? ImageFormat.JPEG : ImageFormat.YUV_420_888;
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                320, 240, format, 4, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder builder = device.createCaptureRequest(record
                        ? CameraDevice.TEMPLATE_RECORD : CameraDevice.TEMPLATE_STILL_CAPTURE);
                if (sensorOrientation != null) {
                    builder.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
                }
                builder.addTarget(reader.surface());
                CameraSupport.Frame[] frames = new CameraSupport.Frame[count];
                long priorTimestamp = -1L;
                boolean monotonic = true;
                boolean valid = true;
                for (int index = 0; index < count; ++index) {
                    long resultTimestamp =
                            CameraSupport.capture(session, builder.build(), handler);
                    CameraSupport.Frame frame = reader.take();
                    frames[index] = frame;
                    valid &= frame.bytes > 0 && frame.jpegValid && frame.jpegExifValid
                            && frame.sample.length == CameraSupport.SAMPLE_BYTES
                            && frame.timestamp == resultTimestamp;
                    monotonic &= priorTimestamp < 0 || resultTimestamp > priorTimestamp;
                    priorTimestamp = resultTimestamp;
                    if (delayMs > 0 && index + 1 < count) Thread.sleep(delayMs);
                }
                return new CaptureBatch(frames, valid, monotonic);
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

    private static byte[][] referenceAlternatives(
            String path, int expectedRotation) throws Exception {
        byte[][] samples = new byte[7][];
        int index = 0;
        for (int offset : new int[] {90, 180, 270}) {
            samples[index++] = CameraSupport.referencePhotoSample(
                    path, 320, 240, (expectedRotation + offset) % 360, false);
        }
        for (int offset : new int[] {0, 90, 180, 270}) {
            samples[index++] = CameraSupport.referencePhotoSample(
                    path, 320, 240, (expectedRotation + offset) % 360, true);
        }
        return samples;
    }

    private static SampleStats sampleStats(byte[] sample) {
        if (sample.length != CameraSupport.SAMPLE_BYTES) {
            return new SampleStats(0.0, 0.0, 0.0, false);
        }
        int pixels = sample.length / CameraSupport.SAMPLE_CHANNELS;
        double lumaTotal = 0.0;
        double lumaSquaredTotal = 0.0;
        double chromaTotal = 0.0;
        int minimumLuma = 255;
        int maximumLuma = 0;
        for (int offset = 0; offset < sample.length;
                offset += CameraSupport.SAMPLE_CHANNELS) {
            int red = sample[offset] & 0xff;
            int green = sample[offset + 1] & 0xff;
            int blue = sample[offset + 2] & 0xff;
            int luma = (77 * red + 150 * green + 29 * blue + 128) >> 8;
            lumaTotal += luma;
            lumaSquaredTotal += (double) luma * luma;
            minimumLuma = Math.min(minimumLuma, luma);
            maximumLuma = Math.max(maximumLuma, luma);
            int high = Math.max(red, Math.max(green, blue));
            int low = Math.min(red, Math.min(green, blue));
            chromaTotal += high - low;
        }
        double meanLuma = lumaTotal / pixels;
        double variance = Math.max(0.0,
                lumaSquaredTotal / pixels - meanLuma * meanLuma);
        double deviation = Math.sqrt(variance);
        double meanChroma = chromaTotal / pixels;
        boolean fallbackLike = meanLuma >= 3.0 && meanLuma <= 55.0
                && minimumLuma <= 28 && maximumLuma <= 80
                && deviation >= 2.0 && meanChroma >= 0.25 && meanChroma <= 12.0;
        return new SampleStats(meanLuma, deviation, meanChroma, fallbackLike);
    }

    private static final class CaptureBatch {
        final CameraSupport.Frame[] frames;
        final boolean valid;
        final boolean timestampsMonotonic;

        CaptureBatch(CameraSupport.Frame[] frames, boolean valid,
                boolean timestampsMonotonic) {
            this.frames = frames;
            this.valid = valid;
            this.timestampsMonotonic = timestampsMonotonic;
        }
    }

    private static final class SampleStats {
        final double meanLuma;
        final double lumaDeviation;
        final double meanChroma;
        final boolean fallbackLike;

        SampleStats(double meanLuma, double lumaDeviation,
                double meanChroma, boolean fallbackLike) {
            this.meanLuma = meanLuma;
            this.lumaDeviation = lumaDeviation;
            this.meanChroma = meanChroma;
            this.fallbackLike = fallbackLike;
        }
    }
}
