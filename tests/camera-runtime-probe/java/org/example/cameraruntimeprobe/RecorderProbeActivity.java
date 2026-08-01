package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.ImageFormat;
import android.hardware.HardwareBuffer;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.media.Image;
import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.media.MediaMetadataRetriever;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.view.Surface;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class RecorderProbeActivity extends Activity {
    private static final int WIDTH = 320;
    private static final int HEIGHT = 240;
    private static final double CONTENT_DELTA_LIMIT = 32.0;
    private HandlerThread callbacks;
    private Handler handler;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        callbacks = new HandlerThread("recorder-probe-callbacks");
        callbacks.start();
        handler = new Handler(callbacks.getLooper());
        new Thread(this::runProbe, "recorder-runtime-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            String referencePath = getIntent().getStringExtra("referenceVideo");
            long expectedDurationMs = getIntent().getLongExtra("durationMs", 0L);
            long requestedRecordMs = getIntent().getLongExtra("recordMs", 0L);
            ReferenceVideo reference = null;
            long recordMs = 1500L;
            if (referencePath != null) {
                if (expectedDurationMs < 2000L || requestedRecordMs <= expectedDurationMs
                        || requestedRecordMs > 180000L) {
                    throw new IllegalArgumentException("invalid configured-video window");
                }
                reference = new ReferenceVideo(referencePath, expectedDurationMs);
                recordMs = requestedRecordMs;
                if (recordMs < reference.durationMs + reference.advanceMs + 250L) {
                    throw new IllegalArgumentException("record window does not cross EOF");
                }
            } else if (expectedDurationMs != 0L || requestedRecordMs != 0L) {
                throw new IllegalArgumentException("reference video is required for EOF coverage");
            }

            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            for (String id : new String[] {"0", "1"}) {
                JSONObject camera = record(id, reference, recordMs);
                cameras.put(camera);
                allOk &= camera.getBoolean("ok");
            }
            report.put("probe", "media-recorder-codec");
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("media-recorder-codec", error);
        }
        ProbeIo.write(this, "recorder.json", report);
        runOnUiThread(() -> {
            callbacks.quitSafely();
            finish();
        });
    }

    private JSONObject record(String id, ReferenceVideo reference, long recordMs) throws Exception {
        File output = new File(getExternalFilesDir(null), "recording-" + id + ".mp4");
        if (output.exists() && !output.delete()) {
            throw new IllegalStateException("prior recording unavailable");
        }
        MediaRecorder recorder = new MediaRecorder();
        CameraDevice device = null;
        CameraCaptureSession session = null;
        boolean started = false;
        AtomicInteger privateFrames = new AtomicInteger();
        AtomicLong firstPrivateTimestamp = new AtomicLong(-1L);
        AtomicLong lastPrivateTimestamp = new AtomicLong(-1L);
        AtomicBoolean privateMonotonic = new AtomicBoolean(true);
        AtomicBoolean privateFailure = new AtomicBoolean(false);
        AtomicInteger captureResults = new AtomicInteger();
        try (CameraSupport.FrameReader preview = new CameraSupport.FrameReader(
                WIDTH, HEIGHT, ImageFormat.PRIVATE, 8, handler)) {
            preview.reader.setOnImageAvailableListener(reader -> {
                try (Image image = reader.acquireNextImage()) {
                    if (image == null || image.getTimestamp() <= 0L) {
                        privateFailure.set(true);
                        return;
                    }
                    HardwareBuffer buffer = image.getHardwareBuffer();
                    if (buffer == null) {
                        privateFailure.set(true);
                        return;
                    }
                    try {
                        if (buffer.getWidth() != WIDTH || buffer.getHeight() != HEIGHT
                                || buffer.getLayers() < 1) {
                            privateFailure.set(true);
                            return;
                        }
                    } finally {
                        buffer.close();
                    }
                    long timestamp = image.getTimestamp();
                    long prior = lastPrivateTimestamp.getAndSet(timestamp);
                    if (prior >= timestamp) privateMonotonic.set(false);
                    firstPrivateTimestamp.compareAndSet(-1L, timestamp);
                    privateFrames.incrementAndGet();
                } catch (Throwable ignored) {
                    privateFailure.set(true);
                }
            }, handler);

            recorder.setVideoSource(MediaRecorder.VideoSource.SURFACE);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            recorder.setVideoEncoder(MediaRecorder.VideoEncoder.H264);
            recorder.setVideoSize(WIDTH, HEIGHT);
            recorder.setVideoFrameRate(30);
            recorder.setVideoEncodingBitRate(1_000_000);
            recorder.setOutputFile(output.getAbsolutePath());
            recorder.prepare();
            Surface recorderSurface = recorder.getSurface();

            CameraManager manager = getSystemService(CameraManager.class);
            device = CameraSupport.open(manager, id, handler);
            session = CameraSupport.configure(device,
                    Arrays.asList(preview.surface(), recorderSurface), handler);
            CaptureRequest.Builder request = device.createCaptureRequest(CameraDevice.TEMPLATE_RECORD);
            request.addTarget(preview.surface());
            request.addTarget(recorderSurface);
            CountDownLatch captureStarted = new CountDownLatch(4);
            session.setRepeatingRequest(request.build(), new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureCompleted(CameraCaptureSession value,
                        CaptureRequest captureRequest,
                        android.hardware.camera2.TotalCaptureResult result) {
                    captureResults.incrementAndGet();
                    captureStarted.countDown();
                }
            }, handler);
            recorder.start();
            started = true;
            if (!captureStarted.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("record capture timeout");
            }
            Thread.sleep(recordMs);
            session.stopRepeating();
            recorder.stop();
            started = false;
            session.abortCaptures();

            int minimumPrivateFrames = reference == null ? 4
                    : (int) Math.max(4L, recordMs / 250L);
            boolean privateProgressed = !privateFailure.get() && privateMonotonic.get()
                    && privateFrames.get() >= minimumPrivateFrames
                    && firstPrivateTimestamp.get() > 0L
                    && lastPrivateTimestamp.get() > firstPrivateTimestamp.get();
            if (!output.isFile() || output.length() <= 0L || !privateProgressed) {
                throw new IllegalStateException("recording outputs unavailable");
            }

            long[] targetOffsetsMs;
            if (reference == null) {
                targetOffsetsMs = new long[] {0L};
            } else {
                targetOffsetsMs = new long[] {
                        reference.startMs,
                        reference.advanceMs,
                        reference.durationMs + reference.startMs,
                        reference.durationMs + reference.advanceMs
                };
            }
            DecodedVideo decoded = decodeRecorded(output, targetOffsetsMs);
            int minimumEncoderFrames = reference == null ? targetOffsetsMs.length
                    : (int) Math.max(4L,
                            (reference.durationMs + reference.advanceMs) / 200L);
            boolean encoderProgressed = decoded.samples.length == targetOffsetsMs.length
                    && decoded.outputFrames >= minimumEncoderFrames
                    && decoded.timestampsMonotonic;
            boolean contentMatched = true;
            boolean loopMatched = true;
            double maximumContentDelta = 0.0;
            if (reference != null) {
                Integer sensorOrientation = manager.getCameraCharacteristics(id).get(
                        CameraCharacteristics.SENSOR_ORIENTATION);
                int referenceRotation = sensorOrientation == null
                        ? 0 : (360 - sensorOrientation) % 360;
                long referenceOffsetMs = reference.alignmentOffset(
                        decoded.samples[0].sample, reference.startMs, referenceRotation);
                byte[] sourceStart = reference.sample(
                        reference.normalize(reference.startMs + referenceOffsetMs),
                        referenceRotation);
                byte[] sourceAdvance = reference.sample(
                        reference.normalize(reference.advanceMs + referenceOffsetMs),
                        referenceRotation);
                double sourceAdvanceDelta = CameraSupport.meanDelta(sourceStart, sourceAdvance);
                double firstDelta = CameraSupport.meanDelta(decoded.samples[0].sample, sourceStart);
                double advanceDelta = CameraSupport.meanDelta(decoded.samples[1].sample, sourceAdvance);
                double wrapDelta = CameraSupport.meanDelta(decoded.samples[2].sample, sourceStart);
                double postWrapAdvanceDelta =
                        CameraSupport.meanDelta(decoded.samples[3].sample, sourceAdvance);
                maximumContentDelta = Math.max(Math.max(firstDelta, advanceDelta),
                        Math.max(wrapDelta, postWrapAdvanceDelta));
                contentMatched = sourceAdvanceDelta >= 8.0
                        && maximumContentDelta <= CONTENT_DELTA_LIMIT;
                loopMatched = wrapDelta <= CONTENT_DELTA_LIMIT
                        && postWrapAdvanceDelta <= CONTENT_DELTA_LIMIT
                        && CameraSupport.meanDelta(
                                decoded.samples[0].sample, decoded.samples[1].sample) >= 4.0
                        && CameraSupport.meanDelta(
                                decoded.samples[2].sample, decoded.samples[3].sample) >= 4.0;
            }
            boolean notTruncated = reference == null
                    || (decoded.durationMs >= recordMs - 1500L
                            && decoded.actualOffsetsMs[decoded.actualOffsetsMs.length - 1]
                                    >= reference.durationMs + reference.advanceMs - 250L);
            JSONObject result = new JSONObject();
            result.put("id", id);
            result.put("privatePreview", privateProgressed);
            result.put("privateFrames", privateFrames.get());
            result.put("privateProgressed", privateProgressed);
            result.put("captureResults", captureResults.get());
            result.put("recordingNonempty", output.length() > 0L);
            result.put("videoTrack", decoded.videoTrack);
            result.put("codecFrames", decoded.outputFrames);
            result.put("encoderProgressed", encoderProgressed);
            result.put("contentMatched", contentMatched);
            result.put("maximumContentDelta", maximumContentDelta);
            result.put("loopMatched", loopMatched);
            result.put("notTruncated", notTruncated);
            result.put("ok", privateProgressed && result.getBoolean("recordingNonempty")
                    && decoded.videoTrack && encoderProgressed && contentMatched
                    && loopMatched && notTruncated);
            return result;
        } finally {
            if (started) {
                try { recorder.stop(); } catch (Throwable ignored) {}
            }
            if (session != null) session.close();
            if (device != null) device.close();
            recorder.release();
            output.delete();
        }
    }

    private DecodedVideo decodeRecorded(File input, long[] targetOffsetsMs) throws Exception {
        MediaExtractor extractor = new MediaExtractor();
        MediaCodec codec = null;
        try (CameraSupport.FrameReader output = new CameraSupport.FrameReader(
                WIDTH, HEIGHT, ImageFormat.YUV_420_888, 8, handler)) {
            extractor.setDataSource(input.getAbsolutePath());
            int track = -1;
            MediaFormat format = null;
            for (int index = 0; index < extractor.getTrackCount(); ++index) {
                MediaFormat candidate = extractor.getTrackFormat(index);
                String candidateMime = candidate.getString(MediaFormat.KEY_MIME);
                if (candidateMime != null && candidateMime.startsWith("video/")) {
                    track = index;
                    format = candidate;
                    break;
                }
            }
            if (track < 0 || format == null) throw new IllegalStateException("video track missing");
            extractor.selectTrack(track);
            long firstPtsUs = extractor.getSampleTime();
            if (firstPtsUs < 0L) throw new IllegalStateException("video samples missing");
            long durationUs = format.containsKey(MediaFormat.KEY_DURATION)
                    ? format.getLong(MediaFormat.KEY_DURATION) : 0L;
            String mime = format.getString(MediaFormat.KEY_MIME);
            if (mime == null) throw new IllegalStateException("video mime missing");
            codec = MediaCodec.createDecoderByType(mime);
            codec.configure(format, output.surface(), null, 0);
            codec.start();

            CameraSupport.Frame[] samples = new CameraSupport.Frame[targetOffsetsMs.length];
            long[] actualOffsetsMs = new long[targetOffsetsMs.length];
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            boolean inputEnded = false;
            boolean outputEnded = false;
            boolean timestampsMonotonic = true;
            long priorPtsUs = -1L;
            int nextTarget = 0;
            int outputFrames = 0;
            long decodeBudgetMs = Math.max(30000L,
                    Math.min(120000L, durationUs > 0L ? durationUs / 1000L * 2L : 30000L));
            long deadline = SystemClock.elapsedRealtime() + decodeBudgetMs;
            while (SystemClock.elapsedRealtime() < deadline && !outputEnded
                    && nextTarget < targetOffsetsMs.length) {
                if (!inputEnded) {
                    int inputIndex = codec.dequeueInputBuffer(10000L);
                    if (inputIndex >= 0) {
                        ByteBuffer buffer = codec.getInputBuffer(inputIndex);
                        if (buffer == null) throw new IllegalStateException("codec buffer missing");
                        int size = extractor.readSampleData(buffer, 0);
                        if (size < 0) {
                            codec.queueInputBuffer(inputIndex, 0, 0, 0L,
                                    MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                            inputEnded = true;
                        } else {
                            codec.queueInputBuffer(inputIndex, 0, size,
                                    extractor.getSampleTime(), extractor.getSampleFlags());
                            extractor.advance();
                        }
                    }
                }
                int outputIndex = codec.dequeueOutputBuffer(info, 10000L);
                if (outputIndex >= 0) {
                    boolean frame = info.size > 0;
                    boolean render = false;
                    if (frame) {
                        timestampsMonotonic &= priorPtsUs < 0L || info.presentationTimeUs > priorPtsUs;
                        priorPtsUs = info.presentationTimeUs;
                        ++outputFrames;
                        long targetUs = firstPtsUs + targetOffsetsMs[nextTarget] * 1000L;
                        render = info.presentationTimeUs >= targetUs;
                    }
                    if (render) output.clear();
                    codec.releaseOutputBuffer(outputIndex, render);
                    if (render) {
                        CameraSupport.Frame decoded = output.take();
                        if (decoded.bytes <= 0 || decoded.sample.length != 16 * 12 * 3) {
                            throw new IllegalStateException("decoded frame unavailable");
                        }
                        samples[nextTarget] = decoded;
                        actualOffsetsMs[nextTarget] =
                                Math.max(0L, (info.presentationTimeUs - firstPtsUs) / 1000L);
                        ++nextTarget;
                    }
                    outputEnded = (info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
                }
            }
            if (nextTarget != targetOffsetsMs.length) {
                throw new IllegalStateException("recorded video ended before target frames");
            }
            return new DecodedVideo(true, Math.max(0L, durationUs / 1000L), outputFrames,
                    timestampsMonotonic, samples, actualOffsetsMs);
        } finally {
            if (codec != null) {
                try { codec.stop(); } catch (Throwable ignored) {}
                codec.release();
            }
            extractor.release();
        }
    }

    private static final class DecodedVideo {
        final boolean videoTrack;
        final long durationMs;
        final int outputFrames;
        final boolean timestampsMonotonic;
        final CameraSupport.Frame[] samples;
        final long[] actualOffsetsMs;

        DecodedVideo(boolean videoTrack, long durationMs, int outputFrames,
                boolean timestampsMonotonic, CameraSupport.Frame[] samples,
                long[] actualOffsetsMs) {
            this.videoTrack = videoTrack;
            this.durationMs = durationMs;
            this.outputFrames = outputFrames;
            this.timestampsMonotonic = timestampsMonotonic;
            this.samples = samples;
            this.actualOffsetsMs = actualOffsetsMs;
        }
    }

    private static final class ReferenceVideo {
        final String path;
        final long durationMs;
        final long startMs;
        final long advanceMs;

        ReferenceVideo(String path, long expectedDurationMs) throws Exception {
            File file = new File(path);
            if (!file.isFile() || file.length() <= 0L) {
                throw new IllegalArgumentException("reference video unavailable");
            }
            MediaMetadataRetriever retriever = new MediaMetadataRetriever();
            long decodedDurationMs;
            try {
                retriever.setDataSource(path);
                String duration = retriever.extractMetadata(
                        MediaMetadataRetriever.METADATA_KEY_DURATION);
                decodedDurationMs = duration == null ? 0L : Long.parseLong(duration);
            } finally {
                retriever.release();
            }
            long toleranceMs = Math.max(250L, expectedDurationMs / 100L);
            if (decodedDurationMs < 2000L
                    || Math.abs(decodedDurationMs - expectedDurationMs) > toleranceMs) {
                throw new IllegalArgumentException("reference video duration mismatch");
            }
            this.path = path;
            durationMs = decodedDurationMs;
            startMs = Math.min(300L, durationMs / 8L);
            advanceMs = Math.min(1500L, durationMs - 300L);
            if (advanceMs <= startMs + 250L) {
                throw new IllegalArgumentException("reference video window too short");
            }
        }

        long normalize(long timestampMs) {
            long normalized = timestampMs % durationMs;
            return normalized < 0L ? normalized + durationMs : normalized;
        }

        long alignmentOffset(byte[] observed, long timestampMs, int rotationDegrees)
                throws Exception {
            MediaMetadataRetriever retriever = new MediaMetadataRetriever();
            try {
                retriever.setDataSource(path);
                long bestAdjustmentMs = 0L;
                double bestDelta = Double.POSITIVE_INFINITY;
                for (long adjustmentMs = -300L; adjustmentMs <= 300L;
                        adjustmentMs += 50L) {
                    Bitmap bitmap = retriever.getFrameAtTime(
                            normalize(timestampMs + adjustmentMs) * 1000L,
                            MediaMetadataRetriever.OPTION_CLOSEST);
                    if (bitmap == null) continue;
                    try {
                        byte[] candidate = CameraSupport.transformedBitmapSample(
                                bitmap, WIDTH, HEIGHT, rotationDegrees);
                        double delta = CameraSupport.meanDelta(observed, candidate);
                        if (delta < bestDelta) {
                            bestDelta = delta;
                            bestAdjustmentMs = adjustmentMs;
                        }
                    } finally {
                        bitmap.recycle();
                    }
                }
                if (!Double.isFinite(bestDelta)) {
                    throw new IllegalStateException("reference alignment unavailable");
                }
                return bestAdjustmentMs;
            } finally {
                retriever.release();
            }
        }

        byte[] sample(long timestampMs, int rotationDegrees) throws Exception {
            MediaMetadataRetriever retriever = new MediaMetadataRetriever();
            try {
                retriever.setDataSource(path);
                Bitmap bitmap = retriever.getFrameAtTime(timestampMs * 1000L,
                        MediaMetadataRetriever.OPTION_CLOSEST);
                if (bitmap == null) throw new IllegalStateException("reference frame unavailable");
                try {
                    return CameraSupport.transformedBitmapSample(
                            bitmap, WIDTH, HEIGHT, rotationDegrees);
                } finally {
                    bitmap.recycle();
                }
            } finally {
                retriever.release();
            }
        }
    }
}
