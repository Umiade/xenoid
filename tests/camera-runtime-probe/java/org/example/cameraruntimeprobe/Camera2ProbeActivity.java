package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.util.Size;
import android.util.SizeF;
import android.view.Surface;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class Camera2ProbeActivity extends Activity {
    private HandlerThread callbacks;
    private Handler handler;
    private static final long MIN_FRAME_DURATION_NS = 33_333_333L;

    private static final class CameraContract {
        final int lensFacing;
        final int sensorOrientation;
        final int pixelWidth;
        final int pixelHeight;
        final float physicalWidth;
        final float physicalHeight;
        final float focalLength;
        final float aperture;
        final boolean flashAvailable;
        final int[][] jpegSizes;
        final int[][] nonStallingSizes;
        final long[] jpegStalls;

        CameraContract(int lensFacing, int sensorOrientation,
                int pixelWidth, int pixelHeight,
                float physicalWidth, float physicalHeight,
                float focalLength, float aperture, boolean flashAvailable,
                int[][] jpegSizes, int[][] nonStallingSizes,
                long[] jpegStalls) {
            this.lensFacing = lensFacing;
            this.sensorOrientation = sensorOrientation;
            this.pixelWidth = pixelWidth;
            this.pixelHeight = pixelHeight;
            this.physicalWidth = physicalWidth;
            this.physicalHeight = physicalHeight;
            this.focalLength = focalLength;
            this.aperture = aperture;
            this.flashAvailable = flashAvailable;
            this.jpegSizes = jpegSizes;
            this.nonStallingSizes = nonStallingSizes;
            this.jpegStalls = jpegStalls;
        }
    }

    private static CameraContract contractFor(String id) {
        if ("0".equals(id)) {
            return new CameraContract(
                    CameraCharacteristics.LENS_FACING_BACK, 90,
                    4080, 3072, 9.792f, 7.3728f, 6.81f, 1.85f, true,
                    new int[][] {{4080, 3072}, {3840, 2160}, {1920, 1080},
                            {1280, 720}, {640, 480}, {320, 240}},
                    new int[][] {{1920, 1080}, {1280, 720},
                            {640, 480}, {320, 240}},
                    new long[] {220_000_000L, 180_000_000L, 100_000_000L,
                            70_000_000L, 30_000_000L, 15_000_000L});
        }
        if ("1".equals(id)) {
            return new CameraContract(
                    CameraCharacteristics.LENS_FACING_FRONT, 270,
                    3840, 2880, 4.6848f, 3.5136f, 2.74f, 2.2f, false,
                    new int[][] {{3840, 2880}, {1920, 1080}, {1280, 720},
                            {640, 480}, {320, 240}},
                    new int[][] {{1920, 1080}, {1280, 720},
                            {640, 480}, {320, 240}},
                    new long[] {200_000_000L, 100_000_000L, 70_000_000L,
                            30_000_000L, 15_000_000L});
        }
        throw new IllegalArgumentException("unexpected camera id");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static boolean close(float left, float right) {
        return Math.abs(left - right) <= 0.0001f;
    }

    private static Set<String> sizeSet(Size[] sizes) {
        Set<String> values = new HashSet<>();
        if (sizes != null) {
            for (Size size : sizes) {
                values.add(size.getWidth() + "x" + size.getHeight());
            }
        }
        return values;
    }

    private static Set<String> sizeSet(int[][] sizes) {
        Set<String> values = new HashSet<>();
        for (int[] size : sizes) values.add(size[0] + "x" + size[1]);
        return values;
    }

    private static void validateCharacteristics(
            CameraCharacteristics characteristics, CameraContract contract) {
        Integer facing = characteristics.get(CameraCharacteristics.LENS_FACING);
        Integer orientation = characteristics.get(
                CameraCharacteristics.SENSOR_ORIENTATION);
        Size pixelArray = characteristics.get(
                CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE);
        SizeF physicalSize = characteristics.get(
                CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE);
        Rect activeArray = characteristics.get(
                CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE);
        Rect preCorrectionArray = characteristics.get(
                CameraCharacteristics.SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE);
        float[] focalLengths = characteristics.get(
                CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS);
        float[] apertures = characteristics.get(
                CameraCharacteristics.LENS_INFO_AVAILABLE_APERTURES);
        Boolean flashAvailable = characteristics.get(
                CameraCharacteristics.FLASH_INFO_AVAILABLE);
        int[] oisModes = characteristics.get(
                CameraCharacteristics.LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION);
        int[] stabilizationModes = characteristics.get(
                CameraCharacteristics.CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES);
        int[] capabilities = characteristics.get(
                CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
        Integer hardwareLevel = characteristics.get(
                CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
        Float minimumFocus = characteristics.get(
                CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE);
        Float maximumZoom = characteristics.get(
                CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM);

        require(facing != null && facing == contract.lensFacing,
                "lens facing differs");
        require(orientation != null && orientation == contract.sensorOrientation,
                "sensor orientation differs");
        require(pixelArray != null
                        && pixelArray.getWidth() == contract.pixelWidth
                        && pixelArray.getHeight() == contract.pixelHeight,
                "pixel array differs");
        require(physicalSize != null
                        && close(physicalSize.getWidth(), contract.physicalWidth)
                        && close(physicalSize.getHeight(), contract.physicalHeight),
                "physical sensor size differs");
        Rect expectedArray = new Rect(
                0, 0, contract.pixelWidth, contract.pixelHeight);
        require(expectedArray.equals(activeArray)
                        && expectedArray.equals(preCorrectionArray),
                "active arrays differ");
        require(focalLengths != null && focalLengths.length == 1
                        && close(focalLengths[0], contract.focalLength),
                "focal length differs");
        require(apertures != null && apertures.length == 1
                        && close(apertures[0], contract.aperture),
                "aperture differs");
        require(flashAvailable != null
                        && flashAvailable == contract.flashAvailable,
                "flash availability differs");
        require(oisModes != null && oisModes.length == 1
                        && oisModes[0] == CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE_OFF,
                "OIS modes differ");
        require(stabilizationModes != null && stabilizationModes.length == 1
                        && stabilizationModes[0]
                        == CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE_OFF,
                "video stabilization modes differ");
        require(capabilities != null && capabilities.length == 1
                        && capabilities[0]
                        == CameraCharacteristics
                        .REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE,
                "camera capabilities differ");
        require(hardwareLevel != null
                        && hardwareLevel
                        == CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
                "hardware level differs");
        require(characteristics.getPhysicalCameraIds().isEmpty(),
                "unexpected physical camera ids");
        require(minimumFocus != null && close(minimumFocus, 0.0f),
                "focus distance differs");
        require(maximumZoom != null && close(maximumZoom, 1.0f),
                "digital zoom differs");

        StreamConfigurationMap map = characteristics.get(
                CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
        require(map != null, "stream configuration map missing");
        Set<Integer> formats = new HashSet<>();
        for (int format : map.getOutputFormats()) formats.add(format);
        Set<Integer> expectedFormats = new HashSet<>(Arrays.asList(
                ImageFormat.JPEG, ImageFormat.YUV_420_888, ImageFormat.PRIVATE));
        require(formats.equals(expectedFormats), "output formats differ");
        require(sizeSet(map.getOutputSizes(ImageFormat.JPEG))
                        .equals(sizeSet(contract.jpegSizes)),
                "JPEG sizes differ");
        require(sizeSet(map.getOutputSizes(ImageFormat.YUV_420_888))
                        .equals(sizeSet(contract.nonStallingSizes)),
                "YUV sizes differ");
        require(sizeSet(map.getOutputSizes(ImageFormat.PRIVATE))
                        .equals(sizeSet(contract.nonStallingSizes)),
                "private sizes differ");
        for (int index = 0; index < contract.jpegSizes.length; ++index) {
            Size size = new Size(
                    contract.jpegSizes[index][0], contract.jpegSizes[index][1]);
            require(map.getOutputMinFrameDuration(ImageFormat.JPEG, size)
                            == MIN_FRAME_DURATION_NS,
                    "JPEG minimum frame duration differs");
            require(map.getOutputStallDuration(ImageFormat.JPEG, size)
                            == contract.jpegStalls[index],
                    "JPEG stall duration differs");
        }
        for (int[] dimensions : contract.nonStallingSizes) {
            Size size = new Size(dimensions[0], dimensions[1]);
            for (int format : new int[] {
                    ImageFormat.YUV_420_888, ImageFormat.PRIVATE}) {
                require(map.getOutputMinFrameDuration(format, size)
                                == MIN_FRAME_DURATION_NS,
                        "non-stalling minimum frame duration differs");
                require(map.getOutputStallDuration(format, size) == 0,
                        "non-stalling output has a stall duration");
            }
        }
    }

    private boolean probeTorch(
            CameraManager manager, String id, boolean flashAvailable)
            throws Exception {
        if (!flashAvailable) {
            boolean rejected = false;
            try {
                manager.setTorchMode(id, true);
            } catch (CameraAccessException | IllegalArgumentException expected) {
                rejected = true;
            } finally {
                if (!rejected) manager.setTorchMode(id, false);
            }
            return rejected;
        }

        CountDownLatch enabled = new CountDownLatch(1);
        CountDownLatch disabled = new CountDownLatch(1);
        AtomicInteger phase = new AtomicInteger();
        CameraManager.TorchCallback callback = new CameraManager.TorchCallback() {
            @Override public void onTorchModeChanged(String cameraId, boolean value) {
                if (!id.equals(cameraId)) return;
                if (phase.get() == 1 && value) enabled.countDown();
                if (phase.get() == 2 && !value) disabled.countDown();
            }
        };
        manager.registerTorchCallback(callback, handler);
        try {
            phase.set(1);
            manager.setTorchMode(id, true);
            boolean enabledObserved = enabled.await(5, TimeUnit.SECONDS);
            phase.set(2);
            manager.setTorchMode(id, false);
            boolean disabledObserved = disabled.await(5, TimeUnit.SECONDS);
            return enabledObserved && disabledObserved;
        } finally {
            try {
                manager.setTorchMode(id, false);
            } finally {
                manager.unregisterTorchCallback(callback);
            }
        }
    }

    private static boolean captureResultMatches(
            TotalCaptureResult result, CameraContract contract, boolean flashFired) {
        Integer flashMode = result.get(CaptureResult.FLASH_MODE);
        Integer flashState = result.get(CaptureResult.FLASH_STATE);
        Integer oisMode = result.get(
                CaptureResult.LENS_OPTICAL_STABILIZATION_MODE);
        Float aperture = result.get(CaptureResult.LENS_APERTURE);
        Float focalLength = result.get(CaptureResult.LENS_FOCAL_LENGTH);
        Rect crop = result.get(CaptureResult.SCALER_CROP_REGION);
        int expectedFlashMode = flashFired
                ? CaptureRequest.FLASH_MODE_SINGLE : CaptureRequest.FLASH_MODE_OFF;
        int expectedFlashState = contract.flashAvailable
                ? flashFired
                        ? CaptureResult.FLASH_STATE_FIRED
                        : CaptureResult.FLASH_STATE_READY
                : CaptureResult.FLASH_STATE_UNAVAILABLE;
        return flashMode != null && flashMode == expectedFlashMode
                && flashState != null && flashState == expectedFlashState
                && oisMode != null
                && oisMode == CaptureResult.LENS_OPTICAL_STABILIZATION_MODE_OFF
                && aperture != null && close(aperture, contract.aperture)
                && focalLength != null && close(focalLength, contract.focalLength)
                && new Rect(0, 0, contract.pixelWidth, contract.pixelHeight)
                .equals(crop);
    }

    private boolean captureMaximumJpeg(
            CameraDevice device, CameraContract contract) throws Exception {
        int width = contract.jpegSizes[0][0];
        int height = contract.jpegSizes[0][1];
        try (CameraSupport.FrameReader reader = new CameraSupport.FrameReader(
                width, height, ImageFormat.JPEG, 2, handler)) {
            CameraCaptureSession session = CameraSupport.configure(
                    device, Collections.singletonList(reader.surface()), handler);
            try {
                CaptureRequest.Builder request = device.createCaptureRequest(
                        CameraDevice.TEMPLATE_STILL_CAPTURE);
                request.addTarget(reader.surface());
                TotalCaptureResult capture = CameraSupport.captureResult(
                        session, request.build(), handler);
                Long timestamp = capture.get(CaptureResult.SENSOR_TIMESTAMP);
                CameraSupport.Frame frame = reader.take();
                return timestamp != null && timestamp == frame.timestamp
                        && frame.bytes > 0 && frame.jpegValid
                        && frame.jpegExifValid
                        && captureResultMatches(capture, contract, false);
            } finally {
                session.close();
            }
        }
    }

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
            Set<String> cameraIds = new HashSet<>(
                    Arrays.asList(manager.getCameraIdList()));
            require(cameraIds.equals(new HashSet<>(Arrays.asList("0", "1"))),
                    "published camera IDs differ");
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
        CameraContract contract = contractFor(id);
        CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
        validateCharacteristics(characteristics, contract);
        boolean torchContract = probeTorch(
                manager, id, contract.flashAvailable);
        int sensorOrientation = contract.sensorOrientation;
        int referenceRotation = (360 - sensorOrientation) % 360;
        byte[] yuvReference = referencePhoto == null ? null
                : CameraSupport.referencePhotoSample(
                        referencePhoto, 320, 240, referenceRotation);
        boolean jpegSwapsAxes =
                sensorOrientation == 90 || sensorOrientation == 270;
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
            all.set(CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
            all.addTarget(yuv.surface());
            all.addTarget(jpeg.surface());
            all.addTarget(opaque.surface());
            TotalCaptureResult allResult = CameraSupport.captureResult(
                    session, all.build(), handler);
            Long allTimestampValue = allResult.get(CaptureResult.SENSOR_TIMESTAMP);
            require(allTimestampValue != null, "capture timestamp missing");
            long allTimestamp = allTimestampValue;
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
            boolean resultMetadata =
                    captureResultMatches(allResult, contract, false);
            boolean flashCapture = true;
            if (contract.flashAvailable) {
                CaptureRequest.Builder flash = device.createCaptureRequest(
                        CameraDevice.TEMPLATE_STILL_CAPTURE);
                flash.set(CaptureRequest.FLASH_MODE,
                        CaptureRequest.FLASH_MODE_SINGLE);
                flash.addTarget(yuv.surface());
                TotalCaptureResult flashResult = CameraSupport.captureResult(
                        session, flash.build(), handler);
                Long flashTimestamp = flashResult.get(
                        CaptureResult.SENSOR_TIMESTAMP);
                CameraSupport.Frame flashFrame = yuv.take();
                flashCapture = flashTimestamp != null
                        && flashTimestamp == flashFrame.timestamp
                        && flashFrame.bytes > 0
                        && captureResultMatches(flashResult, contract, true);
            }
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
            flushBuilder.set(
                    CaptureRequest.JPEG_ORIENTATION, sensorOrientation);
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
            SystemClock.sleep(100L);
            boolean maximumJpeg = captureMaximumJpeg(device, contract);

            device.close();
            device = null;
            SystemClock.sleep(100L);
            boolean reopened = captureAfterReopen(manager, id);
            result.put("multiOutput", multiOutput);
            result.put("jpegExif", jpegFrame.jpegExifValid);
            result.put("referenceContentMatched", referenceContentMatched);
            result.put("characteristics", true);
            result.put("torch", torchContract);
            result.put("resultMetadata", resultMetadata);
            result.put("flashCapture", flashCapture);
            result.put("maximumJpeg", maximumJpeg);
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
            result.put("ok", multiOutput && torchContract
                    && resultMetadata && flashCapture && maximumJpeg
                    && repeatingCompleted && monotonic.get()
                    && repeatingYuv >= 4 && repeatingPrivate >= 4
                    && burstCallbacks && !burstFailed.get()
                    && burstImages == burst.size()
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
