package dev.xenoid.daemon;

import android.Manifest;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public final class CameraSelfTest {
    private static final String PREFERENCES = "camera-self-test";
    private static final String CURRENT_RUN_ID = "currentRunId";
    private static final String CURRENT_STATUS = "currentStatus";
    private static final int WIDTH = 320;
    private static final int HEIGHT = 240;
    private static final long OPEN_TIMEOUT_MS = 5_000L;
    private static final long CONFIGURE_TIMEOUT_MS = 5_000L;
    private static final long CAPTURE_TIMEOUT_MS = 10_000L;
    private static final long CLOSE_TIMEOUT_MS = 2_000L;
    private static final long UNSET_TIMESTAMP = Long.MIN_VALUE;
    private static final long AUTHORIZATION_TTL_NANOS = TimeUnit.SECONDS.toNanos(30L);
    private static final int MAX_SELF_TEST_JPEG_BYTES = 16 * 1024 * 1024;
    private static final Object STATUS_LOCK = new Object();
    private static final Object RUN_LOCK = new Object();
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "camera-self-test");
            thread.setDaemon(true);
            return thread;
        }
    });
    private static PendingAuthorization pendingAuthorization;
    private static ActiveRun activeRun;

    private CameraSelfTest() {}

    private static final class PendingAuthorization {
        final String runId;
        final long expiresAtNanos;

        PendingAuthorization(String runId, long expiresAtNanos) {
            this.runId = runId;
            this.expiresAtNanos = expiresAtNanos;
        }
    }

    private static final class ActiveRun {
        final String runId;
        final List<Runnable> completions = new ArrayList<>();
        boolean terminal;

        ActiveRun(String runId) {
            this.runId = runId;
        }
    }

    public static Map<String,Object> authorize(Context context, String runId) {
        if (!isValidRunId(runId)) {
            return authorizationResult(false, null, "invalid self-test run id");
        }
        Context applicationContext = context.getApplicationContext();
        Context app = applicationContext == null ? context : applicationContext;
        synchronized (RUN_LOCK) {
            discardExpiredAuthorizationLocked();
            if (activeRun != null) {
                return authorizationResult(false, null, "camera self-test is already running");
            }
            if (pendingAuthorization != null) {
                if (pendingAuthorization.runId.equals(runId)) {
                    return authorizationResult(true, runId, null);
                }
                return authorizationResult(false, null, "camera self-test authorization is pending");
            }
            synchronized (STATUS_LOCK) {
                SharedPreferences preferences =
                        app.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
                if (runId.equals(preferences.getString(CURRENT_RUN_ID, ""))) {
                    return authorizationResult(false, null,
                            "self-test run id has already been used");
                }
            }
            pendingAuthorization = new PendingAuthorization(
                    runId, System.nanoTime() + AUTHORIZATION_TTL_NANOS);
            return authorizationResult(true, runId, null);
        }
    }

    public static boolean startAuthorized(Context context, String runId, Runnable completion) {
        if (!isValidRunId(runId)) return false;
        Context applicationContext = context.getApplicationContext();
        final Context app = applicationContext == null ? context : applicationContext;
        final ActiveRun run;
        synchronized (RUN_LOCK) {
            discardExpiredAuthorizationLocked();
            if (activeRun != null) {
                if (!activeRun.runId.equals(runId) || activeRun.terminal) return false;
                if (completion != null) activeRun.completions.add(completion);
                return true;
            }
            if (pendingAuthorization == null
                    || !pendingAuthorization.runId.equals(runId)) {
                return false;
            }
            pendingAuthorization = null;
            run = new ActiveRun(runId);
            if (completion != null) run.completions.add(completion);
            activeRun = run;
        }

        persistNewRun(app, runningStatus(runId));
        if (app.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            completeRun(app, run, errorStatus(runId, "camera permission is not granted",
                    pendingCameras("error")));
            return true;
        }

        try {
            WORKER.execute(new Runnable() {
                @Override public void run() {
                    Map<String,Object> finished;
                    try {
                        finished = execute(app, run.runId);
                    } catch (Throwable ignored) {
                        finished = errorStatus(run.runId, "camera self-test failed",
                                pendingCameras("error"));
                    }
                    completeRun(app, run, finished);
                }
            });
        } catch (RuntimeException ignored) {
            completeRun(app, run, errorStatus(runId, "camera self-test could not start",
                    pendingCameras("error")));
        }
        return true;
    }

    public static Map<String,Object> status(Context context) {
        Context applicationContext = context.getApplicationContext();
        Context app = applicationContext == null ? context : applicationContext;
        synchronized (STATUS_LOCK) {
            SharedPreferences preferences = app.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
            String json = preferences.getString(CURRENT_STATUS, null);
            if (json == null) {
                Map<String,Object> empty = new LinkedHashMap<>();
                empty.put("ok", false);
                empty.put("state", "error");
                empty.put("error", "camera self-test has not run");
                empty.put("cameras", pendingCameras("notRun"));
                return empty;
            }
            try {
                return objectToMap(new JSONObject(json));
            } catch (Exception ignored) {
                Map<String,Object> invalid = new LinkedHashMap<>();
                invalid.put("runId", preferences.getString(CURRENT_RUN_ID, ""));
                invalid.put("ok", false);
                invalid.put("state", "error");
                invalid.put("error", "camera self-test status is unavailable");
                invalid.put("cameras", pendingCameras("error"));
                return invalid;
            }
        }
    }

    private static Map<String,Object> execute(Context context, String runId) {
        CameraManager manager = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
        if (manager == null) {
            return errorStatus(runId, "camera service is unavailable", pendingCameras("error"));
        }

        String backId = null;
        String frontId = null;
        try {
            for (String cameraId : manager.getCameraIdList()) {
                CameraCharacteristics characteristics = manager.getCameraCharacteristics(cameraId);
                Integer facing = characteristics.get(CameraCharacteristics.LENS_FACING);
                if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK && backId == null) {
                    backId = cameraId;
                } else if (facing != null && facing == CameraCharacteristics.LENS_FACING_FRONT && frontId == null) {
                    frontId = cameraId;
                }
            }
        } catch (Exception ignored) {
            return errorStatus(runId, "camera inventory is unavailable", pendingCameras("error"));
        }

        Map<String,Object> cameras = new LinkedHashMap<>();
        Map<String,Object> back = testCamera(manager, backId, "back");
        cameras.put("back", back);
        Map<String,Object> front = testCamera(manager, frontId, "front");
        cameras.put("front", front);

        boolean ok = Boolean.TRUE.equals(back.get("ok")) && Boolean.TRUE.equals(front.get("ok"));
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("runId", runId);
        out.put("state", ok ? "success" : "error");
        out.put("ok", ok);
        out.put("cameras", cameras);
        if (!ok) out.put("error", "one or more camera captures failed");
        return out;
    }

    private static Map<String,Object> testCamera(CameraManager manager, String cameraId, String facing) {
        if (cameraId == null) return failedCamera(facing, "camera is unavailable");
        try {
            CameraCharacteristics characteristics = manager.getCameraCharacteristics(cameraId);
            StreamConfigurationMap configurations =
                    characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            if (!supports(configurations, ImageFormat.YUV_420_888)
                    || !supports(configurations, ImageFormat.JPEG)) {
                return failedCamera(facing, "required capture formats are unavailable");
            }
        } catch (Exception ignored) {
            return failedCamera(facing, "camera characteristics are unavailable");
        }

        final HandlerThread callbackThread = new HandlerThread("camera-self-test-" + facing);
        callbackThread.start();
        final Handler callbackHandler = new Handler(callbackThread.getLooper());
        final AtomicBoolean closing = new AtomicBoolean(false);
        final AtomicReference<CameraDevice> cameraRef = new AtomicReference<>();
        final AtomicReference<CameraCaptureSession> sessionRef = new AtomicReference<>();
        final AtomicReference<String> asynchronousError = new AtomicReference<>();
        ImageReader yuvReader = null;
        ImageReader jpegReader = null;

        try {
            final CountDownLatch openLatch = new CountDownLatch(1);
            manager.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice camera) {
                    if (closing.get()) {
                        camera.close();
                    } else {
                        cameraRef.set(camera);
                    }
                    openLatch.countDown();
                }

                @Override public void onDisconnected(CameraDevice camera) {
                    asynchronousError.compareAndSet(null, "open");
                    camera.close();
                    openLatch.countDown();
                }

                @Override public void onError(CameraDevice camera, int error) {
                    asynchronousError.compareAndSet(null, "open");
                    camera.close();
                    openLatch.countDown();
                }
            }, callbackHandler);

            if (!await(openLatch, OPEN_TIMEOUT_MS) || cameraRef.get() == null
                    || asynchronousError.get() != null) {
                return failedCamera(facing, "camera could not be opened");
            }

            final CountDownLatch imageLatch = new CountDownLatch(2);
            final ImageObservation yuv =
                    new ImageObservation(imageLatch, ImageFormat.YUV_420_888);
            final ImageObservation jpeg =
                    new ImageObservation(imageLatch, ImageFormat.JPEG);
            yuvReader = ImageReader.newInstance(WIDTH, HEIGHT, ImageFormat.YUV_420_888, 2);
            jpegReader = ImageReader.newInstance(WIDTH, HEIGHT, ImageFormat.JPEG, 2);
            yuvReader.setOnImageAvailableListener(yuv, callbackHandler);
            jpegReader.setOnImageAvailableListener(jpeg, callbackHandler);

            final CountDownLatch configureLatch = new CountDownLatch(1);
            CameraDevice camera = cameraRef.get();
            camera.createCaptureSession(Arrays.asList(yuvReader.getSurface(), jpegReader.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override public void onConfigured(CameraCaptureSession session) {
                            if (closing.get()) {
                                session.close();
                            } else {
                                sessionRef.set(session);
                            }
                            configureLatch.countDown();
                        }

                        @Override public void onConfigureFailed(CameraCaptureSession session) {
                            asynchronousError.compareAndSet(null, "configure");
                            session.close();
                            configureLatch.countDown();
                        }
                    }, callbackHandler);

            if (!await(configureLatch, CONFIGURE_TIMEOUT_MS) || sessionRef.get() == null
                    || asynchronousError.get() != null) {
                return failedCamera(facing, "camera outputs could not be configured");
            }

            CaptureRequest.Builder builder = camera.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE);
            builder.addTarget(yuvReader.getSurface());
            builder.addTarget(jpegReader.getSurface());
            builder.set(CaptureRequest.CONTROL_CAPTURE_INTENT,
                    CaptureRequest.CONTROL_CAPTURE_INTENT_STILL_CAPTURE);

            final AtomicLong startedTimestamp = new AtomicLong(UNSET_TIMESTAMP);
            final AtomicLong completedTimestamp = new AtomicLong(UNSET_TIMESTAMP);
            final AtomicBoolean captureCompleted = new AtomicBoolean(false);
            final CountDownLatch captureLatch = new CountDownLatch(1);
            sessionRef.get().capture(builder.build(), new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureStarted(CameraCaptureSession session, CaptureRequest request,
                                                       long timestamp, long frameNumber) {
                    startedTimestamp.compareAndSet(UNSET_TIMESTAMP, timestamp);
                }

                @Override public void onCaptureCompleted(CameraCaptureSession session,
                                                         CaptureRequest request,
                                                         TotalCaptureResult result) {
                    Long timestamp = result.get(CaptureResult.SENSOR_TIMESTAMP);
                    if (timestamp != null) completedTimestamp.set(timestamp);
                    captureCompleted.set(true);
                    captureLatch.countDown();
                }

                @Override public void onCaptureFailed(CameraCaptureSession session,
                                                      CaptureRequest request, CaptureFailure failure) {
                    asynchronousError.compareAndSet(null, "capture");
                    captureLatch.countDown();
                }

                @Override public void onCaptureSequenceAborted(CameraCaptureSession session, int sequenceId) {
                    asynchronousError.compareAndSet(null, "capture");
                    captureLatch.countDown();
                }
            }, callbackHandler);

            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CAPTURE_TIMEOUT_MS);
            boolean callbackArrived = awaitUntil(captureLatch, deadline);
            boolean imagesArrived = awaitUntil(imageLatch, deadline);
            long started = startedTimestamp.get();
            long completed = completedTimestamp.get();
            boolean timestampsMatch = started > 0L && completed > 0L
                    && started == completed
                    && completed == yuv.timestamp.get()
                    && completed == jpeg.timestamp.get();
            boolean yuvValid = yuv.valid();
            boolean jpegValid = jpeg.valid();
            boolean ok = callbackArrived && imagesArrived && captureCompleted.get()
                    && asynchronousError.get() == null && yuvValid && jpegValid && timestampsMatch;
            return cameraResult(facing, ok, captureCompleted.get(), yuvValid, jpegValid,
                    timestampsMatch, ok ? null : "camera returned an incomplete capture");
        } catch (SecurityException ignored) {
            return failedCamera(facing, "camera permission is not granted");
        } catch (CameraAccessException ignored) {
            return failedCamera(facing, "camera service is unavailable");
        } catch (Exception ignored) {
            return failedCamera(facing, "camera capture failed");
        } finally {
            closing.set(true);
            CameraCaptureSession session = sessionRef.getAndSet(null);
            if (session != null) session.close();
            CameraDevice camera = cameraRef.getAndSet(null);
            if (camera != null) camera.close();
            if (yuvReader != null) yuvReader.close();
            if (jpegReader != null) jpegReader.close();
            callbackThread.quitSafely();
            try {
                callbackThread.join(CLOSE_TIMEOUT_MS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static boolean supports(StreamConfigurationMap configurations, int format) {
        if (configurations == null) return false;
        android.util.Size[] sizes = configurations.getOutputSizes(format);
        if (sizes == null) return false;
        for (android.util.Size size : sizes) {
            if (size.getWidth() == WIDTH && size.getHeight() == HEIGHT) return true;
        }
        return false;
    }

    private static boolean await(CountDownLatch latch, long timeoutMs) {
        try {
            return latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static boolean awaitUntil(CountDownLatch latch, long deadlineNanos) {
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0L) return latch.getCount() == 0L;
        try {
            return latch.await(remaining, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static Map<String,Object> cameraResult(String facing, boolean ok,
                                                    boolean captureCompleted, boolean yuvNonempty,
                                                    boolean jpegNonempty, boolean timestampsMatch,
                                                    String error) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("facing", facing);
        result.put("state", ok ? "success" : "error");
        result.put("ok", ok);
        result.put("width", WIDTH);
        result.put("height", HEIGHT);
        result.put("captureCompleted", captureCompleted);
        result.put("yuvNonempty", yuvNonempty);
        result.put("jpegNonempty", jpegNonempty);
        result.put("timestampsMatched", timestampsMatch);
        if (error != null) result.put("error", error);
        return result;
    }

    private static Map<String,Object> failedCamera(String facing, String error) {
        return cameraResult(facing, false, false, false, false, false, error);
    }

    private static Map<String,Object> runningStatus(String runId) {
        Map<String,Object> running = new LinkedHashMap<>();
        running.put("runId", runId);
        running.put("state", "running");
        running.put("ok", false);
        running.put("cameras", pendingCameras("pending"));
        return running;
    }

    private static Map<String,Object> errorStatus(String runId, String error,
                                                   Map<String,Object> cameras) {
        Map<String,Object> failed = new LinkedHashMap<>();
        failed.put("runId", runId);
        failed.put("state", "error");
        failed.put("ok", false);
        failed.put("cameras", cameras);
        failed.put("error", error);
        return failed;
    }

    private static Map<String,Object> pendingCameras(String state) {
        Map<String,Object> cameras = new LinkedHashMap<>();
        cameras.put("back", pendingCamera("back", state));
        cameras.put("front", pendingCamera("front", state));
        return cameras;
    }

    private static Map<String,Object> pendingCamera(String facing, String state) {
        Map<String,Object> camera = new LinkedHashMap<>();
        camera.put("facing", facing);
        camera.put("state", state);
        camera.put("ok", false);
        return camera;
    }

    private static void persistNewRun(Context context, Map<String,Object> snapshot) {
        String runId = String.valueOf(snapshot.get("runId"));
        synchronized (STATUS_LOCK) {
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
                    .putString(CURRENT_RUN_ID, runId)
                    .putString(CURRENT_STATUS, new JSONObject(snapshot).toString())
                    .commit();
        }
    }

    private static void completeRun(Context context, ActiveRun run,
                                    Map<String,Object> terminalSnapshot) {
        List<Runnable> completions;
        synchronized (RUN_LOCK) {
            if (activeRun != run || run.terminal) return;
            run.terminal = true;
            persistTerminalIfRunning(context, run.runId, terminalSnapshot);
            activeRun = null;
            completions = new ArrayList<>(run.completions);
            run.completions.clear();
        }
        postCompletions(completions);
    }

    private static void persistTerminalIfRunning(Context context, String runId,
                                                 Map<String,Object> snapshot) {
        synchronized (STATUS_LOCK) {
            SharedPreferences preferences =
                    context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
            if (!runId.equals(preferences.getString(CURRENT_RUN_ID, ""))) return;
            try {
                String encoded = preferences.getString(CURRENT_STATUS, null);
                if (encoded == null
                        || !"running".equals(new JSONObject(encoded).optString("state"))) {
                    return;
                }
                preferences.edit()
                        .putString(CURRENT_STATUS, new JSONObject(snapshot).toString())
                        .commit();
            } catch (Throwable ignored) {
                // A corrupt or already-terminal snapshot must never be overwritten.
            }
        }
    }

    private static void discardExpiredAuthorizationLocked() {
        if (pendingAuthorization != null
                && System.nanoTime() - pendingAuthorization.expiresAtNanos >= 0L) {
            pendingAuthorization = null;
        }
    }

    private static boolean isValidRunId(String runId) {
        if (runId == null || runId.length() != 32) return false;
        for (int i = 0; i < runId.length(); i++) {
            char value = runId.charAt(i);
            if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static Map<String,Object> authorizationResult(boolean ok, String runId,
                                                          String error) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("ok", ok);
        if (runId != null) result.put("runId", runId);
        if (error != null) result.put("error", error);
        return result;
    }

    private static Map<String,Object> objectToMap(JSONObject object) throws Exception {
        Map<String,Object> map = new LinkedHashMap<>();
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            map.put(key, jsonValue(object.get(key)));
        }
        return map;
    }

    private static Object jsonValue(Object value) throws Exception {
        if (value == JSONObject.NULL) return null;
        if (value instanceof JSONObject) return objectToMap((JSONObject) value);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) list.add(jsonValue(array.get(i)));
            return list;
        }
        if (value instanceof Boolean || value instanceof Number || value instanceof String) return value;
        return String.valueOf(value);
    }

    private static void postCompletions(final List<Runnable> completions) {
        if (completions.isEmpty()) return;
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override public void run() {
                for (Runnable completion : completions) {
                    try {
                        completion.run();
                    } catch (RuntimeException ignored) {
                        // A stale Activity callback must not prevent attached Activities finishing.
                    }
                }
            }
        });
    }

    private static final class ImageObservation implements ImageReader.OnImageAvailableListener {
        final CountDownLatch latch;
        final int expectedFormat;
        final AtomicBoolean received = new AtomicBoolean(false);
        final AtomicBoolean contentValid = new AtomicBoolean(false);
        final AtomicBoolean dimensionsMatch = new AtomicBoolean(false);
        final AtomicLong timestamp = new AtomicLong(UNSET_TIMESTAMP);

        ImageObservation(CountDownLatch latch, int expectedFormat) {
            this.latch = latch;
            this.expectedFormat = expectedFormat;
        }

        @Override public void onImageAvailable(ImageReader reader) {
            Image image = null;
            boolean first = false;
            try {
                image = reader.acquireNextImage();
                if (image == null) return;
                first = received.compareAndSet(false, true);
                if (!first) return;
                timestamp.set(image.getTimestamp());
                dimensionsMatch.set(image.getWidth() == WIDTH && image.getHeight() == HEIGHT);
                contentValid.set(validateContent(image, expectedFormat));
            } catch (RuntimeException ignored) {
                first = first || received.compareAndSet(false, true);
            } finally {
                if (image != null) image.close();
                if (first) latch.countDown();
            }
        }

        boolean valid() {
            return received.get() && contentValid.get() && dimensionsMatch.get()
                    && timestamp.get() > 0L;
        }

        private static boolean validateContent(Image image, int expectedFormat) {
            if (image.getFormat() != expectedFormat) return false;
            if (expectedFormat == ImageFormat.YUV_420_888) return validateYuv(image);
            if (expectedFormat == ImageFormat.JPEG) return validateJpeg(image);
            return false;
        }

        private static boolean validateYuv(Image image) {
            Image.Plane[] planes = image.getPlanes();
            if (planes == null || planes.length != 3) return false;
            int chromaWidth = (WIDTH + 1) / 2;
            int chromaHeight = (HEIGHT + 1) / 2;
            int lumaBits = inspectPlaneContent(planes[0], WIDTH, HEIGHT);
            int chromaUBits = inspectPlaneContent(planes[1], chromaWidth, chromaHeight);
            int chromaVBits = inspectPlaneContent(planes[2], chromaWidth, chromaHeight);
            return lumaBits >= 0 && chromaUBits >= 0 && chromaVBits >= 0
                    && (lumaBits | chromaUBits | chromaVBits) != 0;
        }

        private static int inspectPlaneContent(Image.Plane plane, int columns, int rows) {
            if (plane == null || columns <= 0 || rows <= 0) return -1;
            ByteBuffer source = plane.getBuffer();
            int rowStride = plane.getRowStride();
            int pixelStride = plane.getPixelStride();
            if (source == null || rowStride <= 0 || pixelStride <= 0) return -1;

            ByteBuffer buffer = source.duplicate();
            int start = buffer.position();
            int limit = buffer.limit();
            long rowExtent = (long) (columns - 1) * pixelStride + 1L;
            long end = (long) start + (long) (rows - 1) * rowStride + rowExtent;
            if (rowExtent > rowStride || end > limit) return -1;

            int observedBits = 0;
            for (int row = 0; row < rows; row++) {
                int rowOffset = start + row * rowStride;
                for (int column = 0; column < columns; column++) {
                    observedBits |= buffer.get(rowOffset + column * pixelStride) & 0xff;
                }
            }
            return observedBits;
        }

        private static boolean validateJpeg(Image image) {
            Image.Plane[] planes = image.getPlanes();
            if (planes == null || planes.length != 1 || planes[0] == null) return false;
            ByteBuffer source = planes[0].getBuffer();
            if (source == null) return false;
            ByteBuffer buffer = source.duplicate();
            int length = buffer.remaining();
            if (length < 4 || length > MAX_SELF_TEST_JPEG_BYTES) return false;
            int start = buffer.position();
            int end = buffer.limit();
            if ((buffer.get(start) & 0xff) != 0xff
                    || (buffer.get(start + 1) & 0xff) != 0xd8
                    || (buffer.get(end - 2) & 0xff) != 0xff
                    || (buffer.get(end - 1) & 0xff) != 0xd9) {
                return false;
            }

            byte[] encoded = new byte[length];
            buffer.get(encoded);
            Bitmap decoded = null;
            try {
                decoded = BitmapFactory.decodeByteArray(encoded, 0, encoded.length);
                return decoded != null
                        && decoded.getWidth() == WIDTH
                        && decoded.getHeight() == HEIGHT;
            } catch (RuntimeException ignored) {
                return false;
            } finally {
                if (decoded != null) decoded.recycle();
            }
        }
    }
}
