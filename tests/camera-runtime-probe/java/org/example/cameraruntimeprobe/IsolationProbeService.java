package org.example.cameraruntimeprobe;

import android.app.Service;
import android.content.Intent;
import android.hardware.Camera;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.system.Os;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@SuppressWarnings("deprecation")
public final class IsolationProbeService extends Service {
    private static final String SOURCE_DIRECTORY = "/data/misc/camera/source";

    static {
        System.loadLibrary("camera_runtime_probe");
    }

    private static native String runNativeIsolationProbe();

    private final Binder binder = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (code != 1) return false;
            reply.writeNoException();
            reply.writeString(collect().toString());
            return true;
        }
    };

    @Override public IBinder onBind(Intent intent) { return binder; }
    @Override public boolean onUnbind(Intent intent) {
        new Handler(getMainLooper()).post(
                () -> Process.killProcess(Process.myPid()));
        return false;
    }

    private JSONObject collect() {
        JSONObject result = new JSONObject();
        HandlerThread callbacks = null;
        try {
            File directory = new File(SOURCE_DIRECTORY);
            File configuration = new File(directory, "current.conf");
            boolean sourceHidden = directory.list() == null
                    && !canStat(configuration) && !canRead(configuration);
            result.put("isolated", Process.isIsolated());
            result.put("sourceHidden", sourceHidden);

            CameraManager manager = getSystemService(CameraManager.class);
            callbacks = new HandlerThread("isolated-camera-callbacks");
            callbacks.start();
            Handler handler = new Handler(callbacks.getLooper());
            JSONArray camera2Prevented = new JSONArray();
            JSONArray camera2Completed = new JSONArray();
            for (String id : new String[] {"0", "1"}) {
                CountDownLatch terminal = new CountDownLatch(1);
                AtomicBoolean opened = new AtomicBoolean(false);
                Thread attempt = new Thread(() -> {
                    try {
                        manager.openCamera(id, new CameraDevice.StateCallback() {
                            @Override public void onOpened(CameraDevice camera) {
                                opened.set(true);
                                camera.close();
                                terminal.countDown();
                            }
                            @Override public void onDisconnected(CameraDevice camera) {
                                camera.close();
                                terminal.countDown();
                            }
                            @Override public void onError(CameraDevice camera, int error) {
                                camera.close();
                                terminal.countDown();
                            }
                        }, handler);
                    } catch (Throwable denied) {
                        terminal.countDown();
                    }
                }, "isolated-camera2-attempt");
                attempt.setDaemon(true);
                attempt.start();
                boolean completed = terminal.await(3, TimeUnit.SECONDS);
                if (!completed) attempt.interrupt();
                camera2Prevented.put(!opened.get());
                camera2Completed.put(completed);
            }

            AtomicReference<String> ndkResult = new AtomicReference<>();
            CountDownLatch ndkTerminal = new CountDownLatch(1);
            Thread ndkAttempt = new Thread(() -> {
                try {
                    ndkResult.set(runNativeIsolationProbe());
                } catch (Throwable ignored) {
                } finally {
                    ndkTerminal.countDown();
                }
            }, "isolated-ndk-attempt");
            ndkAttempt.setDaemon(true);
            ndkAttempt.start();
            boolean ndkCompleted = ndkTerminal.await(3, TimeUnit.SECONDS);
            if (!ndkCompleted) ndkAttempt.interrupt();
            JSONObject ndk = ndkResult.get() == null
                    ? null : new JSONObject(ndkResult.get());
            JSONArray ndkPrevented = ndk == null ? null : ndk.optJSONArray("accessDenied");
            boolean ndkOpenPrevented = !ndkCompleted || ndk == null || bothTrue(ndkPrevented);
            JSONArray camera1Prevented = new JSONArray();
            JSONArray camera1Completed = new JSONArray();
            for (int id = 0; id < 2; ++id) {
                final int cameraId = id;
                AtomicBoolean opened = new AtomicBoolean(false);
                CountDownLatch terminal = new CountDownLatch(1);
                Thread attempt = new Thread(() -> {
                    Camera camera = null;
                    try {
                        camera = Camera.open(cameraId);
                        opened.set(camera != null);
                    } catch (Throwable ignored) {
                    } finally {
                        if (camera != null) camera.release();
                        terminal.countDown();
                    }
                }, "isolated-camera1-attempt");
                attempt.setDaemon(true);
                attempt.start();
                boolean completed = terminal.await(3, TimeUnit.SECONDS);
                if (!completed) attempt.interrupt();
                camera1Prevented.put(!opened.get());
                camera1Completed.put(completed);
            }

            boolean attemptsCompleted = bothTrue(camera2Completed)
                    && bothTrue(camera1Completed) && ndkCompleted;
            boolean allPrevented = bothTrue(camera2Prevented)
                    && bothTrue(camera1Prevented) && ndkOpenPrevented;
            result.put("camera2OpenPrevented", camera2Prevented);
            result.put("camera2Completed", camera2Completed);
            result.put("camera1OpenPrevented", camera1Prevented);
            result.put("camera1Completed", camera1Completed);
            result.put("ndkOpenPrevented", ndkOpenPrevented);
            result.put("ndkCompleted", ndkCompleted);
            result.put("boundedProcessTermination", attemptsCompleted);
            result.put("ok", Process.isIsolated() && sourceHidden && allPrevented);
        } catch (Throwable error) {
            try {
                result.put("ok", false);
                result.put("error", error.getClass().getSimpleName());
            } catch (Throwable ignored) {
            }
        } finally {
            if (callbacks != null) callbacks.quitSafely();
        }
        return result;
    }

    private static boolean bothTrue(JSONArray values) {
        return values != null && values.length() == 2
                && values.optBoolean(0) && values.optBoolean(1);
    }

    private static boolean canStat(File file) {
        try {
            Os.stat(file.getAbsolutePath());
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean canRead(File file) {
        try (FileInputStream stream = new FileInputStream(file)) {
            return stream.read() >= -1;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
