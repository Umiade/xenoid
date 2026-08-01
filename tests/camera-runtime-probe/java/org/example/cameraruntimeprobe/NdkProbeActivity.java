package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.os.Bundle;

import org.json.JSONArray;
import org.json.JSONObject;

public final class NdkProbeActivity extends Activity {
    static {
        System.loadLibrary("camera_runtime_probe");
    }

    private static native String runNativeProbe();

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(this::runProbe, "ndk-camera-runtime-probe").start();
    }

    private void runProbe() {
        JSONObject report;
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            JSONObject nativeReport = new JSONObject(runNativeProbe());
            if (!nativeReport.optBoolean("ok")) {
                throw new IllegalStateException("native capture failed");
            }
            String referencePhoto = getIntent().getStringExtra("referencePhoto");
            CameraManager manager = getSystemService(CameraManager.class);
            JSONArray nativeCameras = nativeReport.getJSONArray("cameras");
            if (nativeCameras.length() != 2) {
                throw new IllegalStateException("native camera result mismatch");
            }
            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            for (int index = 0; index < nativeCameras.length(); ++index) {
                JSONObject nativeCamera = nativeCameras.getJSONObject(index);
                String id = nativeCamera.getString("id");
                if (!Integer.toString(index).equals(id)) {
                    throw new IllegalStateException("native camera order mismatch");
                }
                JSONArray values = nativeCamera.getJSONArray("sample");
                if (values.length() != 16 * 12 * 3) {
                    throw new IllegalStateException("native RGB sample size mismatch");
                }
                byte[] sample = new byte[values.length()];
                for (int channel = 0; channel < sample.length; ++channel) {
                    int value = values.getInt(channel);
                    if (value < 0 || value > 255) {
                        throw new IllegalStateException("native RGB sample range");
                    }
                    sample[channel] = (byte) value;
                }
                boolean contentMatched = referencePhoto == null;
                boolean orientationMatched = referencePhoto == null;
                double contentDelta = 0.0;
                if (referencePhoto != null) {
                    Integer sensorOrientation = manager.getCameraCharacteristics(id).get(
                            CameraCharacteristics.SENSOR_ORIENTATION);
                    int referenceRotation = sensorOrientation == null
                            ? 0 : (360 - sensorOrientation) % 360;
                    byte[] reference = CameraSupport.referencePhotoSample(
                            referencePhoto, 320, 240, referenceRotation);
                    contentDelta = CameraSupport.meanDelta(sample, reference);
                    double mirroredDelta =
                            CameraSupport.meanDelta(mirrorRgbSample(sample), reference);
                    double alternateRotationDelta = Double.POSITIVE_INFINITY;
                    for (int rotation : new int[] {0, 90, 180, 270}) {
                        if (rotation == referenceRotation) continue;
                        alternateRotationDelta = Math.min(alternateRotationDelta,
                                CameraSupport.meanDelta(sample,
                                        CameraSupport.referencePhotoSample(
                                                referencePhoto, 320, 240, rotation)));
                    }
                    contentMatched = contentDelta <= 32.0;
                    orientationMatched = contentDelta + 3.0 <= mirroredDelta
                            && contentDelta + 3.0 <= alternateRotationDelta;
                }
                JSONObject camera = new JSONObject();
                camera.put("id", id);
                camera.put("imageNonempty", nativeCamera.getBoolean("imageNonempty"));
                camera.put("timestampsMatched",
                        nativeCamera.getBoolean("timestampsMatched"));
                camera.put("sampleBytes", sample.length);
                boolean fingerprintValid =
                        !nativeCamera.getString("fingerprint").equals("0");
                camera.put("fingerprintValid", fingerprintValid);
                camera.put("contentMatched", contentMatched);
                camera.put("contentDelta", contentDelta);
                camera.put("orientationMatched", orientationMatched);
                boolean ok = nativeCamera.getBoolean("ok")
                        && camera.getBoolean("imageNonempty")
                        && camera.getBoolean("timestampsMatched")
                        && fingerprintValid && contentMatched && orientationMatched;
                camera.put("ok", ok);
                cameras.put(camera);
                allOk &= ok;
            }
            report = new JSONObject();
            report.put("probe", "ndk-camera");
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("ndk-camera", error);
        }
        ProbeIo.write(this, "ndk.json", report);
        runOnUiThread(this::finish);
    }
    private static byte[] mirrorRgbSample(byte[] sample) {
        final int width = 16;
        final int height = 12;
        final int channels = 3;
        if (sample.length != width * height * channels) {
            throw new IllegalArgumentException("unexpected RGB sample size");
        }
        byte[] mirrored = new byte[sample.length];
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                int source = (y * width + x) * channels;
                int target = (y * width + width - 1 - x) * channels;
                System.arraycopy(sample, source, mirrored, target, channels);
            }
        }
        return mirrored;
    }

}
