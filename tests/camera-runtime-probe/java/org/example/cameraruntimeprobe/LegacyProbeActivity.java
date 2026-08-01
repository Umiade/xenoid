package org.example.cameraruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.SurfaceTexture;
import android.graphics.BitmapFactory;
import android.hardware.Camera;
import android.os.Bundle;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@SuppressWarnings("deprecation")
public final class LegacyProbeActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(this::runProbe, "camera1-runtime-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("permission unavailable");
            }
            if (Camera.getNumberOfCameras() != 2) {
                throw new IllegalStateException("camera count mismatch");
            }
            String referencePhoto = getIntent().getStringExtra("referencePhoto");
            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            for (int id = 0; id < 2; ++id) {
                JSONObject camera = capture(id, referencePhoto);
                cameras.put(camera);
                allOk &= camera.getBoolean("ok");
            }
            report.put("probe", "camera1-take-picture");
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("camera1-take-picture", error);
        }
        ProbeIo.write(this, "camera1.json", report);
        runOnUiThread(this::finish);
    }

    private static JSONObject capture(int id, String referencePhoto) throws Exception {
        Camera camera = null;
        SurfaceTexture texture = null;
        try {
            camera = Camera.open(id);
            Camera.Parameters parameters = camera.getParameters();
            Camera.CameraInfo info = new Camera.CameraInfo();
            Camera.getCameraInfo(id, info);
            Camera.Size preview = choose(parameters.getSupportedPreviewSizes());
            Camera.Size picture = choose(parameters.getSupportedPictureSizes());
            parameters.setPreviewSize(preview.width, preview.height);
            parameters.setPictureSize(picture.width, picture.height);
            parameters.setRotation(info.orientation);
            camera.setParameters(parameters);
            texture = new SurfaceTexture(0);
            texture.setDefaultBufferSize(preview.width, preview.height);
            camera.setPreviewTexture(texture);
            camera.startPreview();
            Thread.sleep(300L);
            CountDownLatch terminal = new CountDownLatch(1);
            AtomicReference<byte[]> payload = new AtomicReference<>();
            camera.takePicture(null, null, (data, value) -> {
                payload.set(data);
                terminal.countDown();
            });
            if (!terminal.await(15, TimeUnit.SECONDS) || payload.get() == null
                    || payload.get().length < 4) {
                throw new IllegalStateException("takePicture failed");
            }
            byte[] jpeg = payload.get();
            boolean markers = (jpeg[0] & 0xff) == 0xff && (jpeg[1] & 0xff) == 0xd8
                    && (jpeg[jpeg.length - 2] & 0xff) == 0xff
                    && (jpeg[jpeg.length - 1] & 0xff) == 0xd9;
            Bitmap bitmap = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.length);
            boolean decoded = bitmap != null;
            int decodedWidth = decoded ? bitmap.getWidth() : 0;
            int decodedHeight = decoded ? bitmap.getHeight() : 0;
            boolean contentMatched = referencePhoto == null;
            boolean orientationMatched = referencePhoto == null;
            double contentDelta = 0.0;
            if (bitmap != null && referencePhoto != null) {
                byte[] actual = CameraSupport.transformedBitmapSample(
                        bitmap, decodedWidth, decodedHeight, 0);
                int expectedRotation = 0;
                byte[] expected = CameraSupport.referencePhotoSample(
                        referencePhoto, decodedWidth, decodedHeight, expectedRotation);
                contentDelta = CameraSupport.meanDelta(actual, expected);
                double mirroredDelta = CameraSupport.meanDelta(
                        mirrorRgbSample(actual), expected);
                double alternateRotationDelta = Double.POSITIVE_INFINITY;
                for (int rotation : new int[] {0, 90, 180, 270}) {
                    if (rotation == expectedRotation) continue;
                    alternateRotationDelta = Math.min(alternateRotationDelta,
                            CameraSupport.meanDelta(actual,
                                    CameraSupport.referencePhotoSample(referencePhoto,
                                            decodedWidth, decodedHeight, rotation)));
                }
                contentMatched = contentDelta <= 32.0;
                orientationMatched = contentDelta + 3.0 <= mirroredDelta
                        && contentDelta + 3.0 <= alternateRotationDelta;
            }
            if (bitmap != null) bitmap.recycle();
            JSONObject result = new JSONObject();
            result.put("id", Integer.toString(id));
            result.put("jpegBytes", jpeg.length);
            result.put("jpegNonempty", jpeg.length > 0);
            result.put("jpegMarkers", markers);
            result.put("decoded", decoded);
            result.put("contentMatched", contentMatched);
            result.put("orientationMatched", orientationMatched);
            result.put("contentDelta", contentDelta);
            result.put("ok", markers && decoded && contentMatched && orientationMatched);
            return result;
        } finally {
            if (camera != null) camera.release();
            if (texture != null) texture.release();
        }
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

    private static Camera.Size choose(List<Camera.Size> sizes) {
        if (sizes == null || sizes.isEmpty()) throw new IllegalStateException("no sizes");
        for (Camera.Size size : sizes) {
            if (size.width == 320 && size.height == 240) return size;
        }
        return sizes.get(sizes.size() - 1);
    }
}
