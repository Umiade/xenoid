package org.example.cameraruntimeprobe;

import android.app.Activity;
import android.media.CamcorderProfile;
import android.media.MediaRecorder;
import android.os.Bundle;

import org.json.JSONArray;
import org.json.JSONObject;

public final class CamcorderProfilesProbeActivity extends Activity {
    private static final int[][] EXPECTED_PROFILES = {
            {CamcorderProfile.QUALITY_QVGA, 320, 240},
            {CamcorderProfile.QUALITY_480P, 640, 480},
            {CamcorderProfile.QUALITY_720P, 1280, 720},
            {CamcorderProfile.QUALITY_1080P, 1920, 1080},
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(this::runProbe, "camcorder-profiles-probe").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        try {
            JSONArray cameras = new JSONArray();
            boolean allOk = true;
            for (int cameraId : new int[] {0, 1}) {
                JSONObject camera = inspectCamera(cameraId);
                cameras.put(camera);
                allOk &= camera.getBoolean("ok");
            }
            report.put("probe", "camcorder-profiles");
            report.put("cameras", cameras);
            report.put("ok", allOk);
        } catch (Throwable error) {
            report = ProbeIo.failure("camcorder-profiles", error);
        }
        ProbeIo.write(this, "camcorder-profiles.json", report);
        runOnUiThread(this::finish);
    }

    private static JSONObject inspectCamera(int cameraId) throws Exception {
        JSONObject camera = new JSONObject();
        JSONArray profiles = new JSONArray();
        boolean allOk = CamcorderProfile.hasProfile(cameraId, CamcorderProfile.QUALITY_LOW)
                && CamcorderProfile.hasProfile(cameraId, CamcorderProfile.QUALITY_HIGH);
        for (int[] expected : EXPECTED_PROFILES) {
            int quality = expected[0];
            boolean available = CamcorderProfile.hasProfile(cameraId, quality);
            JSONObject item = new JSONObject();
            item.put("quality", quality);
            item.put("available", available);
            if (available) {
                CamcorderProfile profile = CamcorderProfile.get(cameraId, quality);
                boolean coherent = profile.fileFormat == MediaRecorder.OutputFormat.MPEG_4
                        && profile.videoCodec == MediaRecorder.VideoEncoder.H264
                        && profile.videoFrameWidth == expected[1]
                        && profile.videoFrameHeight == expected[2]
                        && profile.videoFrameRate == 30
                        && profile.audioCodec == MediaRecorder.AudioEncoder.AAC;
                item.put("width", profile.videoFrameWidth);
                item.put("height", profile.videoFrameHeight);
                item.put("coherent", coherent);
                allOk &= coherent;
            } else {
                allOk = false;
            }
            profiles.put(item);
        }
        camera.put("cameraId", cameraId);
        camera.put("profiles", profiles);
        camera.put("ok", allOk);
        return camera;
    }
}
