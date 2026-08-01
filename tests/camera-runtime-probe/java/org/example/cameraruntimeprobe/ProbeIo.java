package org.example.cameraruntimeprobe;

import android.app.Activity;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

final class ProbeIo {
    static final String SCHEMA = "org.example.camera-runtime-probe/v1";

    private ProbeIo() {}

    static JSONObject failure(String probe, Throwable error) {
        JSONObject result = new JSONObject();
        try {
            result.put("schema", SCHEMA);
            result.put("probe", probe);
            result.put("ok", false);
            result.put("error", error == null ? "probe failed" : error.getClass().getSimpleName());
        } catch (Throwable ignored) {
        }
        return result;
    }

    static void write(Activity activity, String name, JSONObject result) {
        try {
            String runNonce = activity.getIntent().getStringExtra("runNonce");
            if (runNonce == null || runNonce.trim().isEmpty()) {
                throw new IllegalArgumentException("run nonce missing");
            }
            result.put("schema", SCHEMA);
            result.put("runNonce", runNonce);
            File directory = activity.getExternalFilesDir(null);
            if (directory == null) return;
            File temporary = new File(directory, name + ".new");
            File destination = new File(directory, name);
            try (FileOutputStream stream = new FileOutputStream(temporary, false)) {
                stream.write(result.toString().getBytes(StandardCharsets.UTF_8));
                stream.getFD().sync();
            }
            if (!temporary.renameTo(destination)) temporary.delete();
        } catch (Throwable ignored) {
        }
    }

    static long fingerprint(byte[] bytes) {
        long value = 0xcbf29ce484222325L;
        for (byte item : bytes) {
            value ^= item & 0xffL;
            value *= 0x100000001b3L;
        }
        return value;
    }
}
