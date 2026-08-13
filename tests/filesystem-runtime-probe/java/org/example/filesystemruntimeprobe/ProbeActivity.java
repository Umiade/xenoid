package org.example.filesystemruntimeprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;

import org.json.JSONObject;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidFilesystemProbe";
    private static final int ISOLATED_RESULT = 1;
    private static final long TIMEOUT_MS = 10000;
    private static boolean emitted;

    static {
        System.loadLibrary("filesystem_runtime_probe");
    }

    static native String nativeProbe(String appDataPath);

    private JSONObject ordinary;

    private final Handler handler = new Handler(Looper.getMainLooper(), message -> {
        if (message.what != ISOLATED_RESULT || emitted) return false;
        JSONObject isolated = new JSONObject();
        try {
            Bundle data = message.getData();
            isolated.put("ok", data.getBoolean("ok", false));
            if (data.containsKey("native")) {
                isolated.put("native", new JSONObject(data.getString("native")));
            }
            if (data.containsKey("error")) isolated.put("error", data.getString("error"));
        } catch (Exception error) {
            isolated = errorObject(error);
        }
        emit(isolated);
        return true;
    });

    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            try {
                Message request = Message.obtain(null, IsolationProbeService.MSG_PROBE);
                request.replyTo = new Messenger(handler);
                new Messenger(service).send(request);
            } catch (Exception error) {
                emit(errorObject(error));
            }
        }
        @Override public void onServiceDisconnected(ComponentName name) { }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            ordinary = new JSONObject(nativeProbe(getFilesDir().getAbsolutePath()));
            Intent intent = new Intent(this, IsolationProbeService.class);
            if (!bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                emit(errorObject(new IllegalStateException("isolated_bind_failed")));
                return;
            }
            handler.postDelayed(() -> {
                if (!emitted) emit(errorObject(new IllegalStateException("isolated_timeout")));
            }, TIMEOUT_MS);
        } catch (Exception error) {
            emit(errorObject(error));
        }
    }

    private void emit(JSONObject isolated) {
        if (emitted) return;
        emitted = true;
        JSONObject result = new JSONObject();
        try {
            result.put("schema", "dev.xenoid.filesystem-runtime-probe/v1");
            result.put("ok", ordinary != null && isolated.optBoolean("ok", false));
            result.put("ordinary", ordinary == null ? JSONObject.NULL : ordinary);
            result.put("isolated", isolated);
        } catch (Exception error) {
            result = errorObject(error);
        }
        Log.i(TAG, result.toString());
        try { unbindService(connection); } catch (Exception ignored) { }
        finish();
    }

    private static JSONObject errorObject(Exception error) {
        JSONObject result = new JSONObject();
        try {
            result.put("ok", false);
            result.put("error", error.getMessage() == null
                    ? error.getClass().getSimpleName() : error.getMessage());
        } catch (Exception ignored) { }
        return result;
    }
}
