package org.example.cellularruntimeprobe;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;

public final class IsolationProbeService extends Service {
    static final int MSG_PROBE = 1;

    private final Messenger messenger = new Messenger(new Handler(Looper.getMainLooper(), message -> {
        if (message.what != MSG_PROBE || message.replyTo == null) return false;
        Bundle data = new Bundle();
        try {
            data.putString("native", ProbeActivity.nativeProbe());
            data.putBoolean("ok", true);
        } catch (Throwable error) {
            data.putBoolean("ok", false);
            data.putString("error", error.getClass().getSimpleName());
        }
        Message response = Message.obtain(null, 2);
        response.setData(data);
        try { message.replyTo.send(response); } catch (Exception ignored) { }
        return true;
    }));

    @Override public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }
}
