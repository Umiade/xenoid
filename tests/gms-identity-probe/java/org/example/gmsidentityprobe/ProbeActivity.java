package org.example.gmsidentityprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Third-party-app view of Google identity surfaces: the app-scope SSAID, the
 * GMS advertising ID (raw IAdvertisingIdService binder call), and the GSF
 * Android ID (gservices content provider). No GMS client libraries are used.
 */
public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidGmsIdentityProbe";
    private static final String AD_SERVICE = "com.google.android.gms.ads.identifier.service.START";
    private static final String AD_DESCRIPTOR = "com.google.android.gms.ads.identifier.internal.IAdvertisingIdService";
    private static final Uri GSERVICES = Uri.parse("content://com.google.android.gsf.gservices");

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context context = getApplicationContext();
        // Binder callbacks arrive on the main thread; all waiting must happen
        // on a worker or onServiceConnected can never be delivered.
        new Thread(() -> {
            JSONObject out = new JSONObject();
            try {
                out.put("ok", true);
                out.put("androidId", Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID));
                out.put("advertisingId", readAdvertisingId(context));
                out.put("gsfAndroidId", readGsfAndroidId(context));
            } catch (Exception failure) {
                try { out.put("ok", false); out.put("error", failure.getClass().getSimpleName()); } catch (Exception ignored) {}
            }
            Log.i(TAG, out.toString());
            try {
                File dir = context.getExternalFilesDir(null);
                File target = new File(dir, "probe-result.json");
                FileOutputStream stream = new FileOutputStream(target);
                stream.write(out.toString().getBytes(StandardCharsets.UTF_8));
                stream.getFD().sync();
                stream.close();
            } catch (Exception writeFailure) {
                Log.w(TAG, "file write failed", writeFailure);
            }
            runOnUiThread(this::finish);
        }, "probe-worker").start();
    }

    private static final class BinderConnection implements ServiceConnection {
        private final CountDownLatch latch = new CountDownLatch(1);
        private volatile IBinder binder;
        @Override public void onServiceConnected(ComponentName name, IBinder service) { binder = service; latch.countDown(); }
        @Override public void onServiceDisconnected(ComponentName name) {}
        IBinder await() throws InterruptedException { return latch.await(10, TimeUnit.SECONDS) ? binder : null; }
    }

    private static Object readAdvertisingId(Context context) {
        BinderConnection connection = new BinderConnection();
        try {
            Intent intent = new Intent(AD_SERVICE).setPackage("com.google.android.gms");
            if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                return "unavailable:bind_rejected";
            }
            IBinder binder = connection.await();
            if (binder == null) {
                return "unavailable:timeout";
            }
            String id = transactGetId(binder, true);
            if (id == null) {
                id = transactGetId(binder, false);
            }
            return id == null ? "unavailable:transact_failed" : id;
        } catch (Exception failure) {
            return "unavailable:" + failure.getClass().getSimpleName();
        } finally {
            try { context.unbindService(connection); } catch (Exception ignored) {}
        }
    }

    private static String transactGetId(IBinder binder, boolean withFlag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AD_DESCRIPTOR);
            if (withFlag) {
                data.writeInt(1);
            }
            if (!binder.transact(1, data, reply, 0)) {
                return null;
            }
            reply.readException();
            return reply.readString();
        } catch (Exception failure) {
            return null;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private static Object readGsfAndroidId(Context context) {
        Cursor cursor = null;
        try {
            cursor = context.getContentResolver().query(GSERVICES, null, null, new String[]{"android_id"}, null);
            if (cursor == null || !cursor.moveToFirst() || cursor.getColumnCount() < 2) {
                return "unavailable:no_row";
            }
            String raw = cursor.getString(1);
            if (raw == null) {
                return "unavailable:null";
            }
            long value = Long.parseLong(raw);
            return value > 0 ? Long.toString(value) : "unavailable:non_positive";
        } catch (SecurityException denied) {
            return "denied:SecurityException";
        } catch (Exception failure) {
            return "unavailable:" + failure.getClass().getSimpleName();
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }
}
