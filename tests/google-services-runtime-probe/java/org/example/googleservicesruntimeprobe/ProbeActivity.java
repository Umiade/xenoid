package org.example.googleservicesruntimeprobe;

import android.accounts.AccountManager;
import android.accounts.AuthenticatorDescription;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidGoogleServicesProbe";
    private static final String GMS_CORE = "com.google.android.gms";
    private static final String GSF = "com.google.android.gsf";
    private static final String PLAY_STORE = "com.android.vending";

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(() -> {
            JSONObject result = collect();
            Log.i(TAG, result.toString());
            runOnUiThread(this::finish);
        }, "xenoid-google-services-probe").start();
    }

    private JSONObject collect() {
        JSONObject out = new JSONObject();
        try {
            PackageManager packages = getPackageManager();
            JSONObject packageState = new JSONObject();
            packageState.put(GMS_CORE, inspectPackage(packages, GMS_CORE));
            packageState.put(GSF, inspectPackage(packages, GSF));
            packageState.put(PLAY_STORE, inspectPackage(packages, PLAY_STORE));
            JSONObject binder = bindGmsCore();
            JSONObject launcher = resolvePlayStoreLauncher(packages);
            JSONObject accountAuthenticator = inspectGoogleAccountAuthenticator();
            out.put("packages", packageState);
            out.put("gmsCoreBinder", binder);
            out.put("playStoreLauncher", launcher);
            out.put("googleAccountAuthenticator", accountAuthenticator);
            out.put(
                "ok",
                packageState.getJSONObject(GMS_CORE).getBoolean("enabled")
                    && packageState.getJSONObject(GSF).getBoolean("enabled")
                    && packageState.getJSONObject(PLAY_STORE).getBoolean("enabled")
                    && binder.getBoolean("connected")
                    && launcher.getBoolean("resolved")
                    && accountAuthenticator.getBoolean("registered")
            );
        } catch (Exception error) {
            try {
                out.put("ok", false);
                out.put("error", error.getClass().getSimpleName());
                out.put("message", String.valueOf(error.getMessage()));
            } catch (Exception ignored) { }
        }
        return out;
    }

    private JSONObject inspectPackage(PackageManager packages, String name) throws Exception {
        PackageInfo info = packages.getPackageInfo(name, 0);
        ApplicationInfo app = info.applicationInfo;
        JSONObject out = new JSONObject();
        out.put("enabled", app != null && app.enabled);
        out.put("system", app != null && (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
        out.put("versionName", info.versionName == null ? "" : info.versionName);
        out.put("versionCode", info.getLongVersionCode());
        return out;
    }

    private JSONObject resolvePlayStoreLauncher(PackageManager packages) throws Exception {
        Intent intent = new Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(PLAY_STORE);
        List<ResolveInfo> matches = packages.queryIntentActivities(intent, 0);
        JSONObject out = new JSONObject();
        out.put("resolved", !matches.isEmpty());
        if (!matches.isEmpty() && matches.get(0).activityInfo != null) {
            out.put("activity", matches.get(0).activityInfo.name);
        }
        return out;
    }

    private JSONObject inspectGoogleAccountAuthenticator() throws Exception {
        JSONObject out = new JSONObject();
        for (AuthenticatorDescription description
                : AccountManager.get(this).getAuthenticatorTypes()) {
            if ("com.google".equals(description.type)) {
                out.put("registered", true);
                out.put("package", description.packageName);
                return out;
            }
        }
        out.put("registered", false);
        return out;
    }

    private JSONObject bindGmsCore() throws Exception {
        CountDownLatch connected = new CountDownLatch(1);
        AtomicReference<String> componentName = new AtomicReference<>("");
        AtomicReference<String> descriptor = new AtomicReference<>("");
        ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                componentName.set(name.flattenToShortString());
                try {
                    descriptor.set(service.getInterfaceDescriptor());
                } catch (Exception error) {
                    descriptor.set(error.getClass().getSimpleName());
                }
                connected.countDown();
            }

            @Override public void onServiceDisconnected(ComponentName name) { }
        };
        Intent intent = new Intent("com.google.android.gms.common.service.START")
            .setPackage(GMS_CORE);
        JSONObject out = new JSONObject();
        boolean accepted = false;
        try {
            accepted = bindService(intent, connection, Context.BIND_AUTO_CREATE);
            boolean reached = accepted && connected.await(5, TimeUnit.SECONDS);
            out.put("accepted", accepted);
            out.put("connected", reached);
            out.put("component", componentName.get());
            out.put("descriptor", descriptor.get());
        } catch (SecurityException error) {
            out.put("accepted", false);
            out.put("connected", false);
            out.put("error", "SecurityException");
        } finally {
            if (accepted) {
                try { unbindService(connection); } catch (Exception ignored) { }
            }
        }
        return out;
    }
}
