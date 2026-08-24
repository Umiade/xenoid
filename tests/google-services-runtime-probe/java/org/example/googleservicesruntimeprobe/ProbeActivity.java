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
import android.content.pm.Signature;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidGoogleServicesProbe";
    private static final String SCHEMA = "dev.xenoid.google-services-probe/v2";
    private static final String PROVIDER = "microg";
    private static final String GMS_CORE = "com.google.android.gms";
    private static final String GSF = "com.google.android.gsf";
    private static final String PLAY_STORE = "com.android.vending";
    private static final String GOOGLE_CERT_SHA256 =
        "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83";
    private static final String MICROG_CERT_SHA256 =
        "9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165";

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
            out.put("schema", SCHEMA);
            out.put("provider", PROVIDER);
            out.put("implementation", "microg");
            out.put("signatureModel", "restricted-spoofing");
            out.put("storeImplementation", "google-play");

            PackageManager packages = getPackageManager();
            JSONObject packageState = new JSONObject();
            JSONObject gmsCore = inspectPackage(
                packages, GMS_CORE, 250932030L, "0.3.15.250932", true, GOOGLE_CERT_SHA256);
            JSONObject gsfProxy = inspectPackage(
                packages, GSF, 8L, "v0.1.0", true, MICROG_CERT_SHA256);
            JSONObject playStore = inspectPackage(
                packages, PLAY_STORE, 83041710L, null, false, GOOGLE_CERT_SHA256);
            packageState.put(GMS_CORE, gmsCore);
            packageState.put(GSF, gsfProxy);
            packageState.put(PLAY_STORE, playStore);

            JSONObject binder = bindGmsCore();
            JSONObject launcher = resolvePlayStoreLauncher(packages);
            JSONObject accountAuthenticator = inspectGoogleAccountAuthenticator();
            JSONObject fusedProvider = inspectFusedProvider();
            JSONObject negativeSignature = inspectOwnSignature(packages);

            boolean googlePlayServicesReady =
                gmsCore.getBoolean("ok") && binder.getBoolean("connected");
            boolean accountAuthReady = accountAuthenticator.getBoolean("registered");
            boolean fusedLocationReady = fusedProvider.getBoolean("available");
            boolean playStoreReady = playStore.getBoolean("ok") && launcher.getBoolean("resolved");
            boolean negativeSignatureReady =
                negativeSignature.getBoolean("unlistedPackageNotSpoofed");
            boolean ok = googlePlayServicesReady
                && gsfProxy.getBoolean("ok")
                && accountAuthReady
                && fusedLocationReady
                && playStoreReady
                && negativeSignatureReady;

            JSONObject capabilities = new JSONObject();
            capabilities.put("googlePlayServices", capability(
                "runtime", googlePlayServicesReady ? "ready" : "failed",
                "notEvaluated", "minimal-live"));
            capabilities.put("accountAuth", capability(
                "runtime-release", accountAuthReady ? "ready" : "failed",
                "notEvaluated", "authenticator"));
            capabilities.put("cloudMessaging", capability(
                "runtime-release", "notEvaluated", "notEvaluated", "fcm-registrar"));
            capabilities.put("fusedLocation", capability(
                "runtime-release", fusedLocationReady ? "ready" : "failed",
                "notEvaluated", "fused-provider"));
            capabilities.put("maps", capability(
                "release", "notEvaluated", "notEvaluated", "release-attestation"));
            capabilities.put("playStore", capability(
                "runtime-release", playStoreReady ? "ready" : "failed",
                "notEvaluated", "launcher"));
            for (String unsupported : new String[] {
                    "playIntegrity", "deviceCertification", "drm", "antiCheat"}) {
                capabilities.put(unsupported, capability(
                    "application", "unsupported", "unsupported", "unsupported"));
            }

            out.put("packages", packageState);
            out.put("gmsCoreBinder", binder);
            out.put("playStoreLauncher", launcher);
            out.put("googleAccountAuthenticator", accountAuthenticator);
            out.put("fusedProvider", fusedProvider);
            out.put("negativeSignature", negativeSignature);
            out.put("requiredCapabilities", new JSONArray()
                .put("googlePlayServices")
                .put("accountAuth")
                .put("cloudMessaging")
                .put("fusedLocation")
                .put("playStore"));
            out.put("capabilities", capabilities);
            out.put("ok", ok);
            out.put("error", ok ? JSONObject.NULL : "google_services_probe_failed");
        } catch (Exception error) {
            try {
                out.put("schema", SCHEMA);
                out.put("provider", PROVIDER);
                out.put("ok", false);
                out.put(
                    "error",
                    "google_services_probe_exception:"
                        + error.getClass().getSimpleName());
            } catch (Exception ignored) { }
        }
        return out;
    }

    private JSONObject inspectPackage(
            PackageManager packages,
            String name,
            long expectedVersionCode,
            String expectedVersionName,
            boolean exactVersion,
            String expectedSigner) throws Exception {
        PackageInfo info = packages.getPackageInfo(name, 0);
        ApplicationInfo app = info.applicationInfo;
        long versionCode = info.getLongVersionCode();
        String versionName = info.versionName == null ? "" : info.versionName;
        boolean versionMatches = exactVersion
            ? versionCode == expectedVersionCode && expectedVersionName.equals(versionName)
            : versionCode >= expectedVersionCode;
        JSONArray legacySigners = packageSigners(
            packages, name, PackageManager.GET_SIGNATURES, false);
        JSONArray signingInfoSigners = packageSigners(
            packages, name, PackageManager.GET_SIGNING_CERTIFICATES, true);
        boolean signerMatches = exactSingle(legacySigners, expectedSigner)
            && exactSingle(signingInfoSigners, expectedSigner);
        boolean enabled = app != null && app.enabled;
        boolean system = app != null && (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
        boolean ok = enabled && system && versionMatches && signerMatches;

        JSONObject out = new JSONObject();
        out.put("enabled", enabled);
        out.put("system", system);
        out.put("versionName", versionName);
        out.put("versionCode", versionCode);
        out.put("versionMatches", versionMatches);
        out.put("legacySignersSha256", legacySigners);
        out.put("signingInfoSha256", signingInfoSigners);
        out.put("signerMatches", signerMatches);
        out.put("ok", ok);
        out.put("error", ok ? JSONObject.NULL : "component_mismatch");
        return out;
    }

    private JSONArray packageSigners(
            PackageManager packages, String name, int flags, boolean signingInfo)
            throws Exception {
        PackageInfo info = packages.getPackageInfo(name, flags);
        Signature[] signatures;
        if (signingInfo) {
            if (info.signingInfo == null) {
                signatures = new Signature[0];
            } else if (info.signingInfo.hasMultipleSigners()) {
                signatures = info.signingInfo.getApkContentsSigners();
            } else {
                signatures = info.signingInfo.getSigningCertificateHistory();
            }
        } else {
            signatures = info.signatures == null ? new Signature[0] : info.signatures;
        }
        Set<String> digests = new TreeSet<>();
        for (Signature signature : signatures) {
            digests.add(sha256(signature.toByteArray()));
        }
        JSONArray result = new JSONArray();
        for (String digest : digests) {
            result.put(digest);
        }
        return result;
    }

    private static boolean exactSingle(JSONArray values, String expected) throws Exception {
        return values.length() == 1 && expected.equals(values.getString(0));
    }

    private JSONObject inspectOwnSignature(PackageManager packages) throws Exception {
        ApplicationInfo application = packages.getApplicationInfo(
            getPackageName(), PackageManager.GET_META_DATA);
        Object raw = application.metaData == null
            ? null : application.metaData.get("fake-signature");
        String declared = raw instanceof String ? (String) raw : null;
        if (declared == null && raw instanceof Integer) {
            declared = getResources().getString((Integer) raw);
        }
        boolean declaredMatches = declared != null
            && GOOGLE_CERT_SHA256.equals(sha256(decodeHex(declared)));
        JSONArray legacy = packageSigners(
            packages, getPackageName(), PackageManager.GET_SIGNATURES, false);
        JSONArray signingInfo = packageSigners(
            packages, getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES, true);
        boolean realSignerCoherent = legacy.length() == 1
            && signingInfo.length() == 1
            && legacy.getString(0).equals(signingInfo.getString(0));
        boolean unlistedPackageNotSpoofed = declaredMatches
            && realSignerCoherent
            && !GOOGLE_CERT_SHA256.equals(legacy.getString(0));
        boolean nonDebuggable =
            (application.flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0;

        JSONObject out = new JSONObject();
        out.put("declaredFakeSignatureMatches", declaredMatches);
        out.put("legacySignersSha256", legacy);
        out.put("signingInfoSha256", signingInfo);
        out.put("realSignerCoherent", realSignerCoherent);
        out.put("nonDebuggable", nonDebuggable);
        out.put("unlistedPackageNotSpoofed", unlistedPackageNotSpoofed && nonDebuggable);
        out.put(
            "error",
            unlistedPackageNotSpoofed && nonDebuggable
                ? JSONObject.NULL : "signature_spoof_scope_mismatch");
        return out;
    }

    private JSONObject inspectFusedProvider() throws Exception {
        LocationManager locations =
            (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        List<String> providers = locations == null
            ? java.util.Collections.emptyList() : locations.getAllProviders();
        boolean registered = providers.contains("fused");
        boolean enabled = false;
        if (registered) {
            try {
                enabled = locations.isProviderEnabled("fused");
            } catch (SecurityException ignored) {
                enabled = false;
            }
        }
        JSONObject out = new JSONObject();
        out.put("provider", "fused");
        out.put("registered", registered);
        out.put("enabled", enabled);
        out.put("available", registered);
        out.put(
            "error",
            registered ? JSONObject.NULL : "fused_provider_unavailable");
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
        out.put("error", matches.isEmpty() ? "play_store_launcher_unavailable" : JSONObject.NULL);
        return out;
    }

    private JSONObject inspectGoogleAccountAuthenticator() throws Exception {
        JSONObject out = new JSONObject();
        for (AuthenticatorDescription description
                : AccountManager.get(this).getAuthenticatorTypes()) {
            if ("com.google".equals(description.type)) {
                out.put("registered", true);
                out.put("package", description.packageName);
                out.put("error", JSONObject.NULL);
                return out;
            }
        }
        out.put("registered", false);
        out.put("error", "google_account_authenticator_unavailable");
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
            out.put("error", reached ? JSONObject.NULL : "gms_core_broker_unavailable");
        } catch (SecurityException error) {
            out.put("accepted", false);
            out.put("connected", false);
            out.put("error", "gms_core_broker_security_error");
        } finally {
            if (accepted) {
                try { unbindService(connection); } catch (Exception ignored) { }
            }
        }
        return out;
    }

    private static JSONObject capability(
            String scope, String runtimeState, String releaseState, String evidence)
            throws Exception {
        JSONObject out = new JSONObject();
        out.put("scope", scope);
        out.put("runtimeState", runtimeState);
        out.put("releaseState", releaseState);
        out.put("evidence", evidence);
        return out;
    }

    private static byte[] decodeHex(String encoded) {
        String value = encoded.trim();
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < value.length(); index += 2) {
            int high = Character.digit(value.charAt(index), 16);
            int low = Character.digit(value.charAt(index + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            result[index / 2] = (byte) ((high << 4) | low);
        }
        return result;
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder encoded = new StringBuilder(digest.length * 2);
        for (byte part : digest) {
            encoded.append(String.format(Locale.ROOT, "%02x", part & 0xff));
        }
        return encoded.toString();
    }
}
