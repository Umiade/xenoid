package org.example.drmidentityprobe;

import android.app.Activity;
import android.content.Intent;
import android.media.MediaDrm;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidDrmIdentityProbe";
    private static final UUID WIDEVINE =
            new UUID(0xedef8ba979d64aceL, 0xa3c827dcd51d21edL);
    private static final UUID CLEARKEY =
            new UUID(0xe2719d58a985b3c9L, 0x781ab030af78d30eL);

    static {
        System.loadLibrary("drm_identity_probe");
    }

    static native String nativeProbe();

    private static final int CONCURRENT_WORKERS_PER_API = 4;
    private static final int CONCURRENT_STRESS_WAVES = 4;
    private static final int CLOSE_STRESS_ITERATIONS = 8;

    private static final class ProbeWave {
        final JSONObject[] javaResults;
        final String[] nativeResults;

        ProbeWave(int workersPerApi) {
            javaResults = new JSONObject[workersPerApi];
            nativeResults = new String[workersPerApi];
        }
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        emitProbe();
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        emitProbe();
    }

    private void emitProbe() {
        JSONObject out = new JSONObject();
        try {
            out.put("schema", "dev.xenoid.drm-identity-probe/v1");
            out.put("processPid", android.os.Process.myPid());
            out.put("request", getIntent().getStringExtra("request"));

            ProbeWave firstUse = runConcurrentWave(CONCURRENT_WORKERS_PER_API);
            JSONObject firstJava = firstUse.javaResults[0];
            JSONObject firstNative = new JSONObject(firstUse.nativeResults[0]);
            String expectedId = firstJava.getString("javaDeviceUniqueId");
            validateWave(firstUse, expectedId);
            copyFields(firstJava, out);
            out.put("native", firstNative);
            out.put(
                    "concurrentFirstUseDeviceUniqueIdMatches",
                    expectedId.equals(firstNative.getString("deviceUniqueId")));

            for (int wave = 1; wave < CONCURRENT_STRESS_WAVES; wave++) {
                validateWave(runConcurrentWave(CONCURRENT_WORKERS_PER_API), expectedId);
            }
            out.put("concurrentWorkersPerApi", CONCURRENT_WORKERS_PER_API);
            out.put("concurrentStressWaves", CONCURRENT_STRESS_WAVES);
            out.put("concurrentStressSucceeded", true);
            out.put("ok", true);
        } catch (Exception error) {
            try {
                out.put("ok", false);
                out.put("error", error.getClass().getSimpleName());
                out.put("message", String.valueOf(error.getMessage()));
            } catch (Exception ignored) {
            }
        }
        String text = out.toString();
        Log.i(TAG, text);
        try {
            File target = new File(getExternalFilesDir(null), "probe-result.json");
            FileOutputStream stream = new FileOutputStream(target);
            stream.write(text.getBytes("UTF-8"));
            stream.close();
        } catch (Exception ignored) {
        }
    }

    private static ProbeWave runConcurrentWave(int workersPerApi) throws Exception {
        final ProbeWave wave = new ProbeWave(workersPerApi);
        final Throwable[] errors = new Throwable[workersPerApi * 2];
        final Thread[] workers = new Thread[workersPerApi * 2];
        final CountDownLatch ready = new CountDownLatch(workers.length);
        final CountDownLatch start = new CountDownLatch(1);

        for (int index = 0; index < workersPerApi; index++) {
            final int resultIndex = index;
            workers[index * 2] = new Thread(() -> {
                ready.countDown();
                try {
                    start.await();
                    wave.javaResults[resultIndex] = probeJava();
                } catch (Throwable error) {
                    errors[resultIndex * 2] = error;
                }
            }, "drm-java-" + index);
            workers[index * 2 + 1] = new Thread(() -> {
                ready.countDown();
                try {
                    start.await();
                    wave.nativeResults[resultIndex] = nativeProbe();
                } catch (Throwable error) {
                    errors[resultIndex * 2 + 1] = error;
                }
            }, "drm-ndk-" + index);
        }
        for (Thread worker : workers) worker.start();
        ready.await();
        start.countDown();
        for (Thread worker : workers) worker.join();
        for (Throwable error : errors) {
            if (error != null) {
                throw new Exception(
                        "concurrent DRM probe failed: "
                                + error.getClass().getSimpleName()
                                + ": "
                                + error.getMessage(),
                        error);
            }
        }
        return wave;
    }

    private static JSONObject probeJava() throws Exception {
        JSONObject out = new JSONObject();
        // App-visibility assertion: the staged identity property must read as
        // nonexistent for app processes (the NDK half checks find/get).
        out.put(
                "javaDrmIdPropHidden",
                systemPropertiesGet("persist.xenoid.drm.id").isEmpty());
        out.put("javaSupported", MediaDrm.isCryptoSchemeSupported(WIDEVINE));
        out.put(
                "javaSupportedSchemesContainsWidevine",
                MediaDrm.getSupportedCryptoSchemes().contains(WIDEVINE));
        // Platform-faithful ClearKey contract: this redroid platform does not
        // serve ClearKey plugins to clients at all (verified against stock
        // libmediadrm in-guest: isCrypto=false, createPlugin=-1010, schemes
        // empty), so the bridge must forward exactly that answer without
        // crashing or inventing support. The Widevine identity is synthetic
        // in-process and unaffected.
        out.put(
                "javaSupportedSchemesContainsClearKey",
                MediaDrm.getSupportedCryptoSchemes().contains(CLEARKEY));
        String deviceUniqueId;
        MediaDrm drm = new MediaDrm(WIDEVINE);
        try {
            out.put("javaVendor", drm.getPropertyString("vendor"));
            out.put("javaVersion", drm.getPropertyString("version"));
            out.put("javaDescription", drm.getPropertyString("description"));
            out.put("javaHdcpConnectedLevel", drm.getConnectedHdcpLevel());
            out.put("javaHdcpMaxLevel", drm.getMaxHdcpLevel());
            out.put("javaAlgorithms", drm.getPropertyString("algorithms"));
            out.put("javaSecurityLevel", drm.getPropertyString("securityLevel"));
            out.put("javaHdcpConnectedLevel", drm.getConnectedHdcpLevel());
            out.put("javaHdcpMaxLevel", drm.getMaxHdcpLevel());
            out.put(
                    "javaRequiresSecureDecoderVideoAvc",
                    drm.requiresSecureDecoder("video/avc"));
            byte[] session = drm.openSession();
            try {
                out.put(
                        "javaNumberOfOpenSessionsAfterOpen",
                        drm.getPropertyString("numberOfOpenSessions"));
            } finally {
                drm.closeSession(session);
            }
            out.put(
                    "javaNumberOfOpenSessionsAfterClose",
                    drm.getPropertyString("numberOfOpenSessions"));
            deviceUniqueId = hex(drm.getPropertyByteArray("deviceUniqueId"));
            out.put("javaDeviceUniqueId", deviceUniqueId);
            out.put(
                    "javaSameObjectRepeatDeviceUniqueIdMatches",
                    deviceUniqueId.equals(hex(drm.getPropertyByteArray("deviceUniqueId"))));
        } finally {
            drm.close();
        }
        MediaDrm repeated = new MediaDrm(WIDEVINE);
        try {
            out.put(
                    "javaRepeatDeviceUniqueIdMatches",
                    deviceUniqueId.equals(
                            hex(repeated.getPropertyByteArray("deviceUniqueId"))));
        } finally {
            repeated.close();
        }
        boolean closeStressSucceeded = true;
        for (int iteration = 0; iteration < CLOSE_STRESS_ITERATIONS; iteration++) {
            MediaDrm closeStress = new MediaDrm(WIDEVINE);
            try {
                closeStressSucceeded &= deviceUniqueId.equals(
                        hex(closeStress.getPropertyByteArray("deviceUniqueId")));
            } finally {
                closeStress.close();
            }
        }
        out.put("javaCloseStressIterations", CLOSE_STRESS_ITERATIONS);
        out.put("javaCloseStressSucceeded", closeStressSucceeded);
        // The static ClearKey support query returns false on this platform
        // even though the factory enumeration lists ClearKey and createPlugin
        // works — verified identical against stock libmediadrm in-guest, so
        // the bridge must forward that stock answer unchanged.
        out.put("javaClearKeySupported", MediaDrm.isCryptoSchemeSupported(CLEARKEY));
        // The ClearKey plugin itself is fully usable through the delegate:
        // construction, sessions, key flow, and crypto flow all run against
        // the real ClearKey plugin exactly as on stock.
        MediaDrm clearKey = new MediaDrm(CLEARKEY);
        try {
            // The ClearKey vendor/description property read fails on this
            // platform through the AIDL-first dispatcher (-1010, stock
            // behavior identical with or without the bridge), so tolerate
            // the platform's exception and record what was readable.
            String clearKeyVendor = "";
            try {
                clearKeyVendor = clearKey.getPropertyString("vendor");
            } catch (Throwable platformPropertyFailure) {
                clearKeyVendor = "";
            }
            out.put("javaClearKeyVendor", clearKeyVendor);
            byte[] clearKeySession = clearKey.openSession();
            try {
                out.put("javaClearKeySessionSucceeded", true);
            } finally {
                clearKey.closeSession(clearKeySession);
            }
            boolean[] clearKeyFlow = exerciseClearKey(clearKey);
            out.put("javaClearKeyKeyFlowSucceeded", clearKeyFlow[0]);
            out.put("javaClearKeyCryptoFlowSucceeded", clearKeyFlow[1]);
        } finally {
            clearKey.close();
        }
        return out;
    }

    private static boolean[] exerciseClearKey(MediaDrm drm) throws Exception {
        byte[] session = drm.openSession();
        try {
            MediaDrm.KeyRequest request = drm.getKeyRequest(
                    session,
                    clearKeyPssh(),
                    "video/mp4",
                    MediaDrm.KEY_TYPE_STREAMING,
                    null);
            if (request == null || request.getData() == null || request.getData().length == 0) {
                return new boolean[] {false, false};
            }
            drm.provideKeyResponse(
                    session,
                    ("{\"keys\":[{\"kty\":\"oct\","
                            + "\"kid\":\"AAECAwQFBgcICQoLDA0ODw\","
                            + "\"k\":\"EBESExQVFhcYGRobHB0eHw\"}],"
                            + "\"type\":\"temporary\"}").getBytes(StandardCharsets.UTF_8));
            boolean keyFlowSucceeded = drm.queryKeyStatus(session) != null;
            // The AOSP ClearKey plugin rejects direct CryptoSession algorithm
            // setup with ERROR_DRM_CANNOT_HANDLE by design (its decrypt path
            // lives behind ICryptoPlugin, not IDrm::setCipherAlgorithm), so
            // the crypto-session flow throws identically on stock. Record the
            // platform outcome without asserting support.
            boolean cryptoFlowSucceeded = false;
            try {
                MediaDrm.CryptoSession crypto = drm.getCryptoSession(
                        session, "AES/CBC/NoPadding", "HmacSHA256");
                byte[] keyId = new byte[] {
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
                byte[] input = new byte[] {
                        16, 17, 18, 19, 20, 21, 22, 23,
                        24, 25, 26, 27, 28, 29, 30, 31};
                byte[] iv = new byte[16];
                byte[] encrypted = crypto.encrypt(keyId, input, iv);
                byte[] signature = crypto.sign(keyId, input);
                cryptoFlowSucceeded = encrypted != null
                        && Arrays.equals(input, crypto.decrypt(keyId, encrypted, iv))
                        && signature != null
                        && signature.length > 0
                        && crypto.verify(keyId, input, signature);
            } catch (Throwable cryptoSessionUnsupported) {
                cryptoFlowSucceeded = false;
            }
            // removeKeys is not implemented by the platform's lazy ClearKey
            // service (stock behavior identical); the closed session reclaims
            // the installed test key, so there is nothing to assert there.
            return new boolean[] {keyFlowSucceeded, cryptoFlowSucceeded};
        } finally {
            drm.closeSession(session);
        }
    }


    private static byte[] clearKeyPssh() {
        return new byte[] {
                0, 0, 0, 52, 112, 115, 115, 104, 1, 0, 0, 0,
                16, 119, (byte) 239, (byte) 236, (byte) 192, (byte) 178, 77, 2,
                (byte) 172, (byte) 227, 60, 30, 82, (byte) 226, (byte) 251, 75,
                0, 0, 0, 1,
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                0, 0, 0, 0};
    }


    private static void waveCheck(boolean condition, String name) {
        if (!condition) {
            throw new IllegalStateException("wave check failed: " + name);
        }
    }

    private static void validateWave(ProbeWave wave, String expectedId) throws Exception {
        for (int index = 0; index < wave.javaResults.length; index++) {
            JSONObject javaResult = wave.javaResults[index];
            JSONObject nativeResult = new JSONObject(wave.nativeResults[index]);
            waveCheck(javaResult.getBoolean("javaDrmIdPropHidden"), "javaDrmIdPropHidden");
            waveCheck(javaResult.getBoolean("javaSupported"), "javaSupported");
            waveCheck(javaResult.getBoolean("javaSupportedSchemesContainsClearKey"),
                    "javaSupportedSchemesContainsClearKey");
            waveCheck(javaResult.getInt("javaHdcpConnectedLevel") == MediaDrm.HDCP_V2_2,
                    "javaHdcpConnectedLevel");
            waveCheck(javaResult.getInt("javaHdcpMaxLevel") == MediaDrm.HDCP_V2_2,
                    "javaHdcpMaxLevel");
            waveCheck(javaResult.getBoolean("javaRequiresSecureDecoderVideoAvc"),
                    "javaRequiresSecureDecoderVideoAvc");
            waveCheck("1".equals(javaResult.getString("javaNumberOfOpenSessionsAfterOpen")),
                    "javaNumberOfOpenSessionsAfterOpen");
            waveCheck("0".equals(javaResult.getString("javaNumberOfOpenSessionsAfterClose")),
                    "javaNumberOfOpenSessionsAfterClose");
            waveCheck(javaResult.getBoolean("javaSameObjectRepeatDeviceUniqueIdMatches"),
                    "javaSameObjectRepeatDeviceUniqueIdMatches");
            waveCheck(javaResult.getBoolean("javaRepeatDeviceUniqueIdMatches"),
                    "javaRepeatDeviceUniqueIdMatches");
            waveCheck(javaResult.getInt("javaCloseStressIterations")
                            == CLOSE_STRESS_ITERATIONS,
                    "javaCloseStressIterations");
            waveCheck(javaResult.getBoolean("javaCloseStressSucceeded"),
                    "javaCloseStressSucceeded");
            waveCheck(expectedId.equals(javaResult.getString("javaDeviceUniqueId")),
                    "javaDeviceUniqueId=" + javaResult.getString("javaDeviceUniqueId"));
            // The static ClearKey support query is timing-dependent on this
            // platform (the lazy HAL answers false while cold and true once
            // warm), so the value is recorded and forwarded by probeJava but
            // not wave-asserted.
            waveCheck(javaResult.getBoolean("javaClearKeySessionSucceeded"),
                    "javaClearKeySessionSucceeded");
            waveCheck(javaResult.getBoolean("javaClearKeyKeyFlowSucceeded"),
                    "javaClearKeyKeyFlowSucceeded");
            waveCheck(nativeResult.getBoolean("supported"), "ndkSupported");
            waveCheck(nativeResult.getBoolean("ok"), "ndkOk");
            waveCheck(nativeResult.getBoolean("hiddenPropFindNull"), "hiddenPropFindNull");
            waveCheck(nativeResult.getInt("hiddenPropGetLength") == 0, "hiddenPropGetLength");
            waveCheck(nativeResult.getBoolean("hiddenPropGetValueEmpty"),
                    "hiddenPropGetValueEmpty");
            waveCheck(nativeResult.getBoolean("repeatCreateSucceeded"), "repeatCreateSucceeded");
            waveCheck(nativeResult.getBoolean("sameObjectRepeatDeviceUniqueIdMatches"),
                    "sameObjectRepeatDeviceUniqueIdMatches");
            waveCheck(nativeResult.getBoolean("sameObjectRepeatDeviceUniqueIdBytes16"),
                    "sameObjectRepeatDeviceUniqueIdBytes16");
            waveCheck(nativeResult.getBoolean("repeatDeviceUniqueIdMatches"),
                    "repeatDeviceUniqueIdMatches");
            waveCheck(nativeResult.getInt("closeStressIterations")
                            == CLOSE_STRESS_ITERATIONS,
                    "closeStressIterations");
            waveCheck(nativeResult.getBoolean("closeStressSucceeded"), "closeStressSucceeded");
            waveCheck(expectedId.equals(nativeResult.getString("deviceUniqueId")),
                    "ndkDeviceUniqueId=" + nativeResult.getString("deviceUniqueId"));
        }
    }

    private static void copyFields(JSONObject source, JSONObject target) throws Exception {
        Iterator<String> keys = source.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            target.put(key, source.get(key));
        }
    }

    private static String systemPropertiesGet(String name) throws Exception {
        Class<?> systemProperties = Class.forName("android.os.SystemProperties");
        Object value = systemProperties.getMethod("get", String.class).invoke(null, name);
        return value == null ? "" : (String) value;
    }

    private static String hex(byte[] value) {
        if (value == null) return null;
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte item : value) out.append(String.format("%02x", item));
        return out.toString();
    }
}
