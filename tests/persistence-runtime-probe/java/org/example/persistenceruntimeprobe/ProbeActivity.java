package org.example.persistenceruntimeprobe;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidPersistenceProbe";
    private static final String PREFS = "persistence_probe_prefs";
    private static final String DB = "persistence_probe.db";
    private static final String KEY_ALIAS = "persistence_probe_key";
    private static final String MARKER_FILE = "persistence-marker";
    private static final String TOKEN_FILE = "login-token";
    private static final String CACHE_FILE = "cache-entry";
    private static final String DE_FILE = "de-marker";
    private static final String EXTERNAL_FILE = "external-marker";
    private static final String MEDIA_FILE = "media-marker";

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        JSONObject result = collect();
        Log.i(TAG, result.toString());
        finish();
    }

    private JSONObject collect() {
        JSONObject out = new JSONObject();
        try {
            Context context = getApplicationContext();
            String marker = readOrCreateMarker(context);
            out.put("ok", true);
            out.put("marker", marker);
            out.put("androidId", Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID));
            out.put("firstInstallTime", getPackageManager().getPackageInfo(getPackageName(), 0).firstInstallTime);
            out.put("credentialEncryptedFiles", credentialEncryptedFiles(context));
            out.put("cache", cache(context));
            out.put("sharedPreferences", sharedPreferences(context, marker));
            out.put("sqlite", sqlite(context, marker));
            out.put("deviceProtectedStorage", deviceProtectedStorage(context));
            out.put("keystoreToken", keystoreToken(context));
            out.put("appScopedExternal", appScopedExternal(context));
            out.put("appScopedMedia", appScopedMedia(context));
        } catch (Exception error) {
            try { out.put("ok", false).put("error", error.getClass().getSimpleName()); } catch (Exception ignored) { }
        }
        return out;
    }

    private String readOrCreateMarker(Context context) throws Exception {
        File file = new File(context.getFilesDir(), MARKER_FILE);
        if (file.exists()) return readFile(file);
        String marker = UUID.randomUUID().toString();
        writeFile(file, marker);
        return marker;
    }

    private JSONObject credentialEncryptedFiles(Context context) throws Exception {
        File file = new File(context.getFilesDir(), MARKER_FILE);
        JSONObject out = new JSONObject();
        out.put("exists", file.exists());
        out.put("value", file.exists() ? readFile(file) : "");
        return out;
    }

    private JSONObject cache(Context context) throws Exception {
        File file = new File(context.getCacheDir(), CACHE_FILE);
        if (!file.exists()) writeFile(file, UUID.randomUUID().toString());
        JSONObject out = new JSONObject();
        out.put("exists", file.exists());
        out.put("value", readFile(file));
        return out;
    }

    private JSONObject sharedPreferences(Context context, String marker) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, MODE_PRIVATE);
        if (prefs.getString("marker", "").isEmpty()) {
            boolean committed = prefs.edit()
                .putString("marker", marker)
                .putString("login_token", "token-" + marker)
                .putLong("first_install_time", System.currentTimeMillis())
                .commit();
            if (!committed) throw new IllegalStateException("shared preferences commit failed");
        }
        JSONObject out = new JSONObject();
        out.put("marker", prefs.getString("marker", ""));
        out.put("loginToken", prefs.getString("login_token", ""));
        out.put("firstInstallTime", prefs.getLong("first_install_time", 0));
        return out;
    }

    private JSONObject sqlite(Context context, String marker) throws Exception {
        SQLiteDatabase db = context.openOrCreateDatabase(DB, MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS probe (id INTEGER PRIMARY KEY, marker TEXT, token TEXT)");
        Cursor cursor = db.rawQuery("SELECT marker, token FROM probe WHERE id = 1", null);
        JSONObject out = new JSONObject();
        if (cursor.moveToFirst()) {
            out.put("marker", cursor.getString(0));
            out.put("token", cursor.getString(1));
        } else {
            db.execSQL("INSERT INTO probe (id, marker, token) VALUES (1, ?, ?)", new Object[]{marker, "db-" + marker});
            cursor.close();
            cursor = db.rawQuery("SELECT marker, token FROM probe WHERE id = 1", null);
            cursor.moveToFirst();
            out.put("marker", cursor.getString(0));
            out.put("token", cursor.getString(1));
        }
        cursor.close();
        db.close();
        return out;
    }

    private JSONObject deviceProtectedStorage(Context context) throws Exception {
        Context de = context.createDeviceProtectedStorageContext();
        File file = new File(de.getFilesDir(), DE_FILE);
        if (!file.exists()) writeFile(file, UUID.randomUUID().toString());
        JSONObject out = new JSONObject();
        out.put("exists", file.exists());
        out.put("value", readFile(file));
        return out;
    }

    private JSONObject keystoreToken(Context context) throws Exception {
        JSONObject out = new JSONObject();
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
            generator.generateKey();
        }
        SecretKey key = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        File tokenFile = new File(context.getFilesDir(), TOKEN_FILE);
        if (!tokenFile.exists()) {
            String token = "login-" + UUID.randomUUID().toString();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
            byte[] iv = cipher.getIV();
            byte[] payload = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
            writeFile(tokenFile, android.util.Base64.encodeToString(payload, android.util.Base64.NO_WRAP));
        }
        String encoded = readFile(tokenFile);
        byte[] payload = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP);
        byte[] iv = new byte[12];
        byte[] encrypted = new byte[payload.length - 12];
        System.arraycopy(payload, 0, iv, 0, 12);
        System.arraycopy(payload, 12, encrypted, 0, encrypted.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] decrypted = cipher.doFinal(encrypted);
        out.put("token", new String(decrypted, StandardCharsets.UTF_8));
        return out;
    }

    private JSONObject appScopedExternal(Context context) throws Exception {
        File dir = context.getExternalFilesDir(null);
        JSONObject out = new JSONObject();
        if (dir == null) {
            out.put("available", false);
            return out;
        }
        File file = new File(dir, EXTERNAL_FILE);
        if (!file.exists()) writeFile(file, UUID.randomUUID().toString());
        out.put("available", true);
        out.put("exists", file.exists());
        out.put("value", readFile(file));
        return out;
    }

    private JSONObject appScopedMedia(Context context) throws Exception {
        File dir = context.getExternalMediaDirs()[0];
        JSONObject out = new JSONObject();
        if (dir == null) {
            out.put("available", false);
            return out;
        }
        File file = new File(dir, MEDIA_FILE);
        if (!file.exists()) writeFile(file, UUID.randomUUID().toString());
        out.put("available", true);
        out.put("exists", file.exists());
        out.put("value", readFile(file));
        return out;
    }

    private String readFile(File file) throws Exception {
        byte[] buffer = new byte[(int) file.length()];
        try (FileInputStream stream = new FileInputStream(file)) {
            int read = 0;
            while (read < buffer.length) {
                int n = stream.read(buffer, read, buffer.length - read);
                if (n < 0) break;
                read += n;
            }
        }
        return new String(buffer, StandardCharsets.UTF_8).trim();
    }

    private void writeFile(File file, String value) throws Exception {
        file.getParentFile().mkdirs();
        try (FileOutputStream stream = new FileOutputStream(file)) {
            stream.write(value.getBytes(StandardCharsets.UTF_8));
        }
    }
}
