package dev.xenoid.daemon;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/** Owns validated keybox state and synchronous convergence with the preloaded interceptor. */
final class KeyboxManager {
    static final long MAX_KEYBOX_BYTES = 8L * 1024L * 1024L;
    static final int MAX_REQUEST_BODY_BYTES = 2048;

    private static final int MAX_FRAME_BYTES = 8 * 1024 * 1024;
    private static final byte[] STATE_MAGIC =
            new byte[] { 'X', 'K', 'B', 'S', '0', '0', '0', '1' };
    private static final int SEED_BYTES = 32;
    private static final String GMS = "com.google.android.gms";
    private static final String VENDING = "com.android.vending";
    private final int appUid;
    private final Context context;
    private final File stateDirectory;
    private final File stateFile;
    private final File candidateFile;
    private final File controlFile;
    private final File stageRequestFile;
    private final String apkPath;
    private final SecureRandom random = new SecureRandom();

    private boolean configured;
    private boolean ready;
    private boolean active;
    private String safeError;
    private KeyboxInfo metadata = KeyboxInfo.empty();
    private long lastEpoch = System.currentTimeMillis();

    KeyboxManager(Context context) throws Exception {
        this.context = context.getApplicationContext();
        stateDirectory = new File(this.context.getNoBackupFilesDir(), "keybox");
        stateFile = new File(stateDirectory, "state.bin");
        candidateFile = new File(stateDirectory, ".candidate.xml");
        controlFile = new File(stateDirectory, "control.json");
        stageRequestFile = new File(stateDirectory, ".stage-request");
        apkPath = this.context.getApplicationInfo().sourceDir;
        appUid = Process.myUid();
        ensureStateDirectory();
        restoreAtStartup();
    }

    synchronized boolean healthReady() {
        return ready;
    }

    synchronized Map<String, Object> status() {
        return statusMap(true, safeError);
    }
    synchronized void cleanupStaged(String stagingPath) {
        if (!validStagePath(stagingPath)) return;
        try {
            ensureStateDirectory();
            writeStageRequest(stagingPath, 0, null);
            RootHelper.cleanupKeyboxStage(stageRequestFile, appUid, apkPath);
        } catch (Throwable ignored) {
        } finally {
            deletePrivateFile(stageRequestFile);
        }
    }


    synchronized Map<String, Object> importStaged(
            String stagingPath, long size, String sha256) {
        Snapshot previous = null;
        byte[] candidate = null;
        byte[] seed = null;
        KeyboxInfo candidateInfo = null;
        boolean copied = false;
        try {
            if (validStagePath(stagingPath)) {
                ensureStateDirectory();
                writeStageRequest(stagingPath, size, sha256);
            }
            if (!validStageRequest(stagingPath, size, sha256)) {
                return responseFailure("invalid_stage");
            }
            deletePrivateFile(candidateFile);
            copied = RootHelper.copyKeyboxStage(
                    stageRequestFile, candidateFile, appUid, apkPath);
            if (!copied) return responseFailure("invalid_stage");
            candidate = readCandidate(size, sha256);
            candidateInfo = parseKeybox(candidate);
            previous = readStateIfValid();
            seed = previous == null ? randomBytes(SEED_BYTES) : previous.seed.clone();

            String convergence = converge(candidate, seed, candidateInfo);
            if (!"ok".equals(convergence)) {
                restoreAfterFailedMutation(previous);
                return responseFailure(convergence);
            }
            try {
                persistState(candidate, seed);
            } catch (Throwable ignored) {
                restoreAfterFailedMutation(previous);
                return responseFailure("state_persist_failed");
            }
            configured = true;
            ready = true;
            active = true;
            safeError = null;
            replaceMetadata(candidateInfo);
            candidateInfo = null;
            return statusMap(true, null);
        } catch (KeyboxFailure failure) {
            return responseFailure(failure.code);
        } catch (Throwable ignored) {
            return responseFailure(copied ? "invalid_keybox" : "invalid_stage");
        } finally {
            RootHelper.cleanupKeyboxStage(stageRequestFile, appUid, apkPath);
            deletePrivateFile(stageRequestFile);
            deletePrivateFile(candidateFile);
            deletePrivateFile(controlFile);
            if (previous != null) previous.destroy();
            if (candidateInfo != null) candidateInfo.destroy();
            if (candidate != null) Arrays.fill(candidate, (byte) 0);
            if (seed != null) Arrays.fill(seed, (byte) 0);
        }
    }

    synchronized Map<String, Object> clear() {
        Snapshot previous = null;
        byte[] temporarySeed = null;
        boolean stateRemoved = false;
        try {
            ensureStateDirectory();
            previous = readStateIfValid();
            temporarySeed = previous == null ? randomBytes(SEED_BYTES) : previous.seed.clone();
            String cleared = convergeEmpty(temporarySeed);
            if (!"ok".equals(cleared)) {
                restoreAfterFailedMutation(previous);
                return responseFailure("clear_failed");
            }
            if (existsNoFollow(stateFile)) {
                if (!stateFile.delete()) {
                    restoreAfterFailedMutation(previous);
                    return responseFailure("clear_failed");
                }
                stateRemoved = true;
            }
            syncDirectory();
            configured = false;
            ready = true;
            active = false;
            safeError = null;
            replaceMetadata(KeyboxInfo.empty());
            return statusMap(true, null);
        } catch (Throwable ignored) {
            if (stateRemoved) {
                boolean restoredState = false;
                if (previous != null) {
                    try {
                        persistState(previous.xml, previous.seed);
                        restoredState = true;
                    } catch (Throwable persistIgnored) { }
                }
                if (!restoredState) {
                    byte[] recoverySeed = temporarySeed;
                    boolean destroyRecoverySeed = false;
                    if (recoverySeed == null) {
                        recoverySeed = randomBytes(SEED_BYTES);
                        destroyRecoverySeed = true;
                    }
                    try {
                        convergeEmpty(recoverySeed);
                    } finally {
                        if (destroyRecoverySeed) Arrays.fill(recoverySeed, (byte) 0);
                    }
                    configured = existsNoFollow(stateFile);
                    ready = false;
                    active = false;
                    safeError = "state_persist_failed";
                    replaceMetadata(KeyboxInfo.empty());
                    return responseFailure("clear_failed");
                }
            }
            restoreAfterFailedMutation(previous);
            return responseFailure("clear_failed");
        } finally {
            deletePrivateFile(controlFile);
            deletePrivateFile(candidateFile);
            if (previous != null) previous.destroy();
            if (temporarySeed != null) Arrays.fill(temporarySeed, (byte) 0);
        }
    }

    private void restoreAtStartup() {
        RootHelper.cleanupKeyboxStage(stageRequestFile, appUid, apkPath);
        deletePrivateFile(stageRequestFile);
        deletePrivateFile(candidateFile);
        deletePrivateFile(controlFile);
        deletePrivateFile(new File(stateDirectory, ".stage-request.tmp"));
        deletePrivateFile(new File(stateDirectory, ".control.tmp"));
        deletePrivateFile(new File(stateDirectory, ".state.tmp"));
        if (!existsNoFollow(stateFile)) {
            configured = false;
            ready = true;
            active = false;
            safeError = null;
            replaceMetadata(KeyboxInfo.empty());
            return;
        }
        configured = true;
        Snapshot snapshot = null;
        try {
            snapshot = readState();
            String convergence = converge(snapshot.xml, snapshot.seed, snapshot.info);
            if (!"ok".equals(convergence)) {
                convergeEmpty(snapshot.seed);
                ready = false;
                active = false;
                safeError = convergence;
                replaceMetadata(snapshot.info.copy());
                return;
            }
            ready = true;
            active = true;
            safeError = null;
            replaceMetadata(snapshot.info.copy());
        } catch (Throwable ignored) {
            byte[] seed = randomBytes(SEED_BYTES);
            try {
                convergeEmpty(seed);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
            ready = false;
            active = false;
            safeError = "invalid_keybox";
            replaceMetadata(KeyboxInfo.empty());
        } finally {
            deletePrivateFile(controlFile);
            if (snapshot != null) snapshot.destroy();
        }
    }

    private String converge(byte[] xml, byte[] seed, KeyboxInfo info) {
        try {
            if (Build.VERSION.SDK_INT != 33) return "native_unavailable";
            writeControlConfig(xml, seed, false);
            String applied = RootHelper.runKeyboxClient(apkPath, "apply");
            if (!"ok".equals(applied)) {
                if ("native_rejected".equals(applied)) return "native_rejected";
                if ("key_migration_unavailable".equals(applied)) {
                    return "key_migration_unavailable";
                }
                return "native_unavailable";
            }
            if (!selfTest(info)) return "attestation_self_test_failed";
            return "ok";
        } catch (KeyboxFailure failure) {
            return failure.code;
        } catch (Throwable ignored) {
            return "native_unavailable";
        } finally {
            deletePrivateFile(controlFile);
        }
    }

    private String convergeEmpty(byte[] seed) {
        try {
            if (Build.VERSION.SDK_INT != 33) return "native_unavailable";
            writeControlConfig(null, seed, true);
            String result = RootHelper.runKeyboxClient(apkPath, "clear");
            return "ok".equals(result) ? "ok" : "clear_failed";
        } catch (Throwable ignored) {
            return "clear_failed";
        } finally {
            deletePrivateFile(controlFile);
        }
    }

    private void restoreAfterFailedMutation(Snapshot previous) {
        if (previous == null) {
            byte[] seed = randomBytes(SEED_BYTES);
            try {
                String result = convergeEmpty(seed);
                configured = existsNoFollow(stateFile);
                ready = !configured && "ok".equals(result);
                active = false;
                safeError = ready ? null : "native_unavailable";
                if (!configured) replaceMetadata(KeyboxInfo.empty());
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
            return;
        }
        String restored = converge(previous.xml, previous.seed, previous.info);
        configured = true;
        ready = "ok".equals(restored);
        active = ready;
        safeError = ready ? null : restored;
        replaceMetadata(previous.info.copy());
    }

    private Map<String, Object> responseFailure(String error) {
        Map<String, Object> response = statusMap(false, error);
        response.put("ok", false);
        return response;
    }

    private Map<String, Object> statusMap(boolean ok, String error) {
        Map<String, Object> algorithms = XenoidDaemonService.map(
                "rsa", metadata.rsa,
                "ecdsa", metadata.ecdsa,
                "rsaChainCount", metadata.rsaChainCount,
                "ecdsaChainCount", metadata.ecdsaChainCount);
        Map<String, Object> response = XenoidDaemonService.map(
                "ok", ok && ready,
                "configured", configured,
                "ready", ready,
                "active", active,
                "algorithms", algorithms);
        if (error != null) response.put("error", error);
        return response;
    }

    private boolean validStageRequest(String path, long size, String sha256) {
        return validStagePath(path)
                && size > 0 && size <= MAX_KEYBOX_BYTES
                && sha256 != null && sha256.matches("[0-9a-f]{64}");
    }

    private boolean validStagePath(String path) {
        return path != null
                && path.matches("/data/local/tmp/\\.keybox-upload-[0-9a-f]{32}");
    }

    private void writeStageRequest(String path, long size, String sha256) throws Exception {
        if (!validStagePath(path)) throw new KeyboxFailure("invalid_stage");
        String safeSha = sha256 != null && sha256.matches("[0-9a-f]{64}")
                ? sha256 : "0000000000000000000000000000000000000000000000000000000000000000";
        File temporary = new File(stateDirectory, ".stage-request.tmp");
        deletePrivateFile(temporary);
        deletePrivateFile(stageRequestFile);
        if (existsNoFollow(temporary) || existsNoFollow(stageRequestFile)) {
            throw new KeyboxFailure("invalid_stage");
        }
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            Os.chmod(temporary.getAbsolutePath(), 0600);
            writeAscii(output, path + "\n" + size + "\n" + safeSha + "\n");
            output.flush();
            output.getFD().sync();
        } catch (Throwable failure) {
            deletePrivateFile(temporary);
            throw failure;
        }
        StructStat stat = Os.lstat(temporary.getAbsolutePath());
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != appUid
                || (stat.st_mode & 0777) != 0600 || stat.st_size <= 70
                || stat.st_size > 512) {
            deletePrivateFile(temporary);
            throw new KeyboxFailure("invalid_stage");
        }
        Os.rename(temporary.getAbsolutePath(), stageRequestFile.getAbsolutePath());
        syncDirectory();
    }

    private void ensureStateDirectory() throws Exception {
        if (!stateDirectory.exists() && !stateDirectory.mkdir()) throw new IOException();
        StructStat stat = Os.lstat(stateDirectory.getAbsolutePath());
        if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != appUid) {
            throw new IOException();
        }
        Os.chmod(stateDirectory.getAbsolutePath(), 0700);
        stat = Os.lstat(stateDirectory.getAbsolutePath());
        if ((stat.st_mode & 0777) != 0700) throw new IOException();
    }

    private byte[] readCandidate(long expectedSize, String expectedSha256) throws Exception {
        StructStat before = Os.lstat(candidateFile.getAbsolutePath());
        if (!OsConstants.S_ISREG(before.st_mode) || before.st_uid != appUid
                || (before.st_mode & 0777) != 0600 || before.st_size != expectedSize) {
            throw new KeyboxFailure("invalid_stage");
        }
        byte[] bytes = readExactly(candidateFile, expectedSize);
        StructStat after = Os.lstat(candidateFile.getAbsolutePath());
        if (!sameFile(before, after)) {
            Arrays.fill(bytes, (byte) 0);
            throw new KeyboxFailure("invalid_stage");
        }
        byte[] expected = hex(expectedSha256);
        byte[] actual = MessageDigest.getInstance("SHA-256").digest(bytes);
        boolean matches = MessageDigest.isEqual(expected, actual);
        Arrays.fill(expected, (byte) 0);
        Arrays.fill(actual, (byte) 0);
        if (!matches) {
            Arrays.fill(bytes, (byte) 0);
            throw new KeyboxFailure("invalid_stage");
        }
        return bytes;
    }

    private Snapshot readStateIfValid() {
        if (!existsNoFollow(stateFile)) return null;
        try {
            return readState();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private Snapshot readState() throws Exception {
        StructStat before = Os.lstat(stateFile.getAbsolutePath());
        if (!OsConstants.S_ISREG(before.st_mode) || before.st_uid != appUid
                || (before.st_mode & 0777) != 0600
                || before.st_size <= STATE_MAGIC.length + SEED_BYTES + 4
                || before.st_size > MAX_KEYBOX_BYTES + 128) {
            throw new KeyboxFailure("invalid_keybox");
        }
        byte[] seed = new byte[SEED_BYTES];
        byte[] xml = null;
        try (DataInputStream input = new DataInputStream(
                new BufferedInputStream(new FileInputStream(stateFile)))) {
            byte[] magic = new byte[STATE_MAGIC.length];
            input.readFully(magic);
            boolean validMagic = MessageDigest.isEqual(magic, STATE_MAGIC);
            Arrays.fill(magic, (byte) 0);
            if (!validMagic) throw new KeyboxFailure("invalid_keybox");
            input.readFully(seed);
            int length = input.readInt();
            if (length <= 0 || length > MAX_KEYBOX_BYTES
                    || before.st_size != STATE_MAGIC.length + SEED_BYTES + 4L + length) {
                throw new KeyboxFailure("invalid_keybox");
            }
            xml = new byte[length];
            input.readFully(xml);
            if (input.read() != -1) throw new KeyboxFailure("invalid_keybox");
        } catch (Throwable failure) {
            Arrays.fill(seed, (byte) 0);
            if (xml != null) Arrays.fill(xml, (byte) 0);
            throw failure;
        }
        StructStat after = Os.lstat(stateFile.getAbsolutePath());
        if (!sameFile(before, after)) {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(xml, (byte) 0);
            throw new KeyboxFailure("invalid_keybox");
        }
        try {
            KeyboxInfo info = parseKeybox(xml);
            return new Snapshot(seed, xml, info);
        } catch (Throwable failure) {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(xml, (byte) 0);
            throw failure;
        }
    }

    private void persistState(byte[] xml, byte[] seed) throws Exception {
        if (seed.length != SEED_BYTES || xml.length <= 0 || xml.length > MAX_KEYBOX_BYTES) {
            throw new IOException();
        }
        File temporary = new File(stateDirectory, ".state.tmp");
        deletePrivateFile(temporary);
        if (existsNoFollow(temporary)) throw new IOException();
        try (FileOutputStream raw = new FileOutputStream(temporary);
             DataOutputStream output = new DataOutputStream(raw)) {
            Os.chmod(temporary.getAbsolutePath(), 0600);
            output.write(STATE_MAGIC);
            output.write(seed);
            output.writeInt(xml.length);
            output.write(xml);
            output.flush();
            raw.getFD().sync();
        } catch (Throwable failure) {
            deletePrivateFile(temporary);
            throw failure;
        }
        StructStat stat = Os.lstat(temporary.getAbsolutePath());
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != appUid
                || (stat.st_mode & 0777) != 0600) {
            deletePrivateFile(temporary);
            throw new IOException();
        }
        Os.rename(temporary.getAbsolutePath(), stateFile.getAbsolutePath());
        syncDirectory();
    }

    private void writeControlConfig(byte[] xml, byte[] seed, boolean empty) throws Exception {
        File temporary = new File(stateDirectory, ".control.tmp");
        deletePrivateFile(temporary);
        deletePrivateFile(controlFile);
        if (existsNoFollow(temporary) || existsNoFollow(controlFile)) throw new IOException();
        long epoch = nextEpoch();
        JSONObject boot = bootInfo(seed);
        JSONObject remainder = empty ? null : profileRemainder();
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            Os.chmod(temporary.getAbsolutePath(), 0600);
            if (empty) {
                writeAscii(output, "{\"type\":\"config\",\"epoch\":" + epoch
                        + ",\"bootInfo\":" + boot.toString() + ",\"profiles\":[]}");
            } else {
                if (xml == null || xml.length <= 0) throw new IOException();
                writeAscii(output, "{\"type\":\"config\",\"epoch\":" + epoch
                        + ",\"bootInfo\":" + boot.toString()
                        + ",\"profiles\":[{\"id\":\"default\",\"keyboxB64\":\"");
                OutputStream base64 = Base64.getEncoder().wrap(new NonClosingOutputStream(output));
                base64.write(xml);
                base64.close();
                String rest = remainder.toString();
                if (rest.length() < 2 || rest.charAt(0) != '{') throw new IOException();
                writeAscii(output, "\"," + rest.substring(1) + "]}");
            }
            output.flush();
            output.getFD().sync();
        } catch (Throwable failure) {
            deletePrivateFile(temporary);
            throw failure;
        }
        StructStat stat = Os.lstat(temporary.getAbsolutePath());
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != appUid
                || (stat.st_mode & 0777) != 0600
                || stat.st_size <= 0 || stat.st_size > MAX_FRAME_BYTES) {
            deletePrivateFile(temporary);
            throw new KeyboxFailure("invalid_keybox");
        }
        Os.rename(temporary.getAbsolutePath(), controlFile.getAbsolutePath());
        syncDirectory();
    }

    private JSONObject bootInfo(byte[] seed) throws Exception {
        if (seed == null || seed.length != SEED_BYTES) throw new IOException();
        byte[] verifiedBootKey = derive(seed, "xenoid-keymint-vb-key");
        byte[] verifiedBootHash = derive(seed, "xenoid-keymint-vb-hash");
        try {
            return new JSONObject()
                    .put("verifiedBootKey", Base64.getEncoder().encodeToString(verifiedBootKey))
                    .put("verifiedBootHash", Base64.getEncoder().encodeToString(verifiedBootHash))
                    .put("deviceLocked", true)
                    .put("verifiedBootState", 0)
                    .put("strongBoxAvailable", false)
                    .put("attestVersionTee", 200)
                    .put("attestVersionStrongBox", 200);
        } finally {
            Arrays.fill(verifiedBootKey, (byte) 0);
            Arrays.fill(verifiedBootHash, (byte) 0);
        }
    }

    private JSONObject profileRemainder() throws Exception {
        int osVersion = currentOsVersion();
        int osPatch = currentPatch(false);
        int fullPatch = currentPatch(true);
        JSONObject ids = new JSONObject()
                .put("brand", Build.BRAND)
                .put("device", Build.DEVICE)
                .put("product", Build.PRODUCT)
                .put("manufacturer", Build.MANUFACTURER)
                .put("model", Build.MODEL);
        // The runtime has no hardware KeyMint HAL, so the xenoid KeyMint service
        // owns the whole device: a "*" target routes every caller to the TA.
        JSONArray packages = new JSONArray().put("*");
        JSONArray packageUsers = new JSONArray().put(0);
        // Legacy attestation keys predating the KeyMint service can never be
        // served by the TA; keep the Play apps' uids listed so the control
        // client deletes those keys on set and they are recreated TA-backed.
        JSONArray uids = new JSONArray();
        JSONArray uidPackages = new JSONArray();
        LinkedHashMap<Integer, String> installed = new LinkedHashMap<>();
        addInstalledUid(installed, GMS);
        addInstalledUid(installed, VENDING);
        for (Map.Entry<Integer, String> item : installed.entrySet()) {
            uids.put(item.getKey());
            uidPackages.put(item.getValue());
        }
        return new JSONObject()
                .put("mode", "generation")
                .put("securityLevel", 1)
                .put("osVersion", osVersion)
                .put("osPatchLevel", osPatch)
                .put("vendorPatchLevel", fullPatch)
                .put("bootPatchLevel", fullPatch)
                .put("deviceIds", ids)
                .put("packages", packages)
                .put("packageUsers", packageUsers)
                .put("uids", uids)
                .put("uidPackages", uidPackages);
    }

    private void addInstalledUid(Map<Integer, String> output, String packageName) {
        try {
            ApplicationInfo info = context.getPackageManager()
                    .getApplicationInfo(packageName, 0);
            if (info.uid >= 10000) output.put(info.uid, packageName);
        } catch (Throwable ignored) { }
    }

    private int currentOsVersion() throws KeyboxFailure {
        String[] components = Build.VERSION.RELEASE.split("\\.");
        try {
            int major = components.length > 0 ? Integer.parseInt(components[0]) : 0;
            int minor = components.length > 1 ? Integer.parseInt(components[1]) : 0;
            int sub = components.length > 2 ? Integer.parseInt(components[2]) : 0;
            if (major != 13 || minor < 0 || minor > 99 || sub < 0 || sub > 99) {
                throw new NumberFormatException();
            }
            return major * 10000 + minor * 100 + sub;
        } catch (Throwable ignored) {
            throw new KeyboxFailure("native_unavailable");
        }
    }

    private int currentPatch(boolean day) throws KeyboxFailure {
        String patch = Build.VERSION.SECURITY_PATCH;
        try {
            if (patch == null || !patch.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) {
                throw new NumberFormatException();
            }
            int year = Integer.parseInt(patch.substring(0, 4));
            int month = Integer.parseInt(patch.substring(5, 7));
            int date = Integer.parseInt(patch.substring(8, 10));
            if (year < 2000 || month < 1 || month > 12 || date < 1 || date > 31) {
                throw new NumberFormatException();
            }
            return day ? year * 10000 + month * 100 + date : year * 100 + month;
        } catch (Throwable ignored) {
            throw new KeyboxFailure("native_unavailable");
        }
    }

    private boolean selfTest(KeyboxInfo info) {
        String alias = "xenoid-keymint-selftest-" + UUID.randomUUID().toString();
        byte[] challenge = randomBytes(32);
        boolean deleted = false;
        try {
            String algorithm = info.ecdsa
                    ? KeyProperties.KEY_ALGORITHM_EC : KeyProperties.KEY_ALGORITHM_RSA;
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    algorithm, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setUserAuthenticationRequired(false);
            if (info.ecdsa) {
                builder.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"));
            } else {
                builder.setKeySize(2048);
            }
            generator.initialize(builder.build());
            generator.generateKeyPair();
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            Certificate[] chain = keyStore.getCertificateChain(alias);
            if (chain == null || chain.length < 2) return false;
            byte[] terminal = chain[chain.length - 1].getEncoded();
            try {
                boolean matches = false;
                for (byte[] root : info.terminalCertificates) {
                    if (MessageDigest.isEqual(terminal, root)) {
                        matches = true;
                        break;
                    }
                }
                if (!matches) return false;
            } finally {
                Arrays.fill(terminal, (byte) 0);
            }
            keyStore.deleteEntry(alias);
            deleted = !keyStore.containsAlias(alias);
            return deleted;
        } catch (Throwable ignored) {
            return false;
        } finally {
            Arrays.fill(challenge, (byte) 0);
            if (!deleted) {
                try {
                    KeyStore cleanup = KeyStore.getInstance("AndroidKeyStore");
                    cleanup.load(null);
                    cleanup.deleteEntry(alias);
                } catch (Throwable ignored) { }
            }
        }
    }

    private KeyboxInfo parseKeybox(byte[] xml) throws KeyboxFailure {
        if (xml == null || xml.length <= 0 || xml.length > MAX_KEYBOX_BYTES) {
            throw new KeyboxFailure("invalid_keybox");
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            // Best-effort parser hardening: Android's stock factory rejects some
            // of these calls with UnsupportedOperationException. The load-bearing
            // checks below (throwing entity resolver + getDoctype rejection +
            // empty external-access attributes) do not depend on them.
            try { factory.setXIncludeAware(false); } catch (Throwable ignored) { }
            try { factory.setExpandEntityReferences(false); } catch (Throwable ignored) { }
            tryFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
            tryFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
            tryFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
            tryFeature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            try { factory.setAttribute(
                    "http://javax.xml.XMLConstants/property/accessExternalDTD", ""); }
            catch (Throwable ignored) { }
            try { factory.setAttribute(
                    "http://javax.xml.XMLConstants/property/accessExternalSchema", ""); }
            catch (Throwable ignored) { }
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("external entity rejected");
            });
            Document document = builder.parse(new InputSource(new ByteArrayInputStream(xml)));
            if (document.getDoctype() != null) throw new KeyboxFailure("invalid_keybox");
            NodeList keys = document.getElementsByTagName("Key");
            AlgorithmInfo rsa = null;
            AlgorithmInfo ecdsa = null;
            for (int index = 0; index < keys.getLength(); index++) {
                Node node = keys.item(index);
                if (!(node instanceof Element)) continue;
                Element element = (Element) node;
                String algorithm = element.getAttribute("algorithm");
                if ("rsa".equals(algorithm)) {
                    if (rsa != null) throw new KeyboxFailure("invalid_keybox");
                    rsa = parseAlgorithm(element, false);
                } else if ("ecdsa".equals(algorithm)) {
                    if (ecdsa != null) throw new KeyboxFailure("invalid_keybox");
                    ecdsa = parseAlgorithm(element, true);
                }
            }
            if (rsa == null || ecdsa == null) throw new KeyboxFailure("unsupported_keybox");
            List<byte[]> roots = new ArrayList<>();
            if (rsa != null) roots.add(rsa.terminal);
            if (ecdsa != null) roots.add(ecdsa.terminal);
            return new KeyboxInfo(
                    rsa != null, ecdsa != null,
                    rsa == null ? 0 : rsa.chainCount,
                    ecdsa == null ? 0 : ecdsa.chainCount,
                    roots);
        } catch (KeyboxFailure failure) {
            throw failure;
        } catch (Throwable ignored) {
            throw new KeyboxFailure("invalid_keybox");
        }
    }

    private AlgorithmInfo parseAlgorithm(Element key, boolean ec) throws Exception {
        Element privateKey = null;
        NodeList children = key.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node child = children.item(index);
            if (child instanceof Element && "PrivateKey".equals(child.getNodeName())) {
                if (privateKey != null) throw new KeyboxFailure("invalid_keybox");
                privateKey = (Element) child;
            }
        }
        if (privateKey == null) throw new KeyboxFailure("invalid_keybox");
        Pem privatePem = decodePem(privateKey.getTextContent(), ec
                ? new String[] { "PRIVATE KEY", "EC PRIVATE KEY" }
                : new String[] { "PRIVATE KEY", "RSA PRIVATE KEY" });
        try {
            NodeList certNodes = key.getElementsByTagName("Certificate");
            if (certNodes.getLength() < 2 || certNodes.getLength() > 64) {
                throw new KeyboxFailure("invalid_keybox");
            }
            List<X509Certificate> certificates = new ArrayList<>();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            for (int index = 0; index < certNodes.getLength(); index++) {
                Pem certificatePem = decodePem(
                        certNodes.item(index).getTextContent(), new String[] { "CERTIFICATE" });
                try {
                    Certificate certificate = certificateFactory.generateCertificate(
                            new ByteArrayInputStream(certificatePem.der));
                    if (!(certificate instanceof X509Certificate)) {
                        throw new KeyboxFailure("invalid_keybox");
                    }
                    certificates.add((X509Certificate) certificate);
                } finally {
                    certificatePem.destroy();
                }
            }
            String publicAlgorithm = certificates.get(0).getPublicKey().getAlgorithm();
            if ((ec && !"EC".equalsIgnoreCase(publicAlgorithm))
                    || (!ec && !"RSA".equalsIgnoreCase(publicAlgorithm))) {
                throw new KeyboxFailure("unsupported_keybox");
            }
            for (int index = 0; index + 1 < certificates.size(); index++) {
                certificates.get(index).verify(certificates.get(index + 1).getPublicKey());
            }
            if ("PRIVATE KEY".equals(privatePem.label)
                    && !privateKeyMatches(privatePem.der, certificates.get(0), ec)) {
                throw new KeyboxFailure("invalid_keybox");
            }
            byte[] terminal = certificates.get(certificates.size() - 1).getEncoded();
            return new AlgorithmInfo(certificates.size(), terminal);
        } finally {
            privatePem.destroy();
        }
    }

    private boolean privateKeyMatches(byte[] der, X509Certificate leaf, boolean ec) {
        byte[] message = randomBytes(32);
        byte[] signatureBytes = null;
        try {
            KeyFactory factory = KeyFactory.getInstance(ec ? "EC" : "RSA");
            PrivateKey key = factory.generatePrivate(new PKCS8EncodedKeySpec(der));
            Signature signer = Signature.getInstance(ec ? "SHA256withECDSA" : "SHA256withRSA");
            signer.initSign(key, random);
            signer.update(message);
            signatureBytes = signer.sign();
            Signature verifier = Signature.getInstance(ec ? "SHA256withECDSA" : "SHA256withRSA");
            verifier.initVerify(leaf.getPublicKey());
            verifier.update(message);
            return verifier.verify(signatureBytes);
        } catch (Throwable ignored) {
            return false;
        } finally {
            Arrays.fill(message, (byte) 0);
            if (signatureBytes != null) Arrays.fill(signatureBytes, (byte) 0);
        }
    }

    private Pem decodePem(String text, String[] allowedLabels) throws Exception {
        if (text == null || text.length() == 0 || text.length() > 512 * 1024) {
            throw new KeyboxFailure("invalid_keybox");
        }
        String normalized = text.trim();
        for (String label : allowedLabels) {
            String begin = "-----BEGIN " + label + "-----";
            String end = "-----END " + label + "-----";
            if (!normalized.startsWith(begin) || !normalized.endsWith(end)) continue;
            String payload = normalized.substring(begin.length(), normalized.length() - end.length())
                    .replaceAll("\\s", "");
            if (payload.length() == 0 || !payload.matches("[A-Za-z0-9+/]*={0,2}")) {
                throw new KeyboxFailure("invalid_keybox");
            }
            byte[] der = Base64.getDecoder().decode(payload);
            if (der.length == 0 || der.length > 384 * 1024) {
                Arrays.fill(der, (byte) 0);
                throw new KeyboxFailure("invalid_keybox");
            }
            return new Pem(label, der);
        }
        throw new KeyboxFailure("invalid_keybox");
    }

    private static void tryFeature(
            DocumentBuilderFactory factory, String name, boolean value) {
        try { factory.setFeature(name, value); } catch (Throwable ignored) { }
    }

    private void replaceMetadata(KeyboxInfo replacement) {
        KeyboxInfo old = metadata;
        metadata = replacement;
        if (old != null && old != replacement) old.destroy();
    }

    private long nextEpoch() {
        long now = System.currentTimeMillis();
        lastEpoch = Math.max(lastEpoch + 1, now);
        return lastEpoch;
    }

    private static byte[] derive(byte[] seed, String domain) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(domain.getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) 0);
        digest.update(seed);
        return digest.digest();
    }

    private byte[] randomBytes(int count) {
        byte[] value = new byte[count];
        random.nextBytes(value);
        return value;
    }

    private static byte[] readExactly(File file, long size) throws Exception {
        if (size <= 0 || size > MAX_KEYBOX_BYTES) throw new IOException();
        byte[] output = new byte[(int) size];
        try (FileInputStream input = new FileInputStream(file)) {
            int offset = 0;
            while (offset < output.length) {
                int count = input.read(output, offset, output.length - offset);
                if (count <= 0) throw new IOException();
                offset += count;
            }
            if (input.read() != -1) throw new IOException();
            return output;
        } catch (Throwable failure) {
            Arrays.fill(output, (byte) 0);
            throw failure;
        }
    }

    private static boolean sameFile(StructStat first, StructStat second) {
        return first.st_dev == second.st_dev && first.st_ino == second.st_ino
                && first.st_size == second.st_size && first.st_mtime == second.st_mtime
                && first.st_uid == second.st_uid && first.st_mode == second.st_mode;
    }

    private static byte[] hex(String text) throws KeyboxFailure {
        if (text == null || text.length() != 64) throw new KeyboxFailure("invalid_stage");
        byte[] output = new byte[32];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(text.charAt(index * 2), 16);
            int low = Character.digit(text.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                Arrays.fill(output, (byte) 0);
                throw new KeyboxFailure("invalid_stage");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private static void writeAscii(OutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try {
            output.write(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private void syncDirectory() throws Exception {
        FileDescriptor descriptor = Os.open(
                stateDirectory.getAbsolutePath(),
                OsConstants.O_RDONLY, 0);
        try {
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private static boolean existsNoFollow(File file) {
        try {
            Os.lstat(file.getAbsolutePath());
            return true;
        } catch (ErrnoException failure) {
            return failure.errno != OsConstants.ENOENT;
        }
    }

    private static void deletePrivateFile(File file) {
        if (file == null) return;
        try {
            if (Os.lstat(file.getAbsolutePath()) != null) file.delete();
        } catch (Throwable ignored) { }
    }

    private static final class NonClosingOutputStream extends FilterOutputStream {
        NonClosingOutputStream(OutputStream output) { super(output); }
        @Override public void close() throws IOException { flush(); }
    }

    private static final class Snapshot {
        final byte[] seed;
        final byte[] xml;
        final KeyboxInfo info;
        Snapshot(byte[] seed, byte[] xml, KeyboxInfo info) {
            this.seed = seed;
            this.xml = xml;
            this.info = info;
        }
        void destroy() {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(xml, (byte) 0);
            info.destroy();
        }
    }

    private static final class KeyboxInfo {
        final boolean rsa;
        final boolean ecdsa;
        final int rsaChainCount;
        final int ecdsaChainCount;
        final List<byte[]> terminalCertificates;
        KeyboxInfo(boolean rsa, boolean ecdsa, int rsaChainCount, int ecdsaChainCount,
                   List<byte[]> terminalCertificates) {
            this.rsa = rsa;
            this.ecdsa = ecdsa;
            this.rsaChainCount = rsaChainCount;
            this.ecdsaChainCount = ecdsaChainCount;
            this.terminalCertificates = terminalCertificates;
        }
        static KeyboxInfo empty() {
            return new KeyboxInfo(false, false, 0, 0, new ArrayList<>());
        }
        KeyboxInfo copy() {
            List<byte[]> roots = new ArrayList<>();
            for (byte[] root : terminalCertificates) roots.add(root.clone());
            return new KeyboxInfo(rsa, ecdsa, rsaChainCount, ecdsaChainCount, roots);
        }
        void destroy() {
            for (byte[] root : terminalCertificates) Arrays.fill(root, (byte) 0);
            terminalCertificates.clear();
        }
    }

    private static final class AlgorithmInfo {
        final int chainCount;
        final byte[] terminal;
        AlgorithmInfo(int chainCount, byte[] terminal) {
            this.chainCount = chainCount;
            this.terminal = terminal;
        }
    }

    private static final class Pem {
        final String label;
        final byte[] der;
        Pem(String label, byte[] der) { this.label = label; this.der = der; }
        void destroy() { Arrays.fill(der, (byte) 0); }
    }

    private static final class KeyboxFailure extends Exception {
        final String code;
        KeyboxFailure(String code) { this.code = code; }
    }
}
