package dev.xenoid.daemon;

import android.content.Context;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The sole persistence and migration owner for proxy desired state.
 *
 * <p>The manager above this class owns runtime policy. This class owns only the app-private,
 * fail-closed desired-state transaction. It deliberately has no public API and no production test
 * endpoint. Tests may inject the two package-private backends; production always uses no-follow
 * {@link Os} operations, AndroidKeyStore for the one-way v1 read, and {@link SecureRandom}.</p>
 */
final class ProxyStateStore {
    static final int SCHEMA_VERSION = 2;
    static final int MAX_SOURCE_BYTES = 1024 * 1024;
    static final int MAX_SELECTED_NODE_BYTES = 512;
    static final int MAX_STATE_BYTES = 1536 * 1024;
    static final int MAX_PENDING_BYTES = 4 * 1024 * 1024;
    static final int MAX_EVIDENCE_BYTES = 64 * 1024;
    static final int MAX_DIRECTORY_ENTRIES = 4096;
    static final String LEGACY_KEY_ALIAS = "dev.xenoid.daemon.proxy.desired.v1";

    static final String ROOT_DIRECTORY = "proxy-state";
    static final String VERSION_DIRECTORY = "v2";
    static final String KEY_DIRECTORY = "keys";
    static final String STATE_DIRECTORY = "states";
    static final String EVIDENCE_DIRECTORY = "evidence";
    static final String QUARANTINE_DIRECTORY = "quarantine";
    static final String ACTIVE_NAME = "active.json";
    static final String PENDING_NAME = "pending.json";

    private static final int DIRECTORY_MODE = 0700;
    private static final int FILE_MODE = 0600;
    private static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_EVIDENCE_DIGESTS = 64;
    private static final String V1_AAD_PREFIX = "XENOID-PROXY-STATE-V1\n";
    private static final String V2_AAD_PREFIX = "XENOID-PROXY-STATE-V2\n";

    private static final Pattern UUID_V4 = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Pattern HEX_32 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern HEX_64 = Pattern.compile("[0-9a-f]{64}");
    private static final Set<String> OPERATIONS = immutableSet(
            "initialize", "update", "migrate", "recover", "clear");
    private static final List<String> PHASES = Collections.unmodifiableList(Arrays.asList(
            "prepared", "objects_materialized", "pointer_activated",
            "evidence_recorded", "cleaned"));

    private final File noBackupDirectory;
    private final File rootDirectory;
    private final File keyDirectory;
    private final File stateDirectory;
    private final File evidenceDirectory;
    private final File quarantineDirectory;
    private final File activeFile;
    private final File pendingFile;
    private final File legacyStateFile;
    private final FilesystemBackend filesystem;
    private final KeyBackend keys;

    static ProxyStateStore open(Context context) {
        Context application = context.getApplicationContext();
        File legacy = new File(new File(application.getFilesDir(), ROOT_DIRECTORY),
                "desired-v1.json");
        return new ProxyStateStore(application.getNoBackupFilesDir(), legacy,
                new OsFilesystemBackend(), new AndroidKeyBackend());
    }

    ProxyStateStore(
            File noBackupDirectory,
            File legacyStateFile,
            FilesystemBackend filesystem,
            KeyBackend keys) {
        this.noBackupDirectory = noBackupDirectory;
        this.rootDirectory = new File(new File(noBackupDirectory, ROOT_DIRECTORY), VERSION_DIRECTORY);
        this.keyDirectory = new File(rootDirectory, KEY_DIRECTORY);
        this.stateDirectory = new File(rootDirectory, STATE_DIRECTORY);
        this.evidenceDirectory = new File(rootDirectory, EVIDENCE_DIRECTORY);
        this.quarantineDirectory = new File(rootDirectory, QUARANTINE_DIRECTORY);
        this.activeFile = new File(rootDirectory, ACTIVE_NAME);
        this.pendingFile = new File(rootDirectory, PENDING_NAME);
        this.legacyStateFile = legacyStateFile;
        this.filesystem = filesystem;
        this.keys = keys;
    }

    /** Loads a verified v2 state, resumes a valid transaction, or reports that a pin is required. */
    synchronized LoadedState load() throws StateException {
        try {
            ensureLayout();
            validateRootEntries();
            if (exists(pendingFile)) {
                Pending pending = readPending();
                resume(pending);
            }
            if (exists(activeFile)) {
                ActiveRecord active = readActive();
                try {
                    return active.loaded;
                } finally {
                    wipe(active.keyMaterial);
                }
            }
            if (!v2ObjectDirectoriesEmpty()) {
                throw invalid();
            }
            if (legacyStateFile != null && exists(legacyStateFile)) {
                LegacyRecord legacy = readLegacy();
                try {
                    if (legacy.instanceId == null) {
                        return LoadedState.requiresInstanceId(legacy.generation);
                    }
                    return migrateLegacy(legacy, legacy.instanceId);
                } finally {
                    legacy.close();
                }
            }
            return LoadedState.requiresInstanceId(0);
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    /**
     * Pins a genuinely fresh state, or finishes a verified legacy state whose v1 instance was null.
     */
    synchronized LoadedState bindInstance(String instanceId) throws StateException {
        requireInstanceId(instanceId);
        try {
            ensureLayout();
            validateRootEntries();
            if (exists(pendingFile)) {
                resume(readPending());
            }
            if (exists(activeFile)) {
                ActiveRecord active = readActive();
                try {
                    if (!instanceId.equals(active.loaded.instanceId)) throw invalid();
                    return active.loaded;
                } finally {
                    wipe(active.keyMaterial);
                }
            }
            if (!v2ObjectDirectoriesEmpty()) throw invalid();
            if (legacyStateFile != null && exists(legacyStateFile)) {
                LegacyRecord legacy = readLegacy();
                try {
                    if (legacy.instanceId != null && !instanceId.equals(legacy.instanceId)) {
                        throw invalid();
                    }
                    return migrateLegacy(legacy, instanceId);
                } finally {
                    legacy.close();
                }
            }
            byte[] key = newRandomKey();
            try {
                Transaction transaction = createTransaction(
                        "initialize", instanceId, 0, false, null, null, key,
                        Collections.<String>emptyList(), Collections.<String>emptyList());
                return commit(transaction);
            } finally {
                wipe(key);
            }
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        }
    }

    /** Ordinary source/select/on/off mutation. The current v2 key is deliberately reused. */
    synchronized LoadedState update(String instanceId, boolean enabled, Source source)
            throws StateException {
        requireInstanceId(instanceId);
        validateSourceState(enabled, source);
        ActiveRecord active = requireActiveForMutation(instanceId);
        try {
            long generation = increment(active.loaded.generation);
            Transaction transaction = createTransaction(
                    "update", instanceId, generation, enabled, source,
                    active.pointerBytes, active.keyMaterial,
                    Collections.<String>emptyList(), Collections.<String>emptyList());
            return commit(transaction);
        } finally {
            wipe(active.keyMaterial);
        }
    }

    /**
     * Authenticated import. A healthy state is an ordinary update; an unreadable state is displaced
     * into raw quarantine and recovered with a new cryptographic key.
     */
    synchronized LoadedState recoverImport(String instanceId, boolean enabled, Source source)
            throws StateException {
        requireInstanceId(instanceId);
        if (source == null) throw invalid();
        validateSourceState(enabled, source);
        try {
            LoadedState current = load();
            if (current.requiresInstanceId) {
                bindInstance(instanceId);
            } else if (!instanceId.equals(current.instanceId)) {
                throw invalid();
            }
            return update(instanceId, enabled, source);
        } catch (StateException failure) {
            if (!isRecoverableStateFailure(failure)) throw failure;
            return recoverUnreadable(instanceId, enabled, source, "recover");
        }
    }

    /**
     * Clears a healthy state normally. Only an explicit discard flag may perform source-less
     * evidence-preserving recovery of unreadable state.
     */
    synchronized LoadedState clear(String instanceId, boolean discardUnreadableState)
            throws StateException {
        requireInstanceId(instanceId);
        try {
            LoadedState current = load();
            if (current.requiresInstanceId) {
                if (!discardUnreadableState) return bindInstance(instanceId);
                bindInstance(instanceId);
                return updateClear(instanceId);
            }
            if (!instanceId.equals(current.instanceId)) throw invalid();
            return updateClear(instanceId);
        } catch (StateException failure) {
            if (!discardUnreadableState || !isRecoverableStateFailure(failure)) throw failure;
            return recoverUnreadable(instanceId, false, null, "clear");
        }
    }

    private LoadedState updateClear(String instanceId) throws StateException {
        ActiveRecord active = requireActiveForMutation(instanceId);
        byte[] newKey = newRandomKey();
        try {
            Map<String, Object> pointer = parseCanonicalObject(
                    active.pointerBytes, MAX_STATE_BYTES);
            String oldKeyId = requireHex64(pointer, "keyId");
            String oldStateId = requireHex64(pointer, "stateId");
            if (oldKeyId.equals(sha256Hex(newKey))) throw commitFailure();
            long generation = increment(active.loaded.generation);
            Transaction transaction = createTransaction(
                    "clear", instanceId, generation, false, null,
                    active.pointerBytes, newKey,
                    Arrays.asList(sha256Hex(active.pointerBytes), oldKeyId, oldStateId),
                    Collections.singletonList("keyObject:" + oldKeyId));
            return commit(transaction);
        } finally {
            wipe(newKey);
            wipe(active.keyMaterial);
        }
    }

    private LoadedState recoverUnreadable(
            String instanceId, boolean enabled, Source source, String operation)
            throws StateException {
        RecoveryMaterial recovery = quarantineInvalidControls(instanceId);
        byte[] key = newRandomKey();
        try {
            Transaction transaction = createTransaction(
                    operation, instanceId, recovery.nextGeneration, enabled, source,
                    null, key, recovery.evidenceDigests,
                    Collections.singletonList("legacyAlias"));
            return commit(transaction);
        } finally {
            wipe(key);
        }
    }

    private LoadedState migrateLegacy(LegacyRecord legacy, String instanceId)
            throws StateException {
        byte[] newKey = newRandomKey();
        try {
            List<String> evidence = Collections.singletonList(sha256Hex(legacy.rawBytes));
            List<String> deletions = Arrays.asList(
                    "legacyState:" + sha256Hex(legacy.rawBytes), "legacyAlias");
            Transaction transaction = createTransaction(
                    "migrate", instanceId, legacy.generation, legacy.enabled, legacy.source,
                    null, newKey, evidence, deletions);
            return commit(transaction);
        } finally {
            wipe(newKey);
        }
    }

    private ActiveRecord requireActiveForMutation(String instanceId) throws StateException {
        try {
            ensureLayout();
            validateRootEntries();
            if (exists(pendingFile)) resume(readPending());
            if (!exists(activeFile)) throw invalid();
            ActiveRecord active = readActive();
            if (!instanceId.equals(active.loaded.instanceId)) {
                wipe(active.keyMaterial);
                throw invalid();
            }
            return active;
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    private Transaction createTransaction(
            String operation,
            String instanceId,
            long generation,
            boolean enabled,
            Source source,
            byte[] previousPointerBytes,
            byte[] currentOrNewKey,
            List<String> evidenceDigests,
            List<String> deleteEntries) throws StateException {
        validateSourceState(enabled, source);
        if (!OPERATIONS.contains(operation) || generation < 0) throw invalid();
        byte[] key = currentOrNewKey;
        if (key == null || key.length != KEY_BYTES) throw keyMismatch();
        String keyId = sha256Hex(key);
        Map<String, Object> envelope = createStateEnvelope(
                instanceId, generation, enabled, source, keyId, key);
        byte[] envelopeBytes = canonicalBytes(envelope);
        if (envelopeBytes.length <= 0 || envelopeBytes.length > MAX_STATE_BYTES) throw invalid();
        String stateId = sha256Hex(envelopeBytes);
        Map<String, Object> pointer = map(
                "schemaVersion", (long) SCHEMA_VERSION,
                "instanceId", instanceId,
                "stateId", stateId,
                "keyId", keyId);

        boolean newKey = previousPointerBytes == null || "clear".equals(operation);
        String targetKeyMaterial = newKey ? Base64.getEncoder().encodeToString(key) : null;
        String previousDigest = previousPointerBytes == null
                ? null : sha256Hex(previousPointerBytes);
        String transactionId = randomHex(16);
        List<String> sortedEvidence = sortedUniqueDigests(evidenceDigests);
        List<String> deletions = validateDeleteEntries(deleteEntries);

        Pending pending = new Pending(
                instanceId, transactionId, operation, "prepared", previousDigest,
                pointer, targetKeyMaterial, envelope, sortedEvidence, deletions);
        validatePendingSemantics(pending);
        return new Transaction(pending, source);
    }

    private LoadedState commit(Transaction transaction) throws StateException {
        try {
            if (exists(pendingFile)) throw invalid();
            writeNewCanonical(pendingFile, transaction.pending.toMap(), MAX_PENDING_BYTES);
            // Before returning or dropping caller plaintext, prove that the journal ciphertext
            // decrypts to the exact requested source.
            Pending first = readPending();
            byte[] key = keyForPending(first);
            try {
                LoadedState decoded = decodeTarget(first, key);
                if (!sameSource(transaction.expectedSource, decoded.source)) throw invalid();
            } finally {
                wipe(key);
            }
            resume(first);
            ActiveRecord active = readActive();
            try {
                return active.loaded;
            } finally {
                wipe(active.keyMaterial);
            }
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        }
    }

    private void resume(Pending initial) throws StateException {
        Pending pending = initial;
        try {
            ActiveDisposition disposition = activeDisposition(pending);
            if (disposition == ActiveDisposition.THIRD) throw invalid();
            validatePreviousTransition(pending, disposition);

            materializeObjects(pending);
            if (phaseIndex(pending.phase) < phaseIndex("objects_materialized")) {
                pending = replacePendingPhase(pending, "objects_materialized");
            }

            disposition = activeDisposition(pending);
            if (disposition == ActiveDisposition.THIRD) throw invalid();
            if (disposition == ActiveDisposition.PREVIOUS) {
                replaceCanonical(activeFile, pending.targetActive, MAX_STATE_BYTES);
            }
            // A target pointer is accepted only after a full pointer/key/state/decrypt reload.
            ActiveRecord activated = readActive();
            byte[] targetBytes = canonicalBytes(pending.targetActive);
            try {
                if (!Arrays.equals(targetBytes, activated.pointerBytes)) throw invalid();
            } finally {
                wipe(targetBytes);
                wipe(activated.keyMaterial);
            }
            if (phaseIndex(pending.phase) < phaseIndex("pointer_activated")) {
                pending = replacePendingPhase(pending, "pointer_activated");
            }

            writeEvidence(pending);
            if (phaseIndex(pending.phase) < phaseIndex("evidence_recorded")) {
                pending = replacePendingPhase(pending, "evidence_recorded");
            }

            performCleanup(pending);
            if (phaseIndex(pending.phase) < phaseIndex("cleaned")) {
                pending = replacePendingPhase(pending, "cleaned");
            }

            byte[] exactPending = canonicalBytes(pending.toMap());
            try {
                deleteExact(pendingFile, exactPending, MAX_PENDING_BYTES);
            } finally {
                wipe(exactPending);
            }
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        }
    }

    private void materializeObjects(Pending pending) throws Exception {
        byte[] key = keyForPending(pending);
        try {
            String keyId = requireString(pending.targetActive, "keyId");
            byte[] stateBytes = canonicalBytes(pending.targetStateEnvelope);
            String stateId = requireString(pending.targetActive, "stateId");
            if (!keyId.equals(sha256Hex(key)) || !stateId.equals(sha256Hex(stateBytes))) {
                throw keyMismatch();
            }
            writeImmutable(new File(keyDirectory, keyId + ".key"), key, KEY_BYTES);
            writeImmutable(new File(stateDirectory, stateId + ".json"), stateBytes,
                    MAX_STATE_BYTES);
            decodeTarget(pending, key);
        } finally {
            wipe(key);
        }
    }

    private byte[] keyForPending(Pending pending) throws Exception {
        String keyId = requireString(pending.targetActive, "keyId");
        if (pending.targetKeyMaterial != null) {
            byte[] key = decodeBase64(pending.targetKeyMaterial, KEY_BYTES, KEY_BYTES);
            if (!keyId.equals(sha256Hex(key))) {
                wipe(key);
                throw keyMismatch();
            }
            return key;
        }
        File file = new File(keyDirectory, keyId + ".key");
        byte[] key = readStrictFile(file, KEY_BYTES, KEY_BYTES);
        if (!keyId.equals(sha256Hex(key))) {
            wipe(key);
            throw keyMismatch();
        }
        return key;
    }

    private LoadedState decodeTarget(Pending pending, byte[] key) throws StateException {
        byte[] bytes = canonicalBytes(pending.targetStateEnvelope);
        return decodeStateEnvelope(bytes, pending.targetStateEnvelope, key,
                requireString(pending.targetActive, "instanceId"),
                requireString(pending.targetActive, "keyId"));
    }

    private ActiveDisposition activeDisposition(Pending pending) throws Exception {
        Metadata metadata = filesystem.lstat(activeFile);
        byte[] target = canonicalBytes(pending.targetActive);
        String targetDigest = sha256Hex(target);
        if (!metadata.exists) {
            return pending.previousActiveSha256 == null
                    ? ActiveDisposition.PREVIOUS : ActiveDisposition.THIRD;
        }
        byte[] active = readStrictFile(activeFile, 1, MAX_STATE_BYTES);
        String digest = sha256Hex(active);
        if (digest.equals(targetDigest) && Arrays.equals(active, target)) {
            return ActiveDisposition.TARGET;
        }
        if (pending.previousActiveSha256 != null
                && digest.equals(pending.previousActiveSha256)) {
            return ActiveDisposition.PREVIOUS;
        }
        return ActiveDisposition.THIRD;
    }

    private Pending replacePendingPhase(Pending pending, String phase) throws Exception {
        int current = phaseIndex(pending.phase);
        int target = phaseIndex(phase);
        if (target != current + 1) throw invalid();
        Pending next = pending.withPhase(phase);
        replaceCanonical(pendingFile, next.toMap(), MAX_PENDING_BYTES);
        return readPending();
    }

    private void writeEvidence(Pending pending) throws Exception {
        Map<String, Object> evidence = map(
                "schemaVersion", (long) SCHEMA_VERSION,
                "instanceId", pending.instanceId,
                "transactionId", pending.transactionId,
                "operation", pending.operation,
                "digests", new ArrayList<Object>(pending.evidenceDigests));
        File target = new File(evidenceDirectory, pending.transactionId + ".json");
        byte[] bytes = canonicalBytes(evidence);
        if (bytes.length > MAX_EVIDENCE_BYTES) throw invalid();
        writeImmutable(target, bytes, MAX_EVIDENCE_BYTES);
    }

    private void performCleanup(Pending pending) throws Exception {
        for (String entry : pending.deleteEntries) {
            if (entry.startsWith("legacyState:")) {
                String digest = entry.substring("legacyState:".length());
                if (!HEX_64.matcher(digest).matches() || legacyStateFile == null) throw invalid();
                Metadata metadata = filesystem.lstat(legacyStateFile);
                if (metadata.exists) {
                    byte[] bytes = readStrictFile(legacyStateFile, 1, MAX_STATE_BYTES);
                    try {
                        if (!digest.equals(sha256Hex(bytes))) throw invalid();
                        deleteExact(legacyStateFile, bytes, MAX_STATE_BYTES);
                    } finally {
                        wipe(bytes);
                    }
                }
            } else if (entry.startsWith("keyObject:")) {
                String keyId = entry.substring("keyObject:".length());
                if (!HEX_64.matcher(keyId).matches()
                        || keyId.equals(requireString(pending.targetActive, "keyId"))) {
                    throw invalid();
                }
                File oldKey = new File(keyDirectory, keyId + ".key");
                if (filesystem.lstat(oldKey).exists) {
                    byte[] bytes = readStrictFile(oldKey, KEY_BYTES, KEY_BYTES);
                    try {
                        if (!keyId.equals(sha256Hex(bytes))) throw keyMismatch();
                        deleteExact(oldKey, bytes, KEY_BYTES);
                    } finally {
                        wipe(bytes);
                    }
                }
            } else if ("legacyAlias".equals(entry)) {
                keys.deleteLegacyAlias();
            } else {
                throw invalid();
            }
        }
    }

    private ActiveRecord readActive() throws StateException {
        byte[] pointerBytes = null;
        byte[] key = null;
        try {
            pointerBytes = readStrictFile(activeFile, 1, MAX_STATE_BYTES);
            Map<String, Object> pointer = parseCanonicalObject(pointerBytes, MAX_STATE_BYTES);
            requireExactKeys(pointer, "schemaVersion", "instanceId", "stateId", "keyId");
            requireLong(pointer, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
            String instanceId = requireInstanceId(requireString(pointer, "instanceId"));
            String stateId = requireHex64(pointer, "stateId");
            String keyId = requireHex64(pointer, "keyId");
            if (!filesystem.lstat(new File(keyDirectory, keyId + ".key")).exists) {
                throw keyMismatch();
            }

            File keyFile = new File(keyDirectory, keyId + ".key");
            key = readStrictFile(keyFile, KEY_BYTES, KEY_BYTES);
            if (!keyId.equals(sha256Hex(key))) throw keyMismatch();

            File stateFile = new File(stateDirectory, stateId + ".json");
            if (!filesystem.lstat(stateFile).exists) throw keyMismatch();
            byte[] stateBytes = readStrictFile(stateFile, 1, MAX_STATE_BYTES);
            try {
                if (!stateId.equals(sha256Hex(stateBytes))) throw keyMismatch();
                Map<String, Object> envelope = parseCanonicalObject(stateBytes, MAX_STATE_BYTES);
                LoadedState loaded = decodeStateEnvelope(
                        stateBytes, envelope, key, instanceId, keyId);
                return new ActiveRecord(loaded, pointerBytes, key);
            } finally {
                wipe(stateBytes);
            }
        } catch (StateException failure) {
            wipe(pointerBytes);
            wipe(key);
            throw failure;
        } catch (Throwable failure) {
            wipe(pointerBytes);
            wipe(key);
            throw invalid();
        }
    }

    private LoadedState decodeStateEnvelope(
            byte[] rawEnvelope,
            Map<String, Object> envelope,
            byte[] key,
            String pointerInstance,
            String pointerKeyId) throws StateException {
        try {
            requireExactKeys(envelope, "schemaVersion", "instanceId", "generation", "enabled",
                    "keyId", "sourceIv", "sourceCiphertext");
            requireLong(envelope, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
            String instanceId = requireInstanceId(requireString(envelope, "instanceId"));
            if (!instanceId.equals(pointerInstance)) throw keyMismatch();
            long generation = requireLong(envelope, "generation", 0, Long.MAX_VALUE);
            boolean enabled = requireBoolean(envelope, "enabled");
            String keyId = requireHex64(envelope, "keyId");
            if (!keyId.equals(pointerKeyId) || !keyId.equals(sha256Hex(key))) {
                throw keyMismatch();
            }
            Object ivValue = envelope.get("sourceIv");
            Object ciphertextValue = envelope.get("sourceCiphertext");
            Source source = null;
            if (ivValue == null || ciphertextValue == null) {
                if (ivValue != null || ciphertextValue != null || enabled) throw invalid();
            } else {
                if (!(ivValue instanceof String) || !(ciphertextValue instanceof String)) {
                    throw invalid();
                }
                byte[] iv = decodeBase64((String) ivValue, IV_BYTES, IV_BYTES);
                byte[] ciphertext = decodeBase64(
                        (String) ciphertextValue, GCM_TAG_BITS / 8,
                        MAX_SOURCE_BYTES + 4096);
                byte[] aad = stateAad(instanceId, generation);
                byte[] plaintext = null;
                try {
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                            new GCMParameterSpec(GCM_TAG_BITS, iv));
                    cipher.updateAAD(aad);
                    plaintext = cipher.doFinal(ciphertext);
                    source = decodeSource(plaintext);
                } catch (AEADBadTagException failure) {
                    throw invalid();
                } finally {
                    wipe(iv);
                    wipe(ciphertext);
                    wipe(aad);
                    wipe(plaintext);
                }
            }
            validateSourceState(enabled, source);
            if (!Arrays.equals(rawEnvelope, canonicalBytes(envelope))) throw invalid();
            return new LoadedState(false, instanceId, generation, enabled, source);
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    private Pending readPending() throws StateException {
        try {
            byte[] bytes = readStrictFile(pendingFile, 1, MAX_PENDING_BYTES);
            Map<String, Object> object;
            try {
                object = parseCanonicalObject(bytes, MAX_PENDING_BYTES);
            } finally {
                wipe(bytes);
            }
            return pendingFromObject(object);
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    private Pending pendingFromObject(Map<String, Object> object)
            throws StateException {
        requireExactKeys(object,
                "schemaVersion", "instanceId", "transactionId", "operation", "phase",
                "previousActiveSha256", "targetActive", "targetKeyMaterial",
                "targetStateEnvelope", "evidenceDigests", "deleteEntries");
        requireLong(object, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
        String instanceId = requireInstanceId(requireString(object, "instanceId"));
        String transactionId = requireString(object, "transactionId");
        if (!HEX_32.matcher(transactionId).matches()) throw invalid();
        String operation = requireString(object, "operation");
        String phase = requireString(object, "phase");
        String previous = nullableHex64(object.get("previousActiveSha256"));
        Map<String, Object> targetActive = requireObject(object, "targetActive");
        String targetKeyMaterial = nullableString(object.get("targetKeyMaterial"));
        Map<String, Object> targetState = requireObject(object, "targetStateEnvelope");
        List<String> evidence = requireDigestList(object, "evidenceDigests");
        List<String> deletions = requireStringList(object, "deleteEntries", 8);
        Pending pending = new Pending(instanceId, transactionId, operation, phase, previous,
                targetActive, targetKeyMaterial, targetState, evidence, deletions);
        validatePendingSemantics(pending);
        return pending;
    }

    private void validatePendingSemantics(Pending pending) throws StateException {
        if (!OPERATIONS.contains(pending.operation) || phaseIndex(pending.phase) < 0) throw invalid();
        requireExactKeys(pending.targetActive, "schemaVersion", "instanceId", "stateId", "keyId");
        requireLong(pending.targetActive, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
        if (!pending.instanceId.equals(requireInstanceId(
                requireString(pending.targetActive, "instanceId")))) throw invalid();
        String stateId = requireHex64(pending.targetActive, "stateId");
        String keyId = requireHex64(pending.targetActive, "keyId");
        byte[] envelopeBytes = canonicalBytes(pending.targetStateEnvelope);
        if (!stateId.equals(sha256Hex(envelopeBytes))) throw invalid();
        requireExactKeys(pending.targetStateEnvelope, "schemaVersion", "instanceId", "generation",
                "enabled", "keyId", "sourceIv", "sourceCiphertext");
        requireLong(pending.targetStateEnvelope, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
        if (!pending.instanceId.equals(requireInstanceId(
                requireString(pending.targetStateEnvelope, "instanceId")))) throw invalid();
        requireLong(pending.targetStateEnvelope, "generation", 0, Long.MAX_VALUE);
        if (!keyId.equals(requireHex64(pending.targetStateEnvelope, "keyId"))) throw keyMismatch();
        boolean hasPrevious = pending.previousActiveSha256 != null;
        boolean hasNewKey = pending.targetKeyMaterial != null;
        if (hasNewKey) {
            byte[] key = decodeBase64(pending.targetKeyMaterial, KEY_BYTES, KEY_BYTES);
            try {
                if (!keyId.equals(sha256Hex(key))) throw keyMismatch();
            } finally {
                wipe(key);
            }
        }
        if ("update".equals(pending.operation)) {
            if (!hasPrevious || hasNewKey) throw invalid();
        } else if ("initialize".equals(pending.operation)
                || "migrate".equals(pending.operation)
                || "recover".equals(pending.operation)) {
            if (hasPrevious || !hasNewKey) throw invalid();
        } else if ("clear".equals(pending.operation)) {
            if (!hasNewKey) throw invalid();
        }
        long targetGeneration = requireLong(
                pending.targetStateEnvelope, "generation", 0, Long.MAX_VALUE);
        if ("initialize".equals(pending.operation) && targetGeneration != 0) throw invalid();
        if (!pending.evidenceDigests.equals(sortedUniqueDigests(pending.evidenceDigests))) {
            throw invalid();
        }
        if (!pending.deleteEntries.equals(validateDeleteEntries(pending.deleteEntries))) {
            throw invalid();
        }
        int keyDeletes = countEntries(pending.deleteEntries, "keyObject:");
        int legacyDeletes = countEntries(pending.deleteEntries, "legacyState:");
        boolean deletesAlias = pending.deleteEntries.contains("legacyAlias");
        if ("initialize".equals(pending.operation) || "update".equals(pending.operation)) {
            if (!pending.deleteEntries.isEmpty()) throw invalid();
        } else if ("migrate".equals(pending.operation)) {
            if (legacyDeletes != 1 || keyDeletes != 0 || !deletesAlias
                    || pending.deleteEntries.size() != 2) throw invalid();
        } else if ("recover".equals(pending.operation)) {
            if (hasPrevious || keyDeletes != 0 || legacyDeletes != 0 || !deletesAlias
                    || pending.deleteEntries.size() != 1) throw invalid();
        } else if ("clear".equals(pending.operation)) {
            if (hasPrevious) {
                if (keyDeletes != 1 || legacyDeletes != 0 || deletesAlias
                        || pending.deleteEntries.size() != 1) throw invalid();
            } else if (keyDeletes != 0 || legacyDeletes != 0 || !deletesAlias
                    || pending.deleteEntries.size() != 1) {
                throw invalid();
            }
        }
    }

    private static int countEntries(List<String> entries, String prefix) {
        int count = 0;
        for (String entry : entries) if (entry.startsWith(prefix)) count++;
        return count;
    }

    private void validatePreviousTransition(
            Pending pending, ActiveDisposition disposition) throws Exception {
        if (disposition != ActiveDisposition.PREVIOUS
                || pending.previousActiveSha256 == null) {
            return;
        }
        ActiveRecord previous = readActive();
        try {
            if (!pending.previousActiveSha256.equals(sha256Hex(previous.pointerBytes))
                    || !pending.instanceId.equals(previous.loaded.instanceId)) {
                throw invalid();
            }
            long targetGeneration = requireLong(
                    pending.targetStateEnvelope, "generation", 0, Long.MAX_VALUE);
            if (targetGeneration != increment(previous.loaded.generation)) throw invalid();
            String targetKeyId = requireString(pending.targetActive, "keyId");
            String previousKeyId = sha256Hex(previous.keyMaterial);
            if ("update".equals(pending.operation)) {
                if (pending.targetKeyMaterial != null
                        || !targetKeyId.equals(previousKeyId)) throw keyMismatch();
            } else if ("clear".equals(pending.operation)) {
                if (pending.targetKeyMaterial == null
                        || targetKeyId.equals(previousKeyId)) throw keyMismatch();
            } else {
                throw invalid();
            }
        } finally {
            wipe(previous.keyMaterial);
        }
    }

    private Map<String, Object> createStateEnvelope(
            String instanceId,
            long generation,
            boolean enabled,
            Source source,
            String keyId,
            byte[] key) throws StateException {
        String encodedIv = null;
        String encodedCiphertext = null;
        if (source != null) {
            byte[] plaintext = encodeSource(source);
            byte[] iv = null;
            byte[] aad = null;
            byte[] ciphertext = null;
            try {
                iv = keys.randomBytes(IV_BYTES);
                if (iv == null || iv.length != IV_BYTES) throw commitFailure();
                aad = stateAad(instanceId, generation);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, iv));
                cipher.updateAAD(aad);
                ciphertext = cipher.doFinal(plaintext);
                encodedIv = Base64.getEncoder().encodeToString(iv);
                encodedCiphertext = Base64.getEncoder().encodeToString(ciphertext);
            } catch (StateException failure) {
                throw failure;
            } catch (Throwable failure) {
                throw commitFailure();
            } finally {
                wipe(plaintext);
                wipe(iv);
                wipe(aad);
                wipe(ciphertext);
            }
        }
        return map(
                "schemaVersion", (long) SCHEMA_VERSION,
                "instanceId", instanceId,
                "generation", generation,
                "enabled", enabled,
                "keyId", keyId,
                "sourceIv", encodedIv,
                "sourceCiphertext", encodedCiphertext);
    }

    private byte[] encodeSource(Source source) throws StateException {
        validateSource(source);
        Map<String, Object> object = map(
                "kind", source.kind,
                "source", source.value,
                "selectedNode", source.selectedNode,
                "udpAllowed", source.udpAllowed,
                "allowInsecureHttp", source.allowInsecureHttp);
        byte[] bytes = canonicalBytes(object);
        if (bytes.length > MAX_SOURCE_BYTES + 2048) {
            wipe(bytes);
            throw invalid();
        }
        return bytes;
    }

    private Source decodeSource(byte[] plaintext) throws StateException {
        if (plaintext == null || plaintext.length <= 0 || plaintext.length > MAX_SOURCE_BYTES + 2048) {
            throw invalid();
        }
        Map<String, Object> object = parseCanonicalObject(plaintext, MAX_SOURCE_BYTES + 2048);
        requireExactKeys(object, "kind", "source", "selectedNode", "udpAllowed",
                "allowInsecureHttp");
        Source source = new Source(
                requireString(object, "kind"),
                requireString(object, "source"),
                requireString(object, "selectedNode"),
                requireBoolean(object, "udpAllowed"),
                requireBoolean(object, "allowInsecureHttp"));
        validateSource(source);
        return source;
    }

    private LegacyRecord readLegacy() throws StateException {
        byte[] raw = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] aad = null;
        byte[] plaintext = null;
        try {
            raw = readStrictFile(legacyStateFile, 1, MAX_STATE_BYTES);
            Map<String, Object> object = parseObject(raw, MAX_STATE_BYTES);
            requireExactKeys(object, "schemaVersion", "instanceId", "generation", "enabled",
                    "sourceIv", "sourceCiphertext");
            requireLong(object, "schemaVersion", 1, 1);
            String instanceId = null;
            Object identity = object.get("instanceId");
            if (identity != null) instanceId = requireInstanceId(String.valueOf(identity));
            long generation = requireLong(object, "generation", 0, Long.MAX_VALUE);
            boolean enabled = requireBoolean(object, "enabled");
            Object ivObject = object.get("sourceIv");
            Object ciphertextObject = object.get("sourceCiphertext");
            Source source = null;
            if (ivObject == null || ciphertextObject == null) {
                if (ivObject != null || ciphertextObject != null || enabled) throw invalid();
            } else {
                if (!(ivObject instanceof String) || !(ciphertextObject instanceof String)) {
                    throw invalid();
                }
                iv = decodeBase64((String) ivObject, IV_BYTES, IV_BYTES);
                ciphertext = decodeBase64((String) ciphertextObject, GCM_TAG_BITS / 8,
                        MAX_SOURCE_BYTES + 4096);
                aad = legacyAad(instanceId, generation);
                try {
                    plaintext = keys.decryptLegacy(iv, ciphertext, aad);
                } catch (KeyUnavailableException failure) {
                    throw keyUnusable();
                } catch (Throwable failure) {
                    throw keyUnusable();
                }
                source = decodeLegacySource(plaintext);
            }
            validateSourceState(enabled, source);
            byte[] retained = raw;
            raw = null;
            return new LegacyRecord(instanceId, generation, enabled, source, retained);
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        } finally {
            wipe(raw);
            wipe(iv);
            wipe(ciphertext);
            wipe(aad);
            wipe(plaintext);
        }
    }

    private Source decodeLegacySource(byte[] plaintext) throws Exception {
        if (plaintext == null || plaintext.length <= 0 || plaintext.length > MAX_SOURCE_BYTES + 1024) {
            throw invalid();
        }
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
        if (input.readInt() != 1) throw invalid();
        String kind = readLegacyString(input, 16);
        String value = readLegacyString(input, MAX_SOURCE_BYTES);
        String selectedNode = readLegacyString(input, MAX_SELECTED_NODE_BYTES);
        boolean udpAllowed = input.readBoolean();
        boolean allowInsecureHttp = input.readBoolean();
        if (input.read() != -1) throw invalid();
        Source source = new Source(kind, value, selectedNode, udpAllowed, allowInsecureHttp);
        validateSource(source);
        return source;
    }

    private static String readLegacyString(DataInputStream input, int maximum) throws Exception {
        int length = input.readInt();
        if (length < 0 || length > maximum) throw new EOFException();
        byte[] bytes = new byte[length];
        try {
            input.readFully(bytes);
            return decodeUtf8(bytes);
        } finally {
            wipe(bytes);
        }
    }

    private RecoveryMaterial quarantineInvalidControls(String instanceId) throws StateException {
        try {
            ensureLayout();
            List<String> evidence = new ArrayList<>();
            long highestGeneration = -1;
            File[] controls = legacyStateFile == null
                    ? new File[] {pendingFile, activeFile}
                    : new File[] {pendingFile, activeFile, legacyStateFile};
            for (File control : controls) {
                Metadata metadata = filesystem.lstat(control);
                if (!metadata.exists) continue;
                if (!metadata.regular || metadata.symbolic || metadata.uid != filesystem.ownerUid()
                        || metadata.linkCount != 1 || metadata.size <= 0
                        || metadata.size > MAX_PENDING_BYTES) {
                    throw invalid();
                }
                byte[] raw = filesystem.read(control, MAX_PENDING_BYTES);
                try {
                    String digest = sha256Hex(raw);
                    evidence.add(digest);
                    highestGeneration = Math.max(highestGeneration,
                            structurallyTrustedQuarantinedGeneration(raw, instanceId));
                    File quarantined = new File(quarantineDirectory, digest + ".raw");
                    writeImmutable(quarantined, raw, MAX_PENDING_BYTES);
                    deleteExact(control, raw, MAX_PENDING_BYTES);
                } finally {
                    wipe(raw);
                }
            }
            // If recovery itself crashed after quarantining a control but before journaling, include
            // every retained raw digest in the new hash-only evidence. Unknown objects stay put.
            for (String name : boundedList(quarantineDirectory)) {
                if (!name.matches("[0-9a-f]{64}\\.raw")) continue;
                String digest = name.substring(0, 64);
                File quarantined = new File(quarantineDirectory, name);
                byte[] raw = readStrictFile(quarantined, 1, MAX_PENDING_BYTES);
                try {
                    if (!digest.equals(sha256Hex(raw))) throw invalid();
                    evidence.add(digest);
                    highestGeneration = Math.max(highestGeneration,
                            structurallyTrustedQuarantinedGeneration(raw, instanceId));
                } finally {
                    wipe(raw);
                }
            }
            if (highestGeneration == Long.MAX_VALUE) throw invalid();
            return new RecoveryMaterial(highestGeneration < 0 ? 0 : highestGeneration + 1,
                    sortedUniqueDigests(evidence));
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        }
    }

    private long structurallyTrustedGeneration(byte[] raw, File control, String instanceId) {
        try {
            if (sameFile(control, activeFile)) {
                Map<String, Object> pointer = parseCanonicalObject(raw, MAX_STATE_BYTES);
                requireExactKeys(pointer, "schemaVersion", "instanceId", "stateId", "keyId");
                requireLong(pointer, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
                if (!instanceId.equals(requireInstanceId(
                        requireString(pointer, "instanceId")))) return -1;
                String stateId = requireHex64(pointer, "stateId");
                String keyId = requireHex64(pointer, "keyId");
                File stateFile = new File(stateDirectory, stateId + ".json");
                if (!filesystem.lstat(stateFile).exists) return -1;
                byte[] stateBytes = readStrictFile(stateFile, 1, MAX_STATE_BYTES);
                try {
                    if (!stateId.equals(sha256Hex(stateBytes))) return -1;
                    Map<String, Object> state = parseCanonicalObject(stateBytes, MAX_STATE_BYTES);
                    requireExactKeys(state, "schemaVersion", "instanceId", "generation", "enabled",
                            "keyId", "sourceIv", "sourceCiphertext");
                    requireLong(state, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
                    if (!instanceId.equals(requireInstanceId(requireString(state, "instanceId")))
                            || !keyId.equals(requireHex64(state, "keyId"))) return -1;
                    return requireLong(state, "generation", 0, Long.MAX_VALUE);
                } finally {
                    wipe(stateBytes);
                }
            }
            if (sameFile(control, pendingFile)) {
                Map<String, Object> pending = parseCanonicalObject(raw, MAX_PENDING_BYTES);
                requireExactKeys(pending,
                        "schemaVersion", "instanceId", "transactionId", "operation", "phase",
                        "previousActiveSha256", "targetActive", "targetKeyMaterial",
                        "targetStateEnvelope", "evidenceDigests", "deleteEntries");
                requireLong(pending, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
                if (!instanceId.equals(requireInstanceId(
                        requireString(pending, "instanceId")))) return -1;
                Map<String, Object> pointer = requireObject(pending, "targetActive");
                Map<String, Object> state = requireObject(pending, "targetStateEnvelope");
                requireExactKeys(pointer, "schemaVersion", "instanceId", "stateId", "keyId");
                requireExactKeys(state, "schemaVersion", "instanceId", "generation", "enabled",
                        "keyId", "sourceIv", "sourceCiphertext");
                String stateId = requireHex64(pointer, "stateId");
                byte[] stateBytes = canonicalBytes(state);
                try {
                    if (!stateId.equals(sha256Hex(stateBytes))
                            || !instanceId.equals(requireInstanceId(
                            requireString(state, "instanceId")))) return -1;
                    return requireLong(state, "generation", 0, Long.MAX_VALUE);
                } finally {
                    wipe(stateBytes);
                }
            }
            if (legacyStateFile != null && sameFile(control, legacyStateFile)) {
                Map<String, Object> legacy = parseObject(raw, MAX_STATE_BYTES);
                requireExactKeys(legacy, "schemaVersion", "instanceId", "generation", "enabled",
                        "sourceIv", "sourceCiphertext");
                requireLong(legacy, "schemaVersion", 1, 1);
                Object identity = legacy.get("instanceId");
                if (identity != null
                        && !instanceId.equals(requireInstanceId(String.valueOf(identity)))) {
                    return -1;
                }
                return requireLong(legacy, "generation", 0, Long.MAX_VALUE);
            }
        } catch (Throwable ignored) {
            // Invalid bytes are evidence, not a source of desired state or generation authority.
        }
        return -1;
    }

    private long structurallyTrustedQuarantinedGeneration(
            byte[] raw, String instanceId) throws StateException {
        Map<String, Object> value;
        try {
            value = parseObject(raw, MAX_PENDING_BYTES);
        } catch (Throwable ignored) {
            return -1;
        }
        boolean activeShape = value.keySet().equals(immutableSet(
                "schemaVersion", "instanceId", "stateId", "keyId"));
        boolean pendingShape = value.keySet().equals(immutableSet(
                "schemaVersion", "instanceId", "transactionId", "operation", "phase",
                "previousActiveSha256", "targetActive", "targetKeyMaterial",
                "targetStateEnvelope", "evidenceDigests", "deleteEntries"));
        boolean legacyShape = value.keySet().equals(immutableSet(
                "schemaVersion", "instanceId", "generation", "enabled",
                "sourceIv", "sourceCiphertext"));
        if (!activeShape && !pendingShape && !legacyShape) return -1;

        Object rawIdentity = value.get("instanceId");
        if (rawIdentity == null) {
            if (!legacyShape) return -1;
        } else {
            if (!(rawIdentity instanceof String)) return -1;
            String parsedIdentity;
            try {
                parsedIdentity = requireInstanceId((String) rawIdentity);
            } catch (StateException ignored) {
                return -1;
            }
            if (!instanceId.equals(parsedIdentity)) throw invalid();
        }
        if (activeShape) {
            return structurallyTrustedGeneration(raw, activeFile, instanceId);
        }
        if (legacyShape) {
            return legacyStateFile == null
                    ? -1
                    : structurallyTrustedGeneration(raw, legacyStateFile, instanceId);
        }
        try {
            Map<String, Object> canonical =
                    parseCanonicalObject(raw, MAX_PENDING_BYTES);
            Pending pending = pendingFromObject(canonical);
            return requireLong(pending.targetStateEnvelope,
                    "generation", 0, Long.MAX_VALUE);
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private void ensureLayout() throws Exception {
        Metadata parent = filesystem.lstat(noBackupDirectory);
        if (!parent.exists || !parent.directory || parent.symbolic
                || parent.uid != filesystem.ownerUid()
                || (parent.mode != DIRECTORY_MODE && parent.mode != 0771)) {
            throw invalid();
        }
        File proxyRoot = new File(noBackupDirectory, ROOT_DIRECTORY);
        ensureDirectory(proxyRoot, true);
        ensureDirectory(rootDirectory, true);
        ensureDirectory(keyDirectory, true);
        ensureDirectory(stateDirectory, true);
        ensureDirectory(evidenceDirectory, true);
        ensureDirectory(quarantineDirectory, true);
    }

    private void ensureDirectory(File directory, boolean create) throws Exception {
        Metadata metadata = filesystem.lstat(directory);
        if (!metadata.exists && create) {
            filesystem.mkdir(directory, DIRECTORY_MODE);
            metadata = filesystem.lstat(directory);
        }
        if (!metadata.exists || !metadata.directory || metadata.symbolic
                || metadata.uid != filesystem.ownerUid() || metadata.mode != DIRECTORY_MODE) {
            throw invalid();
        }
    }

    private void validateRootEntries() throws Exception {
        Set<String> allowed = immutableSet(
                KEY_DIRECTORY, STATE_DIRECTORY, EVIDENCE_DIRECTORY, QUARANTINE_DIRECTORY,
                ACTIVE_NAME, PENDING_NAME);
        for (String name : boundedList(rootDirectory)) {
            if (!allowed.contains(name)) throw invalid();
        }
    }

    private boolean v2ObjectDirectoriesEmpty() throws Exception {
        return boundedList(keyDirectory).isEmpty()
                && boundedList(stateDirectory).isEmpty()
                && boundedList(evidenceDirectory).isEmpty()
                && boundedList(quarantineDirectory).isEmpty();
    }

    private List<String> boundedList(File directory) throws Exception {
        List<String> names = filesystem.list(directory);
        if (names == null || names.size() > MAX_DIRECTORY_ENTRIES) throw invalid();
        ArrayList<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);
        return sorted;
    }

    private void writeImmutable(File target, byte[] bytes, int maximum) throws Exception {
        if (bytes == null || bytes.length <= 0 || bytes.length > maximum) throw invalid();
        Metadata metadata = filesystem.lstat(target);
        if (metadata.exists) {
            byte[] current = readStrictFile(target, bytes.length, bytes.length);
            try {
                if (!Arrays.equals(current, bytes)) throw invalid();
            } finally {
                wipe(current);
            }
            return;
        }
        filesystem.writeNew(target, bytes, FILE_MODE);
        byte[] current = readStrictFile(target, bytes.length, bytes.length);
        try {
            if (!Arrays.equals(current, bytes)) throw invalid();
        } finally {
            wipe(current);
        }
    }

    private void writeNewCanonical(File target, Map<String, Object> object, int maximum)
            throws Exception {
        byte[] bytes = canonicalBytes(object);
        try {
            if (bytes.length <= 0 || bytes.length > maximum) throw invalid();
            filesystem.writeNew(target, bytes, FILE_MODE);
            byte[] reloaded = readStrictFile(target, bytes.length, bytes.length);
            try {
                if (!Arrays.equals(bytes, reloaded)) throw invalid();
            } finally {
                wipe(reloaded);
            }
        } finally {
            wipe(bytes);
        }
    }

    private void replaceCanonical(File target, Map<String, Object> object, int maximum)
            throws Exception {
        byte[] bytes = canonicalBytes(object);
        try {
            if (bytes.length <= 0 || bytes.length > maximum) throw invalid();
            filesystem.replace(target, bytes, FILE_MODE);
            byte[] reloaded = readStrictFile(target, bytes.length, bytes.length);
            try {
                if (!Arrays.equals(bytes, reloaded)) throw invalid();
            } finally {
                wipe(reloaded);
            }
        } finally {
            wipe(bytes);
        }
    }

    private void deleteExact(File target, byte[] expected, int maximum) throws Exception {
        Metadata metadata = filesystem.lstat(target);
        if (!metadata.exists) return;
        byte[] current = readStrictFile(target, expected.length, maximum);
        try {
            if (!Arrays.equals(current, expected)) throw invalid();
            filesystem.delete(target);
        } finally {
            wipe(current);
        }
    }

    private byte[] readStrictFile(File file, int minimum, int maximum) throws Exception {
        Metadata metadata = filesystem.lstat(file);
        if (!metadata.exists || !metadata.regular || metadata.symbolic
                || metadata.uid != filesystem.ownerUid() || metadata.mode != FILE_MODE
                || metadata.linkCount != 1 || metadata.size < minimum || metadata.size > maximum) {
            throw invalid();
        }
        byte[] bytes = filesystem.read(file, maximum);
        if (bytes.length < minimum || bytes.length > maximum || bytes.length != metadata.size) {
            wipe(bytes);
            throw invalid();
        }
        Metadata after = filesystem.lstat(file);
        if (!after.sameIdentity(metadata) || after.size != bytes.length) {
            wipe(bytes);
            throw invalid();
        }
        return bytes;
    }

    private boolean exists(File file) throws Exception {
        return filesystem.lstat(file).exists;
    }


    private byte[] newRandomKey() throws StateException {
        try {
            byte[] key = keys.randomBytes(KEY_BYTES);
            if (key == null || key.length != KEY_BYTES) {
                wipe(key);
                throw commitFailure();
            }
            return key;
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        }
    }

    private static byte[] stateAad(String instanceId, long generation) {
        return (V2_AAD_PREFIX + instanceId + "\n" + generation + "\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] legacyAad(String instanceId, long generation) {
        return (V1_AAD_PREFIX + (instanceId == null ? "" : instanceId) + "\n" + generation)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static boolean sameSource(Source first, Source second) {
        return first == null ? second == null : first.sameAs(second);
    }

    private static boolean isRecoverableStateFailure(StateException failure) {
        return "proxy_state_invalid".equals(failure.code)
                || "proxy_state_key_unusable".equals(failure.code)
                || "proxy_state_key_mismatch".equals(failure.code);
    }

    private static long increment(long generation) throws StateException {
        if (generation < 0 || generation == Long.MAX_VALUE) throw invalid();
        return generation + 1;
    }

    private static void validateSourceState(boolean enabled, Source source) throws StateException {
        if (source == null) {
            if (enabled) throw invalid();
            return;
        }
        validateSource(source);
    }

    private static void validateSource(Source source) throws StateException {
        if (source == null
                || !("endpoint".equals(source.kind) || "uri_list".equals(source.kind)
                || "clash".equals(source.kind) || "subscription".equals(source.kind))) {
            throw invalid();
        }
        int sourceBytes = utf8Length(source.value);
        int selectedBytes = utf8Length(source.selectedNode);
        if (sourceBytes <= 0 || sourceBytes > MAX_SOURCE_BYTES
                || selectedBytes < 0 || selectedBytes > MAX_SELECTED_NODE_BYTES
                || source.value.indexOf('\u0000') >= 0
                || source.selectedNode.indexOf('\u0000') >= 0) {
            throw invalid();
        }
    }

    private static int utf8Length(String value) {
        if (value == null) return -1;
        try {
            return StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value)).remaining();
        } catch (CharacterCodingException failure) {
            return -1;
        }
    }

    private static String requireInstanceId(String value) throws StateException {
        if (value == null || !UUID_V4.matcher(value).matches()) throw invalid();
        return value;
    }

    private static String requireHex64(Map<String, Object> object, String name)
            throws StateException {
        String value = requireString(object, name);
        if (!HEX_64.matcher(value).matches()) throw invalid();
        return value;
    }

    private static String nullableHex64(Object value) throws StateException {
        if (value == null) return null;
        if (!(value instanceof String) || !HEX_64.matcher((String) value).matches()) throw invalid();
        return (String) value;
    }

    private static String nullableString(Object value) throws StateException {
        if (value == null) return null;
        if (!(value instanceof String)) throw invalid();
        return (String) value;
    }

    private static int phaseIndex(String phase) {
        return PHASES.indexOf(phase);
    }

    private static List<String> sortedUniqueDigests(List<String> values) throws StateException {
        if (values == null || values.size() > MAX_EVIDENCE_DIGESTS) throw invalid();
        ArrayList<String> result = new ArrayList<>(values.size());
        for (String value : values) {
            if (value == null || !HEX_64.matcher(value).matches()) throw invalid();
            result.add(value);
        }
        Collections.sort(result);
        for (int index = 1; index < result.size(); index++) {
            if (result.get(index - 1).equals(result.get(index))) result.remove(index--);
        }
        return Collections.unmodifiableList(result);
    }

    private static List<String> validateDeleteEntries(List<String> entries) throws StateException {
        if (entries == null || entries.size() > 8) throw invalid();
        ArrayList<String> result = new ArrayList<>(entries.size());
        HashSet<String> unique = new HashSet<>();
        for (String entry : entries) {
            boolean valid = "legacyAlias".equals(entry)
                    || (entry != null && entry.startsWith("legacyState:")
                    && HEX_64.matcher(entry.substring("legacyState:".length())).matches())
                    || (entry != null && entry.startsWith("keyObject:")
                    && HEX_64.matcher(entry.substring("keyObject:".length())).matches());
            if (!valid || !unique.add(entry)) throw invalid();
            result.add(entry);
        }
        return Collections.unmodifiableList(result);
    }

    private static List<String> requireDigestList(Map<String, Object> object, String name)
            throws StateException {
        return sortedUniqueDigests(requireStringList(object, name, MAX_EVIDENCE_DIGESTS));
    }

    private static List<String> requireStringList(
            Map<String, Object> object, String name, int maximum) throws StateException {
        Object value = object.get(name);
        if (!(value instanceof List)) throw invalid();
        List<?> raw = (List<?>) value;
        if (raw.size() > maximum) throw invalid();
        ArrayList<String> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof String)) throw invalid();
            result.add((String) item);
        }
        return Collections.unmodifiableList(result);
    }

    private static Map<String, Object> parseCanonicalObject(byte[] bytes, int maximum)
            throws StateException {
        Map<String, Object> object = parseObject(bytes, maximum);
        byte[] canonical = canonicalBytes(object);
        try {
            if (!Arrays.equals(bytes, canonical)) throw invalid();
        } finally {
            wipe(canonical);
        }
        return object;
    }

    private static Map<String, Object> parseObject(byte[] bytes, int maximum)
            throws StateException {
        if (bytes == null || bytes.length <= 0 || bytes.length > maximum) throw invalid();
        try {
            String text = decodeUtf8(bytes);
            JSONTokener tokener = new JSONTokener(text);
            Object raw = tokener.nextValue();
            if (tokener.nextClean() != 0 || !(raw instanceof JSONObject)) throw invalid();
            Object converted = convertJson(raw);
            if (!(converted instanceof Map)) throw invalid();
            @SuppressWarnings("unchecked")
            Map<String, Object> object = (Map<String, Object>) converted;
            return object;
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    private static Object convertJson(Object raw) throws StateException {
        if (raw == null || raw == JSONObject.NULL) return null;
        if (raw instanceof String || raw instanceof Boolean) return raw;
        if (raw instanceof Number) {
            Number number = (Number) raw;
            if (raw instanceof Float || raw instanceof Double) throw invalid();
            return number.longValue();
        }
        if (raw instanceof JSONObject) {
            JSONObject object = (JSONObject) raw;
            LinkedHashMap<String, Object> result = new LinkedHashMap<>();
            Iterator<String> keys = object.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if (result.containsKey(key)) throw invalid();
                result.put(key, convertJson(object.opt(key)));
            }
            return result;
        }
        if (raw instanceof JSONArray) {
            JSONArray array = (JSONArray) raw;
            ArrayList<Object> result = new ArrayList<>(array.length());
            for (int index = 0; index < array.length(); index++) {
                result.add(convertJson(array.opt(index)));
            }
            return result;
        }
        throw invalid();
    }

    private static byte[] canonicalBytes(Object value) throws StateException {
        StringBuilder builder = new StringBuilder();
        appendCanonical(builder, value);
        byte[] bytes = builder.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_PENDING_BYTES) {
            wipe(bytes);
            throw invalid();
        }
        return bytes;
    }

    private static void appendCanonical(StringBuilder builder, Object value) throws StateException {
        if (value == null) {
            builder.append("null");
        } else if (value instanceof String) {
            appendJsonString(builder, (String) value);
        } else if (value instanceof Boolean) {
            builder.append(Boolean.TRUE.equals(value) ? "true" : "false");
        } else if (value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            builder.append(((Number) value).longValue());
        } else if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> object = (Map<String, Object>) value;
            ArrayList<String> names = new ArrayList<>(object.keySet());
            Collections.sort(names);
            builder.append('{');
            boolean first = true;
            for (String name : names) {
                if (name == null) throw invalid();
                if (!first) builder.append(',');
                first = false;
                appendJsonString(builder, name);
                builder.append(':');
                appendCanonical(builder, object.get(name));
            }
            builder.append('}');
        } else if (value instanceof List) {
            builder.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) builder.append(',');
                first = false;
                appendCanonical(builder, item);
            }
            builder.append(']');
        } else {
            throw invalid();
        }
    }

    private static void appendJsonString(StringBuilder builder, String value) throws StateException {
        if (utf8Length(value) < 0) throw invalid();
        builder.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': builder.append("\\\""); break;
                case '\\': builder.append("\\\\"); break;
                case '\b': builder.append("\\b"); break;
                case '\f': builder.append("\\f"); break;
                case '\n': builder.append("\\n"); break;
                case '\r': builder.append("\\r"); break;
                case '\t': builder.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        builder.append("\\u00");
                        builder.append(Character.forDigit((character >>> 4) & 0xf, 16));
                        builder.append(Character.forDigit(character & 0xf, 16));
                    } else {
                        builder.append(character);
                    }
            }
        }
        builder.append('"');
    }

    private static void requireExactKeys(Map<String, Object> object, String... names)
            throws StateException {
        Set<String> expected = new HashSet<>(Arrays.asList(names));
        if (object.size() != expected.size() || !object.keySet().equals(expected)) throw invalid();
    }

    private static long requireLong(
            Map<String, Object> object, String name, long minimum, long maximum)
            throws StateException {
        Object value = object.get(name);
        if (!(value instanceof Long)) throw invalid();
        long result = (Long) value;
        if (result < minimum || result > maximum) throw invalid();
        return result;
    }

    private static String requireString(Map<String, Object> object, String name)
            throws StateException {
        Object value = object.get(name);
        if (!(value instanceof String) || utf8Length((String) value) < 0) throw invalid();
        return (String) value;
    }

    private static boolean requireBoolean(Map<String, Object> object, String name)
            throws StateException {
        Object value = object.get(name);
        if (!(value instanceof Boolean)) throw invalid();
        return (Boolean) value;
    }

    private static Map<String, Object> requireObject(Map<String, Object> object, String name)
            throws StateException {
        Object value = object.get(name);
        if (!(value instanceof Map)) throw invalid();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) value;
        return result;
    }

    private static byte[] decodeBase64(String value, int minimum, int maximum)
            throws StateException {
        try {
            if (value == null || value.length() > ((maximum + 2) / 3) * 4 + 4) throw invalid();
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length < minimum || decoded.length > maximum
                    || !Base64.getEncoder().encodeToString(decoded).equals(value)) {
                wipe(decoded);
                throw invalid();
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            throw invalid();
        }
    }

    private static String decodeUtf8(byte[] value) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
    }

    private static String sha256Hex(byte[] value) throws StateException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            try {
                return hex(digest);
            } finally {
                wipe(digest);
            }
        } catch (Throwable failure) {
            throw invalid();
        }
    }

    private String randomHex(int bytes) throws StateException {
        byte[] random = null;
        try {
            random = keys.randomBytes(bytes);
            if (random == null || random.length != bytes) throw commitFailure();
            return hex(random);
        } catch (StateException failure) {
            throw failure;
        } catch (Throwable failure) {
            throw commitFailure();
        } finally {
            wipe(random);
        }
    }

    private static String hex(byte[] bytes) {
        char[] result = new char[bytes.length * 2];
        final char[] alphabet = "0123456789abcdef".toCharArray();
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            result[index * 2] = alphabet[value >>> 4];
            result[index * 2 + 1] = alphabet[value & 0xf];
        }
        return new String(result);
    }

    private static boolean sameFile(File first, File second) {
        return first.getAbsolutePath().equals(second.getAbsolutePath());
    }

    private static Map<String, Object> map(Object... values) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index + 1 < values.length; index += 2) {
            result.put(String.valueOf(values[index]), values[index + 1]);
        }
        return result;
    }

    private static Set<String> immutableSet(String... values) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(values)));
    }

    private static void wipe(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static StateException invalid() {
        return new StateException("proxy_state_invalid");
    }

    private static StateException keyUnusable() {
        return new StateException("proxy_state_key_unusable");
    }

    private static StateException keyMismatch() {
        return new StateException("proxy_state_key_mismatch");
    }

    private static StateException commitFailure() {
        return new StateException("state_commit_failed");
    }

    static final class Source {
        final String kind;
        final String value;
        final String selectedNode;
        final boolean udpAllowed;
        final boolean allowInsecureHttp;

        Source(
                String kind,
                String value,
                String selectedNode,
                boolean udpAllowed,
                boolean allowInsecureHttp) {
            this.kind = kind;
            this.value = value;
            this.selectedNode = selectedNode;
            this.udpAllowed = udpAllowed;
            this.allowInsecureHttp = allowInsecureHttp;
        }

        boolean sameAs(Source other) {
            return other != null
                    && kind.equals(other.kind)
                    && value.equals(other.value)
                    && selectedNode.equals(other.selectedNode)
                    && udpAllowed == other.udpAllowed
                    && allowInsecureHttp == other.allowInsecureHttp;
        }
    }

    static final class LoadedState {
        final boolean requiresInstanceId;
        final String instanceId;
        final long generation;
        final boolean enabled;
        final Source source;

        LoadedState(
                boolean requiresInstanceId,
                String instanceId,
                long generation,
                boolean enabled,
                Source source) {
            this.requiresInstanceId = requiresInstanceId;
            this.instanceId = instanceId;
            this.generation = generation;
            this.enabled = enabled;
            this.source = source;
        }

        static LoadedState requiresInstanceId(long generation) {
            return new LoadedState(true, null, generation, false, null);
        }
    }

    static final class StateException extends Exception {
        final String code;

        StateException(String code) {
            super(code);
            this.code = code;
        }
    }

    static final class Metadata {
        final boolean exists;
        final boolean regular;
        final boolean directory;
        final boolean symbolic;
        final int uid;
        final int mode;
        final long linkCount;
        final long size;
        final long device;
        final long inode;

        Metadata(
                boolean exists,
                boolean regular,
                boolean directory,
                boolean symbolic,
                int uid,
                int mode,
                long linkCount,
                long size,
                long device,
                long inode) {
            this.exists = exists;
            this.regular = regular;
            this.directory = directory;
            this.symbolic = symbolic;
            this.uid = uid;
            this.mode = mode;
            this.linkCount = linkCount;
            this.size = size;
            this.device = device;
            this.inode = inode;
        }

        static Metadata missing() {
            return new Metadata(false, false, false, false, -1, 0, 0, 0, 0, 0);
        }

        boolean sameIdentity(Metadata other) {
            return exists && other.exists && device == other.device && inode == other.inode
                    && regular == other.regular && directory == other.directory
                    && symbolic == other.symbolic && uid == other.uid && mode == other.mode
                    && linkCount == other.linkCount;
        }
    }

    interface FilesystemBackend {
        int ownerUid();
        Metadata lstat(File file) throws Exception;
        List<String> list(File directory) throws Exception;
        byte[] read(File file, int maximum) throws Exception;
        void mkdir(File directory, int mode) throws Exception;
        void writeNew(File file, byte[] bytes, int mode) throws Exception;
        void replace(File file, byte[] bytes, int mode) throws Exception;
        void delete(File file) throws Exception;
        void syncDirectory(File directory) throws Exception;
    }

    interface KeyBackend {
        byte[] randomBytes(int count) throws Exception;
        byte[] decryptLegacy(byte[] iv, byte[] ciphertext, byte[] aad)
                throws KeyUnavailableException;
        void deleteLegacyAlias() throws Exception;
    }

    static final class KeyUnavailableException extends Exception {
        KeyUnavailableException(Throwable cause) {
            super(cause);
        }

        KeyUnavailableException() {
            super();
        }
    }

    private static final class Pending {
        final String instanceId;
        final String transactionId;
        final String operation;
        final String phase;
        final String previousActiveSha256;
        final Map<String, Object> targetActive;
        final String targetKeyMaterial;
        final Map<String, Object> targetStateEnvelope;
        final List<String> evidenceDigests;
        final List<String> deleteEntries;

        Pending(
                String instanceId,
                String transactionId,
                String operation,
                String phase,
                String previousActiveSha256,
                Map<String, Object> targetActive,
                String targetKeyMaterial,
                Map<String, Object> targetStateEnvelope,
                List<String> evidenceDigests,
                List<String> deleteEntries) {
            this.instanceId = instanceId;
            this.transactionId = transactionId;
            this.operation = operation;
            this.phase = phase;
            this.previousActiveSha256 = previousActiveSha256;
            this.targetActive = targetActive;
            this.targetKeyMaterial = targetKeyMaterial;
            this.targetStateEnvelope = targetStateEnvelope;
            this.evidenceDigests = evidenceDigests;
            this.deleteEntries = deleteEntries;
        }

        Pending withPhase(String nextPhase) {
            return new Pending(instanceId, transactionId, operation, nextPhase,
                    previousActiveSha256, targetActive, targetKeyMaterial,
                    targetStateEnvelope, evidenceDigests, deleteEntries);
        }

        Map<String, Object> toMap() {
            return map(
                    "schemaVersion", (long) SCHEMA_VERSION,
                    "instanceId", instanceId,
                    "transactionId", transactionId,
                    "operation", operation,
                    "phase", phase,
                    "previousActiveSha256", previousActiveSha256,
                    "targetActive", targetActive,
                    "targetKeyMaterial", targetKeyMaterial,
                    "targetStateEnvelope", targetStateEnvelope,
                    "evidenceDigests", new ArrayList<Object>(evidenceDigests),
                    "deleteEntries", new ArrayList<Object>(deleteEntries));
        }
    }

    private static final class Transaction {
        final Pending pending;
        final Source expectedSource;

        Transaction(Pending pending, Source expectedSource) {
            this.pending = pending;
            this.expectedSource = expectedSource;
        }
    }

    private static final class ActiveRecord {
        final LoadedState loaded;
        final byte[] pointerBytes;
        final byte[] keyMaterial;

        ActiveRecord(LoadedState loaded, byte[] pointerBytes, byte[] keyMaterial) {
            this.loaded = loaded;
            this.pointerBytes = pointerBytes;
            this.keyMaterial = keyMaterial;
        }
    }

    private static final class LegacyRecord implements AutoCloseable {
        final String instanceId;
        final long generation;
        final boolean enabled;
        final Source source;
        final byte[] rawBytes;

        LegacyRecord(
                String instanceId, long generation, boolean enabled, Source source,
                byte[] rawBytes) {
            this.instanceId = instanceId;
            this.generation = generation;
            this.enabled = enabled;
            this.source = source;
            this.rawBytes = rawBytes;
        }

        @Override
        public void close() {
            wipe(rawBytes);
        }
    }

    private static final class RecoveryMaterial {
        final long nextGeneration;
        final List<String> evidenceDigests;

        RecoveryMaterial(long nextGeneration, List<String> evidenceDigests) {
            this.nextGeneration = nextGeneration;
            this.evidenceDigests = evidenceDigests;
        }
    }

    private enum ActiveDisposition {
        PREVIOUS,
        TARGET,
        THIRD
    }

    private static final class AndroidKeyBackend implements KeyBackend {
        private final SecureRandom random = new SecureRandom();

        @Override
        public byte[] randomBytes(int count) {
            if (count <= 0 || count > KEY_BYTES) throw new IllegalArgumentException();
            byte[] bytes = new byte[count];
            random.nextBytes(bytes);
            return bytes;
        }

        @Override
        public byte[] decryptLegacy(byte[] iv, byte[] ciphertext, byte[] aad)
                throws KeyUnavailableException {
            try {
                KeyStore store = KeyStore.getInstance("AndroidKeyStore");
                store.load(null);
                Key key = store.getKey(LEGACY_KEY_ALIAS, null);
                if (!(key instanceof SecretKey)) throw new KeyUnavailableException();
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, (SecretKey) key,
                        new GCMParameterSpec(GCM_TAG_BITS, iv));
                cipher.updateAAD(aad);
                return cipher.doFinal(ciphertext);
            } catch (KeyUnavailableException failure) {
                throw failure;
            } catch (Throwable failure) {
                throw new KeyUnavailableException(failure);
            }
        }

        @Override
        public void deleteLegacyAlias() throws Exception {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            if (store.containsAlias(LEGACY_KEY_ALIAS)) store.deleteEntry(LEGACY_KEY_ALIAS);
        }
    }

    private static final class OsFilesystemBackend implements FilesystemBackend {
        private final SecureRandom random = new SecureRandom();

        @Override
        public int ownerUid() {
            return Process.myUid();
        }

        @Override
        public Metadata lstat(File file) throws Exception {
            try {
                StructStat stat = Os.lstat(file.getAbsolutePath());
                return metadata(stat);
            } catch (ErrnoException failure) {
                if (failure.errno == OsConstants.ENOENT || failure.errno == OsConstants.ENOTDIR) {
                    return Metadata.missing();
                }
                throw failure;
            }
        }

        @Override
        public List<String> list(File directory) throws Exception {
            Metadata before = lstat(directory);
            if (!before.exists || !before.directory || before.symbolic) throw invalid();
            String[] names = directory.list();
            if (names == null) throw invalid();
            Metadata after = lstat(directory);
            if (!after.sameIdentity(before)) throw invalid();
            return Arrays.asList(names);
        }

        @Override
        public byte[] read(File file, int maximum) throws Exception {
            FileDescriptor descriptor = Os.open(file.getAbsolutePath(),
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW, 0);
            try (FileInputStream input = new FileInputStream(descriptor)) {
                StructStat before = Os.fstat(descriptor);
                if (!OsConstants.S_ISREG(before.st_mode) || before.st_size < 0
                        || before.st_size > maximum || before.st_size > Integer.MAX_VALUE) {
                    throw invalid();
                }
                byte[] bytes = new byte[(int) before.st_size];
                int offset = 0;
                while (offset < bytes.length) {
                    int count = input.read(bytes, offset, bytes.length - offset);
                    if (count < 0) {
                        wipe(bytes);
                        throw new EOFException();
                    }
                    offset += count;
                }
                if (input.read() != -1) {
                    wipe(bytes);
                    throw invalid();
                }
                StructStat after = Os.fstat(descriptor);
                if (before.st_dev != after.st_dev || before.st_ino != after.st_ino
                        || before.st_size != after.st_size) {
                    wipe(bytes);
                    throw invalid();
                }
                return bytes;
            }
        }

        @Override
        public void mkdir(File directory, int mode) throws Exception {
            try {
                Os.mkdir(directory.getAbsolutePath(), mode);
                Os.chmod(directory.getAbsolutePath(), mode);
                syncDirectory(directory.getParentFile());
            } catch (ErrnoException failure) {
                if (failure.errno != OsConstants.EEXIST) throw failure;
            }
        }

        @Override
        public void writeNew(File file, byte[] bytes, int mode) throws Exception {
            FileDescriptor descriptor = null;
            boolean created = false;
            boolean contentSynced = false;
            try {
                descriptor = Os.open(file.getAbsolutePath(),
                        OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL
                                | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,
                        mode);
                created = true;
                Os.fchmod(descriptor, mode);
                try (FileOutputStream output = new FileOutputStream(descriptor)) {
                    descriptor = null;
                    output.write(bytes);
                    output.flush();
                    output.getFD().sync();
                }
                contentSynced = true;
                syncDirectory(file.getParentFile());
            } catch (Throwable failure) {
                if (descriptor != null) try { Os.close(descriptor); } catch (Throwable ignored) { }
                // Once the content is fsynced it is a valid idempotent transaction artifact.
                // Keep it if the subsequent directory fsync fails; retry verifies exact bytes.
                if (created && !contentSynced) {
                    try { Os.remove(file.getAbsolutePath()); } catch (Throwable ignored) { }
                }
                throw failure;
            }
        }

        @Override
        public void replace(File file, byte[] bytes, int mode) throws Exception {
            byte[] suffix = new byte[12];
            random.nextBytes(suffix);
            File temporary = new File(file.getParentFile(),
                    "." + file.getName() + "." + hex(suffix) + ".tmp");
            wipe(suffix);
            boolean written = false;
            try {
                writeNew(temporary, bytes, mode);
                written = true;
                Os.rename(temporary.getAbsolutePath(), file.getAbsolutePath());
                written = false;
                syncDirectory(file.getParentFile());
            } finally {
                if (written) try { Os.remove(temporary.getAbsolutePath()); } catch (Throwable ignored) { }
            }
        }

        @Override
        public void delete(File file) throws Exception {
            Os.remove(file.getAbsolutePath());
            syncDirectory(file.getParentFile());
        }

        @Override
        public void syncDirectory(File directory) throws Exception {
            FileDescriptor descriptor = Os.open(directory.getAbsolutePath(),
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,
                    0);
            try {
                StructStat metadata = Os.fstat(descriptor);
                if (!OsConstants.S_ISDIR(metadata.st_mode)
                        || metadata.st_uid != Process.myUid()) throw new Exception();
                Os.fsync(descriptor);
            } finally {
                Os.close(descriptor);
            }
        }

        private static Metadata metadata(StructStat stat) {
            return new Metadata(
                    true,
                    OsConstants.S_ISREG(stat.st_mode),
                    OsConstants.S_ISDIR(stat.st_mode),
                    OsConstants.S_ISLNK(stat.st_mode),
                    stat.st_uid,
                    stat.st_mode & 0777,
                    stat.st_nlink,
                    stat.st_size,
                    stat.st_dev,
                    stat.st_ino);
        }
    }
}
