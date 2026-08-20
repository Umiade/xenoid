package dev.xenoid.daemon;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** JVM-only crash/recovery contracts for the package-private desired-state store. */
public final class ProxyStateStoreTest {
    private static final String INSTANCE = "123e4567-e89b-42d3-a456-426614174000";
    private static final ProxyStateStore.Source FIRST = new ProxyStateStore.Source(
            "endpoint", "socks5://first.invalid:1080", "first", true, false);
    private static final ProxyStateStore.Source SECOND = new ProxyStateStore.Source(
            "subscription", "https://second.invalid/proxies", "second", false, false);

    @Test
    public void emptyV2CreationUpdateAndRepeatedStartup() throws Exception {
        Fixture fixture = new Fixture();
        ProxyStateStore.LoadedState empty = fixture.store.load();
        assertTrue(empty.requiresInstanceId);
        assertEquals(0, empty.generation);
        assertNull(empty.source);

        ProxyStateStore.LoadedState initialized = fixture.store.bindInstance(INSTANCE);
        assertState(initialized, 0, false, null);
        assertEquals(1, fixture.fs.names(fixture.keysDirectory()).size());
        assertEquals(1, fixture.fs.names(fixture.statesDirectory()).size());
        assertEquals(1, fixture.fs.names(fixture.evidenceDirectory()).size());
        assertFalse(fixture.fs.exists(fixture.pendingFile()));

        String keyName = fixture.fs.names(fixture.keysDirectory()).get(0);
        ProxyStateStore.LoadedState updated = fixture.store.update(INSTANCE, true, FIRST);
        assertState(updated, 1, true, FIRST);
        assertEquals(Collections.singletonList(keyName), fixture.fs.names(fixture.keysDirectory()));
        assertEquals(2, fixture.fs.names(fixture.statesDirectory()).size());
        assertEquals(2, fixture.fs.names(fixture.evidenceDirectory()).size());
        assertFalse(fixture.fs.exists(fixture.pendingFile()));

        for (int attempt = 0; attempt < 3; attempt++) {
            ProxyStateStore.LoadedState reloaded = fixture.restart().load();
            assertState(reloaded, 1, true, FIRST);
            assertFalse(fixture.fs.exists(fixture.pendingFile()));
        }
    }

    @Test
    public void acceptsAndroidNoBackupDirectoryMode() throws Exception {
        Fixture fixture = new Fixture();
        fixture.fs.setMode(fixture.noBackup, 0771);
        ProxyStateStore.LoadedState state = fixture.store.load();
        assertTrue(state.requiresInstanceId);
        assertEquals(0, state.generation);
        assertTrue(fixture.fs.names(fixture.root()).contains("keys"));
    }

    @Test
    public void exactLegacyMigrationDeletesAliasOnlyAfterVerifiedActivation() throws Exception {
        Fixture fixture = new Fixture();
        byte[] legacyPlaintext = legacySource(FIRST);
        fixture.keys.legacyPlaintext = legacyPlaintext;
        byte[] legacyBytes = legacyEnvelope(INSTANCE, 9, true);
        fixture.fs.putFile(fixture.legacyFile, legacyBytes, 0600, fixture.fs.ownerUid());

        ProxyStateStore.LoadedState migrated = fixture.store.load();
        assertState(migrated, 9, true, FIRST);
        assertFalse(fixture.fs.exists(fixture.legacyFile));
        assertTrue(fixture.keys.aliasDeleted);
        assertFalse(fixture.fs.exists(fixture.pendingFile()));
        assertTrue(fixture.fs.names(fixture.quarantineDirectory()).isEmpty());
        assertEvidenceContains(fixture, sha256(legacyBytes));

        Fixture beforeAlias = new Fixture();
        beforeAlias.keys.legacyPlaintext = legacyPlaintext.clone();
        beforeAlias.fs.putFile(beforeAlias.legacyFile, legacyBytes, 0600,
                beforeAlias.fs.ownerUid());
        beforeAlias.keys.failAliasDeleteBefore = true;
        expectCode("state_commit_failed", () -> beforeAlias.store.load());
        assertFalse(beforeAlias.keys.aliasDeleted);
        beforeAlias.keys.failAliasDeleteBefore = false;
        ProxyStateStore.LoadedState resumed = beforeAlias.restart().load();
        assertState(resumed, 9, true, FIRST);
        assertTrue(beforeAlias.keys.aliasDeleted);
        assertFalse(beforeAlias.fs.exists(beforeAlias.legacyFile));
        assertEvidenceContains(beforeAlias, sha256(legacyBytes));

        Fixture afterAlias = new Fixture();
        afterAlias.keys.legacyPlaintext = legacyPlaintext.clone();
        afterAlias.fs.putFile(afterAlias.legacyFile, legacyBytes, 0600,
                afterAlias.fs.ownerUid());
        afterAlias.keys.failAliasDeleteAfter = true;
        expectCode("state_commit_failed", () -> afterAlias.store.load());
        assertTrue(afterAlias.keys.aliasDeleted);
        afterAlias.keys.failAliasDeleteAfter = false;
        assertState(afterAlias.restart().load(), 9, true, FIRST);
        assertTrue(afterAlias.keys.aliasDeleted);
        assertEvidenceContains(afterAlias, sha256(legacyBytes));
    }

    @Test
    public void validV2AlwaysWinsOverLegacyV1() throws Exception {
        Fixture fixture = configuredFixture();
        byte[] active = fixture.fs.bytes(fixture.activeFile());
        byte[] legacy = legacyEnvelope(INSTANCE, 99, true);
        fixture.keys.legacyPlaintext = legacySource(SECOND);
        fixture.fs.putFile(fixture.legacyFile, legacy, 0600, fixture.fs.ownerUid());

        assertState(fixture.restart().load(), 1, true, FIRST);
        assertArrayEquals(active, fixture.fs.bytes(fixture.activeFile()));
        assertArrayEquals(legacy, fixture.fs.bytes(fixture.legacyFile));
        assertFalse(fixture.keys.aliasDeleted);
    }

    @Test
    public void interruptionAtEveryFilesystemAndFsyncBoundaryResumesExactly() throws Exception {
        Fixture base = configuredFixture();
        FakeFilesystem successfulFs = base.fs.copy();
        FakeKeys successfulKeys = base.keys.copy();
        Fixture successful = new Fixture(successfulFs, successfulKeys);
        successful.fs.resetBoundaries();
        assertState(successful.store.clear(INSTANCE, false), 2, false, null);
        List<String> boundaries = new ArrayList<>(successful.fs.boundaries);
        assertTrue(boundaries.toString(), boundaries.size() >= 20);
        assertTrue(containsBoundary(boundaries, "pending.json"));
        assertTrue(containsBoundary(boundaries, "/keys/"));
        assertTrue(containsBoundary(boundaries, "/states/"));
        assertTrue(containsBoundary(boundaries, "active.json"));
        assertTrue(containsBoundary(boundaries, "/evidence/"));
        assertTrue(containsBoundary(boundaries, "delete:"));
        assertTrue(containsBoundary(boundaries, "fsync:"));

        for (int ordinal = 1; ordinal <= boundaries.size(); ordinal++) {
            Fixture interrupted = new Fixture(base.fs.copy(), base.keys.copy());
            interrupted.fs.resetBoundaries();
            interrupted.fs.failBoundary = ordinal;
            try {
                interrupted.store.clear(INSTANCE, false);
                fail("boundary " + ordinal + " did not interrupt: " + boundaries.get(ordinal - 1));
            } catch (ProxyStateStore.StateException expected) {
                assertTrue(expected.code, expected.code.equals("state_commit_failed")
                        || expected.code.equals("proxy_state_invalid"));
            }
            interrupted.fs.failBoundary = -1;
            ProxyStateStore.LoadedState recovered = interrupted.restart().load();
            if (recovered.generation == 1) {
                assertState(recovered, 1, true, FIRST);
            } else {
                assertState(recovered, 2, false, null);
            }
            assertFalse("pending survived boundary " + ordinal,
                    interrupted.fs.exists(interrupted.pendingFile()));
            assertTrue("evidence erased at boundary " + ordinal,
                    interrupted.fs.names(interrupted.evidenceDirectory()).size() >= 1);
        }
    }

    @Test
    public void previousTargetAndThirdActivePointerRecovery() throws Exception {
        Fixture previous = configuredFixture();
        previous.fs.failPointContains = "before:replace:" + previous.activeFile().getPath();
        expectCode("state_commit_failed", () -> previous.store.update(INSTANCE, true, SECOND));
        assertTrue(previous.fs.exists(previous.pendingFile()));
        Map<String, Object> prepared = parse(previous.fs.bytes(previous.pendingFile()));
        ArrayList<String> pendingKeys = new ArrayList<>(prepared.keySet());
        Collections.sort(pendingKeys);
        assertEquals(Arrays.asList(
                "deleteEntries", "evidenceDigests", "instanceId", "operation", "phase",
                "previousActiveSha256", "schemaVersion", "targetActive",
                "targetKeyMaterial", "targetStateEnvelope", "transactionId"), pendingKeys);
        assertEquals("update", prepared.get("operation"));
        assertEquals("objects_materialized", prepared.get("phase"));
        String preparedText = new String(previous.fs.bytes(previous.pendingFile()),
                StandardCharsets.UTF_8);
        assertFalse(preparedText.contains(FIRST.value));
        assertFalse(preparedText.contains(SECOND.value));
        previous.fs.failPointContains = null;
        assertState(previous.restart().load(), 2, true, SECOND);
        assertFalse(previous.fs.exists(previous.pendingFile()));

        Fixture target = configuredFixture();
        target.fs.failPointContains = "after:replace:" + target.activeFile().getPath();
        expectCode("state_commit_failed", () -> target.store.update(INSTANCE, true, SECOND));
        assertTrue(target.fs.exists(target.pendingFile()));
        target.fs.failPointContains = null;
        assertState(target.restart().load(), 2, true, SECOND);
        assertFalse(target.fs.exists(target.pendingFile()));

        Fixture third = configuredFixture();
        third.fs.failPointContains = "before:replace:" + third.activeFile().getPath();
        expectCode("state_commit_failed", () -> third.store.update(INSTANCE, true, SECOND));
        third.fs.failPointContains = null;
        byte[] thirdPointer = canonical(map(
                "schemaVersion", 2L,
                "instanceId", INSTANCE,
                "stateId", repeat('a', 64),
                "keyId", repeat('b', 64)));
        third.fs.replaceRaw(third.activeFile(), thirdPointer, 0600, third.fs.ownerUid());
        byte[] pending = third.fs.bytes(third.pendingFile());
        expectCode("proxy_state_invalid", () -> third.restart().load());
        assertArrayEquals(thirdPointer, third.fs.bytes(third.activeFile()));
        assertArrayEquals(pending, third.fs.bytes(third.pendingFile()));
    }

    @Test
    public void missingPointerDistinguishesFreshFromOrphans() throws Exception {
        Fixture fresh = new Fixture();
        assertTrue(fresh.store.load().requiresInstanceId);

        Fixture stateOrphan = new Fixture();
        stateOrphan.store.load();
        File orphan = new File(stateOrphan.statesDirectory(), repeat('c', 64) + ".json");
        byte[] orphanBytes = "{\"orphan\":true}".getBytes(StandardCharsets.UTF_8);
        stateOrphan.fs.putFile(orphan, orphanBytes, 0600, stateOrphan.fs.ownerUid());
        expectCode("proxy_state_invalid", () -> stateOrphan.restart().load());
        assertArrayEquals(orphanBytes, stateOrphan.fs.bytes(orphan));

        Fixture keyOrphan = new Fixture();
        keyOrphan.store.load();
        File orphanKey = new File(keyOrphan.keysDirectory(), repeat('d', 64) + ".key");
        byte[] keyBytes = new byte[32];
        keyOrphan.fs.putFile(orphanKey, keyBytes, 0600, keyOrphan.fs.ownerUid());
        expectCode("proxy_state_invalid", () -> keyOrphan.restart().load());
        assertArrayEquals(keyBytes, keyOrphan.fs.bytes(orphanKey));
    }

    @Test
    public void unusableLegacyKeyAndMalformedMetadataNeverEraseSourceEvidence() throws Exception {
        Fixture unavailable = new Fixture();
        unavailable.keys.legacyUnavailable = true;
        unavailable.keys.legacyPlaintext = legacySource(FIRST);
        byte[] legacyBytes = legacyEnvelope(INSTANCE, 4, true);
        unavailable.fs.putFile(unavailable.legacyFile, legacyBytes, 0600,
                unavailable.fs.ownerUid());
        expectCode("proxy_state_key_unusable", () -> unavailable.store.load());
        assertArrayEquals(legacyBytes, unavailable.fs.bytes(unavailable.legacyFile));
        assertFalse(unavailable.keys.aliasDeleted);

        Fixture malformedMode = configuredFixture();
        byte[] active = malformedMode.fs.bytes(malformedMode.activeFile());
        malformedMode.fs.setMode(malformedMode.activeFile(), 0644);
        expectCode("proxy_state_invalid", () -> malformedMode.restart().load());
        assertArrayEquals(active, malformedMode.fs.bytes(malformedMode.activeFile()));
        assertFalse(malformedMode.fs.names(malformedMode.evidenceDirectory()).isEmpty());

        Fixture malformedOwner = configuredFixture();
        byte[] ownerActive = malformedOwner.fs.bytes(malformedOwner.activeFile());
        malformedOwner.fs.setOwner(malformedOwner.activeFile(), 9999);
        expectCode("proxy_state_invalid", () -> malformedOwner.restart().load());
        assertArrayEquals(ownerActive, malformedOwner.fs.bytes(malformedOwner.activeFile()));

        Fixture hardlink = configuredFixture();
        byte[] hardlinkActive = hardlink.fs.bytes(hardlink.activeFile());
        hardlink.fs.setLinks(hardlink.activeFile(), 2);
        expectCode("proxy_state_invalid", () -> hardlink.restart().load());
        assertArrayEquals(hardlinkActive, hardlink.fs.bytes(hardlink.activeFile()));

        Fixture symlink = configuredFixture();
        byte[] symlinkActive = symlink.fs.bytes(symlink.activeFile());
        symlink.fs.setSymbolic(symlink.activeFile(), true);
        expectCode("proxy_state_invalid", () -> symlink.restart().load());
        assertArrayEquals(symlinkActive, symlink.fs.bytes(symlink.activeFile()));
    }

    @Test
    public void malformedPointerEnvelopeAadAndV2KeyMismatchFailClosed() throws Exception {
        Fixture malformedPointer = configuredFixture();
        byte[] malformed = "{\"schemaVersion\":2}".getBytes(StandardCharsets.UTF_8);
        malformedPointer.fs.replaceRaw(malformedPointer.activeFile(), malformed, 0600,
                malformedPointer.fs.ownerUid());
        expectCode("proxy_state_invalid", () -> malformedPointer.restart().load());
        assertArrayEquals(malformed, malformedPointer.fs.bytes(malformedPointer.activeFile()));

        Fixture malformedPending = configuredFixture();
        malformedPending.fs.failPointContains =
                "before:replace:" + malformedPending.activeFile().getPath();
        expectCode("state_commit_failed",
                () -> malformedPending.store.update(INSTANCE, true, SECOND));
        malformedPending.fs.failPointContains = null;
        Map<String, Object> pendingObject =
                parse(malformedPending.fs.bytes(malformedPending.pendingFile()));
        pendingObject.put("unexpected", true);
        byte[] invalidPending = canonical(pendingObject);
        malformedPending.fs.replaceRaw(
                malformedPending.pendingFile(), invalidPending, 0600,
                malformedPending.fs.ownerUid());
        expectCode("proxy_state_invalid", () -> malformedPending.restart().load());
        assertArrayEquals(invalidPending,
                malformedPending.fs.bytes(malformedPending.pendingFile()));

        Fixture envelope = configuredFixture();
        Map<String, Object> pointer = parse(envelope.fs.bytes(envelope.activeFile()));
        File oldState = new File(envelope.statesDirectory(), pointer.get("stateId") + ".json");
        Map<String, Object> state = parse(envelope.fs.bytes(oldState));
        state.put("generation", ((Long) state.get("generation")) + 1L);
        byte[] modifiedState = canonical(state);
        String modifiedStateId = sha256(modifiedState);
        File modifiedStateFile = new File(envelope.statesDirectory(), modifiedStateId + ".json");
        envelope.fs.putFile(modifiedStateFile, modifiedState, 0600, envelope.fs.ownerUid());
        pointer.put("stateId", modifiedStateId);
        envelope.fs.replaceRaw(envelope.activeFile(), canonical(pointer), 0600,
                envelope.fs.ownerUid());
        expectCode("proxy_state_invalid", () -> envelope.restart().load());
        assertArrayEquals(modifiedState, envelope.fs.bytes(modifiedStateFile));

        Fixture keyMismatch = configuredFixture();
        Map<String, Object> keyPointer = parse(keyMismatch.fs.bytes(keyMismatch.activeFile()));
        File keyFile = new File(keyMismatch.keysDirectory(), keyPointer.get("keyId") + ".key");
        byte[] displacedKey = keyMismatch.fs.bytes(keyFile);
        byte[] wrongKey = displacedKey.clone();
        wrongKey[0] ^= 0x55;
        keyMismatch.fs.replaceRaw(keyFile, wrongKey, 0600, keyMismatch.fs.ownerUid());
        expectCode("proxy_state_key_mismatch", () -> keyMismatch.restart().load());
        assertArrayEquals(wrongKey, keyMismatch.fs.bytes(keyFile));
    }

    @Test
    public void importRecoveryQuarantinesControlsRetainsOrphansAndWritesHashOnlyEvidence()
            throws Exception {
        Fixture fixture = configuredFixture();
        File orphan = new File(fixture.statesDirectory(), repeat('e', 64) + ".json");
        byte[] orphanBytes = "orphan-state-evidence".getBytes(StandardCharsets.UTF_8);
        fixture.fs.putFile(orphan, orphanBytes, 0600, fixture.fs.ownerUid());
        byte[] invalidActive = "{\"broken\":true}".getBytes(StandardCharsets.UTF_8);
        String invalidDigest = sha256(invalidActive);
        fixture.fs.replaceRaw(fixture.activeFile(), invalidActive, 0600, fixture.fs.ownerUid());

        ProxyStateStore.LoadedState recovered = fixture.restart()
                .recoverImport(INSTANCE, true, SECOND);
        assertTrue(recovered.enabled);
        assertTrue(recovered.source.sameAs(SECOND));
        assertFalse(fixture.fs.exists(fixture.pendingFile()));
        assertArrayEquals(orphanBytes, fixture.fs.bytes(orphan));
        File quarantined = new File(fixture.quarantineDirectory(), invalidDigest + ".raw");
        assertArrayEquals(invalidActive, fixture.fs.bytes(quarantined));
        assertEvidenceContains(fixture, invalidDigest);
        assertNoEvidenceContains(fixture, FIRST.value);
        assertNoEvidenceContains(fixture, SECOND.value);

        List<String> firstEvidence = fixture.fs.names(fixture.evidenceDirectory());
        Map<String, Object> active = parse(fixture.fs.bytes(fixture.activeFile()));
        byte[] secondInvalid = "{\"broken\":\"again\"}".getBytes(StandardCharsets.UTF_8);
        String secondDigest = sha256(secondInvalid);
        fixture.fs.replaceRaw(fixture.activeFile(), secondInvalid, 0600, fixture.fs.ownerUid());
        ProxyStateStore.LoadedState recoveredAgain = fixture.restart()
                .recoverImport(INSTANCE, false, FIRST);
        assertFalse(recoveredAgain.enabled);
        assertTrue(recoveredAgain.source.sameAs(FIRST));
        assertTrue(recoveredAgain.generation >= 0);
        assertTrue(fixture.fs.names(fixture.evidenceDirectory()).containsAll(firstEvidence));
        assertEvidenceContains(fixture, invalidDigest);
        assertEvidenceContains(fixture, secondDigest);
        assertArrayEquals(orphanBytes, fixture.fs.bytes(orphan));
        assertNotEquals(active, parse(fixture.fs.bytes(fixture.activeFile())));
    }

    @Test
    public void ordinaryClearRefusesUnreadableAndExplicitDiscardPreservesEvidence()
            throws Exception {
        Fixture fixture = configuredFixture();
        byte[] invalidActive = "not-a-pointer".getBytes(StandardCharsets.UTF_8);
        String digest = sha256(invalidActive);
        fixture.fs.replaceRaw(fixture.activeFile(), invalidActive, 0600, fixture.fs.ownerUid());
        int evidenceBefore = fixture.fs.names(fixture.evidenceDirectory()).size();

        expectCode("proxy_state_invalid", () -> fixture.restart().clear(INSTANCE, false));
        assertArrayEquals(invalidActive, fixture.fs.bytes(fixture.activeFile()));
        assertEquals(evidenceBefore, fixture.fs.names(fixture.evidenceDirectory()).size());

        ProxyStateStore.LoadedState cleared = fixture.restart().clear(INSTANCE, true);
        assertFalse(cleared.enabled);
        assertNull(cleared.source);
        assertTrue(cleared.generation >= 0);
        assertFalse(fixture.fs.exists(fixture.pendingFile()));
        assertArrayEquals(invalidActive,
                fixture.fs.bytes(new File(fixture.quarantineDirectory(), digest + ".raw")));
        assertEvidenceContains(fixture, digest);
        assertTrue(fixture.fs.names(fixture.evidenceDirectory()).size() > evidenceBefore);
    }

    @Test
    public void recoveryCrashAfterControlDeletionPreservesGenerationFloor()
            throws Exception {
        Fixture fixture = configuredFixture();
        Map<String, Object> pointer = parse(fixture.fs.bytes(fixture.activeFile()));
        File keyFile = new File(
                fixture.keysDirectory(), pointer.get("keyId") + ".key");
        byte[] wrongKey = fixture.fs.bytes(keyFile);
        wrongKey[0] ^= 0x33;
        fixture.fs.replaceRaw(keyFile, wrongKey, 0600, fixture.fs.ownerUid());
        fixture.fs.resetBoundaries();
        fixture.fs.failPointContains =
                "after:delete:" + fixture.activeFile().getPath();
        expectCode("state_commit_failed",
                () -> fixture.restart().clear(INSTANCE, true));
        assertFalse(fixture.fs.exists(fixture.activeFile()));
        fixture.fs.failPointContains = null;
        fixture.fs.resetBoundaries();

        ProxyStateStore.LoadedState recovered =
                fixture.restart().clear(INSTANCE, true);
        assertState(recovered, 2, false, null);
    }

    @Test
    public void typedMalformedRecoveryUsesOnlyTrustedGenerationAndRejectsForeignIdentity()
            throws Exception {
        Fixture malformedActive = configuredFixture();
        byte[] missingState = canonical(map(
                "schemaVersion", 2L,
                "instanceId", INSTANCE,
                "stateId", repeat('a', 64),
                "keyId", repeat('b', 64)));
        malformedActive.fs.replaceRaw(
                malformedActive.activeFile(), missingState, 0600,
                malformedActive.fs.ownerUid());
        assertState(
                malformedActive.restart().clear(INSTANCE, true),
                0, false, null);

        Fixture malformedPending = configuredFixture();
        malformedPending.fs.failPointContains =
                "before:replace:" + malformedPending.activeFile().getPath();
        expectCode("state_commit_failed",
                () -> malformedPending.store.update(INSTANCE, true, SECOND));
        malformedPending.fs.failPointContains = null;
        Map<String, Object> pending =
                parse(malformedPending.fs.bytes(malformedPending.pendingFile()));
        pending.put("transactionId", "bad");
        malformedPending.fs.replaceRaw(
                malformedPending.pendingFile(), canonical(pending), 0600,
                malformedPending.fs.ownerUid());
        assertState(
                malformedPending.restart().clear(INSTANCE, true),
                2, false, null);

        Fixture foreign = configuredFixture();
        byte[] foreignPointer = canonical(map(
                "schemaVersion", 2L,
                "instanceId", "223e4567-e89b-42d3-a456-426614174000",
                "stateId", repeat('c', 64),
                "keyId", repeat('d', 64)));
        foreign.fs.replaceRaw(
                foreign.activeFile(), foreignPointer, 0600,
                foreign.fs.ownerUid());
        expectCode("proxy_state_invalid",
                () -> foreign.restart().clear(INSTANCE, true));
        expectCode("proxy_state_invalid",
                () -> foreign.restart().clear(INSTANCE, true));
    }

    @Test
    public void v2KeyReuseCryptographicRecoveryAndKeyboxIndependence() throws Exception {
        Fixture fixture = configuredFixture();
        List<String> initialKeys = fixture.fs.names(fixture.keysDirectory());
        long keyboxMarker = fixture.keys.keyboxMarker;
        assertState(fixture.store.update(INSTANCE, false, SECOND), 2, false, SECOND);
        assertEquals(initialKeys, fixture.fs.names(fixture.keysDirectory()));
        assertEquals(keyboxMarker, fixture.keys.keyboxMarker);

        ProxyStateStore.LoadedState cleared = fixture.store.clear(INSTANCE, false);
        assertState(cleared, 3, false, null);
        List<String> clearKeys = fixture.fs.names(fixture.keysDirectory());
        assertEquals(1, clearKeys.size());
        assertNotEquals(initialKeys, clearKeys);
        assertEquals(keyboxMarker, fixture.keys.keyboxMarker);

        byte[] invalidActive = "{\"invalid\":true}".getBytes(StandardCharsets.UTF_8);
        fixture.fs.replaceRaw(fixture.activeFile(), invalidActive, 0600, fixture.fs.ownerUid());
        ProxyStateStore.LoadedState recovered = fixture.restart()
                .recoverImport(INSTANCE, true, FIRST);
        assertTrue(recovered.enabled);
        assertTrue(recovered.source.sameAs(FIRST));
        List<String> recoveredKeys = fixture.fs.names(fixture.keysDirectory());
        assertTrue(recoveredKeys.containsAll(clearKeys));
        assertTrue(recoveredKeys.size() > clearKeys.size());
        assertEquals(keyboxMarker, fixture.keys.keyboxMarker);
    }
    private static Fixture configuredFixture() throws Exception {
        Fixture fixture = new Fixture();
        fixture.store.bindInstance(INSTANCE);
        fixture.store.update(INSTANCE, true, FIRST);
        fixture.fs.resetBoundaries();
        return fixture;
    }

    private static void assertState(
            ProxyStateStore.LoadedState state,
            long generation,
            boolean enabled,
            ProxyStateStore.Source source) {
        assertFalse(state.requiresInstanceId);
        assertEquals(INSTANCE, state.instanceId);
        assertEquals(generation, state.generation);
        assertEquals(enabled, state.enabled);
        if (source == null) {
            assertNull(state.source);
        } else {
            assertNotNull(state.source);
            assertTrue(state.source.sameAs(source));
        }
    }

    private static void expectCode(String code, Throwing action) throws Exception {
        try {
            action.run();
            fail("expected " + code);
        } catch (ProxyStateStore.StateException failure) {
            assertEquals(code, failure.code);
        }
    }

    private static boolean containsBoundary(List<String> values, String part) {
        for (String value : values) if (value.contains(part)) return true;
        return false;
    }

    private static void assertEvidenceContains(Fixture fixture, String digest) throws Exception {
        for (String name : fixture.fs.names(fixture.evidenceDirectory())) {
            String text = new String(
                    fixture.fs.bytes(new File(fixture.evidenceDirectory(), name)),
                    StandardCharsets.UTF_8);
            if (text.contains(digest)) return;
        }
        fail("evidence digest absent: " + digest);
    }

    private static void assertNoEvidenceContains(Fixture fixture, String secret) throws Exception {
        for (String name : fixture.fs.names(fixture.evidenceDirectory())) {
            String text = new String(
                    fixture.fs.bytes(new File(fixture.evidenceDirectory(), name)),
                    StandardCharsets.UTF_8);
            assertFalse(text, text.contains(secret));
        }
    }

    private static byte[] legacySource(ProxyStateStore.Source source) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(1);
        writeLegacyString(output, source.kind);
        writeLegacyString(output, source.value);
        writeLegacyString(output, source.selectedNode);
        output.writeBoolean(source.udpAllowed);
        output.writeBoolean(source.allowInsecureHttp);
        output.close();
        return bytes.toByteArray();
    }

    private static void writeLegacyString(DataOutputStream output, String value) throws Exception {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static byte[] legacyEnvelope(
            String instanceId, long generation, boolean enabled) throws Exception {
        return canonical(map(
                "schemaVersion", 1L,
                "instanceId", instanceId,
                "generation", generation,
                "enabled", enabled,
                "sourceIv", Base64.getEncoder().encodeToString(new byte[12]),
                "sourceCiphertext", Base64.getEncoder().encodeToString(new byte[16])));
    }

    private static Map<String, Object> map(Object... values) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            result.put(String.valueOf(values[index]), values[index + 1]);
        }
        return result;
    }

    private static byte[] canonical(Object value) throws Exception {
        StringBuilder output = new StringBuilder();
        appendCanonical(output, value);
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private static void appendCanonical(StringBuilder output, Object value) throws Exception {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String) {
            output.append(JSONObject.quote((String) value));
        } else if (value instanceof Boolean || value instanceof Number) {
            output.append(value);
        } else if (value instanceof Map) {
            Map<String, Object> object = (Map<String, Object>) value;
            List<String> keys = new ArrayList<>(object.keySet());
            Collections.sort(keys);
            output.append('{');
            for (int index = 0; index < keys.size(); index++) {
                if (index > 0) output.append(',');
                String key = keys.get(index);
                output.append(JSONObject.quote(key)).append(':');
                appendCanonical(output, object.get(key));
            }
            output.append('}');
        } else if (value instanceof List) {
            output.append('[');
            List<?> array = (List<?>) value;
            for (int index = 0; index < array.size(); index++) {
                if (index > 0) output.append(',');
                appendCanonical(output, array.get(index));
            }
            output.append(']');
        } else {
            throw new IllegalArgumentException(String.valueOf(value));
        }
    }

    private static Map<String, Object> parse(byte[] bytes) throws Exception {
        return convertObject(new JSONObject(new String(bytes, StandardCharsets.UTF_8)));
    }

    private static Map<String, Object> convertObject(JSONObject object) throws Exception {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        for (java.util.Iterator<String> iterator = object.keys(); iterator.hasNext();) {
            names.add(iterator.next());
        }
        Collections.sort(names);
        for (String name : names) result.put(name, convertJson(object.get(name)));
        return result;
    }

    private static Object convertJson(Object value) throws Exception {
        if (value == JSONObject.NULL) return null;
        if (value instanceof JSONObject) return convertObject((JSONObject) value);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            ArrayList<Object> result = new ArrayList<>();
            for (int index = 0; index < array.length(); index++) {
                result.add(convertJson(array.get(index)));
            }
            return result;
        }
        if (value instanceof Number) return ((Number) value).longValue();
        return value;
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder output = new StringBuilder(64);
        for (byte item : digest) output.append(String.format("%02x", item & 0xff));
        return output.toString();
    }

    private static String repeat(char value, int count) {
        char[] output = new char[count];
        Arrays.fill(output, value);
        return new String(output);
    }

    private interface Throwing {
        void run() throws Exception;
    }

    private static final class Fixture {
        final File noBackup = new File("/fixture/no-backup");
        final File legacyFile = new File("/fixture/files/proxy-state/desired-v1.json");
        final FakeFilesystem fs;
        final FakeKeys keys;
        final ProxyStateStore store;

        Fixture() {
            this(new FakeFilesystem(), new FakeKeys());
        }

        Fixture(FakeFilesystem fs, FakeKeys keys) {
            this.fs = fs;
            this.keys = keys;
            fs.putDirectory(new File("/fixture"), 0700, fs.ownerUid());
            fs.putDirectory(noBackup, 0700, fs.ownerUid());
            fs.putDirectory(new File("/fixture/files"), 0700, fs.ownerUid());
            fs.putDirectory(legacyFile.getParentFile(), 0700, fs.ownerUid());
            store = new ProxyStateStore(noBackup, legacyFile, fs, keys);
        }

        ProxyStateStore restart() {
            return new ProxyStateStore(noBackup, legacyFile, fs, keys);
        }

        File root() {
            return new File(new File(noBackup, ProxyStateStore.ROOT_DIRECTORY),
                    ProxyStateStore.VERSION_DIRECTORY);
        }

        File activeFile() { return new File(root(), ProxyStateStore.ACTIVE_NAME); }
        File pendingFile() { return new File(root(), ProxyStateStore.PENDING_NAME); }
        File keysDirectory() { return new File(root(), ProxyStateStore.KEY_DIRECTORY); }
        File statesDirectory() { return new File(root(), ProxyStateStore.STATE_DIRECTORY); }
        File evidenceDirectory() { return new File(root(), ProxyStateStore.EVIDENCE_DIRECTORY); }
        File quarantineDirectory() { return new File(root(), ProxyStateStore.QUARANTINE_DIRECTORY); }
    }

    /** Package-private, deterministic backend with failure injection at write/rename/fsync edges. */
    static final class FakeFilesystem implements ProxyStateStore.FilesystemBackend {
        private static final class Node {
            boolean directory;
            boolean symbolic;
            int uid;
            int mode;
            long links;
            long inode;
            byte[] bytes;

            Node copy() {
                Node result = new Node();
                result.directory = directory;
                result.symbolic = symbolic;
                result.uid = uid;
                result.mode = mode;
                result.links = links;
                result.inode = inode;
                result.bytes = bytes == null ? null : bytes.clone();
                return result;
            }
        }

        private final LinkedHashMap<String, Node> nodes = new LinkedHashMap<>();
        final List<String> boundaries = new ArrayList<>();
        int failBoundary = -1;
        String failPointContains;
        private int boundaryOrdinal;
        private long nextInode = 10;

        @Override
        public int ownerUid() { return 2000; }

        @Override
        public ProxyStateStore.Metadata lstat(File file) {
            Node node = nodes.get(path(file));
            if (node == null) return ProxyStateStore.Metadata.missing();
            long size = node.bytes == null ? 0 : node.bytes.length;
            return new ProxyStateStore.Metadata(
                    true,
                    !node.directory,
                    node.directory,
                    node.symbolic,
                    node.uid,
                    node.mode,
                    node.links,
                    size,
                    1,
                    node.inode);
        }

        @Override
        public List<String> list(File directory) throws Exception {
            Node parent = require(directory);
            if (!parent.directory) throw new Exception("not_directory");
            String prefix = path(directory) + "/";
            ArrayList<String> result = new ArrayList<>();
            for (String name : nodes.keySet()) {
                if (!name.startsWith(prefix)) continue;
                String suffix = name.substring(prefix.length());
                if (!suffix.isEmpty() && suffix.indexOf('/') < 0) result.add(suffix);
            }
            Collections.sort(result);
            return result;
        }

        @Override
        public byte[] read(File file, int maximum) throws Exception {
            Node node = require(file);
            if (node.directory || node.bytes == null || node.bytes.length > maximum) {
                throw new Exception("invalid_read");
            }
            return node.bytes.clone();
        }

        @Override
        public void mkdir(File directory, int mode) throws Exception {
            mutate("mkdir", directory, () -> {
                if (nodes.containsKey(path(directory))) throw new Exception("exists");
                putDirectory(directory, mode, ownerUid());
            });
        }

        @Override
        public void writeNew(File file, byte[] bytes, int mode) throws Exception {
            mutate("writeNew", file, () -> {
                if (nodes.containsKey(path(file))) throw new Exception("exists");
                putFile(file, bytes, mode, ownerUid());
            });
        }

        @Override
        public void replace(File file, byte[] bytes, int mode) throws Exception {
            mutate("replace", file, () -> replaceRaw(file, bytes, mode, ownerUid()));
        }

        @Override
        public void delete(File file) throws Exception {
            mutate("delete", file, () -> {
                if (nodes.remove(path(file)) == null) throw new Exception("missing");
            });
        }

        @Override
        public void syncDirectory(File directory) throws Exception {
            point("before:fsync:" + path(directory));
            require(directory);
            point("after:fsync:" + path(directory));
        }

        void resetBoundaries() {
            boundaries.clear();
            boundaryOrdinal = 0;
            failBoundary = -1;
            failPointContains = null;
        }

        FakeFilesystem copy() {
            FakeFilesystem copy = new FakeFilesystem();
            copy.nextInode = nextInode;
            for (Map.Entry<String, Node> entry : nodes.entrySet()) {
                copy.nodes.put(entry.getKey(), entry.getValue().copy());
            }
            return copy;
        }

        List<String> names(File directory) throws Exception { return list(directory); }
        boolean exists(File file) { return nodes.containsKey(path(file)); }

        byte[] bytes(File file) throws Exception {
            Node node = require(file);
            return node.bytes == null ? null : node.bytes.clone();
        }

        void putDirectory(File directory, int mode, int uid) {
            if (nodes.containsKey(path(directory))) return;
            Node node = new Node();
            node.directory = true;
            node.uid = uid;
            node.mode = mode;
            node.links = 1;
            node.inode = nextInode++;
            nodes.put(path(directory), node);
        }

        void putFile(File file, byte[] bytes, int mode, int uid) {
            Node node = new Node();
            node.directory = false;
            node.uid = uid;
            node.mode = mode;
            node.links = 1;
            node.inode = nextInode++;
            node.bytes = bytes.clone();
            nodes.put(path(file), node);
        }

        void replaceRaw(File file, byte[] bytes, int mode, int uid) {
            putFile(file, bytes, mode, uid);
        }

        void setMode(File file, int mode) throws Exception { require(file).mode = mode; }
        void setOwner(File file, int uid) throws Exception { require(file).uid = uid; }
        void setLinks(File file, long links) throws Exception { require(file).links = links; }
        void setSymbolic(File file, boolean symbolic) throws Exception {
            require(file).symbolic = symbolic;
        }

        private Node require(File file) throws Exception {
            Node node = nodes.get(path(file));
            if (node == null) throw new Exception("missing: " + path(file));
            return node;
        }

        private void mutate(String operation, File target, Mutation action) throws Exception {
            String location = path(target);
            point("before:" + operation + ":" + location);
            action.run();
            point("after:" + operation + ":" + location);
            point("before:fsync:" + path(target.getParentFile()));
            point("after:fsync:" + path(target.getParentFile()));
        }

        private void point(String value) throws Exception {
            boundaries.add(value);
            boundaryOrdinal++;
            if (boundaryOrdinal == failBoundary
                    || (failPointContains != null && value.contains(failPointContains))) {
                throw new Exception("injected_failure:" + value);
            }
        }

        private static String path(File file) { return file.getPath(); }

        private interface Mutation { void run() throws Exception; }
    }

    /** Package-private deterministic key seam; it never touches AndroidKeyStore or KeyMint. */
    static final class FakeKeys implements ProxyStateStore.KeyBackend {
        int counter = 1;
        byte[] legacyPlaintext;
        boolean legacyUnavailable;
        boolean aliasDeleted;
        boolean failAliasDeleteBefore;
        boolean failAliasDeleteAfter;
        long keyboxMarker = 0x4b4559424f584cL;

        @Override
        public byte[] randomBytes(int count) {
            byte[] result = new byte[count];
            for (int index = 0; index < count; index++) {
                result[index] = (byte) (counter + index * 17);
            }
            counter += 31;
            return result;
        }

        @Override
        public byte[] decryptLegacy(byte[] iv, byte[] ciphertext, byte[] aad)
                throws ProxyStateStore.KeyUnavailableException {
            if (legacyUnavailable || legacyPlaintext == null) {
                throw new ProxyStateStore.KeyUnavailableException();
            }
            assertEquals(12, iv.length);
            assertTrue(ciphertext.length >= 16);
            assertEquals("XENOID-PROXY-STATE-V1\n" + INSTANCE + "\n9",
                    new String(aad, StandardCharsets.UTF_8));
            return legacyPlaintext.clone();
        }

        @Override
        public void deleteLegacyAlias() throws Exception {
            if (failAliasDeleteBefore) throw new Exception("alias_delete_before");
            aliasDeleted = true;
            if (failAliasDeleteAfter) throw new Exception("alias_delete_after");
        }

        FakeKeys copy() {
            FakeKeys copy = new FakeKeys();
            copy.counter = counter;
            copy.legacyPlaintext = legacyPlaintext == null ? null : legacyPlaintext.clone();
            copy.legacyUnavailable = legacyUnavailable;
            copy.aliasDeleted = aliasDeleted;
            copy.keyboxMarker = keyboxMarker;
            return copy;
        }
    }
}
