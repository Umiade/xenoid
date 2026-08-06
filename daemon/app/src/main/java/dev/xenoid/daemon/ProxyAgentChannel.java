package dev.xenoid.daemon;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Process-scoped, direction-separated authenticated channel for one engine runtime. */
public final class ProxyAgentChannel {
    private static final long CLOCK_SKEW_SECONDS = 120;
    private static final int MAX_SESSIONS = 32;
    private static final int MASTER_KEY_BYTES = 32;
    private static final int GCM_TAG_BYTES = 16;
    private static final int MAX_CIPHERTEXT_BYTES =
            ProxyManager.MAX_AGENT_PLAINTEXT_BYTES + GCM_TAG_BYTES;
    private static final String AAD_PREFIX = "XENOID-PROXY-AEAD-V1";
    private static final byte[] C2S_INFO =
            "xenoid-proxy-agent/c2s".getBytes(StandardCharsets.UTF_8);
    private static final byte[] S2C_INFO =
            "xenoid-proxy-agent/s2c".getBytes(StandardCharsets.UTF_8);
    private static final Pattern INSTANCE_ID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern SAFE_EPOCH = Pattern.compile(
            "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern HEX_128 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern STANDARD_BASE64 = Pattern.compile(
            "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");

    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private final ProxyManager manager;
    private final SecureRandom random;
    private final LinkedHashMap<String, Long> highWater = new LinkedHashMap<>();
    private String instanceId = "";
    private String runtimeEpoch = "";
    private byte[] c2sKey;
    private byte[] s2cKey;
    private byte[] agentToken;

    public ProxyAgentChannel(ProxyManager manager) throws InitializationException {
        if (manager == null) throw new InitializationException();
        this.manager = manager;
        try {
            random = new SecureRandom();
            byte[] test = new byte[1];
            random.nextBytes(test);
            Arrays.fill(test, (byte) 0);
        } catch (Throwable ignored) {
            throw new InitializationException();
        }
    }

    public synchronized Map<String, Object> bootstrap(Map<String, Object> request)
            throws ProxyManager.ProxyException {
        ProxyManager.requireKeys(request, "instanceId", "runtimeEpoch");
        String requestedInstance = ProxyManager.requireString(request, "instanceId", 36, false);
        String requestedEpoch = ProxyManager.requireString(request, "runtimeEpoch", 128, false);
        if (!isValidInstanceId(requestedInstance) || !isValidRuntimeEpoch(requestedEpoch)) {
            throw new ProxyManager.ProxyException("invalid_request_schema");
        }

        byte[] master = new byte[MASTER_KEY_BYTES];
        byte[] rawAgentToken = new byte[MASTER_KEY_BYTES];
        byte[] nextC2s = null;
        byte[] nextS2c = null;
        byte[] nextAgentToken = null;
        String encodedMaster;
        String encodedAgentToken;
        try {
            random.nextBytes(master);
            random.nextBytes(rawAgentToken);
            nextC2s = deriveDirectionKey(master, requestedInstance, requestedEpoch, C2S_INFO);
            nextS2c = deriveDirectionKey(master, requestedInstance, requestedEpoch, S2C_INFO);
            encodedMaster = java.util.Base64.getEncoder().encodeToString(master);
            encodedAgentToken =
                    java.util.Base64.getEncoder().encodeToString(rawAgentToken);
            nextAgentToken = encodedAgentToken.getBytes(StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ignored) {
            wipe(nextC2s);
            wipe(nextS2c);
            wipe(nextAgentToken);
            throw new ProxyManager.ProxyException("proxy_unavailable");
        } finally {
            wipe(master);
            wipe(rawAgentToken);
        }

        try {
            manager.bindRuntime(requestedInstance, requestedEpoch);
        } catch (ProxyManager.ProxyException failure) {
            wipe(nextC2s);
            wipe(nextS2c);
            wipe(nextAgentToken);
            throw failure;
        }
        wipe(c2sKey);
        wipe(s2cKey);
        wipe(agentToken);
        c2sKey = nextC2s;
        s2cKey = nextS2c;
        agentToken = nextAgentToken;
        instanceId = requestedInstance;
        runtimeEpoch = requestedEpoch;
        highWater.clear();
        return map(
                "ok", true,
                "version", 1,
                "instanceId", instanceId,
                "runtimeEpoch", runtimeEpoch,
                "masterKey", encodedMaster,
                "agentToken", encodedAgentToken);
    }

    /**
     * Opens one c2s request, performs the operation, and seals a direction-bound s2c response.
     * Envelope/authentication failures intentionally collapse to AgentRejected.
     */
    public synchronized Map<String, Object> handle(Map<String, Object> envelope)
            throws AgentRejected {
        if (c2sKey == null || s2cKey == null) throw new AgentRejected();

        String requestInstance;
        String requestEpoch;
        String session;
        String requestId;
        String encodedCiphertext;
        long sequence;
        try {
            ProxyManager.requireKeys(envelope, "version", "instanceId", "runtimeEpoch",
                    "session", "seq", "requestId", "ciphertext");
            if (ProxyManager.requireLong(envelope, "version", 1, 1) != 1) {
                throw new AgentRejected();
            }
            requestInstance = ProxyManager.requireString(envelope, "instanceId", 36, false);
            requestEpoch = ProxyManager.requireString(envelope, "runtimeEpoch", 128, false);
            session = ProxyManager.requireString(envelope, "session", 32, false);
            sequence = ProxyManager.requireLong(envelope, "seq", 1, Long.MAX_VALUE);
            requestId = ProxyManager.requireString(envelope, "requestId", 32, false);
            encodedCiphertext = ProxyManager.requireString(
                    envelope, "ciphertext", encodedCiphertextLimit(), false);
            if (!instanceId.equals(requestInstance) || !runtimeEpoch.equals(requestEpoch)
                    || !HEX_128.matcher(session).matches()
                    || !HEX_128.matcher(requestId).matches()
                    || !STANDARD_BASE64.matcher(encodedCiphertext).matches()) {
                throw new AgentRejected();
            }
        } catch (ProxyManager.ProxyException ignored) {
            throw new AgentRejected();
        }

        Long previous = highWater.get(session);
        if (previous != null && sequence <= previous) throw new AgentRejected();
        if (previous == null && highWater.size() >= MAX_SESSIONS) throw new AgentRejected();

        byte[] ciphertext;
        try {
            ciphertext = java.util.Base64.getDecoder().decode(encodedCiphertext);
        } catch (IllegalArgumentException ignored) {
            throw new AgentRejected();
        }
        if (!encodedCiphertext.equals(
                java.util.Base64.getEncoder().encodeToString(ciphertext))) {
            wipe(ciphertext);
            throw new AgentRejected();
        }
        if (ciphertext.length < GCM_TAG_BYTES || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
            wipe(ciphertext);
            throw new AgentRejected();
        }

        byte[] plaintext = null;
        try {
            plaintext = open(
                    c2sKey, "c2s", requestInstance, requestEpoch, session, sequence,
                    requestId, 0, ciphertext);
        } catch (GeneralSecurityException ignored) {
            throw new AgentRejected();
        } finally {
            wipe(ciphertext);
        }
        // Authentication succeeded. Consume this sequence even if the operation is malformed.
        highWater.put(session, sequence);

        Map<String, Object> inner;
        try {
            if (plaintext.length > ProxyManager.MAX_AGENT_PLAINTEXT_BYTES) {
                throw new AgentRejected();
            }
            inner = ProxyManager.parseObject(
                    decodeUtf8(plaintext), ProxyManager.MAX_AGENT_PLAINTEXT_BYTES);
        } catch (ProxyManager.ProxyException | CharacterCodingException ignored) {
            throw new AgentRejected();
        } finally {
            wipe(plaintext);
        }


        String operation;
        long timestamp;
        Map<String, Object> body;
        try {
            ProxyManager.requireKeys(inner, "operation", "timestamp", "body");
            operation = ProxyManager.requireString(inner, "operation", 16, false);
            timestamp = ProxyManager.requireLong(inner, "timestamp", 0, Long.MAX_VALUE);
            body = ProxyManager.requireObject(inner, "body");
        } catch (ProxyManager.ProxyException ignored) {
            return sealError(requestInstance, requestEpoch, session, sequence, requestId);
        }

        long now = System.currentTimeMillis() / 1000L;
        if (timestamp < now - CLOCK_SKEW_SECONDS || timestamp > now + CLOCK_SKEW_SECONDS) {
            throw new AgentRejected();
        }

        Map<String, Object> result;
        try {
            if ("desired".equals(operation)) {
                ProxyManager.requireKeys(body);
                result = manager.desiredForAgent(requestInstance, requestEpoch);
            } else if ("report".equals(operation)) {
                result = manager.acceptAgentReport(
                        requestInstance, requestEpoch, body, timestamp);
            } else if ("probe".equals(operation)) {
                result = manager.runAndroidProbe(requestInstance, requestEpoch, body);
            } else {
                return sealError(requestInstance, requestEpoch, session, sequence, requestId);
            }
        } catch (ProxyManager.ProxyException failure) {
            if ("agent_rejected".equals(failure.code)
                    || "instance_identity_mismatch".equals(failure.code)) {
                throw new AgentRejected();
            }
            return sealError(requestInstance, requestEpoch, session, sequence, requestId);
        }

        return sealResponse(
                requestInstance, requestEpoch, session, sequence, requestId, 200,
                map("body", result, "ok", true));
    }

    public synchronized boolean authorizedAgentToken(String supplied) {
        if (agentToken == null || supplied == null || supplied.length() > 128) return false;
        byte[] candidate = supplied.getBytes(StandardCharsets.UTF_8);
        try {
            return MessageDigest.isEqual(agentToken, candidate);
        } finally {
            wipe(candidate);
        }
    }

    public synchronized void close() {
        wipe(c2sKey);
        wipe(s2cKey);
        wipe(agentToken);
        c2sKey = null;
        s2cKey = null;
        agentToken = null;
        instanceId = "";
        runtimeEpoch = "";
        highWater.clear();
    }

    private Map<String, Object> sealError(
            String instance, String epoch, String session, long sequence, String requestId)
            throws AgentRejected {
        return sealResponse(
                instance, epoch, session, sequence, requestId, 400,
                map("error", "invalid_request", "ok", false));
    }

    private Map<String, Object> sealResponse(
            String instance, String epoch, String session, long sequence, String requestId,
            int status, Map<String, Object> inner) throws AgentRejected {
        byte[] plaintext = canonicalJson(inner).getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = null;
        try {
            ciphertext = seal(
                    s2cKey, "s2c", instance, epoch, session, sequence, requestId,
                    status, plaintext);
            return map(
                    "version", 1,
                    "instanceId", instance,
                    "runtimeEpoch", epoch,
                    "session", session,
                    "seq", sequence,
                    "requestId", requestId,
                    "status", status,
                    "ciphertext", java.util.Base64.getEncoder().encodeToString(ciphertext));
        } catch (GeneralSecurityException ignored) {
            throw new AgentRejected();
        } finally {
            wipe(plaintext);
            wipe(ciphertext);
        }
    }

    private static byte[] open(
            byte[] key, String direction, String instance, String epoch, String session,
            long sequence, String requestId, int status, byte[] ciphertext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = nonce(key, session, sequence);
        byte[] aad = aad(direction, instance, epoch, session, sequence, requestId, status);
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } finally {
            wipe(nonce);
            wipe(aad);
        }
    }

    private static byte[] seal(
            byte[] key, String direction, String instance, String epoch, String session,
            long sequence, String requestId, int status, byte[] plaintext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = nonce(key, session, sequence);
        byte[] aad = aad(direction, instance, epoch, session, sequence, requestId, status);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } finally {
            wipe(nonce);
            wipe(aad);
        }
    }

    private static byte[] nonce(byte[] key, String session, long sequence)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] digest = mac.doFinal(session.getBytes(StandardCharsets.UTF_8));
        byte[] nonce = new byte[12];
        System.arraycopy(digest, 0, nonce, 0, 4);
        wipe(digest);
        ByteBuffer.wrap(nonce, 4, 8).putLong(sequence);
        return nonce;
    }

    private static byte[] aad(
            String direction, String instance, String epoch, String session, long sequence,
            String requestId, int status) {
        return (AAD_PREFIX + "\n" + direction + "\n" + instance + "\n" + epoch + "\n"
                + session + "\n" + sequence + "\n" + requestId + "\n" + status)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] deriveDirectionKey(
            byte[] master, String instance, String epoch, byte[] info)
            throws GeneralSecurityException {
        byte[] salt = (instance + "\n" + epoch).getBytes(StandardCharsets.UTF_8);
        byte[] prk = null;
        byte[] expansion = new byte[info.length + 1];
        try {
            Mac extract = Mac.getInstance("HmacSHA256");
            extract.init(new SecretKeySpec(salt, "HmacSHA256"));
            prk = extract.doFinal(master);
            System.arraycopy(info, 0, expansion, 0, info.length);
            expansion[expansion.length - 1] = 1;
            Mac expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(prk, "HmacSHA256"));
            return expand.doFinal(expansion);
        } finally {
            wipe(salt);
            wipe(prk);
            wipe(expansion);
        }
    }

    static boolean isValidInstanceId(String value) {
        return value != null && INSTANCE_ID.matcher(value).matches();
    }

    static boolean isValidRuntimeEpoch(String value) {
        return value != null && SAFE_EPOCH.matcher(value).matches();
    }


    private static int encodedCiphertextLimit() {
        return ((MAX_CIPHERTEXT_BYTES + 2) / 3) * 4;
    }

    private static String decodeUtf8(byte[] value) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
    }

    /** Canonical compact JSON with recursively sorted keys and UTF-8 Unicode strings. */
    @SuppressWarnings("unchecked")
    static String canonicalJson(Object value) {
        StringBuilder output = new StringBuilder();
        appendCanonical(output, value);
        return output.toString();
    }

    @SuppressWarnings("unchecked")
    private static void appendCanonical(StringBuilder output, Object value) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof Boolean || value instanceof Byte
                || value instanceof Short || value instanceof Integer || value instanceof Long) {
            output.append(value);
        } else if (value instanceof String) {
            appendString(output, (String) value);
        } else if (value instanceof Map) {
            Map<String, Object> object = (Map<String, Object>) value;
            ArrayList<String> keys = new ArrayList<>(object.keySet());
            Collections.sort(keys);
            output.append('{');
            boolean first = true;
            for (String key : keys) {
                if (!first) output.append(',');
                first = false;
                appendString(output, key);
                output.append(':');
                appendCanonical(output, object.get(key));
            }
            output.append('}');
        } else if (value instanceof List) {
            output.append('[');
            boolean first = true;
            for (Object item : (List<Object>) value) {
                if (!first) output.append(',');
                first = false;
                appendCanonical(output, item);
            }
            output.append(']');
        } else {
            throw new IllegalArgumentException("unsupported JSON value");
        }
    }

    private static void appendString(StringBuilder output, String value) {
        output.append('"');
        for (int offset = 0; offset < value.length(); offset++) {
            char item = value.charAt(offset);
            switch (item) {
                case '"': output.append("\\\""); break;
                case '\\': output.append("\\\\"); break;
                case '\b': output.append("\\b"); break;
                case '\t': output.append("\\t"); break;
                case '\n': output.append("\\n"); break;
                case '\f': output.append("\\f"); break;
                case '\r': output.append("\\r"); break;
                default:
                    if (item < 0x20) {
                        output.append("\\u00");
                        output.append(HEX[(item >>> 4) & 15]).append(HEX[item & 15]);
                    } else {
                        output.append(item);
                    }
            }
        }
        output.append('"');
    }

    private static Map<String, Object> map(Object... values) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index + 1 < values.length; index += 2) {
            result.put(String.valueOf(values[index]), values[index + 1]);
        }
        return result;
    }

    private static void wipe(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    public static final class AgentRejected extends Exception {
        AgentRejected() {
            super("agent request rejected");
        }
    }

    public static final class InitializationException extends Exception {
        InitializationException() {
            super("agent channel unavailable");
        }
    }
}
