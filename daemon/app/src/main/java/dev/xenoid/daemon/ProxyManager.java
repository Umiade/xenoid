package dev.xenoid.daemon;

import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.Os;
import android.system.OsConstants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Serialized owner of proxy desired state, runtime observations, and the narrow fail-close guard.
 * Only bounded daemon probes perform networking; proxy/VPN data-plane setup never occurs here.
 */
public final class ProxyManager {
    static final int SCHEMA_VERSION = 1;
    static final int MAX_SOURCE_BYTES = 1024 * 1024;
    static final int MAX_SELECTED_NODE = 128;
    static final int MAX_REQUEST_BODY_BYTES = 6 * MAX_SOURCE_BYTES + 4096;
    static final int MAX_AGENT_PLAINTEXT_BYTES = MAX_REQUEST_BODY_BYTES;

    private static final int MAX_STATE_BYTES = 1536 * 1024;
    private static final int MAX_COUNTERS = 64;
    private static final long PROBE_TIMEOUT_MS = 45000L;
    private static final int PROBE_IO_TIMEOUT_MS = 15000;
    private static final int PROBE_DNS_TIMEOUT_MS = 40000;
    private static final int PROBE_TCP_ATTEMPT_TIMEOUT_MS = 8000;
    private static final int PROBE_BLOCKED_UDP_TIMEOUT_MS = 3000;
    private static final int PROBE_TCP_PORT = 80;
    private static final int PROBE_STUN_PORT = 3478;
    private static final int STUN_MAGIC_COOKIE = 0x2112A442;
    private static final String PROBE_V4_DNS_HOST = "1-1-1-1.sslip.io";
    private static final String PROBE_V6_DNS_HOST = "2606-4700-4700--1111.sslip.io";
    private static final byte[] PROBE_V4_TCP_ADDRESS = {1, 1, 1, 1};
    private static final byte[] PROBE_V6_TCP_ADDRESS = {
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11};
    private static final byte[] PROBE_V4_STUN_ADDRESS = {
            (byte) 162, (byte) 159, (byte) 207, 1};
    private static final byte[] PROBE_V6_STUN_ADDRESS = {
            0x26, 0x06, 0x47, 0x00, 0x00, 0x48, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    private static final SecureRandom PROBE_RANDOM = new SecureRandom();
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "dev.xenoid.daemon.proxy.desired.v1";
    private static final String STATE_NAME = "desired-v1.json";
    private static final byte[] STATE_AAD_PREFIX =
            "XENOID-PROXY-STATE-V1\n".getBytes(StandardCharsets.UTF_8);
    private static final Pattern SAFE_TOKEN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern COUNTER_NAME =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]{0,63}");

    private static final Set<String> REPORT_FIELDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "generation", "checkId", "structuralApplied", "dataPlaneVerified",
                    "phase", "selectedNode", "nodeCount", "nodes", "capabilities",
                    "counters", "errorCode")));

    private static final Set<String> CAPABILITY_FIELDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "v4DnsProxy", "v4TcpProxy", "v4UdpProxy",
                    "v6DnsProxy", "v6TcpProxy", "v6UdpProxy")));

    private final File directory;
    private final File stateFile;
    private final SecretKey stateKey;
    private final ExecutorService probeExecutor =
            Executors.newFixedThreadPool(6, runnable -> {
                Thread thread = new Thread(runnable, "proxy-android-probe");
                thread.setDaemon(true);
                return thread;
            });
    private State state;
    private boolean quarantineInstalled;

    // Process scoped only. These fields are never written by commitState.
    private long checkId;
    private String runtimeEpoch = "";
    private Map<String, Object> lastEngineReport;
    private Map<String, Object> lastProbe;

    public ProxyManager(Context context) throws InitializationException {
        directory = new File(context.getApplicationContext().getFilesDir(), "proxy-state");
        stateFile = new File(directory, STATE_NAME);
        try {
            ensurePrivateDirectory(directory);
            stateKey = loadOrCreateStateKey();
            if (stateFile.exists()) {
                state = loadState();
            } else {
                state = State.empty();
                commitState(state);
            }
            quarantineInstalled = state.enabled;
            applyPrivateDnsPolicy(state.enabled);
        } catch (Throwable ignored) {
            throw new InitializationException();
        }
    }

    /** The transparent engine hijacks UDP/TCP 53; opportunistic DNS-over-TLS
     * (853) bypasses that channel and can stall behind exits that cannot carry
     * it, so the resolver must stay on plain DNS while the proxy is enabled. */
    private static void applyPrivateDnsPolicy(boolean enabled) {
        try {
            RootHelper.execRootd(enabled
                    ? "settings put global private_dns_mode off"
                    : "settings delete global private_dns_mode");
        } catch (Throwable ignored) {
            android.util.Log.e("xenoid-daemon", "private DNS policy application failed");
        }
    }

    public synchronized Map<String, Object> status() {
        Desired source = state.desired;
        return map(
                "ok", true,
                "schemaVersion", SCHEMA_VERSION,
                "instanceId", state.instanceId == null ? "" : state.instanceId,
                "generation", state.generation,
                "enabled", state.enabled,
                "configured", source != null,
                "sourceKind", source == null ? null : source.kind,
                "selectedNode", source == null ? "" : source.selectedNode,
                "udpAllowed", source != null && source.udpAllowed,
                "allowInsecureHttp", source != null && source.allowInsecureHttp,
                "quarantined", quarantineInstalled,
                "checkId", checkId,
                "runtimeEpoch", runtimeEpoch,
                "report", deepCopyMap(lastEngineReport),
                "probe", deepCopyMap(lastProbe));
    }

    public synchronized Map<String, Object> setSource(Map<String, Object> request)
            throws ProxyException {
        requireKeys(request, "kind", "value", "enable", "selectedNode", "udpAllowed",
                "allowInsecureHttp");
        String kind = requireString(request, "kind", 16, false);
        if (!"endpoint".equals(kind) && !"uri_list".equals(kind)
                && !"clash".equals(kind) && !"subscription".equals(kind)) {
            throw new ProxyException("source_invalid");
        }
        String value = requireStringBytes(request, "value", MAX_SOURCE_BYTES, false);
        String selectedNode = requireString(request, "selectedNode", MAX_SELECTED_NODE, true);
        boolean enable = requireBoolean(request, "enable");
        boolean udpAllowed = requireBoolean(request, "udpAllowed");
        boolean allowInsecureHttp = requireBoolean(request, "allowInsecureHttp");
        if (containsNul(value) || containsNul(selectedNode)
                || ("endpoint".equals(kind) && udpAllowed
                && isHttpEndpoint(value))
                || ("subscription".equals(kind)
                && !isValidSubscriptionUrl(value, allowInsecureHttp))) {
            throw new ProxyException("source_invalid");
        }
        Desired desired = new Desired(
                kind, value, selectedNode, udpAllowed, allowInsecureHttp);
        if (state.enabled == enable && desired.sameAs(state.desired)) return mutationResult();
        if (enable) requireCheckCapacityLocked();
        if (state.enabled || enable) ensureQuarantineLocked();
        commit(new State(state.instanceId, nextGeneration(), enable, desired));
        if (enable) allocateCheckLocked();
        return mutationResult();
    }

    public synchronized Map<String, Object> setEnabled(Map<String, Object> request)
            throws ProxyException {
        requireKeys(request, "enabled");
        boolean enabled = requireBoolean(request, "enabled");
        if (enabled && state.desired == null) throw new ProxyException("source_invalid");
        if (enabled == state.enabled) return mutationResult();
        if (enabled) requireCheckCapacityLocked();
        ensureQuarantineLocked();
        commit(new State(state.instanceId, nextGeneration(), enabled, state.desired));
        if (enabled) allocateCheckLocked();
        return mutationResult();
    }

    public synchronized Map<String, Object> select(Map<String, Object> request)
            throws ProxyException {
        requireKeys(request, "name");
        String name = requireString(request, "name", MAX_SELECTED_NODE, false);
        if (containsNul(name) || state.desired == null) throw new ProxyException("source_invalid");
        Desired current = state.desired;
        Desired desired = new Desired(
                current.kind, current.value, name, current.udpAllowed,
                current.allowInsecureHttp);
        if (name.equals(current.selectedNode)) return mutationResult();
        if (state.enabled) {
            requireCheckCapacityLocked();
            ensureQuarantineLocked();
        }
        commit(new State(state.instanceId, nextGeneration(), state.enabled, desired));
        if (state.enabled) allocateCheckLocked();
        return mutationResult();
    }

    public synchronized Map<String, Object> clear(Map<String, Object> request)
            throws ProxyException {
        requireKeys(request);
        if (!state.enabled && state.desired == null) return mutationResult();
        if (state.enabled) ensureQuarantineLocked();
        commit(new State(state.instanceId, nextGeneration(), false, null));
        return mutationResult();
    }

    public synchronized Map<String, Object> check(Map<String, Object> request)
            throws ProxyException {
        requireKeys(request);
        if (!state.enabled || state.desired == null) {
            throw new ProxyException("proxy_disabled");
        }
        requireCheckCapacityLocked();
        allocateCheckLocked();
        return map("ok", true, "generation", state.generation, "checkId", checkId);
    }

    /** Full admin export. The service enforces daemon authentication before calling this. */
    public synchronized Map<String, Object> exportDesired() {
        Map<String, Object> exported = desiredPayload();
        exported.put("ok", true);
        return exported;
    }

    /** Pins an immutable volume identity and a process-scoped runtime epoch. */
    public synchronized void bindRuntime(String instanceId, String epoch) throws ProxyException {
        if (state.instanceId == null) {
            commit(new State(instanceId, state.generation, state.enabled, state.desired));
        } else if (!state.instanceId.equals(instanceId)) {
            throw new ProxyException("instance_identity_mismatch");
        }
        runtimeEpoch = epoch;
        lastEngineReport = null;
        lastProbe = null;
        if (state.enabled) {
            ensureQuarantineLocked();
            if (checkId == 0) {
                requireCheckCapacityLocked();
                allocateCheckLocked();
            }
        }
    }

    synchronized Map<String, Object> desiredForAgent(String instanceId, String epoch)
            throws ProxyException {
        requireCurrentRuntime(instanceId, epoch);
        return desiredPayload();
    }

    synchronized Map<String, Object> acceptAgentReport(
            String instanceId, String epoch, Map<String, Object> report, long receivedAt)
            throws ProxyException {
        requireCurrentRuntime(instanceId, epoch);
        Map<String, Object> clean = validateReport(report);
        long reportedGeneration = requireLong(clean, "generation", 0, Long.MAX_VALUE);
        if (reportedGeneration != state.generation) throw new ProxyException("agent_rejected");
        if (clean.containsKey("checkId")) {
            long reportedCheck = requireLong(clean, "checkId", 0, Long.MAX_VALUE);
            if (reportedCheck != checkId) throw new ProxyException("agent_rejected");
        }
        if (state.enabled) ensureQuarantineLocked();
        boolean structurallyApplied = Boolean.TRUE.equals(clean.get("structuralApplied"));
        boolean dataPlaneVerified = Boolean.TRUE.equals(clean.get("dataPlaneVerified"));
        String phase = clean.get("phase") instanceof String ? (String) clean.get("phase") : "";
        if (state.enabled && dataPlaneVerified
                && (!structurallyApplied
                || !"active".equals(phase)
                || !clean.containsKey("checkId")
                || !capabilityMatrixMatchesPolicy(clean.get("capabilities"))
                || !androidProbeReadyLocked())) {
            throw new ProxyException("agent_rejected");
        }
        boolean releaseEnabled = state.enabled && checkId > 0
                && clean.containsKey("checkId") && "active".equals(phase)
                && structurallyApplied && dataPlaneVerified
                && androidProbeReadyLocked();
        boolean releaseDisabled = !state.enabled && "off".equals(phase)
                && structurallyApplied && dataPlaneVerified;
        if (releaseEnabled || releaseDisabled) {
            quarantineInstalled = false;
        }
        LinkedHashMap<String, Object> observation = new LinkedHashMap<>(clean);
        observation.put("receivedAt", receivedAt);
        lastEngineReport = observation;
        return map("accepted", true, "generation", state.generation, "checkId", checkId);
    }

    Map<String, Object> runAndroidProbe(
            String instanceId, String epoch, Map<String, Object> request)
            throws ProxyException {
        requireKeys(request, "checkId");
        long requestedCheck = requireLong(request, "checkId", 1, Long.MAX_VALUE);
        long expectedGeneration;
        boolean udpAllowed;
        synchronized (this) {
            requireCurrentRuntime(instanceId, epoch);
            if (!state.enabled || state.desired == null) {
                throw new ProxyException("agent_rejected");
            }
            if (requestedCheck != checkId || checkId == 0) {
                throw new ProxyException("agent_rejected");
            }
            expectedGeneration = state.generation;
            udpAllowed = state.desired.udpAllowed;
        }

        ProbeResult result = executeAndroidProbe(requestedCheck, udpAllowed);
        String errorCode = probeErrorCode(result, udpAllowed);
        Map<String, Object> observation = map(
                "checkId", requestedCheck,
                "capabilities", probeCapabilities(result),
                "elapsedMs", result.elapsedMs,
                "errorCode", errorCode);
        synchronized (this) {
            requireCurrentRuntime(instanceId, epoch);
            if (requestedCheck != checkId || expectedGeneration != state.generation) {
                observation.put("errorCode", "stale_probe");
                return deepCopyMap(observation);
            }
            lastProbe = observation;
            return deepCopyMap(observation);
        }
    }

    public void close() {
        probeExecutor.shutdownNow();
    }

    private ProbeResult executeAndroidProbe(long requestedCheck, boolean udpAllowed) {
        long started = SystemClock.elapsedRealtime();
        long deadline = started + PROBE_TIMEOUT_MS;
        Future<NetworkProbe> v4DnsFuture = probeExecutor.submit(
                () -> runDnsProbe(false, requestedCheck));
        Future<NetworkProbe> v6DnsFuture = probeExecutor.submit(
                () -> runDnsProbe(true, requestedCheck));
        NetworkProbe v4Dns = awaitProbe(v4DnsFuture, deadline);
        NetworkProbe v6Dns = awaitProbe(v6DnsFuture, deadline);

        Future<NetworkProbe> v4TcpFuture = probeExecutor.submit(
                () -> runTcpProbe(false));
        NetworkProbe v4Tcp = awaitProbe(v4TcpFuture, deadline);
        Future<NetworkProbe> v6TcpFuture = probeExecutor.submit(
                () -> runTcpProbe(true));
        NetworkProbe v6Tcp = awaitProbe(v6TcpFuture, deadline);

        int udpTimeout = udpAllowed
                ? PROBE_IO_TIMEOUT_MS : PROBE_BLOCKED_UDP_TIMEOUT_MS;
        Future<NetworkProbe> v4UdpFuture = probeExecutor.submit(
                () -> runUdpProbe(false, udpTimeout));
        Future<NetworkProbe> v6UdpFuture = probeExecutor.submit(
                () -> runUdpProbe(true, udpTimeout));
        NetworkProbe v4Udp = awaitProbe(v4UdpFuture, deadline);
        NetworkProbe v6Udp = awaitProbe(v6UdpFuture, deadline);
        return new ProbeResult(
                v4Dns.succeeded, v4Tcp.succeeded, v4Udp.succeeded,
                v6Dns.succeeded, v6Tcp.succeeded, v6Udp.succeeded,
                boundedElapsed(started),
                v4Dns.timedOut || v4Tcp.timedOut || v6Dns.timedOut
                        || (udpAllowed && v4Udp.timedOut));
    }

    private static NetworkProbe runDnsProbe(boolean ipv6, long requestedCheck) {
        DatagramSocket socket = null;
        try {
            String query = freshDnsName(
                    ipv6 ? PROBE_V6_DNS_HOST : PROBE_V4_DNS_HOST,
                    requestedCheck, ipv6);
            int identifier = PROBE_RANDOM.nextInt(1 << 16);
            byte[] request = dnsQuery(query, ipv6, identifier);
            byte[] rawAddress = ipv6 ? PROBE_V6_TCP_ADDRESS : PROBE_V4_TCP_ADDRESS;
            InetAddress address = InetAddress.getByAddress(query, rawAddress);
            InetAddress localAddress = InetAddress.getByAddress(
                    ipv6 ? new byte[16] : new byte[4]);
            socket = new DatagramSocket(null);
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.setSoTimeout(PROBE_DNS_TIMEOUT_MS);
            socket.connect(address, 53);
            socket.send(new DatagramPacket(request, request.length));
            byte[] response = new byte[4096];
            DatagramPacket packet = new DatagramPacket(response, response.length);
            socket.receive(packet);
            int flags = ((response[2] & 0xff) << 8) | (response[3] & 0xff);
            int answerCount = ((response[6] & 0xff) << 8) | (response[7] & 0xff);
            if (packet.getLength() >= 12
                    && (response[0] & 0xff) == (identifier >>> 8)
                    && (response[1] & 0xff) == (identifier & 0xff)
                    && (flags & 0x800f) == 0x8000 && answerCount > 0) {
                return NetworkProbe.succeeded();
            }
        } catch (SocketTimeoutException timeout) {
            return NetworkProbe.timedOut();
        } catch (Exception ignored) {
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
        return NetworkProbe.failed();
    }

    private static byte[] dnsQuery(String host, boolean ipv6, int identifier) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(512);
        output.write(identifier >>> 8);
        output.write(identifier);
        output.write(0x01);
        output.write(0x00);
        output.write(0x00);
        output.write(0x01);
        for (int index = 0; index < 6; index++) {
            output.write(0x00);
        }
        String[] labels = host.substring(0, host.length() - 1).split("\\.");
        for (String label : labels) {
            byte[] encoded = label.getBytes(StandardCharsets.US_ASCII);
            output.write(encoded.length);
            output.write(encoded, 0, encoded.length);
        }
        output.write(0x00);
        output.write(0x00);
        output.write(ipv6 ? 0x1c : 0x01);
        output.write(0x00);
        output.write(0x01);
        return output.toByteArray();
    }

    private static String freshDnsName(String host, long requestedCheck, boolean ipv6) {
        long nonce = PROBE_RANDOM.nextLong()
                ^ requestedCheck ^ (ipv6 ? 0x6a09e667f3bcc909L : 0xbb67ae8584caa73bL);
        return Long.toUnsignedString(requestedCheck, 16) + "-"
                + Long.toUnsignedString(nonce, 16) + "." + host + ".";
    }

    private static NetworkProbe runTcpProbe(boolean ipv6) {
        boolean timedOut = false;
        int attempts = ipv6 ? 1 : 3;
        for (int attempt = 0; attempt < attempts; attempt++) {
            Socket socket = null;
            try {
                byte[] rawAddress = ipv6 ? PROBE_V6_TCP_ADDRESS : PROBE_V4_TCP_ADDRESS;
                InetAddress address = InetAddress.getByAddress(rawAddress);
                socket = new Socket();
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(PROBE_TCP_ATTEMPT_TIMEOUT_MS);
                socket.connect(
                        new InetSocketAddress(address, PROBE_TCP_PORT),
                        PROBE_TCP_ATTEMPT_TIMEOUT_MS);
                socket.getOutputStream().write(
                        "HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"
                                .getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                if (socket.getInputStream().read() >= 0) {
                    return NetworkProbe.succeeded();
                }
            } catch (SocketTimeoutException timeout) {
                timedOut = true;
            } catch (Exception ignored) {
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        return timedOut ? NetworkProbe.timedOut() : NetworkProbe.failed();
    }

    private static NetworkProbe runUdpProbe(boolean ipv6, int timeoutMs) {
        DatagramSocket socket = null;
        try {
            byte[] rawAddress = ipv6 ? PROBE_V6_STUN_ADDRESS : PROBE_V4_STUN_ADDRESS;
            InetAddress remoteAddress = InetAddress.getByAddress(rawAddress);
            InetAddress localAddress = InetAddress.getByAddress(new byte[ipv6 ? 16 : 4]);
            socket = new DatagramSocket(null);
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(localAddress, 0));
            socket.connect(new InetSocketAddress(remoteAddress, PROBE_STUN_PORT));
            socket.setSoTimeout(timeoutMs);

            byte[] request = new byte[20];
            request[1] = 1;
            writeInt(request, 4, STUN_MAGIC_COOKIE);
            byte[] transaction = new byte[12];
            PROBE_RANDOM.nextBytes(transaction);
            System.arraycopy(transaction, 0, request, 8, transaction.length);
            socket.send(new DatagramPacket(request, request.length));

            byte[] reply = new byte[512];
            DatagramPacket packet = new DatagramPacket(reply, reply.length);
            socket.receive(packet);
            int received = packet.getLength();
            if (received < 20
                    || readUnsignedShort(reply, 0) != 0x0101
                    || readInt(reply, 4) != STUN_MAGIC_COOKIE) {
                return NetworkProbe.failed();
            }
            int bodyLength = readUnsignedShort(reply, 2);
            if ((bodyLength & 3) != 0 || bodyLength + 20 != received) {
                return NetworkProbe.failed();
            }
            for (int index = 0; index < transaction.length; index++) {
                if (reply[index + 8] != transaction[index]) {
                    return NetworkProbe.failed();
                }
            }
            return NetworkProbe.succeeded();
        } catch (SocketTimeoutException timeout) {
            return NetworkProbe.timedOut();
        } catch (Exception ignored) {
            return NetworkProbe.failed();
        } finally {
            if (socket != null) socket.close();
        }
    }

    private static void writeInt(byte[] destination, int offset, int value) {
        destination[offset] = (byte) (value >>> 24);
        destination[offset + 1] = (byte) (value >>> 16);
        destination[offset + 2] = (byte) (value >>> 8);
        destination[offset + 3] = (byte) value;
    }

    private static int readInt(byte[] source, int offset) {
        return ((source[offset] & 0xff) << 24)
                | ((source[offset + 1] & 0xff) << 16)
                | ((source[offset + 2] & 0xff) << 8)
                | (source[offset + 3] & 0xff);
    }

    private static int readUnsignedShort(byte[] source, int offset) {
        return ((source[offset] & 0xff) << 8) | (source[offset + 1] & 0xff);
    }

    private static NetworkProbe awaitProbe(Future<NetworkProbe> future, long deadline) {
        long remaining = Math.max(0L, deadline - SystemClock.elapsedRealtime());
        try {
            return future.get(remaining, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return NetworkProbe.timedOut();
        } catch (TimeoutException timeout) {
            future.cancel(true);
            return NetworkProbe.timedOut();
        } catch (ExecutionException failure) {
            future.cancel(true);
            return NetworkProbe.failed();
        }
    }

    private static long boundedElapsed(long started) {
        return Math.max(0L, Math.min(PROBE_TIMEOUT_MS, SystemClock.elapsedRealtime() - started));
    }

    private static Map<String, Object> probeCapabilities(ProbeResult result) {
        return map(
                "v4DnsProxy", result.v4DnsProxy,
                "v4TcpProxy", result.v4TcpProxy,
                "v4UdpProxy", result.v4UdpProxy,
                "v6DnsProxy", result.v6DnsProxy,
                "v6TcpProxy", result.v6TcpProxy,
                "v6UdpProxy", result.v6UdpProxy);
    }

    private static String probeErrorCode(ProbeResult result, boolean udpAllowed) {
        if (result.timedOut) return "probe_timeout";
        if (!result.matchesPolicy(udpAllowed)) return "probe_failed";
        return "";
    }

    private Map<String, Object> desiredPayload() {
        Desired desired = state.desired;
        Map<String, Object> source = desired == null ? null : map(
                "kind", desired.kind,
                "value", desired.value,
                "selectedNode", desired.selectedNode,
                "udpAllowed", desired.udpAllowed,
                "allowInsecureHttp", desired.allowInsecureHttp);
        return map(
                "schemaVersion", SCHEMA_VERSION,
                "instanceId", state.instanceId == null ? "" : state.instanceId,
                "generation", state.generation,
                "enabled", state.enabled,
                "checkId", checkId,
                "source", source);
    }

    private Map<String, Object> mutationResult() {
        return map(
                "ok", true,
                "generation", state.generation,
                "checkId", checkId,
                "enabled", state.enabled,
                "configured", state.desired != null,
                "quarantined", quarantineInstalled);
    }

    private void requireCurrentRuntime(String instanceId, String epoch) throws ProxyException {
        if (state.instanceId == null || !state.instanceId.equals(instanceId)
                || runtimeEpoch.isEmpty() || !runtimeEpoch.equals(epoch)) {
            throw new ProxyException("agent_rejected");
        }
    }

    private void ensureQuarantineLocked() {
        // The fail-closed guard lives exclusively on the Docker engine host.
        // This flag tracks pending convergence without creating Android-visible
        // routes, interfaces, VPN state, properties, or netfilter rules.
        quarantineInstalled = true;
    }


    private boolean androidProbeReadyLocked() {
        return lastProbe != null
                && lastProbe.get("checkId") instanceof Long
                && ((Long) lastProbe.get("checkId")) == checkId
                && lastProbe.get("elapsedMs") instanceof Long
                && ((Long) lastProbe.get("elapsedMs")) >= 0
                && ((Long) lastProbe.get("elapsedMs")) <= PROBE_TIMEOUT_MS
                && "".equals(lastProbe.get("errorCode"))
                && capabilityMatrixMatchesPolicy(lastProbe.get("capabilities"));
    }

    private boolean capabilityMatrixMatchesPolicy(Object value) {
        if (!(value instanceof Map) || state.desired == null) return false;
        Map<?, ?> capabilities = (Map<?, ?>) value;
        if (!capabilities.keySet().equals(CAPABILITY_FIELDS)) return false;
        for (Object item : capabilities.values()) {
            if (!(item instanceof Boolean)) return false;
        }
        boolean udpAllowed = state.desired.udpAllowed;
        return Boolean.TRUE.equals(capabilities.get("v4DnsProxy"))
                && Boolean.TRUE.equals(capabilities.get("v4TcpProxy"))
                && Boolean.TRUE.equals(capabilities.get("v6DnsProxy"))
                && Boolean.valueOf(udpAllowed).equals(capabilities.get("v4UdpProxy"))
                && (udpAllowed || Boolean.FALSE.equals(capabilities.get("v6UdpProxy")));
    }
    private void requireCheckCapacityLocked() throws ProxyException {
        if (checkId == Long.MAX_VALUE) throw new ProxyException("proxy_unavailable");
    }

    private void allocateCheckLocked() {
        checkId++;
        lastProbe = null;
    }

    private long nextGeneration() throws ProxyException {
        if (state.generation == Long.MAX_VALUE) throw new ProxyException("proxy_unavailable");
        return state.generation + 1;
    }

    private void commit(State next) throws ProxyException {
        try {
            commitState(next);
            state = next;
            // An old generation can never establish readiness for the new desired state.
            lastEngineReport = null;
            lastProbe = null;
        } catch (Throwable ignored) {
            throw new ProxyException("state_commit_failed");
        }
        applyPrivateDnsPolicy(next.enabled);
    }

    private Map<String, Object> validateReport(Map<String, Object> report) throws ProxyException {
        requireAllowedKeys(report, REPORT_FIELDS);
        if (!report.containsKey("generation")) throw new ProxyException("invalid_request_schema");
        LinkedHashMap<String, Object> clean = new LinkedHashMap<>();
        clean.put("generation", requireLong(report, "generation", 0, Long.MAX_VALUE));
        copyOptionalLong(report, clean, "checkId", 0, Long.MAX_VALUE);
        copyOptionalBoolean(report, clean, "structuralApplied");
        copyOptionalBoolean(report, clean, "dataPlaneVerified");
        copyOptionalSafeToken(report, clean, "phase", 32);
        copyOptionalString(report, clean, "selectedNode", MAX_SELECTED_NODE);
        copyNodeMetadata(report, clean);
        copyOptionalSafeToken(report, clean, "errorCode", 64);
        copyOptionalCapabilities(report, clean);
        copyOptionalCounters(report, clean);
        return clean;
    }

    private static void copyNodeMetadata(
            Map<String, Object> report, Map<String, Object> clean) throws ProxyException {
        boolean hasNodes = report.containsKey("nodes");
        boolean hasCount = report.containsKey("nodeCount");
        String selected = clean.containsKey("selectedNode")
                ? (String) clean.get("selectedNode") : "";
        if (!hasNodes && !hasCount) {
            if (!selected.isEmpty()) throw new ProxyException("invalid_request_schema");
            return;
        }
        if (!hasNodes || !hasCount || !(report.get("nodes") instanceof List)) {
            throw new ProxyException("invalid_request_schema");
        }
        @SuppressWarnings("unchecked")
        List<Object> rawNodes = (List<Object>) report.get("nodes");
        if (rawNodes.size() > 512
                || requireLong(report, "nodeCount", 0, 512) != rawNodes.size()) {
            throw new ProxyException("invalid_request_schema");
        }
        ArrayList<String> nodes = new ArrayList<>(rawNodes.size());
        HashSet<String> unique = new HashSet<>();
        for (Object item : rawNodes) {
            if (!(item instanceof String)) throw new ProxyException("invalid_request_schema");
            String node = (String) item;
            int bytes = utf8Length(node);
            if (bytes < 1 || bytes > 128 || containsControl(node) || !unique.add(node)) {
                throw new ProxyException("invalid_request_schema");
            }
            nodes.add(node);
        }
        if (!selected.isEmpty() && !unique.contains(selected)) {
            throw new ProxyException("invalid_request_schema");
        }
        clean.put("nodeCount", (long) nodes.size());
        clean.put("nodes", nodes);
    }


    private static void copyOptionalBoolean(
            Map<String, Object> from, Map<String, Object> to, String name) throws ProxyException {
        if (from.containsKey(name)) to.put(name, requireBoolean(from, name));
    }

    private static void copyOptionalLong(
            Map<String, Object> from, Map<String, Object> to, String name, long min, long max)
            throws ProxyException {
        if (from.containsKey(name)) to.put(name, requireLong(from, name, min, max));
    }

    private static void copyOptionalString(
            Map<String, Object> from, Map<String, Object> to, String name, int maximum)
            throws ProxyException {
        if (from.containsKey(name)) to.put(name, requireString(from, name, maximum, true));
    }

    private static void copyOptionalSafeToken(
            Map<String, Object> from, Map<String, Object> to, String name, int maximum)
            throws ProxyException {
        if (!from.containsKey(name)) return;
        String value = requireString(from, name, maximum, false);
        if (!SAFE_TOKEN.matcher(value).matches()) throw new ProxyException("invalid_request_schema");
        to.put(name, value);
    }

    private static void copyOptionalCapabilities(
            Map<String, Object> from, Map<String, Object> to) throws ProxyException {
        if (!from.containsKey("capabilities")) return;
        Map<String, Object> capabilities = requireObject(from, "capabilities");
        requireAllowedKeys(capabilities, CAPABILITY_FIELDS);
        LinkedHashMap<String, Object> clean = new LinkedHashMap<>();
        for (String name : CAPABILITY_FIELDS) {
            if (capabilities.containsKey(name)) clean.put(name, requireBoolean(capabilities, name));
        }
        to.put("capabilities", clean);
    }

    private static void copyOptionalCounters(
            Map<String, Object> from, Map<String, Object> to) throws ProxyException {
        if (!from.containsKey("counters")) return;
        Map<String, Object> counters = requireObject(from, "counters");
        if (counters.size() > MAX_COUNTERS) throw new ProxyException("invalid_request_schema");
        LinkedHashMap<String, Object> clean = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : counters.entrySet()) {
            if (!COUNTER_NAME.matcher(entry.getKey()).matches()
                    || !(entry.getValue() instanceof Long) || ((Long) entry.getValue()) < 0) {
                throw new ProxyException("invalid_request_schema");
            }
            clean.put(entry.getKey(), entry.getValue());
        }
        to.put("counters", clean);
    }


    private State loadState() throws Exception {
        if (!Files.isRegularFile(stateFile.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(stateFile.toPath())
                || stateFile.length() <= 0 || stateFile.length() > MAX_STATE_BYTES
                || Os.lstat(stateFile.getAbsolutePath()).st_uid != Process.myUid()) {
            throw new Exception();
        }
        byte[] bytes = Files.readAllBytes(stateFile.toPath());
        Map<String, Object> object;
        try {
            object = parseObject(decodeUtf8(bytes), MAX_STATE_BYTES);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
        requireKeys(object, "schemaVersion", "instanceId", "generation", "enabled",
                "sourceIv", "sourceCiphertext");
        requireLong(object, "schemaVersion", SCHEMA_VERSION, SCHEMA_VERSION);
        long generation = requireLong(object, "generation", 0, Long.MAX_VALUE);
        boolean enabled = requireBoolean(object, "enabled");
        String instanceId = null;
        Object identity = object.get("instanceId");
        if (identity != null) {
            if (!(identity instanceof String)
                    || !ProxyAgentChannel.isValidInstanceId((String) identity)) throw new Exception();
            instanceId = (String) identity;
        }
        Object encodedIv = object.get("sourceIv");
        Object encodedCiphertext = object.get("sourceCiphertext");
        Desired desired = null;
        if (encodedIv == null || encodedCiphertext == null) {
            if (encodedIv != null || encodedCiphertext != null || enabled) throw new Exception();
        } else {
            if (!(encodedIv instanceof String) || !(encodedCiphertext instanceof String)) {
                throw new Exception();
            }
            byte[] iv = java.util.Base64.getDecoder().decode((String) encodedIv);
            byte[] ciphertext = java.util.Base64.getDecoder().decode((String) encodedCiphertext);
            try {
                if (iv.length != 12 || ciphertext.length < 16
                        || ciphertext.length > MAX_SOURCE_BYTES + 1024) throw new Exception();
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, stateKey, new GCMParameterSpec(128, iv));
                byte[] aad = stateAad(instanceId, generation);
                byte[] plaintext;
                try {
                    cipher.updateAAD(aad);
                    plaintext = cipher.doFinal(ciphertext);
                } finally {
                    Arrays.fill(aad, (byte) 0);
                }
                try {
                    desired = decodeDesired(plaintext);
                } finally {
                    Arrays.fill(plaintext, (byte) 0);
                }
            } finally {
                Arrays.fill(iv, (byte) 0);
                Arrays.fill(ciphertext, (byte) 0);
            }
        }
        return new State(instanceId, generation, enabled, desired);
    }

    private void commitState(State value) throws Exception {
        String ivText = null;
        String ciphertextText = null;
        if (value.desired != null) {
            byte[] plaintext = encodeDesired(value.desired);
            byte[] iv = null;
            byte[] ciphertext = null;
            byte[] aad = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, stateKey);
                aad = stateAad(value.instanceId, value.generation);
                cipher.updateAAD(aad);
                iv = cipher.getIV();
                if (iv == null || iv.length != 12) throw new Exception();
                ciphertext = cipher.doFinal(plaintext);
                ivText = java.util.Base64.getEncoder().encodeToString(iv);
                ciphertextText = java.util.Base64.getEncoder().encodeToString(ciphertext);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
                if (aad != null) Arrays.fill(aad, (byte) 0);
                if (iv != null) Arrays.fill(iv, (byte) 0);
                if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
            }
        }
        org.json.JSONObject object = new org.json.JSONObject();
        object.put("schemaVersion", SCHEMA_VERSION);
        object.put("instanceId", value.instanceId == null ? org.json.JSONObject.NULL : value.instanceId);
        object.put("generation", value.generation);
        object.put("enabled", value.enabled);
        object.put("sourceIv", ivText == null ? org.json.JSONObject.NULL : ivText);
        object.put("sourceCiphertext",
                ciphertextText == null ? org.json.JSONObject.NULL : ciphertextText);
        byte[] bytes = object.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STATE_BYTES) throw new Exception();
        File prepared = new File(directory, ".desired-" + randomHex(16) + ".tmp");
        FileOutputStream output = null;
        try {
            output = new FileOutputStream(prepared);
            Os.chmod(prepared.getAbsolutePath(), 0600);
            output.write(bytes);
            output.flush();
            output.getFD().sync();
        } catch (Exception failure) {
            deleteQuietly(prepared);
            throw failure;
        } catch (Error failure) {
            deleteQuietly(prepared);
            throw failure;
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (output != null) try { output.close(); } catch (Throwable ignored) { }
        }
        try {
            Files.move(prepared.toPath(), stateFile.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            syncDirectory(directory);
        } catch (AtomicMoveNotSupportedException failure) {
            throw failure;
        } finally {
            deleteQuietly(prepared);
        }
    }

    private static byte[] encodeDesired(Desired desired) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(SCHEMA_VERSION);
        writeString(output, desired.kind, 16);
        writeString(output, desired.value, MAX_SOURCE_BYTES);
        writeString(output, desired.selectedNode, MAX_SELECTED_NODE * 4);
        output.writeBoolean(desired.udpAllowed);
        output.writeBoolean(desired.allowInsecureHttp);
        output.flush();
        return bytes.toByteArray();
    }

    private static Desired decodeDesired(byte[] plaintext) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
        if (input.readInt() != SCHEMA_VERSION) throw new Exception();
        String kind = readString(input, 16);
        if (!"endpoint".equals(kind) && !"uri_list".equals(kind)
                && !"clash".equals(kind) && !"subscription".equals(kind)) {
            throw new Exception();
        }
        String value = readString(input, MAX_SOURCE_BYTES);
        String selectedNode = readString(input, MAX_SELECTED_NODE * 4);
        boolean udpAllowed = input.readBoolean();
        boolean allowInsecureHttp = input.readBoolean();
        if (input.available() != 0 || value.isEmpty()
                || selectedNode.length() > MAX_SELECTED_NODE
                || containsNul(value) || containsNul(selectedNode)
                || ("subscription".equals(kind)
                && !isValidSubscriptionUrl(value, allowInsecureHttp))) throw new Exception();
        return new Desired(kind, value, selectedNode, udpAllowed, allowInsecureHttp);
    }

    private static void writeString(DataOutputStream output, String value, int maximum)
            throws Exception {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (encoded.length > maximum) throw new Exception();
            output.writeInt(encoded.length);
            output.write(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static String readString(DataInputStream input, int maximum) throws Exception {
        int length = input.readInt();
        if (length < 0 || length > maximum || length > input.available()) throw new Exception();
        byte[] encoded = new byte[length];
        input.readFully(encoded);
        try {
            return decodeUtf8(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] stateAad(String instanceId, long generation) {
        byte[] suffix = ((instanceId == null ? "" : instanceId) + "\n" + generation)
                .getBytes(StandardCharsets.UTF_8);
        byte[] result = Arrays.copyOf(STATE_AAD_PREFIX, STATE_AAD_PREFIX.length + suffix.length);
        System.arraycopy(suffix, 0, result, STATE_AAD_PREFIX.length, suffix.length);
        Arrays.fill(suffix, (byte) 0);
        return result;
    }

    private static SecretKey loadOrCreateStateKey() throws Exception {
        KeyStore store = KeyStore.getInstance(KEYSTORE);
        store.load(null);
        java.security.Key existing = store.getKey(KEY_ALIAS, null);
        if (existing != null) {
            if (!(existing instanceof SecretKey)) throw new Exception();
            return (SecretKey) existing;
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }

    private static void ensurePrivateDirectory(File directory) throws Exception {
        boolean created = false;
        if (!directory.exists()) {
            if (!directory.mkdirs()) throw new Exception();
            created = true;
        }
        if (!directory.isDirectory() || Files.isSymbolicLink(directory.toPath())
                || Os.lstat(directory.getAbsolutePath()).st_uid != Process.myUid()) {
            throw new Exception();
        }
        Os.chmod(directory.getAbsolutePath(), 0700);
        if (created) syncDirectory(directory.getParentFile());
    }

    private static boolean containsControl(String value) {
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            if (Character.isISOControl(codePoint)) return true;
            offset += Character.charCount(codePoint);
        }
        return false;
    }

    private static void syncDirectory(File directory) throws Exception {
        if (directory == null) throw new Exception();
        FileDescriptor descriptor = Os.open(directory.getAbsolutePath(), OsConstants.O_RDONLY, 0);
        try {
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private static String randomHex(int bytes) {
        byte[] value = new byte[bytes];
        new java.security.SecureRandom().nextBytes(value);
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] output = new char[bytes * 2];
        for (int index = 0; index < bytes; index++) {
            int item = value[index] & 0xff;
            output[index * 2] = alphabet[item >>> 4];
            output[index * 2 + 1] = alphabet[item & 15];
        }
        Arrays.fill(value, (byte) 0);
        return new String(output);
    }

    private static void deleteQuietly(File file) {
        try {
            if (file != null && file.isFile() && !Files.isSymbolicLink(file.toPath())) file.delete();
        } catch (Throwable ignored) { }
    }

    static Map<String, Object> parseObject(String body, int maximumUtf8Bytes)
            throws ProxyException {
        if (body == null || body.isEmpty()) throw new ProxyException("invalid_request_body");
        int length = utf8Length(body);
        if (length < 0 || length > maximumUtf8Bytes) throw new ProxyException("invalid_request_body");
        return new StrictJsonParser(body).parseObject();
    }

    static void requireEmptyBody(String body) throws ProxyException {
        if (body != null && !body.isEmpty()) throw new ProxyException("invalid_request_body");
    }

    static void requireKeys(Map<String, Object> object, String... fields) throws ProxyException {
        Set<String> expected = new HashSet<>(Arrays.asList(fields));
        if (object.size() != expected.size() || !object.keySet().equals(expected)) {
            throw new ProxyException("invalid_request_schema");
        }
    }

    static String requireString(
            Map<String, Object> object, String name, int maximum, boolean emptyAllowed)
            throws ProxyException {
        Object value = object.get(name);
        if (!(value instanceof String)) throw new ProxyException("invalid_request_schema");
        String string = (String) value;
        if ((!emptyAllowed && string.isEmpty()) || string.length() > maximum) {
            throw new ProxyException("invalid_request_schema");
        }
        return string;
    }

    static String requireStringBytes(
            Map<String, Object> object, String name, int maximum, boolean emptyAllowed)
            throws ProxyException {
        Object value = object.get(name);
        if (!(value instanceof String)) throw new ProxyException("invalid_request_schema");
        String string = (String) value;
        int length = utf8Length(string);
        if ((!emptyAllowed && string.isEmpty()) || length < 0 || length > maximum) {
            throw new ProxyException("invalid_request_schema");
        }
        return string;
    }

    static boolean requireBoolean(Map<String, Object> object, String name)
            throws ProxyException {
        Object value = object.get(name);
        if (!(value instanceof Boolean)) throw new ProxyException("invalid_request_schema");
        return (Boolean) value;
    }

    static long requireLong(Map<String, Object> object, String name, long min, long max)
            throws ProxyException {
        Object value = object.get(name);
        if (!(value instanceof Long)) throw new ProxyException("invalid_request_schema");
        long number = (Long) value;
        if (number < min || number > max) throw new ProxyException("invalid_request_schema");
        return number;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> requireObject(Map<String, Object> object, String name)
            throws ProxyException {
        Object value = object.get(name);
        if (!(value instanceof Map)) throw new ProxyException("invalid_request_schema");
        return (Map<String, Object>) value;
    }

    private static void requireAllowedKeys(Map<String, Object> object, Set<String> allowed)
            throws ProxyException {
        if (object.size() > allowed.size() || !allowed.containsAll(object.keySet())) {
            throw new ProxyException("invalid_request_schema");
        }
    }

    private static int utf8Length(String value) {
        try {
            return StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value)).remaining();
        } catch (CharacterCodingException ignored) {
            return -1;
        }
    }

    private static String decodeUtf8(byte[] value) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
    }

    private static boolean containsNul(String value) {
        return value.indexOf('\u0000') >= 0;
    }

    private static boolean isHttpEndpoint(String value) {
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean isValidSubscriptionUrl(
            String value, boolean allowInsecureHttp) {
        if (!value.equals(value.trim()) || containsControl(value)) return false;
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            boolean https = "https".equalsIgnoreCase(scheme);
            boolean http = "http".equalsIgnoreCase(scheme);
            if ((!https && !http) || (http && !allowInsecureHttp)
                    || (http && uri.getRawQuery() != null)
                    || uri.isOpaque() || uri.getHost() == null || uri.getHost().isEmpty()
                    || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                return false;
            }
            int port = uri.getPort();
            return port == -1 || (port >= 1 && port <= 65535);
        } catch (Exception ignored) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopyMap(Map<String, Object> source) {
        if (source == null) return null;
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) value = deepCopyMap((Map<String, Object>) value);
            else if (value instanceof List) value = new ArrayList<>((List<Object>) value);
            result.put(entry.getKey(), value);
        }
        return result;
    }

    private static Map<String, Object> map(Object... values) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index + 1 < values.length; index += 2) {
            result.put(String.valueOf(values[index]), values[index + 1]);
        }
        return result;
    }

    static final class ProxyException extends Exception {
        final String code;
        ProxyException(String code) {
            super(code);
            this.code = code;
        }
    }

    public static final class InitializationException extends Exception {
        InitializationException() {
            super("proxy state unavailable");
        }
    }

    private static final class State {
        final String instanceId;
        final long generation;
        final boolean enabled;
        final Desired desired;

        State(String instanceId, long generation, boolean enabled, Desired desired) {
            this.instanceId = instanceId;
            this.generation = generation;
            this.enabled = enabled;
            this.desired = desired;
        }

        static State empty() {
            return new State(null, 0, false, null);
        }
    }

    private static final class Desired {
        final String kind;
        final String value;
        final String selectedNode;
        final boolean udpAllowed;
        final boolean allowInsecureHttp;

        Desired(
                String kind, String value, String selectedNode, boolean udpAllowed,
                boolean allowInsecureHttp) {
            this.kind = kind;
            this.value = value;
            this.selectedNode = selectedNode;
            this.udpAllowed = udpAllowed;
            this.allowInsecureHttp = allowInsecureHttp;
        }

        boolean sameAs(Desired other) {
            return other != null
                    && kind.equals(other.kind)
                    && value.equals(other.value)
                    && selectedNode.equals(other.selectedNode)
                    && udpAllowed == other.udpAllowed
                    && allowInsecureHttp == other.allowInsecureHttp;
        }
    }

    private static final class NetworkProbe {
        final boolean succeeded;
        final boolean timedOut;

        private NetworkProbe(boolean succeeded, boolean timedOut) {
            this.succeeded = succeeded;
            this.timedOut = timedOut;
        }

        static NetworkProbe succeeded() {
            return new NetworkProbe(true, false);
        }

        static NetworkProbe failed() {
            return new NetworkProbe(false, false);
        }

        static NetworkProbe timedOut() {
            return new NetworkProbe(false, true);
        }
    }

    private static final class ProbeResult {
        final boolean v4DnsProxy;
        final boolean v4TcpProxy;
        final boolean v4UdpProxy;
        final boolean v6DnsProxy;
        final boolean v6TcpProxy;
        final boolean v6UdpProxy;
        final long elapsedMs;
        final boolean timedOut;

        ProbeResult(
                boolean v4DnsProxy, boolean v4TcpProxy, boolean v4UdpProxy,
                boolean v6DnsProxy, boolean v6TcpProxy, boolean v6UdpProxy,
                long elapsedMs, boolean timedOut) {
            this.v4DnsProxy = v4DnsProxy;
            this.v4TcpProxy = v4TcpProxy;
            this.v4UdpProxy = v4UdpProxy;
            this.v6DnsProxy = v6DnsProxy;
            this.v6TcpProxy = v6TcpProxy;
            this.v6UdpProxy = v6UdpProxy;
            this.elapsedMs = elapsedMs;
            this.timedOut = timedOut;
        }

        boolean matchesPolicy(boolean udpAllowed) {
            return v4DnsProxy && v4TcpProxy && v6DnsProxy
                    && v4UdpProxy == udpAllowed && (udpAllowed || !v6UdpProxy);
        }
    }

    /** Strict JSON parser: duplicate keys, floats, invalid Unicode and excess nesting are rejected. */
    private static final class StrictJsonParser {
        private static final int MAX_DEPTH = 8;
        private static final int MAX_VALUES = 2048;
        private final String text;
        private int offset;
        private int values;

        StrictJsonParser(String text) {
            this.text = text;
        }

        Map<String, Object> parseObject() throws ProxyException {
            skipWhitespace();
            Object value = parseValue(0);
            skipWhitespace();
            if (!(value instanceof Map) || offset != text.length()) failBody();
            @SuppressWarnings("unchecked")
            Map<String, Object> object = (Map<String, Object>) value;
            return object;
        }

        private Object parseValue(int depth) throws ProxyException {
            if (depth > MAX_DEPTH || ++values > MAX_VALUES || offset >= text.length()) failBody();
            char next = text.charAt(offset);
            if (next == '{') return parseMap(depth + 1);
            if (next == '[') return parseList(depth + 1);
            if (next == '"') return parseString();
            if (next == 't' && consume("true")) return Boolean.TRUE;
            if (next == 'f' && consume("false")) return Boolean.FALSE;
            if (next == 'n' && consume("null")) return null;
            if (next == '-' || (next >= '0' && next <= '9')) return parseLong();
            failBody();
            return null;
        }

        private Map<String, Object> parseMap(int depth) throws ProxyException {
            offset++;
            LinkedHashMap<String, Object> result = new LinkedHashMap<>();
            skipWhitespace();
            if (take('}')) return result;
            while (true) {
                skipWhitespace();
                if (offset >= text.length() || text.charAt(offset) != '"') failBody();
                String key = parseString();
                if (result.containsKey(key)) failBody();
                skipWhitespace();
                if (!take(':')) failBody();
                skipWhitespace();
                result.put(key, parseValue(depth));
                skipWhitespace();
                if (take('}')) return result;
                if (!take(',')) failBody();
            }
        }

        private List<Object> parseList(int depth) throws ProxyException {
            offset++;
            ArrayList<Object> result = new ArrayList<>();
            skipWhitespace();
            if (take(']')) return result;
            while (true) {
                skipWhitespace();
                result.add(parseValue(depth));
                skipWhitespace();
                if (take(']')) return result;
                if (!take(',')) failBody();
            }
        }

        private String parseString() throws ProxyException {
            offset++;
            StringBuilder output = new StringBuilder();
            while (offset < text.length()) {
                char value = text.charAt(offset++);
                if (value == '"') {
                    validateSurrogates(output);
                    return output.toString();
                }
                if (value < 0x20) failBody();
                if (value != '\\') {
                    output.append(value);
                    continue;
                }
                if (offset >= text.length()) failBody();
                char escaped = text.charAt(offset++);
                switch (escaped) {
                    case '"': output.append('"'); break;
                    case '\\': output.append('\\'); break;
                    case '/': output.append('/'); break;
                    case 'b': output.append('\b'); break;
                    case 'f': output.append('\f'); break;
                    case 'n': output.append('\n'); break;
                    case 'r': output.append('\r'); break;
                    case 't': output.append('\t'); break;
                    case 'u': output.append(parseUnicode()); break;
                    default: failBody();
                }
            }
            failBody();
            return "";
        }

        private char parseUnicode() throws ProxyException {
            if (offset + 4 > text.length()) failBody();
            int value = 0;
            for (int count = 0; count < 4; count++) {
                int digit = Character.digit(text.charAt(offset++), 16);
                if (digit < 0) failBody();
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private long parseLong() throws ProxyException {
            int start = offset;
            if (take('-') && offset >= text.length()) failBody();
            if (take('0')) {
                if (offset < text.length() && Character.isDigit(text.charAt(offset))) failBody();
            } else {
                int digits = 0;
                while (offset < text.length() && Character.isDigit(text.charAt(offset))) {
                    offset++;
                    digits++;
                }
                if (digits == 0) failBody();
            }
            if (offset < text.length()) {
                char suffix = text.charAt(offset);
                if (suffix == '.' || suffix == 'e' || suffix == 'E' || suffix == '+') failBody();
            }
            try {
                return Long.parseLong(text.substring(start, offset));
            } catch (NumberFormatException ignored) {
                failBody();
                return 0;
            }
        }

        private boolean consume(String value) {
            if (!text.regionMatches(offset, value, 0, value.length())) return false;
            offset += value.length();
            return true;
        }

        private boolean take(char expected) {
            if (offset < text.length() && text.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private void skipWhitespace() {
            while (offset < text.length()) {
                char value = text.charAt(offset);
                if (value != ' ' && value != '\t' && value != '\r' && value != '\n') return;
                offset++;
            }
        }

        private static void validateSurrogates(CharSequence value) throws ProxyException {
            for (int index = 0; index < value.length(); index++) {
                char item = value.charAt(index);
                if (Character.isHighSurrogate(item)) {
                    if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) {
                        failBody();
                    }
                } else if (Character.isLowSurrogate(item)) {
                    failBody();
                }
            }
        }

        private static void failBody() throws ProxyException {
            throw new ProxyException("invalid_request_body");
        }
    }
}
