package dev.xenoid.daemon;

import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** Serialized, bounded owner of daemon bootstrap generations. */
final class BootstrapCoordinator implements AutoCloseable {
    static final String SCHEMA = "dev.xenoid.daemon-bootstrap/v1";
    private static final String IDENTITY_SCHEMA = "dev.xenoid.daemon-bootstrap-identity/v1";
    private static final long MAX_GENERATION_MS = 230000L;
    private static final Pattern INSTANCE_ID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Pattern RUNTIME_EPOCH = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SAFE_CODE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final List<String> COMPONENT_NAMES = Collections.unmodifiableList(
            Arrays.asList("root", "keybox", "proxy", "location", "camera"));

    private final File identityFile;
    private final ScheduledExecutorService deadlineWatchdog =
            Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "xenoid-bootstrap-deadline");
                thread.setDaemon(true);
                return thread;
            });
    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "xenoid-bootstrap");
        thread.setDaemon(true);
        return thread;
    });

    private Components components;
    private boolean closed;
    private long nextGeneration = 1L;
    private long generation;
    private long generationDeadline;
    private String instanceId = "";
    private String runtimeEpoch = "";
    private String state = "transport_ready";
    private String errorCode;
    private CancellationSignal cancellation;
    private ScheduledFuture<?> generationTimer;
    private Map<String, ComponentStatus> componentStatus = pendingComponents();

    BootstrapCoordinator(Context context) {
        identityFile = new File(context.getApplicationContext().getNoBackupFilesDir(),
                "bootstrap-identity-v1.json");
    }

    synchronized void installComponents(
            KeyboxManager keybox,
            String keyboxError,
            ProxyManager proxy,
            String proxyError,
            LocationIdentityManager location,
            String locationError,
            CameraMediaManager camera,
            String cameraError) {
        if (components != null || closed) return;
        components = new Components(keybox, safeCode(keyboxError, "keybox_unavailable"),
                proxy, safeCode(proxyError, "proxy_unavailable"),
                location, safeCode(locationError, "location_unavailable"),
                camera, safeCode(cameraError, "camera_unavailable"));
        notifyAll();
    }

    synchronized Response reconcile(String body) {
        Request request;
        try {
            request = parseReconcile(body);
        } catch (RequestFailure ignored) {
            return errorResponse(400, "invalid_request");
        }
        if (closed) return errorResponse(409, "bootstrap_unavailable");

        String pinned;
        try {
            pinned = readPinnedIdentity();
        } catch (IdentityFailure failure) {
            return errorResponse(409, failure.code);
        }
        if (pinned != null && !pinned.equals(request.instanceId)) {
            return errorResponse(409, "instance_identity_mismatch");
        }

        boolean sameInput = request.instanceId.equals(instanceId)
                && request.runtimeEpoch.equals(runtimeEpoch);
        if (isActiveState(state)) {
            if (!sameInput) return errorResponse(409, "bootstrap_generation_conflict");
            generationDeadline = Math.min(generationDeadline,
                    saturatingAdd(SystemClock.elapsedRealtime(), request.timeoutMs));
            scheduleGenerationDeadline(generation, cancellation);
            return new Response(202, snapshotLocked());
        }
        if (sameInput && "ready".equals(state)) {
            return new Response(200, snapshotLocked());
        }

        long selectedGeneration = nextGeneration++;
        generation = selectedGeneration;
        instanceId = request.instanceId;
        runtimeEpoch = request.runtimeEpoch;
        generationDeadline = saturatingAdd(SystemClock.elapsedRealtime(),
                Math.min(MAX_GENERATION_MS, request.timeoutMs));
        errorCode = null;
        state = "accepted";
        cancellation = new CancellationSignal();
        if (!sameInput) {
            componentStatus = pendingComponents();
        } else {
            componentStatus = retryableComponents(componentStatus);
        }
        final CancellationSignal selectedCancellation = cancellation;
        scheduleGenerationDeadline(selectedGeneration, selectedCancellation);
        try {
            worker.execute(() -> runGeneration(selectedGeneration, request,
                    selectedCancellation));
        } catch (RejectedExecutionException rejected) {
            cancelGenerationTimer();
            state = "failed";
            errorCode = "bootstrap_unavailable";
            cancellation = null;
            return new Response(200, snapshotLocked());
        }
        return new Response(202, snapshotLocked());
    }

    synchronized Response status(String body) {
        if (body != null && !body.isEmpty()) return errorResponse(400, "invalid_request");
        return new Response(200, snapshotLocked());
    }

    synchronized Response cancel(String body) {
        long requestedGeneration;
        try {
            requestedGeneration = parseCancel(body);
        } catch (RequestFailure ignored) {
            return errorResponse(400, "invalid_request");
        }
        if (!isActiveState(state) || requestedGeneration != generation || cancellation == null) {
            return errorResponse(409, "bootstrap_generation_conflict");
        }
        cancellation.cancel();
        cancelGenerationTimer();
        state = "failed";
        errorCode = "bootstrap_cancelled";
        componentStatus = cancelPending(componentStatus);
        cancellation = null;
        return new Response(200, snapshotLocked());
    }

    synchronized boolean componentReady(String name) {
        ComponentStatus status = componentStatus.get(name);
        return status != null && status.ok;
    }

    synchronized boolean aggregateBootstrapReady() {
        return "ready".equals(state);
    }

    @Override public void close() {
        CancellationSignal active;
        synchronized (this) {
            if (closed) return;
            closed = true;
            active = cancellation;
            cancellation = null;
            cancelGenerationTimer();
            notifyAll();
        }
        if (active != null) active.cancel();
        deadlineWatchdog.shutdownNow();
        worker.shutdownNow();
    }

    private synchronized void scheduleGenerationDeadline(
            long selectedGeneration, CancellationSignal selectedCancellation) {
        cancelGenerationTimer();
        long delay = Math.max(0L, generationDeadline - SystemClock.elapsedRealtime());
        try {
            generationTimer = deadlineWatchdog.schedule(
                    () -> expireGeneration(selectedGeneration, selectedCancellation),
                    delay, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException rejected) {
            expireGeneration(selectedGeneration, selectedCancellation);
        }
    }

    private synchronized void cancelGenerationTimer() {
        if (generationTimer != null) {
            generationTimer.cancel(false);
            generationTimer = null;
        }
    }

    private synchronized void expireGeneration(
            long selectedGeneration, CancellationSignal selectedCancellation) {
        if (generation != selectedGeneration || cancellation != selectedCancellation
                || !isActiveState(state)) return;
        selectedCancellation.cancel();
        componentStatus = timeoutPending(componentStatus);
        state = "degraded";
        errorCode = "bootstrap_timeout";
        cancellation = null;
        generationTimer = null;
    }

    private void runGeneration(long selectedGeneration, Request request,
            CancellationSignal selectedCancellation) {
        try {
            Components selected = waitForComponents(selectedGeneration, selectedCancellation);
            if (selected == null) {
                finishFailed(selectedGeneration, selectedCancellation,
                        selectedCancellation.isCancelled()
                                ? "bootstrap_cancelled" : "bootstrap_components_unavailable");
                return;
            }
            try {
                ensurePinnedIdentity(request.instanceId, selected);
            } catch (IdentityFailure failure) {
                finishFailed(selectedGeneration, selectedCancellation, failure.code);
                return;
            }
            if (!beginReconciling(selectedGeneration, selectedCancellation)) return;

            runComponent(selectedGeneration, selectedCancellation, "root", 10000L,
                    (deadline, cancellation) -> reconcileRoot(deadline, cancellation));
            runComponent(selectedGeneration, selectedCancellation, "proxy", 20000L,
                    (deadline, cancellation) -> selected.proxy == null
                            ? ComponentStatus.failed(selected.proxyError)
                            : selected.proxy.reconcileBootstrap(
                                    request.instanceId, request.runtimeEpoch, deadline, cancellation));
            runComponent(selectedGeneration, selectedCancellation, "keybox", 50000L,
                    (deadline, cancellation) -> selected.keybox == null
                            ? ComponentStatus.failed(selected.keyboxError)
                            : selected.keybox.reconcileBootstrap(deadline, cancellation));
            runComponent(selectedGeneration, selectedCancellation, "location", 50000L,
                    (deadline, cancellation) -> selected.location == null
                            ? ComponentStatus.failed(selected.locationError)
                            : selected.location.reconcileBootstrap(deadline, cancellation));
            runComponent(selectedGeneration, selectedCancellation, "camera", 80000L,
                    (deadline, cancellation) -> selected.camera == null
                            ? ComponentStatus.failed(selected.cameraError)
                            : selected.camera.reconcileBootstrap(deadline, cancellation));
            finishGeneration(selectedGeneration, selectedCancellation);
        } catch (Throwable ignored) {
            finishFailed(selectedGeneration, selectedCancellation, "bootstrap_failed");
        }
    }

    private Components waitForComponents(long selectedGeneration,
            CancellationSignal selectedCancellation) {
        synchronized (this) {
            while (components == null && generation == selectedGeneration && !closed
                    && !selectedCancellation.isCancelled()) {
                long remaining = generationDeadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) return null;
                try {
                    wait(Math.min(remaining, 250L));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
            return generation == selectedGeneration && !closed ? components : null;
        }
    }

    private synchronized boolean beginReconciling(long selectedGeneration,
            CancellationSignal selectedCancellation) {
        if (!isCurrent(selectedGeneration, selectedCancellation)) return false;
        state = "reconciling";
        return true;
    }

    private void runComponent(long selectedGeneration, CancellationSignal selectedCancellation,
            String name, long budgetMs, ComponentOperation operation) {
        ComponentStatus existing;
        long deadline;
        synchronized (this) {
            if (!isCurrent(selectedGeneration, selectedCancellation)) return;
            existing = componentStatus.get(name);
            if (existing != null && existing.ok) return;
            deadline = Math.min(generationDeadline,
                    saturatingAdd(SystemClock.elapsedRealtime(), budgetMs));
            if (deadline <= SystemClock.elapsedRealtime()) {
                replaceComponent(name, ComponentStatus.timedOut());
                return;
            }
            replaceComponent(name, ComponentStatus.reconciling());
        }

        RootHelper.ConnectionHandle handle = RootHelper.newConnectionHandle();
        handle.setTimeoutCapMs((int) Math.max(1L,
                Math.min(Integer.MAX_VALUE, deadline - SystemClock.elapsedRealtime())));
        selectedCancellation.attach(handle);
        ComponentStatus result;
        try (RootHelper.ConnectionScope ignored = RootHelper.bindConnectionHandle(handle)) {
            if (selectedCancellation.isCancelled()) {
                result = ComponentStatus.cancelled();
            } else {
                result = operation.run(deadline, selectedCancellation);
                if (result == null) result = ComponentStatus.failed(name + "_unavailable");
            }
        } catch (Throwable ignored) {
            result = ComponentStatus.failed(name + "_unavailable");
        } finally {
            selectedCancellation.detach(handle);
        }
        long now = SystemClock.elapsedRealtime();
        long effectiveDeadline;
        synchronized (this) {
            effectiveDeadline = Math.min(deadline, generationDeadline);
        }
        if (selectedCancellation.isCancelled()) {
            result = ComponentStatus.cancelled();
        } else if (now >= effectiveDeadline) {
            handle.cancel();
            result = ComponentStatus.timedOut();
        }
        try { handle.close(); } catch (Throwable ignored) { }
        synchronized (this) {
            if (isCurrent(selectedGeneration, selectedCancellation)) {
                replaceComponent(name, result);
            }
        }
    }

    private ComponentStatus reconcileRoot(long deadline, CancellationSignal cancellation) {
        long remaining = deadline - SystemClock.elapsedRealtime();
        if (remaining <= 0 || cancellation.isCancelled()) return ComponentStatus.timedOut();
        RootHelper.ConnectionHandle handle = cancellation.currentHandle();
        Map<String, Object> result = RootHelper.status((int) Math.min(10000L, remaining), handle);
        if (Boolean.TRUE.equals(result.get("ok")) && Boolean.TRUE.equals(result.get("root"))) {
            return ComponentStatus.ready();
        }
        Object error = result.get("error");
        String code = error instanceof String ? (String) error : "rootd_unavailable";
        if ("unauthorized".equals(code) || "rootd_unauthorized".equals(code)) {
            return ComponentStatus.failed("rootd_unauthorized");
        }
        return ComponentStatus.failed("rootd_unavailable");
    }

    private synchronized void finishGeneration(long selectedGeneration,
            CancellationSignal selectedCancellation) {
        if (!isCurrent(selectedGeneration, selectedCancellation)) return;
        boolean allReady = true;
        for (String name : COMPONENT_NAMES) {
            ComponentStatus status = componentStatus.get(name);
            if (status == null || !status.ok) {
                allReady = false;
                break;
            }
        }
        cancelGenerationTimer();
        state = allReady ? "ready" : "degraded";
        errorCode = allReady ? null : "bootstrap_component_failed";
        cancellation = null;
    }

    private synchronized void finishFailed(long selectedGeneration,
            CancellationSignal selectedCancellation, String failure) {
        if (!isCurrent(selectedGeneration, selectedCancellation)) return;
        cancelGenerationTimer();
        state = "failed";
        errorCode = safeCode(failure, "bootstrap_failed");
        componentStatus = cancelPending(componentStatus);
        cancellation = null;
    }

    private boolean isCurrent(long selectedGeneration, CancellationSignal selectedCancellation) {
        return generation == selectedGeneration && cancellation == selectedCancellation
                && !closed && !selectedCancellation.isCancelled();
    }

    private void replaceComponent(String name, ComponentStatus replacement) {
        LinkedHashMap<String, ComponentStatus> copy = new LinkedHashMap<>(componentStatus);
        copy.put(name, replacement);
        componentStatus = Collections.unmodifiableMap(copy);
    }

    private synchronized Map<String, Object> snapshotLocked() {
        LinkedHashMap<String, Object> statuses = new LinkedHashMap<>();
        for (String name : COMPONENT_NAMES) {
            ComponentStatus status = componentStatus.get(name);
            statuses.put(name, status == null ? ComponentStatus.pending().asMap() : status.asMap());
        }
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        result.put("ok", "ready".equals(state));
        result.put("schema", SCHEMA);
        result.put("state", state);
        result.put("generation", generation);
        result.put("instanceId", instanceId);
        result.put("runtimeEpoch", runtimeEpoch);
        result.put("components", Collections.unmodifiableMap(statuses));
        if (errorCode != null) result.put("errorCode", errorCode);
        return Collections.unmodifiableMap(result);
    }

    private Response errorResponse(int status, String code) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        result.put("ok", false);
        result.put("schema", SCHEMA);
        result.put("errorCode", safeCode(code, "invalid_request"));
        return new Response(status, Collections.unmodifiableMap(result));
    }

    private void ensurePinnedIdentity(String requested, Components selected)
            throws IdentityFailure {
        synchronized (this) {
            String pinned = readPinnedIdentity();
            if (pinned != null) {
                if (!pinned.equals(requested)) throw new IdentityFailure("instance_identity_mismatch");
                return;
            }
            ArrayList<String> readable = new ArrayList<>();
            if (selected.proxy != null) {
                String proxyIdentity = selected.proxy.bootstrapInstanceId();
                if (proxyIdentity != null && !proxyIdentity.isEmpty()) readable.add(proxyIdentity);
            }
            for (String componentIdentity : readable) {
                if (!requested.equals(componentIdentity)) {
                    throw new IdentityFailure("instance_identity_mismatch");
                }
            }
            writePinnedIdentity(requested);
        }
    }

    private String readPinnedIdentity() throws IdentityFailure {
        final StructStat stat;
        try {
            stat = Os.lstat(identityFile.getAbsolutePath());
        } catch (android.system.ErrnoException missing) {
            if (missing.errno == OsConstants.ENOENT) return null;
            throw new IdentityFailure("bootstrap_identity_invalid");
        }
        if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG
                || (stat.st_mode & 07777) != 0600 || stat.st_uid != Process.myUid()
                || stat.st_nlink != 1 || stat.st_size <= 0 || stat.st_size > 256) {
            throw new IdentityFailure("bootstrap_identity_invalid");
        }
        byte[] bytes = null;
        try {
            bytes = readNoFollow(identityFile, stat.st_size, 256);
            JSONObject object = strictObject(new String(bytes, StandardCharsets.UTF_8));
            requireKeys(object, "schema", "instanceId");
            if (!IDENTITY_SCHEMA.equals(object.opt("schema"))) throw new Exception();
            Object identity = object.opt("instanceId");
            if (!(identity instanceof String) || !INSTANCE_ID.matcher((String) identity).matches()) {
                throw new Exception();
            }
            return (String) identity;
        } catch (Throwable ignored) {
            throw new IdentityFailure("bootstrap_identity_invalid");
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    private void writePinnedIdentity(String requested) throws IdentityFailure {
        File parent = identityFile.getParentFile();
        File temporary = new File(parent, ".bootstrap-identity-" + UUID.randomUUID() + ".tmp");
        byte[] bytes = ("{\"schema\":\"" + IDENTITY_SCHEMA + "\",\"instanceId\":\""
                + requested + "\"}").getBytes(StandardCharsets.UTF_8);
        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(temporary.getAbsolutePath(), OsConstants.O_WRONLY
                    | OsConstants.O_CREAT | OsConstants.O_EXCL | OsConstants.O_NOFOLLOW, 0600);
            Os.fchmod(descriptor, 0600);
            try (FileOutputStream output = new FileOutputStream(descriptor)) {
                descriptor = null;
                output.write(bytes);
                output.flush();
                output.getFD().sync();
            }
            Os.rename(temporary.getAbsolutePath(), identityFile.getAbsolutePath());
            syncDirectory(parent);
            String pinned = readPinnedIdentity();
            if (!requested.equals(pinned)) throw new Exception();
        } catch (Throwable ignored) {
            try { Os.remove(temporary.getAbsolutePath()); } catch (Throwable unlinkIgnored) { }
            throw new IdentityFailure("bootstrap_identity_invalid");
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (descriptor != null) try { Os.close(descriptor); } catch (Throwable ignored) { }
        }
    }

    private static byte[] readNoFollow(File file, long expected, int maximum) throws Exception {
        if (expected < 0 || expected > maximum) throw new Exception();
        FileDescriptor descriptor = Os.open(file.getAbsolutePath(),
                OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
        try (FileInputStream input = new FileInputStream(descriptor)) {
            descriptor = null;
            byte[] bytes = new byte[(int) expected];
            int offset = 0;
            while (offset < bytes.length) {
                int count = input.read(bytes, offset, bytes.length - offset);
                if (count <= 0) throw new Exception();
                offset += count;
            }
            if (input.read() != -1) throw new Exception();
            return bytes;
        } finally {
            if (descriptor != null) try { Os.close(descriptor); } catch (Throwable ignored) { }
        }
    }

    private static void syncDirectory(File directory) throws Exception {
        FileDescriptor descriptor = Os.open(directory.getAbsolutePath(),
                OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
        try {
            StructStat metadata = Os.fstat(descriptor);
            if ((metadata.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFDIR
                    || metadata.st_uid != Process.myUid()) throw new Exception();
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private static Request parseReconcile(String body) throws RequestFailure {
        try {
            JSONObject object = strictObject(body);
            requireKeys(object, "schema", "instanceId", "runtimeEpoch", "timeoutMs");
            if (!SCHEMA.equals(object.opt("schema"))) throw new Exception();
            Object identity = object.opt("instanceId");
            Object epoch = object.opt("runtimeEpoch");
            Object timeout = object.opt("timeoutMs");
            if (!(identity instanceof String) || !INSTANCE_ID.matcher((String) identity).matches()
                    || !(epoch instanceof String) || !RUNTIME_EPOCH.matcher((String) epoch).matches()
                    || !(timeout instanceof Integer || timeout instanceof Long)) throw new Exception();
            long timeoutMs = ((Number) timeout).longValue();
            if (timeoutMs < 1000L || timeoutMs > MAX_GENERATION_MS) throw new Exception();
            return new Request((String) identity, (String) epoch, timeoutMs);
        } catch (Throwable ignored) {
            throw new RequestFailure();
        }
    }

    private static long parseCancel(String body) throws RequestFailure {
        try {
            JSONObject object = strictObject(body);
            requireKeys(object, "schema", "generation");
            if (!SCHEMA.equals(object.opt("schema"))) throw new Exception();
            Object generation = object.opt("generation");
            if (!(generation instanceof Integer || generation instanceof Long)) throw new Exception();
            long value = ((Number) generation).longValue();
            if (value <= 0) throw new Exception();
            return value;
        } catch (Throwable ignored) {
            throw new RequestFailure();
        }
    }

    private static JSONObject strictObject(String body) throws Exception {
        if (!XenoidDaemonService.isStrictSimpleObject(body)) throw new Exception();
        JSONTokener tokener = new JSONTokener(body);
        Object parsed = tokener.nextValue();
        if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) throw new Exception();
        return (JSONObject) parsed;
    }

    private static void requireKeys(JSONObject object, String... keys) throws Exception {
        List<String> expected = Arrays.asList(keys);
        int count = 0;
        Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) {
            String key = iterator.next();
            if (!expected.contains(key)) throw new Exception();
            count++;
        }
        if (count != expected.size()) throw new Exception();
        for (String key : expected) if (!object.has(key) || object.isNull(key)) throw new Exception();
    }

    private static boolean isActiveState(String value) {
        return "accepted".equals(value) || "reconciling".equals(value);
    }

    private static long saturatingAdd(long left, long right) {
        return Long.MAX_VALUE - left < right ? Long.MAX_VALUE : left + right;
    }

    private static String safeCode(String code, String fallback) {
        return code != null && SAFE_CODE.matcher(code).matches() ? code : fallback;
    }

    private static Map<String, ComponentStatus> pendingComponents() {
        LinkedHashMap<String, ComponentStatus> statuses = new LinkedHashMap<>();
        for (String name : COMPONENT_NAMES) statuses.put(name, ComponentStatus.pending());
        return Collections.unmodifiableMap(statuses);
    }

    private static Map<String, ComponentStatus> retryableComponents(
            Map<String, ComponentStatus> previous) {
        LinkedHashMap<String, ComponentStatus> statuses = new LinkedHashMap<>();
        for (String name : COMPONENT_NAMES) {
            ComponentStatus prior = previous.get(name);
            statuses.put(name, prior != null && prior.ok ? prior : ComponentStatus.pending());
        }
        return Collections.unmodifiableMap(statuses);
    }

    private static Map<String, ComponentStatus> timeoutPending(
            Map<String, ComponentStatus> previous) {
        LinkedHashMap<String, ComponentStatus> statuses = new LinkedHashMap<>();
        for (String name : COMPONENT_NAMES) {
            ComponentStatus prior = previous.get(name);
            if (prior == null || "pending".equals(prior.state)
                    || "reconciling".equals(prior.state)) {
                statuses.put(name, ComponentStatus.timedOut());
            } else {
                statuses.put(name, prior);
            }
        }
        return Collections.unmodifiableMap(statuses);
    }

    private static Map<String, ComponentStatus> cancelPending(
            Map<String, ComponentStatus> previous) {
        LinkedHashMap<String, ComponentStatus> statuses = new LinkedHashMap<>();
        for (String name : COMPONENT_NAMES) {
            ComponentStatus prior = previous.get(name);
            if (prior == null || "pending".equals(prior.state)
                    || "reconciling".equals(prior.state)) {
                statuses.put(name, ComponentStatus.cancelled());
            } else {
                statuses.put(name, prior);
            }
        }
        return Collections.unmodifiableMap(statuses);
    }

    static final class Response {
        final int status;
        final Map<String, Object> body;

        Response(int status, Map<String, Object> body) {
            this.status = status;
            this.body = body;
        }
    }

    static final class ComponentStatus {
        final boolean ok;
        final String state;
        final String errorCode;
        final Map<String, Object> fields;

        private ComponentStatus(boolean ok, String state, String errorCode,
                Map<String, Object> fields) {
            this.ok = ok;
            this.state = state;
            this.errorCode = errorCode == null ? null : safeCode(errorCode, "component_failed");
            this.fields = immutableFields(fields);
        }

        static ComponentStatus pending() {
            return new ComponentStatus(false, "pending", null, null);
        }

        static ComponentStatus reconciling() {
            return new ComponentStatus(false, "reconciling", null, null);
        }

        static ComponentStatus ready() {
            return new ComponentStatus(true, "ready", null, null);
        }

        static ComponentStatus ready(String state, Map<String, Object> fields) {
            if (!("ready".equals(state) || "unconfigured".equals(state)
                    || "quarantined".equals(state) || "deferred".equals(state))) {
                state = "ready";
            }
            return new ComponentStatus(true, state, null, fields);
        }

        static ComponentStatus failed(String code) {
            return new ComponentStatus(false, "failed", code, null);
        }

        static ComponentStatus failed(String code, Map<String, Object> fields) {
            return new ComponentStatus(false, "failed", code, fields);
        }

        static ComponentStatus timedOut() {
            return new ComponentStatus(false, "timed_out", "component_timeout", null);
        }

        static ComponentStatus cancelled() {
            return new ComponentStatus(false, "cancelled", "bootstrap_cancelled", null);
        }

        Map<String, Object> asMap() {
            LinkedHashMap<String, Object> result = new LinkedHashMap<>();
            result.put("ok", ok);
            result.put("state", state);
            result.putAll(fields);
            if (errorCode != null) result.put("errorCode", errorCode);
            return Collections.unmodifiableMap(result);
        }

        private static Map<String, Object> immutableFields(Map<String, Object> source) {
            if (source == null || source.isEmpty()) return Collections.emptyMap();
            LinkedHashMap<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : source.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof Map) {
                    value = immutableFields((Map<String, Object>) value);
                }
                result.put(entry.getKey(), value);
            }
            return Collections.unmodifiableMap(result);
        }
    }

    static final class CancellationSignal {
        private boolean cancelled;
        private RootHelper.ConnectionHandle activeHandle;

        synchronized boolean isCancelled() {
            return cancelled;
        }

        synchronized void cancel() {
            cancelled = true;
            if (activeHandle != null) activeHandle.cancel();
        }

        synchronized void attach(RootHelper.ConnectionHandle handle) {
            if (cancelled) handle.cancel();
            else activeHandle = handle;
        }

        synchronized void detach(RootHelper.ConnectionHandle handle) {
            if (activeHandle == handle) activeHandle = null;
        }

        synchronized RootHelper.ConnectionHandle currentHandle() {
            return activeHandle;
        }
    }

    private interface ComponentOperation {
        ComponentStatus run(long deadline, CancellationSignal cancellation) throws Exception;
    }

    private static final class Request {
        final String instanceId;
        final String runtimeEpoch;
        final long timeoutMs;

        Request(String instanceId, String runtimeEpoch, long timeoutMs) {
            this.instanceId = instanceId;
            this.runtimeEpoch = runtimeEpoch;
            this.timeoutMs = timeoutMs;
        }
    }

    private static final class Components {
        final KeyboxManager keybox;
        final String keyboxError;
        final ProxyManager proxy;
        final String proxyError;
        final LocationIdentityManager location;
        final String locationError;
        final CameraMediaManager camera;
        final String cameraError;

        Components(KeyboxManager keybox, String keyboxError,
                ProxyManager proxy, String proxyError,
                LocationIdentityManager location, String locationError,
                CameraMediaManager camera, String cameraError) {
            this.keybox = keybox;
            this.keyboxError = keyboxError;
            this.proxy = proxy;
            this.proxyError = proxyError;
            this.location = location;
            this.locationError = locationError;
            this.camera = camera;
            this.cameraError = cameraError;
        }
    }

    private static final class RequestFailure extends Exception { }

    private static final class IdentityFailure extends Exception {
        final String code;

        IdentityFailure(String code) {
            this.code = safeCode(code, "bootstrap_identity_invalid");
        }
    }
}
