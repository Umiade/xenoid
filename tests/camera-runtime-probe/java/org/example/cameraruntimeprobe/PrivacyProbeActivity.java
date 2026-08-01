package org.example.cameraruntimeprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.CameraManager;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.system.Os;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class PrivacyProbeActivity extends Activity {
    private static final String SOURCE_DIRECTORY = "/data/misc/camera/source";
    private static final String[] CAMERA_MARKERS =
            new String[] {"xenoid", "mock", "replay", "inject"};
    private static final String[] SU_PATHS = new String[] {
            "/system/bin/su",
            "/system/xbin/su",
            "/vendor/bin/su",
            "/product/bin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/data/local/su",
            "/debug_ramdisk/su"
    };
    private static final int COMMAND_TIMEOUT_SECONDS = 2;
    private static final int MAX_COMMAND_BYTES = 4 * 1024 * 1024;
    private static final int MAX_FILE_BYTES = 1024 * 1024;
    private static final int MAX_PROC_PROCESSES = 1024;
    private static final int MAX_PROC_FDS = 256;
    private static final int MAX_VALUE_ITEMS = 4096;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(this::runProbe, "privacy-probe-controller").start();
    }

    private void runProbe() {
        JSONObject report = new JSONObject();
        ServiceConnection connection = null;
        boolean bound = false;
        try {
            String forbiddenName = cleanExtra(
                    getIntent().getStringExtra("forbiddenName"));
            String forbiddenDigest = cleanExtra(
                    getIntent().getStringExtra("forbiddenDigest"));
            boolean configured = getIntent().getBooleanExtra("configured", false);
            boolean scanRequested = configured
                    || forbiddenName != null || forbiddenDigest != null;
            boolean configuredExtrasValid = !scanRequested
                    || (configured && forbiddenName != null && forbiddenDigest != null);
            LeakScanner scanner = new LeakScanner(
                    scanRequested ? forbiddenName : null,
                    scanRequested ? forbiddenDigest : null);

            PublicationScan publication = inspectPublication(scanner);
            int appId = Process.myUid() % 100000;
            boolean ordinaryAppUid = appId >= 10000 && appId <= 19999
                    && !Process.isIsolated();
            SuScan su = inspectSu();

            MetadataScan metadata = scanRequested
                    ? inspectCameraMetadata(scanner) : MetadataScan.skipped();
            SurfaceScan surfaces = scanRequested
                    ? inspectVisibleSurfaces(scanner) : SurfaceScan.skipped();
            ProcScan proc = scanRequested
                    ? inspectProc(scanner) : ProcScan.skipped();

            CountDownLatch connected = new CountDownLatch(1);
            AtomicReference<IBinder> binder = new AtomicReference<>();
            CountDownLatch terminated = new CountDownLatch(1);
            connection = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName name, IBinder service) {
                    binder.set(service);
                    connected.countDown();
                }
                @Override public void onServiceDisconnected(ComponentName name) {
                    terminated.countDown();
                }
            };
            bound = bindService(new Intent(this, IsolationProbeService.class),
                    connection, Context.BIND_AUTO_CREATE);
            if (!bound || !connected.await(15, TimeUnit.SECONDS) || binder.get() == null) {
                throw new IllegalStateException("isolated service unavailable");
            }
            binder.get().linkToDeath(terminated::countDown, 0);
            Parcel request = Parcel.obtain();
            Parcel response = Parcel.obtain();
            JSONObject isolated;
            try {
                if (!binder.get().transact(1, request, response, 0)) {
                    throw new IllegalStateException("isolated transaction failed");
                }
                response.readException();
                isolated = new JSONObject(response.readString());
            } finally {
                request.recycle();
                response.recycle();
            }
            unbindService(connection);
            bound = false;
            boolean isolatedTerminated = terminated.await(5, TimeUnit.SECONDS);
            isolated.put("boundedProcessTermination", isolatedTerminated);
            isolated.put("ok", isolated.optBoolean("ok") && isolatedTerminated);

            boolean configuredScanComplete = !scanRequested
                    || (configuredExtrasValid && metadata.complete && surfaces.complete
                            && proc.complete && scanner.coverageComplete);
            boolean noLeak = !scanner.sourceIdentityLeak
                    && !scanner.cameraMarkerLeak;
            boolean sourceHidden = publication.directoryReadDenied
                    && publication.configurationHidden
                    && publication.generationHidden;
            boolean ok = ordinaryAppUid && sourceHidden && publication.complete
                    && su.ok && configuredScanComplete && noLeak
                    && isolated.optBoolean("ok");

            report.put("probe", "source-privacy");
            report.put("configuredScan", scanRequested);
            report.put("configuredExtrasValid", configuredExtrasValid);
            report.put("ordinaryAppUid", ordinaryAppUid);
            report.put("ordinarySourceHidden", sourceHidden);
            report.put("sourceDirectoryStatDenied", publication.directoryStatDenied);
            report.put("sourceDirectoryReadDenied", publication.directoryReadDenied);
            report.put("sourceConfigStatDenied", publication.configurationStatDenied);
            report.put("sourceConfigReadDenied", publication.configurationReadDenied);
            report.put("sourceGenerationHidden", publication.generationHidden);
            report.put("filesystemPathsProbed", publication.pathsProbed);
            report.put("cameraMetadataScanComplete", metadata.complete);
            report.put("cameraMetadataKeysScanned", metadata.keysScanned);
            report.put("visibleSurfaceScanComplete", surfaces.complete);
            report.put("visibleSurfaceCommandsScanned", surfaces.commandsScanned);
            report.put("logcatScanComplete", surfaces.logcatComplete);
            report.put("procScanComplete", proc.complete);
            report.put("procSurfacesScanned", proc.surfacesScanned);
            report.put("sourceIdentityAbsent", !scanner.sourceIdentityLeak);
            report.put("cameraMarkersAbsent", !scanner.cameraMarkerLeak);
            report.put("suPathsVisible", su.pathsVisible);
            report.put("suAttempts", su.attempts);
            report.put("suDiscoveryDenied", su.discoveryDenied);
            report.put("suExecutionDenied", su.executionDenied);
            report.put("suAttemptsBounded", su.bounded);
            report.put("effectiveUidUnprivileged", su.effectiveUidUnprivileged);
            report.put("rootShellUnavailable", !su.rootShellObtained);
            report.put("isolated", isolated);
            report.put("ok", ok);
        } catch (Throwable error) {
            report = ProbeIo.failure("source-privacy", error);
        } finally {
            if (bound && connection != null) unbindService(connection);
        }
        ProbeIo.write(this, "privacy.json", report);
        runOnUiThread(this::finish);
    }

    private MetadataScan inspectCameraMetadata(LeakScanner scanner) {
        int keysScanned = 0;
        boolean complete = true;
        try {
            CameraManager manager = getSystemService(CameraManager.class);
            String[] cameraIds = manager.getCameraIdList();
            if (cameraIds.length == 0) complete = false;
            for (String id : cameraIds) {
                scanner.scan(id, true);
                CameraCharacteristics characteristics =
                        manager.getCameraCharacteristics(id);
                List<CameraCharacteristics.Key<?>> keys = characteristics.getKeys();
                if (keys == null) {
                    complete = false;
                    continue;
                }
                for (CameraCharacteristics.Key<?> key : keys) {
                    scanner.scan(key.getName(), true);
                    try {
                        scanner.scanValue(
                                characteristicValue(characteristics, key), true, 0);
                    } catch (Throwable ignored) {
                        complete = false;
                    }
                    ++keysScanned;
                }
                List<CaptureRequest.Key<?>> requestKeys =
                        characteristics.getAvailableCaptureRequestKeys();
                if (requestKeys == null) {
                    complete = false;
                } else {
                    for (CaptureRequest.Key<?> key : requestKeys) {
                        scanner.scan(key.getName(), true);
                        ++keysScanned;
                    }
                }
                List<CaptureResult.Key<?>> resultKeys =
                        characteristics.getAvailableCaptureResultKeys();
                if (resultKeys == null) {
                    complete = false;
                } else {
                    for (CaptureResult.Key<?> key : resultKeys) {
                        scanner.scan(key.getName(), true);
                        ++keysScanned;
                    }
                }
                List<CaptureRequest.Key<?>> sessionKeys =
                        characteristics.getAvailableSessionKeys();
                if (sessionKeys != null) {
                    for (CaptureRequest.Key<?> key : sessionKeys) {
                        scanner.scan(key.getName(), true);
                        ++keysScanned;
                    }
                }
                List<CaptureRequest.Key<?>> physicalKeys =
                        characteristics.getAvailablePhysicalCameraRequestKeys();
                if (physicalKeys != null) {
                    for (CaptureRequest.Key<?> key : physicalKeys) {
                        scanner.scan(key.getName(), true);
                        ++keysScanned;
                    }
                }
            }
        } catch (Throwable ignored) {
            complete = false;
        }
        return new MetadataScan(complete, keysScanned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Object characteristicValue(CameraCharacteristics characteristics,
            CameraCharacteristics.Key<?> key) {
        return characteristics.get((CameraCharacteristics.Key) key);
    }

    private static PublicationScan inspectPublication(LeakScanner scanner) {
        File directory = new File(SOURCE_DIRECTORY);
        File configuration = new File(directory, "current.conf");
        boolean directoryStatDenied = !canStat(directory);
        String[] children = directory.list();
        boolean directoryReadDenied = children == null;
        boolean configurationStatDenied = !canStat(configuration);
        FileRead configurationRead = readFile(configuration, MAX_FILE_BYTES);
        boolean configurationReadDenied = !configurationRead.accessible;
        boolean complete = !configurationRead.truncated;
        int pathsProbed = 2;
        if (configurationRead.accessible) {
            scanner.scan(configurationRead.text, true);
        }

        boolean generationHidden = true;
        if (children != null) {
            if (children.length > MAX_VALUE_ITEMS) complete = false;
            int limit = Math.min(children.length, MAX_VALUE_ITEMS);
            for (int index = 0; index < limit; ++index) {
                String name = children[index];
                scanner.scan(name, true);
                File child = new File(directory, name);
                boolean statAllowed = canStat(child);
                FileRead content = readFile(child, MAX_FILE_BYTES);
                if (content.accessible) scanner.scan(content.text, true);
                generationHidden &= !statAllowed && !content.accessible;
                complete &= !content.truncated;
                ++pathsProbed;
            }
        }
        boolean directoryHidden = directoryStatDenied && directoryReadDenied;
        boolean configurationHidden =
                configurationStatDenied && configurationReadDenied;
        return new PublicationScan(directoryHidden, configurationHidden,
                generationHidden, directoryStatDenied, directoryReadDenied,
                configurationStatDenied, configurationReadDenied, complete, pathsProbed);
    }

    private static SurfaceScan inspectVisibleSurfaces(LeakScanner scanner) {
        String[][] commands = new String[][] {
                {"/system/bin/service", "list"},
                {"/system/bin/cmd", "-l"},
                {"/system/bin/ps", "-A"},
                {"/system/bin/ps", "-A", "-o", "PID,UID,NAME,ARGS"},
                {"/system/bin/dumpsys", "media.camera"},
                {"/system/bin/logcat", "-d", "-v", "brief"}
        };
        boolean complete = true;
        boolean logcatComplete = false;
        int scanned = 0;
        for (int index = 0; index < commands.length; ++index) {
            CommandResult command = runCommand(commands[index]);
            boolean commandComplete = command.launched
                    && command.completed && !command.truncated;
            complete &= commandComplete;
            if (command.launched) {
                boolean cameraDump = index == commands.length - 2;
                scanner.scan(command.output, cameraDump);
                ++scanned;
            }
            if (index == commands.length - 1) logcatComplete = commandComplete;
        }
        return new SurfaceScan(complete, logcatComplete, scanned);
    }

    private static ProcScan inspectProc(LeakScanner scanner) {
        ProcAccumulator accumulator = new ProcAccumulator(scanner);
        accumulator.file(new File("/proc/self/cmdline"));
        accumulator.file(new File("/proc/self/status"));
        accumulator.file(new File("/proc/self/mountinfo"));
        accumulator.file(new File("/proc/self/maps"));
        accumulator.file(new File("/proc/self/environ"));
        accumulator.file(new File("/proc/self/cgroup"));
        accumulator.file(new File("/proc/net/unix"));
        accumulator.file(new File("/proc/mounts"));

        File[] processes = new File("/proc").listFiles();
        if (processes == null) {
            accumulator.complete = false;
            return accumulator.result();
        }
        int processCount = 0;
        for (File process : processes) {
            if (!isNumeric(process.getName())) continue;
            if (++processCount > MAX_PROC_PROCESSES) {
                accumulator.complete = false;
                break;
            }
            accumulator.file(new File(process, "cmdline"));
            accumulator.file(new File(process, "comm"));
            accumulator.file(new File(process, "status"));
            accumulator.file(new File(process, "maps"));
            accumulator.file(new File(process, "environ"));
            accumulator.file(new File(process, "cgroup"));
            accumulator.link(new File(process, "exe"));
            accumulator.link(new File(process, "cwd"));
            accumulator.links(new File(process, "fd"));
        }
        return accumulator.result();
    }

    private static SuScan inspectSu() {
        int pathsVisible = 0;
        int attempts = 0;
        boolean bounded = true;
        boolean executionDenied = true;
        boolean rootShellObtained = false;
        for (String path : SU_PATHS) {
            if (canStat(new File(path))) ++pathsVisible;
            CommandResult attempt = runCommand(
                    new String[] {path, "-c", "/system/bin/id -u"});
            ++attempts;
            bounded &= !attempt.launched || (attempt.completed && !attempt.truncated);
            executionDenied &= !attempt.launched
                    || (attempt.completed && attempt.exitCode != 0);
            rootShellObtained |= rootIdentity(attempt.output);
        }

        CommandResult lookup = runCommand(new String[] {
                "/system/bin/sh", "-c", "command -v su"
        });
        boolean lookupBounded = lookup.launched
                && lookup.completed && !lookup.truncated;
        boolean pathDiscovery = lookupBounded && lookup.exitCode == 0
                && !lookup.output.trim().isEmpty();
        if (pathDiscovery) ++pathsVisible;
        bounded &= lookupBounded;

        CommandResult pathAttempt = runCommand(new String[] {
                "/system/bin/sh", "-c", "su -c '/system/bin/id -u'"
        });
        ++attempts;
        bounded &= pathAttempt.launched
                && pathAttempt.completed && !pathAttempt.truncated;
        executionDenied &= pathAttempt.launched && pathAttempt.completed
                && pathAttempt.exitCode != 0;
        rootShellObtained |= rootIdentity(pathAttempt.output);

        CommandResult effectiveUid = runCommand(
                new String[] {"/system/bin/id", "-u"});
        int observedUid = parseUid(effectiveUid.output);
        boolean effectiveUidUnprivileged = effectiveUid.launched
                && effectiveUid.completed && !effectiveUid.truncated
                && effectiveUid.exitCode == 0 && observedUid == Process.myUid()
                && observedUid != 0;
        bounded &= effectiveUid.launched
                && effectiveUid.completed && !effectiveUid.truncated;
        rootShellObtained |= observedUid == 0;

        boolean discoveryDenied = pathsVisible == 0 && !pathDiscovery;
        boolean ok = discoveryDenied && executionDenied && bounded
                && effectiveUidUnprivileged && !rootShellObtained;
        return new SuScan(ok, discoveryDenied, executionDenied, bounded,
                effectiveUidUnprivileged, rootShellObtained, pathsVisible, attempts);
    }

    private static CommandResult runCommand(String[] command) {
        java.lang.Process child;
        try {
            child = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (Throwable unavailable) {
            return CommandResult.unavailable();
        }
        CommandCapture capture = new CommandCapture(child.getInputStream());
        Thread reader = new Thread(capture, "privacy-command-output");
        reader.setDaemon(true);
        reader.start();
        boolean completed = false;
        try {
            completed = child.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        if (!completed) {
            child.destroy();
            try {
                if (!child.waitFor(200, TimeUnit.MILLISECONDS)) child.destroyForcibly();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                child.destroyForcibly();
            }
        }
        try {
            reader.join(500L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        int exitCode = Integer.MIN_VALUE;
        if (completed) {
            try {
                exitCode = child.exitValue();
            } catch (Throwable ignored) {
                completed = false;
            }
        }
        boolean readerCompleted = !reader.isAlive() && !capture.failed;
        boolean truncated = readerCompleted ? capture.truncated : true;
        String output = readerCompleted ? capture.text() : "";
        return new CommandResult(true, completed && readerCompleted,
                exitCode, truncated, output);
    }

    private static FileRead readFile(File file, int maximumBytes) {
        try (FileInputStream stream = new FileInputStream(file);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            boolean truncated = false;
            int count;
            while ((count = stream.read(buffer)) != -1) {
                int remaining = maximumBytes - output.size();
                if (remaining > 0) output.write(buffer, 0, Math.min(remaining, count));
                if (count > remaining) truncated = true;
            }
            return new FileRead(true, truncated,
                    new String(output.toByteArray(), StandardCharsets.UTF_8));
        } catch (Throwable denied) {
            return FileRead.denied();
        }
    }

    private static boolean canStat(File file) {
        try {
            Os.stat(file.getAbsolutePath());
            return true;
        } catch (Throwable denied) {
            return false;
        }
    }

    private static boolean isNumeric(String value) {
        if (value.isEmpty()) return false;
        for (int index = 0; index < value.length(); ++index) {
            if (value.charAt(index) < '0' || value.charAt(index) > '9') return false;
        }
        return true;
    }

    private static String cleanExtra(String value) {
        if (value == null) return null;
        String cleaned = value.trim();
        return cleaned.isEmpty() ? null : cleaned;
    }

    private static int parseUid(String value) {
        if (value == null) return -1;
        String[] lines = value.split("\\n");
        for (String line : lines) {
            String candidate = line.trim();
            if (candidate.isEmpty()) continue;
            try {
                return Integer.parseInt(candidate);
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }

    private static boolean rootIdentity(String output) {
        if (output == null) return false;
        String[] lines = output.toLowerCase(Locale.ROOT).split("\\n");
        for (String line : lines) {
            String value = line.trim();
            if ("0".equals(value) || value.startsWith("uid=0(")
                    || value.startsWith("uid=0 ")) {
                return true;
            }
        }
        return false;
    }

    private static final class LeakScanner {
        private final String forbiddenName;
        private final String forbiddenDigest;
        private final byte[] forbiddenDigestBytes;
        boolean sourceIdentityLeak;
        boolean cameraMarkerLeak;
        boolean coverageComplete = true;

        LeakScanner(String forbiddenName, String forbiddenDigest) {
            this.forbiddenName = lower(forbiddenName);
            this.forbiddenDigest = lower(forbiddenDigest);
            this.forbiddenDigestBytes = decodeHex(this.forbiddenDigest);
        }

        void scan(String text, boolean whollyCameraRelated) {
            if (text == null || text.isEmpty()) return;
            if (text.length() > MAX_COMMAND_BYTES) {
                coverageComplete = false;
                text = text.substring(0, MAX_COMMAND_BYTES);
            }
            String lower = text.toLowerCase(Locale.ROOT);
            sourceIdentityLeak |= forbiddenName != null && lower.contains(forbiddenName);
            sourceIdentityLeak |= forbiddenDigest != null && lower.contains(forbiddenDigest);
            if (whollyCameraRelated) {
                cameraMarkerLeak |= containsMarker(lower);
                return;
            }
            String[] lines = lower.split("\\n");
            for (String line : lines) {
                if (line.contains("camera") && containsMarker(line)) {
                    cameraMarkerLeak = true;
                }
            }
        }

        void scanValue(Object value, boolean cameraRelated, int depth) {
            if (value == null) return;
            if (depth > 8) {
                coverageComplete = false;
                return;
            }
            if (value instanceof byte[]) {
                byte[] bytes = (byte[]) value;
                scan(new String(bytes, StandardCharsets.UTF_8), cameraRelated);
                if (forbiddenDigestBytes != null
                        && containsBytes(bytes, forbiddenDigestBytes)) {
                    sourceIdentityLeak = true;
                }
                return;
            }
            Class<?> type = value.getClass();
            if (type.isArray()) {
                int length = Array.getLength(value);
                if (length > MAX_VALUE_ITEMS) coverageComplete = false;
                int limit = Math.min(length, MAX_VALUE_ITEMS);
                for (int index = 0; index < limit; ++index) {
                    scanValue(Array.get(value, index), cameraRelated, depth + 1);
                }
                return;
            }
            if (value instanceof Iterable) {
                int count = 0;
                for (Object item : (Iterable<?>) value) {
                    if (++count > MAX_VALUE_ITEMS) {
                        coverageComplete = false;
                        break;
                    }
                    scanValue(item, cameraRelated, depth + 1);
                }
                return;
            }
            scan(String.valueOf(value), cameraRelated);
        }

        private static boolean containsMarker(String value) {
            for (String marker : CAMERA_MARKERS) {
                if (value.contains(marker)) return true;
            }
            return false;
        }

        private static String lower(String value) {
            return value == null ? null : value.toLowerCase(Locale.ROOT);
        }

        private static byte[] decodeHex(String value) {
            if (value == null || value.length() == 0 || (value.length() & 1) != 0) {
                return null;
            }
            byte[] bytes = new byte[value.length() / 2];
            for (int index = 0; index < bytes.length; ++index) {
                int high = Character.digit(value.charAt(index * 2), 16);
                int low = Character.digit(value.charAt(index * 2 + 1), 16);
                if (high < 0 || low < 0) return null;
                bytes[index] = (byte) ((high << 4) | low);
            }
            return bytes;
        }

        private static boolean containsBytes(byte[] value, byte[] target) {
            if (target.length == 0 || target.length > value.length) return false;
            outer:
            for (int index = 0; index <= value.length - target.length; ++index) {
                for (int offset = 0; offset < target.length; ++offset) {
                    if (value[index + offset] != target[offset]) continue outer;
                }
                return true;
            }
            return false;
        }
    }

    private static final class ProcAccumulator {
        final LeakScanner scanner;
        int surfacesScanned;
        boolean complete = true;

        ProcAccumulator(LeakScanner scanner) {
            this.scanner = scanner;
        }

        void file(File file) {
            FileRead read = readFile(file, MAX_FILE_BYTES);
            if (!read.accessible) return;
            ++surfacesScanned;
            complete &= !read.truncated;
            scanner.scan(read.text, false);
        }

        void link(File file) {
            try {
                String target = Os.readlink(file.getAbsolutePath());
                ++surfacesScanned;
                scanner.scan(target, false);
            } catch (Throwable denied) {
            }
        }

        void links(File directory) {
            File[] links = directory.listFiles();
            if (links == null) return;
            if (links.length > MAX_PROC_FDS) complete = false;
            int limit = Math.min(links.length, MAX_PROC_FDS);
            for (int index = 0; index < limit; ++index) link(links[index]);
        }

        ProcScan result() {
            return new ProcScan(complete, surfacesScanned);
        }
    }

    private static final class CommandCapture implements Runnable {
        private final InputStream input;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        boolean truncated;
        boolean failed;

        CommandCapture(InputStream input) {
            this.input = input;
        }

        @Override public void run() {
            try (InputStream stream = input) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = stream.read(buffer)) != -1) {
                    int remaining = MAX_COMMAND_BYTES - output.size();
                    if (remaining > 0) {
                        output.write(buffer, 0, Math.min(remaining, count));
                    }
                    if (count > remaining) truncated = true;
                }
            } catch (Throwable error) {
                failed = true;
            }
        }

        String text() {
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static final class FileRead {
        final boolean accessible;
        final boolean truncated;
        final String text;

        FileRead(boolean accessible, boolean truncated, String text) {
            this.accessible = accessible;
            this.truncated = truncated;
            this.text = text;
        }

        static FileRead denied() {
            return new FileRead(false, false, "");
        }
    }

    private static final class CommandResult {
        final boolean launched;
        final boolean completed;
        final int exitCode;
        final boolean truncated;
        final String output;

        CommandResult(boolean launched, boolean completed, int exitCode,
                boolean truncated, String output) {
            this.launched = launched;
            this.completed = completed;
            this.exitCode = exitCode;
            this.truncated = truncated;
            this.output = output;
        }

        static CommandResult unavailable() {
            return new CommandResult(false, true, Integer.MIN_VALUE, false, "");
        }
    }

    private static final class PublicationScan {
        final boolean directoryHidden;
        final boolean configurationHidden;
        final boolean generationHidden;
        final boolean directoryStatDenied;
        final boolean directoryReadDenied;
        final boolean configurationStatDenied;
        final boolean configurationReadDenied;
        final boolean complete;
        final int pathsProbed;

        PublicationScan(boolean directoryHidden, boolean configurationHidden,
                boolean generationHidden, boolean directoryStatDenied,
                boolean directoryReadDenied, boolean configurationStatDenied,
                boolean configurationReadDenied, boolean complete, int pathsProbed) {
            this.directoryHidden = directoryHidden;
            this.configurationHidden = configurationHidden;
            this.generationHidden = generationHidden;
            this.directoryStatDenied = directoryStatDenied;
            this.directoryReadDenied = directoryReadDenied;
            this.configurationStatDenied = configurationStatDenied;
            this.configurationReadDenied = configurationReadDenied;
            this.complete = complete;
            this.pathsProbed = pathsProbed;
        }
    }

    private static final class MetadataScan {
        final boolean complete;
        final int keysScanned;

        MetadataScan(boolean complete, int keysScanned) {
            this.complete = complete;
            this.keysScanned = keysScanned;
        }

        static MetadataScan skipped() {
            return new MetadataScan(true, 0);
        }
    }

    private static final class SurfaceScan {
        final boolean complete;
        final boolean logcatComplete;
        final int commandsScanned;

        SurfaceScan(boolean complete, boolean logcatComplete, int commandsScanned) {
            this.complete = complete;
            this.logcatComplete = logcatComplete;
            this.commandsScanned = commandsScanned;
        }

        static SurfaceScan skipped() {
            return new SurfaceScan(true, true, 0);
        }
    }

    private static final class ProcScan {
        final boolean complete;
        final int surfacesScanned;

        ProcScan(boolean complete, int surfacesScanned) {
            this.complete = complete;
            this.surfacesScanned = surfacesScanned;
        }

        static ProcScan skipped() {
            return new ProcScan(true, 0);
        }
    }

    private static final class SuScan {
        final boolean ok;
        final boolean discoveryDenied;
        final boolean executionDenied;
        final boolean bounded;
        final boolean effectiveUidUnprivileged;
        final boolean rootShellObtained;
        final int pathsVisible;
        final int attempts;

        SuScan(boolean ok, boolean discoveryDenied, boolean executionDenied,
                boolean bounded, boolean effectiveUidUnprivileged,
                boolean rootShellObtained, int pathsVisible, int attempts) {
            this.ok = ok;
            this.discoveryDenied = discoveryDenied;
            this.executionDenied = executionDenied;
            this.bounded = bounded;
            this.effectiveUidUnprivileged = effectiveUidUnprivileged;
            this.rootShellObtained = rootShellObtained;
            this.pathsVisible = pathsVisible;
            this.attempts = attempts;
        }
    }
}
