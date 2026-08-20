package dev.xenoid.daemon;

import java.io.*;
import java.util.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

final class RootHelper {
    private static final int ROOTD_PORT = 18767;
    private static final int MAX_COMMAND_BYTES = 4096;
    private static final int MAX_RESPONSE_BYTES = 400 * 1024;
    private static final int MAX_OUTPUT_CHARS = 64 * 1024;
    private static final int MIN_TIMEOUT_MS = 100;
    private static final int MAX_TIMEOUT_MS = 230000;
    private static final ThreadLocal<ConnectionHandle> THREAD_CONNECTION = new ThreadLocal<>();
    private static char[] cachedRootdToken = new char[0];

    static final class ConnectionHandle implements AutoCloseable {
        private HttpURLConnection active;
        private boolean cancelled;
        private long deadlineElapsedMs = Long.MAX_VALUE;

        synchronized boolean attach(HttpURLConnection connection) {
            if (cancelled || active != null) return false;
            active = connection;
            return true;
        }

        synchronized void detach(HttpURLConnection connection) {
            if (active == connection) active = null;
        }

        synchronized boolean isCancelled() {
            return cancelled;
        }
        synchronized void setTimeoutCapMs(int timeoutCapMs) {
            long now = android.os.SystemClock.elapsedRealtime();
            long cap = Math.max(0L, Math.min((long) MAX_TIMEOUT_MS, (long) timeoutCapMs));
            long candidate = now > Long.MAX_VALUE - cap ? Long.MAX_VALUE : now + cap;
            deadlineElapsedMs = Math.min(deadlineElapsedMs, candidate);
        }

        synchronized int boundedTimeoutMs(int requestedTimeoutMs) {
            if (cancelled) return -1;
            long remaining = deadlineElapsedMs == Long.MAX_VALUE
                    ? MAX_TIMEOUT_MS
                    : deadlineElapsedMs - android.os.SystemClock.elapsedRealtime();
            if (remaining < MIN_TIMEOUT_MS) return 0;
            long requested = Math.max(
                    (long) MIN_TIMEOUT_MS,
                    Math.min((long) MAX_TIMEOUT_MS, (long) requestedTimeoutMs));
            return (int) Math.min(requested, remaining);
        }

        synchronized void cancel() {
            cancelled = true;
            if (active != null) active.disconnect();
        }

        @Override public synchronized void close() {
            if (active != null) {
                active.disconnect();
                active = null;
            }
        }
    }

    static final class ConnectionScope implements AutoCloseable {
        private final ConnectionHandle previous;
        private boolean closed;

        ConnectionScope(ConnectionHandle handle) {
            previous = THREAD_CONNECTION.get();
            THREAD_CONNECTION.set(handle);
        }

        @Override public void close() {
            if (closed) return;
            closed = true;
            if (previous == null) THREAD_CONNECTION.remove();
            else THREAD_CONNECTION.set(previous);
        }
    }

    static ConnectionHandle newConnectionHandle() {
        return new ConnectionHandle();
    }

    static ConnectionScope bindConnectionHandle(ConnectionHandle handle) {
        if (handle == null) throw new IllegalArgumentException("rootd_handle_required");
        return new ConnectionScope(handle);
    }

    static Map<String,Object> status() {
        return status(10000, THREAD_CONNECTION.get());
    }

    static Map<String,Object> status(int timeoutMs, ConnectionHandle handle) {
        Map<String,Object> out = execRootd(
                "id; getenforce 2>/dev/null || true", timeoutMs, handle);
        out.put("root", String.valueOf(out.get("stdout")).contains("uid=0"));
        return out;
    }

    static Map<String,Object> exec(String command) {
        return execRootd(command, 20000, THREAD_CONNECTION.get());
    }

    static Map<String,Object> exec(String command, int timeoutMs, ConnectionHandle handle) {
        return execRootd(command, timeoutMs, handle);
    }

    /** The service injects its app-private daemon token; it is never staged elsewhere. */
    static synchronized void setRootdToken(String token) {
        Arrays.fill(cachedRootdToken, '\0');
        cachedRootdToken = token != null && token.matches("[0-9a-f]{32}")
                ? token.toCharArray() : new char[0];
    }

    static synchronized String rootdToken() {
        return new String(cachedRootdToken);
    }

    static Map<String,Object> execRootd(String command) {
        return execRootd(command, 20000, THREAD_CONNECTION.get());
    }

    static boolean persistLocationState(File source, int appUid) {
        if (source == null || !source.getName().equals("location-identity.json")
                || source.getParentFile() == null || !source.getParentFile().getName().equals("no_backup")
                || appUid <= 0 || !source.isFile() || source.length() <= 0 || source.length() > 64 * 1024) {
            return false;
        }
        String command = "set -eu;s=" + shellQuote(source.getAbsolutePath())
                + ";d=/data/vendor/radio/xenoid;u=" + appUid + ";"
                + "[ -f $s ];[ ! -L $s ];[ $(stat -c %u $s) = $u ];"
                + "if [ -e $d ];then [ -d $d ];[ ! -L $d ];else mkdir -p $d;fi;"
                + "chown 1001:1001 $d;chmod 750 $d;umask 077;"
                + "rm -f $d/.location-state.v1.tmp;cp -- $s $d/.location-state.v1.tmp;"
                + "chown 0:1001 $d/.location-state.v1.tmp;chmod 640 $d/.location-state.v1.tmp;"
                + "sync -f $d/.location-state.v1.tmp;mv -f $d/.location-state.v1.tmp $d/location-state.v1;sync -f $d;"
                + "[ $(stat -c %u:%g:%a $d/location-state.v1) = 0:1001:640 ]";
        return Boolean.TRUE.equals(execRootd(command, 20000).get("ok"));
    }

    static boolean restoreLocationState(File destination, int appUid) {
        if (destination == null || !destination.getName().equals("location-identity.json")
                || destination.getParentFile() == null
                || !destination.getParentFile().getName().equals("no_backup") || appUid <= 0) {
            return false;
        }
        String command = "set -eu;s=/data/vendor/radio/xenoid/location-state.v1;d="
                + shellQuote(destination.getAbsolutePath()) + ";u=" + appUid + ";"
                + "[ -f $s ];[ ! -L $s ];n=$(stat -c %s $s);[ $n -gt 0 ];[ $n -le 65536 ];"
                + "p=${d%/*};[ -d $p ];[ ! -L $p ];rm -f $p/.location-identity.restore;"
                + "cp -- $s $p/.location-identity.restore;chown $u:$u $p/.location-identity.restore;"
                + "chmod 600 $p/.location-identity.restore;sync -f $p/.location-identity.restore;"
                + "mv -f $p/.location-identity.restore $d;sync -f $p;"
                + "[ $(stat -c %u:%g:%a:%s $d) = $u:$u:600:$n ]";
        return Boolean.TRUE.equals(execRootd(command, 20000).get("ok"));
    }

    static boolean publishLocationProfile(File source, String destination, long size, String sha256) {
        if (source == null || !source.getName().equals("location-profile.stage")
                || !source.getParentFile().getName().equals("no_backup")
                || !"/data/vendor/radio/xenoid/profile.v1".equals(destination)
                || size <= 0 || size > 64 * 1024
                || sha256 == null || !sha256.matches("[0-9a-f]{64}")) return false;
        String command = "set -eu;s=" + shellQuote(source.getAbsolutePath())
                + ";d=/data/vendor/radio/xenoid;n=" + size + ";h=" + sha256 + ";"
                + "[ -f $s ];[ ! -L $s ];[ $(stat -c %s $s) = $n ];"
                + "x=$(sha256sum $s);x=${x%% *};[ $x = $h ];"
                + "if [ -e $d ];then [ -d $d ];[ ! -L $d ];else mkdir -p $d;fi;"
                + "chown 1001:1001 $d;chmod 750 $d;umask 077;"
                + "rm -f $d/.profile.v1.tmp;cp -- $s $d/.profile.v1.tmp;"
                + "chown 1001:1001 $d/.profile.v1.tmp;chmod 640 $d/.profile.v1.tmp;"
                + "sync -f $d/.profile.v1.tmp;mv -f $d/.profile.v1.tmp $d/profile.v1;sync -f $d;"
                + "[ $(stat -c %u:%g:%a:%s $d/profile.v1) = 1001:1001:640:$n ];"
                + "x=$(sha256sum $d/profile.v1);x=${x%% *};[ $x = $h ]";
        return Boolean.TRUE.equals(execRootd(command, 20000).get("ok"));
    }

    static boolean publishDeviceProfile(File source, long size, String sha256) {
        int appUid = android.os.Process.myUid();
        if (source == null || !source.getName().equals("device-profile.stage")
                || source.getParentFile() == null
                || !source.getParentFile().getName().equals("no_backup")
                || appUid <= 0 || size <= 0 || size > 256 * 1024
                || sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
            return false;
        }
        String command = "set -eu;s=" + shellQuote(source.getAbsolutePath())
                + ";d=/data/local/tmp/xenoid-profile;u=" + appUid + ";n=" + size
                + ";h=" + sha256 + ";"
                + "[ -f $s ];[ ! -L $s ];[ $(stat -c %u $s) = $u ];[ $(stat -c %s $s) = $n ];"
                + "x=$(sha256sum $s);x=${x%% *};[ $x = $h ];"
                + "if [ -e $d ];then [ -d $d ];[ ! -L $d ];else mkdir -p $d;fi;"
                + "chown 0:0 $d;chmod 700 $d;umask 077;rm -f $d/.effective.json.tmp;"
                + "cp -- $s $d/.effective.json.tmp;chown 0:0 $d/.effective.json.tmp;"
                + "chmod 600 $d/.effective.json.tmp;sync -f $d/.effective.json.tmp;"
                + "mv -f $d/.effective.json.tmp $d/effective.json;sync -f $d;"
                + "[ $(stat -c %u:%g:%a:%s $d/effective.json) = 0:0:600:$n ];"
                + "x=$(sha256sum $d/effective.json);x=${x%% *};[ $x = $h ]";
        return Boolean.TRUE.equals(execRootd(command, 20000).get("ok"));
    }

    /** Removes the abandoned pre-location regional state copies owned by rootd. */
    static void purgeLegacyRegionalState() {
        execRootd("rm -f /data/vendor/radio/xenoid/state.v1", 20000);
    }

    private static Map<String,Object> execRootd(String command, int timeoutMs) {
        return execRootd(command, timeoutMs, THREAD_CONNECTION.get());
    }
    /** Authenticated POST /exec only: command and token never enter the request target. */

    private static Map<String,Object> execRootd(
            String command, int timeoutMs, ConnectionHandle suppliedHandle) {
        Map<String,Object> out = new LinkedHashMap<>();
        byte[] bodyBytes = command == null ? new byte[0]
                : command.getBytes(StandardCharsets.UTF_8);
        if (bodyBytes.length == 0 || bodyBytes.length > MAX_COMMAND_BYTES) {
            Arrays.fill(bodyBytes, (byte) 0);
            return rootdFailure("rootd_command_invalid");
        }
        ConnectionHandle handle = suppliedHandle;
        boolean ownsHandle = false;
        if (handle == null) {
            handle = newConnectionHandle();
            ownsHandle = true;
        }
        int boundedTimeout = handle.boundedTimeoutMs(timeoutMs);
        if (boundedTimeout < 0) {
            Arrays.fill(bodyBytes, (byte) 0);
            return rootdFailure("rootd_cancelled");
        }
        if (boundedTimeout == 0) {
            Arrays.fill(bodyBytes, (byte) 0);
            return rootdFailure("rootd_command_timeout");
        }
        HttpURLConnection connection = null;
        String requestId = UUID.randomUUID().toString().replace("-", "");
        try {
            URL endpoint = new URL("http://127.0.0.1:" + ROOTD_PORT + "/exec");
            connection = (HttpURLConnection) endpoint.openConnection();
            if (!handle.attach(connection)) return rootdFailure("rootd_cancelled");
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(Math.min(1000, boundedTimeout));
            connection.setReadTimeout(boundedTimeout);
            connection.setUseCaches(false);
            connection.setDoOutput(true);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            connection.setRequestProperty("X-Xenoid-Request-Id", requestId);
            connection.setRequestProperty(
                    "X-Xenoid-Timeout-Ms", Integer.toString(boundedTimeout));
            String token = rootdToken();
            if (!token.isEmpty()) {
                connection.setRequestProperty("X-Xenoid-Token", token);
            }
            connection.setFixedLengthStreamingMode(bodyBytes.length);
            try (OutputStream stream = connection.getOutputStream()) {
                stream.write(bodyBytes);
                stream.flush();
            }
            int statusCode = connection.getResponseCode();
            InputStream stream = statusCode >= 400
                    ? connection.getErrorStream() : connection.getInputStream();
            String response = stream == null ? "" : readLimited(stream, MAX_RESPONSE_BYTES);
            out.put("rootdReachable", true);
            out.put("httpStatus", statusCode);
            if (statusCode != 200) {
                String errorCode = safeRootdError(response,
                        statusCode == 401 ? "rootd_unauthorized" : "rootd_request_failed");
                out.put("ok", false);
                out.put("errorCode", errorCode);
                out.put("error", statusCode == 401 ? "unauthorized" : errorCode);
                return out;
            }
            JSONObject result = new JSONObject(response);
            if (!"dev.xenoid.rootd-exec/v1".equals(result.optString("schema", ""))
                    || !requestId.equals(result.optString("requestId", ""))
                    || !result.has("ok") || !result.has("exitCode")
                    || !result.has("stdout")) {
                return rootdFailure("rootd_protocol_error", true, statusCode);
            }
            String stdout = result.getString("stdout");
            if (stdout.length() > MAX_OUTPUT_CHARS) {
                return rootdFailure("rootd_protocol_error", true, statusCode);
            }
            int exitCode = result.getInt("exitCode");
            boolean ok = result.getBoolean("ok");
            String errorCode = result.optString("errorCode", "");
            if ((ok && (exitCode != 0 || !errorCode.isEmpty()))
                    || (!ok && !errorCode.matches("rootd_[a-z_]{3,48}"))) {
                return rootdFailure("rootd_protocol_error", true, statusCode);
            }
            out.put("ok", ok);
            out.put("exit", exitCode);
            out.put("stdout", stdout);
            if (!ok) {
                out.put("errorCode", errorCode);
                out.put("error", errorCode);
            }
        } catch (SocketTimeoutException timeout) {
            return rootdFailure("rootd_command_timeout");
        } catch (Exception failure) {
            return rootdFailure(handle.isCancelled()
                    ? "rootd_cancelled" : "rootd_unavailable");
        } finally {
            Arrays.fill(bodyBytes, (byte) 0);
            if (connection != null) {
                handle.detach(connection);
                connection.disconnect();
            }
            if (ownsHandle) handle.close();
        }
        return out;
    }

    private static Map<String,Object> rootdFailure(String errorCode) {
        return rootdFailure(errorCode, false, 0);
    }

    private static Map<String,Object> rootdFailure(
            String errorCode, boolean reachable, int httpStatus) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("ok", false);
        out.put("errorCode", errorCode);
        out.put("error", errorCode);
        if (reachable) {
            out.put("rootdReachable", true);
            out.put("httpStatus", httpStatus);
        }
        return out;
    }

    private static String safeRootdError(String response, String fallback) {
        try {
            String error = new JSONObject(response).optString("errorCode", "");
            return error.matches("rootd_[a-z_]{3,48}") ? error : fallback;
        } catch (Throwable ignored) {
            return fallback;
        }
    }


    private static String readKeyboxStagePath(File request) {
        try {
            byte[] bytes = new byte[256];
            int offset = 0;
            try (FileInputStream input = new FileInputStream(request)) {
                while (offset < bytes.length) {
                    int count = input.read(bytes, offset, bytes.length - offset);
                    if (count < 0) break;
                    if (count == 0) return null;
                    offset += count;
                }
                if (offset <= 0) return null;
                int next = input.read();
                if (next != -1) return null;
            }
            String text = new String(bytes, 0, offset, "UTF-8");
            String[] lines = text.split("\n", -1);
            if (lines.length != 4 || !lines[3].isEmpty()
                    || !lines[0].startsWith("/data/local/tmp/.keybox-upload-")) {
                return null;
            }
            String suffix = lines[0].substring("/data/local/tmp/.keybox-upload-".length());
            if (!suffix.matches("[0-9a-f]{32}")) return null;
            return lines[0];
        } catch (Throwable failure) {
            return null;
        }
    }

    static boolean copyKeyboxStage(
            File request, File destination, int appUid, String apkPath) {
        boolean valid = isKeyboxRequest(request) && isKeyboxDestination(destination)
                && request.getParentFile().equals(destination.getParentFile()) && appUid > 0;
        if (!valid) return false;
        if (readKeyboxStagePath(request) == null) return false;
        return "ok".equals(runKeyboxClient(apkPath, "stage"));
    }

    static void cleanupKeyboxStage(File request, int appUid, String apkPath) {
        if (!isKeyboxRequest(request) || !request.isFile() || appUid <= 0) return;
        runKeyboxClient(apkPath, "stage-cleanup");
    }

    static String runKeyboxClient(String apkPath, String operation) {
        if (apkPath == null
                || (!"apply".equals(operation) && !"clear".equals(operation)
                && !"stage".equals(operation) && !"stage-cleanup".equals(operation))) {
            return "control_unavailable";
        }
        File apk = new File(apkPath);
        try {
            if (!apk.isFile() || !apk.getCanonicalPath().equals(apk.getAbsolutePath())) {
                return "control_unavailable";
            }
        } catch (IOException ignored) {
            return "control_unavailable";
        }
        String command = "set -eu;a=" + apk.getAbsolutePath() + ";"
                + "[ -f $a ];[ ! -L $a ];[ $(readlink -f $a) = $a ];"
                + "x=$(cat /proc/$(pidof zygote64)/environ | sed s/\\\\0/@@/g);"
                + "b=${x#*BOOTCLASSPATH=};b=${b%%DEX2OATBOOTCLASSPATH=*};"
                + "d=${x#*DEX2OATBOOTCLASSPATH=};d=${d%%SYSTEMSERVERCLASSPATH=*};"
                + "[ ${#b} -gt 0 ];[ ${#d} -gt 0 ];"
                + "ANDROID_ROOT=/system ANDROID_DATA=/data "
                + "ANDROID_ART_ROOT=/apex/com.android.art "
                + "ANDROID_I18N_ROOT=/apex/com.android.i18n "
                + "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata "
                + "BOOTCLASSPATH=$b DEX2OATBOOTCLASSPATH=$d "
                + "CLASSPATH=$a /system/bin/xenoid-app-process / "
                + "--nice-name=xenoid-keymint-once dev.xenoid.daemon.TeesimControlClient "
                + operation + " 2>/dev/null";
        Map<String, Object> result = execRootd(
                command, "apply".equals(operation) ? 150000 : 60000);
        String output = String.valueOf(result.get("stdout"));
        if (output.contains("xenoid-keymint:ok")) return "ok";
        if (output.contains("xenoid-keymint:native_rejected")) return "native_rejected";
        if (output.contains("xenoid-keymint:key_migration_unavailable")) {
            return "key_migration_unavailable";
        }
        if (output.contains("xenoid-keymint:invalid_stage")) return "invalid_stage";
        return "control_unavailable";
    }


    private static boolean isKeyboxRequest(File request) {
        if (request == null || !".stage-request".equals(request.getName())) return false;
        File parent = request.getParentFile();
        File noBackup = parent == null ? null : parent.getParentFile();
        if (parent == null || noBackup == null || !"keybox".equals(parent.getName())
                || !"no_backup".equals(noBackup.getName())) {
            return false;
        }
        return "/data/user/0/dev.xenoid.daemon/no_backup/keybox/.stage-request"
                .equals(request.getAbsolutePath());
    }

    private static boolean isKeyboxDestination(File destination) {
        if (destination == null || !".candidate.xml".equals(destination.getName())) return false;
        File parent = destination.getParentFile();
        File noBackup = parent == null ? null : parent.getParentFile();
        if (parent == null || noBackup == null || !"keybox".equals(parent.getName())
                || !"no_backup".equals(noBackup.getName())) {
            return false;
        }
        return "/data/user/0/dev.xenoid.daemon/no_backup/keybox/.candidate.xml"
                .equals(destination.getAbsolutePath());
    }

    static boolean copyCameraStage(String stagingPath, File destination, long size, String sha256, int appUid) {
        if (!isCameraStage(stagingPath) || destination == null || size <= 0
                || sha256 == null || !sha256.matches("[0-9a-f]{64}") || appUid <= 0) return false;
        String command = "set -eu;p=" + shellQuote(stagingPath)
                + ";d=" + shellQuote(destination.getAbsolutePath())
                + ";n=" + shellQuote(Long.toString(size))
                + ";h=" + shellQuote(sha256)
                + ";u=" + shellQuote(Integer.toString(appUid))
                + ";trap 'r=$?;trap - EXIT;[ $r -eq 0 ]||rm -f \"$d\";exit $r' EXIT"
                + ";b=${p#/data/local/tmp/.camera-upload-};[ ${#b} -eq 32 ];case \"$b\" in *[!0-9a-f]*) exit 1;;esac;"
                + "[ -f \"$p\" ];[ ! -L \"$p\" ];[ \"$(readlink -f \"$p\")\" = \"$p\" ];"
                + "[ \"$(stat -c %u \"$p\")\" = 2000 ];[ \"$(stat -c %s \"$p\")\" = \"$n\" ];"
                + "x=$(sha256sum \"$p\");x=${x%% *};[ \"$x\" = \"$h\" ];"
                + "[ ! -e \"$d\" ];[ ! -L \"$d\" ];umask 077;cp -- \"$p\" \"$d\";"
                + "chown \"$u:$u\" \"$d\";chmod 600 \"$d\";sync -f \"$d\";"
                + "[ \"$(stat -c %s \"$d\")\" = \"$n\" ];x=$(sha256sum \"$d\");x=${x%% *};[ \"$x\" = \"$h\" ]";
        return rootdCameraOk(command);
    }

    static void cleanupCameraStage(String stagingPath) {
        if (isCameraStage(stagingPath)) {
            rootdCameraOk("rm -f -- " + shellQuote(stagingPath));
        }
    }

    static boolean publishCameraGeneration(
            File photo, File video, long generation, String mode, int appUid) {
        if (generation < 0 || appUid <= 0
                || (!"naturalized".equals(mode) && !"faithful".equals(mode))) return false;
        String photoPath = photo == null ? "" : photo.getAbsolutePath();
        String videoPath = video == null ? "" : video.getAbsolutePath();
        String command = "set -eu;d='/data/misc/camera/source';p=" + shellQuote(photoPath)
                + ";v=" + shellQuote(videoPath)
                + ";g=" + shellQuote(Long.toString(generation))
                + ";m=" + shellQuote(mode)
                + ";u=" + shellQuote(Integer.toString(appUid))
                + ";mkdir -p \"$d\";[ ! -L \"$d\" ];[ \"$(readlink -f \"$d\")\" = \"$d\" ];"
                + "chown 0:0 \"$d\";chmod 700 \"$d\";rm -f \"$d/.p\" \"$d/.v\" \"$d/.c\";"
                + "trap 'rm -f \"$d/.p\" \"$d/.v\" \"$d/.c\"' EXIT;"
                + "pn=;vn=;"
                + "if [ -n \"$p\" ];then [ -f \"$p\" ]&&[ ! -L \"$p\" ]&&[ \"$(readlink -f \"$p\")\" = \"$p\" ]"
                + "&&[ \"$(stat -c %u \"$p\")\" = \"$u\" ];cp -- \"$p\" \"$d/.p\";chown 0:0 \"$d/.p\";"
                + "chmod 600 \"$d/.p\";sync -f \"$d/.p\";pn=\"photo-$g.png\";mv -f \"$d/.p\" \"$d/$pn\";sync -f \"$d\";fi;"
                + "if [ -n \"$v\" ];then [ -f \"$v\" ]&&[ ! -L \"$v\" ]&&[ \"$(readlink -f \"$v\")\" = \"$v\" ]"
                + "&&[ \"$(stat -c %u \"$v\")\" = \"$u\" ];cp -- \"$v\" \"$d/.v\";chown 0:0 \"$d/.v\";"
                + "chmod 600 \"$d/.v\";sync -f \"$d/.v\";vn=\"video-$g.bin\";mv -f \"$d/.v\" \"$d/$vn\";sync -f \"$d\";fi;"
                + "printf 'version=1\\ngeneration=%s\\nmode=%s\\nphoto=%s\\nvideo=%s\\n' \"$g\" \"$m\" \"$pn\" \"$vn\" >\"$d/.c\";"
                + "chown 0:0 \"$d/.c\";chmod 600 \"$d/.c\";sync -f \"$d/.c\";mv -f \"$d/.c\" \"$d/current.conf\";sync -f \"$d\"";
        return rootdCameraOk(command);
    }

    static void cleanupCameraGeneration(long generation) {
        if (generation < 0) return;
        String g = Long.toString(generation);
        rootdCameraOk("set -eu;d='/data/misc/camera/source';[ ! -e \"$d\" ]&&exit 0;"
                + "[ -d \"$d\" ];[ ! -L \"$d\" ];rm -f -- \"$d/photo-" + g
                + ".png\" \"$d/video-" + g
                + ".bin\" \"$d/.p\" \"$d/.v\" \"$d/.c\";sync -f \"$d\"");
    }

    static boolean sweepCameraPublications(
            long generation, boolean retainPhoto, boolean retainVideo) {
        if (generation < -1L || ((retainPhoto || retainVideo) && generation < 0L)) return false;
        String photo = retainPhoto ? "photo-" + generation + ".png" : "";
        String video = retainVideo ? "video-" + generation + ".bin" : "";
        String command = "set -eu;d='/data/misc/camera/source';kp=" + shellQuote(photo)
                + ";kv=" + shellQuote(video)
                + ";[ ! -e \"$d\" ]&&exit 0;[ -d \"$d\" ];[ ! -L \"$d\" ];"
                + "for f in \"$d\"/photo-*.png;do [ -e \"$f\" ]||continue;"
                + "[ -n \"$kp\" ]&&[ \"$f\" = \"$d/$kp\" ]||rm -f -- \"$f\";done;"
                + "for f in \"$d\"/video-*.bin;do [ -e \"$f\" ]||continue;"
                + "[ -n \"$kv\" ]&&[ \"$f\" = \"$d/$kv\" ]||rm -f -- \"$f\";done;"
                + "rm -f -- \"$d/.p\" \"$d/.v\" \"$d/.c\";sync -f \"$d\"";
        return rootdCameraOk(command);
    }

    static boolean deactivateCameraPublication() {
        return rootdCameraOk(
                "set -eu;d='/data/misc/camera/source';[ ! -e \"$d\" ]&&exit 0;"
                        + "[ -d \"$d\" ];[ ! -L \"$d\" ];"
                        + "rm -f -- \"$d/current.conf\" \"$d/.p\" \"$d/.v\" \"$d/.c\";"
                        + "sync -f \"$d\"");
    }

    private static boolean rootdCameraOk(String command) {
        return Boolean.TRUE.equals(execRootd(command, 600000).get("ok"));
    }

    private static boolean isCameraStage(String path) {
        return path != null && path.matches("/data/local/tmp/\\.camera-upload-[0-9a-f]{32}");
    }
    static Map<String,Object> startFrida(int port) {
        return execRootd("pidof .fs64 >/dev/null 2>&1 || (test -x /data/system/.core/svc.bin && ln -sf /data/system/.core/svc.bin /data/local/tmp/.fs64 && /data/local/tmp/.fs64 -D -l 127.0.0.1:" + port + " </dev/null >/dev/null 2>&1); sleep 1; pidof .fs64 >/dev/null");
    }
    static Map<String,Object> stopFrida() { return execRootd("pkill frida-server 2>/dev/null || true; pkill svc.bin 2>/dev/null || true; pkill .fs64 2>/dev/null || true"); }
    static Map<String,Object> fridaStatus() { return execRootd("pidof .fs64 >/dev/null 2>&1 && ps -A | grep '[.]fs64'"); }
    private static Map<String,Object> inputNative(String arguments) {
        String injector = "/data/local/tmp/xenoid-input";
        Map<String,Object> result = execRootd(
                "test -x " + shellQuote(injector) + " && exec " + shellQuote(injector) + " " + arguments,
                20000);
        boolean ok = Boolean.TRUE.equals(result.get("ok"));
        result.put("driverLayer", ok);
        result.put("eventNode", "/dev/uinput");
        result.put("fallback", false);
        result.put("injector", injector);
        if (!ok) {
            result.put("error", "native uinput injection failed; framework input fallback is disabled");
        }
        return result;
    }

    static Map<String,Object> inputReload() {
        return inputNative("reload");
    }

    static Map<String,Object> inputTap(int x, int y) {
        return inputNative("tap " + x + " " + y);
    }

    static Map<String,Object> inputSwipe(int x1, int y1, int x2, int y2, int durationMs) {
        return inputNative("swipe " + x1 + " " + y1 + " " + x2 + " " + y2 + " " + durationMs);
    }
    static Map<String,Object> profileStatus() { return exec("test -x /data/local/tmp/xenoid-profile-helper && /data/local/tmp/xenoid-profile-helper status || echo profile-helper-missing"); }
    static Map<String,Object> profileEnv() { return exec("test -x /data/local/tmp/xenoid-profile-helper && /data/local/tmp/xenoid-profile-helper env || echo profile-helper-missing"); }
    static Map<String,Object> profileDump() { return exec("test -x /data/local/tmp/xenoid-profile-helper && /data/local/tmp/xenoid-profile-helper dump || cat /data/local/tmp/xenoid-profile/effective.json 2>/dev/null || true"); }
    static Map<String,Object> installApk(String path) { return exec("pm install -r " + shellQuote(path)); }
    static Map<String,Object> uninstallPackage(String pkg) { return exec("pm uninstall " + shellQuote(pkg)); }
    static Map<String,Object> launchComponent(String component) { return exec("am start -n " + shellQuote(component)); }
    static String shellQuote(String s) { return "'" + s.replace("'", "'\\''") + "'"; }

    private static String readLimited(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(limit, 8192));
        byte[] buffer = new byte[4096];
        try {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count == 0) continue;
                if (output.size() + count > limit) throw new IOException("bounded_response_exceeded");
                output.write(buffer, 0, count);
            }
            return output.toString("UTF-8");
        } finally {
            Arrays.fill(buffer, (byte) 0);
            input.close();
        }
    }
}
