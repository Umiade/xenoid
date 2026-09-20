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

    /** Exact effective base APK of the pinned microG GmsCore release asset. */
    private static final String GMSCORE_FACTORY_PATH =
            "/system/product/priv-app/GmsCore/GmsCore.apk";
    private static final String GMSCORE_FACTORY_SHA256 =
            "52597e77fd25fdd347574d0457ed1936a4b9561cf4c8d34e7ac8dd8191dfd4b9";

    /**
     * Fail-closed shell predicate proving the installed GMS surface is exactly the
     * shipped pinned microG build: the package resolves to the single factory
     * GmsCore APK, it was never updated onto /data/app, and the immutable factory
     * APK matches the pinned release SHA-256.  Real Google GMS or MindTheGapps
     * installs fail this check.
     */
    private static String pinnedSurfacePredicate() {
        // Distinct pa/ha names: this fragment is also inlined into the seed
        // command, whose loops reuse single-letter variables.
        return "pa=$(pm path com.google.android.gms 2>/dev/null);"
                + "[ \"$pa\" = 'package:" + GMSCORE_FACTORY_PATH + "' ];"
                + "! dumpsys package com.google.android.gms 2>/dev/null"
                + " | grep -q UPDATED_SYSTEM_APP;"
                + "pa=" + GMSCORE_FACTORY_PATH + ";"
                + "[ -f $pa ];[ ! -L $pa ];[ \"$(stat -c %h $pa)\" = 1 ];"
                + "ha=$(sha256sum $pa);ha=${ha%% *};"
                + "[ \"$ha\" = " + GMSCORE_FACTORY_SHA256 + " ];";
    }

    /**
     * True when the rootd failure is a transport/protocol problem rather than a
     * predicate rejection.  A shell predicate that ran and failed exits nonzero,
     * which rootd reports as rootd_command_failed; everything else means the
     * command never ran to a verdict.
     */
    private static boolean rootdTransportFailure(Map<String,Object> ran) {
        return !"rootd_command_failed".equals(String.valueOf(ran.get("errorCode")));
    }

    /**
     * Reports whether the installed GMS surface is exactly the shipped, pinned
     * microG build.  Mutation paths must refuse to run when this is not pinned.
     */
    static Map<String,Object> googleProviderSurface() {
        Map<String,Object> ran = execRootd(
                "set -eu;" + pinnedSurfacePredicate(), 60000);
        Map<String,Object> out = new LinkedHashMap<>();
        if (Boolean.TRUE.equals(ran.get("ok"))) {
            out.put("ok", true);
            out.put("pinned", true);
            return out;
        }
        out.put("ok", false);
        if (rootdTransportFailure(ran)) {
            out.put("error", "google_identity_unavailable");
        } else {
            out.put("pinned", false);
            out.put("error", "google_identity_provider_unsupported");
        }
        return out;
    }

    /**
     * Fail-closed read of the offline-seeded marker: the profile directory must be
     * a real root-owned 0700 directory and the gsf_android_id marker a real,
     * root-owned 0600, single-link, non-symlink file holding a valid nonzero GSF
     * ID.  Every anomaly reports "invalid" — never a silent "absent" — so a
     * tampered or drifted marker fails closed instead of disabling the seeded
     * guarantees.
     */
    static Map<String,Object> offlineGoogleIdentitySeeded() {
        String command = "x=/data/local/tmp/xenoid-profile;f=$x/gsf_android_id;"
                + "if [ -L $x ];then echo invalid;exit 0;fi;"
                + "if [ ! -e $x ];then echo absent;exit 0;fi;"
                + "if [ ! -d $x ]||[ \"$(readlink -f $x)\" != $x ]"
                + "||[ \"$(stat -c %u:%g:%a $x)\" != 0:0:700 ];then echo invalid;exit 0;fi;"
                + "if [ -L $f ];then echo invalid;exit 0;fi;"
                + "if [ ! -e $f ];then echo absent;exit 0;fi;"
                + "if [ ! -f $f ]||[ \"$(stat -c %h $f)\" != 1 ]"
                + "||[ \"$(stat -c %u:%g:%a $f)\" != 0:0:600 ];then echo invalid;exit 0;fi;"
                + "v=$(cat $f);"
                + "if [ \"$(printf '%s' \"$v\" | grep -Ec '^[1-9][0-9]{0,18}$')\" != 1 ];"
                + "then echo invalid;exit 0;fi;"
                + "echo present;printf '%s\\n' \"$v\"";
        Map<String,Object> ran = execRootd(command, 20000);
        Map<String,Object> out = new LinkedHashMap<>();
        if (Boolean.TRUE.equals(ran.get("ok"))) {
            String[] lines = String.valueOf(ran.get("stdout")).split("\n", -1);
            if ("absent".equals(lines[0])) {
                out.put("ok", true);
                out.put("seeded", false);
                return out;
            }
            if (lines.length >= 2 && "present".equals(lines[0])
                    && lines[1].matches("[1-9][0-9]{0,18}")) {
                try {
                    if (Long.parseLong(lines[1]) <= 0) throw new NumberFormatException();
                } catch (NumberFormatException invalid) {
                    out.put("ok", false);
                    out.put("error", "google_identity_seed_state_invalid");
                    return out;
                }
                out.put("ok", true);
                out.put("seeded", true);
                out.put("gsfAndroidId", lines[1]);
                return out;
            }
            out.put("ok", false);
            out.put("error", "google_identity_seed_state_invalid");
            return out;
        }
        out.put("ok", false);
        out.put("error", rootdTransportFailure(ran)
                ? "google_identity_unavailable" : "google_identity_seed_state_invalid");
        return out;
    }

    /**
     * Seeds the exact GSF Android ID offline (check-in stays disabled) and writes
     * the protected marker.  Every relevant path is validated fail-closed BEFORE
     * the force-stop and re-validated after it, so an unsafe surface causes zero
     * mutations; gservices.db and its SQLite sidecars must be regular, singly
     * linked, correctly owned files and are never followed through a symlink.
     * SharedPreferences .bak copies are removed only after the replacement main
     * XML is fsynced into place, and the shared_prefs directory is fsynced before
     * microG is allowed to start again.
     */
    static Map<String,Object> seedGoogleIdentity(String gsfAndroidId) {
        if (gsfAndroidId == null || !gsfAndroidId.matches("[1-9][0-9]{0,18}")) {
            return rootdFailure("google_identity_target_invalid");
        }
        try {
            if (Long.parseLong(gsfAndroidId) <= 0) {
                return rootdFailure("google_identity_target_invalid");
            }
        } catch (NumberFormatException invalid) {
            return rootdFailure("google_identity_target_invalid");
        }
        // Compact canonical SharedPreferences XML keeps the authenticated rootd
        // command below its 4096-byte body ceiling without weakening the seed.
        String checkin = "<?xml version='1.0' encoding='utf-8'?><map>"
                + "<long name=\"androidId\" value=\"" + gsfAndroidId + "\" />"
                + "<string name=\"digest\">1-929a0dca0eee55513280171a8585da7dcd3700f8</string>"
                + "<long name=\"lastCheckin\" value=\"0\" />"
                + "<long name=\"securityToken\" value=\"0\" />"
                + "<string name=\"versionInfo\"></string>"
                + "<string name=\"deviceDataVersionInfo\"></string></map>";
        String sql = "BEGIN IMMEDIATE;"
                + "CREATE TABLE IF NOT EXISTS main (name TEXT PRIMARY KEY, value TEXT);"
                + "CREATE TABLE IF NOT EXISTS overrides (name TEXT PRIMARY KEY, value TEXT);"
                + "CREATE TABLE IF NOT EXISTS saved_system (name TEXT PRIMARY KEY, value TEXT);"
                + "CREATE TABLE IF NOT EXISTS saved_secure (name TEXT PRIMARY KEY, value TEXT);"
                + "PRAGMA user_version=3;"
                + "DELETE FROM overrides WHERE name='android_id';"
                + "INSERT OR REPLACE INTO main(name,value) VALUES('android_id','"
                + gsfAndroidId + "');COMMIT;PRAGMA wal_checkpoint(TRUNCATE);";
        String command = "set -eu;umask 077;"
                + "p=/data/user/0/com.google.android.gms;"
                + "d=$p/databases;s=$p/shared_prefs;"
                + "q=$s/com.google.android.gms_preferences.xml;qb=$q.bak;"
                + "c=$s/checkin.xml;cb=$c.bak;"
                + "b=$d/gservices.db;"
                + "x=/data/local/tmp/xenoid-profile;m=$x/gsf_android_id;t=$m.tmp;"
                + "qt=$s/.q.x;ct=$s/.c.x;"
                + "[ -d $p ];[ ! -L $p ];[ \"$(readlink -f $p)\" = $p ];"
                + "u=$(stat -c %u $p);g=$(stat -c %g $p);"
                + "case $u:$g in ''|*[!0-9:]*) exit 1;;esac;"
                + "[ $u -gt 0 ];"
                + "vdir(){ [ -d \"$1\" ]&&[ ! -L \"$1\" ]"
                + "&&[ \"$(readlink -f \"$1\")\" = \"$1\" ];};"
                + "vown(){ o=$(stat -c %u:%g \"$1\");"
                + "[ \"$o\" = \"$u:$g\" ]||[ \"$o\" = 0:0 ];};"
                + "vfile(){ [ ! -L \"$1\" ]&&[ -f \"$1\" ]"
                + "&&[ \"$(stat -c %h \"$1\")\" = 1 ]&&vown \"$1\";};"
                + "precheck(){ vdir $p;[ \"$(stat -c %u:%g $p)\" = \"$u:$g\" ];"
                + "vdir $x;[ \"$(stat -c %u:%g:%a $x)\" = 0:0:700 ];"
                + "for z in $d $s;do if [ -e $z ]||[ -L $z ];then vdir $z;vown $z;fi;done;"
                + "for f in $b $b-journal $b-wal $b-shm $q $qb $c $cb $qt $ct;do"
                + " if [ -L $f ];then exit 1;fi;"
                + " if [ -e $f ];then vfile $f;fi;"
                + "done;"
                + "for f in $m $t;do [ ! -L $f ];if [ -e $f ];then [ -f $f ];"
                + "[ \"$(stat -c %h:%u:%g:%a $f)\" = 1:0:0:600 ];fi;done;};"
                + pinnedSurfacePredicate()
                + "precheck;"
                + "am force-stop com.google.android.gms;"
                + "precheck;"
                + "for z in $d $s;do"
                + " if [ -e $z ]||[ -L $z ];then vdir $z;vown $z;else mkdir -p $z;fi;"
                + " chown $u:$g $z;chmod 700 $z;"
                + " restorecon $z >/dev/null 2>&1 || true;"
                + "done;"
                + "put(){ a=$1;n=$2;k=$3;chown $u:$g $a;chmod 660 $a;"
                + "restorecon $a >/dev/null 2>&1 || true;sync -f $a;"
                + "cp -p $a $k;restorecon $k >/dev/null 2>&1 || true;sync -f $k;"
                + "mv -f $k $n.bak;sync -f $s;mv -f $a $n;sync -f $n;sync -f $s;"
                + "rm -f $n.bak;sync -f $s;};"
                + "r=$q;[ ! -f $qb ]||r=$qb;rm -f $qt;"
                + "if [ -f $r ];then"
                + " awk 'index($0,\"checkin_enable_service\")==0 {"
                + " if (index($0,\"</map>\"))"
                + " print \"    <boolean name=\\\"checkin_enable_service\\\""
                + " value=\\\"false\\\" />\";print}' $r >$qt;"
                + "else printf '%s\\n'"
                + " '<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>'"
                + " '<map>'"
                + " '    <boolean name=\"checkin_enable_service\" value=\"false\" />'"
                + " '</map>' >$qt;fi;"
                + "[ \"$(grep -c 'name=\"checkin_enable_service\" value=\"false\"' $qt)\" = 1 ];"
                + "put $qt $q $ct;"
                + "rm -f $ct;printf %s " + shellQuote(checkin) + " >$ct;"
                + "put $ct $c $qt;"
                + "export ANDROID_DATA=/data ANDROID_ROOT=/system"
                + " ANDROID_TZDATA_ROOT=/apex/com.android.tzdata"
                + " ANDROID_I18N_ROOT=/apex/com.android.i18n;"
                + "/system/bin/sqlite3 $b 'PRAGMA wal_checkpoint(TRUNCATE);PRAGMA user_version;' >/dev/null;"
                + "rm -f $b-journal $b-wal $b-shm;"
                + "/system/bin/sqlite3 $b " + shellQuote(sql) + ";"
                + "rm -f $b-journal $b-wal $b-shm;"
                + "v=$(/system/bin/sqlite3 $b"
                + " \"SELECT value FROM main WHERE name='android_id';\");"
                + "[ \"$v\" = " + shellQuote(gsfAndroidId) + " ];"
                + "rm -f $b-journal $b-wal $b-shm;"
                + "chown $u:$g $b;chmod 660 $b;"
                + "restorecon $b >/dev/null 2>&1 || true;"
                + "sync -f $b;sync -f $d;"
                + "rm -f $t;"
                + "printf '%s\\n' " + shellQuote(gsfAndroidId) + " >$t;"
                + "chown 0:0 $t;chmod 600 $t;sync -f $t;"
                + "mv -f $t $m;sync -f $x;"
                + "[ \"$(stat -c %h:%u:%g:%a $m)\" = 1:0:0:600 ];"
                + "[ \"$(cat $m)\" = " + shellQuote(gsfAndroidId) + " ]";
        return execRootd(command, 20000);
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
