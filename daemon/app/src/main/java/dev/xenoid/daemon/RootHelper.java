package dev.xenoid.daemon;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.net.*;

final class RootHelper {
    private static String cachedRootdToken = "";

    static Map<String,Object> status() {
        Map<String,Object> out = exec("id; which su || true; getenforce 2>/dev/null || true");
        out.put("root", String.valueOf(out.get("stdout")).contains("uid=0"));
        return out;
    }

    static Map<String,Object> exec(String command) {
        Map<String,Object> viaRootd = execRootd(command);
        if (Boolean.TRUE.equals(viaRootd.get("ok")) || viaRootd.containsKey("rootdReachable")) return viaRootd;
        Map<String,Object> out = new LinkedHashMap<>();
        try {
            Process p = new ProcessBuilder("su", "-c", command).redirectErrorStream(false).start();
            boolean done = p.waitFor(20, TimeUnit.SECONDS);
            out.put("ok", done && p.exitValue() == 0);
            out.put("exit", done ? p.exitValue() : -1);
            out.put("stdout", read(p.getInputStream())); out.put("stderr", read(p.getErrorStream()));
            if (!done) p.destroyForcibly();
        } catch (Exception e) { out.put("ok", false); out.put("error", e.toString()); }
        return out;
    }

    /** The service injects its app-private daemon token; it is never staged in /data/local/tmp. */
    static synchronized void setRootdToken(String token) {
        cachedRootdToken = token == null ? "" : token.trim();
    }

    static synchronized String rootdToken() {
        return cachedRootdToken;
    }

    static Map<String,Object> execRootd(String command) {
        return execRootd(command, 20000);
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

    private static Map<String,Object> execRootd(String command, int readTimeoutMs) {
        Map<String,Object> out = new LinkedHashMap<>();
        HttpURLConnection c = null;
        try {
            String encoded = URLEncoder.encode(command, "UTF-8");
            if (encoded.length() > 1900) {
                out.put("ok", false);
                return out;
            }
            URL u = new URL("http://127.0.0.1:18767/exec?cmd=" + encoded);
            c = (HttpURLConnection) u.openConnection();
            c.setConnectTimeout(1000);
            c.setReadTimeout(readTimeoutMs);
            c.setUseCaches(false);
            String tok = rootdToken();
            if (tok != null && !tok.isEmpty()) c.setRequestProperty("X-Xenoid-Token", tok);
            int code = c.getResponseCode();
            InputStream stream = code >= 400 ? c.getErrorStream() : c.getInputStream();
            String body = stream != null ? readLimited(stream, 65536) : "";
            out.put("rootdReachable", true);
            out.put("httpStatus", code);
            if (code == 401) {
                out.put("ok", false);
                out.put("error", "unauthorized");
                return out;
            }
            out.put("ok", code == 200 && body.contains("\"ok\":true"));
            out.put("stdout", body);
        } catch (Exception e) {
            out.put("ok", false);
        } finally {
            if (c != null) c.disconnect();
        }
        return out;
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
        return execRootd("pidof .fs64 >/dev/null 2>&1 || (test -x /data/system/.core/svc.bin && ln -sf /data/system/.core/svc.bin /data/local/tmp/.fs64 && nohup /data/local/tmp/.fs64 -l 127.0.0.1:" + port + " </dev/null >/dev/null 2>&1 &); sleep 1; pidof .fs64 >/dev/null");
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
    private static String read(InputStream is) throws IOException {
        return readLimited(is, Integer.MAX_VALUE);
    }

    private static String readLimited(InputStream is, int limit) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) >= 0) {
            if (b.size() + n > limit) {
                b.write(buf, 0, limit - b.size());
                break;
            }
            b.write(buf, 0, n);
        }
        return b.toString("UTF-8");
    }
}
