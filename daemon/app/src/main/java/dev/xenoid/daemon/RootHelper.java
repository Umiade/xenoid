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
    static Map<String,Object> inputTap(int x, int y) {
        String injector = "/data/local/tmp/xenoid-input";
        Map<String,Object> nativeTry = exec("test -x " + injector + " && " + injector + " htap " + x + " " + y);
        nativeTry.put("driverLayer", true);
        nativeTry.put("injector", injector);
        if (Boolean.TRUE.equals(nativeTry.get("ok"))) return nativeTry;
        Map<String,Object> fallback = exec("input tap " + x + " " + y);
        fallback.put("driverLayer", false);
        fallback.put("fallback", "android input command; deploy xenoid-input native helper for /dev/uinput injection");
        fallback.put("nativeAttempt", nativeTry);
        return fallback;
    }
    static Map<String,Object> inputSwipe(int x1, int y1, int x2, int y2, int durationMs) {
        String injector = "/data/local/tmp/xenoid-input";
        Map<String,Object> nativeTry = exec("test -x " + injector + " && " + injector + " hswipe " + x1 + " " + y1 + " " + x2 + " " + y2 + " " + durationMs);
        nativeTry.put("driverLayer", true);
        nativeTry.put("injector", injector);
        if (Boolean.TRUE.equals(nativeTry.get("ok"))) return nativeTry;
        Map<String,Object> fallback = exec("input swipe " + x1 + " " + y1 + " " + x2 + " " + y2 + " " + durationMs);
        fallback.put("driverLayer", false);
        fallback.put("fallback", "android input command; deploy xenoid-input native helper for /dev/uinput injection");
        fallback.put("nativeAttempt", nativeTry);
        return fallback;
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
