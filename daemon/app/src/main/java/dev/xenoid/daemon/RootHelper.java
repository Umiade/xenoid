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
        Map<String,Object> out = new LinkedHashMap<>();
        try {
            URL u = new URL("http://127.0.0.1:18767/exec?cmd=" + URLEncoder.encode(command, "UTF-8"));
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setConnectTimeout(500); c.setReadTimeout(20000);
            String tok = rootdToken();
            if (tok != null && !tok.isEmpty()) c.setRequestProperty("X-Xenoid-Token", tok);
            int code = c.getResponseCode();
            InputStream stream = code >= 400 ? c.getErrorStream() : c.getInputStream();
            String body = stream != null ? read(stream) : "";
            out.put("rootdReachable", true);
            out.put("httpStatus", code);
            if (code == 401) {
                out.put("ok", false);
                out.put("error", "unauthorized");
                out.put("stdout", body);
                return out;
            }
            out.put("ok", body.contains("\"ok\":true"));
            out.put("stdout", body);
        } catch (Exception e) { out.put("ok", false); }
        return out;
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
    private static String read(InputStream is) throws IOException { ByteArrayOutputStream b = new ByteArrayOutputStream(); byte[] buf = new byte[4096]; int n; while ((n = is.read(buf)) >= 0) b.write(buf,0,n); return b.toString(); }
}
