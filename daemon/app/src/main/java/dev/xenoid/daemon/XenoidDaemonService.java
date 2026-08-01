package dev.xenoid.daemon;

import android.app.*;
import android.content.*;
import android.os.*;
import org.json.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class XenoidDaemonService extends Service {
    private volatile ExecutorService pool;
    private volatile ServerSocket server;
    private volatile CameraMediaManager cameraMediaManager;
    public IBinder onBind(Intent intent) { return null; }
    public int onStartCommand(Intent intent, int flags, int startId) { enterForeground(); startServer(); return START_STICKY; }
    public void onDestroy() {
        ServerSocket listener = server;
        try { if (listener != null) listener.close(); } catch(Exception ignored) {}
        ExecutorService workers = pool;
        if (workers != null) workers.shutdownNow();
    }
    private void enterForeground() {
        String channelId = "xenoid-control";
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(channelId, "Xenoid control service", NotificationManager.IMPORTANCE_MIN));
        Intent settingsIntent = new Intent(this, MainActivity.class)
                .setAction("dev.xenoid.daemon.action.OPEN_CAMERA_SETTINGS")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent settingsPendingIntent = PendingIntent.getActivity(
                this, 18766, settingsIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new Notification.Builder(this, channelId)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("Xenoid runtime")
                .setContentText("Local control service active")
                .setContentIntent(settingsPendingIntent)
                .setOngoing(true)
                .build();
        startForeground(18765, notification);
    }
    private synchronized void startServer() {
        if (pool != null) return;
        ExecutorService workers = Executors.newFixedThreadPool(16);
        pool = workers;
        workers.submit(() -> initializeServer(workers));
    }

    private void initializeServer(ExecutorService workers) {
        ServerSocket listener = null;
        try {
            String controlToken = getToken();
            RootHelper.setRootdToken(controlToken);
            listener = new ServerSocket(18765, 50, InetAddress.getByName("0.0.0.0"));
            server = listener;
            final ServerSocket activeListener = listener;
            workers.submit(() -> acceptClients(activeListener, workers));
            try {
                cameraMediaManager = CameraMediaManager.get(this);
            } catch (Throwable ignored) {
                android.util.Log.e("xenoid-daemon", "camera manager initialization failed");
            }
        } catch(Exception e) {
            try { if (listener != null) listener.close(); } catch (Exception ignored) { }
            android.util.Log.e("xenoid-daemon", "bind failed", e);
        }
    }

    private void acceptClients(ServerSocket listener, ExecutorService workers) {
        android.util.Log.i("xenoid-daemon", "listening on 18765");
        try {
            while (!listener.isClosed()) {
                Socket client = listener.accept();
                try {
                    workers.submit(new Client(client));
                } catch (RejectedExecutionException e) {
                    try { client.close(); } catch (Exception ignored) { }
                    break;
                }
            }
        } catch (Exception e) {
            if (!listener.isClosed()) {
                android.util.Log.e("xenoid-daemon", "accept failed", e);
            }
        }
    }
    // Shared-secret token for the daemon control channel. Generated once into the
    // app's private dir (only the daemon and root can read it; other apps cannot).
    // The host CLI reads it via the root channel and sends it as X-Xenoid-Token.
    private String token;
    private synchronized String getToken() {
        if (token == null) {
            try {
                File f = new File(getFilesDir(), "daemon.token");
                if (f.exists()) {
                    token = new String(java.nio.file.Files.readAllBytes(f.toPath()), "UTF-8").trim();
                } else {
                    token = UUID.randomUUID().toString().replace("-", "");
                    java.nio.file.Files.write(f.toPath(), token.getBytes("UTF-8"));
                    f.setReadable(false, false); f.setReadable(true, true);
                }
            } catch (Exception e) { token = UUID.randomUUID().toString().replace("-", ""); }
        }
        return token;
    }
    private boolean authorized(String tokenHeader, String path) {
        // /health stays public (liveness probe); every other endpoint needs the token.
        if ("/health".equals(path)) return true;
        String t = getToken();
        return tokenHeader != null && tokenHeader.equals(t);
    }
    final class Client implements Runnable { final Socket s; Client(Socket s){this.s=s;} public void run(){ try { handle(s); } catch(Exception ignored) { } finally { try{s.close();}catch(Exception ignored){} } } }
    private void handle(Socket sock) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        String request = br.readLine(); if (request == null) return; String[] parts = request.split(" "); String method = parts[0], path = parts[1];
        int len = 0; String line; String tokenHeader = null; while((line = br.readLine()) != null && line.length() > 0) { String l=line.toLowerCase(Locale.ROOT); if(l.startsWith("content-length:")) len = Integer.parseInt(line.substring(15).trim()); else if(l.startsWith("x-xenoid-token:")) tokenHeader = line.substring(15).trim(); }
        Map<String,Object> resp;
        boolean isAuthorized = authorized(tokenHeader, path);
        if (!isAuthorized) {
            resp = map("ok", false, "error", "unauthorized");
        } else if (path.startsWith("/camera/") && (len < 0 || len > 2048)) {
            resp = map("ok", false, "error", "invalid request body");
        } else {
            char[] bodyChars = new char[len]; int off=0; while(off<len){ int n=br.read(bodyChars, off, len-off); if(n<0) break; off+=n; } String body = new String(bodyChars,0,off);
            resp = route(method, path, body);
        }
        byte[] bytes = Json.stringify(resp).getBytes(); OutputStream os = sock.getOutputStream();
        String status = isAuthorized ? "200 OK" : "401 Unauthorized";
        os.write(("HTTP/1.1 "+status+"\r\nContent-Type: application/json\r\nContent-Length: "+bytes.length+"\r\nConnection: close\r\n\r\n").getBytes()); os.write(bytes); os.flush();
    }
    private Map<String,Object> route(String method, String path, String body) {
        try {
            if (path.equals("/health")) {
                if (cameraMediaManager == null) {
                    return map("ok", false, "service", "xenoid-daemon",
                            "version", "0.1.0", "error", "service not ready");
                }
                return map("ok", true, "service", "xenoid-daemon", "version", "0.1.0");
            }
            if (path.startsWith("/camera/")) return routeCamera(method, path, body);
            if (path.equals("/root/status")) return RootHelper.status();
            if (path.equals("/root/exec")) return RootHelper.exec(SimpleJson.stringValue(body, "command", "id"));
            if (path.equals("/profile/helper/status")) return RootHelper.profileStatus();
            if (path.equals("/profile/helper/env")) return RootHelper.profileEnv();
            if (path.equals("/profile/helper/dump")) return RootHelper.profileDump();
            if (path.equals("/fingerprint/collect")) { Map<String,Object> m = FingerprintCollector.collect(this); m.put("ok", true); return m; }
            if (path.equals("/fingerprint/apply")) return DeviceProfileManager.apply(body, SimpleJson.boolValue(body, "regenerateUnique", true));
            if (path.equals("/fingerprint/set")) return DeviceProfileManager.setField(SimpleJson.stringValue(body, "field", "raw"), SimpleJson.stringValue(body, "value", body));
            if (path.equals("/automation/run")) return AutomationEngine.run(this, SimpleJson.stringValue(body, "name", "task"), body);
            if (path.equals("/frida/start")) return RootHelper.startFrida(SimpleJson.intValue(body, "port", 27042));
            if (path.equals("/frida/stop")) return RootHelper.stopFrida();
            if (path.equals("/frida/status")) return RootHelper.fridaStatus();
            if (path.equals("/input/tap")) return RootHelper.inputTap(SimpleJson.intValue(body, "x", 0), SimpleJson.intValue(body, "y", 0));
            if (path.equals("/input/swipe")) return RootHelper.inputSwipe(SimpleJson.intValue(body, "x1", 0), SimpleJson.intValue(body, "y1", 0), SimpleJson.intValue(body, "x2", 0), SimpleJson.intValue(body, "y2", 0), SimpleJson.intValue(body, "durationMs", 300));
            if (path.equals("/app/install")) return RootHelper.installApk(SimpleJson.stringValue(body, "path", ""));
            if (path.equals("/app/uninstall")) return RootHelper.uninstallPackage(SimpleJson.stringValue(body, "package", ""));
            if (path.equals("/app/launch")) return RootHelper.launchComponent(SimpleJson.stringValue(body, "component", ""));
            if (path.equals("/hide/status")) return HideManager.status();
            if (path.equals("/hide/apply")) return HideManager.apply(body);
            if (path.equals("/ota/check")) return OtaManager.check();
            if (path.equals("/ota/apply")) return OtaManager.apply(SimpleJson.stringValue(body, "channel", "stable"));
            return map("ok", false, "error", "not found", "path", path);
        } catch(Exception e) { return map("ok", false, "error", e.toString()); }
    }
    private Map<String,Object> routeCamera(String method, String path, String body) {
        try {
            CameraMediaManager manager = cameraMediaManager;
            if (manager == null) {
                if ("/camera/status".equals(path)) {
                    requireCameraMethod(method, "GET");
                    requireEmptyCameraBody(body);
                    return CameraMediaManager.notReadyStatus();
                }
                if ("/camera/source".equals(path)) {
                    requireCameraMethod(method, "POST");
                    JSONObject object = cameraObject(
                            body, "kind", "stagingPath", "size", "sha256");
                    cameraString(object, "kind", 5);
                    cameraLong(object, "size");
                    cameraString(object, "sha256", 64);
                    RootHelper.cleanupCameraStage(
                            cameraString(object, "stagingPath", 128));
                    return CameraMediaManager.notReadyStatus();
                }
                if ("/camera/settings".equals(path)) {
                    requireCameraMethod(method, "POST");
                    JSONObject object = cameraObject(body, "mode");
                    cameraString(object, "mode", 11);
                    return CameraMediaManager.notReadyStatus();
                }
                if ("/camera/clear".equals(path)) {
                    requireCameraMethod(method, "POST");
                    JSONObject object = cameraObject(body, "kind");
                    cameraString(object, "kind", 5);
                    return CameraMediaManager.notReadyStatus();
                }
                if ("/camera/apply".equals(path)) {
                    requireCameraMethod(method, "POST");
                    cameraObject(body);
                    return CameraMediaManager.notReadyStatus();
                }
            }
            if ("/camera/status".equals(path)) {
                requireCameraMethod(method, "GET");
                requireEmptyCameraBody(body);
                return manager.status();
            }
            if ("/camera/source".equals(path)) {
                requireCameraMethod(method, "POST");
                JSONObject object = cameraObject(body, "kind", "stagingPath", "size", "sha256");
                String kind = cameraString(object, "kind", 5);
                String stagingPath = cameraString(object, "stagingPath", 128);
                long size = cameraLong(object, "size");
                String sha256 = cameraString(object, "sha256", 64);
                return manager.importStaged(kind, stagingPath, size, sha256);
            }
            if ("/camera/settings".equals(path)) {
                requireCameraMethod(method, "POST");
                JSONObject object = cameraObject(body, "mode");
                return manager.setMode(cameraString(object, "mode", 11));
            }
            if ("/camera/clear".equals(path)) {
                requireCameraMethod(method, "POST");
                JSONObject object = cameraObject(body, "kind");
                return manager.clear(cameraString(object, "kind", 5));
            }
            if ("/camera/apply".equals(path)) {
                requireCameraMethod(method, "POST");
                cameraObject(body);
                return manager.apply();
            }
            if ("/camera/self-test/start".equals(path)) {
                requireCameraMethod(method, "POST");
                JSONObject object = cameraObject(body, "runId");
                return CameraSelfTest.authorize(
                        this, cameraString(object, "runId", 32));
            }
            if ("/camera/self-test/status".equals(path)) {
                requireCameraMethod(method, "GET");
                requireEmptyCameraBody(body);
                return CameraSelfTest.status(this);
            }
            return map("ok", false, "error", "not found");
        } catch (CameraRequestFailure e) {
            return map("ok", false, "error", e.safeMessage);
        } catch (Throwable ignored) {
            return map("ok", false, "error", "camera request failed");
        }
    }

    private static void requireCameraMethod(String actual, String expected)
            throws CameraRequestFailure {
        if (!expected.equals(actual)) throw new CameraRequestFailure("method not allowed");
    }

    private static void requireEmptyCameraBody(String body) throws CameraRequestFailure {
        if (body != null && !body.trim().isEmpty()) {
            throw new CameraRequestFailure("invalid request body");
        }
    }

    private static JSONObject cameraObject(String body, String... fields)
            throws CameraRequestFailure {
        if (body == null || body.length() == 0 || body.length() > 2048) {
            throw new CameraRequestFailure("invalid request body");
        }
        if (!new StrictCameraObjectParser(body).parse()) {
            throw new CameraRequestFailure("invalid request body");
        }
        try {
            JSONTokener tokener = new JSONTokener(body);
            Object parsed = tokener.nextValue();
            if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) {
                throw new CameraRequestFailure("invalid request body");
            }
            JSONObject object = (JSONObject) parsed;
            Set<String> expected = new HashSet<>(Arrays.asList(fields));
            if (object.length() != expected.size()) {
                throw new CameraRequestFailure("invalid request schema");
            }
            Iterator<String> keys = object.keys();
            while (keys.hasNext()) {
                if (!expected.contains(keys.next())) {
                    throw new CameraRequestFailure("invalid request schema");
                }
            }
            return object;
        } catch (CameraRequestFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new CameraRequestFailure("invalid request body");
        }
    }

    private static String cameraString(JSONObject object, String key, int maximum)
            throws CameraRequestFailure {
        try {
            Object value = object.get(key);
            if (!(value instanceof String)) throw new CameraRequestFailure("invalid request schema");
            String string = (String) value;
            if (string.length() == 0 || string.length() > maximum) {
                throw new CameraRequestFailure("invalid request schema");
            }
            return string;
        } catch (CameraRequestFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new CameraRequestFailure("invalid request schema");
        }
    }

    private static long cameraLong(JSONObject object, String key) throws CameraRequestFailure {
        try {
            Object value = object.get(key);
            if (!(value instanceof Byte) && !(value instanceof Short)
                    && !(value instanceof Integer) && !(value instanceof Long)) {
                throw new CameraRequestFailure("invalid request schema");
            }
            return ((Number) value).longValue();
        } catch (CameraRequestFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new CameraRequestFailure("invalid request schema");
        }
    }

    private static final class StrictCameraObjectParser {
        private final String text;
        private final Set<String> keys = new HashSet<>();
        private int index;

        StrictCameraObjectParser(String text) {
            this.text = text;
        }

        boolean parse() {
            skipWhitespace();
            if (!take('{')) return false;
            skipWhitespace();
            if (take('}')) {
                skipWhitespace();
                return index == text.length();
            }
            while (true) {
                String key = parseString(true);
                if (key == null || !keys.add(key)) return false;
                skipWhitespace();
                if (!take(':')) return false;
                skipWhitespace();
                if (peek('\"')) {
                    if (parseString(false) == null) return false;
                } else if (!parseInteger()) {
                    return false;
                }
                skipWhitespace();
                if (take('}')) {
                    skipWhitespace();
                    return index == text.length();
                }
                if (!take(',')) return false;
                skipWhitespace();
            }
        }

        private String parseString(boolean key) {
            if (!take('\"')) return null;
            StringBuilder value = key ? new StringBuilder() : null;
            while (index < text.length()) {
                char c = text.charAt(index++);
                if (c == '\"') return key ? value.toString() : "";
                if (c < 0x20) return null;
                if (c == '\\') {
                    if (key || index >= text.length()) return null;
                    char escaped = text.charAt(index++);
                    if (escaped == 'u') {
                        for (int i = 0; i < 4; i++) {
                            if (index >= text.length() || Character.digit(text.charAt(index++), 16) < 0) {
                                return null;
                            }
                        }
                    } else if ("\"\\/bfnrt".indexOf(escaped) < 0) {
                        return null;
                    }
                } else if (key) {
                    value.append(c);
                }
            }
            return null;
        }

        private boolean parseInteger() {
            int start = index;
            if (peek('-')) index++;
            if (index >= text.length()) {
                index = start;
                return false;
            }
            if (text.charAt(index) == '0') {
                index++;
                if (index < text.length() && Character.isDigit(text.charAt(index))) {
                    index = start;
                    return false;
                }
                return true;
            }
            if (text.charAt(index) < '1' || text.charAt(index) > '9') {
                index = start;
                return false;
            }
            while (index < text.length() && Character.isDigit(text.charAt(index))) index++;
            return true;
        }

        private boolean peek(char wanted) {
            return index < text.length() && text.charAt(index) == wanted;
        }

        private boolean take(char wanted) {
            if (!peek(wanted)) return false;
            index++;
            return true;
        }

        private void skipWhitespace() {
            while (index < text.length()) {
                char c = text.charAt(index);
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return;
                index++;
            }
        }
    }

    private static final class CameraRequestFailure extends Exception {
        final String safeMessage;
        CameraRequestFailure(String safeMessage) {
            this.safeMessage = safeMessage;
        }
    }

    static Map<String,Object> map(Object... kv) { Map<String,Object> m = new LinkedHashMap<>(); for(int i=0;i+1<kv.length;i+=2)m.put(String.valueOf(kv[i]),kv[i+1]); return m; }
}
