package dev.xenoid.daemon;

import android.app.*;
import android.content.*;
import android.os.*;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class XenoidDaemonService extends Service {
    private static final int MAX_HEADER_LINE_BYTES = 8192;
    private static final int MAX_HEADER_BYTES = 32768;
    private static final int MAX_DEFAULT_BODY_BYTES = 2 * 1024 * 1024;
    private static final int MAX_AGENT_BODY_BYTES = 96 * 1024;
    private static final int HEADER_READ_TIMEOUT_MS = 5000;
    private static final int SOURCE_READ_TIMEOUT_MS = 15000;
    private volatile ExecutorService pool;
    private volatile ServerSocket server;
    private volatile CameraMediaManager cameraMediaManager;
    private volatile ProxyManager proxyManager;
    private volatile ProxyAgentChannel proxyAgentChannel;
    private volatile LocationIdentityManager locationIdentityManager;
    private volatile KeyboxManager keyboxManager;
    public IBinder onBind(Intent intent) { return null; }
    public int onStartCommand(Intent intent, int flags, int startId) { enterForeground(); startServer(); return START_STICKY; }
    public void onDestroy() {
        ServerSocket listener = server;
        try { if (listener != null) listener.close(); } catch(Exception ignored) {}
        ProxyAgentChannel channel = proxyAgentChannel;
        if (channel != null) channel.close();
        ProxyManager manager = proxyManager;
        if (manager != null) manager.close();
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
            try {
                keyboxManager = new KeyboxManager(this);
            } catch (Throwable failure) {
                android.util.Log.e(
                        "xenoid-daemon", "keybox manager initialization failed", failure);
            }
            try {
                ProxyManager manager = new ProxyManager(this);
                ProxyAgentChannel channel = new ProxyAgentChannel(manager);
                proxyManager = manager;
                proxyAgentChannel = channel;
            } catch (Throwable ignored) {
                android.util.Log.e("xenoid-daemon", "proxy control initialization failed");
            }
            try {
                LocationIdentityManager location = new LocationIdentityManager(this);
                locationIdentityManager = location;
                try {
                    location.restoreDataPlane();
                } catch (Throwable ignored) {
                    android.util.Log.e("xenoid-daemon", "location data-plane restoration failed");
                }
            } catch (Throwable ignored) {
                android.util.Log.e("xenoid-daemon", "location identity initialization failed");
            }
            try {
                cameraMediaManager = CameraMediaManager.get(this);
            } catch (Throwable ignored) {
                android.util.Log.e("xenoid-daemon", "camera manager initialization failed");
            }
            listener = new ServerSocket(18765, 50, InetAddress.getByName("0.0.0.0"));
            server = listener;
            LocationIdentityManager location = locationIdentityManager;
            if (location != null) {
                workers.submit(() -> {
                    try {
                        Thread.sleep(2000);
                        location.restoreDataPlane();
                    } catch (Throwable ignored) {
                        android.util.Log.e("xenoid-daemon", "delayed location data-plane restoration failed");
                    }
                });
            }
            final ServerSocket activeListener = listener;
            workers.submit(() -> acceptClients(activeListener, workers));
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
                    client.setSoTimeout(HEADER_READ_TIMEOUT_MS);
                    workers.submit(new Client(client));
                } catch (RejectedExecutionException e) {
                    try { client.close(); } catch (Exception ignored) { }
                    break;
                } catch (SocketException ignored) {
                    try { client.close(); } catch (Exception closeIgnored) { }
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
        // /health is public; /proxy/agent has its separate process-scoped credential.
        if ("/health".equals(path)) return true;
        if (tokenHeader == null) return false;
        byte[] supplied = tokenHeader.getBytes(StandardCharsets.UTF_8);
        byte[] expected = getToken().getBytes(StandardCharsets.UTF_8);
        try {
            return MessageDigest.isEqual(supplied, expected);
        } finally {
            Arrays.fill(supplied, (byte) 0);
            Arrays.fill(expected, (byte) 0);
        }
    }
    final class Client implements Runnable {
        final Socket socket;
        Client(Socket socket) { this.socket = socket; }
        public void run() {
            try {
                handle(socket);
            } catch (Exception ignored) {
            } finally {
                try { socket.close(); } catch (Exception ignored) { }
            }
        }
    }

    private void handle(Socket socket) throws Exception {
        OutputStream output = socket.getOutputStream();
        try {
            InputStream input = new BufferedInputStream(socket.getInputStream());
            long headerDeadline = SystemClock.elapsedRealtime() + HEADER_READ_TIMEOUT_MS;
            applyReadDeadline(socket, headerDeadline);
            String requestLine = readHttpLine(input, 4096);
            if (requestLine == null) return;
            String[] requestParts = requestLine.split(" ", -1);
            if (requestParts.length != 3
                    || requestParts[0].isEmpty() || requestParts[0].length() > 8
                    || !requestParts[0].matches("[A-Z]+")
                    || requestParts[1].isEmpty() || requestParts[1].length() > 256
                    || requestParts[1].charAt(0) != '/'
                    || requestParts[1].indexOf('?') >= 0 || requestParts[1].indexOf('#') >= 0
                    || (!"HTTP/1.1".equals(requestParts[2])
                    && !"HTTP/1.0".equals(requestParts[2]))) {
                throw new HttpFailure();
            }
            String method = requestParts[0];
            String path = requestParts[1];
            int contentLength = 0;
            boolean sawContentLength = false;
            String tokenHeader = null;
            String agentTokenHeader = null;
            int headerBytes = 0;
            for (int count = 0; count < 64; count++) {
                applyReadDeadline(socket, headerDeadline);
                String line = readHttpLine(input, MAX_HEADER_LINE_BYTES);
                if (line == null) throw new HttpFailure();
                headerBytes += line.length() + 2;
                if (headerBytes > MAX_HEADER_BYTES) throw new HttpFailure();
                if (line.isEmpty()) break;
                int separator = line.indexOf(':');
                if (separator <= 0) throw new HttpFailure();
                String name = line.substring(0, separator).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(separator + 1).trim();
                if ("content-length".equals(name)) {
                    if (sawContentLength) throw new HttpFailure();
                    sawContentLength = true;
                    contentLength = parseContentLength(value);
                } else if ("x-xenoid-token".equals(name)) {
                    if (tokenHeader != null || value.length() > 256) throw new HttpFailure();
                    tokenHeader = value;
                } else if ("x-xenoid-agent-token".equals(name)) {
                    if (agentTokenHeader != null || value.length() > 128) throw new HttpFailure();
                    agentTokenHeader = value;
                } else if ("transfer-encoding".equals(name)) {
                    throw new HttpFailure();
                }
                if (count == 63) throw new HttpFailure();
            }

            boolean agentRequest = "/proxy/agent".equals(path);
            ProxyAgentChannel activeChannel = proxyAgentChannel;
            boolean isAuthorized = agentRequest
                    ? tokenHeader == null && activeChannel != null
                    && activeChannel.authorizedAgentToken(agentTokenHeader)
                    : authorized(tokenHeader, path);
            if (!isAuthorized) {
                writeResponse(output, 401, map(
                        "ok", false,
                        "error", agentRequest ? "agent_rejected" : "unauthorized"));
                return;
            }
            int maximumBody = bodyLimit(method, path);
            if (contentLength < 0 || contentLength > maximumBody) {
                writeResponse(output, 400, map("ok", false, "error", "invalid_request_body"));
                return;
            }
            long bodyDeadline = SystemClock.elapsedRealtime()
                    + ("/proxy/source".equals(path)
                    ? SOURCE_READ_TIMEOUT_MS : HEADER_READ_TIMEOUT_MS);
            byte[] bodyBytes = new byte[contentLength];
            int offset = 0;
            while (offset < contentLength) {
                applyReadDeadline(socket, bodyDeadline);
                int read = input.read(bodyBytes, offset, contentLength - offset);
                if (read < 0) {
                    Arrays.fill(bodyBytes, (byte) 0);
                    throw new HttpFailure();
                }
                offset += read;
            }
            String body;
            try {
                body = decodeUtf8(bodyBytes);
            } finally {
                Arrays.fill(bodyBytes, (byte) 0);
            }
            writeResponse(output, 200, route(method, path, body));
        } catch (HttpFailure | SocketTimeoutException ignored) {
            writeResponse(output, 400, map("ok", false, "error", "invalid_request"));
        }
    }

    private static void applyReadDeadline(Socket socket, long deadline)
            throws SocketException, SocketTimeoutException {
        long remaining = deadline - SystemClock.elapsedRealtime();
        if (remaining <= 0) throw new SocketTimeoutException();
        socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, remaining));
    }

    private static int bodyLimit(String method, String path) {
        if ("/health".equals(path)) return "GET".equals(method) ? 0 : 0;
        if ("/proxy/source".equals(path)) {
            return "POST".equals(method) ? ProxyManager.MAX_REQUEST_BODY_BYTES : 0;
        }
        if ("/proxy/agent".equals(path)) {
            return "POST".equals(method) ? MAX_AGENT_BODY_BYTES : 0;
        }
        if (path.startsWith("/proxy/")) {
            if (("/proxy/status".equals(path) || "/proxy/export".equals(path))
                    && "GET".equals(method)) return 0;
            return "POST".equals(method) ? 4096 : 0;
        }
        if (path.startsWith("/location/")) {
            if ("/location/status".equals(path) && "GET".equals(method)) return 0;
            return "POST".equals(method) ? 128 * 1024 : 0;
        }
        if (path.startsWith("/keybox/")) return KeyboxManager.MAX_REQUEST_BODY_BYTES;
        if (path.startsWith("/camera/")) return 2048;
        return MAX_DEFAULT_BODY_BYTES;
    }

    private static int parseContentLength(String value) throws HttpFailure {
        if (value.isEmpty() || value.length() > 10) throw new HttpFailure();
        long result = 0;
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item < '0' || item > '9') throw new HttpFailure();
            result = result * 10 + item - '0';
            if (result > Integer.MAX_VALUE) throw new HttpFailure();
        }
        return (int) result;
    }

    private static String readHttpLine(InputStream input, int maximum) throws IOException, HttpFailure {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(maximum, 256));
        while (bytes.size() <= maximum) {
            int value = input.read();
            if (value < 0) {
                if (bytes.size() == 0) return null;
                throw new HttpFailure();
            }
            if (value == '\n') {
                byte[] line = bytes.toByteArray();
                int length = line.length;
                if (length > 0 && line[length - 1] == '\r') length--;
                for (int index = 0; index < length; index++) {
                    if ((line[index] & 0x80) != 0 || line[index] == 0) throw new HttpFailure();
                }
                return new String(line, 0, length, StandardCharsets.US_ASCII);
            }
            bytes.write(value);
        }
        throw new HttpFailure();
    }

    private static String decodeUtf8(byte[] value) throws HttpFailure {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (Exception ignored) {
            throw new HttpFailure();
        }
    }

    private static void writeResponse(OutputStream output, int status, Map<String, Object> response)
            throws IOException {
        byte[] bytes = new JSONObject(response).toString().getBytes(StandardCharsets.UTF_8);
        try {
            String label = status == 200 ? "200 OK"
                    : status == 401 ? "401 Unauthorized" : "400 Bad Request";
            output.write(("HTTP/1.1 " + label
                    + "\r\nContent-Type: application/json\r\nContent-Length: " + bytes.length
                    + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            output.write(bytes);
            output.flush();
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static final class HttpFailure extends Exception { }
    private Map<String,Object> route(String method, String path, String body) {
        try {
            if (path.equals("/health")) {
                if (!"GET".equals(method) || (body != null && !body.isEmpty())) {
                    return map("ok", false, "error", "invalid_request");
                }
                KeyboxManager keybox = keyboxManager;
                if (cameraMediaManager == null || proxyManager == null
                        || proxyAgentChannel == null || locationIdentityManager == null
                        || keybox == null || !keybox.healthReady()) {
                    return map("ok", false, "service", "xenoid-daemon",
                            "version", "0.1.0", "error", "service not ready");
                }
                return map("ok", true, "service", "xenoid-daemon", "version", "0.1.0");
            }
            if (path.startsWith("/proxy/")) return routeProxy(method, path, body);
            if (path.startsWith("/location/")) return routeLocation(method, path, body);
            if (path.startsWith("/camera/")) return routeCamera(method, path, body);
            if (path.startsWith("/keybox/")) return routeKeybox(method, path, body);
            if (path.equals("/root/status")) return RootHelper.status();
            if (path.equals("/root/exec")) return RootHelper.exec(SimpleJson.stringValue(body, "command", "id"));
            if (path.equals("/profile/helper/status")) return RootHelper.profileStatus();
            if (path.equals("/profile/helper/env")) return RootHelper.profileEnv();
            if (path.equals("/profile/helper/dump")) return RootHelper.profileDump();
            if (path.equals("/fingerprint/collect")) { Map<String,Object> m = FingerprintCollector.collect(this); m.put("ok", true); return m; }
            if (path.equals("/fingerprint/apply")) return DeviceProfileManager.apply(this, body, SimpleJson.boolValue(body, "regenerateUnique", true));
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

    private Map<String, Object> routeKeybox(String method, String path, String body) {
        boolean sourceHandled = false;
        try {
            if ("/keybox/status".equals(path)) {
                requireKeyboxMethod(method, "GET");
                requireEmptyKeyboxBody(body);
                KeyboxManager manager = keyboxManager;
                return manager == null
                        ? keyboxError("native_unavailable") : manager.status();
            }
            if ("/keybox/source".equals(path)) {
                requireKeyboxMethod(method, "POST");
                JSONObject object = cameraObject(body, "stagingPath", "size", "sha256");
                String stagingPath = cameraString(object, "stagingPath", 128);
                long size = cameraLong(object, "size");
                String sha256 = cameraString(object, "sha256", 64);
                KeyboxManager manager = keyboxManager;
                if (manager == null) return keyboxError("native_unavailable");
                sourceHandled = true;
                return manager.importStaged(stagingPath, size, sha256);
            }
            if ("/keybox/clear".equals(path)) {
                requireKeyboxMethod(method, "POST");
                cameraObject(body);
                KeyboxManager manager = keyboxManager;
                return manager == null
                        ? keyboxError("native_unavailable") : manager.clear();
            }
            return keyboxError("invalid_request");
        } catch (CameraRequestFailure ignored) {
            return keyboxError("invalid_request");
        } catch (KeyboxMethodFailure failure) {
            return keyboxError(failure.code);
        } catch (Throwable ignored) {
            return keyboxError("native_unavailable");
        } finally {
            if ("/keybox/source".equals(path) && !sourceHandled) {
                cleanupKeyboxStageFromBody(body);
            }
        }
    }

    private Map<String, Object> keyboxError(String error) {
        KeyboxManager manager = keyboxManager;
        Map<String, Object> response = manager == null
                ? map("ok", false, "configured", false, "ready", false, "active", false,
                        "algorithms", map("rsa", false, "ecdsa", false,
                                "rsaChainCount", 0, "ecdsaChainCount", 0))
                : manager.status();
        response.put("ok", false);
        response.put("error", error);
        return response;
    }

    private static void requireKeyboxMethod(String actual, String expected)
            throws KeyboxMethodFailure {
        if (!expected.equals(actual)) throw new KeyboxMethodFailure("method_not_allowed");
    }

    private static void requireEmptyKeyboxBody(String body) throws CameraRequestFailure {
        if (body != null && !body.trim().isEmpty()) {
            throw new CameraRequestFailure("invalid_request");
        }
    }
    private void cleanupKeyboxStageFromBody(String body) {
        KeyboxManager manager = keyboxManager;
        if (manager == null || body == null || body.length() == 0
                || body.length() > KeyboxManager.MAX_REQUEST_BODY_BYTES) return;
        try {
            JSONTokener tokener = new JSONTokener(body);
            Object parsed = tokener.nextValue();
            if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) return;
            Object value = ((JSONObject) parsed).opt("stagingPath");
            if (value instanceof String) manager.cleanupStaged((String) value);
        } catch (Throwable ignored) { }
    }


    private Map<String, Object> routeLocation(String method, String path, String body) throws Exception {
        LocationIdentityManager manager = locationIdentityManager;
        if (manager == null) throw new IllegalStateException("location_unavailable");
        if ("/location/status".equals(path)) {
            requireProxyMethod(method, "GET");
            ProxyManager.requireEmptyBody(body);
            return manager.status();
        }
        if ("/location/stage".equals(path)) {
            requireProxyMethod(method, "POST");
            return manager.stage(ProxyManager.parseObject(body, 128 * 1024));
        }
        if ("/location/verify".equals(path)) {
            requireProxyMethod(method, "POST");
            return manager.verify(ProxyManager.parseObject(body, 4096));
        }
        return map("ok", false, "error", "not_found");
    }

    private Map<String, Object> routeProxy(String method, String path, String body) {
        try {
            if ("/proxy/status".equals(path)) {
                requireProxyMethod(method, "GET");
                ProxyManager.requireEmptyBody(body);
                return requireProxyManager().status();
            }
            if ("/proxy/source".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request =
                        ProxyManager.parseObject(body, ProxyManager.MAX_REQUEST_BODY_BYTES);
                return requireProxyManager().setSource(request);
            }
            if ("/proxy/enabled".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request = ProxyManager.parseObject(body, 4096);
                return requireProxyManager().setEnabled(request);
            }
            if ("/proxy/select".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request = ProxyManager.parseObject(body, 4096);
                return requireProxyManager().select(request);
            }
            if ("/proxy/clear".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request = ProxyManager.parseObject(body, 4096);
                return requireProxyManager().clear(request);
            }
            if ("/proxy/check".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request = ProxyManager.parseObject(body, 4096);
                return requireProxyManager().check(request);
            }
            if ("/proxy/export".equals(path)) {
                requireProxyMethod(method, "GET");
                ProxyManager.requireEmptyBody(body);
                return requireProxyManager().exportDesired();
            }
            if ("/proxy/agent-bootstrap".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request = ProxyManager.parseObject(body, 4096);
                ProxyAgentChannel channel = proxyAgentChannel;
                if (channel == null || proxyManager == null) {
                    throw new ProxyManager.ProxyException("proxy_unavailable");
                }
                return channel.bootstrap(request);
            }
            if ("/proxy/agent".equals(path)) {
                requireProxyMethod(method, "POST");
                Map<String, Object> request =
                        ProxyManager.parseObject(body, MAX_AGENT_BODY_BYTES);
                ProxyAgentChannel channel = proxyAgentChannel;
                if (channel == null || proxyManager == null) {
                    throw new ProxyManager.ProxyException("proxy_unavailable");
                }
                return channel.handle(request);
            }
            return map("ok", false, "error", "not_found");
        } catch (ProxyManager.ProxyException failure) {
            return map("ok", false, "error", failure.code);
        } catch (ProxyAgentChannel.AgentRejected ignored) {
            return map("ok", false, "error", "agent_rejected");
        } catch (Throwable failure) {
            android.util.Log.e("xenoid-daemon", "proxy route failed", failure);
            return map("ok", false, "error", "proxy_request_failed");
        }
    }

    private ProxyManager requireProxyManager() throws ProxyManager.ProxyException {
        ProxyManager manager = proxyManager;
        if (manager == null || proxyAgentChannel == null) {
            throw new ProxyManager.ProxyException("proxy_unavailable");
        }
        return manager;
    }

    private static void requireProxyMethod(String actual, String expected)
            throws ProxyManager.ProxyException {
        if (!expected.equals(actual)) {
            throw new ProxyManager.ProxyException("method_not_allowed");
        }
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

    private static final class KeyboxMethodFailure extends Exception {
        final String code;
        KeyboxMethodFailure(String code) { this.code = code; }
    }

    static Map<String,Object> map(Object... kv) { Map<String,Object> m = new LinkedHashMap<>(); for(int i=0;i+1<kv.length;i+=2)m.put(String.valueOf(kv[i]),kv[i+1]); return m; }
}
