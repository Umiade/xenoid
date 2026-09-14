package dev.xenoid.daemon;

import android.app.*;
import android.content.*;
import android.os.*;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
    private volatile Thread acceptThread;
    private volatile Thread initializerThread;
    private volatile ServerSocket server;
    private volatile CameraMediaManager cameraMediaManager;
    private volatile ProxyManager proxyManager;
    private volatile ProxyAgentChannel proxyAgentChannel;
    private volatile LocationIdentityManager locationIdentityManager;
    private volatile KeyboxManager keyboxManager;
    private volatile BootstrapCoordinator bootstrapCoordinator;
    private final Set<Client> clients =
            Collections.newSetFromMap(new ConcurrentHashMap<Client, Boolean>());
    public IBinder onBind(Intent intent) { return null; }
    public int onStartCommand(Intent intent, int flags, int startId) { enterForeground(); startServer(); return START_STICKY; }
    {
        // Display resolution is runtime state lost on every container restart;
        // replay this instance's own effective profile so it self-heals even
        // when the host skips identity convergence for an already-converged
        // instance. The root helper may not be up yet at early boot, so apply
        // on a background thread and retry a few times before giving up.
        Thread reapply = new Thread(() -> {
            for (int attempt = 0; attempt < 30; attempt++) {
                try {
                    Map<String, Object> result = DeviceProfileManager.reapplyDisplayFromEffectiveProfile();
                    boolean skipped = result != null && result.get("skipped") != null;
                    if (result != null && Boolean.TRUE.equals(result.get("ok")) && !skipped) {
                        android.util.Log.i("XenoidDisplay", "display reapplied on attempt " + attempt);
                        return;
                    }
                    if (skipped) {
                        // No effective profile yet: host will apply identity; stop retrying.
                        return;
                    }
                    // rootd not reachable yet (it is started by the host's up path); keep retrying.
                } catch (Throwable ignored) {
                }
                try { Thread.sleep(3000L); } catch (InterruptedException interrupted) { return; }
            }
            android.util.Log.w("XenoidDisplay", "display reapply gave up: rootd unavailable");
        }, "xenoid-display-reapply");
        reapply.setDaemon(true);
        reapply.start();
    }
    public void onDestroy() {
        ServerSocket listener = server;
        try { if (listener != null) listener.close(); } catch(Exception ignored) {}
        BootstrapCoordinator coordinator = bootstrapCoordinator;
        if (coordinator != null) coordinator.close();
        ProxyAgentChannel channel = proxyAgentChannel;
        if (channel != null) channel.close();
        ProxyManager manager = proxyManager;
        if (manager != null) manager.close();
        for (Client client : clients) client.close();
        ExecutorService workers = pool;
        if (workers != null) {
            for (Runnable abandoned : workers.shutdownNow()) {
                if (abandoned instanceof Client) ((Client) abandoned).close();
            }
        }
        for (Client client : clients) client.close();
        Thread acceptor = acceptThread;
        if (acceptor != null) acceptor.interrupt();
        Thread initializer = initializerThread;
        if (initializer != null) initializer.interrupt();
        super.onDestroy();
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
        ExecutorService workers = new ThreadPoolExecutor(
                16, 16, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(32),
                runnable -> {
                    Thread thread = new Thread(runnable, "xenoid-http");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        pool = workers;
        Thread initializer = new Thread(
                () -> initializeServer(workers), "xenoid-http-initialize");
        initializer.setDaemon(true);
        initializerThread = initializer;
        initializer.start();
    }

    private void initializeServer(ExecutorService workers) {
        ServerSocket listener = null;
        BootstrapCoordinator coordinator = null;
        try {
            String controlToken = loadOrCreateTokenStrict();
            token = controlToken;
            RootHelper.setRootdToken(controlToken);
            coordinator = new BootstrapCoordinator(this);
            bootstrapCoordinator = coordinator;

            listener = new ServerSocket(18765, 50, InetAddress.getByName("127.0.0.1"));
            if (workers.isShutdown() || Thread.currentThread().isInterrupted()) {
                listener.close();
                return;
            }
            server = listener;
            final ServerSocket activeListener = listener;
            Thread acceptor = new Thread(
                    () -> acceptClients(activeListener, workers), "xenoid-http-accept");
            acceptor.setDaemon(true);
            acceptThread = acceptor;
            acceptor.start();

            String keyboxError = null;
            try {
                keyboxManager = new KeyboxManager(this);
            } catch (Throwable ignored) {
                keyboxError = "keybox_unavailable";
                android.util.Log.e("xenoid-daemon", "keybox manager initialization failed");
            }

            String proxyError = null;
            ProxyManager candidateProxy = null;
            try {
                candidateProxy = new ProxyManager(this);
                proxyManager = candidateProxy;
                proxyError = candidateProxy.initializationErrorCode();
            } catch (Throwable ignored) {
                proxyError = "proxy_state_invalid";
                android.util.Log.e("xenoid-daemon", "proxy state facade initialization failed");
            }
            if (candidateProxy != null) {
                try {
                    proxyAgentChannel = new ProxyAgentChannel(candidateProxy);
                } catch (Throwable ignored) {
                    if (proxyError == null) proxyError = "proxy_unavailable";
                    android.util.Log.e("xenoid-daemon", "proxy agent channel initialization failed");
                }
            }

            String locationError = null;
            try {
                locationIdentityManager = new LocationIdentityManager(this);
            } catch (Throwable ignored) {
                locationError = "location_unavailable";
                android.util.Log.e("xenoid-daemon", "location identity initialization failed");
            }

            String cameraError = null;
            try {
                cameraMediaManager = CameraMediaManager.get(this);
            } catch (Throwable ignored) {
                cameraError = "camera_unavailable";
                android.util.Log.e("xenoid-daemon", "camera manager initialization failed");
            }
            coordinator.installComponents(
                    keyboxManager, keyboxError,
                    proxyAgentChannel == null ? null : proxyManager, proxyError,
                    locationIdentityManager, locationError,
                    cameraMediaManager, cameraError);
        } catch(Exception ignored) {
            try { if (listener != null) listener.close(); } catch (Exception closeIgnored) { }
            if (coordinator != null) coordinator.close();
            android.util.Log.e("xenoid-daemon", "control listener initialization failed");
        }
    }

    private void acceptClients(ServerSocket listener, ExecutorService workers) {
        android.util.Log.i("xenoid-daemon", "listening on 18765");
        try {
            while (!listener.isClosed()) {
                Socket client = listener.accept();
                try {
                    client.setSoTimeout(HEADER_READ_TIMEOUT_MS);
                    Client request = new Client(client);
                    clients.add(request);
                    try {
                        workers.execute(request);
                    } catch (RejectedExecutionException rejected) {
                        clients.remove(request);
                        request.close();
                    }
                } catch (SocketException ignored) {
                    try { client.close(); } catch (Exception closeIgnored) { }
                }
            }
        } catch (Exception ignored) {
            if (!listener.isClosed()) {
                android.util.Log.e("xenoid-daemon", "control listener accept failed");
            }
        }
    }
    // The only durable control credential is this app-private, strictly validated file.
    private String token;

    private synchronized String loadOrCreateTokenStrict() throws Exception {
        File file = new File(getFilesDir(), "daemon.token");
        try {
            return readStrictToken(file);
        } catch (android.system.ErrnoException missing) {
            if (missing.errno != OsConstants.ENOENT) throw missing;
        } catch (InvalidToken invalid) {
            Os.remove(file.getAbsolutePath());
            syncDirectory(file.getParentFile());
        }

        byte[] random = new byte[16];
        byte[] encoded = new byte[32];
        new SecureRandom().nextBytes(random);
        final byte[] digits = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        for (int index = 0; index < random.length; index++) {
            int value = random[index] & 0xff;
            encoded[index * 2] = digits[value >>> 4];
            encoded[index * 2 + 1] = digits[value & 0x0f];
        }
        File temporary = new File(file.getParentFile(),
                ".daemon.token." + UUID.randomUUID() + ".tmp");
        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(temporary.getAbsolutePath(), OsConstants.O_WRONLY
                    | OsConstants.O_CREAT | OsConstants.O_EXCL | OsConstants.O_NOFOLLOW, 0600);
            Os.fchmod(descriptor, 0600);
            try (FileOutputStream output = new FileOutputStream(descriptor)) {
                descriptor = null;
                output.write(encoded);
                output.flush();
                output.getFD().sync();
            }
            Os.rename(temporary.getAbsolutePath(), file.getAbsolutePath());
            syncDirectory(file.getParentFile());
            return readStrictToken(file);
        } finally {
            Arrays.fill(random, (byte) 0);
            Arrays.fill(encoded, (byte) 0);
            if (descriptor != null) try { Os.close(descriptor); } catch (Throwable ignored) { }
            try { Os.remove(temporary.getAbsolutePath()); } catch (Throwable ignored) { }
        }
    }

    private static String readStrictToken(File file) throws Exception {
        StructStat initial = Os.lstat(file.getAbsolutePath());
        if (!validTokenStat(initial)) throw new InvalidToken();
        FileDescriptor descriptor = Os.open(file.getAbsolutePath(),
                OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
        byte[] bytes = new byte[32];
        try (FileInputStream input = new FileInputStream(descriptor)) {
            descriptor = null;
            StructStat opened = Os.fstat(input.getFD());
            if (!validTokenStat(opened)
                    || opened.st_dev != initial.st_dev || opened.st_ino != initial.st_ino) {
                throw new InvalidToken();
            }
            int offset = 0;
            while (offset < bytes.length) {
                int count = input.read(bytes, offset, bytes.length - offset);
                if (count <= 0) throw new InvalidToken();
                offset += count;
            }
            if (input.read() != -1) throw new InvalidToken();
            for (byte value : bytes) {
                if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
                    throw new InvalidToken();
                }
            }
            return new String(bytes, StandardCharsets.US_ASCII);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (descriptor != null) try { Os.close(descriptor); } catch (Throwable ignored) { }
        }
    }

    private static boolean validTokenStat(StructStat stat) {
        return (stat.st_mode & OsConstants.S_IFMT) == OsConstants.S_IFREG
                && (stat.st_mode & 07777) == 0600
                && stat.st_uid == android.os.Process.myUid()
                && stat.st_nlink == 1 && stat.st_size == 32;
    }

    private static void syncDirectory(File directory) throws Exception {
        FileDescriptor descriptor = Os.open(directory.getAbsolutePath(),
                OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
        try {
            StructStat metadata = Os.fstat(descriptor);
            if ((metadata.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFDIR
                    || metadata.st_uid != android.os.Process.myUid()) throw new Exception();
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private boolean authorized(String tokenHeader, String path) {
        if ("/health".equals(path) || "/bootstrap/transport".equals(path)) return true;
        String expectedToken = token;
        if (tokenHeader == null || expectedToken == null) return false;
        byte[] supplied = tokenHeader.getBytes(StandardCharsets.UTF_8);
        byte[] expected = expectedToken.getBytes(StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(supplied, expected);
        } finally {
            Arrays.fill(supplied, (byte) 0);
            Arrays.fill(expected, (byte) 0);
        }
    }

    private static final class InvalidToken extends Exception { }
    final class Client implements Runnable {
        final Socket socket;
        Client(Socket socket) { this.socket = socket; }
        void close() {
            try { socket.close(); } catch (Exception ignored) { }
        }
        public void run() {
            try {
                handle(socket);
            } catch (Exception ignored) {
            } finally {
                clients.remove(this);
                close();
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
                        "errorCode", agentRequest ? "agent_rejected" : "unauthorized"));
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
            String body = null;
            try {
                body = decodeUtf8(bodyBytes);
            } finally {
                Arrays.fill(bodyBytes, (byte) 0);
            }
            HttpResponse response;
            try {
                response = dispatch(method, path, body);
            } finally {
                body = null;
            }
            try {
                writeResponse(output, response.status, response.body);
            } finally {
                if ("/proxy/export".equals(path)
                        || "/proxy/agent-bootstrap".equals(path)) response.body.clear();
            }
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
        if ("/health".equals(path) || "/bootstrap/transport".equals(path)
                || "/bootstrap/status".equals(path)) return 0;
        if ("/bootstrap/reconcile".equals(path)) return "POST".equals(method) ? 512 : 0;
        if ("/bootstrap/cancel".equals(path)) return "POST".equals(method) ? 256 : 0;
        if (path.startsWith("/bootstrap/")) return 0;
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
                    : status == 202 ? "202 Accepted"
                    : status == 401 ? "401 Unauthorized"
                    : status == 409 ? "409 Conflict" : "400 Bad Request";
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

    private HttpResponse dispatch(String method, String path, String body) {
        if ("/bootstrap/transport".equals(path)) {
            if (!"GET".equals(method) || (body != null && !body.isEmpty())) {
                return bootstrapError(400, "invalid_request");
            }
            return new HttpResponse(200, map(
                    "ok", true,
                    "schema", "dev.xenoid.daemon-transport/v1",
                    "service", "xenoid-daemon",
                    "transportReady", true));
        }
        if (path.startsWith("/bootstrap/")) {
            BootstrapCoordinator coordinator = bootstrapCoordinator;
            if (coordinator == null) return bootstrapError(409, "bootstrap_unavailable");
            BootstrapCoordinator.Response result;
            if ("/bootstrap/reconcile".equals(path)) {
                if (!"POST".equals(method)) return bootstrapError(400, "invalid_request");
                result = coordinator.reconcile(body);
            } else if ("/bootstrap/status".equals(path)) {
                if (!"GET".equals(method)) return bootstrapError(400, "invalid_request");
                result = coordinator.status(body);
            } else if ("/bootstrap/cancel".equals(path)) {
                if (!"POST".equals(method)) return bootstrapError(400, "invalid_request");
                result = coordinator.cancel(body);
            } else {
                return bootstrapError(400, "invalid_request");
            }
            return new HttpResponse(result.status, result.body);
        }
        return new HttpResponse(200, route(method, path, body));
    }

    private static HttpResponse bootstrapError(int status, String code) {
        return new HttpResponse(status, map(
                "ok", false,
                "schema", BootstrapCoordinator.SCHEMA,
                "errorCode", code));
    }

    private static final class HttpResponse {
        final int status;
        final Map<String, Object> body;

        HttpResponse(int status, Map<String, Object> body) {
            this.status = status;
            this.body = body;
        }
    }
    private Map<String,Object> route(String method, String path, String body) {
        try {
            if (path.equals("/health")) {
                if (!"GET".equals(method) || (body != null && !body.isEmpty())) {
                    return map("ok", false, "error", "invalid_request");
                }
                KeyboxManager keybox = keyboxManager;
                ProxyManager proxy = proxyManager;
                BootstrapCoordinator coordinator = bootstrapCoordinator;
                if (cameraMediaManager == null || proxy == null
                        || proxyAgentChannel == null || locationIdentityManager == null
                        || keybox == null || coordinator == null
                        || !coordinator.aggregateBootstrapReady()
                        || !keybox.healthReady() || !proxy.healthReady()
                        || !locationIdentityManager.healthReady()
                        || !cameraMediaManager.healthReady()
                        || !rootHealthReady()) {
                    return map("ok", false, "service", "xenoid-daemon",
                            "version", "0.1.0", "error", "service_not_ready");
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
            return map("ok", false, "error", "not_found");
        } catch(Exception ignored) {
            return map("ok", false, "error", "internal_error");
        }
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
            if (!rootComponentReady()) return keyboxError("rootd_unavailable");
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
                if (!rootComponentReady()) return keyboxError("rootd_unavailable");
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
        if (manager == null) return map("ok", false, "error", "location_unavailable");
        if ("/location/status".equals(path)) {
            requireProxyMethod(method, "GET");
            ProxyManager.requireEmptyBody(body);
            return manager.status();
        }
        if (!rootComponentReady()) {
            return map("ok", false, "error", "rootd_unavailable");
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
                try {
                    return requireProxyManager().setSource(request);
                } finally {
                    request.clear();
                }
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
        } catch (Throwable ignored) {
            return map("ok", false, "error", "proxy_request_failed");
        }
    }

    private ProxyManager requireProxyManager() throws ProxyManager.ProxyException {
        ProxyManager manager = proxyManager;
        if (manager == null) {
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

    private boolean rootComponentReady() {
        BootstrapCoordinator coordinator = bootstrapCoordinator;
        return coordinator != null && coordinator.componentReady("root");
    }

    private boolean rootHealthReady() {
        RootHelper.ConnectionHandle handle = RootHelper.newConnectionHandle();
        try {
            Map<String, Object> status = RootHelper.status(10000, handle);
            return Boolean.TRUE.equals(status.get("ok"))
                    && Boolean.TRUE.equals(status.get("root"));
        } catch (Throwable ignored) {
            return false;
        } finally {
            handle.close();
        }
    }
    private Map<String,Object> routeCamera(String method, String path, String body) {
        try {
            CameraMediaManager manager = cameraMediaManager;
            if (manager != null && !"/camera/status".equals(path)
                    && !rootComponentReady()) {
                Map<String, Object> response = manager.status();
                response.put("ok", false);
                response.put("error", "rootd_unavailable");
                return response;
            }
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

    static boolean isStrictSimpleObject(String body) {
        return body != null && body.length() <= 1024
                && new StrictCameraObjectParser(body).parse();
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
