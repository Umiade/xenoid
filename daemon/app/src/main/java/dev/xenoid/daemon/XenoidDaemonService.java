package dev.xenoid.daemon;

import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class XenoidDaemonService extends Service {
    private ExecutorService pool; private ServerSocket server;
    public IBinder onBind(Intent intent) { return null; }
    public int onStartCommand(Intent intent, int flags, int startId) { enterForeground(); startServer(); return START_STICKY; }
    public void onDestroy() { try { if (server != null) server.close(); } catch(Exception ignored) {} if (pool != null) pool.shutdownNow(); }
    private void enterForeground() {
        String channelId = "xenoid-control";
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(channelId, "Xenoid control service", NotificationManager.IMPORTANCE_MIN));
        Notification notification = new Notification.Builder(this, channelId)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("Xenoid runtime")
                .setContentText("Local control service active")
                .setOngoing(true)
                .build();
        startForeground(18765, notification);
    }
    private synchronized void startServer() {
        if (pool != null) return;
        token = getToken();
        RootHelper.setRootdToken(token);
        pool = Executors.newFixedThreadPool(16);
        // adb forward reaches this socket through the redroid device interface,
        // so bind-all is required here. Every non-health route is token-gated.
        pool.submit(() -> { try { server = new ServerSocket(18765, 50, InetAddress.getByName("0.0.0.0")); android.util.Log.i("xenoid-daemon", "listening on 18765"); while (!server.isClosed()) pool.submit(new Client(server.accept())); } catch(Exception e) { android.util.Log.e("xenoid-daemon", "bind failed", e); } });
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
            if (path.equals("/health")) return map("ok", true, "service", "xenoid-daemon", "version", "0.1.0");
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
    static Map<String,Object> map(Object... kv) { Map<String,Object> m = new LinkedHashMap<>(); for(int i=0;i+1<kv.length;i+=2)m.put(String.valueOf(kv[i]),kv[i+1]); return m; }
}
