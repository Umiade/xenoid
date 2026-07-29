package dev.xenoid.daemon;

import java.io.*;
import java.util.*;

final class OtaManager {
    private static final String DIR = "/data/local/tmp/xenoid-ota";
    private static final String STATE = DIR + "/state.json";

    static Map<String,Object> check() {
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("current", "0.1.0");
        m.put("channel", "local");
        m.put("statePath", STATE);
        m.put("state", readFile(STATE));
        m.put("updateAvailable", false);
        return m;
    }

    static Map<String,Object> apply(String channel) {
        Map<String,Object> m = new LinkedHashMap<>();
        List<Object> actions = new ArrayList<>();
        String state = "{\"version\":\"0.1.0\",\"channel\":\"" + escape(channel) + "\",\"appliedAt\":\"" + System.currentTimeMillis() + "\"}";
        actions.add(RootHelper.exec("mkdir -p " + RootHelper.shellQuote(DIR)));
        actions.add(RootHelper.exec("printf %s " + RootHelper.shellQuote(state) + " > " + RootHelper.shellQuote(STATE)));
        actions.add(RootHelper.exec("chmod 755 /data/local/tmp/xenoid-input 2>/dev/null || true"));
        m.put("ok", true);
        m.put("channel", channel);
        m.put("staged", true);
        m.put("statePath", STATE);
        m.put("actions", actions);
        m.put("note", "Daemon-side OTA state applied. Host bundle installer handles APK/helper payload deployment.");
        return m;
    }

    private static String readFile(String path) {
        try {
            BufferedReader r = new BufferedReader(new FileReader(path));
            StringBuilder b = new StringBuilder(); String line;
            while ((line = r.readLine()) != null) b.append(line).append('\n');
            r.close();
            return b.toString();
        } catch (Exception e) { return null; }
    }
    private static String escape(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }
}
