package dev.xenoid.daemon;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SimpleJson {
    static String stringValue(String body, String key, String fallback) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"").matcher(body == null ? "" : body);
        return m.find() ? unescape(m.group(1)) : fallback;
    }

    static int intValue(String body, String key, int fallback) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*(-?\\d+)").matcher(body == null ? "" : body);
        if (!m.find()) return fallback;
        try { return Integer.parseInt(m.group(1)); } catch (Exception e) { return fallback; }
    }

    static boolean boolValue(String body, String key, boolean fallback) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*(true|false)").matcher(body == null ? "" : body);
        return m.find() ? Boolean.parseBoolean(m.group(1)) : fallback;
    }

    private static String unescape(String s) {
        return s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
