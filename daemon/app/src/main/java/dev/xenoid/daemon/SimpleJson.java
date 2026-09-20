package dev.xenoid.daemon;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SimpleJson {
    // The capture honors JSON escaping: an escaped quote (\") or escaped
    // backslash (\\) stays inside the string token instead of terminating it.
    // Without this, any value containing a double quote was silently
    // truncated at the first escaped quote (e.g. shell "$(...)" fragments
    // sent to /root/exec arrived corrupted).
    static String stringValue(String body, String key, String fallback) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"((?:\\\\.|[^\"\\\\])*)\\\"").matcher(body == null ? "" : body);
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
        // Single left-to-right pass: "\\n" (escaped backslash + n) must yield
        // backslash + 'n', not backslash + newline. The previous ordered
        // replace() chain matched "\n" inside "\\n" first and corrupted every
        // escaped backslash (e.g. shell printf format strings in /root/exec).
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(++i);
                if (next == 'n') out.append('\n');
                else if (next == 'r') out.append('\r');
                else if (next == 't') out.append('\t');
                else if (next == 'b') out.append('\b');
                else if (next == 'f') out.append('\f');
                else if (next == '/') out.append('/');
                else if (next == '\\') out.append('\\');
                else if (next == '"') out.append('"');
                else { out.append('\\'); out.append(next); }
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
