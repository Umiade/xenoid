package dev.xenoid.daemon;

import java.util.*;
import java.util.regex.*;

final class HideManager {
    static Map<String,Object> status() {
        Map<String,Object> nativeStatus = RootHelper.exec(
                "test -x /data/local/tmp/xenoid-hide-helper && " +
                "/data/local/tmp/xenoid-hide-helper status");
        Map<String,Object> overlayStatus = RootHelper.exec(
                "test -x /data/local/tmp/xenoid-overlay-helper && " +
                "/data/local/tmp/xenoid-overlay-helper status-json");
        Map<String,Object> propertyStatus = RootHelper.exec(
                "test \"$(getprop ro.boot.verifiedbootstate)\" = green && " +
                "test \"$(getprop ro.boot.flash.locked)\" = 1 && " +
                "test \"$(getprop ro.boot.vbmeta.device_state)\" = locked && " +
                "test \"$(getprop ro.boot.veritymode)\" = enforcing");
        boolean active = actionOk(nativeStatus) && actionOk(overlayStatus) && actionOk(propertyStatus);

        Map<String,Object> out = new LinkedHashMap<>();
        out.put("ok", active);
        out.put("policyVersion", "dev.xenoid.hide/v1");
        out.put("surfaces", Arrays.asList("filesystem", "properties", "packages", "processes", "network"));
        out.put("active", active);
        out.put("native", nativeStatus);
        out.put("overlay", overlayStatus);
        out.put("properties", propertyStatus);
        if (!active) out.put("error", "one or more Android protection layers are inactive");
        return out;
    }

    static Map<String,Object> apply(String rawJson) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("accepted", true);
        out.put("policyVersion", "dev.xenoid.hide/v1");
        List<Object> actions = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        addAction(actions, failures, "runtime-properties",
                "setprop ro.boot.verifiedbootstate green 2>/dev/null || true; " +
                "setprop ro.boot.flash.locked 1 2>/dev/null || true; " +
                "setprop ro.boot.vbmeta.device_state locked 2>/dev/null || true; " +
                "setprop ro.boot.veritymode enforcing 2>/dev/null || true; " +
                "setprop ro.boot.mode normal 2>/dev/null || true; " +
                "setprop ro.oem_unlock_supported 1 2>/dev/null || true; " +
                "setprop sys.oem_unlock_allowed 0 2>/dev/null || true; " +
                "setprop ro.boot.warranty_bit 0 2>/dev/null || true; " +
                "setprop ro.warranty_bit 0 2>/dev/null || true",
                false);
        addAction(actions, failures, "property-area",
                "if [ -x /system/bin/xenoid-prop-area ]; then " +
                "/system/bin/xenoid-prop-area --identity; " +
                "elif [ -x /data/local/tmp/xenoid-prop-area ]; then " +
                "/data/local/tmp/xenoid-prop-area --identity; else exit 127; fi " +
                ">/data/local/tmp/xenoid-prop-area.log 2>&1",
                true);
        addAction(actions, failures, "property-verification",
                "test \"$(getprop ro.boot.verifiedbootstate)\" = green && " +
                "test \"$(getprop ro.boot.flash.locked)\" = 1 && " +
                "test \"$(getprop ro.boot.vbmeta.device_state)\" = locked && " +
                "test \"$(getprop ro.boot.veritymode)\" = enforcing",
                true);
        addAction(actions, failures, "policy-stage",
                "mkdir -p /data/local/tmp/xenoid-hide && printf %s " +
                RootHelper.shellQuote(rawJson == null ? "{}" : rawJson) +
                " > /data/local/tmp/xenoid-hide/policy.json",
                true);
        for (String pkg : packageDenylist(rawJson)) {
            addAction(actions, failures, "package:" + pkg,
                    "if pm path " + RootHelper.shellQuote(pkg) + " >/dev/null 2>&1; then " +
                    "pm hide --user 0 " + RootHelper.shellQuote(pkg) + " 2>/dev/null || " +
                    "pm suspend --user 0 " + RootHelper.shellQuote(pkg) + " 2>/dev/null; fi",
                    true);
        }
        addAction(actions, failures, "native-helper",
                "test -x /data/local/tmp/xenoid-hide-helper && " +
                "/data/local/tmp/xenoid-hide-helper apply /data/local/tmp/xenoid-hide/policy.json",
                true);
        addAction(actions, failures, "overlay",
                "test -x /data/local/tmp/xenoid-overlay-helper && " +
                "/data/local/tmp/xenoid-overlay-helper apply " +
                ">/data/local/tmp/xenoid-overlay.log 2>&1",
                true);
        addAction(actions, failures, "native-verification",
                "/data/local/tmp/xenoid-hide-helper status",
                true);
        addAction(actions, failures, "overlay-verification",
                "/data/local/tmp/xenoid-overlay-helper status-json",
                true);

        out.put("actions", actions);
        out.put("failures", failures);
        out.put("ok", failures.isEmpty());
        if (!failures.isEmpty()) out.put("error", "required protection actions failed");
        return out;
    }

    private static boolean actionOk(Map<String,Object> result) {
        return Boolean.TRUE.equals(result.get("ok"));
    }

    private static void addAction(List<Object> actions, List<String> failures,
                                  String name, String command, boolean required) {
        Map<String,Object> result = RootHelper.exec(command);
        result.put("name", name);
        result.put("required", required);
        actions.add(result);
        if (required && !actionOk(result)) failures.add(name);
    }

    private static List<String> packageDenylist(String rawJson) {
        List<String> out = new ArrayList<>();
        String s = rawJson == null ? "" : rawJson;
        Matcher arr = Pattern.compile("\"packageDenylist\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(s);
        if (arr.find()) {
            Matcher item = Pattern.compile("\"([^\"]+)\"").matcher(arr.group(1));
            while (item.find()) out.add(item.group(1));
        }
        if (out.isEmpty()) {
            out.add("com.topjohnwu.magisk");
            out.add("org.lsposed.manager");
            out.add("re.frida.server");
        }
        return out;
    }
}
