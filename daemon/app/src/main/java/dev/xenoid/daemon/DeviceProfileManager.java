package dev.xenoid.daemon;

import org.json.JSONObject;
import java.security.SecureRandom;
import java.util.*;

final class DeviceProfileManager {
    private static final SecureRandom RNG = new SecureRandom();
    private static final String BATTERY_HEALTH_REFRESH =
        "stop vendor.health-default >/dev/null 2>&1 || true; "
        + "start vendor.health-default >/dev/null 2>&1 || true; "
        + "sleep 1; dumpsys battery reset >/dev/null 2>&1 || true";

    static Map<String,Object> apply(String rawJson, boolean regenerateUnique) {
        Map<String,Object> out = new LinkedHashMap<>();
        List<Object> actions = new ArrayList<>();
        Map<String,String> generated = regenerateUnique ? generatedUnique() : new LinkedHashMap<String,String>();
        try {
            JSONObject req = new JSONObject(rawJson == null || rawJson.length() == 0 ? "{}" : rawJson);
            JSONObject profile = req.optJSONObject("profile");
            if (profile == null) profile = req;

            JSONObject ids = profile.optJSONObject("ids");
            String androidId = generated.containsKey("android_id") ? generated.get("android_id") : (ids == null ? null : ids.optString("android_id", null));
            String bootId = generated.containsKey("boot_id") ? generated.get("boot_id") : (ids == null ? null : ids.optString("boot_id", null));
            if (androidId != null && androidId.length() > 0 && !"REGENERATE".equals(androidId)) {
                actions.add(applyField("android_id", androidId));
            } else if (generated.containsKey("android_id")) {
                actions.add(applyField("android_id", generated.get("android_id")));
            }
            if (bootId != null && bootId.length() > 0 && !"REGENERATE".equals(bootId)) {
                actions.add(applyField("boot_id", bootId));
            } else if (generated.containsKey("boot_id")) {
                actions.add(applyField("boot_id", generated.get("boot_id")));
            }
            String randomUuid = generated.containsKey("random_uuid") ? generated.get("random_uuid") : (ids == null ? null : ids.optString("random_uuid", null));
            if (randomUuid != null && randomUuid.length() > 0 && !"REGENERATE".equals(randomUuid)) {
                actions.add(applyField("random_uuid", randomUuid));
            } else if (generated.containsKey("random_uuid")) {
                actions.add(applyField("random_uuid", generated.get("random_uuid")));
            }
            String serial = generated.containsKey("serial") ? generated.get("serial") : (ids == null ? null : ids.optString("serial", null));
            if (serial != null && serial.length() > 0 && !"REGENERATE".equals(serial)) actions.add(applyField("serial", serial));
            else if (generated.containsKey("serial")) actions.add(applyField("serial", generated.get("serial")));
            String imei = generated.containsKey("imei") ? generated.get("imei") : (ids == null ? null : ids.optString("imei", null));
            if (imei != null && imei.length() > 0 && !"REGENERATE".equals(imei)) actions.add(applyField("imei", imei));
            else if (generated.containsKey("imei")) actions.add(applyField("imei", generated.get("imei")));
            String imeisv = generated.containsKey("imeisv") ? generated.get("imeisv") : (ids == null ? null : ids.optString("imeisv", null));
            if (imeisv != null && imeisv.length() > 0 && !"REGENERATE".equals(imeisv)) actions.add(applyField("imeisv", imeisv));
            else if (generated.containsKey("imeisv")) actions.add(applyField("imeisv", generated.get("imeisv")));

            JSONObject build = profile.optJSONObject("build");
            if (build != null) {
                Map<String,String> propMap = new LinkedHashMap<>();
                propMap.put("brand", "ro.product.brand");
                propMap.put("manufacturer", "ro.product.manufacturer");
                propMap.put("model", "ro.product.model");
                propMap.put("device", "ro.product.device");
                propMap.put("product", "ro.product.name");
                propMap.put("fingerprint", "ro.build.fingerprint");
                propMap.put("hardware", "ro.hardware");
                propMap.put("board", "ro.product.board");
                propMap.put("bootloader", "ro.bootloader");
                propMap.put("security_patch", "ro.build.version.security_patch");
                propMap.put("first_api_level", "ro.product.first_api_level");
                propMap.put("sku", "ro.boot.hardware.sku");
                propMap.put("abi", "ro.product.cpu.abi");
                propMap.put("bionic_arch", "ro.bionic.arch");
                propMap.put("dalvik_isa_arm64", "ro.dalvik.vm.isa.arm64");
                propMap.put("dalvik_isa_arm", "ro.dalvik.vm.isa.arm");
                Iterator<String> it = propMap.keySet().iterator();
                while (it.hasNext()) {
                    String key = it.next();
                    String v = build.optString(key, null);
                    if (v != null && v.length() > 0) actions.add(applyField(propMap.get(key), v));
                }
                String brand = build.optString("brand", null);
                String manufacturer = build.optString("manufacturer", null);
                String model = build.optString("model", null);
                String device = build.optString("device", null);
                String product = build.optString("product", null);
                String fingerprint = build.optString("fingerprint", null);
                String tags = build.optString("tags", "release-keys");
                String type = build.optString("type", "user");
                String abi = build.optString("abi", "arm64-v8a");
                String abilist = build.optString("abilist", "arm64-v8a");
                String abilist32 = build.optString("abilist32", "");
                String abilist64 = build.optString("abilist64", "arm64-v8a");
                for (String part : new String[]{"", "product", "system", "system_ext", "vendor", "odm", "vendor_dlkm", "odm_dlkm", "system_dlkm"}) {
                    String prefix = part.length() == 0 ? "ro.product" : "ro.product." + part;
                    if (brand != null && brand.length() > 0) actions.add(applyField(prefix + ".brand", brand));
                    if (manufacturer != null && manufacturer.length() > 0) actions.add(applyField(prefix + ".manufacturer", manufacturer));
                    if (model != null && model.length() > 0) actions.add(applyField(prefix + ".model", model));
                    if (device != null && device.length() > 0) actions.add(applyField(prefix + ".device", device));
                    if (product != null && product.length() > 0) actions.add(applyField(prefix + ".name", product));
                    String buildPrefix = part.length() == 0 ? "ro.build" : "ro." + part + ".build";
                    if (fingerprint != null && fingerprint.length() > 0) actions.add(applyField(buildPrefix + ".fingerprint", fingerprint));
                    actions.add(applyField(buildPrefix + ".tags", tags));
                    actions.add(applyField(buildPrefix + ".type", type));
                }
                for (String prefix : new String[]{"ro.product.cpu", "ro.vendor.product.cpu", "ro.odm.product.cpu", "ro.system.product.cpu"}) {
                    actions.add(applyField(prefix + ".abilist", abilist));
                    actions.add(applyField(prefix + ".abilist32", abilist32));
                    actions.add(applyField(prefix + ".abilist64", abilist64));
                }
                actions.add(applyField("ro.product.cpu.abi", abi));
                actions.add(applyField("dalvik.vm.isa.x86.variant", ""));
                actions.add(applyField("dalvik.vm.isa.x86_64.variant", ""));
                String securityPatch = build.optString("security_patch", null);
                if (securityPatch != null && securityPatch.length() > 0) actions.add(applyField("ro.vendor.build.security_patch", securityPatch));
            }

            JSONObject network = profile.optJSONObject("network");
            JSONObject hardware = profile.optJSONObject("hardware_profile");
            if (network != null || profile.has("locale") || profile.has("timezone")
                    || (hardware != null && (hardware.has("mac") || hardware.has("wifi_mac")))) {
                throw new IllegalArgumentException("location_identity_owned");
            }

            JSONObject usb = profile.optJSONObject("usb");
            if (usb != null) {
                if (usb.has("serial")) {
                    String usbSerial = String.valueOf(usb.opt("serial"));
                    if ("REGENERATE".equals(usbSerial) && generated.containsKey("serial")) usbSerial = generated.get("serial");
                    if (!"REGENERATE".equals(usbSerial)) actions.add(applyField("serial", usbSerial));
                }
                if (usb.has("manufacturer")) actions.add(applyField("usb.manufacturer", String.valueOf(usb.opt("manufacturer"))));
                if (usb.has("product")) actions.add(applyField("usb.product", String.valueOf(usb.opt("product"))));
                if (usb.has("vendor_id")) actions.add(applyField("usb.vendor_id", String.valueOf(usb.opt("vendor_id"))));
                if (usb.has("product_id")) actions.add(applyField("usb.product_id", String.valueOf(usb.opt("product_id"))));
            }

            JSONObject battery = profile.optJSONObject("battery");
            if (battery != null) {
                Iterator<String> keys = battery.keys();
                while (keys.hasNext()) {
                    String k = keys.next();
                    actions.add(applyField("battery." + k, String.valueOf(battery.opt(k)), false));
                }
            }
            JSONObject thermal = profile.optJSONObject("thermal");
            if (thermal != null) {
                Iterator<String> keys = thermal.keys();
                while (keys.hasNext()) {
                    String k = keys.next();
                    Object v = thermal.opt(k);
                    if (v instanceof JSONObject) {
                        JSONObject z = (JSONObject) v;
                        if (z.has("temp")) actions.add(applyField("thermal." + k + ".temp", String.valueOf(z.opt("temp"))));
                        if (z.has("type")) actions.add(applyField("thermal." + k + ".type", String.valueOf(z.opt("type"))));
                    } else {
                        actions.add(applyField("thermal." + k, String.valueOf(v)));
                    }
                }
            }
            JSONObject display = profile.optJSONObject("display");
            if (display != null) {
                if (display.has("width")) actions.add(applyField("display.width", String.valueOf(display.opt("width"))));
                if (display.has("height")) actions.add(applyField("display.height", String.valueOf(display.opt("height"))));
                if (display.has("densityDpi")) actions.add(applyField("display.densityDpi", String.valueOf(display.opt("densityDpi"))));
                if (display.has("density_dpi")) actions.add(applyField("display.densityDpi", String.valueOf(display.opt("density_dpi"))));
                if (display.has("brightness")) actions.add(applyField("display.brightness", String.valueOf(display.opt("brightness"))));
            }
            if (profile.has("display_width")) actions.add(applyField("display.width", String.valueOf(profile.opt("display_width"))));
            if (profile.has("display_height")) actions.add(applyField("display.height", String.valueOf(profile.opt("display_height"))));

            actions.addAll(stageEffectiveProfile(rawJson == null ? "{}" : rawJson));
            Map<String,Object> inputReload = RootHelper.inputReload();
            actions.add(inputReload);
            if (!Boolean.TRUE.equals(inputReload.get("ok"))) {
                throw new IllegalStateException("input_driver_reload_failed");
            }
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
            if (battery != null) actions.add(RootHelper.exec(BATTERY_HEALTH_REFRESH));
            out.put("ok", true);
            out.put("accepted", true);
            out.put("regenerateUnique", regenerateUnique);
            out.put("generated", generated);
            out.put("actions", actions);
            out.put("note", "Applied mutable settings/properties immediately and staged full profile for native property/sensor/battery overlay modules.");
        } catch (Exception e) {
            out.put("ok", false);
            out.put("error", e.toString());
            out.put("actions", actions);
        }
        return out;
    }

    private static List<Object> stageEffectiveProfile(String rawJson) {
        List<Object> actions = new ArrayList<>();
        String path = "/data/local/tmp/xenoid-profile/effective.json";
        actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && : > " + RootHelper.shellQuote(path)));
        final int chunkSize = 1200;
        for (int off = 0; off < rawJson.length(); off += chunkSize) {
            String chunk = rawJson.substring(off, Math.min(rawJson.length(), off + chunkSize));
            actions.add(RootHelper.exec("printf %s " + RootHelper.shellQuote(chunk) + " >> " + RootHelper.shellQuote(path)));
        }
        return actions;
    }

    static Map<String,Object> setField(String field, String value) {
        Map<String,Object> out = applyField(field, value);
        boolean inputField = field != null
                && (field.startsWith("input.")
                    || field.startsWith("touch.")
                    || "display.width".equals(field)
                    || "display.height".equals(field));
        if (inputField && Boolean.TRUE.equals(out.get("ok"))) {
            Map<String,Object> reload = RootHelper.inputReload();
            out.put("inputReload", reload);
            if (!Boolean.TRUE.equals(reload.get("ok"))) {
                out.put("ok", false);
                out.put("error", "input_driver_reload_failed");
            }
        }
        return out;
    }

    private static Map<String,Object> applyField(String field, String value) {
        return applyField(field, value, true);
    }

    private static Map<String,Object> applyField(String field, String value, boolean refreshBattery) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("field", field);
        out.put("value", value);
        List<Object> actions = new ArrayList<>();
        if ("android_id".equals(field) || "settings.secure.android_id".equals(field)) {
            actions.add(RootHelper.exec("settings put secure android_id " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/android_id"));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-ssaid && /data/local/tmp/xenoid-ssaid " + RootHelper.shellQuote(value) + " >/data/local/tmp/xenoid-ssaid.log 2>&1 || true"));
        } else if ("boot_id".equals(field)) {
            actions.add(RootHelper.exec("setprop persist.xenoid.boot_id " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/boot_id"));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if ("random_uuid".equals(field)) {
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/random_uuid"));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if ("imei".equals(field) || "persist.xenoid.radio.imei".equals(field)) {
            actions.add(RootHelper.exec("setprop persist.xenoid.radio.imei " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/imei"));
        } else if ("imeisv".equals(field) || "persist.xenoid.radio.imeisv".equals(field)) {
            actions.add(RootHelper.exec("setprop persist.xenoid.radio.imeisv " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/imeisv"));
        } else if ("serial".equals(field) || "ro.serialno".equals(field) || "ro.boot.serialno".equals(field)) {
            String serial = value.trim().replaceAll("[^A-Za-z0-9._-]", "");
            if (serial.length() == 0) serial = "3A4940E5EDFA";
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(serial + "\n") + " > /data/local/tmp/xenoid-profile/serial"));
            actions.add(RootHelper.exec("resetprop ro.serialno " + RootHelper.shellQuote(serial) + " 2>/dev/null || setprop ro.serialno " + RootHelper.shellQuote(serial) + " 2>/dev/null || true"));
            actions.add(RootHelper.exec("resetprop ro.boot.serialno " + RootHelper.shellQuote(serial) + " 2>/dev/null || setprop ro.boot.serialno " + RootHelper.shellQuote(serial) + " 2>/dev/null || true"));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if (field.startsWith("ro.") || field.startsWith("persist.")) {
            actions.add(RootHelper.exec("resetprop " + RootHelper.shellQuote(field) + " " + RootHelper.shellQuote(value) + " 2>/dev/null || setprop " + RootHelper.shellQuote(field) + " " + RootHelper.shellQuote(value) + " || true"));
        } else if (field.startsWith("usb.")) {
            String key = field.substring("usb.".length()).replace('-', '_');
            String outName = "usb_" + key;
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/" + outName));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if (field.startsWith("network.") || "mac".equals(field)
                || "mac_address".equals(field) || "wifi_mac".equals(field)
                || "ip".equals(field) || "ip_address".equals(field)
                || "mtu".equals(field) || "ifname".equals(field)) {
            out.put("actions", actions);
            out.put("ok", false);
            out.put("applied", false);
            out.put("error", "network_identity_location_owned");
            return out;
        } else if (field.startsWith("battery.")) {
            actions.add(RootHelper.exec("setprop " + RootHelper.shellQuote("persist.xenoid." + field.replace(".", "_")) + " " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile/battery && printf %s " + RootHelper.shellQuote(value) + " > " + RootHelper.shellQuote("/data/local/tmp/xenoid-profile/" + field.replace("/", "_").replace(".", "_"))));
            String k = field.substring("battery.".length());
            boolean healthBacked = "voltage".equals(k) || "level".equals(k)
                || "temperature".equals(k) || "temp".equals(k) || "status".equals(k)
                || "plugged".equals(k) || "health".equals(k) || "present".equals(k);
            if (healthBacked) {
                actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
                if (refreshBattery) actions.add(RootHelper.exec(BATTERY_HEALTH_REFRESH));
            }
        } else if (field.startsWith("thermal.")) {
            String rest = field.substring("thermal.".length()).replace("zone", "").replace("thermal_zone", "");
            String[] parts = rest.split("\\.");
            String zone = parts.length > 0 ? parts[0].replaceAll("[^0-9]", "") : "0";
            String key = parts.length > 1 ? parts[1] : "temp";
            if (zone.length() == 0) zone = "0";
            String outName = "type".equals(key) ? "thermal_zone" + zone + "_type" : "thermal_zone" + zone + "_temp";
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/" + outName));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if (field.startsWith("display.")) {
            String key = field.substring("display.".length()).replace('-', '_');
            String outName = "densityDpi".equals(key) || "density_dpi".equals(key) ? "display_density_dpi" : "display_" + key;
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/" + outName));
            if ("width".equals(key) || "height".equals(key)) {
                actions.add(RootHelper.exec("wm size " + RootHelper.shellQuote(value) + " 2>/dev/null || true"));
            } else if ("densityDpi".equals(key) || "density_dpi".equals(key)) {
                actions.add(RootHelper.exec("wm density " + RootHelper.shellQuote(value) + " 2>/dev/null || true"));
            }
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if (field.startsWith("input.") || field.startsWith("touch.")) {
            String key = field.substring(field.indexOf('.') + 1).replace('-', '_');
            String outName = ("name".equals(key) || "device_name".equals(key)) ? "input_name" : "input_" + key;
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile && printf %s " + RootHelper.shellQuote(value + "\n") + " > /data/local/tmp/xenoid-profile/" + outName));
            actions.add(RootHelper.exec("test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
        } else if ("locale".equals(field) || "timezone".equals(field)) {
            out.put("ok", false);
            out.put("applied", false);
            out.put("error", "location_identity_owned");
            return out;
        } else {
            actions.add(RootHelper.exec("mkdir -p /data/local/tmp/xenoid-profile/fields && printf %s " + RootHelper.shellQuote(value) + " > /data/local/tmp/xenoid-profile/fields/" + RootHelper.shellQuote(field.replace('/', '_'))));
        }
        out.put("actions", actions);
        out.put("ok", true);
        out.put("applied", true);
        return out;
    }

    private static Map<String,String> generatedUnique() {
        Map<String,String> g = new LinkedHashMap<>();
        g.put("android_id", hex(8));
        g.put("boot_id", UUID.randomUUID().toString());
        g.put("random_uuid", UUID.randomUUID().toString());
        g.put("serial", pixelSerial());
        g.put("imei", pixelImei());
        g.put("imeisv", "01");
        return g;
    }
    private static String pixelSerial() { return "3A" + hex(5).toUpperCase(Locale.ROOT); }
    private static String pixelImei() {
        StringBuilder first = new StringBuilder("35693803");
        while (first.length() < 14) first.append(RNG.nextInt(10));
        int total = 0;
        for (int i = 0; i < first.length(); i++) {
            int digit = first.charAt(i) - '0';
            if ((i & 1) == 1) {
                digit *= 2;
                digit = digit / 10 + digit % 10;
            }
            total += digit;
        }
        return first.toString() + ((10 - total % 10) % 10);
    }
    private static String hex(int bytes) { byte[] b = new byte[bytes]; RNG.nextBytes(b); StringBuilder s = new StringBuilder(); for(byte x:b) s.append(String.format("%02x", x)); return s.toString(); }
}
