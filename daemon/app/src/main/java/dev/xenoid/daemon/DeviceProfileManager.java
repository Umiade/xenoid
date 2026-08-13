package dev.xenoid.daemon;

import android.content.Context;
import android.system.Os;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

final class DeviceProfileManager {
    private static final SecureRandom RNG = new SecureRandom();
    private static final String BATTERY_HEALTH_REFRESH =
        "stop vendor.health-default >/dev/null 2>&1 || true; "
        + "start vendor.health-default >/dev/null 2>&1 || true; "
        + "sleep 1; dumpsys battery reset >/dev/null 2>&1 || true";

    static Map<String,Object> apply(Context context, String rawJson, boolean regenerateUnique) {
        Map<String,Object> out = new LinkedHashMap<>();
        List<Object> actions = new ArrayList<>();
        Map<String,String> generated = regenerateUnique ? generatedUnique() : new LinkedHashMap<String,String>();
        try {
            JSONObject req = new JSONObject(rawJson == null || rawJson.length() == 0 ? "{}" : rawJson);
            JSONObject supplied = req.optJSONObject("profile");
            if (supplied == null) supplied = req;
            JSONObject profile = new JSONObject(supplied.toString());
            if (!"dev.xenoid.fingerprint/v1".equals(profile.optString("schema", ""))) {
                throw new IllegalArgumentException("device_profile_schema_invalid");
            }
            JSONObject battery = profile.optJSONObject("battery");
            validateBatteryProfile(battery);
            Map<String,String> hardwareProfileFields = prepareHardwareProfile(profile);
            JSONObject ids = profile.optJSONObject("ids");
            if (ids == null) ids = new JSONObject();
            for (Map.Entry<String,String> entry : generated.entrySet()) {
                ids.put(entry.getKey(), entry.getValue());
            }
            profile.put("ids", ids);
            JSONObject effectiveUsb = profile.optJSONObject("usb");
            if (effectiveUsb != null && generated.containsKey("serial")) {
                effectiveUsb.put("serial", generated.get("serial"));
            }
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
            if (build == null) throw new IllegalArgumentException("build_profile_required");
            String brand = requiredString(build, "brand");
            String manufacturer = requiredString(build, "manufacturer");
            String model = requiredString(build, "model");
            String device = requiredString(build, "device");
            String product = requiredString(build, "product");
            String fingerprint = requiredString(build, "fingerprint");
            String hardwareName = requiredString(build, "hardware");
            String board = requiredString(build, "board");
            String platform = requiredString(build, "platform");
            String socManufacturer = requiredString(build, "soc_manufacturer");
            String socModel = requiredString(build, "soc_model");
            String bootloader = requiredString(build, "bootloader");
            String securityPatch = requiredString(build, "security_patch");
            String firstApiLevel = requiredString(build, "first_api_level");
            String sku = requiredString(build, "sku");
            String buildId = requiredString(build, "id");
            String incremental = requiredString(build, "incremental");
            String release = requiredString(build, "release");
            String sdk = requiredString(build, "sdk");
            String description = requiredString(build, "description");
            String tags = requiredString(build, "tags");
            String type = requiredString(build, "type");
            String abi = requiredString(build, "abi");
            String abilist = requiredString(build, "abilist");
            String abilist32 = build.optString("abilist32", null);
            String abilist64 = requiredString(build, "abilist64");
            String bionicArch = requiredString(build, "bionic_arch");
            String dalvikArm64 = requiredString(build, "dalvik_isa_arm64");
            String dalvikArm = build.optString("dalvik_isa_arm", null);
            if (abilist32 == null || dalvikArm == null) {
                throw new IllegalArgumentException("build_profile_required");
            }

            Map<String,String> exactProps = new LinkedHashMap<>();
            exactProps.put("ro.build.fingerprint", fingerprint);
            exactProps.put("ro.build.id", buildId);
            exactProps.put("ro.build.display.id", buildId);
            exactProps.put("ro.build.version.incremental", incremental);
            exactProps.put("ro.build.version.release", release);
            exactProps.put("ro.build.version.release_or_codename", release);
            exactProps.put("ro.build.version.sdk", sdk);
            exactProps.put("ro.build.version.security_patch", securityPatch);
            exactProps.put("ro.build.description", description);
            exactProps.put("ro.build.product", product);
            exactProps.put("ro.hardware", hardwareName);
            exactProps.put("ro.boot.hardware", hardwareName);
            exactProps.put("ro.product.board", board);
            exactProps.put("ro.board.platform", platform);
            exactProps.put("ro.soc.manufacturer", socManufacturer);
            exactProps.put("ro.soc.model", socModel);
            exactProps.put("ro.bootloader", bootloader);
            exactProps.put("ro.product.first_api_level", firstApiLevel);
            exactProps.put("ro.boot.hardware.sku", sku);
            exactProps.put("ro.hardware.sku", sku);
            exactProps.put("ro.product.cpu.abi", abi);
            exactProps.put("ro.bionic.arch", bionicArch);
            exactProps.put("ro.dalvik.vm.isa.arm64", dalvikArm64);
            exactProps.put("ro.dalvik.vm.isa.arm", dalvikArm);
            for (Map.Entry<String,String> entry : exactProps.entrySet()) {
                actions.add(applyField(entry.getKey(), entry.getValue()));
            }

            String[] partitions = new String[]{
                "", "product", "system", "system_ext", "vendor", "odm",
                "vendor_dlkm", "odm_dlkm", "system_dlkm"
            };
            for (String part : partitions) {
                String productPrefix = part.length() == 0 ? "ro.product" : "ro.product." + part;
                actions.add(applyField(productPrefix + ".brand", brand));
                actions.add(applyField(productPrefix + ".manufacturer", manufacturer));
                actions.add(applyField(productPrefix + ".model", model));
                actions.add(applyField(productPrefix + ".device", device));
                actions.add(applyField(productPrefix + ".name", product));
                String buildPrefix = part.length() == 0 ? "ro.build" : "ro." + part + ".build";
                actions.add(applyField(buildPrefix + ".fingerprint", fingerprint));
                actions.add(applyField(buildPrefix + ".id", buildId));
                actions.add(applyField(buildPrefix + ".version.incremental", incremental));
                actions.add(applyField(buildPrefix + ".version.release", release));
                actions.add(applyField(buildPrefix + ".version.release_or_codename", release));
                actions.add(applyField(buildPrefix + ".version.sdk", sdk));
                actions.add(applyField(buildPrefix + ".tags", tags));
                actions.add(applyField(buildPrefix + ".type", type));
            }
            for (String prefix : new String[]{
                    "ro.product.cpu", "ro.product.product.cpu", "ro.system.product.cpu",
                    "ro.system_ext.product.cpu", "ro.vendor.product.cpu", "ro.odm.product.cpu",
                    "ro.vendor_dlkm.product.cpu", "ro.odm_dlkm.product.cpu",
                    "ro.system_dlkm.product.cpu"}) {
                actions.add(applyField(prefix + ".abilist", abilist));
                actions.add(applyField(prefix + ".abilist32", abilist32));
                actions.add(applyField(prefix + ".abilist64", abilist64));
            }
            actions.add(applyField("ro.vendor.build.security_patch", securityPatch));
            actions.add(applyField("dalvik.vm.isa.x86.variant", ""));
            actions.add(applyField("dalvik.vm.isa.x86_64.variant", ""));

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

            battery = profile.optJSONObject("battery");
            if (battery != null) {
                Iterator<String> keys = battery.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    Map<String,Object> batteryAction = applyField(
                            "battery." + key, String.valueOf(battery.opt(key)), false);
                    actions.add(batteryAction);
                    if (!Boolean.TRUE.equals(batteryAction.get("ok"))) {
                        throw new IllegalStateException(
                                "battery_profile_apply_failed:" + key);
                    }
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
                String width = requiredString(display, "width");
                String height = requiredString(display, "height");
                actions.add(applyDisplayMetrics(
                        width, height, requiredString(display, "densityDpi")));
                actions.add(applyField("display.physicalPpi", requiredString(display, "physicalPpi")));
                actions.add(applyField("display.defaultRefreshRateHz",
                        requiredString(display, "defaultRefreshRateHz")));
                actions.add(applyField("display.peakRefreshRateHz",
                        requiredString(display, "peakRefreshRateHz")));
                actions.add(applyField("input.width", width));
                actions.add(applyField("input.height", height));
            }
            JSONObject input = profile.optJSONObject("input");
            if (input == null) throw new IllegalArgumentException("input_profile_required");
            actions.add(applyField("input.name", requiredString(input, "name")));
            actions.add(applyField("input.busType", requiredString(input, "busType")));
            actions.add(applyField("input.vendorId", requiredString(input, "vendorId")));
            actions.add(applyField("input.productId", requiredString(input, "productId")));
            actions.add(applyField("input.version", requiredString(input, "version")));
            for (String axis : new String[]{"x", "y", "pressure", "trackingId"}) {
                JSONObject values = input.optJSONObject(axis);
                if (values == null) {
                    throw new IllegalArgumentException("input_axis_required:" + axis);
                }
                actions.add(applyField(
                        "input." + axis + "_minimum", requiredString(values, "minimum")));
                actions.add(applyField(
                        "input." + axis + "_maximum", requiredString(values, "maximum")));
            }

            actions.add(stageHardwareProfile(hardwareProfileFields));

            actions.add(stageEffectiveProfile(context, profile));
            Map<String,Object> inputReload = RootHelper.inputReload();
            actions.add(inputReload);
            if (!Boolean.TRUE.equals(inputReload.get("ok"))) {
                throw new IllegalStateException("input_driver_reload_failed");
            }
            Map<String,Object> overlay = RootHelper.exec(
                    "test -x /data/local/tmp/xenoid-overlay-helper"
                    + " && /data/local/tmp/xenoid-overlay-helper apply"
                    + " >/data/local/tmp/xenoid-overlay.log 2>&1");
            actions.add(overlay);
            if (!Boolean.TRUE.equals(overlay.get("ok"))) {
                throw new IllegalStateException("profile_overlay_apply_failed");
            }
            actions.add(RootHelper.exec(BATTERY_HEALTH_REFRESH));
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

    private static Map<String,String> prepareHardwareProfile(JSONObject profile) throws Exception {
        JSONObject cpu = profile.optJSONObject("cpu");
        if (cpu == null) throw new IllegalArgumentException("cpu_profile_required");
        String implementer = requiredString(cpu, "implementer");
        if (!implementer.matches("0x[0-9A-Fa-f]{1,8}")) {
            throw new IllegalArgumentException("cpu_implementer_invalid");
        }
        JSONArray cores = cpu.optJSONArray("cores");
        if (cores == null || cores.length() != 8) {
            throw new IllegalArgumentException("cpu_core_count_invalid");
        }

        Map<String,String> fields = new LinkedHashMap<>();
        fields.put("cpu_count", String.valueOf(cores.length()));
        fields.put("cpu_implementer", implementer);
        long[] minimums = new long[8];
        long[] maximums = new long[8];
        String[] parts = new String[8];
        String[] models = new String[8];
        for (int index = 0; index < cores.length(); index++) {
            JSONObject core = cores.optJSONObject(index);
            if (core == null) throw new IllegalArgumentException("cpu_core_invalid:" + index);
            long processor = requiredLong(core, "processor", 0, 7);
            if (processor != index) {
                throw new IllegalArgumentException("cpu_processor_order_invalid:" + index);
            }
            String part = requiredString(core, "part");
            String model = requiredString(core, "model");
            if (!part.matches("0x[0-9A-Fa-f]{1,8}") || model.length() > 64) {
                throw new IllegalArgumentException("cpu_core_identity_invalid:" + index);
            }
            long minimum = requiredLong(core, "minimumFrequencyKhz", 1, 10000000);
            long maximum = requiredLong(core, "maximumFrequencyKhz", minimum, 10000000);
            minimums[index] = minimum;
            maximums[index] = maximum;
            parts[index] = part;
            models[index] = model;
            String prefix = "cpu_" + index + "_";
            fields.put(prefix + "processor", String.valueOf(processor));
            fields.put(prefix + "part", part);
            fields.put(prefix + "model", model);
            fields.put(prefix + "minimumFrequencyKhz", String.valueOf(minimum));
            fields.put(prefix + "maximumFrequencyKhz", String.valueOf(maximum));
        }
        for (int index = 0; index < cores.length(); index++) {
            int leader = index < 4 ? 0 : (index < 6 ? 4 : 6);
            if (minimums[index] != minimums[leader]
                    || maximums[index] != maximums[leader]
                    || !parts[index].equals(parts[leader])
                    || !models[index].equals(models[leader])) {
                throw new IllegalArgumentException("cpu_cluster_inconsistent:" + index);
            }
        }

        JSONObject memory = profile.optJSONObject("memory");
        if (memory == null) throw new IllegalArgumentException("memory_profile_required");
        long totalBytes = requiredLong(memory, "totalBytes", 4096, 1L << 50);
        long totalKiB = requiredLong(memory, "totalKiB", 4, 1L << 40);
        long swapBytes = requiredLong(memory, "swapBytes", 0, 1L << 50);
        if (totalKiB > Long.MAX_VALUE / 1024 || totalBytes != totalKiB * 1024
                || totalKiB % 4 != 0 || swapBytes % 1024 != 0) {
            throw new IllegalArgumentException("memory_profile_inconsistent");
        }
        fields.put("memory_totalBytes", String.valueOf(totalBytes));
        fields.put("memory_totalKiB", String.valueOf(totalKiB));
        fields.put("memory_swapBytes", String.valueOf(swapBytes));

        JSONObject storage = profile.optJSONObject("storage");
        if (storage == null) throw new IllegalArgumentException("storage_profile_required");
        long capacityBytes = requiredLong(storage, "capacityBytes", 512, 1L << 50);
        long sectorSizeBytes = requiredLong(storage, "sectorSizeBytes", 1, 1L << 20);
        long sectorCount = requiredLong(storage, "sectorCount", 1, 1L << 50);
        String variant = requiredString(storage, "variant");
        String blockDevice = requiredString(storage, "blockDevice");
        String mountSource = requiredString(storage, "mountSource");
        String technology = requiredString(storage, "technology");
        String filesystem = requiredString(storage, "filesystem");
        if (sectorCount > Long.MAX_VALUE / sectorSizeBytes
                || capacityBytes != sectorSizeBytes * sectorCount
                || capacityBytes != 128_000_000_000L
                || sectorSizeBytes != 512
                || sectorCount != 250_000_000
                || !"128GB".equals(variant)
                || !"sda".equals(blockDevice)
                || !"/dev/block/platform/14700000.ufs/by-name/userdata".equals(mountSource)
                || !"UFS 3.1".equals(technology)
                || !"f2fs".equals(filesystem)
                || !requiredBoolean(storage, "sparse")
                || requiredBoolean(storage, "removable")) {
            throw new IllegalArgumentException("storage_profile_inconsistent");
        }
        fields.put("storage_capacityBytes", String.valueOf(capacityBytes));
        fields.put("storage_blockDevice", blockDevice);
        fields.put("storage_mountSource", mountSource);
        fields.put("storage_sectorSizeBytes", String.valueOf(sectorSizeBytes));
        fields.put("storage_sectorCount", String.valueOf(sectorCount));
        fields.put("storage_technology", technology);
        fields.put("storage_filesystem", filesystem);

        return fields;
    }

    private static Map<String,Object> stageHardwareProfile(
            Map<String,String> fields) throws Exception {
        List<Object> writes = new ArrayList<>();
        String base = "set -eu;d=/data/local/tmp/xenoid-profile;mkdir -p \"$d\";";
        StringBuilder command = new StringBuilder(base);
        for (Map.Entry<String,String> entry : fields.entrySet()) {
            String fragment = "printf %s " + RootHelper.shellQuote(entry.getValue() + "\n")
                    + " > \"$d/" + entry.getKey() + "\";";
            if (command.length() + fragment.length() > 700) {
                Map<String,Object> write = RootHelper.exec(command.toString());
                writes.add(write);
                if (!Boolean.TRUE.equals(write.get("ok"))) {
                    throw new IllegalStateException("hardware_profile_stage_failed");
                }
                command.setLength(0);
                command.append(base);
            }
            command.append(fragment);
        }
        if (command.length() > base.length()) {
            Map<String,Object> write = RootHelper.exec(command.toString());
            writes.add(write);
            if (!Boolean.TRUE.equals(write.get("ok"))) {
                throw new IllegalStateException("hardware_profile_stage_failed");
            }
        }
        Map<String,Object> action = new LinkedHashMap<>();
        action.put("ok", true);
        action.put("operation", "stageHardwareProfile");
        action.put("fieldCount", fields.size());
        action.put("writes", writes);
        return action;
    }

    private static Map<String,Object> stageEffectiveProfile(Context context, JSONObject profile) throws Exception {
        Map<String,Object> action = new LinkedHashMap<>();
        byte[] encoded = profile.toString().getBytes(StandardCharsets.UTF_8);
        if (encoded.length == 0 || encoded.length > 256 * 1024) {
            throw new IllegalArgumentException("effective_profile_size_invalid");
        }
        File directory = context.getNoBackupFilesDir();
        File prepared = new File(directory, ".device-profile.stage.tmp");
        File staged = new File(directory, "device-profile.stage");
        if (prepared.exists() && !prepared.delete()) {
            throw new IllegalStateException("effective_profile_prepare_failed");
        }
        try {
            try (FileOutputStream output = new FileOutputStream(prepared, false)) {
                output.write(encoded);
                output.flush();
                output.getFD().sync();
            }
            Os.chmod(prepared.getAbsolutePath(), 0600);
            try {
                Files.move(prepared.toPath(), staged.toPath(),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException failure) {
                throw new IllegalStateException("effective_profile_atomic_move_unsupported", failure);
            }
            String digest = sha256(encoded);
            boolean published = RootHelper.publishDeviceProfile(staged, encoded.length, digest);
            action.put("ok", published);
            action.put("operation", "stageEffectiveProfile");
            action.put("size", encoded.length);
            action.put("sha256", digest);
            if (!published) {
                throw new IllegalStateException("effective_profile_publish_failed");
            }
            return action;
        } finally {
            Arrays.fill(encoded, (byte) 0);
            if (prepared.exists()) prepared.delete();
            if (staged.exists()) staged.delete();
        }
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte value : digest) out.append(String.format(Locale.ROOT, "%02x", value));
        return out.toString();
    }

    private static String requiredString(JSONObject object, String key) {
        Object raw = object.opt(key);
        if (raw == null || raw == JSONObject.NULL) {
            throw new IllegalArgumentException("profile_field_required:" + key);
        }
        String value = String.valueOf(raw);
        if (value.length() == 0) {
            throw new IllegalArgumentException("profile_field_required:" + key);
        }
        return value;
    }

    private static boolean requiredBoolean(JSONObject object, String key) {
        Object raw = object.opt(key);
        if (!(raw instanceof Boolean)) {
            throw new IllegalArgumentException("profile_field_invalid:" + key);
        }
        return (Boolean) raw;
    }

    private static long requiredLong(JSONObject object, String key, long minimum, long maximum) {
        Object raw = object.opt(key);
        if (raw == null || raw == JSONObject.NULL) {
            throw new IllegalArgumentException("profile_field_required:" + key);
        }
        String text = String.valueOf(raw);
        if (!text.matches("-?[0-9]+")) {
            throw new IllegalArgumentException("profile_field_invalid:" + key);
        }
        try {
            long value = Long.parseLong(text);
            if (value < minimum || value > maximum) {
                throw new IllegalArgumentException("profile_field_out_of_range:" + key);
            }
            return value;
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("profile_field_invalid:" + key, failure);
        }
    }

    private static void validateBatteryProfile(JSONObject battery) {
        if (battery == null) {
            throw new IllegalArgumentException("battery_profile_required");
        }
        long level = requiredLong(battery, "level", 0, 100);
        long scale = requiredLong(battery, "scale", 100, 100);
        requiredLong(battery, "voltage", 1000, 6000);
        requiredLong(battery, "temperature", -500, 1000);
        long status = requiredLong(battery, "status", 1, 5);
        long plugged = requiredLong(battery, "plugged", 0, 4);
        if (plugged == 3 || (plugged == 0 && status == 2)
                || (plugged != 0 && status == 3)
                || (status == 5 && level != scale)) {
            throw new IllegalArgumentException("battery_state_inconsistent");
        }
        requiredLong(battery, "health", 1, 7);
        requiredLong(battery, "present", 0, 1);
        if (!"Li-ion".equals(requiredString(battery, "technology"))) {
            throw new IllegalArgumentException("battery_technology_invalid");
        }
        long capacityMah = requiredLong(battery, "capacityMah", 1, 100000);
        long minimumCapacityMah =
                requiredLong(battery, "minimumCapacityMah", 1, capacityMah);
        long designUah =
                requiredLong(battery, "chargeFullDesignUah", 1, 100000000);
        long fullUah = requiredLong(battery, "chargeFullUah", 1, designUah);
        long counterUah =
                requiredLong(battery, "chargeCounterUah", 0, fullUah);
        if (minimumCapacityMah > capacityMah
                || designUah != capacityMah * 1000
                || counterUah != fullUah * level / scale) {
            throw new IllegalArgumentException("battery_capacity_inconsistent");
        }
    }

    private static String batteryKernelParameter(String key) {
        if ("level".equals(key)) return "battery_level";
        if ("voltage".equals(key)) return "battery_voltage_mv";
        if ("temperature".equals(key)) return "battery_temperature_deci_c";
        if ("status".equals(key)) return "battery_status_android";
        if ("plugged".equals(key)) return "battery_plugged_android";
        if ("health".equals(key)) return "battery_health_android";
        if ("present".equals(key)) return "battery_present";
        if ("chargeFullDesignUah".equals(key)) {
            return "battery_charge_full_design_uah";
        }
        if ("chargeFullUah".equals(key)) return "battery_charge_full_uah";
        if ("chargeCounterUah".equals(key)) return "battery_charge_counter_uah";
        return null;
    }

    private static Map<String,Object> applyDisplayMetrics(
            String width, String height, String densityDpi) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("field", "display.metrics");
        out.put("value", width + "x" + height + "@" + densityDpi);
        List<Object> actions = new ArrayList<>();
        actions.add(RootHelper.exec(
                "mkdir -p /data/local/tmp/xenoid-profile && "
                + "printf %s " + RootHelper.shellQuote(width + "\n")
                + " > /data/local/tmp/xenoid-profile/display_width && "
                + "printf %s " + RootHelper.shellQuote(height + "\n")
                + " > /data/local/tmp/xenoid-profile/display_height && "
                + "printf %s " + RootHelper.shellQuote(densityDpi + "\n")
                + " > /data/local/tmp/xenoid-profile/display_density_dpi && "
                + "wm size " + RootHelper.shellQuote(width + "x" + height)
                + " && wm density " + RootHelper.shellQuote(densityDpi)));
        out.put("actions", actions);
        boolean ok = true;
        for (Object action : actions) {
            if (action instanceof Map && !Boolean.TRUE.equals(((Map<?,?>) action).get("ok"))) {
                ok = false;
            }
        }
        out.put("ok", ok);
        out.put("applied", ok);
        return out;
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
            String serial = value.trim();
            if (!serial.matches("[A-Za-z0-9][A-Za-z0-9._-]{5,31}")) {
                throw new IllegalArgumentException("serial_invalid");
            }
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
            actions.add(RootHelper.exec("setprop "
                    + RootHelper.shellQuote("persist.xenoid." + field.replace(".", "_"))
                    + " " + RootHelper.shellQuote(value)));
            actions.add(RootHelper.exec(
                    "mkdir -p /data/local/tmp/xenoid-profile && printf %s "
                    + RootHelper.shellQuote(value + "\n") + " > "
                    + RootHelper.shellQuote(
                            "/data/local/tmp/xenoid-profile/"
                            + field.replace("/", "_").replace(".", "_"))));
            String key = field.substring("battery.".length());
            String parameter = batteryKernelParameter(key);
            if (parameter != null) {
                String path = "/sys/module/xenoid_kmod/parameters/" + parameter;
                actions.add(RootHelper.exec(
                        "test ! -e " + RootHelper.shellQuote(path)
                        + " || printf %s " + RootHelper.shellQuote(value + "\n")
                        + " > " + RootHelper.shellQuote(path)));
            }
            if (refreshBattery) {
                actions.add(RootHelper.exec(
                        "test -x /data/local/tmp/xenoid-overlay-helper"
                        + " && /data/local/tmp/xenoid-overlay-helper apply"
                        + " >/data/local/tmp/xenoid-overlay.log 2>&1"));
                actions.add(RootHelper.exec(BATTERY_HEALTH_REFRESH));
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
            String outName = "densityDpi".equals(key) || "density_dpi".equals(key)
                    ? "display_density_dpi" : "display_" + key;
            actions.add(RootHelper.exec(
                    "mkdir -p /data/local/tmp/xenoid-profile && printf %s "
                    + RootHelper.shellQuote(value + "\n") + " > "
                    + RootHelper.shellQuote("/data/local/tmp/xenoid-profile/" + outName)));
            actions.add(RootHelper.exec(
                    "test -x /data/local/tmp/xenoid-overlay-helper && "
                    + "/data/local/tmp/xenoid-overlay-helper apply "
                    + ">/data/local/tmp/xenoid-overlay.log 2>&1 || true"));
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
        boolean ok = true;
        for (Object action : actions) {
            if (action instanceof Map
                    && !Boolean.TRUE.equals(((Map<?,?>) action).get("ok"))) {
                ok = false;
            }
        }
        out.put("ok", ok);
        out.put("applied", ok);
        if (!ok) out.put("error", "profile_field_apply_failed");
        return out;
    }

    private static Map<String,String> generatedUnique() {
        Map<String,String> g = new LinkedHashMap<>();
        g.put("android_id", hex(8));
        g.put("boot_id", UUID.randomUUID().toString());
        g.put("random_uuid", UUID.randomUUID().toString());
        g.put("serial", randomSerial());
        g.put("imei", randomImei());
        g.put("imeisv", "01");
        return g;
    }
    private static String randomSerial() { return hex(8).toUpperCase(Locale.ROOT); }
    private static String randomImei() {
        StringBuilder first = new StringBuilder(String.valueOf(RNG.nextInt(9) + 1));
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
