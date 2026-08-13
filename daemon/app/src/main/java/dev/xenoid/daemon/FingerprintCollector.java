package dev.xenoid.daemon;

import android.content.*;
import android.hardware.*;
import android.os.*;
import android.provider.Settings;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class FingerprintCollector {
    static Map<String, Object> collect(Context ctx) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> build = new LinkedHashMap<>();
        build.put("brand", Build.BRAND);
        build.put("manufacturer", Build.MANUFACTURER);
        build.put("model", Build.MODEL);
        build.put("device", Build.DEVICE);
        build.put("product", Build.PRODUCT);
        build.put("fingerprint", Build.FINGERPRINT);
        build.put("hardware", Build.HARDWARE);
        build.put("board", Build.BOARD);
        build.put("bootloader", Build.BOOTLOADER);
        build.put("display", Build.DISPLAY);
        build.put("host", Build.HOST);
        build.put("id", Build.ID);
        build.put("tags", Build.TAGS);
        build.put("type", Build.TYPE);
        build.put("user", Build.USER);
        build.put("soc_manufacturer", Build.SOC_MANUFACTURER);
        build.put("soc_model", Build.SOC_MODEL);
        build.put("sku", Build.SKU);
        build.put("odm_sku", Build.ODM_SKU);
        build.put("incremental", Build.VERSION.INCREMENTAL);
        build.put("release", Build.VERSION.RELEASE);
        build.put("sdk", String.valueOf(Build.VERSION.SDK_INT));
        build.put("security_patch", Build.VERSION.SECURITY_PATCH);
        build.put("first_api_level", readProperty("ro.product.first_api_level"));
        build.put("abi", Build.SUPPORTED_64_BIT_ABIS.length > 0
                ? Build.SUPPORTED_64_BIT_ABIS[0]
                : (Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : null));
        build.put("abilist", join(Build.SUPPORTED_ABIS));
        build.put("abilist32", join(Build.SUPPORTED_32_BIT_ABIS));
        build.put("abilist64", join(Build.SUPPORTED_64_BIT_ABIS));
        out.put("build", build);
        Map<String, Object> ids = new LinkedHashMap<>();
        ids.put("android_id", Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID));
        ids.put("boot_id", readFirst("/proc/sys/kernel/random/boot_id"));
        try { ids.put("serial", Build.getSerial()); } catch (Exception e) { ids.put("serial", null); }
        out.put("ids", ids);
        out.put("battery", battery(ctx));
        out.put("network", network());
        out.put("display", display(ctx));
        out.put("sensors", sensors(ctx));
        out.put("sensorEventSamples", sensorEventSamples(ctx));
        out.put("locale", Locale.getDefault().toLanguageTag());
        out.put("timezone", TimeZone.getDefault().getID());
        out.put("schema", "dev.xenoid.fingerprint/v1");
        return out;
    }
    private static String readFirst(String p) { try (BufferedReader r = new BufferedReader(new FileReader(p))) { return r.readLine(); } catch(Exception e) { return null; } }
    private static String readProperty(String key) {
        try {
            java.lang.Process process = new ProcessBuilder("/system/bin/getprop", key).start();
            String value;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                value = reader.readLine();
            }
            if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly();
            return value;
        } catch (Exception ignored) {
            return null;
        }
    }
    private static String join(String[] a) { StringBuilder sb = new StringBuilder(); if (a != null) for (String x : a) { if (sb.length() > 0) sb.append(','); sb.append(x); } return sb.toString(); }
    private static String macBytes(byte[] b) { if (b == null || b.length < 6) return null; StringBuilder sb = new StringBuilder(); for (int i=0;i<6;i++) { if (i>0) sb.append(':'); sb.append(String.format(Locale.US, "%02x", b[i] & 0xff)); } return sb.toString(); }
    private static Map<String,Object> network() {
        Map<String,Object> n = new LinkedHashMap<>();
        n.put("mac", readFirst("/sys/class/net/rmnet_data0/address"));
        try {
            NetworkInterface ni = NetworkInterface.getByName("rmnet_data0");
            if (ni != null) { n.put("netif_mac", macBytes(ni.getHardwareAddress())); n.put("mtu", ni.getMTU()); n.put("virtual", ni.isVirtual()); n.put("up", ni.isUp()); }
        } catch (Exception ignored) {}
        return n;
    }
    private static Map<String,Object> battery(Context ctx) {
        Intent intent = ctx.registerReceiver(
                null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        Map<String,Object> battery = new LinkedHashMap<>();
        if (intent == null) return battery;
        battery.put("level", intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1));
        battery.put("scale", intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1));
        battery.put("voltage", intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1));
        battery.put(
                "temperature",
                intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1));
        battery.put("status", intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1));
        battery.put("plugged", intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1));
        battery.put("health", intent.getIntExtra(BatteryManager.EXTRA_HEALTH, -1));
        battery.put("present", intent.getBooleanExtra(BatteryManager.EXTRA_PRESENT, false));
        battery.put("technology", intent.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY));
        BatteryManager manager =
                (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
        if (manager != null) {
            battery.put(
                    "capacityPercent",
                    manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY));
            battery.put(
                    "chargeCounterUah",
                    manager.getIntProperty(
                            BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER));
        }
        return battery;
    }
    private static Map<String,Object> display(Context ctx) {
        DisplayMetrics dm = new DisplayMetrics(); ((WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE)).getDefaultDisplay().getRealMetrics(dm);
        Map<String,Object> d = new LinkedHashMap<>(); d.put("width", dm.widthPixels); d.put("height", dm.heightPixels); d.put("densityDpi", dm.densityDpi); d.put("density", dm.density); return d;
    }
    private static List<Map<String,Object>> sensors(Context ctx) {
        SensorManager manager =
                (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        List<Map<String,Object>> sensors = new ArrayList<>();
        for (Sensor sensor : manager.getSensorList(Sensor.TYPE_ALL)) {
            Map<String,Object> value = new LinkedHashMap<>();
            value.put("name", sensor.getName());
            value.put("vendor", sensor.getVendor());
            value.put("type", sensor.getType());
            value.put("typeString", sensor.getStringType());
            value.put("version", sensor.getVersion());
            value.put("powerMa", sensor.getPower());
            value.put("resolution", sensor.getResolution());
            value.put("maximumRange", sensor.getMaximumRange());
            value.put("minimumDelayUs", sensor.getMinDelay());
            value.put("maximumDelayUs", sensor.getMaxDelay());
            value.put(
                    "fifoReservedEventCount",
                    sensor.getFifoReservedEventCount());
            value.put("fifoMaxEventCount", sensor.getFifoMaxEventCount());
            value.put("reportingMode", sensor.getReportingMode());
            value.put("wakeUp", sensor.isWakeUpSensor());
            sensors.add(value);
        }
        return sensors;
    }
    private static List<Map<String,Object>> sensorEventSamples(Context ctx) {
        SensorManager manager =
                (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        Sensor accelerometer = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
        Sensor rearLight = null;
        for (Sensor sensor : manager.getSensorList(Sensor.TYPE_ALL)) {
            if (sensor.getType() == 65545) {
                rearLight = sensor;
                break;
            }
        }
        List<Map<String,Object>> samples = new ArrayList<>();
        samples.add(sensorEventSample(manager, accelerometer, Sensor.TYPE_ACCELEROMETER));
        samples.add(sensorEventSample(manager, rearLight, 65545));
        return samples;
    }

    private static Map<String,Object> sensorEventSample(
            SensorManager manager, Sensor sensor, int requestedType) {
        Map<String,Object> sample = new LinkedHashMap<>();
        sample.put("requestedType", requestedType);
        if (sensor == null) {
            sample.put("registered", false);
            sample.put("eventReceived", false);
            return sample;
        }
        sample.put("sensor", sensor.getName());
        sample.put("type", sensor.getType());
        sample.put("typeString", sensor.getStringType());
        HandlerThread thread = new HandlerThread(
                "xenoid-sensor-sample-" + requestedType);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<SensorEvent> observed = new AtomicReference<>();
        SensorEventListener listener = new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent event) {
                if (observed.compareAndSet(null, event)) latch.countDown();
            }
            @Override public void onAccuracyChanged(
                    Sensor ignored, int accuracy) {}
        };
        thread.start();
        boolean registered = manager.registerListener(
                listener,
                sensor,
                SensorManager.SENSOR_DELAY_GAME,
                new Handler(thread.getLooper()));
        try {
            if (registered) latch.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
        } finally {
            manager.unregisterListener(listener);
            thread.quitSafely();
        }
        SensorEvent event = observed.get();
        sample.put("registered", registered);
        sample.put("eventReceived", event != null);
        if (event != null) {
            sample.put("timestamp", event.timestamp);
            List<Float> values = new ArrayList<>();
            for (float value : event.values) values.add(value);
            sample.put("values", values);
        }
        return sample;
    }
}
