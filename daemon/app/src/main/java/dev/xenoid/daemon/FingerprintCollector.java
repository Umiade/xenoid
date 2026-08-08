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
        build.put("brand", Build.BRAND); build.put("manufacturer", Build.MANUFACTURER); build.put("model", Build.MODEL);
        build.put("device", Build.DEVICE); build.put("product", Build.PRODUCT); build.put("fingerprint", Build.FINGERPRINT);
        build.put("hardware", Build.HARDWARE); build.put("board", Build.BOARD); build.put("bootloader", Build.BOOTLOADER);
        build.put("host", Build.HOST); build.put("id", Build.ID); build.put("tags", Build.TAGS); build.put("type", Build.TYPE);
        build.put("abi", Build.SUPPORTED_64_BIT_ABIS.length > 0 ? Build.SUPPORTED_64_BIT_ABIS[0] : (Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : null));
        build.put("abilist", join(Build.SUPPORTED_ABIS)); build.put("abilist32", join(Build.SUPPORTED_32_BIT_ABIS)); build.put("abilist64", join(Build.SUPPORTED_64_BIT_ABIS));
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
        out.put("sensorEventSample", sensorEventSample(ctx));
        out.put("locale", Locale.getDefault().toLanguageTag());
        out.put("timezone", TimeZone.getDefault().getID());
        out.put("schema", "dev.xenoid.fingerprint/v1");
        return out;
    }
    private static String readFirst(String p) { try (BufferedReader r = new BufferedReader(new FileReader(p))) { return r.readLine(); } catch(Exception e) { return null; } }
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
        Intent i = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        Map<String,Object> b = new LinkedHashMap<>(); if (i == null) return b;
        b.put("level", i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)); b.put("scale", i.getIntExtra(BatteryManager.EXTRA_SCALE, -1));
        b.put("voltage", i.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1)); b.put("temperature", i.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1));
        b.put("status", i.getIntExtra(BatteryManager.EXTRA_STATUS, -1)); b.put("plugged", i.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1));
        return b;
    }
    private static Map<String,Object> display(Context ctx) {
        DisplayMetrics dm = new DisplayMetrics(); ((WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE)).getDefaultDisplay().getRealMetrics(dm);
        Map<String,Object> d = new LinkedHashMap<>(); d.put("width", dm.widthPixels); d.put("height", dm.heightPixels); d.put("densityDpi", dm.densityDpi); d.put("density", dm.density); return d;
    }
    private static List<Map<String,Object>> sensors(Context ctx) {
        SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE); List<Map<String,Object>> arr = new ArrayList<>();
        for (Sensor s : sm.getSensorList(Sensor.TYPE_ALL)) { Map<String,Object> m = new LinkedHashMap<>(); m.put("name", s.getName()); m.put("vendor", s.getVendor()); m.put("type", s.getType()); m.put("version", s.getVersion()); m.put("power", s.getPower()); m.put("resolution", s.getResolution()); m.put("maxRange", s.getMaximumRange()); arr.add(m); }
        return arr;
    }
    private static Map<String,Object> sensorEventSample(Context ctx) {
        Map<String,Object> sample = new LinkedHashMap<>();
        SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        Sensor sensor = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
        if (sensor == null) {
            sample.put("registered", false);
            sample.put("eventReceived", false);
            return sample;
        }
        HandlerThread thread = new HandlerThread("xenoid-sensor-sample");
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<SensorEvent> observed = new AtomicReference<>();
        SensorEventListener listener = new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent event) {
                if (observed.compareAndSet(null, event)) latch.countDown();
            }
            @Override public void onAccuracyChanged(Sensor ignored, int accuracy) {}
        };
        thread.start();
        boolean registered = sm.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_GAME,
                                                 new Handler(thread.getLooper()));
        try {
            if (registered) latch.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            sm.unregisterListener(listener);
            thread.quitSafely();
        }
        SensorEvent event = observed.get();
        sample.put("registered", registered);
        sample.put("eventReceived", event != null);
        sample.put("sensor", sensor.getName());
        if (event != null) {
            sample.put("timestamp", event.timestamp);
            List<Float> values = new ArrayList<>();
            for (float value : event.values) values.add(value);
            sample.put("values", values);
        }
        return sample;
    }
}
