package org.example.cellularruntimeprobe;

import android.Manifest;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.telephony.CellIdentityLte;
import android.telephony.CellInfo;
import android.telephony.CellInfoLte;
import android.telephony.CellSignalStrengthLte;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public final class ProbeActivity extends Activity {
    private static final String TAG = "XenoidCellularProbe";
    private static final int PERMISSIONS = 1;
    private static final int ISOLATED_RESULT = 2;
    private static final long ISOLATED_TIMEOUT_MS = 10000;
    private static boolean emitted;
    private boolean isolationStarted;
    private List<CellInfo> requestedCells;

    static {
        System.loadLibrary("cellular_runtime_probe");
    }

    static native String nativeProbe();

    private final Handler handler = new Handler(Looper.getMainLooper(), message -> {
        if (message.what != ISOLATED_RESULT || emitted) return false;
        Bundle data = message.getData();
        JSONObject isolated = new JSONObject();
        try {
            isolated.put("ok", data.getBoolean("ok", false));
            if (data.containsKey("native")) isolated.put("native", new JSONObject(data.getString("native")));
            if (data.containsKey("error")) isolated.put("error", data.getString("error"));
        } catch (Exception error) {
            try { isolated.put("ok", false).put("error", error.getClass().getSimpleName()); } catch (Exception ignored) { }
        }
        emit(collect(isolated));
        return true;
    });

    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            try {
                Message request = Message.obtain(null, IsolationProbeService.MSG_PROBE);
                request.replyTo = new Messenger(handler);
                new Messenger(service).send(request);
            } catch (Exception error) {
                emit(collect(errorObject(error)));
            }
        }
        @Override public void onServiceDisconnected(ComponentName name) { }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.READ_PHONE_NUMBERS) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {
                    Manifest.permission.READ_PHONE_STATE,
                    Manifest.permission.READ_PHONE_NUMBERS,
                    Manifest.permission.ACCESS_COARSE_LOCATION,
                    Manifest.permission.ACCESS_FINE_LOCATION,
            }, PERMISSIONS);
            return;
        }
        startProbe();
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (requestCode != PERMISSIONS) return;
        for (int grant : grants) {
            if (grant != PackageManager.PERMISSION_GRANTED) {
                emit(errorResult("permission_denied"));
                return;
            }
        }
        startProbe();
    }

    private void startProbe() {
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        try {
            manager.requestCellInfoUpdate(getMainExecutor(), new TelephonyManager.CellInfoCallback() {
                @Override public void onCellInfo(List<CellInfo> values) {
                    requestedCells = values;
                    bindIsolation();
                }
                @Override public void onError(int errorCode, Throwable detail) {
                    bindIsolation();
                }
            });
        } catch (Exception ignored) {
            bindIsolation();
        }
        handler.postDelayed(this::bindIsolation, 5000);
        handler.postDelayed(() -> {
            if (!emitted) emit(errorResult("isolated_timeout"));
        }, ISOLATED_TIMEOUT_MS);
    }

    private void bindIsolation() {
        if (isolationStarted || emitted) return;
        isolationStarted = true;
        Intent intent = new Intent(this, IsolationProbeService.class);
        if (!bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            emit(errorResult("isolated_bind_failed"));
        }
    }

    private JSONObject collect(JSONObject isolated) {
        JSONObject result = new JSONObject();
        try {
            result.put("schema", "dev.xenoid.cellular-runtime-probe/v2");
            result.put("ok", true);
            result.put("telephony", collectTelephony());
            result.put("connectivity", collectConnectivity());
            result.put("javaIfaces", javaInterfaces());
            result.put("native", new JSONObject(nativeProbe()));
            result.put("isolated", isolated);
        } catch (Exception error) {
            Log.e(TAG, "ordinary cellular probe failed", error);
            return errorResult(error.getClass().getSimpleName());
        }
        return result;
    }

    private JSONObject collectTelephony() throws Exception {
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        JSONObject out = new JSONObject();
        out.put("simState", manager.getSimState());
        out.put("simOperator", manager.getSimOperator());
        out.put("simOperatorName", manager.getSimOperatorName());
        out.put("networkOperator", manager.getNetworkOperator());
        out.put("networkOperatorName", manager.getNetworkOperatorName());
        out.put("networkCountryIso", manager.getNetworkCountryIso());
        out.put("dataNetworkType", manager.getDataNetworkType());
        try {
            String line1 = manager.getLine1Number();
            out.put("line1Number", line1 == null ? JSONObject.NULL : line1);
        } catch (SecurityException error) {
            out.put("line1Number", JSONObject.NULL);
            out.put("line1Error", "security");
        }
        SubscriptionManager subscriptions = (SubscriptionManager) getSystemService(TELEPHONY_SUBSCRIPTION_SERVICE);
        List<SubscriptionInfo> active = subscriptions.getActiveSubscriptionInfoList();
        out.put("subscriptionCount", active == null ? 0 : active.size());
        if (active != null && active.size() == 1) {
            String number = active.get(0).getNumber();
            out.put("subscriptionNumber", number == null ? JSONObject.NULL : number);
        }
        JSONArray cells = new JSONArray();
        List<CellInfo> all = requestedCells != null ? requestedCells : manager.getAllCellInfo();
        if (all != null) for (CellInfo item : all) {
            if (!(item instanceof CellInfoLte)) continue;
            CellInfoLte lte = (CellInfoLte) item;
            CellIdentityLte identity = lte.getCellIdentity();
            CellSignalStrengthLte signal = lte.getCellSignalStrength();
            JSONObject cell = new JSONObject();
            cell.put("registered", lte.isRegistered());
            cell.put("mcc", identity.getMccString());
            cell.put("mnc", identity.getMncString());
            cell.put("tac", identity.getTac());
            cell.put("ci", identity.getCi());
            cell.put("pci", identity.getPci());
            cell.put("earfcn", identity.getEarfcn());
            JSONArray bands = new JSONArray();
            for (int band : identity.getBands()) bands.put(band);
            cell.put("bands", bands);
            cell.put("rsrp", signal.getRsrp());
            cell.put("rsrq", signal.getRsrq());
            cell.put("rssnr", signal.getRssnr());
            cells.put(cell);
        }
        out.put("lteCells", cells);
        return out;
    }

    private JSONObject collectConnectivity() throws Exception {
        ConnectivityManager manager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        JSONObject out = new JSONObject();
        int cellular = 0;
        int ethernet = 0;
        JSONArray interfaces = new JSONArray();
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities == null) continue;
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) cellular++;
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) ethernet++;
            LinkProperties link = manager.getLinkProperties(network);
            if (link != null && link.getInterfaceName() != null) interfaces.put(link.getInterfaceName());
        }
        Network active = manager.getActiveNetwork();
        NetworkCapabilities activeCapabilities = active == null ? null : manager.getNetworkCapabilities(active);
        out.put("cellularCount", cellular);
        out.put("ethernetCount", ethernet);
        out.put("activeCellular", activeCapabilities != null
                && activeCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
        out.put("activeEthernet", activeCapabilities != null
                && activeCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
        out.put("interfaces", interfaces);
        return out;
    }

    private static JSONArray javaInterfaces() throws Exception {
        JSONArray out = new JSONArray();
        Enumeration<NetworkInterface> values = NetworkInterface.getNetworkInterfaces();
        if (values == null) return out;
        for (NetworkInterface value : Collections.list(values)) out.put(value.getName());
        return out;
    }

    private static JSONObject errorObject(Exception error) {
        return errorResult(error.getClass().getSimpleName());
    }

    private static JSONObject errorResult(String code) {
        JSONObject out = new JSONObject();
        try { out.put("ok", false).put("error", code); } catch (Exception ignored) { }
        return out;
    }

    private void emit(JSONObject result) {
        if (emitted) return;
        emitted = true;
        Log.i(TAG, result.toString());
        try { unbindService(connection); } catch (Exception ignored) { }
        finish();
    }
}
