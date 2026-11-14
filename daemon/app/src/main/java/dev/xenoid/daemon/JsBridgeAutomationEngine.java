package dev.xenoid.daemon;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;

final class JsBridgeAutomationEngine {
    private static final int TIMEOUT_MS = 30000;

    static Map<String,Object> run(Context ctx, String name, String rawScript) {
        Bridge bridge = new Bridge();
        Handler main = new Handler(Looper.getMainLooper());
        WebView[] web = new WebView[1];
        try {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                bridge.fail("automation_main_thread");
            } else {
                String source = new JSONObject(rawScript).getString("script");
                main.post(() -> {
                    if (bridge.finished()) return;
                    try {
                        web[0] = new WebView(ctx);
                        web[0].getSettings().setJavaScriptEnabled(true);
                        web[0].getSettings().setAllowFileAccess(false);
                        web[0].getSettings().setAllowContentAccess(false);
                        web[0].getSettings().setBlockNetworkLoads(true);
                        web[0].addJavascriptInterface(bridge, "xenoidNative");
                        web[0].setWebViewClient(new WebViewClient() {
                            private boolean started;
                            @Override public void onPageFinished(WebView view, String url) {
                                if (started || bridge.finished()) return;
                                started = true;
                                view.evaluateJavascript(wrap(source), null);
                            }
                        });
                        web[0].loadDataWithBaseURL("https://xenoid.invalid/",
                                "<!doctype html><html></html>", "text/html", "UTF-8", null);
                    } catch (Exception failure) {
                        bridge.fail("automation_webview_failed");
                    }
                });
                if (!bridge.done.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    bridge.fail("automation_timeout");
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            bridge.fail("automation_cancelled");
        } catch (Exception failure) {
            bridge.fail("automation_script_invalid");
        } finally {
            bridge.connection.cancel();
            main.post(() -> {
                if (web[0] != null) {
                    web[0].removeJavascriptInterface("xenoidNative");
                    web[0].destroy();
                }
            });
        }
        Map<String,Object> out = bridge.snapshot();
        out.put("taskId", UUID.randomUUID().toString());
        out.put("name", name);
        out.put("language", "js-webview-bridge");
        return out;
    }

    private static String wrap(String source) {
        return "(async()=>{let url;try{" +
            "const call=(value)=>{const r=JSON.parse(value);" +
            "if(r.ok!==true)throw new Error('automation_action_failed');return r;};" +
            "const xenoid={" +
            "tap:async(x,y)=>call(xenoidNative.tap(x,y))," +
            "swipe:async(x1,y1,x2,y2,d=300)=>call(xenoidNative.swipe(x1,y1,x2,y2,d))," +
            "sleep:async(ms)=>call(xenoidNative.sleep(ms))," +
            "shell:async(c)=>call(xenoidNative.shell(String(c)))," +
            "launch:async(c)=>call(xenoidNative.launch(String(c)))," +
            "install:async(p)=>call(xenoidNative.install(String(p)))," +
            "uninstall:async(p)=>call(xenoidNative.uninstall(String(p)))," +
            "set:async(f,v)=>call(xenoidNative.set(String(f),String(v)))" +
            "};url=URL.createObjectURL(new Blob([" + JSONObject.quote(source) +
            "],{type:'text/javascript'}));const mod=await import(url);" +
            "if(typeof mod.default!=='function')throw new Error('missing task');" +
            "const result=await mod.default(xenoid);" +
            "xenoidNative.complete(JSON.stringify({ok:!(result&&result.ok===false),result}));" +
            "}catch(e){xenoidNative.complete(JSON.stringify({ok:false,error:'automation_script_failed'}));}" +
            "finally{if(url)URL.revokeObjectURL(url);}})()";
    }

    static final class Bridge {
        final CountDownLatch done = new CountDownLatch(1);
        final RootHelper.ConnectionHandle connection = RootHelper.newConnectionHandle();
        private final List<Object> steps = new ArrayList<>();
        private final Map<String,Object> result = new LinkedHashMap<>();

        Bridge() { connection.setTimeoutCapMs(TIMEOUT_MS); }

        synchronized boolean finished() { return done.getCount() == 0; }

        synchronized void fail(String error) {
            if (finished()) return;
            result.put("ok", false);
            result.put("error", error);
            done.countDown();
        }

        synchronized Map<String,Object> snapshot() {
            Map<String,Object> out = new LinkedHashMap<>(result);
            out.put("steps", new ArrayList<>(steps));
            return out;
        }

        @JavascriptInterface public synchronized void complete(String value) {
            if (finished()) return;
            try {
                JSONObject completion = new JSONObject(value);
                result.put("ok", completion.getBoolean("ok"));
                result.put("result", completion.opt("result"));
                if (!completion.getBoolean("ok")) result.put("error", "automation_script_failed");
                done.countDown();
            } catch (Exception invalid) {
                fail("automation_result_invalid");
            }
        }

        private String step(Callable<Map<String,Object>> action) {
            if (finished()) return "{\"ok\":false,\"error\":\"automation_finished\"}";
            Map<String,Object> value;
            try (RootHelper.ConnectionScope ignored = RootHelper.bindConnectionHandle(connection)) {
                value = action.call();
            } catch (Exception failure) {
                value = new LinkedHashMap<>();
                value.put("ok", false);
                value.put("error", "automation_action_failed");
            }
            synchronized (this) {
                if (!finished()) {
                    steps.add(value);
                    if (!Boolean.TRUE.equals(value.get("ok"))) fail("automation_action_failed");
                }
            }
            return Json.stringify(value);
        }

        @JavascriptInterface public String tap(int x, int y) { return step(() -> RootHelper.inputTap(x, y)); }
        @JavascriptInterface public String swipe(int x1, int y1, int x2, int y2, int d) { return step(() -> RootHelper.inputSwipe(x1, y1, x2, y2, d)); }
        @JavascriptInterface public String sleep(int ms) {
            return step(() -> {
                if (ms < 0) throw new IllegalArgumentException();
                Map<String,Object> value = new LinkedHashMap<>();
                value.put("ok", !done.await(ms, TimeUnit.MILLISECONDS));
                value.put("sleepMs", ms);
                return value;
            });
        }
        @JavascriptInterface public String shell(String command) { return step(() -> RootHelper.exec(command)); }
        @JavascriptInterface public String launch(String component) { return step(() -> RootHelper.launchComponent(component)); }
        @JavascriptInterface public String install(String path) { return step(() -> RootHelper.installApk(path)); }
        @JavascriptInterface public String uninstall(String name) { return step(() -> RootHelper.uninstallPackage(name)); }
        @JavascriptInterface public String set(String field, String value) { return step(() -> DeviceProfileManager.setField(field, value)); }
    }
}
