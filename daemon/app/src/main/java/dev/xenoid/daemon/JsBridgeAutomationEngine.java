package dev.xenoid.daemon;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import java.util.*;
import java.util.concurrent.*;

final class JsBridgeAutomationEngine {
    static Map<String,Object> run(Context ctx, String name, String rawScript) {
        Map<String,Object> out = new LinkedHashMap<>();
        if (Looper.myLooper() == Looper.getMainLooper()) {
            out.put("ok", false); out.put("error", "JS bridge cannot block main looper"); return out;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final List<Object> steps = Collections.synchronizedList(new ArrayList<Object>());
        final Map<String,Object> result = Collections.synchronizedMap(new LinkedHashMap<String,Object>());
        String source = SimpleJson.stringValue(rawScript, "script", rawScript);
        new Handler(Looper.getMainLooper()).post(new Runnable() { public void run() {
            try {
                WebView web = new WebView(ctx);
                WebSettings settings = web.getSettings();
                settings.setJavaScriptEnabled(true);
                settings.setAllowFileAccess(false);
                settings.setAllowContentAccess(false);
                Bridge bridge = new Bridge(steps);
                web.addJavascriptInterface(bridge, "xenoidNative");
                String wrapped = wrap(source);
                web.evaluateJavascript(wrapped, value -> { result.put("value", value); result.put("ok", true); latch.countDown(); });
            } catch (Throwable t) { result.put("ok", false); result.put("error", t.toString()); latch.countDown(); }
        }});
        try { latch.await(30, TimeUnit.SECONDS); } catch (Exception e) { result.put("ok", false); result.put("error", e.toString()); }
        out.put("ok", Boolean.TRUE.equals(result.get("ok")));
        out.put("taskId", UUID.randomUUID().toString());
        out.put("name", name);
        out.put("language", "js-webview-bridge");
        out.put("steps", new ArrayList<Object>(steps));
        out.put("result", new LinkedHashMap<String,Object>(result));
        return out;
    }

    private static String wrap(String source) {
        String escaped = source.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${");
        return "(async function(){"+
            "const xenoid={"+
            "tap:async(x,y)=>JSON.parse(xenoidNative.tap(x,y)),"+
            "swipe:async(x1,y1,x2,y2,d)=>JSON.parse(xenoidNative.swipe(x1,y1,x2,y2,d||300)),"+
            "sleep:async(ms)=>JSON.parse(xenoidNative.sleep(ms)),"+
            "shell:async(c)=>JSON.parse(xenoidNative.shell(String(c))),"+
            "launch:async(c)=>JSON.parse(xenoidNative.launch(String(c))),"+
            "install:async(p)=>JSON.parse(xenoidNative.install(String(p))),"+
            "uninstall:async(p)=>JSON.parse(xenoidNative.uninstall(String(p))),"+
            "set:async(f,v)=>JSON.parse(xenoidNative.set(String(f),String(v)))"+
            "};"+
            "let module={exports:{}};let exports=module.exports;"+
            "let __src=`"+escaped+"`;"+
            "__src=__src.replace(/export\\s+default\\s+async\\s+function\\s+task/, 'async function task');"+
            "__src=__src.replace(/export\\s+default\\s+function\\s+task/, 'function task');"+
            "eval(__src);"+
            "if(typeof task==='function') return await task(xenoid);"+
            "return {ok:false,error:'missing task function'};"+
            "})()";
    }

    static final class Bridge {
        final List<Object> steps;
        Bridge(List<Object> steps) { this.steps = steps; }
        @JavascriptInterface public String tap(int x, int y) { Map<String,Object> r = RootHelper.inputTap(x,y); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String swipe(int x1, int y1, int x2, int y2, int d) { Map<String,Object> r = RootHelper.inputSwipe(x1,y1,x2,y2,d); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String sleep(int ms) { Map<String,Object> r = new LinkedHashMap<>(); try { Thread.sleep(ms); r.put("ok", true); } catch(Exception e) { r.put("ok", false); r.put("error", e.toString()); } r.put("sleepMs", ms); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String shell(String c) { Map<String,Object> r = RootHelper.exec(c); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String launch(String c) { Map<String,Object> r = RootHelper.launchComponent(c); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String install(String p) { Map<String,Object> r = RootHelper.installApk(p); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String uninstall(String p) { Map<String,Object> r = RootHelper.uninstallPackage(p); steps.add(r); return Json.stringify(r); }
        @JavascriptInterface public String set(String f, String v) { Map<String,Object> r = DeviceProfileManager.setField(f, v); steps.add(r); return Json.stringify(r); }
    }
}
