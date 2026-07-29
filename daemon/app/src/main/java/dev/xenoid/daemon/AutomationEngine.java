package dev.xenoid.daemon;

import java.util.*;
import java.util.regex.*;

final class AutomationEngine {
    static Map<String,Object> run(android.content.Context ctx, String name, String script) {
        Map<String,Object> bridge = JsBridgeAutomationEngine.run(ctx, name, script);
        if (Boolean.TRUE.equals(bridge.get("ok"))) return bridge;
        Map<String,Object> fallback = runSubset(name, script);
        fallback.put("bridgeAttempt", bridge);
        return fallback;
    }

    static Map<String,Object> runSubset(String name, String script) {
        Map<String,Object> out = new LinkedHashMap<>();
        List<Object> steps = new ArrayList<>();
        String source = SimpleJson.stringValue(script, "script", script);
        List<Action> actions = parseActions(source);
        Collections.sort(actions, new Comparator<Action>() { public int compare(Action a, Action b) { return a.index - b.index; }});
        for (Action a : actions) steps.add(a.run());
        out.put("ok", true);
        out.put("taskId", UUID.randomUUID().toString());
        out.put("name", name);
        out.put("language", "js-subset");
        out.put("parsedActions", actions.size());
        out.put("steps", steps);
        out.put("accepted", true);
        out.put("note", "Executed ordered automation actions with the compatibility runner.");
        return out;
    }

    private static List<Action> parseActions(String source) {
        List<Action> actions = new ArrayList<>();
        Matcher tap = Pattern.compile("xenoid\\.tap\\s*\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*\\)").matcher(source);
        while (tap.find()) actions.add(new TapAction(tap.start(), Integer.parseInt(tap.group(1)), Integer.parseInt(tap.group(2))));
        Matcher swipe = Pattern.compile("xenoid\\.swipe\\s*\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*(\\d+))?\\s*\\)").matcher(source);
        while (swipe.find()) actions.add(new SwipeAction(swipe.start(), Integer.parseInt(swipe.group(1)), Integer.parseInt(swipe.group(2)), Integer.parseInt(swipe.group(3)), Integer.parseInt(swipe.group(4)), swipe.group(5) == null ? 300 : Integer.parseInt(swipe.group(5))));
        Matcher sleep = Pattern.compile("xenoid\\.sleep\\s*\\(\\s*(\\d+)\\s*\\)").matcher(source);
        while (sleep.find()) actions.add(new SleepAction(sleep.start(), Integer.parseInt(sleep.group(1))));
        addStringActions(actions, source, "launch", 1);
        addStringActions(actions, source, "install", 2);
        addStringActions(actions, source, "uninstall", 3);
        addStringActions(actions, source, "shell", 4);
        return actions;
    }

    private static void addStringActions(List<Action> actions, String source, String method, int op) {
        Matcher m = Pattern.compile("xenoid\\." + method + "\\s*\\(\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*\\)").matcher(source);
        while (m.find()) actions.add(new StringAction(m.start(), method, op, m.group(1)));
    }

    private static abstract class Action { final int index; Action(int index){this.index=index;} abstract Object run(); }
    private static final class TapAction extends Action { final int x,y; TapAction(int i,int x,int y){super(i);this.x=x;this.y=y;} Object run(){return RootHelper.inputTap(x,y);} }
    private static final class SwipeAction extends Action { final int x1,y1,x2,y2,d; SwipeAction(int i,int x1,int y1,int x2,int y2,int d){super(i);this.x1=x1;this.y1=y1;this.x2=x2;this.y2=y2;this.d=d;} Object run(){return RootHelper.inputSwipe(x1,y1,x2,y2,d);} }
    private static final class SleepAction extends Action { final int ms; SleepAction(int i,int ms){super(i);this.ms=ms;} Object run(){Map<String,Object> m=new LinkedHashMap<>(); try{Thread.sleep(ms);m.put("ok",true);}catch(Exception e){m.put("ok",false);m.put("error",e.toString());} m.put("sleepMs",ms); return m;} }
    private static final class StringAction extends Action { final String method,value; final int op; StringAction(int i,String method,int op,String value){super(i);this.method=method;this.op=op;this.value=value;} Object run(){ if(op==1)return RootHelper.launchComponent(value); if(op==2)return RootHelper.installApk(value); if(op==3)return RootHelper.uninstallPackage(value); if(op==4)return RootHelper.exec(value); Map<String,Object> m=new LinkedHashMap<>();m.put("ok",false);m.put("method",method);m.put("value",value);return m;} }
}
