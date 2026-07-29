package dev.xenoid.daemon;
import android.content.*;
public class BootReceiver extends BroadcastReceiver { public void onReceive(Context c, Intent i) { c.startForegroundService(new Intent(c, XenoidDaemonService.class)); } }
