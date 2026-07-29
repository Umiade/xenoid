package dev.xenoid.daemon;

import android.app.*; import android.content.*; import android.os.*;

public class MainActivity extends Activity {
    protected void onCreate(Bundle b) { super.onCreate(b); startForegroundService(new Intent(this, XenoidDaemonService.class)); moveTaskToBack(true); finish(); }
}
