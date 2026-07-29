// Xenoid device profile Frida hook template.
// This script reads a generated profile from global XENOID_PROFILE_JSON when injected by tooling.
// Kept as a standalone asset so OTA/runtime context can ship it.

const profile = (typeof XENOID_PROFILE_JSON !== 'undefined') ? JSON.parse(XENOID_PROFILE_JSON) : {};
if (Java.available) {
  Java.perform(() => {
    const Build = Java.use('android.os.Build');
    const b = profile.build || {};
    Object.keys(b).forEach(k => {
      const field = k.toUpperCase();
      try { if (Build[field]) Build[field].value = String(b[k]); } catch (_) {}
    });
  });
}
console.log('[xenoid] profile hook loaded');
