// Xenoid default Frida hook policy.
// Loaded by: frida -U -f <package> -l /data/local/tmp/xenoid-frida/xenoid-default.js
// Hides common root/hook markers. Device identity comes from generated profile
// hooks; sensor inventory comes from the system AIDL sensor HAL.

const XENOID = {
  hiddenPaths: [
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
    '/sbin/.magisk', '/debug_ramdisk/.magisk', '/data/adb/magisk',
    '/data/local/tmp/frida-server', '/data/local/tmp/.fs64',
    '/data/local/tmp/xenoid-hide-helper',
    '/data/local/tmp/xenoid-frida', '/data/local/tmp/xenoid-rootd',
    '/data/local/tmp/.netd-helper'
  ],
  hiddenNeedles: ['frida', 'magisk', 'zygisk', 'lsposed', 'xposed', 'substrate', 'adbd', 'gum-js-loop', 'xenoid'],
  props: {
    'ro.debuggable': '0',
    'ro.secure': '1',
    'ro.build.tags': 'release-keys',
    'ro.adb.secure': '1',
    'service.adb.tcp.port': '-1',
    'init.svc.adbd': 'stopped'
  }
};

function containsHiddenNeedle(s) {
  if (!s) return false;
  const lower = String(s).toLowerCase();
  return XENOID.hiddenNeedles.some(n => lower.indexOf(n) >= 0);
}

function shouldHidePath(path) {
  if (!path) return false;
  const s = String(path);
  return XENOID.hiddenPaths.indexOf(s) >= 0 || containsHiddenNeedle(s);
}

function resolveExport(moduleName, name) {
  // Frida 17 removed Module.findExportByName; prefer module-scoped lookup.
  try {
    const mod = Process.getModuleByName(moduleName);
    if (mod && typeof mod.findExportByName === 'function') {
      const addr = mod.findExportByName(name);
      if (addr) return addr;
    }
  } catch (_) {}
  if (typeof Module.getGlobalExportByName === 'function') {
    try { return Module.getGlobalExportByName(name); } catch (_) {}
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(moduleName, name); } catch (_) {}
  }
  return null;
}

function hookLibc() {
  ['access', 'stat', 'lstat', 'faccessat', 'open', 'openat'].forEach(name => {
    const addr = resolveExport('libc.so', name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        this.hide = false;
        try {
          const pathArg = (name === 'openat' || name === 'faccessat') ? args[1] : args[0];
          this.hide = shouldHidePath(pathArg.readCString());
        } catch (_) {}
      },
      onLeave(retval) { if (this.hide) retval.replace(-1); }
    });
  });
}


function hookJavaFiles() {
  Java.perform(() => {
    try {
      const Files = Java.use('java.nio.file.Files');
      const StringCls = Java.use('java.lang.String');
      function filterTcp(text) {
        return String(text).split('\n').filter(l => l.indexOf(':15B3') < 0).join('\n') + '\n';
      }
      Files.readAllBytes.implementation = function (path) {
        const p = String(path.toString());
        if (p.indexOf('/proc/sys/kernel/random/boot_id') >= 0) {
          const boot = (typeof XENOID_PROFILE !== 'undefined' && XENOID_PROFILE.ids && XENOID_PROFILE.ids.boot_id) ? XENOID_PROFILE.ids.boot_id : '00000000-0000-4000-8000-000000000000';
          return StringCls.$new(String(boot) + '\n').getBytes();
        }
        if (p.indexOf('/proc/net/tcp') >= 0) {
          const orig = this.readAllBytes(path);
          const text = StringCls.$new(orig).toString();
          return StringCls.$new(filterTcp(text)).getBytes();
        }
        return this.readAllBytes(path);
      };
      console.log('[xenoid] Java Files hooks loaded');
    } catch (e) { console.log('[xenoid] Files hook failed: ' + e); }
  });
}

const XENOID_SELFTEST = { fileHits: 0, propHits: 0 };

function hookJava() {
  Java.perform(() => {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      XENOID_SELFTEST.fileHits++;
      const path = this.getAbsolutePath();
      if (shouldHidePath(path)) return false;
      return this.exists();
    };

    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (containsHiddenNeedle(cmd) || String(cmd).indexOf(' su') >= 0 || String(cmd) === 'su') {
        cmd = 'false';
      }
      return this.exec(cmd);
    };

    const SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
      XENOID_SELFTEST.propHits++;
      const k = String(key);
      if (Object.prototype.hasOwnProperty.call(XENOID.props, k)) return XENOID.props[k];
      return this.get(key);
    };
    SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
      const k = String(key);
      if (Object.prototype.hasOwnProperty.call(XENOID.props, k)) return XENOID.props[k];
      return this.get(key, def);
    };
  });
}

function selfTest() {
  Java.perform(() => {
    let fileHit = false;
    let propHit = false;
    try {
      const File = Java.use('java.io.File');
      const before = XENOID_SELFTEST.fileHits;
      File.$new('/system/build.prop').exists();
      fileHit = XENOID_SELFTEST.fileHits > before;
    } catch (e) { console.log('[xenoid-selftest] file error: ' + e); }
    try {
      const SystemProperties = Java.use('android.os.SystemProperties');
      const before = XENOID_SELFTEST.propHits;
      SystemProperties.get('ro.build.id');
      propHit = XENOID_SELFTEST.propHits > before;
    } catch (e) { console.log('[xenoid-selftest] prop error: ' + e); }
    console.log('[xenoid-selftest] fileHit=' + fileHit + ' propHit=' + propHit);
  });
}

try { hookLibc(); } catch (e) { console.log('[xenoid] libc hook failed: ' + e); }
if (Java.available) {
  try { hookJava(); } catch (e) { console.log('[xenoid] java hook failed: ' + e); }
  try { hookJavaFiles(); } catch (e) { console.log('[xenoid] java files hook failed: ' + e); }
  try { selfTest(); } catch (e) { console.log('[xenoid-selftest] failed: ' + e); }
}
console.log('[xenoid] default Frida policy loaded');
