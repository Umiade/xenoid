# xenoid-input

Native Android helper for low-level input through `/dev/uinput`.

Build with the Android NDK:

```bash
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
make
adb push xenoid-input /data/local/tmp/xenoid-input
adb shell chmod 755 /data/local/tmp/xenoid-input
```

Android init starts the helper as a persistent service. It creates one profile-backed `/dev/uinput` device, publishes its evdev node under `/dev/input`, and keeps both stable across gestures so InputReader sees a direct touchscreen rather than a sequence of hot-plugged devices. The daemon invokes the same binary as a root-only Unix-socket client and fails the operation if the service is unavailable; there is no framework or `input`-command fallback.

`tap` emits a pressure ramp, distinct contact/tool major and minor axes, orientation, bounded position drift, and a timed lift. `swipe` adds pressure/contact evolution, correlated micro-motion, an arced cubic Bézier path, smooth velocity, and an absolute monotonic deadline for the requested duration.

The uinput device identity is read from `/data/local/tmp/xenoid-profile/effective.json`. Supported profile fields include `input_name`, `input_bustype`, `input_vendor`, `input_product`, `display_width`, and `display_height`.
