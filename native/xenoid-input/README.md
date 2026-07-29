# xenoid-input

Native Android helper for low-level input through `/dev/uinput`.

Build with the Android NDK:

```bash
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
make
adb push xenoid-input /data/local/tmp/xenoid-input
adb shell chmod 755 /data/local/tmp/xenoid-input
```

The daemon uses this helper before its Android input-command fallback.

The uinput device identity is read from `/data/local/tmp/xenoid-profile/effective.json`. Supported profile fields include `input_name`, `input_bustype`, `input_vendor`, `input_product`, `display_width`, and `display_height`.
