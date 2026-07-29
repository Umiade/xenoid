# Xenoid Frida Scripts

- `xenoid-default.js`: hides common root/Frida/Magisk/Zygisk/Xposed surfaces in app processes.
- `xenoid-profile.js`: profile spoofing template for generated build-field hooks.

Deploy:

```bash
./xenoid frida deploy-scripts
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js
```
