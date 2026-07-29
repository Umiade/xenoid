#!/usr/bin/env python3
from __future__ import annotations
import pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
src=(ROOT/'native/xenoid-hide/xenoid_prop_area.c').read_text()
required_exact={
 'ro.bionic.arch':'g_bionic_arch',
 'ro.dalvik.vm.isa.arm64':'g_dalvik_isa_arm64',
 'ro.dalvik.vm.isa.arm':'g_dalvik_isa_arm',
 'dalvik.vm.isa.x86.variant':'',
 'dalvik.vm.isa.x86_64.variant':'',
 'ro.boot.verifiedbootstate':'green',
 'ro.boot.flash.locked':'1',
 'ro.boot.vbmeta.device_state':'locked',
 'ro.boot.veritymode':'enforcing',
 'sys.usb.config':'mtp',
 'sys.usb.state':'mtp',
 'persist.sys.usb.config':'mtp',
}
forbidden_global_rewrites=['service.adb.tcp.port']
missing=[]
for k,v in required_exact.items():
    if f'!strcmp(full,"{k}")' not in src or not (f'return "{v}"' in src or f'return {v}' in src):
        missing.append(k)
required_substrings=['cpu.abilist64','cpu.abilist32','cpu.abilist']
for k in required_substrings:
    if f'strstr(full,"{k}")' not in src:
        missing.append(k)
for sym in ['PROFILE_JSON','load_profile_values','json_copy_string','g_fingerprint','g_abilist','g_bionic_arch']:
    if sym not in src:
        missing.append('profile:'+sym)
for k in forbidden_global_rewrites:
    if f'!strcmp(full,"{k}")' in src:
        missing.append('forbidden-global:'+k)
required_files=[
 'build_system_prop','system_prop','dalvik_config_prop','dalvik_prop','exported_dalvik_prop','bionic_prop','runtime_prop',
 'bootloader_prop','bootloader_boot_reason_prop','vendor_security_patch_level_prop','vendor_default_prop','exported_default_prop',
 'usb_control_prop','adbd_config_prop'
]
for f in required_files:
    if f not in src:
        missing.append('file:'+f)
for needle in ['ro.boot.redroid_', 'ro.kernel.redroid.', 'ro.boot.use_redroid_c2', 'init.svc.redroid_net']:
    if needle not in src:
        missing.append('redroid:'+needle)
print({'ok': not missing, 'missing': missing})
sys.exit(0 if not missing else 1)
