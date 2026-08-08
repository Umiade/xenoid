#!/usr/bin/env python3
"""Bake Xenoid identity into stock build.prop files extracted from the base image.

Why: init derives ro.build.fingerprint and unscoped ro.product.* from the
partition-scoped props + ro.build.version.* at BOOT. Zygote preloads
android.os.Build before prop-area can run, so identity must be correct in the
FILES, not just patched post-boot.

Single source of truth for partition identity text: native/xenoid-hide/
xenoid_overlay.c (the same text the runtime overlay bind-mounts post-boot).
ro.hardware is baked as tensor into the vendor build.prop; the runtime image
provides tensor-named HAL aliases so the redroid graphics implementation boots.
"""
from __future__ import annotations
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OVERLAY_C = ROOT / "native/xenoid-hide/xenoid_overlay.c"

# name -> (stock file path in image, overlay var/function in C)
PARTITIONS = {
    "system_build.prop": ("system/build.prop", "system_build_prop_text"),
    "vendor_build.prop": ("vendor/build.prop", "vendor_build_prop_text"),
    "product_build.prop": ("system/product/etc/build.prop", "product"),
    "system_ext_build.prop": ("system/system_ext/etc/build.prop", "system_ext"),
    "system_dlkm_build.prop": ("system/system_dlkm/etc/build.prop", "system_dlkm"),
    "odm_build.prop": ("vendor/odm/etc/build.prop", "odm"),
    "vendor_dlkm_build.prop": ("vendor/vendor_dlkm/etc/build.prop", "vendor_dlkm"),
    "odm_dlkm_build.prop": ("vendor/odm_dlkm/etc/build.prop", "odm_dlkm"),
}

# Extra identity keys for /system/build.prop that the overlay does not need
# post-boot (prop-area sets them in the area) but that MUST be right at boot so
# the derived ro.build.fingerprint and preloaded Build.* are correct.
SYSTEM_EXTRA = {
    "ro.build.id": "TP1A.221005.002",
    "ro.build.version.incremental": "8977058",
    "ro.build.version.release": "13",
    "ro.build.version.release_or_codename": "13",
    "ro.build.version.security_patch": "2022-10-05",
    "ro.build.display.id": "TP1A.221005.002",
    "ro.build.description": "raven-user 13 TP1A.221005.002 8977058 release-keys",
    "ro.bootmode": "normal",
    "ro.telephony.default_network": "9",
    "ro.telephony.sim.count": "1",
}
VENDOR_EXTRA = {
    "ro.radio.noril": "no",
    "vendor.rild.libpath": "/vendor/lib64/libxenoid-ril.so",
}
SKIP_APPEND_KEYS = set()  # ro.hardware=tensor is baked into vendor/build.prop


def _split_lines(raw: list[str]) -> list[str]:
    out: list[str] = []
    for s in raw:
        out.extend(p for p in s.split("\\n") if p and "=" in p)
    return out


def extract_overlay_texts() -> dict[str, list[str]]:
    """Parse the C source for the per-partition identity lines."""
    src = OVERLAY_C.read_text()
    texts: dict[str, list[str]] = {}
    # function-bodied texts: static const char *NAME(void) { return "..." "..."; }
    for name in ("system_build_prop_text", "vendor_build_prop_text"):
        m = re.search(r"static const char \*" + name + r"\(void\) \{(.*?)\n\}", src, re.S)
        body = m.group(1)
        texts[name] = _split_lines(re.findall(r'"([^"\n]*(?:=)[^"\n]*)\\n"', body))
    # overlay_extra_build_props: const char *VAR = "...\n..."; (single literal with \n)
    extra = re.search(r"overlay_extra_build_props\(.*?\{(.*?)\n\}", src, re.S)
    body = extra.group(1)
    for var in ("product", "system_ext", "system_dlkm", "odm", "vendor_dlkm", "odm_dlkm"):
        m = re.search(r'const char \*' + var + r' =\s*(.*?);', body, re.S)
        texts[var] = _split_lines(re.findall(r'"([^"\n]*(?:=)[^"\n]*)\\n"', m.group(1)))
    return texts


def main() -> int:
    stock_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    texts = extract_overlay_texts()
    if len(texts) != len(PARTITIONS):
        missing = set(v[1] for v in PARTITIONS.values()) - set(texts)
        print(f"patch-runtime-props: failed to extract overlay texts: {sorted(missing)}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, (rel, var) in PARTITIONS.items():
        stock = (stock_dir / rel).read_text()
        append = [l for l in texts[var] if l.split("=", 1)[0] not in SKIP_APPEND_KEYS]
        if name == "system_build.prop":
            append += [f"{k}={v}" for k, v in SYSTEM_EXTRA.items()]
        elif name == "vendor_build.prop":
            append += [f"{k}={v}" for k, v in VENDOR_EXTRA.items()]
        drop_keys = {l.split("=", 1)[0] for l in append}
        kept = [l for l in stock.splitlines()
                if not l.strip().startswith("#") and l.split("=", 1)[0] not in drop_keys]
        # keep original comments at top, then kept lines, then identity block
        comments = [l for l in stock.splitlines() if l.strip().startswith("#")]
        out = comments + kept + ["", "# xenoid identity (see scripts/patch-runtime-props.py)"] + append + [""]
        (out_dir / name).write_text("\n".join(out))
        print(f"patched {name}: kept={len(kept)} dropped={len(drop_keys)} appended={len(append)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
