#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, re, sys
from typing import Any

BUILD_ALIASES = {
    "brand": ["brand", "ro.product.brand", "ro.product.system.brand", "ro.product.vendor.brand"],
    "manufacturer": ["manufacturer", "ro.product.manufacturer", "ro.product.system.manufacturer", "ro.product.vendor.manufacturer"],
    "model": ["model", "ro.product.model", "ro.product.system.model", "ro.product.vendor.model"],
    "device": ["device", "ro.product.device", "ro.product.system.device", "ro.product.vendor.device"],
    "product": ["product", "name", "ro.product.name", "ro.product.system.name", "ro.product.vendor.name"],
    "hardware": ["hardware", "ro.hardware", "ro.boot.hardware"],
    "board": ["board", "ro.product.board", "ro.board.platform"],
    "bootloader": ["bootloader", "ro.bootloader"],
    "fingerprint": ["fingerprint", "ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint"],
    "tags": ["tags", "ro.build.tags"],
    "type": ["type", "ro.build.type"],
    "security_patch": ["security_patch", "ro.build.version.security_patch", "ro.vendor.build.security_patch"],
    "first_api_level": ["first_api_level", "ro.product.first_api_level"],
    "sku": ["sku", "ro.boot.hardware.sku"],
    "abi": ["abi", "ro.product.cpu.abi"],
    "abilist": ["abilist", "ro.product.cpu.abilist"],
    "abilist32": ["abilist32", "ro.product.cpu.abilist32"],
    "abilist64": ["abilist64", "ro.product.cpu.abilist64"],
    "bionic_arch": ["bionic_arch", "ro.bionic.arch"],
    "dalvik_isa_arm64": ["dalvik_isa_arm64", "ro.dalvik.vm.isa.arm64"],
    "dalvik_isa_arm": ["dalvik_isa_arm", "ro.dalvik.vm.isa.arm"],
}

INPUT_ALIASES = {
    "input_name": ["input_name", "touch_name", "input_device_name", "input.name", "touch.name"],
    "input_bustype": ["input_bustype", "bustype", "input.bustype", "touch.bustype"],
    "input_vendor": ["input_vendor", "vendor_id", "input.vendor", "touch.vendor"],
    "input_product": ["input_product", "product_id", "input.product", "touch.product"],
    "input_version": ["input_version", "input.version", "touch.version"],
    "display_width": ["display_width", "width", "display.width", "input.width", "touch.width"],
    "display_height": ["display_height", "height", "display.height", "input.height", "touch.height"],
    "pressure_max": ["pressure_max", "input.pressure_max", "touch.pressure_max"],
    "tracking_max": ["tracking_max", "input.tracking_max", "touch.tracking_max"],
}

def walk(obj: Any, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            yield ks, v
            if prefix:
                yield prefix + "." + ks, v
            yield from walk(v, ks if not prefix else prefix + "." + ks)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, prefix + f"[{i}]")

def flat_lookup(obj: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in walk(obj):
        if isinstance(v, (str, int, float, bool)) or v is None:
            out.setdefault(k, v)
            out.setdefault(k.lower(), v)
    # Special containers often used by daemon templates.
    for key in ("build", "props", "properties", "systemProperties", "device", "profile", "template"):
        sub = obj.get(key) if isinstance(obj, dict) else None
        if isinstance(sub, dict):
            for k, v in sub.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    out.setdefault(str(k), v); out.setdefault(str(k).lower(), v)
    return out

def pick(flat: dict[str, Any], aliases: list[str], default: str | None = None) -> str | None:
    for a in aliases:
        for k in (a, a.lower()):
            v = flat.get(k)
            if v is not None and str(v) != "": return str(v)
    return default

def slug(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", s.strip()).strip("-").lower()
    return s or "pixel-template"

def thermal_from_flat(flat: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    existing = data.get("thermal") if isinstance(data.get("thermal"), dict) else {}
    out: dict[str, Any] = {}
    for i in range(10):
        zkey = f"zone{i}"
        z = existing.get(zkey) if isinstance(existing.get(zkey), dict) else {}
        t = z.get("type") or pick(flat, [f"thermal_zone{i}_type", f"thermal.zone{i}.type", f"thermal.{i}.type"], None)
        temp = z.get("temp") or pick(flat, [f"thermal_zone{i}_temp", f"thermal.zone{i}.temp", f"thermal.{i}.temp", f"thermal_zone{i}"], None)
        if t is not None or temp is not None:
            out[zkey] = {}
            if t is not None: out[zkey]["type"] = str(t)
            if temp is not None: out[zkey]["temp"] = int(temp) if re.fullmatch(r"-?\d+", str(temp)) else temp
    if not out:
        defaults = [("skin",32000),("battery",31000),("cpu-0",36000),("cpu-1",35500),("gpu",34000)]
        for i,(t,temp) in enumerate(defaults): out[f"zone{i}"]={"type":t,"temp":temp}
    return out

def normalize(data: dict[str, Any], source_name: str) -> dict[str, Any]:
    if data.get("schema") == "dev.xenoid.fingerprint/v1":
        data = dict(data)
        data.pop("network", None)
        if isinstance(data.get("hardware_profile"), dict):
            data["hardware_profile"] = {key: value for key, value in data["hardware_profile"].items()
                                        if key not in {"mac", "wifi_mac"}}
        data.setdefault("source", {})
        if isinstance(data["source"], dict): data["source"].setdefault("importedFrom", source_name)
        flat_existing = flat_lookup(data)
        input_defaults = {
            "input_name": "sec_touchscreen", "input_bustype": "24", "input_vendor": "1256", "input_product": "26720", "input_version": "256",
            "display_width": "1344", "display_height": "2992", "pressure_max": "255", "tracking_max": "65535",
        }
        input_profile = data.get("input") if isinstance(data.get("input"), dict) else {}
        input_profile = dict(input_profile)
        for key, aliases in INPUT_ALIASES.items():
            v = data.get(key) if data.get(key) is not None else pick(flat_existing, aliases, input_defaults.get(key))
            if key != "input_name" and v is not None and re.fullmatch(r"-?\d+", str(v)):
                v = int(v)
            input_profile.setdefault(key, v)
            data.setdefault(key, v)
        data["input"] = input_profile
        thermal = thermal_from_flat(flat_existing, data)
        data.setdefault("thermal", thermal)
        for z, val in thermal.items():
            idx = str(z).replace("zone", "")
            if isinstance(val, dict):
                if "type" in val: data.setdefault(f"thermal_zone{idx}_type", val["type"])
                if "temp" in val: data.setdefault(f"thermal_zone{idx}_temp", val["temp"])
        return data
    flat = flat_lookup(data)
    build = {}
    defaults = {
        "brand": "google", "manufacturer": "Google", "model": "Pixel 6 Pro", "device": "raven", "product": "raven",
        "hardware": "tensor", "board": "raven", "fingerprint": "google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys",
        "bootloader": "slider-1.2-8977058", "tags": "release-keys", "type": "user", "security_patch": "2022-10-05",
        "first_api_level": "33", "sku": "G1MNW", "abi": "arm64-v8a", "abilist": "arm64-v8a",
        "abilist32": "", "abilist64": "arm64-v8a", "bionic_arch": "arm64", "dalvik_isa_arm64": "arm64", "dalvik_isa_arm": "",
    }
    for out_key, aliases in BUILD_ALIASES.items():
        build[out_key] = pick(flat, aliases, defaults.get(out_key))
    battery = {}
    for k, default in {"level":83,"scale":100,"voltage":4100,"temperature":310,"status":2,"plugged":0,"health":2,"present":1}.items():
        v = pick(flat, ["battery."+k, "battery_"+k, k], str(default))
        try: battery[k] = int(v) if v is not None and re.fullmatch(r"-?\d+", str(v)) else v
        except Exception: battery[k] = default
    sensors = data.get("sensors") if isinstance(data.get("sensors"), list) else data.get("sensorList") if isinstance(data.get("sensorList"), list) else []
    if not sensors:
        sensors = [
            {"type":1,"name":"BMI160 Accelerometer","vendor":"Bosch","version":1},
            {"type":2,"name":"AK09918 Magnetometer","vendor":"AKM","version":2},
            {"type":4,"name":"BMI160 Gyroscope","vendor":"Bosch","version":4},
            {"type":5,"name":"LTR-559 Light","vendor":"Lite-On","version":5},
            {"type":6,"name":"BMP388 Pressure","vendor":"Bosch","version":6},
        ]
    input_defaults = {
        "input_name": "sec_touchscreen", "input_bustype": "24", "input_vendor": "1256", "input_product": "26720", "input_version": "256",
        "display_width": "1344", "display_height": "2992", "pressure_max": "255", "tracking_max": "65535",
    }
    input_profile = {}
    for key, aliases in INPUT_ALIASES.items():
        v = pick(flat, aliases, input_defaults.get(key))
        if key != "input_name" and v is not None and re.fullmatch(r"-?\d+", str(v)):
            input_profile[key] = int(v)
        else:
            input_profile[key] = v
    thermal = thermal_from_flat(flat, data)
    out = {
        "schema": "dev.xenoid.fingerprint/v1",
        "template": slug(str(data.get("name") or data.get("template") or source_name)),
        "build": build,
        "ids": {"android_id": "REGENERATE", "boot_id": "REGENERATE"},
        "battery": battery,
        "sensors": sensors,
        "input": dict(input_profile),
        "thermal": thermal,
        "locale": pick(flat, ["locale", "persist.sys.locale"], "en-US"),
        "timezone": pick(flat, ["timezone", "persist.sys.timezone"], "America/Los_Angeles"),
        "source": {"importedFrom": source_name, "rawSchema": data.get("schema")},
    }
    out.update(input_profile)
    for z, val in thermal.items():
        idx = str(z).replace("zone", "")
        if isinstance(val, dict):
            if "type" in val: out[f"thermal_zone{idx}_type"] = val["type"]
            if "temp" in val: out[f"thermal_zone{idx}_temp"] = val["temp"]
    return out

def convert_file(path: pathlib.Path, out_dir: pathlib.Path, overwrite: bool) -> pathlib.Path:
    data = json.loads(path.read_text())
    norm = normalize(data, path.name)
    name = slug(str(norm.get("template") or path.stem)) + ".json"
    out = out_dir / name
    if out.exists() and not overwrite:
        raise FileExistsError(f"exists: {out}; pass --overwrite")
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(norm, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return out

def main() -> int:
    ap = argparse.ArgumentParser(description="Import Pixel daemon/device templates into Xenoid fingerprint profile schema")
    ap.add_argument("source", help="JSON file or directory containing JSON templates")
    ap.add_argument("--out-dir", default="examples/fingerprints/imported")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()
    src = pathlib.Path(args.source).expanduser().resolve()
    out_dir = pathlib.Path(args.out_dir).expanduser().resolve()
    files = sorted(src.rglob("*.json")) if src.is_dir() else [src]
    written = []
    for f in files:
        try:
            written.append(str(convert_file(f, out_dir, args.overwrite)))
        except Exception as e:
            print(json.dumps({"ok": False, "file": str(f), "error": str(e)}, ensure_ascii=False), file=sys.stderr)
            return 1
    print(json.dumps({"ok": True, "count": len(written), "files": written}, ensure_ascii=False, indent=2))
    return 0
if __name__ == "__main__": sys.exit(main())
