#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib
ap=argparse.ArgumentParser(); ap.add_argument('--config', default='.xenoid/config.json'); ap.add_argument('--out', default='dist/docker-compose.yml'); args=ap.parse_args()
config=pathlib.Path(args.config)
cfg=json.loads(config.read_text()) if config.exists() else {}
image=cfg.get('runtime_image_tag') if cfg.get('auto_build_runtime_image') else cfg.get('image','redroid/redroid:13.0.0-latest')
# ARM hosts have no AArch32 — stock image must be 64only.
if (not cfg.get('auto_build_runtime_image')) and image in {'redroid/redroid:13.0.0-latest', 'redroid/redroid:13.0.0'}:
    import platform as _platform
    if _platform.machine() in {'arm64', 'aarch64'}:
        image = 'redroid/redroid:13.0.0_64only-latest'
net_enabled=cfg.get('network_enabled', False)
net=cfg.get('network_name','xenoid-net'); ip=cfg.get('network_ip','172.31.0.10'); mac=cfg.get('network_mac','02:11:22:33:44:55'); subnet=cfg.get('network_subnet','172.31.0.0/24'); gateway=cfg.get('network_gateway','172.31.0.1')
name=cfg.get('container_name','xenoid-android'); adb=cfg.get('adb_port',5555); android_adb=cfg.get('android_adb_port',62111); daemon=cfg.get('daemon_port',18765); vol=cfg.get('android_data_volume','xenoid-data')
base_image=str(cfg.get('image') or '')
service_network = f'''    networks:
      {net}:
        ipv4_address: {ip}
        mac_address: {mac}
''' if net_enabled else ''
top_network = f'''networks:
  {net}:
    driver: bridge
    ipam:
      config:
        - subnet: {subnet}
          gateway: {gateway}
''' if net_enabled else ''
text=f'''# xenoid runtime compose — base_image={base_image}
services:
  xenoid-android:
    image: {image}
    container_name: {name}
    privileged: true
    restart: unless-stopped
    ports:
      - "127.0.0.1:{adb}:{android_adb}"
    volumes:
      - {vol}:/data
      - /dev/binderfs:/dev/binderfs
{service_network}    command:
      - androidboot.redroid_width=1080
      - androidboot.redroid_height=1920
      - androidboot.redroid_dpi=480
      - service.adb.tcp.port={android_adb}
      - androidboot.use_memfd=true
volumes:
  {vol}: {{}}
{top_network}'''
out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(text)
print(json.dumps({'ok': True, 'out': str(out), 'image': image, 'service': 'xenoid-android'}, indent=2))
