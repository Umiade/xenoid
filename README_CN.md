# Xenoid

[English README](README.md)

Xenoid 是面向 Apple Silicon macOS 与 Linux ARM 主机的 Android 云手机运行时编排项目。它以 64 位 redroid Android 13 为基础，为启动、设备画像、环境隐藏、受控 root、Frida、eBPF、自动化、OTA、CLI 与 MCP 提供统一控制面。

当前生产路径：

- **macOS：** Colima ARM64 虚拟机与 Docker CLI；
- **Linux ARM / ARM ECS：** 原生 Docker 与 binderfs；
- **Android：** redroid 13 `64only` 镜像；
- **控制面：** `xenoid` CLI、`xenoid-mcp` 与 Android daemon；
- **权限边界：** daemon 签发短期 token，rootd 验证后执行，不暴露可被应用长期发现的 `su` 路径；
- **环境塑造：** rootfs/data 镜像、mount namespace、overlay、property-area 修改、kmod/eBPF、zygote shim 与 framework/HAL 补丁共同工作。

## 快速启动

### Apple Silicon macOS

要求：Apple Silicon、macOS、Homebrew、Python 3.9 或更新版本，以及至少 8 GB 可分配内存。

将本仓库克隆为 `xenoid`，然后执行：

```bash
cd xenoid
./xenoid install-runtime
./xenoid up
./xenoid view
```

`install-runtime` 安装并验证 macOS 宿主工具链，准备 Colima 与 binderfs；本地配置不存在时，它会从 `examples/config-macos-colima.json` 初始化 `default` 实例。该命令不会启动 Android。

`up` 是面向用户的启动命令。它构建并启动完整运行时，部署 daemon 与 native helper，应用设备画像和隐藏策略，加载 eBPF，最后执行与 `doctor --require-runtime` 相同的在线运行时验收。如果启动中途失败，`up` 会先采集独立 doctor 报告，再保留原始错误码退出。

正常启动前后都不需要用户再单独执行 `doctor`。

### 实例生命周期与数据持久化

每个 Xenoid 实例是一台逻辑设备，由三个持久组件共同定义：

1. **实例配置** `.xenoid/instances/<name>/config.json`（项目根目录）；
2. **私有控制状态** `~/.xenoid/instances/<UUID>/`（操作者状态）；
3. **Android 用户数据** Docker engine 命名卷（`xenoid-data-<tag>`），其中包含稀疏 ext4 `xenoid-data.img`，作为容器的 `/data` 挂载。

`stop`、重复 `up`、容器重建以及 `colima stop/start` 都会保留数据卷。`colima delete`、外部删除/清理 volume，或丢失宿主实例状态，会在下次启动时导致 Xenoid 硬失败，而不是静默创建空盘。

应用缓存和登录状态保存在同一 `/data` 分区，跨重启保留。Android 自身的存储压力和缓存清理语义仍然适用；Xenoid 不增加每次启动擦除的临时设备模式。

### 多实例操作

多个实例共享一个 Colima VM（macOS）或一个 Docker engine/binderfs（Linux ARM）。每个实例从操作者 registry 获得独立的 container、volume、network、MAC、IPv4/IPv6、宿主机 ADB/daemon 端口和 proxy 路由表。

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

设备标识（Android ID、serial、IMEI/IMEISV）每个实例生成一次，持久化在 `~/.xenoid/instances/<UUID>/device-identity.json`。容器重建时只轮换 boot-scoped 值（`boot_id`、`random_uuid`）。显式轮换通过 `device apply --keep-unique` 或 `device set` 更新同一宿主状态，避免下一次 `up` 回滚。

本次“等同唯一真实设备”的验收范围是 Android 用户/数据/keystore/账户状态与实例标识/生命周期。Xenoid 不模拟宿主机不存在的物理电话、短信或硬件传感器能力。

### Linux ARM / ARM ECS

要求：Ubuntu 22.04 或 24.04 ARM64、Python 3.9 或更新版本、Docker Engine、root 或 sudo 权限，以及可以加载 `binder_linux` 的内核。源码构建还需要 JDK 17、Android SDK platform 35、Android build-tools 35.0.0，以及 Android NDK 27.2.12479018 或兼容的更新版本。

将本仓库克隆为 `xenoid`，然后执行：

```bash
cd xenoid
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
./xenoid up
```

使用远程 Docker context 时，在启动前设置：

```bash
./xenoid config set --backend linux-docker --docker-context CONTEXT_NAME
./xenoid up
```

Linux 主机必须向 redroid 暴露 binderfs 设备。ARM64 主机必须使用 `64only` redroid 镜像，不能用 x86_64 镜像替代。

## 诊断

`doctor` 是独立诊断与证据命令。正常用户流程不需要它，因为 `up` 已在内部复用同一套检查。

执行非侵入式宿主和运行时诊断：

```bash
./xenoid doctor
```

要求真实 Android 运行时在线：

```bash
./xenoid doctor --require-runtime
```

执行构建、OTA、runtime context、hook surface 与完整在线运行时 smoke：

```bash
./xenoid doctor --full --require-runtime
```

保存 JSON 报告：

```bash
./xenoid doctor --out /tmp/xenoid-doctor.json
```

关键字段：

- `ok`：本次调用要求的检查全部通过；
- `complete`：真实 Android 已在线，且所有已执行检查通过；
- `runtimeAvailable`：运行时容器正在运行；
- `checks`：各部分的简明结果；
- `sections`：可审计的详细证据；
- `nextActions`：失败后的恢复命令。

默认 doctor 不会启动 Android，也不会注入 Frida。Android 离线时，宿主检查仍可能通过，但 `complete` 为 `false`，`nextActions` 会建议运行 `./xenoid up`。

## 生命周期

```bash
./xenoid up
./xenoid status
./xenoid logs
./xenoid view
./xenoid stop
```

常用操作：

```bash
# 只显示完整收敛计划，不修改运行时。
./xenoid up --dry-run

# 使用 release 中的预构建产物，不重新构建。
./xenoid up --skip-build

# 直接执行 ADB 命令。
./xenoid adb shell getprop ro.product.model
```

## 位置身份

设备位置是一套显式、与代理完全解耦的身份：国家、系统 locale、时区、单卡 USIM、运营商、APN 和已注册的 LTE 小区都来自同一份按实例持久化的 profile。新实例首次 `./xenoid up` 默认应用新加坡；之后的运行保留已选择的国家。

```bash
# 列出支持的国家（不访问运行时；AU DE GB HK JP SG US）。
./xenoid location list

# 查看脱敏后的宿主与 Android 位置状态。
./xenoid location status
./xenoid location status --check

# 选择国家并收敛身份。
./xenoid location set US
```

重复选择当前国家是幂等操作。切换国家会对受管理的 Android 容器执行恰好一次重建；硬件标识（IMEI、serial、Android ID、MAC/IP 租约）保持不变，切回曾经使用过的国家会恢复该国原来的 SIM、手机号和小区身份。`./xenoid location set` 切换国家时会自行完成这次容器重建，之后请再运行 `./xenoid up` 重新验证完整生产状态。手机号是按冻结的 libphonenumber 国家元数据生成的稳定合成身份，不是真实分配的号码，也不提供电话/SMS 能力。全局代理不读取也不修改这套身份，代理变更永远不会重启运行时。

## 全局代理

可以在 Android 的 Xenoid 设置界面中保存代理来源，也可以使用宿主 CLI。来源内容和凭据不得放入命令行参数：

```bash
# SOCKS5、HTTP 或 HTTPS 端点；输入过程不回显。
./xenoid proxy set --prompt

# 直接 HTTP 端点无法转发 UDP。
./xenoid proxy set --prompt --no-udp

# Clash YAML/JSON、URI 列表或 base64 URI 订阅。
chmod 600 /path/to/proxy-source
./xenoid proxy import /path/to/proxy-source

# 在线配置链接；默认只允许 HTTPS。
./xenoid proxy subscribe --prompt
```

编译器支持 SOCKS5、HTTP/HTTPS、Shadowsocks、ShadowsocksR、Trojan、VMess、VLESS、Hysteria 1/2、TUIC、AnyTLS、Mieru 和 Snell 节点。Clash `proxy-providers` 会被下载并合并；不支持的规则、监听器、分组与 provider 设置不会透传到代理引擎。

管理代理并查看经过脱敏的就绪证据：

```bash
./xenoid proxy status --check
./xenoid proxy list
./xenoid proxy select NAME
./xenoid proxy off
./xenoid proxy on
./xenoid proxy export --out /path/to/private-backup
./xenoid proxy clear
```

代理默认全局生效。Docker 引擎宿主会在 Android 容器流量离开网桥前透明接管 IPv4/IPv6 DNS、TCP 以及策略允许的 UDP，因此 Java 客户端、native 库和原始 socket 统一走代理；Android 网络命名空间中无需设置代理属性、VPN transport 或 TUN 设备。启用过程默认封闭：只有绑定到当前实例和运行时的普通应用检查证明所需数据面后才放行流量。`./xenoid up` 会恢复并验证已保存的期望状态。


## Root

root 通过 daemon 与 token-gated rootd 提供，用户无需进入 Android root shell。

```bash
./xenoid daemon health
./xenoid root status
./xenoid root exec id
./xenoid root exec 'cat /proc/version'
```

生产 rootfs 不包含可被应用长期发现的 `su` 路径。CLI 与 MCP 共用同一权限边界。

## 相机媒体

Xenoid 的 Android 设置界面与宿主 CLI 都可以把一张图片、一段视频或两者同时设为两个普通 Camera2 设备的来源：

```bash
./xenoid camera status
./xenoid camera set photo FILE
./xenoid camera set video FILE
./xenoid camera mode naturalized
./xenoid camera mode faithful
./xenoid camera clear photo
./xenoid camera clear all
./xenoid camera apply
./xenoid camera status --check
```

`naturalized` 会加入轻微的逐帧传感器变化；`faithful` 除必要的缩放与相机坐标变换外保留解码后的源像素。导入内容经验证后复制到 Android 私有存储，原始宿主路径与文件名不会被保留或返回。保存的相机状态可跨 daemon 与运行时重启恢复，修改会在下一次打开相机时生效。

`up` 会重新发布已保存的来源状态，并通过两个相机完成普通应用权限下的 YUV/JPEG 捕获。未配置来源也是有效状态，此时使用内置的回退画面。运行时还会发布一致的框架录像档案，因此 Android 系统相机无需配置来源即可打开、拍照并录制 H.264 视频。

## Frida

Frida 是显式分析能力，不属于生产启动。`up` 会停止并清除遗留的 frida-server 进程与临时 payload。

```bash
python -m pip install frida-tools
./xenoid frida install
./xenoid frida start
./xenoid frida status
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

`frida install` 自动匹配宿主 `frida-tools` 版本，下载对应的 `android-arm64` server，并通过 daemon/rootd 部署。也可以直接部署已有二进制：

```bash
./xenoid frida deploy /path/to/frida-server
./xenoid frida deploy-scripts
```

Frida 适合应用进程动态分析与 app-layer hook。文件系统、mount、Binder、HAL 与内核可见面由系统层处理。

## 设备画像

采集当前画像：

```bash
./xenoid device collect --out /tmp/device-profile.json
```

应用画像并重新生成唯一标识：

```bash
./xenoid device apply examples/fingerprints/sample-profile.json
```

应用 profile 中明确给出的唯一标识，不再生成替代值：

```bash
./xenoid device apply examples/fingerprints/sample-profile.json --keep-unique
```

生成应用层与服务层 Frida profile：

```bash
./xenoid device generate-frida examples/fingerprints/sample-profile.json --out /tmp/device-profile.js
./xenoid device generate-service-frida examples/fingerprints/sample-profile.json --out /tmp/service-profile.js
```

`device apply` 会同步 daemon profile、SettingsProvider、property-area 状态与重启后持久化的数据。换机后必须冷启动目标应用并重新采集完整画像，单个 `getprop` 值不能作为充分证据。

## 可选 Google Play 运行时

Google 移动服务默认关闭。Xenoid 仅支持一个显式固定的 Android 13 ARM64 版本：`MindTheGapps-13.0.0-arm64-20231025_200931`。从[上游 GitHub release](https://github.com/MindTheGapps/13.0.0-arm64/releases/tag/MindTheGapps-13.0.0-arm64-20231025_200931)获取官方 ZIP 与配套的 `release.x509.pem`，再配置一个全新实例：

```bash
./xenoid --instance play init --config examples/config-macos-colima.json
./xenoid --instance play google-services import-mindthegapps \
  /path/to/MindTheGapps-13.0.0-arm64-20231025_200931.zip \
  /path/to/release.x509.pem
./xenoid --instance play google-services enable
./xenoid --instance play up
./xenoid --instance play google-services status --require-runtime
```

导入只保存在本机，并在接纳 payload 前校验固定的 release 证书、归档签名、完整归档清单、每个成员的摘要、APK 签名沿革、包/版本清单和 native ABI。Xenoid 不会自动下载、再分发 Google 二进制，也不会把它们放入源码、release 或 OTA bundle。Android data 一旦存在，Google 选择即不可变；启用或禁用必须在全新实例上完成。Google 账号登录仍由操作员执行。Play Integrity 与设备认证是 Google 独立控制的能力，本集成不声明支持。

## 应用、输入与自动化

```bash
./xenoid app install /path/to/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid app uninstall com.example.app

./xenoid input tap 540 1800
./xenoid input swipe 540 1600 540 400 500

./xenoid automation plan examples/automation/ordered-task.js
./xenoid automation run examples/automation/ordered-task.js
```

低层输入通过 daemon 使用 `/dev/uinput` helper。自动化支持顺序动作和宿主侧执行。各子命令的 `--help` 输出是参数的权威说明。

## 网络身份

```bash
./xenoid netctl status --ifname rmnet_data0
./xenoid netctl set-mac 02:00:00:00:00:01 --ifname rmnet_data0
```

一致的网络画像包括接口、route、namespace、MAC 地址和 framework 可见值，只修改一个属性是不够的。

## OTA

```bash
./xenoid ota make --version 0.1.0
./xenoid ota install-bundle dist/ota/xenoid-0.1.0.tar.gz
./xenoid ota check
./xenoid ota apply
```

OTA bundle 包含 daemon、native runtime helper 与 manifest/hash 元数据。Frida server 和 script 仅通过独立的显式分析命令安装。

## MCP

生成 stdio MCP 配置：

```bash
./xenoid mcp-config
```

或直接启动 server：

```bash
./xenoid-mcp
```

代表性工具包括：

- `xenoid_doctor`，参数为 `full` 与 `requireRuntime`；
- `xenoid_up_plan`，用于无副作用的完整启动计划；
- `xenoid_stop` 与 `xenoid_status`，用于运行时生命周期控制；
- `xenoid_google_services_status`、`xenoid_google_services_enable` 与 `xenoid_google_services_disable`；
- `xenoid_root_status` 与 `xenoid_root_exec`；
- `xenoid_frida_install` 与 `xenoid_frida_load_script`；
- `xenoid_device_collect` 与 `xenoid_device_apply`；
- `xenoid_automation_run` 与 `xenoid_input_tap`。

MCP 不绕过 daemon token、backend 约束或运行时前置条件。向 agent 开放写操作前，应明确目标运行时、应用包名和允许的操作范围。

完整工具契约见 [`docs/mcp-tools.md`](docs/mcp-tools.md)。

## 配置

```bash
./xenoid config show
./xenoid config set --backend colima-docker
./xenoid init --backend colima-docker
```

配置示例：

- `examples/config-macos-colima.json`
- `examples/config-linux-arm.json`

本地配置保存在 `.xenoid/config.json`。不要提交凭据、token、私有镜像地址或工作站绝对路径。

## 构建与发布

```bash
./xenoid build all
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

单独构建组件：

```bash
./xenoid build daemon
./xenoid build input
./xenoid build profile
./xenoid build netctl
```

发布包包含 CLI、MCP server、非专有运行时资源、daemon APK、native helper、配置示例、公开 Google release 元数据、skill 文件、`doctor.json` 与 SHA-256 manifest。发布包绝不包含已导入的 Google ZIP、证书或展开后的 payload。

## 路线图

- [ ] 为可信宿主操作员增加可编程 eBPF hook 接口：支持用户自有 CO-RE 程序、隔离的生命周期与事件流、原子替换、回滚和可选的启动恢复，且不覆盖 Xenoid 内置运行时保护。

## 架构与详细文档

- [`docs/architecture.md`](docs/architecture.md)：架构与信任边界；
- [`docs/operations.md`](docs/operations.md)：运行、故障定位与发布操作；
- [`docs/profile-and-hiding.md`](docs/profile-and-hiding.md)：设备画像与环境隐藏；
- [`docs/build.md`](docs/build.md)：构建产物与依赖；
- [`docs/mcp-tools.md`](docs/mcp-tools.md)：MCP 工具参数。
