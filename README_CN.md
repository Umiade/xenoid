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

`install-runtime` 安装并验证 macOS 宿主工具链，准备 Colima 与 binderfs；本地配置不存在时，它会从 macOS 模板创建 `.xenoid/config.json`。该命令不会启动 Android。

`up` 是面向用户的启动命令。它构建并启动完整运行时，部署 daemon 与 native helper，应用设备画像和隐藏策略，加载 eBPF，最后执行与 `doctor --require-runtime` 相同的在线运行时验收。如果启动中途失败，`up` 会先采集独立 doctor 报告，再保留原始错误码退出。

正常启动前后都不需要用户再单独执行 `doctor`。

### Linux ARM / ARM ECS

要求：Ubuntu 22.04 或 24.04 ARM64、Python 3.9 或更新版本、Docker Engine、root 或 sudo 权限，以及可以加载 `binder_linux` 的内核。源码构建还需要 JDK 17、Android SDK platform 35、Android build-tools 35.0.0，以及 Android NDK 27.2.12479018 或兼容的更新版本。

将本仓库克隆为 `xenoid`，然后执行：

```bash
cd xenoid
mkdir -p .xenoid
cp examples/config-linux-arm.json .xenoid/config.json
sudo ./scripts/setup-linux-binderfs.sh
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

## Root

root 通过 daemon 与 token-gated rootd 提供，用户无需进入 Android root shell。

```bash
./xenoid daemon health
./xenoid root status
./xenoid root exec id
./xenoid root exec 'cat /proc/version'
```

生产 rootfs 不包含可被应用长期发现的 `su` 路径。CLI 与 MCP 共用同一权限边界。

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
./xenoid netctl status --ifname eth0
./xenoid netctl set-mac 02:00:00:00:00:01 --ifname eth0
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

发布包包含 CLI、MCP server、运行时资源、daemon APK、native helper、配置示例、skill 文件、`doctor.json` 与 SHA-256 manifest。

## 路线图

- [ ] 为可信宿主操作员增加可编程 eBPF hook 接口：支持用户自有 CO-RE 程序、隔离的生命周期与事件流、原子替换、回滚和可选的启动恢复，且不覆盖 Xenoid 内置运行时保护。

## 架构与详细文档

- [`docs/architecture.md`](docs/architecture.md)：架构与信任边界；
- [`docs/operations.md`](docs/operations.md)：运行、故障定位与发布操作；
- [`docs/profile-and-hiding.md`](docs/profile-and-hiding.md)：设备画像与环境隐藏；
- [`docs/build.md`](docs/build.md)：构建产物与依赖；
- [`docs/mcp-tools.md`](docs/mcp-tools.md)：MCP 工具参数。
