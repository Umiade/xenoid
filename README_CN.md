# Xenoid

[English](README.md)

[更新日志](CHANGELOG_CN.md)

Xenoid 是面向移动安全工作的受控 Android 13 ARM64 运行时，支持 Apple Silicon macOS 与 Linux ARM64。它将 redroid 收敛为持久化的 Raven 设备，生产入口只有一个：

```bash
./xenoid up
```

`up` 成功意味着运行时、daemon、设备画像、保护层、存储和已配置服务全部就绪。部分就绪等同失败。Xenoid 拒绝不受支持的主机、模糊的资源归属和过期产物，不做侥幸兼容。

## 能力

- 基于 redroid `64only` 的持久化 Android 13 `arm64-v8a` 实例。
- 内容寻址、幂等且可恢复的 artifact、镜像和运行时收敛。
- Pixel 6 Pro（`raven`）画像；framework、property、HAL、procfs、sysfs、文件系统、蜂窝和 raw syscall 表面保持一致。
- 独立的国家、locale、时区、SIM、运营商、APN 与 LTE 小区画像。
- 支持 SOCKS5、HTTP(S)、Clash、URI 列表和订阅的 fail-closed 全局代理。
- 通过 token-gated rootd 提供受控 root 操作，不暴露应用可见的 `su`。
- KeyMint/keybox、相机媒体注入、传感器、Radio、输入、应用、自动化、OTA、Frida 与 MCP 控制。
- 多实例安全共享的 engine 级 kmod/eBPF 保护。
- 新实例默认启用镜像内置 microG 组合运行时。

Frida 只用于显式检查，不进入正常生产启动。凭据、代理源、keybox、Google 二进制、设备采集和运行时状态只保留在本机，不进入版本库。

## 要求

### Apple Silicon macOS

- Apple Silicon Mac
- macOS 与 Homebrew
- Python 3.9 或更高版本
- 至少 8 GiB 可分配内存

### Linux ARM64

- Ubuntu 22.04 或 24.04 ARM64
- Docker Engine
- root 或 sudo 权限
- 支持 `binder_linux`/binderfs 的内核

Xenoid 只支持一条生产架构：ARM64 主机运行 Android 13 `64only`。x86 与 32 位 Android 不在兼容范围内。

## 快速开始

### macOS

```bash
./xenoid install-runtime
./xenoid init --config examples/config-macos-colima.json
```

### Linux ARM64

```bash
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
```

新实例默认启用 Google 服务。第一次执行 `up` 时会通过 HTTPS 下载固定的第三方资产，完整校验 release、哈希、证书、包名、签名、SDK 与 ABI，并且只把字节保存在被忽略的 `.xenoid/` 本机状态中：

```bash
./xenoid up
./xenoid view
```

每个实例只执行一次 `init`。后续 `up` 会复用健康的 artifact、镜像、存储和容器。

## 常用操作

本节只覆盖日常高频子集。完整命令与子命令清单见[命令参考](docs/commands.md)。

### 运行时

```bash
./xenoid up
./xenoid up --dry-run
./xenoid up --skip-build
./xenoid status
./xenoid doctor --require-runtime
./xenoid logs
./xenoid view
./xenoid stop
./xenoid adb shell getprop ro.product.model
```

`--dry-run` 只观察，不修改。`--skip-build` 仍会校验源码、工具、artifact record、输出和镜像身份；缺失或过期时直接失败，不会编译。

### 实例

```bash
./xenoid instance list
./xenoid --instance phone-a init --config examples/config-macos-colima.json --no-google-services
./xenoid --instance phone-a up
./xenoid --instance phone-a status
./xenoid --instance phone-a delete --dry-run
./xenoid --instance phone-a delete
```

未指定 `--instance` 时选择 `default`。`delete` 会不可逆地销毁该实例的
Android 用户数据，并释放其容器、数据卷、Docker 网络、端口和 registry 租约；共享的
运行时镜像与引擎宿主机保护层会被保留。`--dry-run` 只报告计划，不执行删除。

### 设备与位置身份

```bash
./xenoid location list
./xenoid location set US
./xenoid location status --check

./xenoid device collect --out /tmp/device-profile.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid device regenerate
```

`device regenerate` 在运行中的运行时上原位轮换设备、SIM、启动、存储、Google 与应用身份——一次软重启，不重建容器——同时保留用户数据与已安装应用。该命令接受 `--dry-run`，不再接受 `--skip-build`；`up --skip-build` 仍然可用。microG 轮换完成后使用 `googleIdentityMode=offline-seeded`，因此 FCM 注册与投递不可用。

### 全局代理

```bash
./xenoid proxy set --prompt
./xenoid proxy on
./xenoid proxy status --check
./xenoid proxy off

chmod 600 /path/to/proxy-source
./xenoid proxy import /path/to/proxy-source
```

秘密不应出现在命令参数中。代理失败时保持 quarantine，不会静默恢复直连。

### Root、应用、相机与检查

```bash
./xenoid root status
./xenoid root exec id

./xenoid app install /path/to/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid input tap 540 1800

./xenoid camera set photo /path/to/image.png
./xenoid camera status --check

python -m pip install frida-tools
./xenoid frida install
./xenoid frida start
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

### Google 服务

新实例默认使用 `microg` release `microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`；仅在创建时通过 `init --no-google-services` 显式关闭。第一次 `up` 会安全获取并校验固定资产；原理和手工导入备用命令见[运维文档](docs/operations.md#google-play-services-default)。


### MCP、构建与验证

```bash
./xenoid mcp-config
./xenoid-mcp

./xenoid build all
./scripts/verify.sh --fresh
./xenoid package-release --version 0.9.2
./xenoid verify-release dist/release/xenoid-0.9.2.tar.gz
```

详细契约：

- [命令参考](docs/commands.md)
- [架构](docs/architecture.md)
- [运维](docs/operations.md)
- [构建与发布](docs/build.md)
- [MCP 工具](docs/mcp-tools.md)
- [远程服务](docs/remote-service.md)

参数以各命令的 `--help` 输出为准。

## 许可证

Xenoid 原创源码采用 `GPL-3.0-or-later`。路径级例外与第三方条款见 [NOTICE](NOTICE)，其覆盖范围继续以对应许可证为准。

## 致谢

Xenoid 建立在可靠的上游工作之上。贡献应归于真正完成它的人：

- [Android Open Source Project](https://source.android.com/)
- [redroid](https://github.com/remote-android/redroid-doc)
- [microG](https://microg.org/)
- [LineageOS for microG](https://github.com/lineageos4microg)
- [MindTheGapps](https://gitlab.com/MindTheGapps/vendor_gapps)
- [TEESimulator](https://github.com/JingMatrix/TEESimulator)
- [Frida](https://frida.re/)

第三方组件继续遵循各自的许可证。
