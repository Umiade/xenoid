# 更新日志

[English](CHANGELOG.md)

Xenoid 的所有重要变更都记录在此。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；发布标签为
`xenoid-<版本号>`，daemon 的 `versionCode` 计算规则为
`major * 10000 + minor * 100 + patch`。

## [0.9.1] - 2026-09-18

首个对当前运行时状态的版本化记录。除版本号基础设施本身外无行为变化。

基线：唯一生产入口 `./xenoid up` 负责收敛 redroid `64only` Android 13
ARM64 运行时、令牌门控的 daemon、Raven（Pixel 6 Pro）设备画像、各保护层
（属性区、overlay 挂载、内核模块、eBPF、servicemanager 拦截、zygote
预加载）、存储及已配置服务。设备身份在 framework API、系统属性、文件、
服务、HAL、procfs、sysfs 与裸系统调用等所有观测面保持一致。
`xenoid device regenerate` 通过重建容器来轮换身份。Google 服务由内置
microG 提供；不支持 DRM 播放与授权。Frida 仍是显式启用的检查能力，
绝不进入正常生产启动流程。

### 新增

- 版本号基础设施：`./xenoid --version` 输出共享包版本；daemon 构建为
  `versionName 0.9.1` / `versionCode 901`。
- `version-contract` CI 门禁，保证四处版本字符串、按公式计算的
  versionCode 与两份更新日志始终一致。
- 本双语更新日志，并已从两份 README 链接。

### 变更

- `xenoid-service` 改为上报共享包版本，不再使用硬编码字符串。
