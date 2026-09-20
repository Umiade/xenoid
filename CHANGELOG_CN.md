# 更新日志

[English](CHANGELOG.md)

Xenoid 的所有重要变更都记录在此。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；发布标签为
`xenoid-<版本号>`，daemon 的 `versionCode` 计算规则为
`major * 10000 + minor * 100 + patch`。

## [0.9.2] - 2026-09-18

原地运行时设备身份轮换。`xenoid device regenerate` 不再重建容器：它在
运行的运行时上提交固定的身份目标，由宿主机驱动一次软重启，并在替换后
的 daemon 健康后通过 microG 原位轮换 Google 身份，最后以 fail-closed 的
逐项读回验证每个因子。容器、数据卷、用户数据、已安装应用、keystore
状态以及位置国家/运营商全部保留。

### 新增

- 运行时镜像 payload 校验：`buildx` 导出 `image.tar` 后，构建器回放
  镜像层，把 Dockerfile 每条 `COPY` 规则产生的 payload 目标文件与
  `context-manifest.json` 中记录的摘要比对，任何分歧都以
  `runtime_image_payload_mismatch` 失败。BuildKit 本地 context/blob 缓存
  在同尺寸、仅内容变化的 payload 上静默复用旧字节的问题（已实际观测到）
  再也无法发布内容与记录不一致的镜像。
  回放还会按 OCI 描述符校验每个压缩层 blob 的摘要，接受合法的 `./`
  根记录，在目标祖先被非目录节点替换时清除其全部后代，并对层数、
  成员数与解压字节量实施预算限制及截止时间/取消检查。校验合约版本
  混入 `inputSha256`，合约变更前生成的内容标签永不再被复用。
- 进程内 Widevine DRM 身份：`xenoid-zygote` 预加载提供合成的 `IDrm`
  工厂（`android::DrmUtils::MakeDrm` 是 `libmediadrm.so` 中可拦截的
  导出跨 DSO 符号），因此每个应用进程里的 Java `MediaDrm` 与 NDK
  `AMediaDrm_*` 调用都解析到同一实现。它报告 vendor `Google`、描述
  `Widevine CDM`、algorithms、`securityLevel=L1`，并且每次调用都从
  专用暂存系统属性读取 `deviceUniqueId`（同时镜像到画像文件），因此无需
  用户空间重启即可轮换。这只是身份观测面：DRM 播放与授权仍不支持，
  `drm` 能力依旧为 `unsupported`。`persist.xenoid.drm.id` 没有显式的
  `property_contexts` 映射，继承基础策略的默认属性标签。`ci-full` 的 DRM
  门禁会临时构建、安装并移除未跟踪的普通应用探针，校验 Java/NDK 一致性
  与逐调用轮换，最后恢复原属性。

### 变更

- `xenoid device regenerate` 完全在运行时完成。它在严格的
  `dev.xenoid.device-regenerate/v3` 日志中一次性发布每个固定目标
  （GAID 是下文说明的后置条件例外；阶段为 `prepared`、`staged`、
  `props_committed`、`settings_committed`、`radio_committed`、
  `storage_identity_committed`、`soft_rebooted`、`google_reset`、
  `verified`、`committed`），保留命令名及向后兼容的嵌套
  `regeneration` 对象；直接成功与崩溃恢复清理统一返回规范的顶层 v3
  结果，并报告 `runtimeOnly=true` / `containerRecreated=false`。
  轮换因子：设备级 `ANDROID_ID`；每应用 SSAID（删除
  `settings_ssaid.xml`，由 Android 重建）；`Build.SERIAL` /
  `ro.serialno` / `ro.boot.serialno`；
  `boot_id`；IMEI/IMEISV；SIM 身份（IMSI、ICCID、MSISDN、LTE 小区，
  通过 SIM epoch 轮换）；`/data` 的 `statfs` `f_fsid`；蓝牙地址；设备名称
  与网络主机名；GAID 与 GSF Android ID（通过 microG 轮换，不清除任何
  Google 包，也不运行网络签到）；以及 DRM `deviceUniqueId`。型号、指纹与
  构建属性保持不变。
- Google 身份轮换完全在运行中的 microG 上完成。一个正十进制 GSF
  Android ID 由轮换事务与已提交的 Google 绑定确定性派生。GmsCore 强制
  停止期间会原子关闭 microG 签到，把该精确目标离线写入 `checkin.xml`、
  `gservices.db` 与暂存画像；绝不启动 `CheckinService`，也不发起或等待
  网络签到。该 `googleIdentityMode=offline-seeded` 策略使轮换后的实例
  不再支持 FCM 注册或投递；Google 状态把 `cloudMessaging` 报告为
  `unsupported`，证据为 `offline-checkin-disabled`，并将其从该实例必需
  的运行时能力中移除。
  GAID 明确不是固定日志目标。daemon 调用
  `IAdvertisingIdService.resetAdvertisingId`（Binder transaction 3）并关闭
  全局 LAT（transaction 4），只接受非零且不同于事务前观测值的应用可见
  GAID。返回的 SHA-256 摘要只是观测证据，不是目标；固定 microG 的
  `MemoryAdvertisingIdConfiguration` 没有 setter，因此 microG 服务或
  进程日后重建时仍可能再次生成 GAID。fail-closed 校验要求两项身份都与
  事务前不同，且 GSF 摘要等于其固定目标。provider 为 `none` 时跳过；
  已配置的非 microG provider 以 unsupported 失败。该阶段必须位于软重启
  之后，因为 zygote/GmsCore 重启会重建内存中的广告 ID 状态。
- 软重启由宿主机通过令牌门控的 rootd 路径驱动：先重启 `rild` 与
  `zygote`，`keystore2` 仅在替换后的 `system_server`/PackageManager
  就绪后重启，避免持有失效 binder 句柄，保持密钥证明绑定。就绪判定是
  真实的 `sys.boot_completed` 清除→置位跃迁加 daemon 健康检查。
- 日志固定原始容器 ID/epoch。`up` 只能启动并恢复该同一个已停止的
  `--restart=no` 容器，最终逐项读回会拒绝任何容器替换。rootd 仅在删除
  SSAID 并发出 RIL/zygote 重启请求后写入回执，从而区分本次受控软重启与
  无关的 `system_server` 或容器重启。
- 蓝牙身份改为写入 Android 13 用户 0 的 `Settings.Secure`
  `bluetooth_address` 与 `bluetooth_addr_valid`。生成的主机名以私有文件
  暂存，并与显示运行时状态一起在普通容器重启后重新应用。
- `/data` 的 `f_fsid` 现在是运行时输入：可写的内核模块参数喂给
  `vfs_statfs` 整形，同一值镜像到 shim/zygote 暂存文件，kmod、shim、
  zygote 与裸 `statfs` 系统调用四处一致。磁盘上的 ext4 UUID 对应用不再
  可见。
- 旧版 v1/v2 轮换日志仍会被识别，但不再可恢复：以
  `device_regeneration_legacy_pending` 失败；恢复方式是删除记录的旧日志
  文件后重新执行 `device regenerate`。
- daemon 构建为 `versionName 0.9.2` / `versionCode 902`。

### 移除

- `/proc/sys/kernel/random/uuid` 的 overlay 伪造（固定的内核熵源本身就
  是异常）；`randomUuid` 已从身份模型中删除。
- 离线 ext4 UUID 轮换：`scripts/rotate-storage-identity.sh`、存储轮换
  后端路径，以及 `rotationTargetUuid` / `rotationTargetRootfsUuid` 状态
  字段。实例存储 schema v5 升级会透明丢弃普通 v3/v4 记录中的空旧字段，
  但保留崩溃窗口证据：任何有效的非空旧轮换目标都会以
  `storage_legacy_rotation_pending` fail-closed，并保持原状态文件逐字节不变。
- 重建容器的轮换路径与 `device regenerate --restart-legacy-transaction`
  逃生参数。
- `device regenerate --skip-build`；轮换现在必须针对现有已校验产物执行
  运行时收敛预检。`up --skip-build` 仍然受支持。

### 修复

- microG 运行时门禁现在在 provider-managed 与 offline-seeded 两种模式下
  都检查固定 GmsCore 实际运行的 `com.google.android.gms` 进程；用户空间
  重启后不再等待并不存在的 `:persistent` 进程。
- Google 签名策略校验改为验证正在运行的受管容器实际使用的镜像（不可变
  镜像 ID 加固定的 Google 标签），不再使用针对当前完整源码树选出的
  运行时镜像；因此仅 daemon 的在线更新不会再仅仅因为无关的当前镜像
  输入没有新构建镜像而以 `google_services_runtime_not_ready` 失败。
- 普通 `up` 在 `container_created` 后崩溃恢复时，会启动日志固定的同一个
  容器并校验记录的两项运行时镜像摘要标签；不再要求收敛日志并未保存的
  镜像 ID 字段。
- 原生 DRM 桥接在重复读取 Widevine 身份前会清空字节向量，并把非
  Widevine 的密钥与加密操作委托回系统实现；因此同一事务中的合成身份
  保持稳定，同时保留 ClearKey 原生行为。
- overlay 的 apply、cleanup 与 revert 现在都会卸载旧部署遗留的
  `/proc/sys/kernel/random/uuid` bind mount。
- 新初始化实例首次 `up` 不再以 `storage_identity_mismatch` 失败：fresh
  存储 pending 记录现在携带收敛日志固定的 data UUID（rootfs 固定值在
  initialize 动作处强制执行），使 boot-seed 目标、已提交记录与恢复校验
  三者一致。此前新镜像会静默生成不一致的 UUID，每次恢复都失败关闭。
- 重生成恢复现在对引擎重启安全：在没有运行时活跃时恢复日志固定的共享
  保护部署（记录在日志的 before-state 中），并在补水（rehydrate）前重新
  执行 bootstrap/rootd 配置与单用户检查；事务期间源码树变更会以
  inputs-changed 失败关闭。恢复时的无线旋转在写入 LocationStateStore
  之前先校验日志固定的 profile digest，包括已轮换重试路径。
- 容器启动后的 `f_fsid` 重发布现在先等待 ext4 `/data` pivot 挂载完成再判定
  暂存叶子，快速的 `docker exec` 不会再读到 pivot 前的外层 `/data` 而使
  内核参数保持为零。netns 排他性证明现在枚举引擎上的全部容器，而非仅
  带标签的容器。
- 已记录的软重启完成后用户空间再次发生重启（zygote 崩溃）不再触发第二次
  破坏性 zygote 重启与 SSAID 重清；已记录的回执加完成纪元证明恰好一次。
- `up --dry-run` 在日志判定期间同样持有实例操作锁；无关的变更操作遇到
  legacy/畸形日志会得到规范 v3 错误信封而非裸身份错误；MCP/远程的
  `xenoid_up` 在执行器前会启动冷引擎主机，`xenoid_up_plan` 对挂起的重生成
  日志返回与真实运行一致的规范 v3 dry-run 信封。
- 新实例现在会在普通身份收敛期间播种持久化的合成 Widevine
  `deviceUniqueId`，不再在首次重生成前报告 Widevine unsupported。
- GMS 缺失（provider 为 `none` 或包被移除）时，Google 身份自愈不再无限
  重试：该面按终止处理；瞬时 rootd/服务丢失仍保留有限去重退避。
- 原生 DRM 桥接对照真实 Android 13 IDrm ABI 的修正：真实工厂桥接接受
  与原生工厂一致的部分后端 `-ENODEV` initCheck（使本 HIDL-only 客户机上的
  ClearKey 委托可用）；`requiresSecureDecoder` 按 `const char*` 读取 mime
  （已对照客户机 `DrmHal` 签名验证），不再崩溃；HDCP 与安全级别改用从 1
  开始的 framework 枚举（`HDCP_V2_2=5`、`HW_SECURE_ALL=5`）；
  `getKeyRequest` 委托 trampoline 现在按 AAPCS 转发经栈传递的第九个参数，
  ClearKey 密钥请求不再返回 `unknown key request type`。DRM 冒烟中的
  ClearKey 断言已对齐平台真实契约：枚举与密钥流程经委托可用；lazy HAL
  随温度变化的静态支持查询、未实现的 `removeKeys`、vendor/description
  属性读取，以及按设计拒绝 `ERROR_DRM_CANNOT_HANDLE` 的直接
  CryptoSession 算法设置，均按原生平台行为容忍。

### 已知问题

- Phonesky 自更新：Play Store 可能按自身节奏把固定的 Phonesky 种子
  （30.4.17）自更新到更新版本，与轮换无关——`device regenerate` 既不清除
  也不启动 Phonesky，不会触发该更新。更新包使用的 Google 证书与固定种子
  的签名谱系不同，组件校验会拒绝它，`up` 随之以
  `google_services_runtime_not_ready` 失败。恢复方法：`pm uninstall
  com.android.vending` 将商店回滚到已校验的出厂种子。

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
