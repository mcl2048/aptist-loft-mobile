# LOFT 0.1.7-LYNX · 应用保护与安全备忘录

## 交付范围

- **应用保护**。设置页管理六位数字 PIN，可启用 Android 强生物识别。在 TOTP 和安全备忘录之间切换或结束可见会话时，撤销旧页面的访问权。PIN 验证使用 Argon2id，失败次数和退避期限先写入 SQLCipher。TOTP 原有的单条秘密查看保护继续独立执行。
- **离线备忘录**。Rust 先提交本地加密事务，界面再确认保存。支持标题、正文、日期时间、emoji 图标和多标签，原生 Markdown 编辑器保留当前行的源标记，其他行显示排版。备忘录列表支持模糊搜索、标签过滤、滑动归档和删除，按钮菜单提供无障碍操作。横线纸面、展开内屏双栏和折叠外屏单栏复用现有 WindowManager 安全区域。折叠和尺寸变化保留当前草稿和光标。
- **可选同步**。已有企业 Hub 的耐久登录必须先配对设备。既有匿名备忘录留在本机。配对后创建的备忘录归属当前 Hub 账号，同一账号的设备使用配对密钥进行端到端加密同步。换账号时隐藏旧账号集合。D1 只保留当前版本的密文及元数据。

[安全备忘录契约](../docs/contracts/secure-notes.md) · [资源契约](../docs/contracts/resources.md)

## 同步与删除

WorkManager 每 60 分钟安排一次拉取，弹性窗口 15 分钟。编辑触发的同步合并到 30 秒后执行。任务要求网络可用和电量未达系统低电量阈值，退避初始 30 秒，最多三次尝试。Android 使用当前系统 Network。LOFT VPN 活跃时，必须同时确认当前 VPN 状态、实际 Network 和 app UID 路由，绕开 VPN 的配置会延迟同步。LOFT 代码没有持有常驻唤醒锁，WorkManager 依赖的标准唤醒权限由 Android 合并进 manifest。

版本相同且本地干净时，Hub 返回空正文 304，客户端不克隆、不重新加密也不重写备忘录集合。每份集合的密文解码后最大 256 KiB，账号内写入通过版本比较和交换完成。使用 SQLCipher 的逻辑安全删除和跨设备删除标记。闪存磨损均衡、尚未上线的设备和 D1 Time Travel 历史都超出 APK 的物理擦除控制范围。AES-256-GCM 使用设备端 256 位随机密钥和经 HKDF 派生的版本密钥。没有独立的抗量子协议认证。 [Android WorkManager](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work) · [NIST 介质消毒指南](https://csrc.nist.gov/pubs/sp/800/88/r2/final)

## Cloudflare

现有 Hub 已应用 `0003_secure_notes.sql`，Worker 版本 `69d52350-0182-4a32-bb0d-77882dcba8a7`，Pages 部署 `c5274710`。线上 HTTPS 探测确认旧版能力列表、新版协商能力列表和无会话的 401。实际 workerd、Pages 服务绑定与 D1 测试覆盖同账号第二设备、跨账号隔离、并发版本提交、过量密文、会话注销和 304 空正文。线上个人账号未用于同步测试。 [部署记录](../docs/validation/hub-0.1.7-deployment.json) · [生产 Hub](https://aptist-loft-hub.pages.dev)

## 验证

| 范围 | 结果 |
| --- | --- |
| 平台基础 | Python 43 项通过，Rust 架构约束检查通过 |
| Rust | 125 项通过，workspace fmt 和 all-target Clippy 通过 |
| Go | 固定 Gateway 8.0.36-LYNX 来源，正常和 race 各 115 项及 145 项子测试通过。无 tag、vet、模块验证和所有权检查通过 |
| Hub | Rust 7 项、实际 SQL 7 项、Wasm target Clippy、打包和本地 workerd 集成通过 |
| Android 源码预检 | 初次 Release Kotlin 预检发现两处类型错误，分别修正 Activity 上下文和服务内部 API 可见性。Notes 独立 JVM 7 项覆盖 Markdown 游标、补全、标签布局和精确 60% 滑动阈值 |
| Android ARM64 Release | 应用 JVM 105 项及基础 JVM 121 项通过。R8、资源缩减和 lint 通过。Lint 54 条警告、0 错误。首轮 lint 的缩进错误已修复后重跑 |

构建使用 `source scripts/env.sh`、Rust 1.100.0、Go 1.27.4、NDK 28.2、Gradle 8.13、AGP 8.13.2 和 SDK 36。ARM64 与独立 x86_64 使用相同的 Rust 源码和源锁定 Go 适配器，各自生成 JNI。开发签名与实机验收单独记录。

## APK 与设备验收

ARM64 Release 版本号为 `0.1.7-LYNX`，versionCode 为 8。使用既有 LOFT 开发证书。APK SHA-256 为 `8f557b12f015b3c408df10018cf87228e254291029459e56521db916d69bcb17`。签名、manifest、16 KiB ZIP/ELF 对齐以及 Git 暂存区和 APK 凭据扫描均在发布流程中核验。 [APK 记录](../docs/validation/apk-0.1.7-release.json) · [构建记录](../docs/validation/build-0.1.7.json)

API 29 x86_64 的应用和仪器测试 APK 均已构建，使用同一套 Rust 和 Go 源码。该对 APK 早于 ARM64 版的最终 Kotlin lint 缩进修正。软件模拟器接收应用 APK 后，Android 包管理器的 `StorageManagerService.allocateBytes` 遇到空 `PackageManagerInternal`。重试期间系统服务重新启动，测试未开始。Pixel Fold、Galaxy Z Fold4、实际指纹/人脸识别、VPN 同步出口与实机耗电均未获得实机数据。

## 发布记录

功能提交 `bba8b7025c7566622166f5df2e82f10a52eeaba2` 已正常推送，GitHub `main` 读回一致。任务文件中的凭据首次收到 HTTP 403，随后用现有 GitHub CLI 登录凭据通过 Git askpass 推送成功。发布检查读取实际 Git 暂存区及 `bin/loft.apk`。任务专用模拟器和 x86 Gradle 中间输出已清理，保留 APK 与日志。

## 验收清单

| 项目 | 状态 | 范围 |
| --- | --- | --- |
| 应用保护与 TOTP/安全备忘录入口 | ✅ | Rust 和 Android Release 验证通过 |
| 原生离线笔记、Markdown、标签、归档与逻辑删除 | ✅ | Rust、应用 JVM、基础布局测试通过 |
| Cloudflare 加密同步服务 | ✅ | 线上部署、兼容性和未认证响应已核验。多设备隔离与版本合并由本地 workerd 和 Rust 验证 |
| Android 实机 Fold、强生物识别、生产账号多设备及功耗 |  | 尚缺硬件和运行证据 |
| 对所有恢复工具不可恢复的闪存与云端历史物理擦除 |  | Android 和 D1 无法提供该证明 |
