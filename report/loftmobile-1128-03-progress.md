# LOFT 0.1.8-LYNX · 安全备忘录密钥与多设备同步

## 功能与数据边界

- ✅ **重置加密密钥**。可保留备忘录并重新加密，也可明确确认后清空本机确认范围和当前账号的云端集合。匹配的云端回执确认后才提交本机删除并展示新密钥。清空确认后新建或修改的设备本地笔记保留。Cloudflare 历史备份和离线设备上的旧副本有各自的保留周期。
- ✅ **复制密钥**。生成的配对码带复制按钮，Android 剪贴板条目标记为敏感，避免 Android 13 及以上版本的系统预览显示密钥。
- ✅ **普通登录识别**。备忘录与 TOTP 依据耐久 Hub 会话。邮件权限独立。Android 区分身份、Hub 能力、配对要求和密钥恢复。已登录旧客户端升级后可以重新协商能力。旧 Hub 的 v1 协议回退限制在原 origin 和 issuer。
- ✅ **同步冲突处理**。备忘录以最近一次确认的版本为合并基线，独立修改合并，同一条目上的不兼容修改保留两端的版本并报告冲突。已确认删除的标记维持优先。TOTP 在写入遇到并发版本提交时自动重新读取并尝试一次。

[备忘录契约](../docs/contracts/secure-notes.md) · [TOTP 契约](../docs/contracts/vault.md)

## 线上 Hub 与回归验证

D1 已应用 `0004_notes_key_epoch.sql`。Worker 版本为 `91cf9ef5-1736-4f8c-b166-23619816bd58`，Pages 部署为 `443a81fb`。线上核对了三个兼容发现响应和无会话重置的 401。真实本地 workerd 与 D1 覆盖已存在的加密集合、并发重置、跨账号隔离、精确回执重试和旧密钥代际写入拒绝。部署检验未修改真实用户的备忘录。 [部署回执](../docs/validation/hub-0.1.8-deployment.json) · [生产 Hub](https://aptist-loft-hub.pages.dev)

| 范围 | 执行结果 |
| --- | --- |
| 根目录 | Python 43 项及架构检查通过 |
| Rust 客户端 | 130 项通过，Clippy 和格式检查通过。包括 SQLCipher 重开重试、普通登录、备忘录三方合并与 TOTP 版本重试 |
| Go VPN | 正常与 race 各 115 项及 145 个子测试通过。源锁、模块验证、vet 和无 tag 检查通过 |
| Hub | 7 项 Rust、8 项 SQL、Wasm Clippy 和本地 workerd 测试通过 |
| Android 预检 | 真正的 UniFFI 输入通过 Release Kotlin 预编译。Android Hub Wire 4 项和备忘录同步状态 3 项通过 |
| ARM64 Release | 应用 JVM 109 项、基础 JVM 121 项通过。Lint 为 0 错误、56 警告。R8 和资源缩减通过 |

首次 workerd 用例复现 v2 能力缺失。客户端先复现了同一条备忘录编辑被覆盖和 TOTP 并发版本写入直接失败。Android 的 Hub Wire 预检先确认旧版格式无法表达耐久身份和协商状态。最终 Rust 和 Android 使用相同修订的生成接口。 [Rust 验证](../loft-core-rust/docs/validation.md) · [Android 敏感剪贴板](https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling) · [D1](https://developers.cloudflare.com/d1/worker-api/d1-database/)

## 安装包与运行范围

签名 ARM64 Release 版本号为 `0.1.8-LYNX`，versionCode 为 9。使用已有 LOFT 开发签名证书。发布 APK 的 SHA-256 为 `d0ae8912249ab4201c1034b2ddca81379e6e9fee6e9dbd521e4a75f6c4e6ba6f`。对应构建使用 Rust 1.100.0、Go 1.27.4、Gradle 8.13、AGP 8.13.2、NDK 28.2 和 SDK 36。生产 Go 输入仍固定为 Gateway 8.0.36。 [APK 记录](../docs/validation/apk-0.1.8-release.json) · [构建记录](../docs/validation/build-0.1.8.json)

x86_64 应用和仪器测试 APK 已构建。API 29 软件模拟器一度响应包管理和 Activity 查询，但始终未报告启动完成，因而未安装测试包。剪贴板实机行为和生产账号在两台手机间的完整同步仍缺少运行证据。
