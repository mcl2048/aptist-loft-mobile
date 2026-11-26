# Android 通知与邮件事件接入

状态：0.1.2 框架实施中。用户要求 VPN 运行时顶部通知栏显示图标，新邮件产生通知。平台通知、实际远端推送和后台存活分别验收。

## VPN 前台通知

`LoftVpnService` 使用 Android 前台服务及独立的 `vpn_connection` 渠道，LOW importance、原生 small icon 和不可变的打开/停止 PendingIntent。通知依据匹配的实际启动、Ready、Blocked、Unavailable 和停止回执更新；连接或资源仍由服务持有时保留通知，完成释放后移除。停止动作走已有优先取消入口，不等待普通队列。

Android 14+ 使用已声明的 `systemExempted` 类型与权限。Android 官方列出的适用情形包括已配置的 VPN 应用，不能为满足静态检查增加无用途的精确闹钟权限。用户启动服务与系统授权的顺序保持有效，前台通知不能由一个后台计时器代替。

Android 13+ 在首次用户连接或主动启用邮件通知的上下文内请求 `POST_NOTIFICATIONS`。还需读取应用通知与具体渠道的实际开关：权限已授予不代表渠道可见。拒绝或关闭时提供明确状态和系统设置入口，保留合法的 VPN 前台服务操作。官方明确指出拒绝权限后 FGS 提示仍在 Task Manager，但不会显示在 notification drawer；此时不能报告顶部图标可见。

通知只显示应用名、真实 VPN 状态与必要动作，不展示节点凭据、账号、流量目标或邮件内容。状态变化及时更新，普通计数最多每 60 秒更新一次，没有通知专用轮询、WakeLock 或额外心跳。通知改善服务的后台运行条件，系统强停、回收、通知策略及厂商行为仍需实际测试。

## 邮件事件与实际能力

Portal 输入固定为 `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36`。`modules/idp/http.ts` 的 Mail GET 仅提供列表、正文与附件。`modules/mail/service.ts` 发布邮件后调用的 `notifyUnread` 只写数据库中的未读标记与 revision，并非手机推送、订阅或 webhook。现有 `mail.read` Token 最长 300 秒，没有 refresh；不能通过延长本地期限实现长期邮件推送。

Android 框架提供独立的惰性邮件渠道、受限的确认事件交付边界和固定 Mail 入口。默认事件权限拒绝，当前没有实际生产者。渠道创建、fixture 投递或通知权限通过均不能标为企业邮件已推送。没有配置的 Firebase SDK、后台邮件轮询或模拟通知不进入默认 APK。

实际部署需在收信的**成功发布边界**增加可认证的邮件事件出口。事件不得由 `accepted: true`、未完成写入、重复 ingest 或列表中的旧邮件推断。Rust 控制面管理显式订阅许可、来源校验、用户/邮箱映射、持久事件记录、推送适配器与有界重试；APK 验证当前 `productId/serverProfileId/issuer/subject/订阅代际` 后才交付通知。邮箱归属以源服务事实为准，不能按邮件地址后缀或客户端传入的目标用户选择。

现有短期 `mail.read` 许可下，订阅不得超过其有效源授权。要实现长期后台新邮件通知，必须另行交付显式的服务端订阅授权及源账号/邮箱/客户端变更的撤销传播，或者经审查的上游续授权机制。读取权限、通知许可与后台订阅期限分别管理；无有效许可时停止投递，不反复打开浏览器登录。

GMS 产品可选 FCM 适配器，需要真实 Firebase 项目、产品配置与服务端密钥；无 GMS 产品使用经过验证的相应提供者或明确显示远端推送不可用。提供者由编译产品配置选择，API/域名集中在适配器。普通新邮件允许系统省电延迟；高优先级只用于实际需要及时显示的用户通知，并遵循提供者当前规则。没有永久在线连接、新的邮件前台服务或反复唤醒来模拟推送。

推送只携带不透明事件/订阅定位与有界计数提示，不传主题、地址、正文、附件、Portal bearer、secret 或可控制的跳转 URL。默认锁屏显示“有新邮件”，点击固定入口后按当前会话主动读取；通知不改变 Portal 源已读状态。退出、切服务器/账号、许可失效或关闭邮件通知时撤销订阅、清除相关通知与去重状态，旧代际事件失败关闭；旧推送不能启动另一企业登录或向其发送令牌。

| 资源 | 初始实施上限 |
| --- | --- |
| 单事件 | 2 KiB，严格长度/字段/代际检查，禁止正文或附件 |
| 待交付 | 8 项、合计 32 KiB，按同一作用域合并摘要 |
| 近期去重 | 128 项、32 KiB，受事件 TTL/订阅期限约束 |
| 平台回调 | 立即交付已确认通知，不自动读取邮件/图像；较长工作由独立有界任务承担 |
| UI 徽标 | 仅已确认通知摘要，最多 99+；不冒充全邮箱未读总数 |

## 验证

VPN 验证通知图标/渠道、实际 FGS、五种状态、顶部停止、UI 退出、权限/渠道关闭和资源释放；以实际 API 29/33/36 范围记录。邮件验证实际投递、重复/乱序/过期事件、跨账户/服务器、退出、隐私锁屏、点击再授权、Doze/离线恢复和有界任务释放。消息被服务接收、被提供者接受和设备实际展示是三个不同回执。

本轮官方资料读取于2026-11-25，原文SHA256/访问状态的可携带记录在 [notification-sources.json](../validation/notification-sources.json)，原文保存在本机 `tmp/research/notifications-2026-11-25/`：

- [Android FGS 类型](https://developer.android.com/develop/background-work/services/fgs/service-types)：VPN 适用条件与 `systemExempted`。
- [Android 通知权限](https://developer.android.com/develop/ui/compose/notifications/notification-permission)：API 33 权限、拒绝后的 FGS/通知抽屉行为。
- [FCM Android 优先级](https://firebase.google.com/docs/cloud-messaging/android-message-priority)：Doze、有限回调工作与高优先级限制。

最终验收仍针对项目根目录 `bin/loft.apk`。实际远端邮件推送依赖尚未部署时，报告保留该前置条件，不以框架渠道替代。
