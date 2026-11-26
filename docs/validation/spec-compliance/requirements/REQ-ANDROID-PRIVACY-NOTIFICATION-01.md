# REQ-ANDROID-PRIVACY-NOTIFICATION-01

目标：0.1.2-LYNX / Android versionCode3。状态：**限定范围的源码审查完成；完整 APP、设备与产物验收待根集成**。

**Verdict：implemented（本次限定的 Android 源码边界）；完整端到端要求仍为 partial / verification pending。** 源码结论固定于 Android owner 的2026-11-26T03:02:22Z preflight `6ca78cbc557b0f925de1520432c49c1d38ea278dfd2e771cbdd021dd6f81f459`。本代理独立匹配128 source entries与3 verified inputs的 bytes/SHA256，逐份解析34个XML回执，未发现身份或计数差异。owner说明没有预定生产源码改动；任何编译驱动改动须重新核对此结论。

本记录由独立 Android 边界审查代理维护。只读核对生产源码、实际调用链、相关测试源码与已保存的完整XML/日志；未执行构建、测试、模拟器、漏洞扫描或设备测量。A04另以只读官方AOSP GET核对Android10实现。仅修改本记录，没有修改 Android、Go、Rust、Gateway 或 Portal 源码。首次host测试执行者为Android owner，A04设备尝试执行者为root；本代理核对身份与结果，没有独立复跑，亦不把host component证据升级为Android运行证据。

## 规范与审查范围

规范为 `docs/contracts/network-privacy.md`、`docs/contracts/resources.md`、`docs/decisions/notifications.md`，以及本机 `guide/guide.md` v3.6 的“Android 通知”“VPN 全局 DNS / WebRTC 防泄漏”和 `guide/ui-design.md` 的“系统通知与权限”“VPN 首页”“UI 自身的内存与电池约束”。遵守根/Android AGENTS、aptist-loft skill；先追踪调用者和被调用者，再判断规范差异。

本次检查 Android 的实际 UID/策略冻结、canonical policy 交付、TUN/Go Ready 与 Blocked 回执、优先 Stop/原始 descriptor 关闭、停止后的统计历史、VPN 前台通知权限/顺序/语言和默认拒绝的邮件投递边界。Go 的协议实现、Rust 的已完成审查、TTL 修复、Portal OAuth 和生产推送不在重复审查范围。

规范原文：

> “Kotlin rechecks the installation/UID facts before Builder, after establishment and before Ready. A mismatch priority-stops that captured attempt.” — `docs/contracts/network-privacy.md`，Scope and ticket freeze。
>
> “Android must not turn this closed history into active protection or combine totals across scopes.” — 同文，DNS, RTC and bounded resources。
>
> “通知依据匹配的实际启动、Ready、Blocked、Unavailable 和停止回执更新；连接或资源仍由服务持有时保留通知，完成释放后移除。停止动作走已有优先取消入口，不等待普通队列。” — `docs/decisions/notifications.md:L7`。
>
> “默认事件权限拒绝，当前没有实际生产者。渠道创建、fixture 投递或通知权限通过均不能标为企业邮件已推送。” — 同文，邮件事件与实际能力。

## 已追踪的生产调用链

下表的 service/adapter 文件均在 `loft-android/app/src/main/kotlin/net/aptist/loft/service/`；foundation 文件在 `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/`。代码范围引用对应下方 preflight 哈希，未把旧行号指向修订后的源码。

| 要求 | 实际调用链及依赖 |
| --- | --- |
| 实际作用域冻结 | `LoftRuntimeOwner.beginVpn:L188-L214` → `AndroidPackageScope:L26-L47` → `SharedUidScope.effective:L21-L48` / `FrozenUidScope.capture:L11-L32` → ticket `freezeEffectivePackages`、`freezeNetworkScope`。全隧道仍冻结正的实际 owner UID；所选模式展开完整共享 UID 组，限制100包/4096名称字节，并检查同 Android user。 |
| 冻结策略先于运行 | `LoftRuntimeOwner:L198-L207` 从同一 Rust ticket 捕获 epoch/scope/policy；`startTransport:L263-L280` 在 Builder 前后重新检查安装身份，再验证 ticket 的确定性 canonical JSON，`setNetworkPolicy` 在 listener、one-use raw URI、Go Start 前执行。`GoNetworkPolicy:L11-L24` 检查4096 bytes与完整 canonical equality。实际 Builder 先建立，不将未启动的数据面标为 Ready。 |
| Ready 来自实际事实 | `LoftRuntimeOwner:L307-L337` 拒绝错代际/错策略及无证明的 Running，在 Ready 前再次检查 UID；`NetworkPrivacyReceipts:L9-L21` 要求当前 scope、三项 TUN 配置确认、Go authenticated/owned/protected/current-enforcer/no-pending，再由 Rust `markVpnReady` 接受。`GoVpnSnapshot:L17-L23`、`GoNetworkPrivacyFacts:L17-L25` 分别约束真实运行与策略 proof。 |
| Blocked 与 Stop 分开 | `LoftRuntimeOwner.reconcileFailure:L347-L374` 在保留原始 TUN 时先 Abort/join；`NetworkPrivacyReceipts:L24-L36` 要求 disabled、无 active DNS/RTC/IPv6/Hydra proof、当前 scope 及 construction join；Rust接受后才标记 Blocked。 |
| 优先取消与真实关闭 | Binder `LoftCoreService:L18-L20` /通知 `LoftVpnService:L40-L41` / revoke `L105` → owner `L381-L423`：优先 Rust fence、cached stopping notice、terminal resolver cancellation与captured original close。`StopDispatch:L5-L9` 在coalescing/enqueue前执行original cancellation；Go Abort、Start await、Close、查询与发布在reserved worker。owner `L436-L485` 分别确认original/Go/平台 callback owners，失败不释放 active ownership、不移除foreground lease。 |
| 停止后的历史不恢复防护 | `NetworkResourceSnapshot:L17-L25` 只接收同一 epoch/scope/policy；owner `L459-L467` 只保留Rust接受且joined的最终统计，`L493-L511` 关联正确attempt/applied facts。`SnapshotWire:L180-L201` finalized仅允许Disconnected/Unavailable、无applied proof、动态资源零；新attempt在owner `L212` 清除旧记录。资源record没有enforcement flags，计数不可充当proof。 |
| 通知依据服务事实 | `LoftVpnService:L34-L45,L64-L103` 使用真实FGS/native icon/fixed immutable intents与测试过的projection；`ForegroundPublication:L8-L18` 检查lease/sequence。`LoftNotificationChannels:L24-L39` 分别检查权限、APP/渠道；`MainActivity:L125-L134` 将申请绑定用户连接并在拒绝后继续实际VPN授权。owner `L98-L103`、`CoreServiceClient:L66-L70` 与private Binder locale port只修改呈现。 |
| 邮件默认拒绝且有界 | owner `L55,L95-L97` 使用默认deny；`MailNotificationEvents:L28-L34,L116-L153` 严格codec、8 pending/128 recent与重检scope/subscription/期限；没有provider/IPC生产者。`LoftMailNotifications:L20-L27,L33-L41` 本地clock、单作用域/compiled product检查与权限重检；`L46-L59` 泛化锁屏文字、固定Mail入口，只标platform submission。`LoftApp:L538-L545` 单独明确远端事件未配置。 |

以上是源码追踪结果，不是对实际 VPN/设备效果的验收。TUN 三项 Boolean 确认成功建立的 Builder 配置，不是独立的内核证明。

## 发现与修订检查

### A01：停止/不可用通知被 Blocked 文案覆盖

已确认的旧生产分支：`LoftVpnService.show` 先测试 `frame.tunHeld && frame.forwardingDisabled`，再测试 Rust `STOPPING` / `UNAVAILABLE`。因此原始 descriptor Close 失败或待清理、TUN仍保持 drop scope 的合法停止/不可用帧会显示 Blocked，而规范要求清晰显示停止中/状态不可用。调用者为 `LoftRuntimeOwner.publish`；资源/状态来源为 `metadata` 与 Rust snapshot。

2026-11-26T02:15:18Z 观察的该文件：6796 bytes，SHA256 `55c9805a7adc3a287b2c14b2efabf2b7a02717606f3ecf9f8ad38c34a604fe02`。发现已同时发送root/Android owner，owner独立确认。

最终修订已入生产链：`VpnNotificationProjection:L12-L24` 按Rust枚举先映射Stopping/Unavailable，Connected/Blocked另需匹配actual proof，Disconnected只在资源已释放时为Released。service `L66-L88` 使用此projection、current stopping/ready/blocked cache及unsequenced Stop fence；owner `L396-L401` 在实际取消入口发布Stopping，所有Go/resource join仍留在worker。实际cleanup失败走owner `L477-L481` 的sequenced frame，不伪装已释放。`snapshotAllowed` 明确保留sequenced Unavailable以报告真实停止失败；未宣称它拒绝一切Unavailable消息。source/host component修订已确认，实际Android通知排序/展示仍待root执行。

### A02：resource JSON 严格尾部/数字语法

初次阅读时 closing branch 以 JSONTokener 的 NUL sentinel 判断 EOF，不能独立证明原始 NUL/后续 bytes 已耗尽；同一 parser 的宽松 whitespace/整数行为也不满足严格 schema。没有在本审查执行复现，故不记作独立复现漏洞。

随后读到实际修订 `GoVpnSnapshot.FlatReader:L57-L137`：明确cursor/end，只接受JSON whitespace、十进制整数、严格string escape，在known-key/type转换前拒绝未知/重复/null/nested/trailing。测试 `GoVpnSnapshotTest:L42-L56` 含NUL后跟bytes、01/0x1/1e0/+1。02:15:18Z中间文件9705 bytes/SHA `b8a509ccbb7e84b446d5660571b1ea1c30bfb5897071ca57d6ed66baebb937b9`；最终身份见inventory附录。本代理检查owner保存的58/1语法RED及58/0 GREEN，随后69/0完整wire回执仍覆盖该测试。结论是已确认的source/host-component修订，没有额外Android或漏洞利用验收。

### A03：旧 startup callback 与同步 snapshot 的顺序（已确认component缺陷与修订）

Go `Runtime.SetListener/publish/deliver` 将先捕获的 JSON 入队，Android `startTransport` 还在 Start 返回后直接调用 `receiveGo(runtime.snapshot())`。初读版本的 `receiveGo` 允许generation0/1；同一 attempt 当时未见 startup snapshot 的单调顺序检查。如果先捕获的 Idle/Starting callback 在同步 Running 与 Rust Ready 之后才到达，它可能覆盖 `attempt.facts`；后续 `metadata` 的 Connected/ready=false 组合被 `SnapshotWire` 拒绝并触发 fault。Stop/fault fence 已避免晚到 Ready 恢复被停止的连接，所述疑点是另一个可能的可用性退化。

初始阶段仅为source疑点。本代理随后读取owner的blind-set baseline cache源码、configured Idle variant、真实 `SnapshotWire.encode` 的1/1失败XML与69/10 baseline。configured variant保留了已安装epoch/scope/policy，避免用未配置fixture冒充setter后的Idle；这些是重现原cache行为及encoder影响的host component证据，不是实际JNI listener调度复现。

最终 `GoSnapshotAdmission:L14-L27` 在同一 `@Synchronized observe` 内检查generation floor、离开startup、terminal/fully-joined closure，再提交 `facts.set`；不存在compare后解锁再commit。`LoftRuntimeOwner:L83,L316,L327,L354,L444,L499` 的receiver、abort refresh、cleanup与metadata均使用同一cache，没有旁路 `AtomicReference.set`。错误Running proof在owner `L311-L312` 先触发fault，不能被旧startup过滤器掩盖。`GoSnapshotAdmissionTest:L36-L108` 覆盖真实encoder、late Idle/Starting、pending→joined、terminal→late Ready和受控两线程capture/Ready交错；保存的完整GREEN69/0无失败。source/host-component修订已确认；真正Go callback/Android运行留给匹配输入测试。

## 保存回执的独立核对

以下目录相对 `loft-android/`。本代理逐份解析完整XML及日志成功/失败标记、核对hash，未启动这些测试命令。

| 回执 | XML tests / failures / errors / skipped | 日志SHA256 |
| --- | --- | --- |
| `build/android-receipt-admission-review/red/gradle.log`，blind cache + 原projection | 69 / 10 / 0 / 0 | `c91011b5b03242a298a1d49f5edab22d15100d7bf57016c2e3ef53cf3a20b687` |
| `build/android-receipt-admission-review/configured-publication-impact-red/gradle.log`，configured Idle→actual encoder | 1 / 1 / 0 / 0 | `545b07f4a1a7135a621cd06216f9fa27886e6c7719d6a2928bbf2bd15ad7076a` |
| `build/android-receipt-admission-review/green/gradle.log` | 69 / 0 / 0 / 0 | `c7f224b453072a199abb0b7d5a31400c1f0f08ad42a7a9e9a29031d27fea572b` |
| `build/go-resource-json-review/red/gradle.log` | 58 / 1 / 0 / 0 | `4ac95524f51c5b9f306a533c750f36f1b9fe2c86d0b555e884875107bd42da43` |
| `build/go-resource-json-review/green/gradle.log` | 58 / 0 / 0 / 0 | `419ea7b64ef8c495938a30313d870488c53cef4b9295c902067aaac2ece433fe` |
| preflight pinned foundation XML，含mail deny/codec/queue与UID/lease/Stop组件 | 115 / 0 / 0 / 0 | 22 XML均匹配preflight的完整SHA/bytes |

其中RED69/10的10个失败分别落在late startup/encoder、generation regression、captured Idle、terminal/pending closure与5个notification projection条件；不是依赖下载或编译失败。GREEN69/0包含所有12个wire suites，与preflight匹配。255个字符串key存在于en/zh/ja/de的preflight source；本代理另逐项读取关键通知/隐私文案，不把四语source一致性写成设备显示通过。

## 搜索与反证边界

- 搜索并逐段读取 `freezeNetworkScope` / `setNetworkPolicy` / `markVpnReady` / `markVpnBlocked` / `requestStopOwned` / `facts.observe,current` 的实际caller/callee；setter、receipt、cache和worker路径均命中production，不只命中tests。
- `acceptMailEvent` 只有内部默认deny边界；AIDL/manifest没有mail event producer，默认APK路径没有Firebase/WorkManager/periodic notification or mail worker。`Firebase|WorkManager|PeriodicWork|postDelayed|Timer|WakeLock|WifiLock|scheduleAtFixed|poll` 在production树的检查仅命中“无隐藏轮询”静态文案，无相应执行逻辑。
- 对A01的反证是业务state优先于general held/drop，Blocked/Ready另以current cached receipt限制；对A03的反证是compare+commit同锁及无旁路写。源码缺陷与host组件证据相互对应，未把这次审查称为生产漏洞扫描或完整安全认证。

## 待完成的证据

- 后续任何build-driven source变化，须重新生成preflight并复核本记录；当前128 source/3 input与XML身份已完成独立核对。
- 根集成执行匹配 Rust/Go/AAR/native 的完整受影响 suites、实际 X/Pro synthetic DNS→alias→original-hostname certificate/TLS/HTTP200、Stop/失联/资源 join 及通知入口测试。本记录不将历史0.1.1结果移植为0.1.2验收。
- 实际通知图标/FGS/顶部停止/UI退出/语言，以及 API33+ 权限和渠道关闭；源码权限检查不能证明顶部可见。
- ARM64 Release 与最终 `bin/loft.apk` 的真实构建、签名/版本/manifest/ABI/对齐/secret、same-source identities；本审查没有产生APK或Git交付回执。
- 实体 Fold、所选/未选APP出口、安装/共享UID变更、Always-on/lockdown、厂商后台/Doze、PSS/耗电及24/48/72小时长跑保持未验证。
- 实际新邮件仍缺真实成功发布事件、Rust订阅/source authority、长期授权及配置好的provider；default-denied sink、channel与fixture均不算生产推送完成。

## 输入身份

2026-11-26T02:15:18Z 规范文件观察值（本机 guide 仅记录摘要，仍不随交付分发）：

| 文件 | bytes | SHA256 |
| --- | ---: | --- |
| `docs/contracts/network-privacy.md` | 9274 | `0c63bb7491e22ddb8bb95956f4299ab3cf41783d3e96eac22d8015baad725809` |
| `docs/contracts/resources.md` | 7718 | `7d5a92bf64e9f75a327c7a9bfcde94511bb99fa99acbb49de06618eecd1ffcd4` |
| `docs/decisions/notifications.md` | 6196 | `46c030de4ad820cb04fe3ad4019061cbaf0970028eeaeeaf6cbffcf3ac633d22` |
| `guide/guide.md` | 149779 | `9df7afd301093eee10f04be9dc7450eb9f34444b86d4e345cbbf5abe3f7dc3d6` |
| `guide/ui-design.md` | 42919 | `e1d94bcf119db2059d34b7a167cebf678d3434f9c288e49b73e535935360e007` |

上述03:02 preflight当时仅是source checkpoint：`whole_app_compiled=false`、`instrumentation_executed=false`、`matching_go_aar_pending=true`。后续root的x86编译及通知失败记录见A04，不回写或覆盖这份首次输入。最终ARM64 APK、权限/渠道拒绝、实体Fold/PSS/电池与邮件provider仍须独立验收；完整产品要求仍为partial，不能用本记录替代项目根 `bin/loft.apk` 的验收。

## 关键源码身份

owner完整preflight位于本机 `loft-android/build/source-preflight/0.1.2-LYNX/android-source-preflight.json`，SHA256 `6ca78cbc557b0f925de1520432c49c1d38ea278dfd2e771cbdd021dd6f81f459`。本代理已核对其128 entries，下面保留本次读取路径的关键身份供source变更审查；路径相对 `loft-android/`。预审没有匹配Go AAR或完整APK。

<details>
<summary>关键源码/测试/系统资源的bytes与SHA256</summary>

| 路径 | bytes | SHA256 |
| --- | ---: | --- |
| `app/src/androidTest/kotlin/net/aptist/loft/service/AndroidVpnIntegrationTest.kt` | 25936 | `1637ad8cc3fc24aa3470d5b3a8d95ff4fa3ef15e02505c2581e2c996a2a63b30` |
| `app/src/main/AndroidManifest.xml` | 2348 | `8ed4a7d3e79fd3c5b32bae395187aa31deaa207ac6cb75fc86c53becfc883979` |
| `app/src/main/aidl/net/aptist/loft/ipc/ILoftControl.aidl` | 419 | `495e69f563328530284887396546b1053dcc8d1a44f602cc467842cb31ebf5de` |
| `app/src/main/aidl/net/aptist/loft/ipc/ILoftEvents.aidl` | 252 | `39348c9f59113daaa42661f614c164e441e0213862a91bfd3724a522bc539c7b` |
| `app/src/main/kotlin/net/aptist/loft/MainActivity.kt` | 7069 | `4810d789e0bf83e5fddffe6d7e77c9b7a42981255be7bdbe35e0c790002f71b8` |
| `app/src/main/kotlin/net/aptist/loft/service/AndroidPackageScope.kt` | 2554 | `05d7620b3a48bf0fb5681a4acec8081536370bb6240ae675ce249ab7ac47b7dc` |
| `app/src/main/kotlin/net/aptist/loft/service/AndroidSocketProtector.kt` | 4119 | `622ab0926d96731e4036650e7f733a4b8aceed02570041b5ea38450f26f17408` |
| `app/src/main/kotlin/net/aptist/loft/service/CoreServiceClient.kt` | 9041 | `4358f211296829f67a967f1f73cbd12975449ca96e3516af66e07949c65507c9` |
| `app/src/main/kotlin/net/aptist/loft/service/GoNetworkPolicy.kt` | 4729 | `6abb7c83916749e65fb10a47f27fa15dfac02b92f7540490c3604fda4a111bf7` |
| `app/src/main/kotlin/net/aptist/loft/service/GoNetworkPrivacyFacts.kt` | 2159 | `7700090eb39056863c5a19a3ea220f4d36f0456f26389586cff6755db2773ce1` |
| `app/src/main/kotlin/net/aptist/loft/service/GoSnapshotAdmission.kt` | 1532 | `6534694eccaac15d8a4a6b7a13ac8e12b9e31e92209aba97c55084c8fb4eb1ce` |
| `app/src/main/kotlin/net/aptist/loft/service/GoVpnSnapshot.kt` | 12256 | `535138da3b01e7876e819ed7b4663f57cc15a73b0c3af8b6941e5be7af13637d` |
| `app/src/main/kotlin/net/aptist/loft/service/LoftCoreService.kt` | 1741 | `b0a1be77f329488e0f1e6cf628bfbf2a060188998d886bff33bb69bb07187678` |
| `app/src/main/kotlin/net/aptist/loft/service/LoftMailNotifications.kt` | 4015 | `60b49b6e4161842c55dbc2b265e3c8df9cec3229119d75b2ca6a40eb32056241` |
| `app/src/main/kotlin/net/aptist/loft/service/LoftNotificationChannels.kt` | 2112 | `1dadb083f1242cc6dda8d274884d4f51efb7b22134acdfd3acf4b297089ddfcd` |
| `app/src/main/kotlin/net/aptist/loft/service/LoftRuntimeOwner.kt` | 34280 | `7f34905ec9b1f6a68b036a47134954fcf29f41be252187ff1a0179b187bcebcd` |
| `app/src/main/kotlin/net/aptist/loft/service/LoftVpnService.kt` | 7412 | `dd6a25e0c2a304c2b1e06ceea73a944d78bf8e66103748b1b205f478fe934d7c` |
| `app/src/main/kotlin/net/aptist/loft/service/NetworkPrivacyAdapter.kt` | 1343 | `e2a3ce9b41a2e219e794cf29cd591cb16068bea3eab72260b48a64080ed6cc46` |
| `app/src/main/kotlin/net/aptist/loft/service/NetworkPrivacyReceipts.kt` | 2699 | `fe8f08bf332114efd779d53b019a1bf93389e01982e05d04878643ca40da8bde` |
| `app/src/main/kotlin/net/aptist/loft/service/NetworkResourceSnapshot.kt` | 1923 | `789997cd61fe1ed50186e21ee0b88726df4a1ea6bda1c6c9308a900359e7c3f4` |
| `app/src/main/kotlin/net/aptist/loft/service/SnapshotConsumer.kt` | 535 | `ae5b9a42a90775d96ee909cbed7a45fd241b26eac2e5db4a38119d304c87806c` |
| `app/src/main/kotlin/net/aptist/loft/service/SnapshotPublisher.kt` | 1437 | `9ca00b95edc777528f792502dd52a68d701e6d4693293b194599d45731086d7f` |
| `app/src/main/kotlin/net/aptist/loft/service/SnapshotWire.kt` | 17975 | `b6ea9086098f469ecc4756f2bef4265e8908ca5c4a649d58462447e6601c3660` |
| `app/src/main/kotlin/net/aptist/loft/service/VpnNotificationProjection.kt` | 1948 | `164400c94b3ef5e563ebc13831ee106ba925c14075793caa8ac5ea2cd2ca7732` |
| `app/src/main/kotlin/net/aptist/loft/ui/LoftApp.kt` | 46622 | `c839438de59aa5ff3cde0ad0a07b9c9fac762754e9d89536f8b28bd19cb624ad` |
| `app/src/main/kotlin/net/aptist/loft/ui/LoftViewModel.kt` | 24585 | `bcbd40e241e846b2c780424aa255f9a6cd59df85efb248bbaa961bd5ed3335cd` |
| `app/src/main/res/drawable/ic_mail.xml` | 401 | `b4bf52d3a7d51b692cc84d01419bf1824403d284590225f846f5cbf51aa41e1b` |
| `app/src/main/res/drawable/ic_network.xml` | 438 | `606b641b8c286e032bf93f1e03cfa8a11cba951be87931857ae0d934614a8d7f` |
| `app/src/main/res/values/strings.xml` | 22914 | `8b17ffa3023c1bd41fc6757d78d3a1d621dbe7353ee0589e9456eeb8a6a62284` |
| `app/src/main/res/values-de/strings.xml` | 24829 | `c162110794f96329880272a92ad3a30c17cb9ea64554cd8e976abe6543664c0b` |
| `app/src/main/res/values-ja/strings.xml` | 27240 | `4fa87ca046552144ea143e83552c074f0cf208bbad067e22f8595275f2026b59` |
| `app/src/main/res/values-zh/strings.xml` | 21815 | `e4d6f3437187666354c59a2c3467a631f4bfbc939bcd6c413c0c81f09d3ce008` |
| `app/src/test/kotlin/net/aptist/loft/service/GoSnapshotAdmissionTest.kt` | 6200 | `a6c838c2c677844776a08a29ffc8b921fe752b6e0e4e6a763bab7bf1cd3d0980` |
| `app/src/test/kotlin/net/aptist/loft/service/GoVpnSnapshotTest.kt` | 9873 | `4e05e309c3f52167c46906b2e2172eef3745747ea73ad2403f81ba214c883c7c` |
| `app/src/test/kotlin/net/aptist/loft/service/NetworkPrivacyReceiptsTest.kt` | 4840 | `e2dbe4c363d63626c80ebb679da01e128a4320e3ea6ac7179df50174807b5103` |
| `app/src/test/kotlin/net/aptist/loft/service/NetworkResourceSnapshotTest.kt` | 3039 | `c8bf25a4678bbb0fefb76f6b87f03eb26f94026508487a243c6f8d8a3e0b61e8` |
| `app/src/test/kotlin/net/aptist/loft/service/VpnNotificationProjectionTest.kt` | 3427 | `5d49764d86ae4428468412ed8cf1aebc63196314e92969ac5437ea1b1c113261` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/ForegroundPublication.kt` | 966 | `429429cb6a76bebb30275514dfc7b924974c3b5a8a8b462e9b4ca4bbde9e08bc` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/FrozenUidScope.kt` | 2173 | `60841cd82a588c08c5beb8a03f0467e4d9f6c8ed7b87b7918da92a8240ab437e` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/MailNotificationEvents.kt` | 9631 | `af40e46d08ad72f82ca40567067824e53dcd24eb9bbdf4678cae18d995b0872f` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/NativeResources.kt` | 1689 | `6242b81a6a80c57c5a9d0273dd84d09324bce994b9ad6e316fb21c1a8bfa8bf5` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/NotificationAccess.kt` | 875 | `c8adf379bfaa65250edba903d7ce5a48e319d0c57c78e5bb2f73c84f86e14351` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/OriginalTunOwnership.kt` | 2311 | `ea2c6b7a5fea55c20d65ec369d17f737325af517b2a55e003970cd205b04153f` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/SharedUidScope.kt` | 3080 | `22ab51a394a55a425c3e68e3706bd22ca9bb1897240a7f9e0292a3583ec95f80` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/SnapshotSequence.kt` | 630 | `f430a01e983a5de536be3a57e1381722de4c0e7d8c0abbea25bf10a13171f502` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/StartOwnership.kt` | 966 | `07712d15db1a86ebe6009988f4c4ba6646b96211bdcac9eda5e0a82f79a4634b` |
| `ui-foundation/src/main/kotlin/net/aptist/loft/foundation/StopDispatch.kt` | 406 | `663b02e460015e983aef8c8c4b4dac28263d26b8ccc5b62fb7c4d3c9024b2f24` |
| `ui-foundation/src/test/kotlin/net/aptist/loft/foundation/ForegroundPublicationTest.kt` | 2456 | `e2bc879b919407ff32b5d4083858394d24fb3290c5cfe56c130a9c71d0f9f455` |
| `ui-foundation/src/test/kotlin/net/aptist/loft/foundation/MailNotificationEventsTest.kt` | 7128 | `40021b3e377363b858ef2671f102042655e77f913859f28f5a6e0501f7109fe1` |
| `ui-foundation/src/test/kotlin/net/aptist/loft/foundation/NotificationAccessTest.kt` | 1478 | `bb868f26d601e6232fee5a5a2707135ec67ab3b42693ed54b574c498baa4a297` |

</details>

已核对的生成输入仅为：UniFFI Kotlin143797 bytes/SHA `656d7b78abac672575af6ef1ec3cec4bba324356eccbc8d0216d4681809ef853`；ARM64 Rust JNI1582648 bytes/SHA `ac386efe89d8ea30cd437e3309ca52b78b2649e11391e9867b4f2b4aa9ea5446`；项目VERSION11 bytes/SHA `c5d6b92ba83dafb28a2566dd2b8ee17cb22d861464323c3832c2b0175277991c`。这三项身份一致，不构成Go绑定、签名、APK或设备验收。

## A04：Android10 pending通知对象与实际前台服务的观察竞态

追加范围：root在真实0.1.2 x86 APK运行中发现通知标志位断言失败，独立审查仅追踪Android10 AMS/NMS及应用调用链、核对安全日志与身份。**当前结论：单次getter结果的FGS flag断言不能证明服务退出前台；source定义了pending update窗口，root的同时段诊断实际观察到AMS foreground=true。通知稳定条件及Stop完整测试仍待root重跑。** 不把第一次失败改成通过，也未修改生产生命周期或手工添加FGS flag。

### 首次输入、失败与诊断身份

- 保留首次preflight `6ca78cbc557b0f925de1520432c49c1d38ea278dfd2e771cbdd021dd6f81f459`，保存副本 `loft-android/build/fgs-flag-review/baseline/first-preflight.json` 内容相同。
- 首个已编译x86 debug应用：49672189 bytes，SHA256 `652456169a6c9d91e635a2513bbb72c594a8482c6196ecbd0edaec82ce512ae8`。来源为 `docs/validation/android-0.1.2-x86-build.json`；本代理03:52独立流式hash当前该APK，确认仍匹配。它是software-emulator profile，不能替代ARM64 `bin/loft.apk`。
- 首次 `realStartFailureKeepsBlockedNotificationUntilStop` 使用公开loopback SOCKS失败目标，已到达真实Rust Blocked、TUN held、proxy disabled、privacy Blocked及own-notification getter的正确文字/icon；在旧test:L321的 `FLAG_FOREGROUND_SERVICE` assertion失败，后续 `requireActualForegroundService` 尚未执行。安全日志 `tmp/verification/root-0.1.2/android-blocked-notification.log` SHA `dc3c6d5df883e33105a72cd6909895b3fe6213b2f6f1f58b6e1ebafc8b591433`，JSON `passed=false`。命令exit0不代表测试通过；JUnit为1 test / 1 failure。
- Android owner追加test-only同时段诊断，保存原assertion；本代理03:52核对时，production `LoftVpnService` SHA `dd6a25e0c2a304c2b1e06ceea73a944d78bf8e66103748b1b205f478fe934d7c` 与 `LoftRuntimeOwner` SHA `7f34905ec9b1f6a68b036a47134954fcf29f41be252187ff1a0179b187bcebcd` 均匹配首次preflight和baseline。诊断test源码SHA `4942da16301b5cb881341cceb7ab5f11852297eba01a9d092e787438dd21c455`，test APK SHA `37721db56a5d1304ff9bcbca56519d56f31ebbaa7949a259cece2cca95a94a30`。
- root诊断运行日志 `tmp/verification/root-0.1.2/android-blocked-notification-diagnostic.log` SHA `4f3bb6f7550d3e24850e0880083fb81ea79eee005e55b70ac6a70e79442663f9`，JSON仍 `passed=false`。本代理完整读取并核对其hash。发生在assertion之前的记录为 `flags=0x2, fgRecords=1, foreground=1, started=1, pidKnown=true, state=BLOCKED, tun=true, ready=false, disabled=true, released=false`。这是同时段AMS事实，不是失败后force-stop状态的推断。原flag assertion仍为1/1失败，Stop尾段尚不能标为通过。

### 独立核对的官方源码

只读GET官方 `platform/frameworks/base` 的 `refs/tags/android-10.0.0_r1`，没有使用floating HEAD。owner的 `loft-android/build/fgs-flag-review/references/source-pins.json` SHA `aab7b73b274323df8753c70a1b598549db709a75c1d6e450a85e41114304d26a` 固定解析commit `57bb140be9e48cf08acba131f7463e461777bb8e`；本代理另直接GET前三份的commit URL，再次确认bytes/SHA/local copy完全相等。下表为实际Base64解码body身份，行号针对该内容；官方参考pin不冒充模拟器framework二进制的精确build identity。

| 来源路径（位于上述官方release tag） | bytes | SHA256 |
| --- | ---: | --- |
| [ActiveServices.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java) | 205018 | `31e4b7a7d300ba14401175f301c822649783442b8e34eea835281fc6446e4849` |
| [ServiceRecord.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/services/core/java/com/android/server/am/ServiceRecord.java) | 45297 | `5976c9e0c94ff583f0733855577ce0563130458ffa46a904e27a1aa666e0a1e8` |
| [NotificationManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/services/core/java/com/android/server/notification/NotificationManagerService.java) | 377290 | `af2ba2a6e5fe84233bf4b453512c7dfd5f26cfa675477f3a9a73293db63b85cf` |
| [NotificationManager.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/core/java/android/app/NotificationManager.java) | 81495 | `058a2d716e3f925619cf54aa11528e1cf508f33e0aa2673be037eb6a784faa0d` |
| [Notification.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/core/java/android/app/Notification.java) | 419070 | `04f4b745c48c3cee5b1b4ae0ef9c963342e304cbb68d296e614d559a1f4d2fc4` |
| [NotificationRecord.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/services/core/java/com/android/server/notification/NotificationRecord.java) | 53303 | `c10e1d3d7958fc02a940455e4a04d712d871e13525038faa198f05306e01f4f8` |

### 实际调用链及flag时间点

1. 应用 `LoftVpnService:L34-L45` 首先调用真实 `startForeground`。AMS `ActiveServices.setServiceForegroundInnerLocked:L1330-L1379` 在允许分支给notification加FGS flag、保存foregroundNoti、设置 `ServiceRecord.isForeground=true`，再发通知；`ServiceRecord.postNotification:L792-L805,L890-L905` 通过AMS handler异步调用NMS，notification posting与AMS业务标志不是同一个原子动作。
2. 应用 `show/showBlocked/showUnavailable/refreshLocalizedNotification:L64-L92` 以 `NotificationManager.notify` 更新相同id，`notification:L97-L103` 是新的ongoing Builder对象，并未手工加FGS flag。系统NMS `enqueueNotificationInternal:L4718-L4724,L4779` 创建新record并排Enqueue；`EnqueueNotificationRunnable:L5273-L5281` 将其放入pending list。被调用的 `NotificationRecord.copyRankingInformation:L399-L413` 只复制ranking字段，没有复制FGS flag。
3. NMS直到 `PostNotificationRunnable:L5371-L5397` 替换已有posted record时才从old继承FGS flag（`L5383-L5385`），再补ongoing/no-clear等flags；pending record最终在 `L5440-L5447` 移除。两次handler阶段之间存在可观察窗口。
4. 应用的public `NotificationManager.getActiveNotifications:L1996-L2004` 调用NMS `getAppActiveNotifications`。NMS `L2971-L2994` 先读posted records，再把pending records按相同key覆盖进返回map；因此调用方可先看到正确的新Blocked文字/icon，却拿到尚未继承FGS flag的pending Builder。`sanitizeSbn:L3002-L3014` 使用clone；`Notification.cloneInto:L2371` 原样复制flags，未在public getter中故意抹去FGS bit。
5. 与此独立，`ActiveServices.makeRunningServiceInfoLocked:L3712-L3728` 直接从 `ServiceRecord.isForeground` 填 `RunningServiceInfo.foreground`。root的新诊断在flag断言前取到了这一事实，返回foreground1，而不是根据notification bit猜测。普通 `notify()` 不调用 `setServiceForeground(...id=0)`；真正stop分支在 `ActiveServices:L1409-L1443`，当前应用仅在确认实际释放后的 `releaseForeground:L93-L95` 进入。

上述实现能产生“getter中flag缺失但AMS仍在前台”的反例，与实际 `0x2/foreground1` 诊断相符。原首次日志没有NMS内部pending/post位置，故不将某个具体内部调度序列称为已完整重放；已经证明的一点是**缺少单次通知bit不能等价于FGS退出**。另一种生命周期失败路径为AMS `OP_START_FOREGROUND` / background restriction忽略请求（`ActiveServices:L1294-L1323`），但它不能用来解释当前已测得foreground1的同一诊断时刻，也不能由后验force-stop来补证。

### 当前处理与验收边界

root/Android owner据此将test改为同一5秒deadline内等待fresh notification满足实际text/icon/FGS flag，并独立核对同作用域AMS foreground，同时保留原始RED、诊断和Stop尾段要求。新test源码28048 bytes/SHA `42baca5f611873546f92dc1b25f7fa445719527baa24e199228410724aab764a`；仅为测试观察条件修订，root负责重建及运行。此处不接受手工设置 `FLAG_FOREGROUND_SERVICE` 或移除实际foreground断言来消除失败；通知观察修订没有增加production poll/heartbeat或改变前台服务生命周期。

并行输入说明：本代理结束前的再次身份检查发现 `LoftRuntimeOwner` 已因另一个pending-RUNNING回执修补变为SHA `78e44537b81e66ea1a4bdd3433dfb8e32d7c8623234fade473bdcc289bca4062`，`receiveGo` 改为调用 `GoSnapshotAdmission.requiresFault`。`LoftVpnService` 仍为首次SHA，A04的源/运行分析固定于原APK65245616…及保存的首次生产baseline；未在本FGS范围审查上述其他修补。首份implemented source verdict不覆盖新的worktree，root须提供该修补的独立source/build/runtime回执，不能用首次preflight替代。

截至本追加记录，稳定谓词的完整通知测试重跑结果尚未读取，故不宣布已修复/通过。诊断只证明这一API29 software运行时刻的actual foreground与Blocked/TUN事实；它不证明连续运行、顶部视觉可见、权限/渠道拒绝、系统强停恢复、ARM64/Fold/Doze/PSS/耗电或72小时验收，也不触及真实邮件provider。
