# loftmobile-1125-01 · 框架开发与验证记录

当前状态：**框架与实际签名APK验收通过**。版本 **0.1.2-LYNX / versionCode3**。成品位于 `/home/coder/LOFT-mobile/bin/loft.apk`，21,507,686bytes，SHA256 `64c9ae2370eaf1df45533ea2fb3e93d0961287d381501cac39e0785ff785a81e`；签名/版本/manifest/4-native ZIP+ELF与handoff扫描对同一文件通过。ARM64 Release/R8/shrink/lint、配对x86 Debug的8项API29、独立minified x86 Rust/JNA/private-service/UI启动与静态Go JNI探测均通过。源码发布的确切远端SHA由Root最终独立回执提供；此状态不代表guide完整P0–P5或实机认证。

设计输入为本机 `/home/coder/LOFT-mobile/guide/guide.md` v3.6 和 `/home/coder/LOFT-mobile/guide/ui-design.md`，包括 Pixel/Samsung Fold、共享 DNS/WebRTC 防护和系统通知。Gateway8.0.32-LYNX `231f14813f2b45cb6f0bde984181c57cba1d02fd` 与 Portal2.2.0-PUMA `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36` 是只读输入，未修改其源码或缓存。任务安全上下文 SHA256 为 `bbb40ec5a8c1bd82346552162e320bf5bee9e60b312b69b0995077ab64e9a081`；私有任务和测试节点不进入源码、APK、归档或日志。

最终验收只针对本机 `/home/coder/LOFT-mobile/bin/loft.apk` 的实际文件及对应源码、构建和测试身份；此原则已写入仓库与安装版 aptist-loft skill。文件采用本地开发签名 `CN=LOFT Local Development, O=LOFT Mobile`，cert SHA256 `4fd578439fe8c3bb5ab2abc6c33e494753a965dc47e44d96e313962852a400fc`，RSA3072。默认SDK29+验签选择v3，另按SDK24..27验证v2签名块的cryptographic范围，应用minSdk仍29；这不提供Android24安装或ARM64实机认证。[实际交付回执](../docs/validation/apk-0.1.2-release.json)保存校验详情。

## 0.1.2 已执行的检查

以下结果均有实际回执；它们的范围不互相替代。所有者的组件测试与整合 APP 测试存在重叠，不能把计数相加当作独立覆盖量。

| 验证项目 | 实际结果与身份 |
| --- | --- |
| 开发环境 | Rust1.100.0、Go1.27.4、JDK21.0.13.1、Gradle8.13、AGP8.13.2、SDK/build-tools36、NDK28.2.13676358；服务器约171GiB磁盘/9.7GiB内存/4CPU，重型原生和Gradle工作串行。配对x86 build为1worker；ARM canonical entry实际2workers/parallel=false、独立Gradle/Kotlin daemon各配置1536MiB heap limit，环境请求in-process不是执行事实。工具安装与本任务输出不修改其他项目配置。 |
| 根工具与架构 | Root独立38项Python测试与Rust直接生产依赖守护退出0；包含真实index、PAT跨块、URI/PEM/DER私钥、有界读取与归档错误检查。最终暂存区/成品仍需扫描。 |
| Rust核心 | Root完整93测试、fmt/Clippy全部退出0，36个冻结文件bytes/SHA256逐一匹配；[rust-0.1.2-checks.json](../docs/validation/rust-0.1.2-checks.json)。冻结清单SHA `db5b0bc7a146af10f4c24a72ca3459252ae35e7d5a4e3f2a2aa228bb4beb58f3`。 |
| Rust依赖 | [audit回执](../docs/validation/rust-0.1.2-audit.json)：137锁定依赖、0已知漏洞；basic-toml维护提示RUSTSEC-2026-0374仅属host binding-generator，normal Android FFI依赖图不包含它。Cargo.lock SHA `dc811b80791237566399467b9a6b59e59931c3bf058557c36ca666a3bacbfad8`。 |
| Go完整数据面 | Root独立with_gvisor normal/race各114顶层/145子测试、0失败/竞态；499冻结身份匹配。所有者no-tag86/140、vet、module verify、lint和govulncheck退出0；owned source verifier核对434文件、12项移动修改与6组来源补丁，不依赖上游当前worktree。[go-0.1.2-checks.json](../docs/validation/go-0.1.2-checks.json)。冻结SHA `ccfb8e15f0b4a4966fdf1505fd2f040f2fd2bb99a77cb6756e6b4ceb94007292`。 |
| 实际主机隐私路径 | 完整Go套件包括受控X/Pro/SOCKS gVisor DNS→alias→原FQDN证书/TLS/HTTP200→UDP→Stop、任意端口/分段/畸形识别与拒绝、TTL/引用/池恢复、loss/Abort/Stop和实际资源归还；不是Android或节点侧DNS/Firewall验收。 |
| 独立DNS修补 | 相同实际Map/Budget与原harness保留RED，Go1.27.4修补后4顶层/3子测试退出0；覆盖晚到续期不能缩短广告TTL、TTL内不能驱逐、并发捕获、正常续期和动态预算归还。[dns-advertisement-ttl-review.json](../docs/validation/dns-advertisement-ttl-review.json)。 |
| 匹配原生输入 | ARM64与隔离x86均生成，Kotlin绑定逐字节相同；ARM64 Rust/Go ELF16KiB兼容检查通过。[native-0.1.2-builds.json](../docs/validation/native-0.1.2-builds.json)绑定到上述Rust/Go冻结源。 |
| Android源码/组件 | 最新130文件源身份匹配，owner preflight SHA `205fb8df1fe2d49b2d32f1e47b4c17a4937f1f1401f0a57a7813d3e7827e6acc`；wire75/0、foundation115/0。当前合法最大binary fixture32811bytes，小于61440；这是实际编码，不是UTF16估算。[source回执](../docs/validation/android-0.1.2-post-pending-source.json)。 |
| 完整x86 APP/AndroidTest | 最新匹配输入Gradle退出0，78 APP JVM测试/0失败/0错误/0跳过，APK及test XML身份已核对。[post-pending build](../docs/validation/android-0.1.2-post-pending-x86-build.json)。APP SHA `e6b575c29d3c3010656d5328e920bf217d20181f43dbc1d91318ada0ede40103`，50,183,475bytes；test SHA `5856a00671f7e4d7099d68a32208263aa4acbb1bc4e26717e95a9b59897d89db`。 |
| 当前APK实际执行 | [android-0.1.2-runtime.json](../docs/validation/android-0.1.2-runtime.json)：8项/0失败，130-source输入匹配，guest与guest-policy/locale已在该APK再次通过；逐项receipt/log及实际APP/test哈希核对无差异。原native1/cancellation-sensitive6在初次0.1.2执行、相关测试源和原生输入未变，未在当前APK重跑，不计入当前8项。 |
| 初次0.1.2 Android检查点 | 首个APP SHA65245616…/testf9e4e158…的72 JVM测试及实际native1、cancel/sensitive6、guest1、guest-policy/locale1通过；此9项API执行属于初次输入，最新130-file APK需独立回归。[初次build](../docs/validation/android-0.1.2-x86-build.json)。 |
| 最新Blocked通知/Stop | 实际API29 loopback连接失败→原TUN held/drop→匹配原生图标、posted NMS FGSflag与AMS foreground→priority Stop→TUN/Go资源/通知移除，1/1通过。`tmp/verification/android-delivery-0.1.2/public-blocked-notification.json`，log SHA `20179f10523881cab76514c8e8677081710a34fecb5cc4a4eb9383434522d4cd`。这是程序化API29范围，状态栏视觉与实机后台存活另验。 |
| 最新X域名VPN | 同一APP/test实际API29 VPN Network uncached A→198.19合成alias→原example.com证书/TLS/HTTP200→Stop，1/1通过；断言匹配策略scope、synthetic正计数、wire/business物理resolver0、fixed540672与动态owner归零。`tmp/verification/android-delivery-0.1.2/node-x-domain.json`，log SHA `30519323f53747501cb6a8c9b509bc9e362c7f9891ff518f78c7f5f0b4fcfe57`。 |
| 最新Pro域名VPN | 与X同一APP/test、同一默认DNS→原域名HTTPS/Stop流程实际1/1通过。`tmp/verification/android-delivery-0.1.2/node-pro-domain.json`，log SHA `7f4c287f29715b35a0d69c29883a22d14b6c90512872b55b05ae915b4ab4994e`。两协议仅guest墙钟按host校准，协议/应用期限未变；仍非handsetpower或Fold证据。 |
| 最新X/Pro连接请求后Stop | 两协议各1/1通过，同一APP/test；停止后5秒观察窗口无late Ready/held TUN，资源按实际join归还。X log SHA `d70d4cc730b983a968a48e36384aaa3c44bf77177f8290ccbb4fb77fb9aa5ce6`，Pro `2820df4ef532551efc5b1ed2616c0e1b241847aa9b2d3aea4d25848616f12829`；对应node-x/pro-stop.json在同一检查目录。该测试不定位Stop精确打断了哪个认证阶段。 |
| 最新已连接通知/四语/UI隐藏 | 同一APP/test的X实际1/1通过：en/zh/ja/de通知文本、原生icon/ongoing/posted NMS FGSflag+AMSforeground，隐藏UI后保持服务；Rust generation/attempt/privacyScope不变。实际notification PendingIntent Stop后TUN/Go资源/通知释放。`node-x-notification.json`在同一检查目录，log SHA `cd123cef91feab7d268dc2a369debe0f4037a667978774f349b7fa2fca5591b4`。 |
| ARM64 Release/R8/lint | 实际canonical entry bash scripts/build-android.sh退出0；14份APP XML共78 tests、22份foundation XML共115，全0失败/error/skip；Lint0 Error/32 Warning。实际执行minifyReleaseWithR8、convertShrunkResourcesToBinaryRelease、optimizeReleaseResources。36 XML、lint、build log及unsigned APK哈希核对无差异；[ARM build receipt](../docs/validation/android-0.1.2-arm64-release-build.json)。unsigned SHA `fdcec3c1686e578657e208817ea3fbc9f0c30cc7f3a070e14e94f0463b2338d1`，21,499,830bytes，不等于最终签名文件。 |
| 实际UI中/宽窗口 | 当前x86 Debug APP的游客VPN页、英语浅色外观、常驻左侧轨道与双列真实截图：[673dp](../docs/validation/ui/loft-0.1.2-guest-vpn-673dp.png)为673×900px/160dpi；[1440dp](../docs/validation/ui/loft-0.1.2-guest-vpn-1440dp.png)实际900×563px/100dpi，Activity config w1440dp/h820dp。两份metadata和PNG哈希匹配，fresh force-stopped guest/无私有节点，显示Not connected/保护inactive；不是物理折叠/ARM Release执行。 |
| 实际签名成品 | [apk-0.1.2-release.json](../docs/validation/apk-0.1.2-release.json)：原子放置bin/loft.apk，candidate与canonical SHA相同并重新检查实际canonical。package net.aptist.loft、29/36/code3、非debug/no backup/no cleartext、private :vpn/BIND_VPN_SERVICE、FGS0x400；四ARM64 native ZIP/ELF16KiB与stripped输出逐bytes/hash匹配，开发签名v3/v2范围及handoff index+APK secret scan通过。Release-doc owner再次独立运行同一APK hash、verify_apk、两种signature范围与aapt2，全部退出0。 |
| Minified x86实际启动 | [r8-smoke](../docs/validation/android-0.1.2-x86-r8-smoke.json)：非debug development APK SHA `b99a6450bcb0ddb31913b801bd52c4c23c5d024db8eff58cab9bb78763654a27`，22,736,474bytes；普通app UID下Rust/JNA/private :vpn service与真实guest snapshot/轨道UI启动通过，四native/PNG/保留Debug/Test哈希匹配。不是ARM执行或新增node回归。 |
| Minified Go JNI独立探测 | [r8-go-jni](../docs/validation/android-0.1.2-x86-r8-go-jni.json)：同一minified APK，普通target UID实际reflection调用kept Engine.vpnRuntimeInfo，305bytes/schema1/gVisor linked/GOMAXPROCS2/inactive descriptor通过，instrumentation退出0。未创建Go VPNRuntime/TUN/节点/socket或网络请求，descriptor Ready=false不当作实时VPN回执。 |
| 发布流程 | 文档/skill冻结后由Root统一核验最终完整index与同一bin/loft.apk，普通main提交保留历史。确切远端SHA以Root最终独立回执/答复为准，不写未来已推送或报告自身提交哈希。 |

原生输入关键身份如下；实际产物清单及命令在native回执内。

| 输入 | SHA256 |
| --- | --- |
| ARM64 Go AAR | `77df0f72d069de9047762c0dbcf8c2df9dbe05634825ee7ef09b583026ee57f4` |
| x86 Go AAR | `b2fed78b8f5503544df594bf52202fdf3bf6f580fbee479ecb353b4161f3b919` |
| ARM64 Rust JNI | `ac386efe89d8ea30cd437e3309ca52b78b2649e11391e9867b4f2b4aa9ea5446` |
| x86 Rust JNI | `5fea563df079bc14c8ca163c253d5873664eb012556a051d7459ada79209d0f9` |
| 两ABI共有Kotlin绑定 | `656d7b78abac672575af6ef1ec3cec4bba324356eccbc8d0216d4681809ef853` |

## 本轮修补、原失败与实际边界

共享DNS/RTC防护位于Go数据路径、在传输选择前执行。Rust冻结独立policy epoch、实际owner UID与PackageManager实际报告的installed/shared-UID范围；Android在Builder前后/Ready前重核OS事实，配置编辑保持draft。Canonical policy是live frozen ticket的无secret幂等getter，raw URI仍一次性且须prior canonical delivery；旧稿“一次性canonical”已按冻结代码纠正。CoreSnapshot2、Android envelope3、NodePage1与Go policy1的版本彼此独立。[独立Rust复核](../docs/validation/spec-compliance/requirements/REQ-NETWORK-PRIVACY-01.md)未确认票据重绑、重复raw消费或旧证明恢复的新缺口；其partial verdict保留自身检查范围，不能改称全平台认证。

Fake-IP默认提供域名路由alias，恢复原FQDN后才由所选代理OPEN；真实wire resolver模式另测。新增256映射/256KiB、TTL60s与固定528KiB地址deadline表全部在8MiB预算内，dynamic为7,847,936bytes。修复稳定续期消耗永久有限池、prepared reply缺I/O租约、旧捕获时间缩短较新TTL、resolve后解锁再borrow误绑定，以及literal IPv6 bootstrap校验绕过。最终回复I/O延伸最大广告期限；late/失败写入只延伸隔离，不恢复proof。关闭后仅保留非域名deadline和一份脱敏ended-scope总数；active proof全false/off，历史不显示为已保护。Hydra沿已有X/Pro钩子独立、默认关闭，producer实际完成计数不依赖caller等候时间；QUBF独立传输尚未接入。

第一次Root Go normal退出1，原497-file源副本与冻结/失败收据完整保留，failure receipt SHA `218353d26cbdba1678d2c793b02107d6e2b61ea72e869aae521a64314cf814cb`、archive SHA `3663864e0ec333ebf5d5f8cf45018b652e2146b3afdf30de7e7a3691c04c83a8`。原调度2/30、确定性3/3复现证明fixture先destroy QUIC listener未发送CONNECTION_CLOSE，再把本地read deadline误作远端关闭。修补只调整测试fixture关闭顺序、真实peer终止断言与清理；431生产Go文件/协议窗口未变。真实peer-loss100轮/300子测试及Root完整normal/race通过，原失败未删除。

初次X domain未到DNS即从Connecting/TUNtrue进入Blocked。实际冻结Go producer观察到合法Running+ownership_pending=true，在Start外层join后只有pendingtrue→false变化；Android误把未settled所有权当fault，late callback又可能覆盖direct Ready。现在同一attempt的callback/direct admission floor原子比较并提交：pending不能fault或发布Ready，也不能覆盖settled Ready/closure；真实loss/invalid settled proof仍拒绝。保留wire RED75/3→GREEN75/0及[实际Go观察](../docs/validation/go-running-pending-observation.json)，130-source重编译后两协议域名测试通过。该原失败不归咎节点DNS。

Android严格consumer同时修复JSONTokener尾NUL把未消费字节当EOF的问题，拒绝unknown/duplicate/case-alias/missing/null/错type及非canonical整数。通知投影保留Rust Stopping/Unavailable优先于generic held-TUN Blocked；Stop ingress只取消/fence，不调用Go getter或等待join。初次通知断言失败保留：[独立通知复核](../docs/validation/spec-compliance/requirements/REQ-ANDROID-PRIVACY-NOTIFICATION-01.md)查明Android10 getActiveNotifications可短暂返回queued update（flags0x2），而AMS.foreground=1。测试在原5秒期限内等待匹配text/icon/posted FGSflag并独立核对AMS；未手工制造flag、删除foreground断言或改变production通知生命周期。最新实际Blocked/Stop通过，原诊断与首次APK身份仍保留。

当前32项Lint warning按实际源码/产物边界保留：singleton的app归一applicationContext，activeAttempt有意持有Service/保护器至实际join后清除，静态检查不等于零泄漏或PSS通过；Android11+目录只有MAIN+LAUNCHER可见、无QUERY_ALL，UID冻结只精确匹配PM报告成员，隐藏成员与全设备/工作资料范围仍待实测；当前单体APK的en/zh/ja/de已由AAPT2确认，未来AAB语言split/download另设验收。合并manifest保留AndroidX Emoji2/lifecycle/profileinstaller标准初始化器，“未初始化push SDK/无额外业务轮询”不能扩大成“没有任何平台初始化”。

## 0.1.1 历史基线

以下是此前的检查点，不能用于替代新的0.1.2完整构建/执行。原回执、失败和哈希不随本轮版本改写。

| 历史检查 | 记录范围 |
| --- | --- |
| 主机完整套件 | Root Rust67/fmt/Clippy、Python38/architecture、audit0已知漏洞；Go normal/race76顶层/31子测试、no-tag/vet/module/govulncheck通过。 |
| Android编译 | 修补后app34+foundation88共122 JVM tests；ARM64 Release/R8/lint退出0，Lint0错误/31警告，四native ZIP/ELF16KiB与manifest检查通过。当时尚未开发签名/最终交付。 |
| actual API29 | guestCreatesNoTunOrGoTransport、Go JNI inert/capability、六项CancellationSignal/触摸/窗口生命周期通过；320dp原生Compose截图展示常驻轨道。不是外部真实overlay/TalkBack/Fold验收。 |
| 私有节点 | X/Pro host认证与域名/literal HTTPS200/577bytes通过；actual API29 selected-UID literal TUN/TLS/HTTP200/Stop和两协议连接中Stop通过。[android-runtime-checkpoint.json](../docs/validation/android-runtime-checkpoint.json)。APP SHA `2a5b0d901bbee202cacfe30dbcdf52bdc3735d663cc25d05b3340a3245b588c0`；主要test SHA `c13b700d443072e15829bbcc799a2d3394d50ed1951c48abf9bd71b32ca088c1`，原Pro literal/cancel-sensitive检查点另有记录内的test身份。 |
| TUN与墙钟原失败 | 初始underlying Network必须在Builder.establish前设置，旧service setter阻止两协议到TUN；[原问题及修补](../docs/validation/spec-compliance/requirements/REQ-VPN-INITIAL-TUN-01.md)保留。X软件guest墙钟落后1639秒触发既有30秒gate，校准仅guest墙钟后同源通过，未修改协议窗口或monotonic应用deadline。 |
| DNS负证据 | 用户指定9.9.9.9:53、149.112.112.112:53、208.67.220.220:53的六组TCP/UDP会话均认证、无有效转发答案；recognized公共DoH也失败。它们属于客户端wire探测，不证明节点内部DNS损坏，没有加入physical business DNS fallback。Literal-IP TLS与当前Fake-IP域名闭环分别留证。 |
| 较早修补 | 节点51–200不可达、敏感full/partial obscured触摸、main/Binder Stop阻塞、Stop后节点解析仍准入、Go64-SYN关闭死锁、empty UDP当EOF、双向copy提前归还、在途/late cleanup误报释放与loss后cached Ready；正常/异常/取消及原失败仍在对应[需求复核](../docs/requirements.md)与tmp/owner检查目录。 |

## 后续能力与未执行验收

匿名启动保持本地、一个private :vpn Rust core与lazy Go runtime；UI退出、主题/语言/Fold重排不管理VPN生命周期。实际Builder可选APP范围已有冻结与准入，但完整selected/unselected UID出口/DNS、APP安装变化、lockdown、在线TUN候选替换/回退和自动恢复尚未完成产品矩阵。浏览器SDP本地地址枚举超出包过滤控制，未选APP直连不计入VPN防护范围。

QR、超过60KiB的Android FD导入、SQLCipher/Keystore恢复、live路由/TUN替换、自动重连、Rust BFF/OAuth、own-user mail、Shield软件/设备证明与Gateway签名策略/租约/撤销回执仍为明确后续任务。UI不制造登录、空邮箱、安全软件结论或verified server。当前Portal confidential clientSecret仅交给服务端BFF，APP path不存Portal bearer；mail.read最长300秒且无refresh，UserInfo不提供role/ORGID映射。

VPN通知使用真实LOW前台渠道、原生icon/immutable Open与priority Stop及四语presentation bridge；权限/渠道关闭必须按实际状态显示，FGS运行不等于顶部可见。Portal notifyUnread仅写数据库marker，Mail GET无手机事件接口。独立mail sink默认拒绝，无生产source/Firebase/polling；真实新邮件推送需要成功发布事件、Rust订阅authority、源撤销传播与真实provider配置。[通知决策](../docs/decisions/notifications.md)和[官方来源](../docs/validation/notification-sources.json)记录API/授权/有界投递要求。

本机没有KVM，软件设备为API29 x86_64 QEMU TCG；较早API36和常规API29 boot在安装LOFT之前失败。可启动API29与guest墙钟校准不能证明Android15/16、ARM64实体手机、Pixel/Samsung Fold、Always-on/Doze、真实延迟、总PSS、电池或24/48/72小时长跑。布局策略与截图也不能替代实机铰链/字体/旋转矩阵。8MiB自有ledger、GOMAXPROCS2和静态APK大小都不是PSS或功耗测量。

交接：需求/skill/回执记录已按实际源码、构建、Debug8项与独立minified两条探测范围整理；UI私密输入排除归档由Root记录。文档冻结后，Root再次核验真实完整index与实际bin/loft.apk并普通提交/推送，保留原main历史；远端SHA、Task完成标记和本任务废弃输出清理由Root独立记录。历史literal/JNI/敏感边界与当前8项API执行保持各自输入范围，实机与provider前置仍为未验证。

完整原始记录在本机忽略目录tmp/verification与各owner检查目录，可携带脱敏摘要在docs/validation。未运行项始终保持未验证。
