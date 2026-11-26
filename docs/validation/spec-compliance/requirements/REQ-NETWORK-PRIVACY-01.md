## REQ-NETWORK-PRIVACY-01 — 共享 VPN 隐私策略、冻结范围与实际回执

> "Ready requires the consumed current ticket, complete effective package freeze, exact policy epoch/scope/modes and matching applied Hydra scope, plus authenticated selected transport, ready TUN, protected sockets, actual IPv4 capture, no bypass and IPv6 rejection."
> — `docs/contracts/network-privacy.md:L54`

> "Rust removes effective claims immediately on priority Stop/poison, preserving separate actual Blocked or closure facts."
> — `docs/contracts/network-privacy.md:L56`

**Verdict:** partial · confidence: high for the frozen Rust state/FFI source; cross-language packet/platform enforcement and final artifact acceptance remain unverified in this review.

本报告是 0.1.2 实施期间的独立检查点。审查时 Rust 已冻结；Go/Android 仍由各所有者实施，不能把其暂存 skeleton 或旧绑定调用判为最终产物失败。冻结 Rust 中未确认新增的票据重绑、重复 URI 消费或旧证明重新进入 Connected 的缺口。完整要求仍需下述跨端与实际设备证据。

审查日期：2026-11-26 UTC。已阅读根/适用子树AGENTS、`docs/aptist-loft/SKILL.md`及其架构/发行教训、两份完整本地设计（guide v3.6/UI）、根Readme/latest progress、framework/privacy/resources/notifications契约，以及Rust Readme/隐私契约/最新validation。使用aptist-loft、audit-context-building、spec-to-code-compliance和verification-before-completion；仅本要求的独立检查点结论进入本报告。

### 身份与本次实际执行

| 项目 | 独立观察 |
| --- | --- |
| 冻结清单 | `loft-core-rust/target/privacy-source-inventory.json`，SHA256 `db5b0bc7a146af10f4c24a72ca3459252ae35e7d5a4e3f2a2aa228bb4beb58f3` |
| 文件身份 | Python 对清单 36 个路径逐一读取 bytes/SHA256，36 匹配、0 差异；只读取 Rust 清单内路径 |
| 契约身份 | 澄清后 `docs/contracts/network-privacy.md` SHA256 `12ad36a72d49e49ecae0716a8d2bdcfd8cfd456d501b13455b6028d9717b43c4` |
| 清单声称 | core 版本 0.1.2-LYNX；CoreSnapshot2、Go policy1、NodePage1；`native_generation=not_run`、`tests_passed=93` |
| 独立测试计数 | 冻结文件中有 93 个 `#[test]` 声明。这个源码计数不证明测试执行或通过 |
| 本审查执行范围 | 文档与源码只读、调用链/失败分支检查、文件身份与测试声明核对；未运行 Cargo 测试、fmt/Clippy、Go normal/race/vet、native、Gradle、模拟器或实机 |
| 外部动作 | 没有网络探测、生产节点、OAuth/邮件操作、上游修改、提交或推送；凭据输入未读取 |

作者的 93-test 记录保留在 Rust `docs/validation.md`；Root 另行报告 fresh workspace 93 tests/fmt/Clippy 退出 0。这些执行者的回执应由最终整合报告绑定到上述源码身份，本审查不把作者或 Root 的结果改称为自己的执行。清单、源码声明和检查点 APK/native generation 均不能证明实际 DNS/RTC、设备功耗或 72 小时验收。

本报告的 `core/src/`、`core/tests/` 分别指 `loft-core-rust/crates/loft-core/src/`、`loft-core-rust/crates/loft-core/tests/`；`ffi/src/`、`ffi/tests/` 分别指 `loft-core-rust/crates/loft-ffi/src/`、`loft-core-rust/crates/loft-ffi/tests/`。

---

### What this demands of an implementation

Rust 对一个真实服务拥有的尝试冻结独立策略 epoch、实际 owner UID 与完整 effective package→UID 范围；只有该尝试的真实平台/代理回执能改变有效状态。UI 编辑只保存 draft；取消、失败、资源未完成与旧回执不能恢复有效代理证明。Go 的共享 DNS/RTC 路径、原始域名恢复、实际 Hydra 安装和 Android TUN 范围必须分别产生证据，不能从 Rust 合法配置、合成 helper 回执或编译能力推导。

### Where enforcement lives

| 核验项 | 已走过的入口、比较与失败路径 | 本检查点判断 |
| --- | --- | --- |
| 默认与政策校验 | `CoreState::with_stop_signal` 建立本地 epoch1/default policy（`core/src/lib.rs:L183-L196`）；`NetworkPrivacyPolicy::normalized` 分开处理 synthetic 空 endpoint 与 literal IPv4/port wire endpoint，检查 DNS 数量/字节/TTL/query/response 和全部 Hydra 字段（`core/src/privacy.rs:L99-L157`） | Rust 实现；无网络解析或周期任务 |
| independent draft epoch | `set_network_privacy_policy` 先比较 expected global generation，再 normalize/no-op，checked_add 两个计数后才提交（`core/src/lib.rs:L243-L263`）；不写 VPN applied/ticket | Rust 实现；有效变更原子提交，现有尝试保持旧 draft capture |
| 原尝试与 URI来源 | `begin_vpn` 检查当前 generation、Disconnected/Stop、节点存在、Hydra/SOCKS 冲突和 checked admission，才复制冻结配置并提交（`core/src/vpn.rs:L374-L433`）；URI 经 `NodeConfig::canonical_uri`/`encode_into` 受 512 KiB 检查（`core/src/import.rs:L154-L329`） | Rust 实现；节点、scope、policy 不能被后续普通配置修改重绑 |
| effective package freeze | `freeze_effective_packages` normalize 后拒绝 selected 空集合/full 非空集合；在同一 content Mutex 内重检 live、拒绝第二次 freeze（`core/src/vpn.rs:L232-L250`；包名/100/4096校验 `core/src/lib.rs:L415-L460`） | Rust 实现；完整共享 UID 扩展本身由可信 Android adapter 提供 |
| owner/shared UID/profile freeze | `freeze_network_scope` 要求 prior effective freeze 且 once；`normalized` 检查正 UID/Android signed范围、同 user UID区间、100/4096、重复 package 名及全量集合精确相等（`core/src/vpn.rs:L173-L198`；`core/src/privacy.rs:L223-L261`） | Rust 实现；实际 owner/membership 的 OS事实仍待 Android 最终回执 |
| scope digest | SHA256 包含 domain separation、attempt、node length/name、routing bit、owner UID、pair count/name length/name/UID，以及带 epoch 的 normalized canonical policy（`core/src/privacy.rs:L263-L285`） | Rust 实现；是关联摘要，不是远端签名或设备证明 |
| canonical policy | frozen live scope 经 deterministic JSON输出 exact keys、uint64 decimal-string epoch、64 lowercase hex scope，限4096；仅设 prior-delivery flag，合法幂等读取（`core/src/vpn.rs:L200-L216`；`core/src/privacy.rs:L159-L198`） | Rust 实现；严格 JSON consumer 不在此函数中，由 Go/Android 各自验证 |
| raw one-use与取消 | `take_raw_node` 要求 effective+scope+prior canonical；content Mutex/Option.take 确保共享 Arc 一次消费，复制后再检查 valid/Stop，成功才置 delivered（`core/src/vpn.rs:L253-L277`）；invalidate 先写 AtomicBool，再尽力清 URI（`L339-L344`） | Rust 实现；取消后原 scope metadata 可供 closure，不能重新取 URI |
| Ready admission | `mark_vpn_ready` 先比较当前 attempt/Stop/state，要求 transport/auth/TUN/protected、consumed URI、精确 packages 与三项平台确认（`core/src/vpn.rs:L436-L470`）；`applied_privacy` 比较 epoch/scope/modes/installed/active/DNS/RTC/IPv6/pending/Hydra（`L297-L337`） | Rust 实现；只验证可信 adapter提交的事实，不能自己证明 OS/packet效果 |
| Ready reaffirmation | Connected 的重复匹配回执只在 applied routing/privacy 完全相等时幂等返回；首次 Ready invalidate ticket 后提交两份 applied/state（`core/src/vpn.rs:L477-L491`） | Rust 实现；保存新 draft 不会把旧尝试误标为新 epoch 已应用 |
| loss/failure/late callbacks | `mark_vpn_failed` 比较 attempt，拒绝 Disconnected/priority 后普通 late failure，invalidate ticket、保留 Revoked 因果、转 Stopping（`core/src/vpn.rs:L494-L518`）；Ready 不能从 Stopping/Blocked/Disconnected恢复（`L438-L445`） | Rust 实现；真实 loss 的及时通知/Abort仍由适配器执行 |
| Blocked与实际关闭 | `mark_vpn_blocked` 要求 current attempt、非 priority Stop、Stopping/Blocked、原 TUN held/drop、exact packages/epoch/scope和平台确认；Hydra scope设Off（`core/src/vpn.rs:L521-L567`）。`confirm_vpn_stopped` 只在 tun_closed 与 resources_released 均为真后，确认状态并清 ticket/target/applied（`L585-L610`） | Rust 实现；false closure 不能替换实际 join；真实原 PFD/Go duplicate/owners需独立证据 |
| priority Stop/poison projection | `AppCore::begin_vpn_stop` 在普通 Mutex 之外设置 cancellation/fence，try_lock失败直接返回 active attempt（`ffi/src/lib.rs:L431-L448`）；snapshot 从 immutable published Arc读取，poison清 active/applied privacy并Unavailable/Inactive，Stop立即Stopping/Inactive（`L336-L355`） | Rust projection实现；原始 TUN关闭与停止真实 forwarding仍是服务所有者职责 |
| 不复用计数 | epoch/global mutation checked_add；epoch在 canonical JSON用u64文本（`core/src/lib.rs:L255-L259`、`L408-L412`；`core/src/privacy.rs:L177`）；attempt checked_add（`core/src/vpn.rs:L399-L403`）；cleanup/lifecycle saturating generation继续处理真实关闭（`L635-L638`） | Rust admission边界实现；MAX不绕回新的policy/attempt |
| schema与分页 | CoreSnapshot2独立字段（`core/src/lib.rs:L122-L140`、`L208-L239`）；NodePage1/50/200及 read-only query/fence（`L268-L291`）；FFI逐字段搬运所有新增 policy/receipt 字段（`ffi/src/lib.rs:L570-L593`、`L642-L673`、`L754-L821`） | Rust声明与转换实现；实际 envelope3二进制/旧consumer拒绝尚未在本检查点终验 |

FFI ticket getters/freeze/take入口（`ffi/src/lib.rs:L227-L266`）直接委托同一个 Rust ticket，不存在另一套票据状态。`with_state` 在普通操作前 reconcile priority Stop、再执行并发布（`L456-L475`）；政策/receipt error映射均保留稳定类型（`L478-L518`）。Kotlin immutable record配置在 `loft-core-rust/crates/loft-ffi/uniffi.toml:L6`；真正生成的 Kotlin/native ABI匹配仍需最终 generation receipt。

---

### Paths walked

1. `AppCore::set_network_privacy_policy` → `with_state` → `CoreState::set_network_privacy_policy` → `normalized` → checked/no-op commit：stale、bad endpoint、quota、Hydra、MAX均在提交前拒绝。scope hash 使用票据的私有已校验配置；公开 caller不能向 canonical函数传入任意 epoch/endpoint。
2. `AppCore::begin_vpn` → admission fence/`with_state` → `CoreState::begin_vpn` → `NodeConfig::canonical_uri` → `append_query`/`append_base64`/`encode_into` → ticket；之后 effective freeze → UID/profile normalize/digest → live canonical → Option.take raw。content Mutex共享于所有 Arc，第二次 scope/effective freeze和第二次 raw消费没有独立副本。
3. `AppCore::mark_vpn_ready` → `with_state` → current attempt/state checks → consumed+package+platform comparison → `applied_privacy` → same-applied幂等/first commit；新 draft在此链中不能改变已冻结policy。另一尝试、错scope/epoch、false proof、pending、缺Hydra安装或错scope均拒绝。
4. failure → invalid ticket/Stopping；只有 matching held-original-TUN/drop receipt 可到Blocked。priority Stop → atomic projection/reconcile → matching stopped receipt → owner/applied clear。任何 late Ready不能进入Connecting/Connected允许分支；older attempt不能修改new attempt。
5. snapshot/page FFI都只输出 owned metadata。NodePage query不使用 mutation helper；poison snapshot独立于普通 state lock，不能恢复中间状态为Connected。实际 Go Abort/原PFD关闭不由此内存查询执行。

信任前置条件明确保留：Rust的四个 transport facts、三个 platform confirmations、完整 effective package/UID freeze、forwarding_disabled/resources_released均来自服务adapter。本次在被冻结Rust内部没有找到 OS事实的独立生产者；这是职责边界，需在冻结Android/Go源码、实际API/packet中继续核验，不能用 test helper补足。

### Tests read, with their practical limits

实际读过 `core/tests/privacy_policy.rs:L1-L181`、`privacy_lifecycle.rs:L1-L421`、`vpn_lifecycle.rs:L1-L321`、`import_validation.rs:L1-L140`与`L627-L681`、`ffi/tests/privacy_boundary.rs:L1-L126`、`vpn_port.rs:L1-L94`、两个 tests/support module，以及 source中的 counter/owner tests。X/Pro材料helpers经rcgen在测试内生成独立server/client/CA/key（`import_validation.rs:L20-L94`），没有使用任务或生产节点材料。

新增策略测试覆盖 endpoint/quotas/disabled-Hydra校验；lifecycle测试覆盖17种单独无效Ready事实、完整UID/profile freeze、draft/applied分离、取消和Block。Hydra的generated X/Pro材料测试先拒绝缺安装/错scope，再接受X LogicalStreams或Pro TcpOnly（`core/tests/import_validation.rs:L628-L681`）。MAX测试检查epoch不wrap、unsigned JSON为`18446744073709551615`（`core/src/lib.rs:L468-L494`），及实际Stop可在global MAX完成、attempt MAX拒绝（`core/src/vpn.rs:L53-L110`）。FFI真实Mutex poison/held-lock测试检查Unavailable/Inactive/优先取消（`ffi/src/lib.rs:L830-L993`）。

这些测试调用真实CoreState/AppCore，测试的是校验与状态准入。support模块明确提供synthetic receipt facts（`core/tests/support/mod.rs:L1-L46`）；它们不是实际认证、UID路由、DNS答复、Hydra record shaping、PFD关闭或流量不泄漏的证明。测试名称中的“actual/real proof”只能在这一准入范围解读。

---

### 原始文字出入与反证记录

首次读取的根 privacy contract:L17 写作 “one-use canonical policy and raw node URI”。审查观察到 `canonical_network_policy` 不拒绝重复读取（`core/src/vpn.rs:L200-L216`），且 `privacy_lifecycle.rs:L155` 显式验证第二次读取相同结果；FFI直接透传。这个初始差异已立即发给Root。

Root核对既有owner契约 `loft-core-rust/docs/network-privacy-contract.md:L29-L31` 后澄清：canonical是live frozen ticket的无secret immutable幂等getter；raw URI仍one-use且须prior canonical delivery。根契约当前:L17已明确上述语义，Rust冻结源码未为此改动。旧稿的文档偏差已消除，不记作已确认安全漏洞：重复canonical不能重绑范围、消费第二份raw URI，也不能让停止/失败的旧ticket恢复Ready。

### Searched

- Rust `freeze_network_scope`/`freeze_effective_packages`/`canonical_network_policy`/`take_raw_node`/`mark_vpn_ready`/`mark_vpn_blocked`/`confirm_vpn_stopped`：生产命中在 core/FFI入口、callee与转换，另有测试；已逐段阅读，并未只按函数名接受。
- `HydraScope::LogicalStreams|TcpOnly`、`hydra.enabled = true`：除policy/lifecycle测试，还命中 `core/tests/import_validation.rs:L633-L678` 的真实生成材料正反准入，已阅读；未误报为缺enabled分支测试。
- Android `freezeNetworkScope`/`takeNetworkPolicy`/`markVpnReady`/`markVpnBlocked`/policy字段：本检查点命中旧service调用和新canonical decoder skeleton。相关文件未冻结，结论只作为后续整合检查入口。
- 猜测的 `ui-foundation/.../CoreAvailabilityGuard.kt` 路径搜索退出2（文件不存在）；全目录rg找到实际 `app/.../service/CoreAvailabilityGuard.kt:L6-L7`，已纠正并阅读。没有据错误路径断言实现缺失。
- 完整Rust freeze inventory bytes/hash核验与`#[test]`声明计数分别完成，后者未代替测试执行。

### How the verdict was reached

冻结Rust中的政策/票据/receipt/projection已得到逐路径源代码支持；没有把actual adapter事实当作Rust本地能证明的OS或packet行为。partial来自尚未冻结的共享实现与未执行的端到端/设备范围，不能由93个源码test声明或0.1.1的历史APK改变。

Android当前检查到的 publication链为 `SnapshotPublisher.capture` 先保留sequence再query（`app/.../service/SnapshotPublisher.kt:L16-L22`）→`SnapshotWire`→`SnapshotConsumer.consume`→`SnapshotSequence.accepts`（foundation文件:L9-L12）；MAX先显式拒绝capture。当前 service 的poison guard经 `capture` 后 `observe`→`fault`→worker `reconcileFailure/Abort`（`app/.../service/LoftRuntimeOwner.kt:L40`、`L298-L320`、`L430-L439`）。这些是读取的集成链路，未运行，也不对其尚未冻结的0.1.2 receipt/schema迁移给最终通过判定。

### Open questions / not checked

- 冻结后的Go `setNetworkPolicy` strict parser与Android canonical/resource decoder是否拒绝duplicate/case-alias/unknown/missing/null、错误type、尾随值和MAX epoch降为Double/Long；完整consumer/producer真实契约测试待验收。
- Android在Builder前、establish后、Ready前是否重新核验实际owner、全量共享UID/profile membership，变化时priority Stop同一attempt；full-mode owner也必须是真实UID。尚未冻结的caller不能作为最终OS证明。
- Go是否从当前ready client/session与已安装TUN路径生成proof，loss/Abort/Stop/retirement在新准入和bytes前撤销；所有协议、普通/空UDP、fragmented/arbitrary-port/malformed DNS/RTC/reply的实际验证尚未由本审查执行。
- Fake-IP返回alias后经恢复原FQDN完成真实certificate/TLS/HTTP200、node-bootstrap-only physical resolver、wire失败无直连fallback，以及TTL/live-lease/quarantine耗尽恢复/528 KiB fixed与dynamic ledger，均需冻结Go与实际路径证据。
- 原始Android PFD、Go duplicate、pending/retiring resources的真实取消/关闭/join、late callback/poison races，必须在同一构建输入上验证；boolean或zero counters不是释放证据。
- Hydra actual hooks、X logical/pro TCP scope、record/padding计数和默认Disabled分别验收；配置getter与Rust准入不能证明字节已整形。
- CoreSnapshot2/envelope3/NodePage1最终binary长度、schema/trailing checks、snapshot binding/sequence和node-page request fence，以及matching generated Kotlin/native输入，需要冻结后复核。
- 本检查点未生成或验证最终 `bin/loft.apk`；同一实际签名ARM64 Release、APK/signature/version/manifest/alignment/index+artifact secret scan、通知实际权限/渠道可见性，以及ARM64/Fold/Doze/PSS/电池/72小时均未在本审查执行。

审查只写此独立报告；Rust、Android、Go所有者源码和Gateway/Portal保持只读。后续终验必须附新的源码/测试/构建/实际APK身份，不能将本检查点改称为产品发布认证。
