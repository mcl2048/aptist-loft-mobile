最新复验结论：**implemented**（2026-11-25 18:28:38 UTC）。文末记录验证了源码与真实主机边界；下方原始 **partial** 记录及其输入摘要完整保留。Android Binder/Compose 实机验收未在本项运行。

## REQ-NODE-01 — 已接受节点可分页访问，合法状态快照满足 Binder 字节上限

> "**首版需求**：用户通过“扫码添加”或“导入链接”两种入口，均可将 Loft-Gateway 的 SOCKS5、HyrakenX、Hyraken Pro 节点加入节点列表，保存后可按权限选择连接。两种入口共用 Rust 配置导入适配器与同一套校验规则。"
> — `guide/guide.md` v3.6「节点添加：扫码与链接导入」L405
>
> "以下是移动端新增适配层的**首版初始配额**，由代码检查并在 P0 验证。上游协议已有的 TLS/H2/QUIC 缓冲与流控窗口单独计量，最终以进程测量为准。"
> — `guide/guide.md`「低内存：先设可控上限，再冻结实测门槛」L687
>
> "| 控制请求与状态 | 请求队列最多 32 项且正文合计 1 MiB；单条 Binder 消息 64 KiB | 区分可靠命令与可合并统计；较大导入用受限文件 FD |"
> — `guide/guide.md` 同节 L696
>
> "| 节点目录/导入 | 本地工作集最多 200 节点；单次解析 512 KiB | 原始及解码后的输入均计额，数量与字节双限额 |"
> — `guide/guide.md` 同节 L700
>
> "| 审计/节点列表 | 分页与稳定 ID，避免全量复制、每行单独数据库连接或重组 |"
> — `guide/ui-design.md`「UI 自身的内存与电池约束」L344
>
> "- 显示当前已生效模式与数量，编辑期间另外标记草稿数量；退出页面不自动应用。"
> — `guide/ui-design.md`「按应用代理」L251
>
> "Snapshot exposes at most 50 bounded metadata rows; never raw URLs/seed/password/key/PEM. Core retains at most 200 nodes; snapshots/IPC stay below 64 KiB. Imports validate raw and decoded byte quotas and strict schemes/duplicate parameters/required materials. Node storage is explicitly session-local for this release, not plaintext persistent storage. Enabled app-routing empty selection is rejected atomically and remains a draft; no claim that TUN routing is applied."
> — `docs/contracts/framework.md` L9

**Verdict:** partial · confidence: high

**What this demands of an implementation:** 本项检查已接受的本地节点目录，而非完整 P0–P5 产品：最多 200 个工作集节点应仍能经有界状态接口逐页发现、查看并选择/管理；一帧最多 50 行是分页大小，不得让第 51–200 个成功导入的记录无法访问。合法节点文本、服务器地址、路由草稿以及已有回执的有效名单一起编码时，应满足 64 KiB Binder 消息预算。SQLCipher/Keystore、OAuth、扫码/领取及真实 VPN 能力的阶段完成情况不构成本项分页缺陷。

审查对象：`0.1.1-LYNX` 工作树，Git 基线 `b0c611067981fba74b2c616e73fcf7ab9f434721`；搜索记录时间 2026-11-25 16:47:14 UTC，文档核对截至 16:52:11 UTC。Rust 来源冻结；Android/Go 同时集成，因此本记录以文末源码 SHA-256 和具体行号界定观察版本。没有修改 Rust、Android、Go 源码；未读取任务文件、`guide/TEST.TXT` 或真实凭据。

下文 `loft-core/src/`、`loft-ffi/src/` 分别指 `loft-core-rust/crates/loft-core/src/`、`loft-core-rust/crates/loft-ffi/src/`；Kotlin 服务/UI 文件分别位于 `loft-android/app/src/main/kotlin/net/aptist/loft/service/`、`ui/`，foundation 文件位于 `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/`。

---

**Where enforcement lives:**

```rust
// loft-core-rust/crates/loft-core/src/lib.rs:L165-L175
pub fn snapshot(&self) -> CoreSnapshot {
    CoreSnapshot {
        schema_version: 1,
        core_version: "0.1.1-LYNX".into(),
        nodes: self
            .nodes
            .iter()
            .take(MAX_SNAPSHOT_NODES)
            .map(|node| node.summary.clone())
            .collect(),
        node_count: self.nodes.len() as u32,
```

- **工作集与输入边界已实现。** `loft-core/src/lib.rs:L199-L231` 先完整解析、拒绝重复、检查最多 200 个及 8 MiB 保留额，再生成稳定 ID 并提交；第 201 个返回 `NodeCapacityReached`。`loft-core/src/import.rs:L401-L405,L610-L654` 检查原始和解码输入 512 KiB 配额。此处接受记录的上限与查询固定前缀的上限不同。
- **分页接口缺失。** 上述 `snapshot()` 没有 offset/cursor/page 参数；`CoreSnapshot` 记录 (`loft-core/src/lib.rs:L95-L111`) 也没有页标识或继续查询信息。`loft-ffi/src/lib.rs:L198-L215,L294-L313,L388-L405` 仅复制已发布的这一份快照，未增加查询范围。整个导出 `AppCore` 方法块 (`L183-L292`) 没有节点页/按 ID 读取摘要的方法。
- **Android 的成功导入回执无法补全目录。** `LoftRuntimeOwner.kt:L124` 调用 `core.importNode(command.raw)` 后丢弃其 `NodeSummary` 返回值，仅保留 `NODE_IMPORTED` 结果码；`L136-L138` 捕获同一快照并广播/回复。`ILoftControl.aidl:L5-L9` 只有 subscribe/unsubscribe/execute；`ControlCodec.kt:L14-L22,L33-L47,L58-L72` 的 1–7 号命令仅包含导入、删除、服务器、路由、连接与停止，没有节点页查询。
- **页面只展示第一批记录。** `LoftApp.kt:L326-L355` 直接遍历 `native.core.nodes`，使用稳定 `id` 键；多于当前行数时只显示 `first_page_only` 文本。`values/strings.xml:L42` 和其他三个 locale 的 L42 明确写着更多节点分页需要存储适配器，没有对应操作。

```kotlin
// loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftViewModel.kt:L157-L161
fun selectNode(id: String, showDetails: Boolean) {
    val state = mutable.value
    if (state.native?.core?.nodes?.none { it.id == id } != false) return
    mutable.value = state.copy(presentation = state.presentation.copy(selectedNodeId = id))
    if (showDetails) navigate(Page.NODE_DETAILS)
}
```

- `LoftViewModel.kt:L275-L282` 每次收到新快照，又将不属于当前 50 行的选中 ID 替换成首行；`LoftApp.kt:L357-L364` 详情同样只在快照行中找节点。用户无法在保留前面记录的情况下查看、选择或管理第 51–200 个节点。核心拥有这些记录：`loft-core/src/lib.rs:L234-L253,L299-L305` 的删除/目标校验，以及 `loft-core/src/vpn.rs:L245-L263` 的启动票据查询均遍历整个工作集；拥有 ID 的私有调用者可以操作后续记录，UI 没有取得这些 ID/摘要的入口。
- **实际快照大小边界已实现，未确认超限。** 标签按 UTF-8 字节最多 64 (`import.rs:L551-L580,L622-L654`)，地址的 ASCII 主机最多 253 加五位端口，生成 endpoint 最多 259 (`origin.rs:L51-L95,L98-L131`)；生成 ID 为 21 字节 (`lib.rs:L222`)，规范化 HTTPS origin 最多 267 (`origin.rs:L35-L41`)。这些都小于 `SnapshotWire.kt:L38-L43,L48,L56,L66` 的对应编码限额。
- 路由每份最多 100 包、合计 4096 ASCII 字节、单包 255 字节 (`loft-core/src/lib.rs:L320-L365`)；票据冻结与 ready/blocked 回执分别再次调用同一规范化器 (`vpn.rs:L150-L168,L320-L327,L388-L396`)。快照确实同时携带草稿和有效两份 (`lib.rs:L178-L179,L189-L195`)，编码器也分别计数、分别执行 4096 字节检查 (`SnapshotWire.kt:L50-L63,L133-L150`)；不能按 `100 × 255` 把每份合法名单假定为 25,500 字节。
- `SnapshotPublisher.kt:L16-L22` 使用真实 Rust 快照和单调 publication sequence 调用 `SnapshotWire.encode`；`SnapshotWire.kt:L29-L73,L152-L159` 为长度前缀 UTF-8 二进制格式，检查最终字节数不超过 `ControlCodec.MAX_CONTROL_BYTES = 60 * 1024` (`ControlCodec.kt:L28`)。AIDL 发送 `byte[]` (`ILoftEvents.aidl:L3-L5`)，不会将整帧膨胀为 UTF-16 JSON。`LoftRuntimeOwner.kt:L376-L385,L397-L404` 的捕获、广播和回执路径使用同一编码器及上限；失败返回明确 unavailable 回执，未静默裁剪合法帧。

仅按编码器本身允许的更宽字段上限作保守布局求和：固定头 92、节点 `50 × 485`、可选服务器 2053、两个模式标志 2、草稿名单 4500、状态字段 36、两个代际 16、可选活动节点 69、有效名单 4538、可选错误 37、引擎版本 68、四个事实标志 4，总计 **35,665 字节**。实际 Rust 字段约束更小。60 KiB 限额另为 Binder 元数据保留 4 KiB；本次没有运行 Android `Parcel`/跨进程 Binder 设备测量。

---

**Paths walked:**

- **导入/发布/显示：** `LoftViewModel.confirmImport` → `CoreCommand.ImportNode` → `ControlCodec.encode/decode` → `CoreServiceClient.execute` → 私有 `LoftCoreService.execute` → `LoftRuntimeOwner.execute` → UniFFI `AppCore.import_node/with_state` → `CoreState.import_node/parse_node` → `CoreState.snapshot` → `AppCore.published/snapshot` → `SnapshotPublisher.capture` → `SnapshotWire.encode` → `ILoftEvents.onSnapshot/onReceipt` → `SnapshotConsumer.consume/decode` → `LoftViewModel.receivedFrame` → `NodesPage/NodeDetails`。第 51 个导入仍返回成功；生成快照固定保留前 50 行，成功结果码未附导入摘要。✗
- **重订阅/重新读取：** `CoreServiceClient.subscribe` (`L61-L79`) → `LoftRuntimeOwner.subscribe/freshPayload` (`L93-L100,L383-L385`) → 同一个 `AppCore.snapshot` → 同一前缀。`SnapshotConsumer.kt:L10-L12` 只按 sequence 接受新整帧，既不请求后续页也不拼合节点目录；重新进入页面或重新绑定不能翻页。✗
- **选择/删除：** 节点行点击 → `selectNode` 的快照成员检查 → 当前 ID → UI 详情/删除命令；可用集合始终是那 50 行。直接向核心传入合成测试事先持有的第 51/200 个 ID 可以取得票据或删除，证明记录没有丢失；删除前面一行后第 51 个才被推入窗口。这种删除会改变目录，不能提供完整目录的普通分页访问。✗
- **APP 分页反证：** `RoutingPage` (`LoftApp.kt:L376-L381,L422-L427`) → `AppCatalog.page(query, selected, selectedOnly, offset)` (`RoutingDraft.kt:L42-L46`) 确实 drop(offset)/take(50)，但输入是 Android 可见 APP 目录；其 appPage/next_page 控件没有调用任何节点状态页。未将这条不同路径算作节点分页。
- **Go 替代入口反证：** `LoftRuntimeOwner.startTransport` 只把所选票据的原始节点交给 `VPNRuntime.Start`；`engine/vpn.go:L42-L55` 的 Snapshot 对外只返回资源事实，未返回 Rust 节点工作集，不能补齐节点目录。
- **最大双份名单编码：** 真实 `AppCore.importNode` 接受 200 个合成长文本 Pro 配置 → `setAppRouting` 接受 4096 字节名单 → 实际 FFI `beginVpn/freezeEffectivePackages/takeRawNode` → **仅审查用的合成 reducer ready 回执**建立 applied 字段 → 另一次 `setAppRouting` 保留不同草稿 → 合成 failure 回执 → 实际 `SnapshotPublisher.capture/SnapshotWire.encode/decode`。两份名单完整、字段往返成功、字节数未超限。✓ 此路径只证明状态与序列化，未运行 Go、VpnService、TUN 或网络。

---

**Searched:**

工作目录均为 `/home/coder/LOFT-mobile`。完整命令和逐行结果保留在本地 `tmp/review/req-node-01/search-records.json`，该目录按交付规则排除。

| 搜索模式 / 范围 | 结果与判读 |
| --- | --- |
| `(fun\|fn) +(nodePage\|queryNodes\|listNodes\|snapshotPage\|node_page\|query_nodes\|list_nodes\|snapshot_page)\b`；Rust crates、Android main 和 ui-foundation main，kt/rs/aidl | 0 命中（rg exit 1）；与完整 FFI 方法块、命令枚举和 AIDL 的人工遍历一致。 |
| `list_nodes\|query_nodes\|node.?page\|page.?node\|node.?cursor\|cursor.?node`；相同源码、res 与 contracts | 13 行命中；宽模式命中了 Page.NODES/NodesPage 导航和英文“Further node pages”说明，无查询 API。 |
| `cursor\|offset`；Rust core/FFI src、Android service 和 RoutingDraft.kt | 14 行命中：8 行百分号解析器 cursor、3 行 PEM `std::io::Cursor`、3 行 APP 分页 offset；无节点查询游标。 |
| `first_page_only\|next_page\|setAppPage\|nodePage\|nodeQuery`；Android UI 与四语 res | 12 行命中：8 行 locale 文本、1 行 setAppPage、2 行 APP 翻页按钮、1 行节点首屏提示；节点分页动作 0。 |
| `ILoftControl\|queryNode\|nodePage`；Android main kt/aidl | 6 行，仅私有服务 Binder、UI 客户端和接口定义；无第二个节点查询 Binder。 |
| `node_count\|nodes\b\|cursor\|offset\|page`；Go engine 非测试 .go | 1 行，仅 info.go:L47 声明元数据不依赖 imported nodes；进一步读取 VPNRuntime Start/Snapshot 对外方法，无目录页。 |

读取了 `guide/guide.md` 的配置/导入/按应用/低内存/开发契约/阶段章节（L388–447、L654–720、L816–845），`guide/ui-design.md` 的节点/导入/按应用/UI 内存章节（L213–258、L334–364），以及 root/子树 AGENTS、LOFT skill 和 framework contract。没有以常量名、LazyColumn 或“page”文本命中代替调用链判断。

---

**How the verdict was reached:**

`partial` 的理由是工作集、稳定 ID、快照行数、字段/字节边界和真实编码器均已实现，而第 51–200 个 **已成功接受** 节点的查询、UI 发现和选择路径缺失。此限制在 UI 文本中被披露，仍不能满足已实现节点目录的分页要求；不依赖将 P2 数据库或 QR/OAuth 规划升级成框架必做项。本项没有发现合法节点文本或双份合法包名单导致 `SnapshotWire` 超限的反例。

**复现命令与结果：**

```text
cd /home/coder/LOFT-mobile
python3 tmp/review/req-node-01/run_review.py
exit 0
```

脚本使用 OpenSSL 在内存生成公开测试证书（私钥不落盘/不输出），所有 URI 目标均为保留 `.invalid` 域名。调用既有 host `libloft_ffi.so` 和生成 UniFFI 类；重新编译真实 SnapshotWire/Publisher/Consumer/ControlCodec/Sequence，未运行 Gradle/Cargo 大构建。编译 JVM 为 `-Xmx384m -XX:ActiveProcessorCount=1`、Kotlin `-Xbackend-threads=1`；运行 JVM 为 `-Xmx192m -XX:ActiveProcessorCount=1`。工具为 JDK 21.0.13.1、Kotlin 2.3.21、JNA 5.18.1，SDK 36 android.jar 仅提供生成绑定选择 JNA cleaner 所需的 Build.VERSION 类（SDK stub 值 0），未调用 Android 平台方法。确切编译/运行参数和摘要位于本地 `commands-and-hashes.json`。

| 实际观察 | 结果 |
| --- | --- |
| 导入合法 Pro 节点；名称 64 UTF-8 B、endpoint 259 B、HTTPS origin 267 B | 成功接受 200 个；第 201 个原子拒绝；65 B 名称原子拒绝。 |
| 状态查询及真实发布/消费重复查询 | nodeCount=200、nodes=50；余下 150 个在重复查询中仍不可见。 |
| 事先保留的隐藏 ID | 第 51 个 ID 的目标校验/票据可达；第 200 个可删除；删除首行才让第 51 个出现在快照中。 |
| 名单配额 | 草稿及有效名单分别 100 包、分别 4096 B；101 包、4097 B、单包 256 B 均拒绝。 |
| 首次无有效回执快照 | 23,865 B。 |
| 带不同草稿/有效名单的合成 reducer connected 回执快照 | 28,406 B。 |
| 保留两份名单及最长错误字段的合成 stopping 快照 | **28,428 B**；真实编码/解码成功。 |
| 同形 UTF-8 64 B 标签编码/解码 | 28,428 B；未按 UTF-16 或 JSON 转义错误计费。 |
| 超过 61,440 B 的 wire 输入 | 真实 decoder 拒绝。 |

可复核的关键调用序列是 `accepted = (0 until 200).map { core.importNode(publicSyntheticUri(it)) }`；`core.snapshot().nodes == accepted.take(50)`；对 `accepted.drop(50)` 的 ID 无节点查询入口；`publisher.capture(core::snapshot, matchingMetadata)` 后 `SnapshotWire.decode(payload)` 验证完整两份名单和 `payload.size == 28428`。本地 `result.json` 与 `max-legal-snapshot.bin` 保存实际结果；合成 ready/failure 只构造 reducer 状态，**没有实际 VPN 连接、认证或设备验收**。

失败尝试已区分为审查环境/材料问题：第一次 JVM 运行缺少 Android `Build.VERSION` 类而退出 1；加入既有 SDK 类定义后第二次退出 1，合成 pin 中两个未转义的 `+` 被正确的 form-query 解码为空格，返回 `InvalidCertificate`。依据 `import.rs:L644-L645,L737-L739` 和现有公开测试的 percent-encoding 做法，为合成 Base64 query 值进行 URL 编码后，上述命令退出 0。两次失败没有被计为框架缺陷。

---

**Open questions / unverified:**

- 未运行最终 APK 的 Android Parcel 大小、跨进程 Binder 或真实 UI 设备操作；28,428 B 是当前实际 Binder payload 编码器和发布器的主机结果，35,665 B 是源代码字段上限的保守和。不得将这些结果写为已完成实机验收。
- Android/Go 在本次只读审查期间仍有集成变化，最终交付需确认下面被审查的函数/摘要仍一致；一旦新增节点页 API、修改收据载体或名单上限，应重新走本项路径。该待确认项不削弱当前固定前缀调用链的证据。
- 当未来页接口接入后，跨页选择、删除导致页窗口变化、陈旧代际以及有效节点不在当前页时的详情保留还需要行为验证；当前实现没有该入口，本次不推断未来实现的行为。
- 本项没有独立执行安全漏洞定级或另一个代理的反证轮次；结论供根审查者复核。没有将 SQLCipher、OAuth、QR、生产节点、真实设备或 72 小时验收状态纳入本项 verdict。

观察版本 SHA-256（用于本项复核，非最终发行产物声明）：

```text
loft-core-rust/crates/loft-core/src/lib.rs
  3c8de38dc014da3292675f94e390bdb8a1fdd0e5e396774843ee05d72506240a
loft-core-rust/crates/loft-ffi/src/lib.rs
  4faa04ec494d6d754112966b71f5bea511b36c052a7868d8d25c76af77799c4f
loft-core-rust/target/debug/libloft_ffi.so
  d76387f1dac0e0dc8b19d69adb99a984ae2d314502cb3de93111c38e664bdd9a
loft-android/app/build/generated/uniffi/net/aptist/loft/core/generated/loft_ffi.kt
  e5e767f313219a78d0be792d75d759bf0d622c234e7bc313de82eb28d169da95
loft-android/app/src/main/kotlin/net/aptist/loft/service/SnapshotWire.kt
  9b3720af8bdff614ed95963c102f4ee297089b074852977b1ebda2f6fc2bb39d
loft-android/app/src/main/kotlin/net/aptist/loft/service/SnapshotPublisher.kt
  7f5e5d4e0a14725bb33123ec2c205667395ed7b451c63f0daabc397c105a52fa
loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/ControlCodec.kt
  37ef3c30cd415c7bcce8bc997c748f7d6f50a434b50c41155155658f3cf74b32
loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftViewModel.kt
  cdc25b06ee8b3227c52adfab2256aaaf8aadd2c401d15dc1b92a662864746e9c
loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftApp.kt
  10bf08e182ebc1bff3b0fa3be2d01f22c45d7e3abb922d6069daeb8bc4f7b8b6
loft-android/app/src/main/kotlin/net/aptist/loft/service/LoftRuntimeOwner.kt
  f57fb91cd1e0512f696fe0fef4be9de7e0a41c3bdb6254c658b5b23d5f3eb5c8
```

---

## REQ-NODE-01 — 修复后独立复验（2026-11-25 18:28:38 UTC）

> "| 节点目录/导入 | 本地工作集最多 200 节点；单次解析 512 KiB | 原始及解码后的输入均计额，数量与字节双限额 |"
> — `guide/guide.md` v3.6「低内存：先设可控上限，再冻结实测门槛」L700
>
> "| 审计/节点列表 | 分页与稳定 ID，避免全量复制、每行单独数据库连接或重组 |"
> — `guide/ui-design.md`「UI 自身的内存与电池约束」L344
>
> "- Stop、撤销与阻断使用优先取消入口，幂等调用；普通请求队列满时返回繁忙，数据转发、数据库写入与统计不能阻塞停止信号。"
> — `guide/guide.md`「连接状态机与故障恢复」L678
>
> "UI 只展示 Rust 的只读快照和订阅事件，不管理连接对象，也不在页面中另建重连、心跳、扫描或 Token 刷新任务。活动页拥有订阅；切页、进后台与 Binder 断开时解除，重新进入读取最新代际。"
> — `guide/ui-design.md`「UI 自身的内存与电池约束」L336
>
> "`nodePage(offset: UInt, expectedGeneration: ULong)` returns an owned `NodePage` with `schemaVersion`, `generation`, `offset`, full `nodeCount`, up to 50 summaries and optional `nextOffset`. Valid page starts are 0/50/100/150 within the workset; an empty workset permits offset 0. An intervening global generation change returns `StaleGeneration`; malformed offsets return `InvalidNodePage`; a poisoned owner returns `StateUnavailable`. Reading a page neither publishes nor reconciles priority Stop nor advances a generation. The Android page boundary must reject stale binding/request epochs, retain only one page and preserve a stable selected ID plus bounded metadata across pages. Selection is a UI draft; `activeNodeId` remains Rust's confirmed connection."
> — 当前 `docs/contracts/framework.md`「Local configuration and queries」L17

**Verdict:** implemented · confidence: high

**What this demands of an implementation:** 保持原要求范围，确认第 51–200 个已接受节点确实能通过有界接口被发现、选中并交给原有目标/删除命令；新页请求和回调不串请求、绑定或代际，不因读取而取消票据/改变业务状态，不延迟优先 Stop。实际页载体及含草稿/有效两份名单的主快照应满足 Binder 字节预算。此 verdict 描述已实现的源码与已执行主机边界，不声明真实 VPN、最终 APK 或实机 UI/Binder 验收完成。

原始发现和复现输入未被改写：本地 `tmp/review/req-node-01-postfix/baseline/` 保存原始报告、result、命令/摘要与搜索记录；原始报告 SHA-256 为 `b71501695b3ded3df9767da904392f82e733f184ecd663447395a9617ecaf753`。Git 基线仍为 `b0c611067981fba74b2c616e73fcf7ab9f434721`；未提交工作树通过下面 SHA-256 固定。Rust 在移除旧 PEM wrapper 依赖后重新冻结，Android 分页源代码/API 已完成接入；本审查未改动其实现。

---

**Where enforcement lives:**

```rust
// loft-core-rust/crates/loft-core/src/lib.rs:L212-L234
pub fn node_page(&self, offset: u32, expected_generation: u64) -> Result<NodePage, CoreError> {
    if expected_generation != self.generation {
        return Err(CoreError::StaleGeneration);
    }
    let start = usize::try_from(offset).map_err(|_| CoreError::InvalidNodePage)?;
    if !start.is_multiple_of(MAX_SNAPSHOT_NODES) || (start != 0 && start >= self.nodes.len()) {
        return Err(CoreError::InvalidNodePage);
    }
    let nodes: Vec<_> = self
        .nodes
        .iter()
        .skip(start)
        .take(MAX_SNAPSHOT_NODES)
        .map(|node| node.summary.clone())
        .collect();
    let end = start + nodes.len();
    Ok(NodePage {
        schema_version: 1,
        generation: self.generation,
        offset,
        node_count: self.nodes.len() as u32,
        nodes,
        next_offset: (end < self.nodes.len()).then_some(end as u32),
```

- **完整目录可查询。** `NodePage` (`loft-core/src/lib.rs:L96-L104`) 明确带 generation、offset、总数、最多 50 行及 next_offset。查询先验证代际，再验证固定页起点；空目录只允许 offset=0。满 200 个时四页为 0/50/100/150，稳定顺序来自原工作集的迭代，不依赖导入回执缓存。常规 `CoreSnapshot.nodes` (`L176-L186`) 仍是前 50 行，但已不是唯一目录读取入口。
- **FFI 查询保持只读。** `loft-ffi/src/lib.rs:L227-L235` 用真实 owner Mutex 取得状态并调用 `&self` 查询，随后在锁外转换记录；明确绕过 `with_state`，没有 reconcile_priority_stop 或 publish_snapshot。错误映射及记录转换位于 `L369,L411-L422`。实际读前/读后快照相等，票据仍可冻结和一次性领取。
- **新的实际 IPC 路径存在。** `ILoftControl.aidl:L9`、`ILoftEvents.aidl:L6` 增加 queryNodePage/onNodePage；`LoftCoreService.kt:L21-L32` 对该入口同样检查 Binder UID。当前 `LoftRuntimeOwner.kt:L103-L123` 校验 requestId/offset、使用已有单 worker/8 槽命令队列、调用真实 `core.nodePage`，再编码并发送专门页回调；成功不修改核心或伪造 snapshot。错误返回 typed code/空页载体，队列满返回 RESOURCE_BUSY。`L444-L446` 再检查载体上限。
- **页字节/形状有界。** `NodePageWire.kt:L17-L34,L36-L64,L66-L81` 对 schema、最多 200 总数、固定 offset、确切当前行数及 continuation 检查；UTF-8 文本、strict Boolean、剩余字节、50 行和 60 KiB 上限均由真实编码/解码器执行，decoded nodes 为不可变集合。更宽 wire 字段上限的保守页大小为 `28 + 50×485 + 5 = 24,283 B`，仍小于 60 KiB；实际最大合法测试页为 19,033 B。
- **陈旧回调被隔离。** `NodePageConsumer.kt:L7-L24` 只保留一个 binding/request/offset/generation 元组；旧绑定、被替代请求及重复响应拒绝，cancel/end 清理请求。当前请求解码后一次性消费；offset/generation 不符返回 null，不能当作有效页。`CoreServiceClient.kt:L115-L139,L149-L155` 还验证 UID、code/字节大小和 binding ticket，并在断开时结束 consumer。
- **UI 使用已测试的页与选择组件。** `LoftViewModel.kt:L172-L177` 从当前页或基础快照取得 summary，调用 `NodeChoice.select`；`L346-L354` 接收基础快照时改用 `NodeChoice.receive`，保留末页选择。`NodeChoice.kt:L8-L17` 只保留一个脱敏选中摘要，区分选中候选和 snapshot.activeNodeId，不把首屏缺少该行解释为丢失选择。`LoftApp.kt:L343-L359,L366-L382,L464-L470` 实际显示 current page、Prev/Next/refresh，并从保留摘要显示详情/候选，原 first_page_only 提示不再承担目录入口。
- **可见性与代际生效。** `LoftViewModel.kt:L88-L93,L138-L148,L269-L321,L382-L389` 仅在可见节点/详情页查询，离开/后台/断开时取消；查询代际/offset 与当前 core 一起绑定。回调再次校验 request、可见性、generation、offset、nodeCount；目录缩减时 offset 夹到合法末页。没有节点轮询或独立业务运行时。
- **Stop 仍走优先通道。** 当前 `LoftRuntimeOwner.kt:L128-L138` 的 Stop 不进入普通队列，`L327-L350` 先原子投影 Stop 并取消持有者，再在专门 priority worker 回收。Rust 页查询不与 mutation helper 共用 reconcile；FFI 已编译单元测试用真实 Mutex 证明被排队的读和被占用的普通锁不能延迟 begin_vpn_stop。

---

**Paths walked:**

- **真实主机目录链：** 生成 UniFFI `AppCore.importNode` → Rust 200 个合法合成 Pro 配置 → 实际 `AppCore.nodePage` → `NodePageWire.encode` → `NodePageConsumer.expect/consume` → 200 个原顺序 summary/ID。每页 50 行、next_offset=50/100/150/None；所有 ID 唯一且等于实际导入集合。✓
- **实际 Android caller 链（源码遍历）：** 节点页 Prev/Next/refresh → `LoftViewModel.loadNodePage` → `CoreServiceClient.queryNodePage` → 私有 AIDL/服务 UID 检查 → `LoftRuntimeOwner.queryNodePage` → 同一个真实 FFI/页编码器 → `ILoftEvents.onNodePage` → tuple consumer → `receivedNodePage` → current page。此链使用了上条已执行的生产组件；跨进程 Binder/Compose 本身未在主机执行。
- **末页选择到真实命令：** 末页原始 index=180（第 181 个记录）→ 生产 `NodeChoice.select` → 实际 `SnapshotPublisher/Consumer` 的前 50 行快照 → 选中 ID/summary 保持 → `ControlCodec.encode/decode(CoreCommand.Connect(id,generation))` → 真实 `AppCore.beginVpn` → 返回票据目标及 generation 匹配。连接/停止的合成 reducer 结果也不会让首屏快照清除选择。✓ Android 系统授权入口 `MainActivity.kt:L56-L65`、`LoftViewModel.kt:L181-L196` 另经 permission draft 保存目标/代际；本次没有实际授予系统 VPN 权限。
- **末页管理：** 第 200 个记录 ID → 生产 RemoveNode 编码/解码 → 真实 `AppCore.removeNode` → 当前代际末页 49 行、nodeCount=199、无 next_offset。选中项的显式 removed 也清理摘要。✓
- **陈旧请求/回调变体：** 真实 consumer 先请求第一页再请求末页，旧 request、错误 offset、错误 generation、重复 current reply、已 cancel 的 pending、已 end/换绑定的旧响应均返回 null；重新发起的正确 current request 获得末页。实际 core 在业务代际变化后对旧 generation（包括 UInt.MAX_VALUE offset）返回 StaleGeneration；检查不修改 snapshot。✓
- **读取/Stop：** 真实页查询在 Connecting 和 Stopping 中保持 core snapshot 相等、保留未取消票据；显式 Stop 后票据领取返回 TicketExpired，页读取不解除 Stopping。独立执行真实 Mutex/queued-read 三个单元测试：优先 Stop 立即可达，查询不触发 reconcile。✓ 合成 stopped receipt 只验证 reducer，不作为 FD/Go/TUN 已回收证据。
- **合法尺寸/保持行为：** 50 行最长合法 Pro summary 页、不同草稿/有效名单各 100 包各 4096 B，与原最大主 frame 相同的字段/格式均能经生产编码器完整往返；oversized/trailing 页载体被拒绝。新增页没有把原主快照膨胀为 200 行或 UTF-16 JSON。✓

---

**Searched:**

完整命令/逐行结果保留在 `tmp/review/req-node-01-postfix/search-records.json`；结果用于定位调用链，未当作行为测试。

| 搜索 / 范围 | 实际结果 |
| --- | --- |
| `pub fn node_page\|fun queryNodePage\|void queryNodePage\|void onNodePage`；Rust core/FFI、Android service/AIDL | 7 个生产定义：Rust 2、client/service/owner 3、AIDL 2；全部读取其 caller/callee。 |
| 原 `state.native?.core?.nodes?.none` / `frame.core.nodes.any` 选择守卫；LoftViewModel | 0 命中；现在使用 production NodeChoice，末页行为已实际执行。 |
| `items(state.nodePage\|previousNodePage\|nextNodePage\|refreshNodes\|selectedNodeMetadata\|NodeChoice`；LoftApp/LoftViewModel | 20 行命中，包含页列表、三个操作、详情摘要和选择/收据 adapter；已读取 L172–177、L269–321、L346–380 与 UI L326–382。 |
| `nodePageVisible\|cancelNodePage\|page.generation != core.generation\|page.nodeCount != core.nodeCount`；LoftViewModel | 15 行命中，覆盖可见性、离开/后台/换绑定、重发及 current core 校验。 |

重读了主计划节点/资源和 Stop 契约，以及 UI 节点列表、按应用草稿/有效两份和 UI 内存/生命周期要求；未读取私有 Task/TEST 输入。原查询/回执缺失搜索记录保留在历史段，不用于描述修复后的实现。

---

**How the verdict was reached:**

旧 `partial` 的具体失败条件是成功接受的 150 个后续记录没有目录入口；现在实际 FFI 读出的四页经过生产 wire/consumer 得到全部 200 个，并能把末页选中 ID 经生产命令 codec 交给原真实目标/删除路径。新增元组/可见性/代际检查，以及读前后状态相等和 queued Stop 测试，排除了仅增加方法名、拼接导入回执或查询引入生命周期副作用的替代解释。原主快照字节行为保持，未发现新的确认偏差。

**本审查实际执行命令：**

```text
cd /home/coder/LOFT-mobile
python3 tmp/review/req-node-01-postfix/run_review.py
exit 0
```

该独立脚本先校验冻结 host .so 和生成 Kotlin 摘要，将实际生产 Kotlin、被遍历的 Rust/Android caller、160 个生成类与 host library 复制到哈希固定的 `inputs/`，只在审查 tmp 中编译。Kotlin 2.3.21/JDK 21/JNA 5.18.1，编译 `-Xmx384m -XX:ActiveProcessorCount=1 -Xbackend-threads=1`，执行 `-Xmx192m -XX:ActiveProcessorCount=1`。SDK 36 类定义仅供生成绑定选择 JNA cleaner，实际 AppCore 为真实 native handle；没有模拟 AppCore、Go、Android service 或业务状态实现。OpenSSL 私钥始终在内存，URI 使用公开合成 `.invalid` 目标，原文不输出。

| 执行观察 | 结果 |
| --- | --- |
| 实际接受 / 四页发现 | 200 / 200，原顺序且唯一。 |
| offset / continuation | 0→50→100→150→None。 |
| 四个实际页 payload | **19,033 / 19,033 / 19,033 / 19,029 B**。 |
| 末页原 index=180 选择 | 前 50 行 snapshot 后保留，真实 FFI 票据目标/代际匹配。 |
| 陈旧/错误 offset、generation、request、重复、取消、旧 binding | 真实 consumer/core 拒绝。 |
| 读取和 Stop | 实际 snapshot 相等；未取消票据可继续；显式 Stop 使未领取票据过期。 |
| 末页删除 | 真实 FFI 删除后总数 199、末页 49 行，目标 ID 不存在。 |
| 草稿/有效各 100 包各 4096 B 主 frame | connected reducer fixture 28,406 B；stopping reducer fixture **28,428 B**。 |

另在同一个已编译生产 wire/consumer/selection 与生成记录上直接运行现有六个页测试（未调用 Gradle）：

```text
java -Xmx192m -XX:ActiveProcessorCount=1 -cp <pinned classes and JUnit dependencies>
  org.junit.runner.JUnitCore net.aptist.loft.service.NodePageWireTest
  net.aptist.loft.service.NodePageSelectionTest
OK (6 tests); exit 0
```

六个测试补充空/单行/50/51/末页形状、ULong.MAX_VALUE、不可变行集合、错误 schema/count/offset/continuation 与陈旧选择回调。确切 argv、class SHA 和 stdout/stderr 位于 `focused-wire-tests-command.json` 及相邻日志；不是 source-text assertions。

真实 Mutex/Stop 测试在 root 已编译的 FFI unit binary 上独立执行（未编译 Rust）：

```text
loft-core-rust/target/debug/build/loft-ffi/45afba7b0496f816/out/loft_ffi-45afba7b0496f816
  --test-threads=1 node_page --nocapture
2 passed; 0 failed; exit 0

same binary --test-threads=1 priority_stop_does_not_wait_for_a_held_normal_owner_lock --nocapture
1 passed; 0 failed; exit 0
```

涵盖 `a_queued_node_page_cannot_delay_priority_stop`、`node_page_does_not_reconcile_a_pending_priority_stop` 和 held-normal-owner lock Stop。binary SHA-256 为 `24eeabec4688aa5e053659921bb7baebb68cb82d41b9ac38f18ca0f387ef533a`；`priority-stop-commands.json`/相邻日志保留确切证据。root 的 fresh workspace 日志 `tmp/verification/rust-root-final-workspace.log` 另显示 67 个测试无失败；本代理只独立重跑上述三个。新复验各执行退出 0，没有将准备阶段 skeleton 或路径缺失当作修复后产品失败。

文档核对第一次将历史合同 L9 与同期重写后的合同比较，因引文不同而退出 1；随后源码一致性核对又因同期 caller 改动而退出 1。已分别按历史报告摘要、当前 L17 引文和 caller 后续观察记录核对；这些核对失败没有被计为功能缺陷。

---

**Open questions / unverified:**

- 未运行 Android 跨进程 Binder/Parcel 实测、完整 ViewModel/Compose 点击、真实系统授权、ARM64 JNI/最终 APK 或实机 VPN/功耗验收；Android caller 证据为已读源码，实际动态证据来自生成 FFI 与同一生产 wire/consumer/selection/control 组件。APK 编译/最终 native 包装由 root/Android owner 完成，不从本主机测试推断。
- ready/failure/stopped 均为审查专用 typed reducer 夹具，虽经真实 core 校验，仍没有真实连接、身份认证、Go/TUN/FD 释放或设备接受；没有伪造这种完成状态。
- 原始证据保全和当前源码/输入 SHA 已校验；这是实际 runtime 边界复验及 caller 审查，未宣称运行了完整双 worktree 安全 PPV runner 或独立实机流程。历史失败适用于历史输入，最新 verdict 适用于下面固定输入。
- 运行期 source/records/library 与固定输入一致。执行后 root 重写了当前 framework contract，并在 LoftRuntimeOwner 增加一次性 FailureDispatch/blocked 发送保护；后者的页查询、Stop 和页发送函数内容保持一致、行号移动，已额外读取 caller 并按上文更新引用。此后 owner 又将 forwarding-disabled 事实收紧为 start joined 与 Go proof 同时满足，当前观察 SHA 为 `de60649540996233154d091f1b5923ebf63b1aaffaefed0e480af2b5f4ee2f8b`，单独保存在 `caller-followup-2/`，页查询/Stop 入口仍未改变。相邻故障/事实调度改动由 owning agent 验证，本记录没有把它当作本代理已执行的动态代码。当前合同以 `fb67cb732c596c6127c7265bce7558d7f101e5fa5fe179c6d2781c5365173f31` 固定在 `caller-followup/`；原始合同 L9 引用属于历史初版，不跟随当前合同改写。最终 delivery 若修改 page API、codec/tuple、选择 adapter 或名单/字段上限，需要重验其影响。
- Android owner 随后报告完整 source/AIDL/app/foundation/instrumentation Kotlin 编译测试退出 0，pager/API/NodeChoice 保持不变；LoftApp 的后续触摸防护改动属于另一个审查范围。本文 UI caller 的行号/摘要标记被读取的固定版本，未把同期改动后的完整 UI 或 APK 当作本代理已动态执行。
- SQLCipher、OAuth、QR、生产节点和完整 P0–P5 能力仍不在本 requirement 的完成声明中。

本次固定输入 SHA-256（其余 caller/class 摘要在本地 `input-hashes.json`）：

```text
loft-core-rust/crates/loft-core/src/lib.rs
  dd7076dfea9a4887be840ba327cf28c874854943e46dfd722d9d5cbed1443fc1
loft-core-rust/crates/loft-ffi/src/lib.rs
  ea27b7020d58a57d6143590ad73e3b3e08bbfef2767f01aa7746b5af0e3a1d48
host libloft_ffi.so
  cf19b0babf3cc3a066565e21d93e5e2606addc40ca995cf5c0e34871520b05d6
generated loft_ffi.kt
  0f04b7df8550e111fdc7f5552d72aeec01b7d14b619949ad3d521dbb36569467
NodePageWire.kt
  40ad986f52934dd41c860e3d099b81e21b46abd8c697adf66b15e78bfff0071a
NodePageConsumer.kt
  363d434b23e66fa3d670bf3edf293071b5252515efe14a71bf0ca1b2f3ca3fd8
NodeChoice.kt
  88a6a9833393d4b71e42b0d1a55ee3eae501f8862460f4c374fdce9c645e3014
CoreServiceClient.kt
  37f291e051e659be53a6aef1db0b0048515d320086f2505bc8fc9e90ee4f4f79
LoftRuntimeOwner.kt
  75f9ce8a3d3584b9b14c1e59ab9427b3f92148218c31a58934a390826a79edbd
LoftViewModel.kt
  963a3d94aa6c60a5304758f454f28e284a42735d9b705955d765cdbc2f0cb19d
LoftApp.kt
  82748d9f696b91c34af5836d3937987c47fbefbf3488889999b6b1664e31e67b
```
