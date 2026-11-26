## REQ-VPN-STOP-INGRESS-01 — Priority Stop/revoke ingress and truthful release

> "| `onRevoke()` / 用户停止 | 取消重连，关闭 Go 连接、TUN 与关联任务 | 资源回收完成，系统接管后的状态准确 |"
> — `guide/guide.md` v3.6, connection state machine, L673
>
> "- Stop、撤销与阻断使用优先取消入口，幂等调用；普通请求队列满时返回繁忙，数据转发、数据库写入与统计不能阻塞停止信号。"
> — `guide/guide.md`, L678
>
> "- Stop 的完成条件包括任务结束、FD 关闭与自有配额归还；超时返回失败，由服务生命周期处理。"
> — `guide/guide.md`, L679
>
> "| 主操作 | 连接、取消连接、停止或恢复验证 | 直接发 Rust 命令；状态来自回执，按钮不自行宣布成功 |"
> — `guide/ui-design.md`, L190
>
> "| 停止中 | 正在停止 | 暂不可重复操作 | 完成资源回收后显示未连接；失败显示真实状态 |"
> — `guide/ui-design.md`, L208

**Latest verdict:** `implemented` · confidence: high, for the reviewed source contract and executed host components after the scoped Android repair. Actual Android main/Binder/TUN/revoke execution remains **unverified**. The original `partial` baseline and its source/native evidence are preserved below; the final source/host re-review is at the end of this record.

**What this demands of an implementation:** UI/private Binder, notification Stop, system revoke and matching VPN-service destruction must bypass ordinary queued work. They must promptly fence new/start work and cancel platform resolution/original-TUN ownership without waiting on Go completion or ordinary Rust mutation/publication. Native Abort/Stop/Close and owner joins belong on a reserved worker. `Disconnected` requires a matching attempt and actual original TUN closure, Go duplicate release, construction/copy/listener completion and returned owned resources. A caller timeout must retain incomplete ownership and report failure.

Scope is this framework's Stop/revoke path, not automatic reconnect, the full P0–P5 roadmap, actual device acceptance or production VPN/DNS. Product source was read-only; this document is the sole delivery edit. Temporary host harnesses and compiled outputs are recorded separately. No task credential file, `guide/TEST.TXT`, private node or upstream project source was read. Git baseline: `b0c611067981fba74b2c616e73fcf7ab9f434721`; code observations are identified by SHA-256 below.

---

**Baseline source enforcement / paths walked (pre-repair hashes):**

- UI `LoftViewModel.stopControl` (`loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftViewModel.kt:L198-L212`) cancels the permission draft, uses a separate Stop request even when ordinary work is pending and falls back to the OS Stop intent if control is unavailable. `CoreServiceClient.execute` (`app/src/main/kotlin/net/aptist/loft/service/CoreServiceClient.kt:L92-L114`) calls the synchronous private control method from the UI entry; it does not independently offload native work.
- `ILoftControl.aidl:L5-L10` is synchronous; `ILoftEvents.aidl:L3-L6` is oneway. `LoftCoreService.kt:L15-L22,L31-L33` enforces the same application UID and calls the shared `LoftRuntimeOwner`. Manifest L30-L34 keeps controller private and the OS VPN service guarded by `BIND_VPN_SERVICE`, in the same `:vpn` process.
- Notification `PendingIntent.getService` → `LoftVpnService.onStartCommand(ACTION_STOP)` (`LoftVpnService.kt:L33-L43,L76-L83`); `onRevoke` → `requestStop` (L83); `onDestroy` → `serviceDestroyed` (L84-L88) → matching-attempt `requestStop` (`LoftRuntimeOwner.kt:L387-L390`). Destroying the separate UI control service only releases the UI lease (`LoftCoreService.kt:L34-L37`).
- `LoftRuntimeOwner.execute:L121-L158` decodes a bounded command and recognizes Stop at L131 before `resources.retainUi` or the ordinary eight-item command worker. `beginVpn:L160-L194` captures/rechecks the Stop epoch and rejects an attempt admitted across Stop. `startTransport:L209-L249` checks cancellation before TUN/Go startup and joins its `StartOwnership` in `finally`.
- **Baseline ingress contradiction:** `LoftRuntimeOwner.requestStop:L320-L344` sets the admission/attempt fence, but then calls `resources.currentCore` (L323), Rust/publication (L325), and synchronous `go.runtime.abort()` (L327) before closing the original (L328). `NativeResources.currentCore`/`retainUi` share a monitor with native disposal (`ui-foundation/.../NativeResources.kt:L12-L25,L32-L53`). Go `VPNRuntime.Abort` directly calls native `Runtime.Abort` (`loft-vpn-engine-go/engine/vpn.go:L67-L73`), whose held-work path waits up to five seconds (`internal/vpn/runtime.go:L260-L313`). The tested held-reader case actually waited 5.01 seconds. Thus the main/Binder ingress can wait on native completion while the original TUN remains open; the reserved worker only begins at owner L341. This is a source-confirmed divergence with host native-wait evidence, not a device reproduction.
- **Baseline resolver admission contradiction:** `AndroidSocketProtector.resolveNode:L52-L66` checks `stopped` before `QueryGate.start`; `cancelPending:L69` only sets `stopped=true` and calls `cancelAll`. `QueryGate.cancelAll:L47-L55` cancels current members but permits a later admission (`start:L44-L46`). The interleaving `read stopped=false` → Stop `cancelAll` → query `start` admits work after Stop. The adapter can call `DnsResolver.query` afterwards while its stopped callback executor drops callbacks (L32-L35), leaving the query's creation deadline as the fallback. The compiled production gate/real-descriptor harness below confirms the admission behavior; no `DnsResolver` API was executed.
- Rust FFI `begin_vpn_stop` (`loft-core-rust/crates/loft-ffi/src/lib.rs:L292-L309`) atomically sets a cancellation signal and uses `try_lock` for the normal state mutex; held or poisoned normal state does not delay the signal. `snapshot:L209-L225` projects immutable `Stopping`/`Unavailable`; `begin_vpn:L267-L282` checks both signal and fence. The underlying ticket rejects use after the signal (`loft-core/src/vpn.rs:L188-L192`), and Ready rejects canceled/stale attempts (L295-L310).
- Original Android descriptor ownership (`ui-foundation/.../OriginalTunOwnership.kt:L17-L35,L46-L66`) marks late establishment unconfirmed, fences adoption after Stop, closes the adopted original, and retains descriptor/close-failed facts after an error. `StartOwnership.kt:L11-L25` records real completion independently of a timeout.
- Go `Runtime.Abort:L260-L328` disables admission/context before its owned completion joins protocol/copy work. `Runtime.Stop:L331-L436` admits one completion owner, cancels pending construction, waits for Start/Abort/Drain/listener completion and retains an explicit five-second caller timeout. `Runtime.Close:L439-L450` closes that same owner permanently. `Snapshot:L186-L202` suppresses released facts while any such join remains owned.
- Go `session.signalCancellation`/`abort` (`internal/vpn/session_gvisor.go:L564-L612`) disables admission, cancels contexts, closes netstack before lazy flow closers and closes protocol resources. `session.stop:L623-L655` closes the Go TUN, joins copy/endpoint/stack/monitor owners, and marks release only if its closure result succeeds. `session.facts:L545-L563` requires released TUN, no flows, no physical sockets and zero added-buffer bytes. `finish:L259-L291`, TCP copy completion L294-L371 and UDP completion L374-L448 keep leases until their actual copy owners return. `internal/transport/client.go:L524-L569` cancels and joins Ready/business/monitor ownership before clearing material. `tun_fd_linux.go:L10-L29` verifies the TUN and creates a separate `F_DUPFD_CLOEXEC` duplicate; successful kernel duplication is source evidence only here.
- Baseline Android `cleanup` (`LoftRuntimeOwner.kt:L346-L385`) requires Start join, successful Go close plus strict `GoVpnFacts.provesReleased` (`GoVpnSnapshot.kt:L18-L19`), terminated resolver callbacks, network-listener unregistration and `tun.stop().tunClosed` before releasing the VPN lease and sending `confirmVpnStopped`. Failure reports `ENGINE_STOP_INCOMPLETE`/`ENGINE_STOP_FAILED` and keeps ownership. Rust `confirm_vpn_stopped` (`loft-core/src/vpn.rs:L417-L441`) checks attempt equality and both closure fields before clearing target/routing and publishing `Disconnected`; repeated matching complete receipts remain idempotent. These closure protections are implemented even though baseline ingress is defective.

Android service paths above use the full prefix `loft-android/app/src/main/kotlin/net/aptist/loft/service/`; foundation paths use `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/`. Rust core references use `loft-core-rust/crates/loft-core/src/`. AIDL/manifest paths are under `loft-android/app/src/main/`.

---

**Executed host evidence (independent reviewer):**

Tools actually used: Rust `1.100.0 (0ef1bc386 2026-11-09)`, Go `go1.27.4 linux/amd64`, OpenJDK `21.0.13.1+2-1-deb13u1-Debian`. Commands ran on 2026-11-25 with the pinned `scripts/env.sh`; native/Gradle/APK builds were not run by this reviewer.

```bash
# cwd /home/coder/LOFT-mobile
source scripts/env.sh
CARGO_BUILD_JOBS=1 cargo test --manifest-path loft-core-rust/Cargo.toml -p loft-ffi --lib --locked priority_stop
# exit 0; 3 passed, 0 failed, 1 filtered; affected crates compiled in 7.31s.

CARGO_BUILD_JOBS=1 cargo test --manifest-path loft-core-rust/Cargo.toml -p loft-core --test vpn_lifecycle --locked stop
# exit 0; 1 passed, 0 failed, 9 filtered; affected test compiled in 1.78s.

loft-core-rust/target/debug/build/loft-core/760986b4336b06c1/out/vpn_lifecycle-760986b4336b06c1 --test-threads=1 revocation_reason_can_follow_priority_cancellation_without_reopening_traffic --nocapture
# exit 0; 1 passed, 0 failed, 9 filtered; existing compiled test binary.
```

The FFI tests hold the actual state mutex and run a queued node-page reader while priority Stop returns and invalidates the ticket. The core lifecycle tests reject each incomplete closure field and late Ready, accept only matching complete receipts, and retain the Revoked reason. Their receipt values exercise the real reducer; they do not establish actual TUN closure.

```bash
# cwd /home/coder/LOFT-mobile/loft-vpn-engine-go
source ../scripts/env.sh
GOMAXPROCS=2 GOFLAGS=-p=1 go test -count=1 -tags with_gvisor -timeout 45s -run '^(TestCanceledTCPHandlerJoinsBothCopyOwnersBeforeReleasingBytes|TestAbortDeadlineRetainsOwnedCompletionUntilRealReaderJoins|TestNativeCloseFailureCannotFabricateReleasedStop|TestPendingStartStopAndCloseKeepOwnershipUnconfirmedUntilReadyJoins|TestConcurrentStopsShareOneOwnedCompletionWorker|TestStopTimeoutKeepsOwnershipAndReconcilesLateCompletion|TestCloseJoinsListenerAndKeepsReleaseUnconfirmedWhileCallbackRuns|TestStartRejectsNonTUNDescriptorBeforeAnyNetworkWork)$' -v ./internal/vpn
# exit 0; 8 top-level tests passed in 10.239s, including Stop/Close subcases.
```

This suite exercised actual authenticated loopback transport, blocked `net.Pipe` copy owners, a held TUN-close completion, pending Ready and listener joins. Abort and Stop caller timeouts took 5.01s each; ownership remained unreleased until the held owner returned. Sixty-four concurrent Stop callers shared one completion owner. Close failure did not fabricate release; an ordinary OS pipe was rejected as TUN before any network work. The packet-link TUN fixture substitutes the kernel TUN boundary, so these passes are not successful Android FD-duplication/closure evidence. The Go log also recorded host TCP Brutal/BBR unavailability and verified CUBIC fallback; it did not fail the tests.

The supplemental deterministic two-thread component harness is `/tmp/loft-stop-ingress-review/LateQueryAdmission.java`. It compiles against the existing production `QueryGate` class, reads the Stop flag before a latch, cancels or closes the gate while the worker is held, then releases admission. A real `FileInputStream` descriptor proves the admitted owner's cancellation behavior. Exact `javac`/`java` argv, stdout and exit codes are stored in `/tmp/loft-stop-ingress-review/late-query-command.json`; both exited 0. Actual output:

```text
cancelAll: late query admitted after Stop; real descriptor remained open until separate cancellation
close: late query rejected before platform work
```

This demonstrates the gate primitive's actual behavior and supports the source interleaving; it does not execute `AndroidSocketProtector`, `DnsResolver`, Binder or the VPN service. Harness Java SHA-256: `a40a51b564e174992f47457768cbf720d24be564488d4faf288315a8cd58d3a1`; harness class: `ab91fa07285df34de99265dac0c9730f95b6b0f2b9c0c86a49fc9b650e16ba29`. Tested production gate class: `1c7c5dea04dfa631778bd134d4dfba5edb0ddf3592f9023a993eefc68237db66`; Pending class: `098784bb44c47b0a5ff25fbee3827c96969506df14f8b71b5fdd9064b06867b4`.

**Owner-reported / read-only baseline receipts:** Android owner reported standalone RED: 86 tests, two StopDispatch assertion failures. The initially read XML `loft-android/ui-foundation/build/standalone/test-results/test/TEST-net.aptist.loft.foundation.StopDispatchTest.xml` had tests=2/failures=2, timestamp `2026-11-25T19:19:28.027Z`. The intentionally faulty helper waited for held native I/O and failed to close the original on a coalesced request. This was not a baseline Android service execution by this reviewer. The subsequent combined RED/GREEN and independent compiled reruns are recorded in the final re-review below.

**Failed discovery attempts:** guessed `internal/vpn/tun_unix.go`, `internal/vpn/fd*`, root `build/`, foundation `SnapshotPublisher.kt` and the instrumentation test's initial package path did not exist. Subsequent `rg --files` resolved them to `tun_fd_linux.go`, app service `SnapshotPublisher.kt`, isolated foundation output and `service/AndroidVpnIntegrationTest.kt`. These read/discovery failures are not failed product tests. No independent host test failed.

---

**Searched:**

- `Stop|revoke|停止|Disconnected|Binder|队列|取消` in the two designated guides: state-machine L673/L678-L679 and UI L190/L204-L209 supply the requirement; guide L314 also distinguishes Stop closure from TUN-retaining Block.
- `requestStop|priority|cancel|abort|shutdown|close|confirmVpnStopped|beginVpnStop|onRevoke|onDestroy|STOP` across the Android service package and foundation Stop helper/tests: every current user/system Stop ingress above leads to the shared owner; Stop is recognized before ordinary command submission.
- `begin_vpn_stop|confirm_vpn_stopped|priority_stop|resources_released|tun_closed` across Rust: FFI signal/try-lock, core ticket/readiness/state/receipt enforcement and their compiled tests.
- Go `Abort|Stop|Close|ownership_pending|resources_released` and lifecycle tests in `engine/`, `internal/vpn/`, `internal/transport/`: actual VPN wrappers and resource lifecycle, not the separate controller-only reservation runtime. Searches also identified real packet/copy/transport owners and the verified TUN duplication function.
- `rg --files loft-android/app/src/androidTest` and `Stop|stop|revoke|original|Descriptor|DISCONNECTED`: existing `AndroidVpnIntegrationTest.kt` has `realSelectedUidLiteralTlsTunAndStops` (L74-L110) and `stopDuringConnectionClosesEveryOwnedDescriptor` (L160-L177), but no executed onRevoke/notification/held-cleanup latency receipt was obtained here. These instrumentation sources require separately staged input and OS permission and were not run.

**How the baseline verdict was reached:** `partial`, because ordinary-queue bypass, Rust cancellation/readiness fences and actual completion-receipt gates exist and the small native host tests pass; the baseline active Android Stop/revoke ingress waits for native Abort before original cancellation, and its resolver can admit work across Stop. The requirement is neither absent nor undecidable. Successful fast cleanup does not refute the held-owner counterexample. Both contradictions were sent to the Android owner for a scoped fix; the final re-review below uses the stable repaired source and actual compiled tests.

---

**Open questions / unverified:**

- At the baseline, the final Android StopDispatch/owner/resolver patch, compiled class hashes, app/AIDL compilation and owner GREEN receipts were pending. The final source/host re-review below resolves these source/compilation questions; it does not establish a rebuilt release APK or actual Android execution.
- Android main-loop responsiveness, cross-process Binder ingress, actual `onRevoke`/notification/system destruction, successful verified TUN duplication and original/duplicate closure are unverified. Ordinary file/pipe closure and host packet-link ownership are narrower executed evidence.
- No emulator/handset/Fold/Doze/Always-on/lockdown/battery/72-hour or production acceptance was run by this review. The root integrator owns matching native generation, final release checks and separate device evidence.
- A five-second native caller bound is not a numeric Android ingress or total end-to-end cleanup latency promise. The guide supplies no numerical main-thread latency budget; the checkable property here is absence of native completion waits on entry and truthful incomplete receipts.

**Fixed input SHA-256 (baseline; recheck after owner repair):**

```text
guide/guide.md                                  14898b2d1c2a8cf531b2c9e74c0e1ec8ebbf653fcb67a01edb069572a1718999
guide/ui-design.md                              7e6fa82d80f112b849698592ce5d61c75aede5b5d240edd23cf62fc35d0dd038
docs/contracts/framework.md                     fb67cb732c596c6127c7265bce7558d7f101e5fa5fe179c6d2781c5365173f31
docs/contracts/resources.md                     0a4175aa49c51251daaf44dccd60f2daf53db12cde6c456d6a67ac129e5e97e6
Android service/LoftRuntimeOwner.kt              4abae449c0418dd5f6f736d90d5489302131a0deba3c7f0a12bc93cd65fe3245
Android service/AndroidSocketProtector.kt        3f4558468ddc1b3912427c4bc947b7043ee69dcbfb9c3df355dac87e0e79d7ee
Android service/LoftVpnService.kt                7f8a24a486db75a3b5e1b57c46e98d5f1b9f2a1de618e57f5c23606f2010776c
Android service/LoftCoreService.kt               091791f3a70d6c7a97f18b225eef821c8296383d72feab57e894bd0c7b44b3d6
Android service/CoreServiceClient.kt             37f291e051e659be53a6aef1db0b0048515d320086f2505bc8fc9e90ee4f4f79
Android service/GoVpnSnapshot.kt                172ba6751b59a81417667c0c6ee76eaebb3d1ad29d1d36bc70ec559dd6017d84
Android foundation/OriginalTunOwnership.kt       ea2c6b7a5fea55c20d65ec369d17f737325af517b2a55e003970cd205b04153f
Android foundation/NativeResources.kt            6242b81a6a80c57c5a9d0273dd84d09324bce994b9ad6e316fb21c1a8bfa8bf5
Android foundation/StartOwnership.kt             07712d15db1a86ebe6009988f4c4ba6646b96211bdcac9eda5e0a82f79a4634b
Android foundation/QueryGate.kt                  56e1ef4b12692a0250519e612f89b4eda461963319e84f7cd99eb85fd489381e
Rust crates/loft-ffi/src/lib.rs                  ea27b7020d58a57d6143590ad73e3b3e08bbfef2767f01aa7746b5af0e3a1d48
Rust crates/loft-core/src/vpn.rs                 737fab5b46a7a44cddfbe6fdbde9573844204cc05db8516f8613d703b008e983
Rust crates/loft-core/tests/vpn_lifecycle.rs      8dde51b4551f0a8d22adad4271aa521ace9a1801364e90df258e8f8663da118b
Go engine/vpn.go                                eed2c9e028556f822ae55351dbaf6c08913cae94b21cb4d2e5470c87d8b0a506
Go internal/vpn/runtime.go                      92d0eb0125d6a4d44230f0192a3891938871bce91c529be7aae5be7d5ab2bec2
Go internal/vpn/session_gvisor.go                613f9af5c128dac4b1470391d9299b869c830bc9cac5e87cbd979fb815ccfb48
Go internal/vpn/tun_fd_linux.go                  73ee3c46935fc7523ced3dfc9b461a011d05304011a2185e1689e9e9c46ba30c
Go internal/transport/client.go                  2c40328f8a543531cd9f0ef6998eeda57fed5ca1292cac318e1fe3f38a8f2a15
Go internal/vpn/lifecycle_test.go                4e462c98940691d13c73e88db3fba25e8bb0858401584b4f2282f00a502e84e9
Go internal/vpn/runtime_test.go                  5873c3b0309961ea60950b5ddfba6505a2607e201fb00145b09e248d7e3c9f5d
Rust compiled FFI unit binary                    acdc62b6615e6fc5c27fb396142b82c9195194bb8422d5065e5c167b75a93cb0
Rust compiled vpn_lifecycle binary               b0e22791c1d131dd1d548a43929c4d8ec72d303ea465435ef6fed9f1e73d19ef
```

Compiled Rust binary paths are the exact command paths above. Kotlin compiled-component paths are recorded in the harness command JSON. Temporary harnesses, caches, generated binaries and both guide inputs remain excluded from delivery.

---

**Final re-review — scoped Android repair, 2026-11-25 19:59:52 UTC:**

**Verdict:** `implemented` · confidence: high. This selects the skill's implementation verdict for the source requirement, with the Android API/real-TUN/device evidence limits stated separately. The baseline is not silently relabeled as passing.

**Current enforcement / every ingress branch:**

- All UI, notification, `onRevoke` and matching service-destruction paths still reach the same `requestStop`. The private Binder/manifest, Stop-before-command-queue dispatch, permission cancellation, Rust and Go exported APIs are unchanged. In the current owner, ordinary Stop dispatch is at `LoftRuntimeOwner.kt:L133`; Start's captured Stop epoch is checked at L164-L180. The distinct bounded ordinary and reserved priority workers are at L41-L45.
- `requestStop:L322-L374` captures the active attempt and establishes/coalesces Stop under admission/Stop locks (L323-L333), cancels the captured attempt (L328), and calls only the atomic Rust priority port (L336) plus terminal platform-resolution cancellation (L337) on entry. It does not call `currentCore`, `retainUi`, publisher/query, Go Abort/Close or `StartOwnership.await` on entry.
- `StopDispatch.kt:L5-L9` always cancels the original before deciding whether cleanup is coalesced or can be submitted. The owner scopes that close to the captured active identity under the admission lock (`requestStop:L339-L341`), so a delayed old coalesced call cannot close a replacement's TUN. A coalesced call returns without admitting a second cleanup (L342-L343). Four retained receipt observers bound coalescing; a busy observer receives an empty, unsuccessful busy receipt (L364), without synchronous native capture.
- Fresh work is submitted only to the reserved worker at L362. That closure performs publication, bounded Go Abort, resource monitor lookup/retain, optional Revoked mutation and cleanup (L344-L357). Abort at L348 precedes the construction join at `cleanup:L378`; a canceled pending Ready is signaled before its owner is awaited. Unexpected submission rejection returns `ENGINE_STOP_INCOMPLETE` with an empty payload and releases the Stop-admission guard for retry (L365-L372), rather than claiming release.
- `AndroidSocketProtector.kt:L28,L50-L67` now uses the production `NodeResolutionOwnership`. `NodeResolutionOwnership.kt:L10-L13` permanently closes its actual `QueryGate` in `cancelPending`; a stale earlier `stopped=false` check cannot admit a new query after that close. Existing admitted cancellation owners are canceled and late answers rejected by the same real gate. Callback executor termination is still joined only in Android cleanup (`AndroidSocketProtector.kt:L72-L76`), not ingress. Callback-overflow `cancelCurrent` is a separate nonterminal cancellation.
- Current `cleanup:L375-L414` preserves the baseline closure proof: construction joined, successful Go Close with strict released facts, platform callback termination, listener unregistration, original-TUN closure and successful VPN-resource release before `confirmVpnStopped` (L402). Incomplete cleanup reports failure and retains the attempt (L407); it never submits a complete receipt merely because the caller's wait ended. `metadata:L420-L428` still requires joined start, actual original closure and strict Go release for released facts, and suppresses readiness for canceled/faulted work. `serviceDestroyed:L416-L418` only stops the matching service owner.
- Rust FFI/core and Go runtime/session hashes below remained equal to the executed native host inputs. Their priority/readiness/receipt and owned-completion enforcement described in the baseline therefore still applies. No Go/Rust API or source repair was performed by this requirement review.

**Independent baseline-versus-patched compiled behavior:**

The owning agent preserved the combined RED input under `loft-android/build/post-patch-validation/stop-ingress/baseline/`. The two RED XML files each contain 2 tests/2 assertion failures, at `2026-11-25T19:38:57.891Z` (Stop) and `19:38:59.233Z` (resolution). The owner reports the combined run as 88 tests/4 failures, exit 1 in 34s; it subsequently ran GREEN88/0 in 32s. The RED helper/resolver are deliberate boundary skeletons representing the identified old ordering/admission defects, not a compiled pre-repair Android VPN-service binary.

This reviewer independently ran the preserved compiled RED helpers with the **same test-class bytes** as the patched standalone run. The run reached four behavioral assertions and exited 1 in 1.204s:

- Coalesced Stop accepted a late original descriptor.
- Held pipe completion kept both the caller and original open: expected `[true, true]`, actual `[false, false]`.
- A stale precheck admitted, completed and delivered a post-Stop query: expected `[true, true, true]`, actual `[false, false, false]`.
- A terminal cancellation owner could rearm another query.

The preserved RED test hashes are `e09f08a75ba409c89d0b11c989d67a0840cca8458d4f26d9176e7efc2438a4b8` (Stop) and `2de3664160cad96a8d67fc9bb42c1ebb4920f7ba15054daa07281e03e63ca43d` (resolution), exactly equal to the patched standalone test hashes. The defective helper hashes are `758a9c66df1d6c7cfd2af1365e3426d754bff3664c3022744dcaf1a1e02cb12c` and `19fbb0952d413165bc5ac6f61cd855dc8f6323d6a276396a067228bf91d1ef32`. Exact argv/output are in `/tmp/loft-stop-ingress-review/baseline-junit-command.json`.

Independent patched JUnitCore runs then passed **26 tests / 0 failures**, first using the stable standalone build (0.356s), then using the distinct current full Android build's compiled foundation classes (0.468s). Both exited 0; all watched helper/inner/test class hashes stayed unchanged during each execution. The six classes were `StopDispatchTest`, `NodeResolutionOwnershipTest`, `OriginalTunOwnershipTest`, `QueryGateTest`, `StartOwnershipTest`, and `NativeResourcesTest` (2/2/4/8/3/7 tests). They exercise actual held pipe I/O, original regular-file descriptors, stale admission, cancellation/deadline/latch behavior, incomplete construction and retained infrastructure ownership. They do not execute Binder or `ParcelFileDescriptor` TUN operations.

Exact independent replay commands, with classpath arguments expanded through task-specific variables:

```bash
LOFT_STOP_DEPS=/home/coder/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.3.21/a2ee2c4e220fee522f0451b723bab2a43f3481a7/kotlin-stdlib-2.3.21.jar:/home/coder/.gradle/caches/modules-2/files-2.1/junit/junit/4.13.2/8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12/junit-4.13.2.jar:/home/coder/.gradle/caches/modules-2/files-2.1/org.hamcrest/hamcrest-core/1.3/42a25dc3219429f0e5d060061f71acb49bf010a0/hamcrest-core-1.3.jar
LOFT_STOP_RED=/home/coder/LOFT-mobile/loft-android/build/post-patch-validation/stop-ingress/baseline
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -XX:ActiveProcessorCount=1 -cp "$LOFT_STOP_RED/classes/main:$LOFT_STOP_RED/classes/test:$LOFT_STOP_DEPS" org.junit.runner.JUnitCore net.aptist.loft.foundation.StopDispatchTest net.aptist.loft.foundation.NodeResolutionOwnershipTest
# expected exit 1; Tests run: 4, Failures: 4; reached behavioral assertions.

LOFT_STOP_GREEN=/home/coder/LOFT-mobile/loft-android/ui-foundation/build/standalone
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -XX:ActiveProcessorCount=1 -cp "$LOFT_STOP_GREEN/classes/kotlin/main:$LOFT_STOP_GREEN/classes/kotlin/test:$LOFT_STOP_DEPS" org.junit.runner.JUnitCore net.aptist.loft.foundation.StopDispatchTest net.aptist.loft.foundation.NodeResolutionOwnershipTest net.aptist.loft.foundation.OriginalTunOwnershipTest net.aptist.loft.foundation.QueryGateTest net.aptist.loft.foundation.StartOwnershipTest net.aptist.loft.foundation.NativeResourcesTest
# exit 0; OK (26 tests); 0.356s.

LOFT_STOP_GREEN=/home/coder/LOFT-mobile/loft-android/ui-foundation/build
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -XX:ActiveProcessorCount=1 -cp "$LOFT_STOP_GREEN/classes/kotlin/main:$LOFT_STOP_GREEN/classes/kotlin/test:$LOFT_STOP_DEPS" org.junit.runner.JUnitCore net.aptist.loft.foundation.StopDispatchTest net.aptist.loft.foundation.NodeResolutionOwnershipTest net.aptist.loft.foundation.OriginalTunOwnershipTest net.aptist.loft.foundation.QueryGateTest net.aptist.loft.foundation.StartOwnershipTest net.aptist.loft.foundation.NativeResourcesTest
# exit 0; OK (26 tests); 0.468s; current full-build compiled inputs.
```

Structured exact argv, stdout and all watched class hashes are in `/tmp/loft-stop-ingress-review/focused-junit-command.json` (standalone) and `full-build-junit-command.json` (current full build).

The additional compiled `RejectedStopQueue` harness filled a real one-thread/one-slot `ThreadPoolExecutor` while its worker was held in pipe I/O. The production patched StopDispatch closed its original `FileInputStream`, returned `false` after enqueue rejection, and never ran the rejected cleanup. Both `javac` and `java` exited 0. This independently checks the helper's failure ordering; the owner's typed `ENGINE_STOP_INCOMPLETE` Binder receipt remains source evidence. Actual output:

```text
full reserved queue: original closed; request returned false; rejected cleanup never ran
```

Exact argv/output: `/tmp/loft-stop-ingress-review/rejected-stop-command.json`; Java fixture SHA `ccdd7a95d0b60d1c9e102026f6ee80c5c9b422a8b478db2be03f0c6bf5300419`; class SHA `89f378ed70eb035c7f019fae6cc231e8c70527b6d3cf86a42866ad0ac803bef0`. This uses real I/O/executor admission, not source-text assertions or a fabricated engine/connection result.

**Current Android source compilation and host suite (owner executed, independently inspected):**

```bash
# cwd /home/coder/LOFT-mobile; executed by Android owner in the granted build slot
ANDROID_HOME=/home/coder/.local/share/loft-mobile/android-sdk python3 scripts/run_gradle.py -p loft-android :app:testDebugUnitTest :ui-foundation:test :app:compileDebugAndroidTestKotlin --no-daemon --max-workers=1 -Dorg.gradle.jvmargs=-Xmx1536m -Pkotlin.compiler.execution.strategy=in-process
# exit 0; BUILD SUCCESSFUL in 1m 8s; 43 tasks: 11 executed, 32 up-to-date.
```

The reviewer read the completed raw `loft-android/build/check-receipts/full-android-stop-source-check.log` and independently parsed every current XML result: `app/build/test-results/testDebugUnitTest` contains **31 tests**, `ui-foundation/build/test-results/test` contains **88 tests**, all 0 failures/errors/skips (119 total). App XML timestamps are `19:49:21.097Z`–`19:49:21.437Z`; foundation timestamps `19:49:25.835Z`–`19:49:26.400Z`. Raw log SHA-256: `d7190bf1932bbdcd9d858d8fe083ef7f8d8f1ed9c6cbf6e69b9b4e7d5ab43e45`.

Production Kotlin/AIDL and all **10 instrumentation methods compile**. The new `AndroidQueryCancellationTest.kt:L13-L36` uses actual Android `CancellationSignal` objects in two methods but was **not executed** here. No APK build/install, successful kernel TUN duplication, API cancellation, notification/main-loop, revoke or device pass is inferred from compilation. The SDK XML-version warning remains an environment warning, not a failed test.

The reviewer also inspected the actual compiled instrumentation declarations with:

```bash
/usr/lib/jvm/java-21-openjdk-amd64/bin/javap -public -classpath loft-android/app/build/tmp/kotlin-classes/debugAndroidTest net.aptist.loft.service.AndroidVpnIntegrationTest net.aptist.loft.service.AndroidQueryCancellationTest net.aptist.loft.SensitiveTouchIntegrationTest
# exit 0; compiled declarations contain 4 VPN, 2 cancellation and 4 touch test methods.
```

The respective compiled class hashes are `b638f5e8e6ae02b9892cb020b839909f9ea378d1ceae171a22f59282ff65e08a`, `62ef2b1a219247f68b1457f579bb5f9945ed01bbdacc2c7c8887f73aad1fbcc7` and `fea456eb36c879f365a3cc788ccfb5980d706b6266d34c06fbae78883baf15f0`. This is compiled-method metadata, not instrumentation execution.

The final owner source freeze is `loft-android/build/check-receipts/android-source-freeze.json`, file SHA-256 `49864b143732ea3300925e7dd2043104205ceae81afccf50328f5a2a4add95ec`; its source-inventory SHA is `f21c41d57783562a38628ae62ec87a0998b9a7596b91776626b78ed60f27c60a`. The reviewer read it and checked that all four repaired Stop/resolver source entries match the actual current file hashes. The owner's additional nine-case component replay is documented in `loft-android/build/post-patch-validation/stop-ingress/report.md`; its self-stated limit remains JVM components rather than direct APK/Android-TUN replay. This requirement record does not claim completion of a broader security/manual/device acceptance review from that component report.

**Final source / host / Android evidence distinction:**

| Evidence layer | Result and limit |
| --- | --- |
| Source contract | Implemented on the reviewed current Stop/revoke/control/service paths; both baseline source contradictions corrected, actual completion gates preserved |
| Independent Rust/Go host | 3 FFI priority tests + 2 lifecycle cases; 8 Go top-level cancellation/completion tests; exact commands and limits retained above |
| Independent JVM behavior | Preserved RED4/4 reached assertions; patched standalone26/26 and current full-build26/26; real queue-rejection and gate-admission harnesses passed |
| Android source compilation / JVM suite | Owner command exit0 independently confirmed in raw log/XML: 119 JVM tests and 10 instrumentation methods compiled |
| Actual Android APIs, Binder, original PFD and verified TUN duplicate | **Unverified** in this review; regular-file/pipe descriptors and packet-link TUN substitutes do not establish this layer |
| Actual device / production | **Unverified**; no handset/Fold/Doze/Always-on/lockdown/power/72-hour or production run by this reviewer |

Why `implemented` rather than `partial`: the previously demonstrated source ordering and late-admission gaps are removed, each current ingress/error/coalescing/closure branch was traced, the same compiled counterexample tests turn green, and current production Kotlin/AIDL compiles. Missing actual Android/device acceptance is explicitly unverified evidence, not an inferred code contradiction or a fabricated completion claim. Final ARM64/x86 native matching, optimized APK/signing/release checks and real platform acceptance remain the integrator's separate work.

**Final repaired inputs SHA-256:**

```text
loft-android/app/src/main/kotlin/net/aptist/loft/service/LoftRuntimeOwner.kt
  434a117ef173f0e738736112e71fb2574cf40fc05aeaa883aa429726131b89f2
loft-android/app/src/main/kotlin/net/aptist/loft/service/AndroidSocketProtector.kt
  622ab0926d96731e4036650e7f733a4b8aceed02570041b5ea38450f26f17408
loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/StopDispatch.kt
  663b02e460015e983aef8c8c4b4dac28263d26b8ccc5b62fb7c4d3c9024b2f24
loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/NodeResolutionOwnership.kt
  31bb9f4f18aad1870af64715913e7f4ba11675e5e236658e85a36f7b39385221
loft-android/ui-foundation/src/test/kotlin/net/aptist/loft/foundation/StopDispatchTest.kt
  483d7eeb4d2f629dddd7778dc6823476c60b2c319051977a1860d4e4551d912b
loft-android/ui-foundation/src/test/kotlin/net/aptist/loft/foundation/NodeResolutionOwnershipTest.kt
  0a7ce01797cf5ed8f3b40840f2eb7506a3fbda32b773b0dd9fa1db36dcf08e65
loft-android/app/src/androidTest/kotlin/net/aptist/loft/service/AndroidQueryCancellationTest.kt
  3033c8585f581dfff28a9c27058cc36177a7ad8e1ff5a7078ff55e79c5f273a6
full-build classes/kotlin/main/net/aptist/loft/foundation/StopDispatch.class
  5a1d67d3b0be3af56b15e344d78a9ef102ee66b678ca715460a8d762fc318dff
full-build classes/kotlin/main/net/aptist/loft/foundation/NodeResolutionOwnership.class
  09f1e7f8066862a56bfb7b6612c61d0bcd40dffe996290bb245e1153f97353f5
full-build classes/kotlin/test/net/aptist/loft/foundation/StopDispatchTest.class
  865e03ef8da1053fe35963a772a148bc1ac438c7a047b7f6beb41bf12a21b60e
full-build classes/kotlin/test/net/aptist/loft/foundation/NodeResolutionOwnershipTest.class
  713dbc467266b23c11cdf7d9357954368271c9534462ffc635d0abe242d06430
standalone classes/kotlin/main/net/aptist/loft/foundation/StopDispatch.class
  c6a539556b7e55f2f7dd810d511f08a9c5bff2a1f4c77b5f8f16f58cd7fc47a1
standalone classes/kotlin/main/net/aptist/loft/foundation/NodeResolutionOwnership.class
  6cbe7e5ee0f103ae4a7170861e4e271613b738553d9adbb6ee69737b9f4950f3
```

Full-build and standalone class roots are respectively `loft-android/ui-foundation/build/` and `loft-android/ui-foundation/build/standalone/`. Unchanged guide, contracts, service entry/consumer, original/query/start/native resource, Rust and Go hashes are the baseline hashes above and were checked again after the scoped repair. These hashes identify reviewed source/host inputs, not a final APK/device certification.
