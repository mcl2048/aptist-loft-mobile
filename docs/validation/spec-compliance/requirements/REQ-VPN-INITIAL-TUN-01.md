## REQ-VPN-INITIAL-TUN-01 — Initial Android TUN configuration and permitted foreground service

> "- **Kotlin 系统桥与 Shield 适配器**：调用 `VpnService.prepare()`、建立 TUN、执行 socket 保护、监听网络、管理通知；Shield 适配器负责采集 Android 平台信号并执行界面级防护动作。系统要求导出的入口受权限保护，应用私有的 Binder 控制入口使用非导出组件，两者复用 `:vpn` 中的核心。"
> — `guide/guide.md` v3.6, L363
>
> "5. **组件、权限与敏感数据**：见“应用自身加固基线”；仅申请 VPN 与必要平台权限；Root/调试迹象作为风险信号交由 Shield 评估；Rust 用 `zeroize` 管理敏感缓冲，Go/Kotlin 副本缩短生命周期并清理；密钥、Token、完整节点凭据和流量正文不进入普通日志。"
> — `guide/guide.md`, L648
>
> "| 主操作 | 连接、取消连接、停止或恢复验证 | 直接发 Rust 命令；状态来自回执，按钮不自行宣布成功 |"
> — `guide/ui-design.md`, L190
>
> "| 未连接且候选完整 | 未连接 | 连接 | 防重复点击，等待 Start 回执 |"
> — `guide/ui-design.md`, L203

**Latest verdict:** `implemented` · confidence: high, for the initial-TUN source requirement, source-supported configured-VPN foreground declaration and observed API29 initial TUN execution. The original baseline is `contradicted` and is preserved below. Repaired API29 Pro passed its real TUN/selected-UID literal TLS/Stop case; X adopted a real original TUN and then remained Blocked at a later native/authorization boundary. API34+ typed foreground execution, ARM64/handset and full DNS/P5 acceptance remain unverified.

**What this demands:** after actual user VPN preparation and validated routing, the first VPN start must configure its captured physical underlying network through an API valid before TUN establishment. It must keep real socket protection, nonempty effective per-app routing, original/duplicate TUN ownership, priority Stop and authentic Ready/Disconnected receipts. Foreground-service declarations must preserve necessary permissions and actual configured-VPN eligibility; a static lint finding must not cause unnecessary alarm privileges or removal of the foreground/permission checks.

Product source is read-only in this review. The sole delivery edit is this requirement record. Both local design inputs remain excluded from delivery. No Task/TEST input, credential, private node address, private logcat or node-bearing command was read. Only the explicitly approved redacted alias JSON/log pairs were consumed, after their scan flags and exact log hashes were verified.

The repaired source/test references below identify the **initial-TUN checkpoint**, source inventory `63481eac…` and app/test APKs `2a5b0d…`/`e9ca0d…`. Subsequent engineKnown/inert diagnostic instrumentation is a separate input. The initial-TUN test source is preserved as `loft-android/build/native-inert-review/baseline/AndroidVpnIntegrationTest.kt`, SHA `072e163f1d8082e231820d46170557c1d504312791a1dea7b619cd15d708c300`; production service/manifest/ownership inputs remained unchanged.

---

**Baseline source contradiction and actual API29 failure evidence:**

`LoftVpnService.establishTun` formerly began with `check(setUnderlyingNetworks(arrayOf(network)))` (`loft-android/app/src/main/kotlin/net/aptist/loft/service/LoftVpnService.kt:L45-L54`, baseline SHA `7f8a24a486db75a3b5e1b57c46e98d5f1b9f2a1de618e57f5c23606f2010776c`). The call targets the outer service method, before its `Builder` exists or calls `establish`.

This precondition cannot hold for the first TUN on the reviewed API29 fresh-start path:

- Pinned `VpnService.java:L365-L374` explicitly says the service setter succeeds only for an already established VPN and delegates to `setUnderlyingNetworksForVpn`.
- Pinned server `Vpn.java:L1148-L1156` requires both `mNetworkAgent` and `mInterface`, plus the owning caller UID. Its setter at L1537-L1539 returns `false` when that established-owner predicate fails.
- `Builder.setUnderlyingNetworks` instead clones the network array into the initial `mConfig` and returns the Builder (`VpnService.java:L821-L823`). `Builder.establish:L892-L897` subsequently submits that configuration to the system.
- Therefore the old Kotlin `check` throws before the first `Builder.establish`, despite valid user preparation. This is a source/API-confirmed defect. The failure logs below do not directly record the setter return value; they record the resulting stalled readiness stage and are consistent with this unavoidable fresh-start precondition failure.

The root's actual pre-repair X/Pro literal cases are preserved at `tmp/verification/android-node-{x,pro}-literal-before-initial-tun.{json,log}`. This reviewer first read `output_private_scan_passed=true`, compared each `.log` byte hash to its JSON `log_sha256`, and only then read bounded UTF-8 output. Each log is 1874 bytes and reports `SNAPSHOT_TIMEOUT` at `AndroidVpnIntegrationTest.kt:L89`, with **1 test / 1 failure**. Baseline test source SHA `5d8d09d4d25d702dc4fe90e44cdea65857721deeb7f2c2e2f532a49556759dcc`: L85-L88 imports the node, requires `ROUTING_STAGED` and `VPN_STARTING`, then L89 waits for `Connected`. The stack reaching that wait establishes those prior assertions were reached, not successful TUN/authentication/TLS or DNS. The later TLS and successful Stop assertions were not reached. Cleanup attempted in `@After` is not an asserted Stop receipt.

| Alias | Preserved JSON SHA-256 | Verified log SHA-256 | Result |
| --- | --- | --- | --- |
| X | `f6ff39a82bad16a75a18c07353db4de2ad8588d579d177574b03d29e426b4e1b` | `da45563ed60f8d4f9f339d76e176d6ad32a336fa1948e9b6a89427b9f49925a6` | `passed=false`; Connected wait timed out |
| Pro | `79527da403538e357ea3f0aea052beef74a6f63b50098e02e353528757efa11d` | `3d1abfe949093af976be34fac548dfa689ed946bf4f36c6775d127ce6ffd3001` | `passed=false`; Connected wait timed out |

Both receipts identify `Android_API29_x86_64_TCG_scaled_clock`. Their shell exit is 0 while instrumentation has a failure; the recorded `passed=false` and test assertions govern the result. Reported emulator times are 33.551/33.116 seconds and host elapsed times 197.224/204.554 seconds. Scaled-clock TCG results are Android API evidence, not real-time latency, handset power, ARM64 or physical-device acceptance. These failures do not establish that either private node itself is invalid.

---

**Authoritative source URLs and pins:**

The root initially fetched the mutable `android10-release` ref. It then resolved that ref to immutable commit **`37a24f52e6be75e7f7db461e3bee465152318c99`**, refetched both files by that commit and confirmed byte equality. This reviewer read the receipt and checked the actual local hashes. Provenance receipt: `tmp/research/android-vpn-source-receipt.json`, checked `2026-11-25T20:59:31.465560+00:00`, SHA `2a93119bc506be7b665c7872c5285e2ac3d36618493b8273706c49cbaf35f41b`.

- [Pinned API29 VpnService.java](https://android.googlesource.com/platform/frameworks/base/+/37a24f52e6be75e7f7db461e3bee465152318c99/core/java/android/net/VpnService.java?format=TEXT): local `tmp/research/aosp-api29-VpnService.java`, 39210 decoded bytes, SHA `d5fde79d5faf4839aa47f68941d5a3fb53b7c11abf85e71009a3f562822a92c1`.
- [Pinned API29 server Vpn.java](https://android.googlesource.com/platform/frameworks/base/+/37a24f52e6be75e7f7db461e3bee465152318c99/services/core/java/com/android/server/connectivity/Vpn.java?format=TEXT): local `tmp/research/aosp-api29-Vpn.java`, 93337 decoded bytes, SHA `d92bf3cb84dbfb3361a39cdc0463c1ef9c0977d63a652831da8d0d70d4dab34e`.
- Original fetched URLs used the same paths under `+/android10-release/`. The Android owner's independently fetched `refs/tags/android-10.0.0_r1` versions have the same decoded file hashes; their exact URLs are in `loft-android/build/initial-tun-review/source-pins.json`. A branch name alone was not treated as an immutable commit pin.
- [Android systemExempted documentation](https://developer.android.com/develop/background-work/services/fgs/service-types#system-exempted): saved `tmp/research/android-fgs-service-types.html`, SHA `18cc2f5dee9475fc8cf3eb59e4aab3c6c8e3e5581c909246362539eb934f722e`. This is a hash-pinned documentation fetch, not an immutable published revision.
- [Android16 foreground-service policy, tag android-16.0.0_r1](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/app/ForegroundServiceTypePolicy.java?format=TEXT): saved `loft-android/build/fgs-permission-review/aosp-api36-ForegroundServiceTypePolicy.java`, SHA `c12a4ed9ea14c7053dc3f49f1baff5e4a381ef9bd08073cfd871e31ffc16a3bd`. Its saved tag/fetch receipt is `aosp-api36-pin.json`; no separate resolved-commit claim is made for this tag.

These public AOSP/documentation sources were read as API evidence; Gateway/Portal project sources were not opened.

---

**ForegroundServicePermission finding — independently confirmed false positive for alarm necessity:**

The preserved lint report (`loft-android/build/initial-tun-review/baseline/app/build/reports/lint-results-release.xml:L5-L17`) reports a manifest error requiring `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` **and** one of `SCHEDULE_EXACT_ALARM`/`USE_EXACT_ALARM`. The baseline manifest already declares the FGS permissions, `BIND_VPN_SERVICE`, the `android.net.VpnService` action and `systemExempted`.

The official documentation at saved HTML L10580-L10594 says at least one qualifying alternative is required and separately lists configured VPN apps. Android16 source confirms the actual condition: policy L546-L561 requires `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` and an **any-of** list containing both alarm permissions **and `AppOpPermission(OP_ACTIVATE_VPN)`**. The list implementation L1082-L1103 accepts any granted member; `AppOpPermission:L1275-L1280` checks the actual calling UID/package's app-op mode. A configured VPN app-op is not inferred from a manifest declaration and is not an arbitrary-app exemption. This also differs from the initial TUN service setter: the app-op condition does not require an already established interface.

This reviewer independently ran `javap` on the actual cached `com.android.tools.lint:lint-checks:31.13.2` jar (SHA `3b64f395ae17fcea104882b00a4acdc7dc691f5daca5dff2bdde89fa052bb199`). Its compiled `ForegroundServicePermissionDetector` instructions 703–734 build only the two-alarm any-of list for `systemExempted`, omitting the VPN app-op alternative. The saved owning-agent disassembly is `loft-android/build/fgs-permission-review/detector.javap.txt`, SHA `36402c795af120d52b9a523f05988eb1e862ca635f04969548d7907ab8f3a3b1`; the independently inspected instruction block matches it.

```bash
/usr/lib/jvm/java-21-openjdk-amd64/bin/javap -c -p -classpath /home/coder/.gradle/caches/modules-2/files-2.1/com.android.tools.lint/lint-checks/31.13.2/e2f3f7637e4e711839115773d649f9fc6974c1a9/lint-checks-31.13.2.jar com.android.tools.lint.checks.ForegroundServicePermissionDetector
# exit 0; actual detector bytecode inspected, not Android runtime execution.
```

The service-scoped `tools:ignore="ForegroundServicePermission"` is therefore justified for this configured-VPN path. Required FGS declarations, actual user VPN consent, runtime `startForeground` checks, type, `BIND_VPN_SERVICE` and all other lint checks remain in force. Neither an alarm permission nor a global lint disable was added. Actual API34+ typed foreground-service acceptance remains unverified here; API29 executes the ordinary two-argument branch.

---

**Final scoped source diff / preserved semantics:**

The reviewer ran exact `diff -u` comparisons between `loft-android/build/initial-tun-review/baseline/app/...` and current source for the service, manifest and instrumentation test. Each diff exits 1 because a change exists; these are review observations, not failed product tests.

- `LoftVpnService.kt:L45-L56` removes the pre-establishment outer service setter and calls `Builder.setUnderlyingNetworks(arrayOf(network))` before `establish`. It preserves MTU1280, `198.18.0.1/30`, the IPv4 default route, synthetic DNS `198.18.0.2`, nonblocking mode, IPv6 exclusion, effective `addAllowedApplication`, nonempty per-app validation and null-PFD failure. The returned descriptor remains the actual Android original.
- Manifest L31-L37 adds a tools namespace, explanatory source link and **one service-element lint ignore**. The foreground type, FGS permissions, VPN bind permission, private controller, `:vpn` ownership and `stopWithTask=false` are unchanged.
- Instrumentation-only diagnostics retain at most12 lines of stable state/failure enum names, typed receipt names and Boolean TUN/ready/released/forwarding facts (`AndroidVpnIntegrationTest.kt:L47,L52-L56,L225-L245`). The diff preserves test predicates, deadlines, authentication/TLS checks and Stop assertions. It does not retain/emit raw snapshots, endpoints, node IDs, URIs or exception messages. No product flow or live credential fixture was added.
- `MainActivity.kt:L114-L123` and `LoftRuntimeOwner.kt:L162-L180` retain actual user permission and the service-side prepare recheck before admission. API29 `Vpn.java:L1031-L1039,L1052-L1058` still checks owning UID, consent and `BIND_VPN_SERVICE` at establishment; API29 `Builder.establish` can return null after revoke (L876-L899). The repair removes the impossible first-interface update precondition; it does not bypass consent or accept null as success.
- `AndroidSocketProtector.kt:L36-L47` retains actual FD validation, captured physical `Network.bindSocket`, `VpnService.protect(fd)` and stopped/network checks before use. The initial underlying-network declaration describes the same captured uplink; actual socket binding/protection still takes place separately. Its source hash remains `622ab0926d96731e4036650e7f733a4b8aceed02570041b5ea38450f26f17408`.
- `LoftRuntimeOwner.kt:L211-L249` still establishes/adopts the original, rechecks cancellation, creates the lazy Go owner and starts with the one-use URI. `reconcile:L279-L289` and Rust ready/stop receipt enforcement retain matching attempt, exact packages, authentication, protection and physical ownership checks. `requestStop:L322-L374` remains the reviewed priority off-entry-completion path; matching service destruction/revoke and actual original/duplicate release gates are unchanged. Its hash remains `434a117ef173f0e738736112e71fb2574cf40fc05aeaa883aa429726131b89f2`. No Rust/Go exported API or business state was changed.

The reviewer additionally inspected the **actual newly compiled x86 service class**, not an SDK stub or mocked Builder:

```bash
/usr/lib/jvm/java-21-openjdk-amd64/bin/javap -c -p -classpath /home/coder/LOFT-mobile/loft-android/app/build/test-x86_64/tmp/kotlin-classes/debug net.aptist.loft.service.LoftVpnService
# exit 0; compiled establishTun block inspected.
```

Bytecode instruction76 calls `android/net/VpnService$Builder.setUnderlyingNetworks`, before instruction219 calls `Builder.establish`; empty-list and null-descriptor exception branches remain. Class SHA `a93116ac5aa245f87c33c841925536f0b9f0af0907861fd415816a69b876128a`. This proves compiled method selection and preserved checks, not execution of those API calls on a handset.

---

**Compilation/lint evidence — owner executed, independently inspected:**

```bash
# cwd /home/coder/LOFT-mobile; root-granted build slot; reviewer ran no Gradle/native build
ANDROID_HOME=/home/coder/.local/share/loft-mobile/android-sdk python3 scripts/run_gradle.py -p loft-android -PloftTestAbi=x86_64 -PloftNativeGeneratedRoot=/home/coder/LOFT-mobile/tmp/native-test-x86_64/generated :app:testDebugUnitTest :ui-foundation:test :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon --max-workers=1 -Dorg.gradle.jvmargs=-Xmx1536m -Pkotlin.compiler.execution.strategy=in-process
# exit 0; BUILD SUCCESSFUL in1m31s; 81 tasks,19 executed/62 up-to-date.

ANDROID_HOME=/home/coder/.local/share/loft-mobile/android-sdk python3 scripts/run_gradle.py -p loft-android :app:lintRelease --no-daemon --max-workers=1 -Dorg.gradle.jvmargs=-Xmx1536m -Pkotlin.compiler.execution.strategy=in-process
# exit 0; BUILD SUCCESSFUL in2m35s; default ARM64 source/lint profile.
```

The reviewer read the completed logs and parsed all current x86 XML: **34 app +88 foundation =122 tests**, 0 failures/errors/skips. App timestamps `2026-11-25T21:05:19.101Z`–`21:05:19.524Z`; foundation `21:05:28.852Z`–`21:05:29.390Z`. Current default lint XML contains **0 Error/Fatal,31 Warning**, and no `ForegroundServicePermission` issue. Lint warnings remain reported; a successful lint run does not establish runtime foreground eligibility.

- `loft-android/build/check-receipts/initial-tun-x86-source-check.log`: SHA `6b6426893103a05668709b1392924b5e0f0b99272b8fff12c77ff85f42ef90aa`.
- `initial-tun-arm64-lint-check.log`: SHA `f9be70d986bcf4a9728f4349c24754c173686ac3e660cada98399587c918216e`.
- Current `app/build/reports/lint-results-release.xml`: SHA `fea030117f35c2a761adc489cff7202415dcf788ef193d8d6b3445d81773f556`.
- Frozen source/producer receipt `loft-android/build/check-receipts/android-source-freeze-initial-tun.json`: SHA `ac3c0ad192aea620a7013db868c42ae704bea75f745d76ebf1183ae3f8673acf`, source-inventory SHA `63481eac3c24e1340340962e12503ca3c66bff84d4ebfd6d9eb837b918e0f92a`. The owner reports all101 source/config and three production producer inputs match; the reviewer independently checked the scoped files/diffs, source/API pins, compiled call target and recorded result hashes.
- Rebuilt x86 app APK: 49619271 bytes, SHA `2a5b0d901bbee202cacfe30dbcdf52bdc3735d663cc25d05b3340a3245b588c0`; test APK: 920092 bytes, SHA `e9ca0dad99b3bcd38d2bf7a68812ebd7eb800638be7ac09ba123969ceb355c69`. Root reports these verified/installed and a private scan passed685 members. This reviewer has not inferred runtime success from packaging or that member count.

**Actual API29 non-VPN control evidence:** the approved `tmp/verification/android-api29-cancellation-sensitive.json` reports 6 tests passed in `API29_x86_64_TCG_injected_dispatch_and_CancellationSignal`. The reviewer verified its scan flag and exact log hash before reading the result. JSON SHA `13c59cd5c1f93a572bf270efba8c757b95e56703c395dd11b9aae1ed3ae61bed`; log SHA `c9cb545cc87aab0b9d1d22bd9d9ebed2fa144da7e07dee3913c78ec0214b7d09`; output `OK (6 tests)`, checked `2026-11-25T21:00:30.317158+00:00`. These two actual `CancellationSignal` and four injected-touch methods used the **earlier unchanged UI/fixture inputs**: app SHA `3d9658a0b78383f075118b9847b76e5a88552096f4f612c03c971c8ecd12290f`, test SHA `a96efb289f0e6c13470e106cfa61ab12a4ea22b71b0c819e0839fe1bbd0254fd`. They are not proof of the repaired TUN path, Compose/external-overlay/TalkBack acceptance, or handset performance.

---

**Searched / paths walked:**

- Both designated guides: `VpnService|TUN|Builder|权限|前台|通知|真实|socket|protect` resolved the platform bridge, minimal permissions, routing/empty-list, foreground lifetime and genuine Start/Stop receipt requirements. Full P0–P5 stages are not treated as completed.
- Product: `setUnderlyingNetworks|establishTun|prepare|startForegroundService|requestStop|go.runtime.start|markVpnReady`, manifest/AIDL and actual source/diff inspection. Initial TUN, permission, foreground, routing, protection, Ready/failure and Stop ownership callers were walked.
- Pinned AOSP API29: service/Builder setters, initial config delivery, established-owner predicate, consent and bind permission enforcement.
- Official FGS HTML, Android16 policy and actual lint detector bytecode: documented qualifying alternatives, runtime any-of semantics and the detector's two-alarm-only condition.
- Explicitly approved alias receipts/logs: scan flag→actual byte hash→bounded result output. No private input, prior reader-failure content, private logcat or node-bearing command artifact was inspected.

**Open questions / evidence limits at this checkpoint:**

- The repaired Pro TUN/literal-TLS/Stop result and X's real TUN adoption are now recorded below. X's full literal test still failed; a subsequent guest-clock/environment test is pending. The baseline failures remain intact.
- API34+ typed `systemExempted` foreground acceptance, normal-user permission UI completion, ARM64 runtime, physical handsets/Fold, Doze/Always-on/lockdown, battery/PSS/72-hour and full DNS/UDP/Gateway policy acceptance are unverified here.
- Literal-IP TLS uses a target resolved physically before VPN, and therefore cannot establish tunneled DNS. The separate no-cache VPN-network DNS test must have its own result.
- Default ARM64 compilation/lint and the completed Release/R8 build are build evidence. ARM64 runtime, signing/device acceptance and remaining actual-node/DNS work remain separate integrator responsibilities.

**Initial-TUN checkpoint source SHA-256 (inventory63481eac…):**

```text
LoftVpnService.kt baseline       7f8a24a486db75a3b5e1b57c46e98d5f1b9f2a1de618e57f5c23606f2010776c
LoftVpnService.kt repaired       a0d97841f98ae8a60cccc839c42436095aa9281aa5b7feb94c23dcd4c4b95bdb
AndroidManifest.xml baseline    694edd1fd5e9703c989a1aed5e777343441fc2cad73ab5d8fe0e48470d5f1e10
AndroidManifest.xml repaired    8ed4a7d3e79fd3c5b32bae395187aa31deaa207ac6cb75fc86c53becfc883979
AndroidVpnIntegrationTest old   5d8d09d4d25d702dc4fe90e44cdea65857721deeb7f2c2e2f532a49556759dcc
AndroidVpnIntegrationTest new   072e163f1d8082e231820d46170557c1d504312791a1dea7b619cd15d708c300
LoftRuntimeOwner.kt unchanged   434a117ef173f0e738736112e71fb2574cf40fc05aeaa883aa429726131b89f2
AndroidSocketProtector.kt       622ab0926d96731e4036650e7f733a4b8aceed02570041b5ea38450f26f17408
GoVpnSnapshot.kt                172ba6751b59a81417667c0c6ee76eaebb3d1ad29d1d36bc70ec559dd6017d84
OriginalTunOwnership.kt         ea2c6b7a5fea55c20d65ec369d17f737325af517b2a55e003970cd205b04153f
Rust loft-core/src/vpn.rs       737fab5b46a7a44cddfbe6fdbde9573844204cc05db8516f8613d703b008e983
Rust loft-ffi/src/lib.rs        ea27b7020d58a57d6143590ad73e3b3e08bbfef2767f01aa7746b5af0e3a1d48
Go engine/vpn.go                eed2c9e028556f822ae55351dbaf6c08913cae94b21cb4d2e5470c87d8b0a506
Go internal/vpn/runtime.go      92d0eb0125d6a4d44230f0192a3891938871bce91c529be7aae5be7d5ab2bec2
guide/guide.md                  14898b2d1c2a8cf531b2c9e74c0e1ec8ebbf653fcb67a01edb069572a1718999
guide/ui-design.md              7e6fa82d80f112b849698592ce5d61c75aede5b5d240edd23cf62fc35d0dd038
```

Service Kotlin paths are under `loft-android/app/src/main/kotlin/net/aptist/loft/service/`; the manifest is `app/src/main/AndroidManifest.xml`; instrumentation is `app/src/androidTest/kotlin/net/aptist/loft/service/`; foundation is `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/`; Rust crate references are under `loft-core-rust/crates/`; Go references under `loft-vpn-engine-go/`. Preserved pre-repair product sources are under `loft-android/build/initial-tun-review/baseline/`. This record contains requirement/source evidence; guide, tmp, caches, private material and compiled outputs remain excluded from delivery.

---

**Final re-review — actual repaired API29 evidence:**

**Verdict:** `implemented` · confidence: high. This is the implementation verdict for this one requirement, not a declaration that both VPN protocols, all DNS/routing modes or P5 are complete. The initial service-setter precondition is removed; compiled method selection and actual initial TUN adoption are verified. The configured-VPN lint suppression models an existing permitted platform path while preserving runtime permission checks.

The reviewer independently read the current repaired alias JSONs, verified `output_private_scan_passed=true`, compared the exact `.log` byte hashes, and only then read their bounded redacted results. The root independently confirmed both runs used installed app SHA `2a5b0d901bbee202cacfe30dbcdf52bdc3735d663cc25d05b3340a3245b588c0`, instrumentation SHA `e9ca0dad99b3bcd38d2bf7a68812ebd7eb800638be7ac09ba123969ceb355c69` and frozen source inventory `63481eac3c24e1340340962e12503ca3c66bff84d4ebfd6d9eb837b918e0f92a` (`android-source-freeze-initial-tun.json`). These are the initial-TUN APK inputs above, with matching frozen native AAR/Rust inputs. Later test-only engineKnown/inert diagnostics were not installed for these results and are not silently substituted as their source inputs.

| Repaired case | JSON SHA-256 | Verified log SHA-256 | Actual result |
| --- | --- | --- | --- |
| X literal | `6c96e1d5e5282fa042091b8b75839526148e3d5340dcb5e80d77f4d3b0fa903b` | `a9e8a48b150f2f73a29eb6a5a16d846c275f39c6d60b2240d7bdd87cd1a2b989` | `passed=false`; original TUN adopted, later Blocked/ENGINE_UNAVAILABLE, Connected/TLS not achieved |
| Pro literal | `3d53f48bd0d62db1fe347f99046c2c1d3ab4e7c9c3f376b80d0d7660de0c6ce5` | `b94aec4093339da673087c274fee4fdf0725204cd9b3820b4418f09535325f07` | `passed=true`; `OK (1 test)` for the actual Connected/literal TLS/Stop case |

The repaired X result was originally at `tmp/verification/android-node-x-literal.{json,log}` and is now preserved as `tmp/verification/android-node-x-literal-before-clock-sync.{json,log}`. Pro remains at `tmp/verification/android-node-pro-literal.{json,log}`. Both have scope `Android_API29_x86_64_TCG_scaled_clock`. A final read of the former current X path encountered `FileNotFoundError` after the root relocated it; the reviewer then verified both preserved/current scan flags and exact JSON/log hashes again. This artifact-location change is not an additional product test failure.

X's bounded trace contains the actual progression:

```text
receipt=NODE_IMPORTED
receipt=ROUTING_STAGED
state=CONNECTING,...,tun=false,ready=false,released=false,forwardingDisabled=false
receipt=VPN_STARTING
state=CONNECTING,...,tun=true,ready=false,released=false,forwardingDisabled=false
state=BLOCKED,failure=ENGINE_UNAVAILABLE,tun=true,ready=false,released=false,forwardingDisabled=true
```

`tun=true` comes from the actual original-descriptor owner after `service.establishTun` and `tun.adopt`, not a test-generated readiness value. This verifies the formerly unreachable initial TUN path ran on API29. It also preserves the safety boundary: the test did not turn failure into Connected or release a held drop scope. The full X case still reports 1 test/1 failure at the Connected wait (`AndroidVpnIntegrationTest.kt:L93,L244`). No X authentication, TLS, completed Stop or resolver result is claimed from that failed case. Root reported a measured 1639-second guest wall-clock skew against X's existing 30-second epoch/±1 gate and is correcting guest time for a subsequent environment test; that is a reported pending investigation, not a verified X fix or a relaxation of crypto/deadlines.

Pro's approved log records `realSelectedUidLiteralTlsTunAndStops`, status0 and `OK (1 test)`. Against the hash-pinned initial-TUN test source, the completed case asserts actual Connected/ready/held TUN, frozen applied packages and a VPN active network; sends an ordinary selected-UID literal-IP TLS HEAD request and requires HTTP200; then requires `CONTROL_STOPPED`, no held TUN, released owned resources and Rust `Disconnected`. These are executed Android resource/transport receipt checks, not synthetic Ready/Stopped fixtures. Its reported emulator time is3.949s and host elapsed70.086s; the scaled-clock TCG scope does not establish real-time or handset performance. The target was physically resolved before VPN, so the TLS pass is not tunneled DNS evidence.

**ARM64 build checkpoint:** Root reported the full ARM64 Release/R8/lint build exit0 in4m31s. The reviewer read its completed log `tmp/verification/android-arm64-final-release.log`, which records `minifyReleaseWithR8`, `packageRelease`, `assembleRelease` and `BUILD SUCCESSFUL`; log SHA `b1e3a8eb9f779d27204accda54dd01c852c35003ab666e0996632c2d03636738`. This adds actual Release/R8 build evidence to the separate default lint result above; it does not establish ARM64 execution, final signing/alignment/private scanning or physical-device acceptance.

**Evidence distinction:**

| Layer | Verified result / remaining limit |
| --- | --- |
| Specification/source/API | Old first-TUN precondition contradicted pinned API29; repaired Builder method is valid before establish; all scoped permission/protection/Stop checks preserved |
| Compiled code/lint | Actual x86 Builder call inspected;122 JVM tests passed; default ARM64 lint0 errors/31 warnings; Release/R8 build completed |
| Actual API29 initial TUN | X and Pro reached real original-TUN ownership after the patch |
| Actual API29 transport/Stop | Pro selected-UID literal TLS HTTP200 and matching Stop/Disconnected passed; X remains failed at a later boundary |
| Actual API34+ foreground type | Unverified; documented/AOSP configured-VPN eligibility is source evidence and runtime checks remain active |
| DNS/full protocol/routing matrix | Unverified in this requirement; separate resolver probes and broader protocol cases need their own results |
| ARM64/physical-device/P5 | Unverified; software x86 API execution and compilation do not establish handset/Fold/Doze/power/PSS/72-hour or release acceptance |

Why `implemented` rather than `partial` for this requirement: the specific initial-establishment misuse is eliminated and now observed working on the minimum API; the valid configured-VPN foreground declaration is independently supported by official documentation, runtime policy and detector analysis. X's later failure remains explicitly unresolved and does not erase observed initial TUN adoption. Missing API34+/handset/full-DNS evidence is not converted into a completion claim. No product source, native/crypto gate, permission or deadline was changed by this reviewer.

---

**Latest evidence addendum — 2026-11-25, guest wall-clock calibration:**

The later X literal case now **passes** after guest-only wall-clock alignment. The earlier X Blocked/failure observations above remain historical evidence. This reviewer independently checked the new approved scan flags, exact JSON/log byte hashes and completed instrumentation output:

| Later evidence | Receipt SHA-256 | Verified log SHA-256 | Result |
| --- | --- | --- | --- |
| `tmp/verification/android-node-x-literal.{json,log}` | `8dd0526f7c01e028d32e77372976dcd3fd67bbfa0f673eb9803f83c6f76bde15` | `8407fd569fefc53eb93ffa900fd771cfbb2c9582d3481bceb8447c5079fd4301` | `passed=true`, `OK (1 test)` for actual initial TUN, selected-UID literal TLS/HTTP200 and matching Stop/Disconnected |
| `tmp/verification/android-native-inert-api29.{json,log}` | `631ad17fb487f4f8059068ad9c183e081bfb3380e5d6764cc1295917c2fa6ffa` | `99fc267c5d40084fcf0b063d0665356f5031754734a5dc388f5e2eababaf6c5a` | `passed=true`, `OK (1 test)` for actual Go JNI/capability admission and inert construction/close; this method creates no TUN, network work or AppCore |

Both later runs use the same production app SHA `2a5b0d901bbee202cacfe30dbcdf52bdc3735d663cc25d05b3340a3245b588c0` and newer diagnostic test APK SHA `c13b700d443072e15829bbcc799a2d3394d50ed1951c48abf9bd71b32ca088c1`. Production/native inputs remain those of the initial-TUN app; only test diagnostics differ. The earlier Pro success (`b94aec409…`) used instrumentation `e9ca0dad…` and remains a separate pinned observation.

Associated `tmp/verification/android-clock-sync-x-literal.json`, SHA `2300b8160b73e962ae1f0ad6c11928345b95518a7ff08240b9ff78e623acc48b`, checked `2026-11-25T21:59:08.945774+00:00`, records15 guest date sets and15 successful `set_exit=0` samples, child exit0, host-aligned guest wall time and `application_gate_and_timeouts_unchanged=true`. Product service/manifest/owner/protector hashes were checked again and are unchanged. The emulator monotonic clock, application gates and deadlines were not relaxed. This calibration does not establish real-time latency, handset power or72-hour acceptance.

The requirement verdict remains **implemented**. The latest runtime evidence now includes X and Pro literal TUN/TLS/Stop success in their explicitly different API29 input/clock profiles. It does **not** establish VPN DNS: Root reports that all three user-approved resolver TCP/UDP pairs failed on both aliases (Go-verified record `a3e4babd…`), with user clarification pending. API34+ typed foreground execution, full DNS/protocol/routing acceptance and ARM64/physical-device/P5 evidence remain separate and unverified. No product source was changed by this addendum.
