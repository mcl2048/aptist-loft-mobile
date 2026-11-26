## REQ-UI-SENSITIVE-01 — Sensitive-screen capture, touch and lifecycle protection

> 敏感页面禁止截屏与最近任务预览、过滤被覆盖时的触摸、必要时拒绝在辅助功能干扰下展示敏感信息（按 API 级别启用相应平台能力）
> — Local `guide/guide.md` v3.6, “强制执行”, L551

> 敏感材料默认隐藏，领取链接来源先确认，核心安全失败不提供“跳过验证”。
> — Local `guide/guide.md`, “编辑与确认”, L791

> 确认面板使用可滚动字段区和固定 `48dp` 操作区，默认占用窗口约一半，内容长或字体放大时可扩至全高。屏幕保护范围覆盖含敏感凭据的导入/详情，预览图不绘制真实二维码、Token 或私钥。
> — Local `guide/ui-design.md`, “扫码、链接导入与确认”, L243

> IME、系统栏与手势 Insets 由 Compose/平台处理；敏感弹层下禁止误触背景，退出后恢复合理焦点。
> — Local `guide/ui-design.md`, “无障碍与不同窗口”, L332

> 按实机验证截图、无障碍、后台订阅/相机/邮件释放、UI+VPN并发与资源预算，记录与设计参考的有意差异。
> — Local `guide/ui-design.md`, “给 Codex Sol Max 的实现顺序”, L362, item 8

**Verdict:** partial · confidence: high for the implementation trace and the identified evidence boundary.

The framework implements protected import/account windows, masked import material and whole-gesture obscuration admission. Fresh compiled JVM tests pass. The guide's actual-device capture, recents, overlay and accessibility acceptance remains unverified. No confirmed source contradiction was found on the walked paths. The current framework has no real login, mailbox, credential reveal/export or Shield interference policy; those capabilities are not certified by this requirement review (`docs/contracts/framework.md:L61-L63`).

Review scope is this one requirement in task `loftmobile-1125-01`, not the complete P0–P5 product. The Android owner declared production/source API freeze after the final source-check command below; reviewed source and class pins remained unchanged when checked at 2026-11-25T19:00Z. The private task and node test files were not review inputs. Final native packaging/APK/device acceptance belongs to the integrator and remains separate from this source check.

---

**What this demands of an implementation:** apply capture protection before sensitive content can be shown; retain it while that content can become a recent-task preview; reject fully and partially obscured sensitive gestures, including clean UP after a rejected DOWN and obscuration after an admitted DOWN; cancel an already pressed control safely. Keep clean input and legitimate accessibility actions usable within the platform's capabilities. Sensitive modal input must not reach the background, and keyboard/focus/recreation handling must preserve controlled in-memory drafts. These code properties and their real Android/device effects need distinct evidence. The memory rule is explicit in `guide/guide.md:L810` and `guide/ui-design.md:L59`; actual-device acceptance is explicit in `guide/guide.md:L795,L812` and `guide/ui-design.md:L362,L368`.

**Where enforcement lives:**

```kotlin
// loft-android/app/src/main/kotlin/net/aptist/loft/MainActivity.kt:L84-L97
val sensitive = page == Page.IMPORT_NODE || page == Page.ACCOUNT
// ...
val protectInput = sensitivePage && windowActive
touchGate.setSensitive(protectInput)
window.decorView.filterTouchesWhenObscured = protectInput
if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(protectInput)
if (sensitivePage) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
```

- `MainActivity.kt:L44` disables descendant autofill. Its `onCreate` reads the retained ViewModel's current page before `setContent` (`L45-L60`); `LoftApp.kt:L54-L58` follows actual lifecycle-collected navigation state and calls `setSensitivePage` after each committed composition. `onStart` reapplies the page and input/window policy (`MainActivity.kt:L63-L68`).
- `onStop` turns off active input/overlay suppression while leaving `sensitivePage` set, so `FLAG_SECURE` remains requested for a sensitive background window (`MainActivity.kt:L70-L97`). Page leave clears the flag. `onDestroy` clears the old activity's scope/flags and resets the gate (`L76-L81`); its effect on an actual transition/task snapshot is not device-tested here.
- API 29/30 receives `FLAG_SECURE`, decor filtering and the explicit full/partial gesture gate. API 31+ additionally calls `setHideOverlayWindows`; the required permission is present in `app/src/main/AndroidManifest.xml:L8`. The branch is API-guarded (`MainActivity.kt:L94`). These calls are not evidence that every OS/OEM/trusted overlay is detected or hidden.
- `ObscuredTouchGate.kt:L17-L38` checks `flags & (1 | 2)`, corresponding to the public full/partial Android obscuration flags. A rejected DOWN consumes the rest through UP/CANCEL. A clean admitted DOWN followed by an obscured event returns `CANCEL_AND_CONSUME`; subsequent events are consumed until termination. A new clean gesture is admitted. Nonsensitive scope returns PASS; changes of scope reset admission (`L11-L15,L18`).
- `MainActivity.kt:L99-L112` delegates PASS to the actual superclass dispatcher, consumes rejected input, and constructs a new public `MotionEvent.ACTION_CANCEL` with the original pointer properties/coordinates and zero obscuration flags before sending it to the superclass. Clearing the flags is material: otherwise decor's own filtering could prevent the pressed target from receiving cancellation. The cancellation is recycled in `finally`.
- The import field is password-transformed, uses a password keyboard and disables autocorrection (`LoftApp.kt:L242-L246`). Clipboard reading is a button-triggered operation (`L247-L248`; `LoftViewModel.kt:L158-L161`), not a listener. Raw text lives in the retained ViewModel (`LoftViewModel.kt:L28-L58,L69-L72`), is cleared after a matching successful import receipt (`L356-L366`), on explicit discard (`L121-L126`) and on ViewModel disposal (`L388-L392`). Only locale/theme enter preferences (`L60-L65`). No application `rememberSaveable`, `SavedStateHandle` or `onSaveInstanceState` raw-input path was found.
- The account page is conservatively protected, but its current content is anonymous state and a server candidate, with dependency information for login/mail (`LoftApp.kt:L256-L271,L467-L474`). It contains no implemented user credential/token screen. `NODE_DETAILS` is outside sensitive scope because its current fields are redacted metadata and a material-presence Boolean (`LoftApp.kt:L361-L377`), not a credential reveal. `NodeSummary` has no raw credential fields (`loft-core-rust/crates/loft-core/src/lib.rs:L85-L94`); `NodeCandidate.summary` constructs that metadata (`loft-core-rust/crates/loft-core/src/import.rs:L338-L358`); `Endpoint.display` emits only host/port (`loft-core-rust/crates/loft-core/src/origin.rs:L46-L54,L134-L140`); FFI mapping preserves those fields (`loft-core-rust/crates/loft-ffi/src/lib.rs:L397-L407`). Adding a real reveal/export/detail path requires extending scope and acceptance tests.

**Paths walked:**

1. Import/account entry: `LoftApp` rail/header/welcome/node actions (`L140-L142,L169-L177,L192-L194,L229,L326`) → `LoftViewModel.navigate` (`L101-L104`) → `NavigationState.navigate` (`Navigation.kt:L21-L24`) → `changeNavigation` (`LoftViewModel.kt:L138-L149`) → lifecycle-collected `LoftApp` state → `SideEffect` → `MainActivity.setSensitivePage/applySensitiveWindow`. A dirty draft retains the original page and records only a pending destination; it therefore retains the sensitive scope until discard/actual page change (`Navigation.kt:L23,L32-L33`).
2. Recreation/background: retained ViewModel → pre-content `onCreate` page selection → `onStart` active filtering → `onStop` secure background scope → recreation reads the retained page again. Process restart creates the default welcome state and has no ordinary raw draft restoration (`Navigation.kt:L16`; `LoftViewModel.kt:L28-L35,L69-L72`). These are code paths, not physical-device rotation/recents receipts.
3. Import completion/leave: masked input → bounded `setImportText` (`LoftViewModel.kt:L152-L156`) → review/confirm (`L163-L165`) → one pending `submit` (`L331-L344`) → matching request receipt (`L356-L366`) → cleared raw draft and `Page.NODES` → capture/input scope clears. Failure retains the draft on the protected page. Back first hides the IME in the system `BackHandler` (`LoftApp.kt:L59-L62`); `LoftViewModel.back` closes confirmation/menu/pending-discard state before ordinary leave (`L111-L119`; `Navigation.kt:L26-L30`). Toolbar back calls `model.back` directly (`LoftApp.kt:L171-L173`); toolbar/IME interaction remains part of actual UI acceptance.
4. Obscured DOWN → gate CONSUME → clean MOVE/UP remains consumed → no target DOWN/click. Clean DOWN → actual superclass dispatcher → full or partial obscured MOVE/UP → one clean CANCEL to the superclass → rejected remainder consumed → next clean DOWN/UP passes. All return branches of the gate and dispatcher were read and the current gate bytecode was inspected.
5. Pending discard: `pendingPage != null` → background `clearAndSetSemantics` (`LoftApp.kt:L83-L84`) → full-size absorbing overlay and modal pane (`L97,L522-L534`). This is Compose content in the same protected activity window. Keep/discard callbacks retain or clear the draft (`LoftViewModel.kt:L121-L130`). No explicit focus handoff/restoration is implemented; actual Compose/IME focus behavior is unverified, rather than a confirmed leak.
6. Clean interaction: PASS reaches superclass dispatch; normal pages remove filtering. Existing Compose fields/buttons retain their ordinary semantic roles and localized labels (`LoftApp.kt:L158,L242-L246,L553-L558`). No global accessibility shutdown is called. A risk-conditioned Shield refusal under accessibility interference is not implemented; the current import stays visually masked and login material is unavailable. Legitimate TalkBack and interference/degradation cases need platform evidence.

**Searched:** all commands below ran from `/home/coder/LOFT-mobile`; counts are matching source lines.

| Search | Scope | Result |
| --- | --- | --- |
| `rg -n 'setSensitivePage'` | `loft-android/app/src/main/kotlin` | 4: definition, `onCreate`, `onStart`, and `LoftApp.SideEffect`; all walked |
| `rg -n 'FLAG_SECURE\|filterTouchesWhenObscured\|setHideOverlayWindows\|HIDE_OVERLAY_WINDOWS'` | `loft-android/app/src/main` | 5: permission and the window set/clear/input calls; all walked |
| `rg -n 'FocusRequester\|requestFocus\|LocalFocusManager\|AccessibilityManager\|TYPE_ACCESSIBILITY_OVERLAY\|setAccessibilityDataSensitive\|AccessibilityService'` | app and ui-foundation production Kotlin | 0; no explicit interference policy or modal focus restoration found |
| `rg -n 'rememberSaveable\|SavedStateHandle\|onSaveInstanceState'` | app production Kotlin | 0; retained ViewModel and appearance-only preferences were read directly |
| `rg -n 'TYPE_APPLICATION_OVERLAY\|TYPE_ACCESSIBILITY_OVERLAY\|canDrawOverlays\|takeScreenshot\|screencap\|setHideOverlayWindows'` | app Android/JVM tests and foundation tests | 0; no genuine overlay/capture acceptance fixture in these test sources |

The absence searches are confined to this requirement and the named source trees. They do not assert absence of integrator-owned external test scripts or future platform facilities.

---

**Verification executed by this reviewer:** JDK `21.0.13.1+2-1-deb13u1-Debian`, Kotlin stdlib `2.3.21`, JUnit `4.13.2`, Hamcrest `1.3`. The following read-only run used the already compiled current foundation classes and completed with exit 0, `OK (14 tests)`, 0.116 seconds of JUnit execution:

```bash
LOFT_REVIEW_TEST_CP='/home/coder/LOFT-mobile/loft-android/ui-foundation/build/classes/kotlin/main:/home/coder/LOFT-mobile/loft-android/ui-foundation/build/classes/kotlin/test:/home/coder/.gradle/caches/modules-2/files-2.1/junit/junit/4.13.2/8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12/junit-4.13.2.jar:/home/coder/.gradle/caches/modules-2/files-2.1/org.hamcrest/hamcrest-core/1.3/42a25dc3219429f0e5d060061f71acb49bf010a0/hamcrest-core-1.3.jar:/home/coder/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.3.21/a2ee2c4e220fee522f0451b723bab2a43f3481a7/kotlin-stdlib-2.3.21.jar'
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx64m -cp "$LOFT_REVIEW_TEST_CP" org.junit.runner.JUnitCore net.aptist.loft.foundation.ObscuredTouchGateTest net.aptist.loft.foundation.NavigationTest
```

`ObscuredTouchGateTest.kt:L22-L54` contributes seven logical gesture tests; `NavigationTest.kt:L8-L56` contributes seven navigation tests, including explicit discard/keep and menu/back ordering. The gesture suite's simulated pressed/click target is a JVM model (`ObscuredTouchGateTest.kt:L7-L20`), not an Android control.

Compiled branches were also inspected with these read-only commands, each exit 0:

```bash
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -version
/usr/lib/jvm/java-21-openjdk-amd64/bin/javap -c -p -classpath loft-android/ui-foundation/build/classes/kotlin/main net.aptist.loft.foundation.ObscuredTouchGate
/usr/lib/jvm/java-21-openjdk-amd64/bin/javap -c -p -classpath loft-android/app/build/tmp/kotlin-classes/debug net.aptist.loft.MainActivity
```

The current MainActivity bytecode contains the IMPORT_NODE/ACCOUNT scope, SDK >=31 branch, secure flag 8192, gate dispatch and a flags-zero `MotionEvent.obtain` CANCEL followed by actual superclass dispatch. Bytecode inspection proves compiled wiring, not execution of Android/window APIs.

The Android owner executed the following final integrated source-check command; this reviewer read its complete raw log at `loft-android/build/check-receipts/full-android-source-check.log`:

```bash
ANDROID_HOME=/home/coder/.local/share/loft-mobile/android-sdk python3 scripts/run_gradle.py -p loft-android :app:testDebugUnitTest :ui-foundation:test :app:compileDebugAndroidTestKotlin --no-daemon --max-workers=1 -Dorg.gradle.jvmargs=-Xmx1536m -Pkotlin.compiler.execution.strategy=in-process
```

The owner reported exit 0; the inspected log records `BUILD SUCCESSFUL in 1m 19s`, production Kotlin compilation, app JVM tests and instrumentation Kotlin compilation. Direct XML inspection totals 31 app tests with zero failures/errors/skips at 2026-11-25T18:56:40–41Z and 84 foundation tests with zero failures/errors/skips at 18:43:27–28Z. The foundation Gradle task was `UP-TO-DATE` in this final invocation; this review's fresh 14-test run is the current gate/navigation runtime receipt. The four sensitive-window instrumentation methods compile, along with the other Android instrumentation source, but the log contains no instrumentation execution. MainActivity and SensitiveTouchIntegrationTest compiled class hashes remained unchanged. This reviewer did not rerun Gradle or claim APK/native packaging/device acceptance from this command. The SDK XML-version warning in the log did not fail the build.

The owner's manual post-patch evidence at `loft-android/build/post-patch-validation/android-boundaries/report.md` and `result.json` records reached baseline failures/patched passes for full/partial DOWN and MOVE variants, plus unchanged benign/control output. Its MainActivity/LoftApp/gate/test source pins match this review. Its earlier compiled gate/test hashes differ from the current full-Gradle outputs; each receipt retains its own binary identity. That report labels itself `incomplete` and explicitly leaves Android/device execution pending. This reviewer inspected the record and freshly ran the current suites, but did not re-execute its baseline campaign or the official Git/worktree runner.

| Evidence level | Actual status at this review |
| --- | --- |
| JVM gate and navigation behavior | Fresh 14-test compiled run passed |
| Compiled Activity/window dispatch wiring | Current bytecode inspected; no Android execution in this review |
| Android Activity/decor dispatch fixture | Four tests in `SensitiveTouchIntegrationTest.kt:L36-L124`; compiled fixture, execution pending |
| Actual Compose controls | Fixture replaces Compose via `setContentView(ClickTarget)` (`L128-L134`); unverified |
| Actual Android full/partial flags | Fixture manufactures flags and directly calls `activity.dispatchTouchEvent` (`L137-L147`); genuine external overlay evidence pending |
| API 29/30 | Gate and secure-window code present; actual dispatch/capture/recents acceptance pending |
| API 31+ | Permission and guarded hide-overlay call present; actual hide-overlay behavior pending |
| Screenshot/recording/recent-task disclosure | Secure flag asserted only in the unexecuted lifecycle fixture (`L102-L124,L149`); no capture/preview test executed |
| Accessibility | Unexecuted native Button `ACTION_CLICK` check (`L77-L99`); Compose TalkBack, keyboard and modal focus/interference acceptance pending |
| ARM64 Pixel/Samsung/Fold and production acceptance | No evidence produced by this review; guide acceptance remains open |

The instrumentation fixtures call `setSensitivePage` directly. Even the lifecycle test pairs ViewModel navigation with that manual setter (`SensitiveTouchIntegrationTest.kt:L105-L106,L120-L121`). Their eventual pass would therefore establish explicit Activity scope behavior, rather than independently prove that real Compose navigation invokes the `LoftApp.SideEffect` scope caller. That caller was traced in source; actual Compose navigation belongs in remaining acceptance.

---

**How the verdict was reached:** this is partial against the complete quoted requirement because the implementation foundations exist but the specification's actual screenshot/accessibility acceptance has not been established. The source trace does not warrant an `absent` verdict, and no reproduced behavioral contradiction warrants `contradicted`. The missing platform evidence is an acceptance gap, not an inferred vulnerability. Full Shield policy/degradation and future real credential screens remain outside the delivered framework and cannot inherit certification from this logical gate.

**Source and receipt identities:** SHA-256, source/class pins captured 2026-11-25T18:55:34Z and rechecked unchanged after source freeze at 19:00Z; final source-check log inspected and hashed after freeze. Paths are relative to `/home/coder/LOFT-mobile`; guide inputs are local excluded design documents.

| Path | SHA-256 |
| --- | --- |
| `guide/guide.md` | `14898b2d1c2a8cf531b2c9e74c0e1ec8ebbf653fcb67a01edb069572a1718999` |
| `guide/ui-design.md` | `7e6fa82d80f112b849698592ce5d61c75aede5b5d240edd23cf62fc35d0dd038` |
| `loft-android/app/src/main/AndroidManifest.xml` | `694edd1fd5e9703c989a1aed5e777343441fc2cad73ab5d8fe0e48470d5f1e10` |
| `loft-android/app/src/main/kotlin/net/aptist/loft/MainActivity.kt` | `90378b3d86b172ba9d8d093bb13e8c6659dd09aaff7e8581f676d51ffd8f5554` |
| `loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftApp.kt` | `3472bf799e90f08ab49e451d8137a4d23806cefc640f3b6b66fd8981fb15af25` |
| `loft-android/app/src/main/kotlin/net/aptist/loft/ui/LoftViewModel.kt` | `963a3d94aa6c60a5304758f454f28e284a42735d9b705955d765cdbc2f0cb19d` |
| `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/ObscuredTouchGate.kt` | `63d05a974a61a3a4afe5e9d37266238b47fc892b8d291176dfb0f60305ccc706` |
| `loft-android/ui-foundation/src/main/kotlin/net/aptist/loft/foundation/Navigation.kt` | `290e91ef5ffaffcfce2fe95e088c7417305be7f661277d50ba2d8f6d0cda0a93` |
| `loft-android/ui-foundation/src/test/kotlin/net/aptist/loft/foundation/ObscuredTouchGateTest.kt` | `74b47d7040ab3ec1d858078b9070c1751e8fa20e0b5c7715400d5a0b413a9cd6` |
| `loft-android/ui-foundation/src/test/kotlin/net/aptist/loft/foundation/NavigationTest.kt` | `42c10a851f702f5809663d13d6d8dfcfa5ea58980b3366e024bbcb4c832a4219` |
| `loft-android/app/src/androidTest/kotlin/net/aptist/loft/SensitiveTouchIntegrationTest.kt` | `f130c4e4f943d655fa3e3022b75f9be21e421560f25e94699dbe9eb0a959e5e8` |
| `loft-core-rust/crates/loft-core/src/import.rs` | `ad1ca1f44f6b9e36703012061916e5295f261643f694c94ff189552d707603d5` |
| `loft-core-rust/crates/loft-core/src/origin.rs` | `e947eaa35f9a9b8c79bc38e40283f5830e7276e9538a5bc7e80bb57df266f2f8` |
| `loft-core-rust/crates/loft-core/src/lib.rs` | `dd7076dfea9a4887be840ba327cf28c874854943e46dfd722d9d5cbed1443fc1` |
| `loft-core-rust/crates/loft-ffi/src/lib.rs` | `ea27b7020d58a57d6143590ad73e3b3e08bbfef2767f01aa7746b5af0e3a1d48` |
| `loft-android/ui-foundation/build/classes/kotlin/main/net/aptist/loft/foundation/ObscuredTouchGate.class` | `51697c8c914b27238f81ba1d5fbb0ff501b1e6c75eb1bf874318bc597964383d` |
| `loft-android/ui-foundation/build/classes/kotlin/test/net/aptist/loft/foundation/ObscuredTouchGateTest.class` | `f8cd0c3a7d6e386cdeb76bdff933de5443eb82563b0cb6d15708f512181372e4` |
| `loft-android/ui-foundation/build/classes/kotlin/main/net/aptist/loft/foundation/NavigationState.class` | `71367753a88abca454c691c6fdd466fb6ce629111c597312ef6faac54eb2ba30` |
| `loft-android/ui-foundation/build/classes/kotlin/test/net/aptist/loft/foundation/NavigationTest.class` | `cc257aafec8c42a74e35432e055cd6ce46f155903243fe2c69b93bed1f00b503` |
| `loft-android/app/build/tmp/kotlin-classes/debug/net/aptist/loft/MainActivity.class` | `e6fb193245e78c42662715af97fee58fa6a41eca60115cd260d4f5225e0fca1d` |
| `loft-android/app/build/tmp/kotlin-classes/debugAndroidTest/net/aptist/loft/SensitiveTouchIntegrationTest.class` | `fea456eb36c879f365a3cc788ccfb5980d706b6266d34c06fbae78883baf15f0` |
| `loft-android/build/post-patch-validation/android-boundaries/report.md` | `6fbc8e8252d75d94fe36f4fe1438b0bc22ebc19bc017262139dc3400c2b85690` |
| `loft-android/build/post-patch-validation/android-boundaries/result.json` | `de58a1d2cb7f7dff90c7754d5f79a195f05506450393dee2bfb1b4ef717906ec` |
| `loft-android/build/check-receipts/full-android-source-check.log` | `4cb3cc05d1139d4dd5ffde55ba9818e98f103897eb4515a4509596d7bf1548db` |

**Open questions / remaining acceptance:**

- Associate subsequent Android capture/gesture observations with the integrator's final paired native libraries and exact APK; the verified source-check log is not an APK or device receipt.
- Execute the Android dispatcher/lifecycle fixture on API29 and API31+; keep injected flag evidence separate from real external full/partial overlay tests. Include a clean gesture after cancellation and normal nonsensitive interaction.
- Observe actual sensitive-window screenshots/recording/task previews across entry, Home/background, rotation/theme/locale recreation, page leave and window destruction. Use synthetic credentials and associate observations with the exact APK/device/API.
- Verify actual Compose import/account controls, TalkBack, password semantics, clean touch, keyboard navigation, toolbar/system Back, modal background absorption and focus restoration, including large font/Fold scenarios.
- Define and implement the necessary Shield interference/refusal policy before real sensitive reveal/export/login paths exist. Available Android signals are not a universal assurance that accessibility or trusted overlays cannot interfere.

