# LOFT mobile · 0.1.7-LYNX

LOFT is a native Android application framework with Rust-owned business state and source-pinned Go VPN adapters. Task `loftmobile-1125-01` builds the foundation against local `guide/guide.md` v3.6 and `guide/ui-design.md`. The complete P0–P5 product roadmap has separate implementation and device gates.

Task `loftmobile-1128-02` adds Application protection for the TOTP vault and Secure Notes. Secure Notes supports local encrypted editing, Markdown with source visibility on the current line, search, tags, archive and deletion. The editor shares the existing hinge-safe layout and retains its draft across window resizing. A verified Hub profile and a paired device key enable optional background sync. Existing anonymous notes remain local. [Secure Notes contract](docs/contracts/secure-notes.md) · [Task report](report/loftmobile-1128-02-progress.md)

The signed 0.1.7-LYNX ARM64 Release is `bin/loft.apk`, versionCode 8, SHA-256 `8f557b12f015b3c408df10018cf87228e254291029459e56521db916d69bcb17`. The APK carries the LOFT development certificate. The existing Hub serves Notes API v1. [APK verification](docs/validation/apk-0.1.7-release.json) · [Build evidence](docs/validation/build-0.1.7.json) · [Live Hub](https://aptist-loft-hub.pages.dev)

Task `loftmobile-1128-01` adds a native overview with account, VPN and app traffic status, a direct VPN node directory, and a shared bottom shield. It also reduces HyrakenX UDP buffer usage and updates the mobile transport inputs to Gateway 8.0.36. [Task report](report/loftmobile-1128-01-progress.md)

The 0.1.6-LYNX ARM64 Release used versionCode 7 and SHA256 `374460971ef192a0841f40a2bc28b2fad2d4a255b2439369c907e6ddf180cb53`. It used the LOFT development signing certificate. [APK receipt](docs/validation/apk-0.1.6-release.json) · [Build receipt](docs/validation/build-0.1.6.json)

Task `loftmobile-1126-02` adds durable Hub login, a native offline TOTP and password vault, and the Gateway 8.0.34 transport refresh. The vault supports camera or manual TOTP import, editing, archive and restore, and explicit encrypted sync. It stays usable after signing out. Hub uses the original Portal grant for mail, so expired mail access requests consent independently. [Vault contract](docs/contracts/vault.md) · [Hub contract](docs/contracts/hub.md) · [Task report](report/loftmobile-1126-02-progress.md)

Task `loftmobile-1126-01` adds LOFT Hub. A Cloudflare Pages endpoint forwards to a Rust Worker, which verifies Portal OAuth and holds short-lived encrypted authorization state in D1. In Android, enter a Hub HTTPS origin as the server address candidate, verify and activate it, then use the system browser to sign in to Portal. Explicit mail consent enables read-only inbox, trash, message and attachment access for the signed-in account. [Hub contract](docs/contracts/hub.md) · [Linux installer](hub-install/Readme.md) · [Task report](report/loftmobile-1126-01-progress.md)

The first deployment is [aptist-loft-hub.pages.dev](https://aptist-loft-hub.pages.dev). The 0.1.4 ARM64 Release used versionCode `5`, SHA256 `8b62eb2ae82c218cee91fe7c335c17d66b08d3afb126d210c1e48c1ace06fc18`. It uses the local development certificate and passed 83 APP and 117 foundation JVM tests, APK signature, native alignment and the index/artifact secret scan. [Build evidence](docs/validation/build-0.1.4.json) · [Exact APK verification](docs/validation/apk-0.1.4-release.json)

The preceding 0.1.5-LYNX ARM64 Release used versionCode 6, SHA256 `84d722ef75d875c7f244798af1b61b9090493102df68c78b8f895bca67d1c45b`. The exact file uses LOFT’s local development certificate and passed signature, alignment and credential verification. [APK receipt](docs/validation/apk-0.1.5-release.json) · [Build receipt](docs/validation/build-0.1.5.json)

Task `loftmobile-1125-02` adds the icon-only native module rail and encrypted guest persistence. The rail retains localized accessibility names, selected state and the full module titles in secondary navigation. The guest store retains complete imported SOCKS5, HyrakenX and Hyraken Pro configuration, including credentials, certificates and protocol parameters. Saved routing, privacy and server drafts also survive restart. An Android Keystore key wraps the SQLCipher database key. [Storage contract](docs/contracts/encrypted-storage.md) · [Current task report](report/loftmobile-1125-02-progress.md)

The 0.1.3 signed ARM64 Release used versionCode `4` and the local development certificate from 0.1.2. That build passed 79 APP and 117 foundation JVM tests. API 29 covered force-stop restoration and accessibility on the paired x86 Debug app, plus guest startup on the minified x86 Release. [0.1.3 APK verification](docs/validation/apk-0.1.3-release.json) · [0.1.3 build evidence](docs/validation/build-0.1.3.json) · [0.1.3 runtime](docs/validation/android-0.1.3-runtime.json)

The private `:vpn` process owns one Rust core, the Android TUN and the lazy Go runtime. Compose displays immutable receipts; closing the UI, changing language/theme or resizing a Fold window does not own the VPN lifetime. Guest startup is local and has no Portal or cloud dependency.

| Available foundation | Actual boundary |
| --- | --- |
| Strict SOCKS5/X/Pro link parsing | Atomic, bounded imports; certificate/name/pin/key checks; redacted metadata; credentials stay encrypted across restarts |
| Complete bounded node directory | 200 nodes exposed in 50-row generation-bound pages; stable selection across pages |
| Rust VPN state and private IPC | Frozen startup scope, one-use credential delivery, actual routing/privacy/closure receipts; priority Stop and stale-callback fences |
| Source-pinned IPv4 VPN adapter | gVisor TUN, protected/bound physical sockets, TCP/UDP admission and ownership; real authentication and host packet tests |
| App routing foundation | Exact PackageManager-reported UID/package Builder scope; empty/lockdown conflict rejection, drafts separate from applied routing; hidden-package/device scope remains unverified |
| Shared network privacy | Node-domain Fake-IP, original FQDN restoration, current-client DNS/RTC proof, IPv6 rejection and bounded passive TTL/lease recovery |
| Native UI | Persistent icon-only module rail, four locales, themes, window/hinge/tabletop layouts and retained presentation drafts |
| Optional Portal account and mail | Origin verification and confirmation, system-browser OAuth, explicit `mail.read` and own-user mailbox operations |
| Shield | Reports the capability boundary for software checks and attestation |
| Notification foundation | Real VPN foreground lease, native icon and priority Stop; actual permission/channel reporting; default-denied mail event boundary |
| Release foundation | Fixed tools, generated native bindings, architecture/source/secret guards, R8/lint/native/signature checks and validation records |

Default DNS uses `198.18.0.2` inside the VPN to return bounded synthetic routing aliases. The shared engine restores the original hostname before the selected proxy opens the connection; a Fake-IP answer is not a public resolver answer. The 0.1.2 API29 test APK passed uncached VPN DNS→alias→original-hostname certificate/TLS/HTTP200→Stop on both private X/Pro nodes. Explicit `wire_tcp` mode instead needs a permitted literal IPv4 resolver and never falls back to physical business DNS. Historical public TCP/UDP53 failures belong to that forwarding-probe path and do not establish a broken node DNS subsystem or a current default-mode failure.

DNS and recognized WebRTC traffic use shared `proxy_only`/`block` rules before all transport adapters, with exact policy epoch, owner/shared-UID scope and current TUN/client proof. Stop, loss and Abort revoke enforcement claims. Packet filtering cannot promise to hide browser SDP address enumeration or cover APPs deliberately outside the selected VPN scope. Hydra uses the existing X/Pro shaping hooks independently and defaults to Disabled; QUBF transports remain future adapters.

The added-memory ledger is 8 MiB, including a fixed 528 KiB non-domain address quarantine reservation; dynamic capacity is 7,847,936 bytes. Mappings are limited to 256 entries/256 KiB and retain identity through live I/O and advertised TTL. Passive recovery needs no periodic restart or extra polling. These allocation limits do not establish handset PSS or battery performance.

QR, the 512 KiB Android FD-import path, live TUN replacement, automatic reconnect, Shield/attestation and Gateway policy integration remain roadmap items. Portal confidential OAuth keeps the administrator client secret and upstream user bearer in the Worker. The APP confirms compatibility over HTTPS and stores a durable Hub-only session after user consent. Portal mail access retains its own short deadline.

Portal `notifyUnread` writes a database marker, not a mobile event. Real new-mail push still needs a successful-publication event source, Rust subscription authority and an actual configured provider. The framework does not poll mail or initialize an unconfigured push service. API29 passed actual Blocked/Connected foreground notifications, four-language text, hidden-UI continuity and notification PendingIntent Stop/removal; API33+ denial, status-bar rendering and physical background survival remain separate acceptance.

## Build and development

Read [AGENTS.md](AGENTS.md), the [framework contract](docs/contracts/framework.md), [resource contract](docs/contracts/resources.md) and [build procedure](docs/build.md). The portable `aptist-loft` skill is in [docs/aptist-loft](docs/aptist-loft/SKILL.md); its installed server copy is `/home/coder/.codex/skills/aptist-loft`.

The task-local design files are `/home/coder/LOFT-mobile/guide/guide.md` and `/home/coder/LOFT-mobile/guide/ui-design.md`. Git delivery excludes guide, Prompt, tmp, local keys, caches and compiled artifacts. The local canonical APK is a separate delivery at `bin/loft.apk`. A clean clone uses the owned protocol snapshot and source manifest; it does not need either upstream checkout.

`toolchain-lock.json` pins Rust1.100.0, Go1.27.4, JDK21, Gradle8.13, AGP8.13.2, Kotlin2.3.21, Compose2026.03.01, WindowManager1.5.1, SDK36/build-tools36 and NDK28.2.13676358. Minimum Android is29; production ABI is ARM64 with16 KiB native alignment.

```bash
source scripts/env.sh
python3 -m unittest discover -s tests -v
python3 scripts/verify_architecture.py
cargo test --manifest-path loft-core-rust/Cargo.toml --workspace --locked
bash scripts/build-native.sh
bash scripts/build-android.sh
```

Native builds require `with_gvisor` and matching UniFFI/library inputs. The Gradle Release APK is unsigned; development signing uses a local ignored key after build checks. Final acceptance verifies the exact signed `bin/loft.apk` with native alignment, signature/version/manifest and index/artifact secret checks. A labelled x86_64 profile exists only for server emulator tests, with separate generated/native/build outputs. It does not add a production ABI or establish ARM64/Fold/Doze/battery acceptance.

## Source and verification

The linked Gateway adapter is pinned to 8.0.36-LYNX at `a984911c8aa0e932c885bb298134031432eb82b7`; Portal2.2.0-PUMA review input is `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36`. Both are read-only source inputs. The owned Go snapshot preserves the existing X/Pro authentication and payload boundaries: X1–1024-byte application UDP; Pro0–65,507, including empty packets. Pro's66,023-byte XUDP envelope is not application payload. Ordinary SOCKS5 has no tunnel encryption.

[Requirements and remaining acceptance](docs/requirements.md), [task progress](report/loftmobile-1125-01-progress.md), [trust boundaries](docs/threat-model/framework.md) and [privacy](docs/privacy/framework.md) distinguish host, Android and physical-device results. The repaired node-directory finding retains its [original and post-fix evidence](docs/validation/spec-compliance/requirements/REQ-NODE-01.md).

The preceding 0.1.2-LYNX release has its own source and artifact records.

| Executed check | Receipt and scope |
| --- | --- |
| Rust workspace | [93 tests, fmt and Clippy](docs/validation/rust-0.1.2-checks.json), exit0; all36 frozen source identities matched |
| Rust dependencies | [cargo-audit](docs/validation/rust-0.1.2-audit.json):0 known vulnerabilities across137 locked dependencies; one host-only `basic-toml` maintenance notice |
| Go shared data path | [Root normal/race](docs/validation/go-0.1.2-checks.json):114 top-level/145 subtests per run,0 failures/races; all499 frozen identities matched; owner no-tag/vet/module/lint/govulncheck receipts retained |
| Paired native inputs | [ARM64 and x86](docs/validation/native-0.1.2-builds.json), identical generated Kotlin; ARM64 Rust/Go ELF16KiB checks passed |
| Latest Android input | [130-file source identity](docs/validation/android-0.1.2-post-pending-source.json) and [matching x86 build](docs/validation/android-0.1.2-post-pending-x86-build.json):78 APP JVM tests passed; compile evidence is distinct from API execution |
| Latest Android execution | [Current matching APK](docs/validation/android-0.1.2-runtime.json):8 tests/0 failures; prior native/cancellation/sensitive7 are labelled separately and were not rerun on this APK |
| ARM64 Release build | [Canonical build entry](docs/validation/android-0.1.2-arm64-release-build.json):APP78/foundation115 tests passed, actual R8/resource shrink and lint0 errors/32 warnings; unsigned output is a separate artifact from final signing/device execution |
| Exact final APK | [Signed ARM64 Release](docs/validation/apk-0.1.2-release.json):bin/loft.apk hash/version/manifest/4-native alignment/signature and handoff index/artifact secret scan passed; local development cert SHA256 `4fd578439fe8c3bb5ab2abc6c33e494753a965dc47e44d96e313962852a400fc` |
| Minified startup | [x86 Release](docs/validation/android-0.1.2-x86-r8-smoke.json):actual Rust/JNA/private-service/guest UI passed; [kept Go JNI](docs/validation/android-0.1.2-x86-r8-go-jni.json):305-byte static metadata, linked gVisor/GOMAXPROCS2/inactive descriptor, ordinary application UID. No node/TUN/Go-runtime startup was invoked |
| Historical Android baseline | [0.1.1 API29](docs/validation/android-runtime-checkpoint.json):actual X/Pro selected-UID literal TLS/HTTP200 and Stop; its old hashes and failures remain unchanged |

Actual native guest UI is recorded at [673dp](docs/validation/ui/loft-0.1.2-guest-vpn-673dp.png) and [1440dp](docs/validation/ui/loft-0.1.2-guest-vpn-1440dp.png). Their metadata records physical pixels/density and the real Activity window; both show the persistent rail and inactive protection, with no private nodes imported. These are API29 x86 Debug captures, separate from physical Fold or ARM64 Release execution.

The 0.1.2 checkpoint also passed 38 Python tests and the direct-dependency architecture guard. The `basic-toml` notice concerns a host-only tooling dependency. The older task report records its build, API and artifact results alongside the original failures. [0.1.2 task report](report/loftmobile-1125-01-progress.md)

The combined application/Go adapter uses compatible GPL terms; the independent Rust workspace keeps Apache2 metadata. Read [third-party notices](THIRD-PARTY-NOTICES.md) and the source/license inventory before distribution.
