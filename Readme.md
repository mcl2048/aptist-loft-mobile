# LOFT mobile · 0.1.2-LYNX

LOFT is a native Android application framework with Rust-owned business state and source-pinned Go VPN adapters. Task `loftmobile-1125-01` builds the foundation against local `guide/guide.md` v3.6 and `guide/ui-design.md`. The complete P0–P5 product roadmap has separate implementation and device gates.

The signed ARM64 Release is delivered locally at `/home/coder/LOFT-mobile/bin/loft.apk`:version `0.1.2-LYNX`, Android versionCode `3`,21,507,686bytes, SHA256 `64c9ae2370eaf1df45533ea2fb3e93d0961287d381501cac39e0785ff785a81e`. It uses the local development signing identity. Actual package, declared minSdk29/targetSdk36 manifest, signature and all4 native ZIP/ELF16KiB checks passed on that exact file; [delivery receipt](docs/validation/apk-0.1.2-release.json) records source/build/scan identity. Production identity and physical-device acceptance are separate gates.

ARM64 Release/R8/resource shrink/lint passed with78 APP and115 foundation JVM tests; lint has0 errors/32 warnings. The paired x86 Debug APK passed8 actual API29 guest, X/Pro default DNS→original-hostname HTTPS/Stop, connection-request cancellation and foreground-notification checks. Minified x86 Release Rust/JNA/private-service/UI startup and an independent static Go JNI reflection probe also passed; their Go runtime/TUN/node remained unconstructed. The signed ARM64 artifact and each Android execution scope remain distinct.

The private `:vpn` process owns one Rust core, the Android TUN and the lazy Go runtime. Compose displays immutable receipts; closing the UI, changing language/theme or resizing a Fold window does not own the VPN lifetime. Guest startup is local and has no Portal or cloud dependency.

| Available foundation | Actual boundary |
| --- | --- |
| Strict SOCKS5/X/Pro link parsing | Atomic, bounded imports; certificate/name/pin/key checks; redacted metadata; session-local credentials |
| Complete bounded node directory | 200 nodes exposed in 50-row generation-bound pages; stable selection across pages |
| Rust VPN state and private IPC | Frozen startup scope, one-use credential delivery, actual routing/privacy/closure receipts; priority Stop and stale-callback fences |
| Source-pinned IPv4 VPN adapter | gVisor TUN, protected/bound physical sockets, TCP/UDP admission and ownership; real authentication and host packet tests |
| App routing foundation | Exact PackageManager-reported UID/package Builder scope; empty/lockdown conflict rejection, drafts separate from applied routing; hidden-package/device scope remains unverified |
| Shared network privacy | Node-domain Fake-IP, original FQDN restoration, current-client DNS/RTC proof, IPv6 rejection and bounded passive TTL/lease recovery |
| Native UI | Persistent module rail, four locales, themes, window/hinge/tabletop layouts and retained presentation drafts |
| Optional account/mail/Shield | Honest dependency states; no simulated login, inbox, malware verdict or server trust |
| Notification foundation | Real VPN foreground lease, native icon and priority Stop; actual permission/channel reporting; default-denied mail event boundary |
| Release foundation | Fixed tools, generated native bindings, architecture/source/secret guards, R8/lint/native/signature checks and validation records |

Default DNS uses `198.18.0.2` inside the VPN to return bounded synthetic routing aliases. The shared engine restores the original hostname before the selected proxy opens the connection; a Fake-IP answer is not a public resolver answer. The latest matching API29 APK passed uncached VPN DNS→alias→original-hostname certificate/TLS/HTTP200→Stop on both private X/Pro nodes. Explicit `wire_tcp` mode instead needs a permitted literal IPv4 resolver and never falls back to physical business DNS. Historical public TCP/UDP53 failures belong to that forwarding-probe path and do not establish a broken node DNS subsystem or a current default-mode failure.

DNS and recognized WebRTC traffic use shared `proxy_only`/`block` rules before all transport adapters, with exact policy epoch, owner/shared-UID scope and current TUN/client proof. Stop, loss and Abort revoke enforcement claims. Packet filtering cannot promise to hide browser SDP address enumeration or cover APPs deliberately outside the selected VPN scope. Hydra uses the existing X/Pro shaping hooks independently and defaults to Disabled; QUBF transports remain future adapters.

The added-memory ledger is 8 MiB, including a fixed 528 KiB non-domain address quarantine reservation; dynamic capacity is 7,847,936 bytes. Mappings are limited to 256 entries/256 KiB and retain identity through live I/O and advertised TTL. Passive recovery needs no periodic restart or extra polling. These allocation limits do not establish handset PSS or battery performance.

QR, the 512 KiB Android FD-import path, SQLCipher/Keystore persistence, live TUN/candidate replacement, automatic reconnect, Rust BFF/OAuth, own-user mail, Shield/attestation and Gateway policy integration remain explicit later capabilities. The current Portal only supports confidential OAuth; its administrator clientSecret and user bearer do not belong in this APP's BFF path. A normalized server candidate is not a verified enterprise server.

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

Gateway8.0.32-LYNX is pinned to `231f14813f2b45cb6f0bde984181c57cba1d02fd`; Portal2.2.0-PUMA review input is `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36`. Both are read-only source inputs. The owned Go snapshot preserves the existing X/Pro authentication and payload boundaries: X1–1024-byte application UDP; Pro0–65,507, including empty packets. Pro's66,023-byte XUDP envelope is not application payload. Ordinary SOCKS5 has no tunnel encryption.

[Requirements and remaining acceptance](docs/requirements.md), [task progress](report/loftmobile-1125-01-progress.md), [trust boundaries](docs/threat-model/framework.md) and [privacy](docs/privacy/framework.md) distinguish host, Android and physical-device results. The repaired node-directory finding retains its [original and post-fix evidence](docs/validation/spec-compliance/requirements/REQ-NODE-01.md).

The current source/artifact records are:

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

Root Python38 tests and the direct-dependency architecture guard also passed at the recorded checkpoint. The one `basic-toml` notice is absent from the normal Android `loft-ffi` dependency graph. The [task report](report/loftmobile-1125-01-progress.md) records current source/build/API/artifact results and retained failures. Source publication uses a normal main commit preserving remote history; the exact confirmed remote SHA is in Root's final independent receipt/answer. No physical-device or72-hour certification is claimed.

The combined application/Go adapter uses compatible GPL terms; the independent Rust workspace keeps Apache2 metadata. Read [third-party notices](THIRD-PARTY-NOTICES.md) and the source/license inventory before distribution.
