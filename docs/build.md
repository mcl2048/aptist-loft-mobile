# Reproducible framework builds

Run commands from the repository root. The local design inputs are `guide/guide.md` v3.6 and `guide/ui-design.md`; Git delivery excludes them, private test nodes and task credentials. `toolchain-lock.json` records the fixed tool versions. Generated bindings and binaries are build outputs, never hand-edited or committed. The separate local acceptance artifact is `bin/loft.apk`.

The server installation uses `/home/coder/.local/share/loft-mobile` for Gradle/Android SDK, JDK21 and Rust1.100.0. `scripts/env.sh` selects Go1.27.4, Android API36/build-tools36/NDK28.2.13676358 and at most two build workers. Source it in each independent shell; from a temporary working directory use the absolute `/home/coder/LOFT-mobile/scripts/env.sh`. A failed relative source can select a different auto-downloaded Go toolchain, so record the actual tool versions. Override `JAVA_HOME`, `LOFT_ANDROID_SDK_ROOT`, `LOFT_GO_BIN` and `LOFT_GRADLE_BIN` for another installation. Do not replace HOME or other projects' settings. The Gradle proxy wrapper accepts credential-free HTTP CONNECT proxies only and never writes global Gradle configuration.

```bash
source scripts/env.sh
python3 -m unittest discover -s tests -v
python3 scripts/verify_architecture.py
cargo fmt --manifest-path loft-core-rust/Cargo.toml --all --check
cargo test --manifest-path loft-core-rust/Cargo.toml --workspace --locked
cargo clippy --manifest-path loft-core-rust/Cargo.toml --workspace --all-targets --locked -- -D warnings
```

```bash
cd loft-vpn-engine-go
python3 tools/verify_owned_sources.py
go test -tags=with_gvisor -p=1 ./... -count=1
go test -race -tags=with_gvisor -p=1 ./... -count=1
go vet -tags=with_gvisor -p=1 ./...
go mod verify
cd ..
bash scripts/build-native.sh
bash scripts/build-android.sh
```

Native builds must use `with_gvisor`: sing-tun's real stack is feature-gated. A default-tag controller build does not establish a VPN. The Rust ARM64 linker targets API29 and 16KiB LOAD alignment. UniFFI0.32.2 uses a global `--config` and a positional library input; gomobile locates the exact module-locked `gobind` executable rather than invoking `gomobile init` and installing a moving latest tool.

The Rust storage adapter builds the Cargo-locked SQLCipher amalgamation and vendored OpenSSL with the NDK toolchain. The host needs `perl` and `make` for the OpenSSL build. Keep the production and emulator native roots paired with their recorded Cargo.lock, target and artifact hashes. The source and license inventory tracks the native build inputs. [Rust dependency inventory](dependencies/rust-android-resolved.json)

Regenerate native outputs after any FFI or Go API change. Android consumes `app/build/generated/uniffi`, `jniLibs/arm64-v8a` and `gomobile/loft-engine.aar`. Pair each source freeze with the actual consumed AAR/JNI/binding hashes; component preflight is not whole-APP compilation or API execution. Do not run standalone and root Gradle configurations concurrently against the same cache. Large Rust/Go/Gradle jobs are serialized on this4CPU server. The paired x86 build used1worker; the canonical ARM entry actually used2workers/parallel=false with Gradle and a separate Kotlin daemon, each configured with a1536MiB heap limit. An environment request for in-process compilation was not the execution fact. Read the [task report](../report/loftmobile-1125-01-progress.md) for commands actually executed and their results; the list above is a reproducible procedure.

An isolated software-emulator build uses both `-PloftTestAbi=x86_64` and an absolute `-PloftNativeGeneratedRoot` pointing to the paired x86 inputs. Its build output is separate from the ARM64 production tree. [Paired native identities](validation/native-0.1.2-builds.json) and [post-pending complete x86 build](validation/android-0.1.2-post-pending-x86-build.json) record the current inputs; do not reuse an older test AAR or APK because its filenames match.

[ARM64 Release validation](validation/android-0.1.2-arm64-release-build.json) records the exact APP/foundation XML, lint, log and unsigned artifact paths. Current AGP actually executes `minifyReleaseWithR8`, `convertShrunkResourcesToBinaryRelease` and `optimizeReleaseResources`; verify those tasks and consumed paths rather than infer an older shrink-task/output name. A paired x86 minified Release startup smoke has its own source/artifact/execution receipt. Debug node tests, Release startup and actual ARM64 execution remain separate scopes.

The release Gradle artifact is unsigned. An explicitly labelled development APK is signed outside Gradle using a local ignored key; production signing, store distribution and handset acceptance are separate gates. Validate the candidate before replacing project-root `bin/loft.apk` atomically, then verify that exact final file:

```bash
python3 scripts/verify_apk.py bin/loft.apk
"${ANDROID_HOME}/build-tools/36.0.0/apksigner" verify --verbose --print-certs --min-sdk-version 29 --max-sdk-version 36 bin/loft.apk
"${ANDROID_HOME}/build-tools/36.0.0/apksigner" verify --verbose --min-sdk-version 24 --max-sdk-version 27 bin/loft.apk
"${ANDROID_HOME}/build-tools/36.0.0/aapt2" dump badging bin/loft.apk
python3 scripts/verify_secrets.py --apk bin/loft.apk
sha256sum bin/loft.apk
```

The second signature command checks the v2 block cryptographically in SDK24..27; it does not lower the APK's declared minSdk29. A single-range verifier reports the scheme it selects, so v2=false in the SDK29+ run is not evidence that the v2 block is absent.

Also inspect the actual binary manifest for package/versionCode, minSdk29/targetSdk36, ARM64-only ABI, non-debuggable/no-cleartext/no-backup policy and private service permissions. SDK36 aapt2 can show the foreground type as hexadecimal0x400, which represents systemExempted; decode the actual value rather than require a textual type label. `verify_apk.py` covers ARM64 ZIP/ELF alignment; it is not a signature or version verifier. `verify_secrets.py` scans the actual Git index and all artifact members using bounded local private inputs plus known PAT/URI/key forms, with redacted errors. Scan the final staged index again before a normal user-authorized push, preserve remote history and confirm the exact remote commit. Record matching source/build/test receipts, APK SHA256, signing identity and actual device scope.

Private node probes take `guide/TEST.TXT` as runtime input, never a build input. Desktop authentication/HTTPS, DNS/UDP, synthetic TUN packets, Android VpnService and physical-device power tests are distinct evidence. Record a failed resolver/policy test as failed. The local directory must not be added to Git or included in UI archives.
