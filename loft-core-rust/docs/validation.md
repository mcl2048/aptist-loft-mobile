# Rust validation evidence

## Frozen schema-1 foundation, 2026-11-25

Toolchain observed directly: `cargo 1.100.0 (3acc79c0c 2026-11-05)` and `rustc 1.100.0 (0ef1bc386 2026-11-09)`. `Cargo.lock` pins dependencies; UniFFI is 0.32.2. Builds used at most two workers.

The first test compilation failed because rcgen 0.14 renamed a fixture public-key API. The fixture was corrected to `PublicKeyData::subject_public_key_info`; this compiler error was not counted as TDD red behavior.

`cargo test -p loft-core --no-fail-fast` then exited 101 against compileable admission shells: 26 tests, 24 expected failures and two startup/rejection cases passing. Failed targets were `--lib`, `core_state`, `import_validation`, `server_origin` and `snapshot_budget`. They observed missing real imports, missing origin normalization, wrong routing/resource error branches and missing generation-exhaustion behavior. After implementation all 26 passed. A dedup fixture's unescaped fragment space was corrected to `%20` without relaxing the parser.

`cargo test -p loft-ffi --no-fail-fast` exited 101 against exported adapter shells: four tests failed on real `AppCore` command/state behavior. After forwarding and exhaustive boundary conversions all four passed, including four concurrent callers committing 200 unique nodes and isolated snapshot copies.

A self-review regression reproduced accepted dotted hexadecimal IPv4 in both origin and node inputs. `hexadecimal_ipv4_components_are_rejected_as_ambiguous_origins` and `legacy_numeric_node_addresses_cannot_change_identity_in_an_adapter` each exited 101 before correction. An independent Node URL constructor, without networking, normalized three hex variants to `https://127.0.0.1`. The common host validator was strengthened; the complete workspace subsequently passed 32 tests.

The first direct binding-generation command exited 1: UniFFI 0.32 rejected the old flat CLI config shape and could not find ambient `cargo metadata`. The generator's optional metadata discovery was disabled and an explicit global `[crate-roots]` configuration was added. Fresh generation from the repository root then exited 0 without an ambient Cargo-path requirement. Generated records use immutable Kotlin `val` fields; `AppCore()` is real, disposal is `close()`/`destroy()`, and errors are flat `CoreException` types with empty messages.

Fresh final foundation checks:

| Command | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 0; one nested-format fixture lint was fixed first |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0; 32 passed, zero failed |
| `cargo build -p loft-ffi -p loft-bindgen --locked` | Exit 0; host native library and executable built |
| `loft-bindgen generate <host-so> --language kotlin --config <global-config> --out-dir <target-generated> --no-format` from repository root | Exit 0 |
| `cargo test -p loft-core --test snapshot_budget --locked -- --nocapture` | Exit 0; maximum fixture metadata JSON Parcel was 61,622 bytes |

The snapshot fixture uses 50 maximum-length endpoints/escaped labels, 100 routing selections and a maximum-length server origin. This is a serialization bound, not measured JVM/Go/native PSS or device acceptance. Node admission tests also fill the retained-byte budget with valid independent generated certificate material and verify that removal returns quota.

No Rust test uses TEST.TXT, task credentials, real deployment secrets or production nodes. Certificate fixtures are generated independently in test memory and are excluded from production compilation. Source Gateway/Portal roots were read-only. Reviewed URI source pin: Gateway `231f14813f2b45cb6f0bde984181c57cba1d02fd`; protocol payload limits remain X 1..1024 and Pro 0..65507.

The foundation has no actual data plane, TUN, encrypted storage, cloud authentication, mailbox or scanner. Its successful native compilation does not prove Android socket protection, full TLS behavior, actual app routing, real-device VPN, memory/battery budgets or 72-hour acceptance. ARM64 library packaging and 16 KiB alignment belong to the root native build evidence.

## Actual VPN port extension

The user subsequently requested real X/Pro VPN-module testing. Root approved the opaque ticket/real receipt extension in [the port proposal](engine-port-proposal.md). The frozen foundation's 32 tests are not relabelled as actual VPN tests.


## Frozen 0.1.1-LYNX receipt port, 2026-11-25

The initial extension red run exited 101 with ten new core failures (nine lifecycle/ticket/receipt tests plus X/Pro private URI preservation) while 28 existing domain tests stayed green. After implementation all 38 passed. The FFI extension first exited 101 with four new exported-port/owner failures while the original four stayed green. A specific poison regression then observed Connected after owner-lock poison and failed expecting Unavailable. Published immutable metadata, explicit unavailable projection and atomic/try-lock priority stop corrected it; the held-normal-lock stop test passed without waiting for that mutex.

The priority revocation test separately failed with Err(StaleGeneration) where a trusted Revoked cause had to be recordable after cancellation. It was corrected without accepting a late generic start failure or ready callback. Rust 1.100 warned that atomic fetch_update was renamed; the implementation uses try_update.

All workspace/lockfile own-package versions are 0.1.1 and exported core_version is 0.1.1-LYNX. Fresh cargo test --workspace --no-fail-fast exited 0 with 50 passed, zero failed. Fresh cargo fmt --all --check and cargo clippy --workspace --all-targets --locked -- -D warnings exited 0. Counter-exhaustion and complete snapshot-boundary tests also pass. These are independent local validation/reducer/FFI/cancellation tests, not live VPN or device evidence.

Complete-metadata tests measured an initial UTF-16 JSON Parcel of 61,790 bytes and a maximum draft/applied UTF-8 byte-array frame of 35,157 bytes, below the live 60 KiB frame limit. This is serialization/admission evidence, not process PSS or kernel/Go memory cost.

The matching ARM64 release library was built using scripts/env.sh, RUSTUP_TOOLCHAIN=1.100.0, NDK 28.2.13676358, API 29 linker and -C link-arg=-Wl,-z,max-page-size=16384. cargo build -p loft-ffi --release --locked --target aarch64-linux-android exited 0. It was copied to Android generated jniLibs/arm64-v8a and Kotlin regenerated directly from that artifact using the global config, exit 0. All four ELF PT_LOAD segments have 0x4000 alignment.

Freeze artifact: library 1,539,256 bytes, SHA256 e2772aac339612501b6de0515fce0d2ea5d208cfc297fbe53903505e72c39517; generated Kotlin SHA256 e5e767f313219a78d0be792d75d759bf0d622c234e7bc313de82eb28d169da95. Source/copied native SHA matched. Generated output is not source delivery. Android/Go own actual JNI, TUN/protected-socket, protocol/live-node, DNS and consumer-ordering evidence. No TEST.TXT credential entered Rust files or logs.

## REQ-NODE-01: read-only memory-directory pages, 2026-11-25

The independent review in the root's `docs/validation/spec-compliance/requirements/REQ-NODE-01.md` found a current framework gap: Rust accepted 200 nodes but only the first 50 could be discovered through state queries. The owner re-read guide v3.6's accepted-node/200-workset requirements, UI design's import-order/stable-ID pagination requirement and `docs/contracts/framework.md`'s 50-row snapshot limit. Those constraints require bounded access to all accepted session-local records; pending SQLCipher/Keystore work does not justify hiding records 51–200. The independent review's actual binary snapshot result (28,428 bytes) is its host serializer evidence, not a new Rust measurement or a confirmed overflow.

Android and Rust froze `AppCore.node_page(offset: u32, expected_generation: u64) -> Result<NodePage, CoreError>`, generated as `nodePage(offset: UInt, expectedGeneration: ULong): NodePage`. `NodePage` is an immutable schema-1 record with generation, offset, full-workset node_count, at most 50 existing redacted summaries and optional next_offset. Valid page starts are 0/50/100/150 smaller than the current nonempty count; an empty directory accepts only zero. Generation is checked before the offset. `InvalidNodePage` was appended to the error enum; stale requests use `StaleGeneration`, poisoned owners use `StateUnavailable`.

The core method reads existing memory state through `&self` and clones only one page in original import order. The FFI read drops its ordinary mutex guard before converting the record. It does not use the mutation helper, reconcile priority cancellation or publish a snapshot. The snapshot schema/first 50 rows, global generation, 200-node/8 MiB admission and non-waiting priority Stop remain intact. No SQL, new runtime, persistence or raw configuration field was added.

TDD used actual core and exported `AppCore` imports/queries. Tests were written before compileable query shells. The first `cargo test --workspace --locked --no-fail-fast` exited 101: the original 50 tests passed; 11 new tests failed on missing page behavior and one new Pro metadata fixture failed earlier with `MissingField` because it omitted mandatory material. That fixture mistake was corrected using the existing independently generated valid X/Pro identity fixtures and was not counted as TDD red evidence. `cargo test -p loft-core --test node_pages --test import_validation --locked --no-fail-fast` then exited 101 with all eight new core/page-material tests failing on `StateUnavailable` from the shell, while the 11 prior material tests passed. The five new FFI/owner tests had already failed on the query shell in the full red run.

After implementation, fresh verification from this workspace, with `source ../scripts/env.sh` supplying the pinned toolchain and two workers:

| Command | Observed result |
| --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0; 63 passed, zero failed, including all original 50 |
| `cargo fmt --all` then `cargo fmt --all --check` | Both exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 0 |
| `cargo build -p loft-ffi -p loft-bindgen --locked` | Exit 0; host debug library/generator only |
| `target/debug/loft-bindgen generate target/debug/libloft_ffi.so --language kotlin --config bindings/uniffi.toml --out-dir target/generated/kotlin --no-format` | Exit 0; generated matching host Kotlin |

The shell initially lacked Cargo in PATH (`cargo --version` exited 127); loading the existing environment script resolved it. This was environment setup, not a validation failure.

New tests cover all four full pages with no missing/duplicate IDs, original order, terminal empty/partial pages, invalid offsets including u32::MAX, stale generations after off-page changes and profile/routing mutations, future generations, later-page target/removal behavior, active/pending removal rejection, owned caller copies, actual generated X/Pro/PEM/seed and SOCKS credential redaction, poison errors, and queued-query priority cancellation without generation reconciliation. These are reducer/FFI state proofs; the synthetic stopped receipt in the selection/removal test does not prove Android TUN closure or a live connection.

Host debug library SHA256: `814a3b4b3c5426a2264db92edf73a97021c980bac95e9f87ba74756cf46ed52f`. Generated Kotlin at `target/generated/kotlin/net/aptist/loft/core/generated/loft_ffi.kt` SHA256: `0f04b7df8550e111fdc7f5552d72aeec01b7d14b619949ad3d521dbb36569467`. Generated declarations were inspected for the frozen UInt/ULong method, six val record fields and appended error variant. No Android generated directory was overwritten. The earlier ARM64 receipt-port artifact predates paging; final matching ARM64 regeneration/16 KiB alignment, page Binder serialization, UI selection/order handling and device acceptance remain Android/root integration work. Version stays `0.1.1-LYNX`; no commit/push was performed.

## Maintained PEM parser migration, 2026-11-25

Root's cargo-audit 0.23.0 report contained zero known vulnerabilities and two unmaintained notices. `rustls-pemfile 2.2.0` / `RUSTSEC-2025-0134` was a direct production dependency of `loft-core`; this notice was not treated as an exploitable finding. Its actual local source delegates to `rustls-pki-types 1.16.0`. The owner read that version's `pem.rs`/`lib.rs`, including `PemObject`, slice iteration, private-key section conversion and `Zeroize` implementation.

The production dependency was removed from workspace/core manifests and the lockfile. Certificate decoding now uses `rustls::pki_types::CertificateDer::pem_slice_iter`; private-key decoding uses `PrivateKeyDer::from_pem_slice`. The existing strict envelope, eight-certificate/one-key limit, DER completeness, time/SAN/SPKI-pin/chain/EKU checks, key relationship and `Zeroizing` ownership remain. The decoder's diagnostic text still maps to a flat `InvalidCertificate`. Empty required material retains `MissingField`. FFI, pager, public record/error ordering and version were not changed.

Four tests were added using independently generated real X/Pro identities and a signed eight-certificate chain. Initial test expectations incorrectly assigned `InvalidCertificate` to empty required fields; they were corrected to the existing `MissingField` before baseline/red evidence and did not change production validation. `cargo test -p loft-core --test import_validation --locked pem_ -- --nocapture` then passed all four against the old implementation. A temporary envelope/cap bypass produced three real failures: preamble-bearing certificate/key imports and a ninth certificate were wrongly accepted. Restoring the envelope and substituting a decoding shell produced two failures on valid X/Pro material and the valid eight-link chain. These are deliberate regression sensitivity probes, not vulnerabilities reported against the original implementation. The maintained decoder passed all four afterward. Temporary probes were removed; no lint or audit suppression was added.

Cargo's lockfile pruning removed only `rustls-pemfile 2.2.0` and the `loft-core` dependency reference: 138 packages became 137, with no new packages and every retained registry record/version/checksum unchanged. An initial `--no-deps` metadata query did not prune. Full offline metadata pruned the lockfile but failed when trying to load the uncached, unrelated-platform `r-efi 6.0.0`; `cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu` then succeeded without downloading or upgrading it.

Fresh final commands used `source ../scripts/env.sh` and at most two build workers:

| Command | Observed result |
| --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0; 67 passed, zero failed, including all prior 63 |
| `cargo fmt --all --check` | Exit 0 after formatting |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 0 |
| `cargo build -p loft-ffi -p loft-bindgen --locked` | Exit 0; matching host debug library/generator |
| `target/debug/loft-bindgen generate target/debug/libloft_ffi.so --language kotlin --config bindings/uniffi.toml --out-dir target/generated/kotlin --no-format` | Exit 0; Kotlin hash unchanged |
| `cargo audit --json --no-fetch --file Cargo.lock` | Exit 0; zero known vulnerabilities, one unmaintained notice |

The remaining `basic-toml 0.1.10` / `RUSTSEC-2026-0374` notice is in the host binding-generator/proc-macro chain: `basic-toml -> askama_derive 0.16.1 -> askama_macros (proc-macro) -> askama -> uniffi_bindgen 0.32.2 -> uniffi/loft-bindgen`. Workspace feature unification can also show `loft-ffi` beneath `uniffi`; the normal Android `loft-ffi` runtime dependency graph does not contain `basic-toml`. It remains in the audited lockfile and was not ignored or relabelled as a production exploit. Upgrading that tool chain is outside this API-preserving migration.

Final SHA256 inventory:

| Artifact | SHA256 |
| --- | --- |
| `Cargo.lock` | `ee4e0e421696d1acd3cb27dd3507b61dcfa632d2cf1f8a5532a31ca9bd2c8242` |
| `crates/loft-core/src/certificates.rs` | `7beb0c0ca29f724af8bfaae3f6ccd6d80e8fd8a5cccef192dbc0ee67c5a5d481` |
| `target/debug/libloft_ffi.so` | `cf19b0babf3cc3a066565e21d93e5e2606addc40ca995cf5c0e34871520b05d6` |
| `target/generated/kotlin/net/aptist/loft/core/generated/loft_ffi.kt` | `0f04b7df8550e111fdc7f5552d72aeec01b7d14b619949ad3d521dbb36569467` |
| `target/pem-migration-audit.json` | `833be0657b1d7878bb060b40c285d038d87daf6ddedecedc16752401422ea48a` |
| `target/pem-migration-host-metadata.json` | `8058430d8e1662d09e732a2b835d520748ca49d1bb8d8ae621152acfbedcd838` |

Host output is not delivery source. No ARM64 rebuild, Android generated-file replacement, upstream-source change, commit or push was performed; root owns the final native/architecture/release checks and root documentation.

## 0.1.2-LYNX VPN-global network privacy contract

Root approved the source-pinned shared Go DNS/RTC guard and the typed Rust policy/receipt seam after read-only v3.6/UI/resource-contract review. This supersedes the old development wire-resolver default: the initial Rust policy epoch is 1, DNS is explicitly synthetic node-domain/Fake-IP routing, DNS/WebRTC leak modes are ProxyOnly, resolver endpoint is empty and Hydra is disabled. Fake-IP does not establish a real resolver answer or Gateway DNS/Firewall deployment success. Recognition is scoped to actual supported DNS/RTC channels and captured VPN UIDs; browser-local SDP candidates, unselected apps and other profiles are not claimed hidden/protected.

`privacy.rs` owns bounded validation, normalization, deterministic canonical policy JSON, actual UID identity normalization and framed SHA256 scope derivation. No production dependency was added; the same 137 locked packages remain, with the three own-package versions synchronized to 0.1.2. A changed valid policy increments global configuration generation and a separate checked policy epoch atomically; a normalized no-op increments neither. Existing tickets and confirmed applied policies retain their captured settings until explicit Stop/join/new attempt. Read-only pages still use schema 1 and original capacity/fences.

Android/Go/root agreed the actual scope after a package-only digest was identified as insufficient: `freezeEffectivePackages` is followed by one `freezeNetworkScope(NetworkScopeIdentity)` with actual service owner UID and complete package→UID pairs. Rust validates the 100-row/4,096-name-byte cap, exact expanded package membership, duplicates, signed-Android UID range and same installation/user profile. Full tunnel uses empty pairs plus actual owner/profile identity. Android revalidates actual membership before Builder, after establishment and before Ready; changed identity denies/Stops rather than rebinding. Canonical policy and one-use raw URI require a live identity-frozen ticket; canonical delivery comes first. Frozen nonsecret scope metadata remains available for later failure/closure receipts.

CoreSnapshot payload schema is 2; Android publication envelope is independently 3, while NodePage and canonical Go policy remain schema 1. Snapshots expose separate draft policy/epoch, confirmed applied policy/scope and Inactive/Active/Blocked enforcement. Ready requires original transport/auth/TUN/socket/consumption/routing proof plus exact epoch/scope/modes, actual installed DNS/RTC/IPv6 enforcement, no pending resource owner, matching Hydra profile scope and Android IPv4/no-bypass/IPv6 capture confirmations. Stop projects Inactive without waiting for the state mutex; poison also clears applied privacy. Blocked requires actual original TUN held/drop and matching captured scope/platform proof. DNS/RTC/Hydra packet counters remain Go resource metadata; Rust adds no packet copies, timer, poll or runtime.

Meaningful red/green observations:

- `cargo test -p loft-core --test privacy_policy --locked --no-fail-fast`: first exited 101 against validation shells, five valid-policy failures and three rejection cases passing. Implemented normalization then passed all eight, including literal endpoints, DNS quotas, blocked modes and Hydra disabled/zero/boundary behavior.
- `cargo test -p loft-core --test privacy_lifecycle --locked --no-fail-fast`: first exited 101 with ten failures against lifecycle/scope/config shells. After implementing draft/scope/canonical behavior, seven passed and three failed on actual wrong branches: Ready accepted unconfirmed privacy proof, Blocked accepted wrong scope, and confirmed privacy was absent. Exact receipt checks corrected those branches.
- The first complete updated suite exited 101 with 88 passed and two failures. Existing/new FFI poison and held-normal-mutex priority Stop tests observed Active where Inactive was required from the published snapshot. Explicit immutable projection corrected both; ordinary Stop still does not wait for that mutex.
- Two additional max-epoch regressions first passed the intended implementation. Deliberately substituting wrapping policy admission and signed JSON conversion made both fail: mutation returned Ok under a reused epoch, and JSON contained "-1" instead of "18446744073709551615". The original checked unsigned implementation was restored and final suites passed. These sensitivity probes are not reported as original exploitable findings.
- A generated-real X/Pro material test rejects enabled Hydra without actual profile application/scope, then accepts only LogicalStreams for X or TcpOnly for Pro. It is a reducer receipt test, not actual wire shaping evidence; record/padding activity remains separate Go evidence.

The original 67 test cases remain, adapted only for schema 2/new mandatory receipt and identity inputs. Test-only helper modules supply explicitly synthetic reducer/boundary proofs; they are excluded from production and never read task/private nodes. New tests include 17 separate invalid Ready conditions, policy draft versus applied/late receipt behavior, UID/profile digest changes, identity failures, one-use/cancelled configuration, policy generation/page conflicts, and platform/ownership/Hydra receipt rejection. No source-text or mock-only test was introduced.

Fresh source verification from this workspace, with `source ../scripts/env.sh` and two workers:

| Command | Observed result |
| --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0; 93 passed, zero failed (original 67 plus 26) |
| `cargo fmt --all --check` | Exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 0 after fixing test initializer/borrow style, with no suppression |
| `cargo audit --json --no-fetch --file Cargo.lock` | Exit 0; zero known vulnerabilities, remaining host basic-toml unmaintained notice |
| `cargo test -p loft-core --test snapshot_budget --locked -- --nocapture` | Exit 0; complete schema-2 fixture 62,878-byte UTF-16 JSON Parcel and 36,240-byte draft/applied UTF-8 frame |

The JSON fixture now includes both policy copies and effective status, but it is a conservative serializer fixture, not Android's actual binary Binder result. Actual payload/envelope size and foreign binding/engine/UID-scope/DNS/RTC behavior belong to Android/Go/root integration.

The exact typed API is recorded in [network-privacy-contract.md](network-privacy-contract.md). Source inventory is in ignored `target/privacy-source-inventory.json`. No binding generation or native rebuild was performed for this checkpoint: root explicitly reserved those jobs until the agreed source/ABI and build slot are reviewed. The previous 0.1.1 host/ARM64/APK artifacts do not prove the new 0.1.2 privacy behavior. No upstream/private input, another subtree, commit or push was changed.

## 0.1.3-LYNX encrypted local configuration

`AppCore.openPersistent` authenticates one SQLCipher database and restores local node records, the ID allocator, the last committed configuration generation, routing preferences, the network privacy preference and epoch, and the staged HTTPS server candidate. It starts with a disconnected VPN, a fresh attempt allocator and empty routing and protection receipts. The store commits each edit before the state owner updates and publishes its in-memory configuration. An indeterminate commit requires an authenticated reopen before a subsequent configuration edit or VPN start. Priority Stop and redacted snapshot inspection remain available.

The encrypted store uses `rusqlite` 0.43.0, `libsqlite3-sys` 0.40.0, SQLCipher 4.20.0 with SQLite 3.54.1, and vendored OpenSSL 3.6.3. SQLCipher policy includes HMAC, memory sanitization, 4 KiB pages, a 2 MiB page-cache target, memory-only temporary storage, secure delete, disabled attached databases and a 64 MiB database cap. The serialized connection uses a DELETE rollback journal with `synchronous=EXTRA`. The 200-entry directory, bounded row streaming and the existing 8 MiB decoded node configuration budget govern Rust memory. Original imported links are bounded per row and by the encrypted file quota, and they are loaded one row at a time. Snapshot and node page schemas remain at 2 and 1. Schema migration and fresh initialization share the same transaction boundary. Unknown versions, missing active files, invalid keys and tampering preserve the existing data for recovery. An older otherwise valid copy of the complete database can replay local state if an attacker can write the app's private directory.

The first TDD compile failed against the previous feature set at the new constructor and recovery error references. The first implemented open run failed because the locked SQLCipher overrides `PRAGMA page_size` with a text-valued result. A bounded synthetic diagnostic captured the column name and type, then the adapter switched to the explicit `cipher_page_size` result. SQLCipher status and HMAC flags also use text results. No diagnostic or fixture uses actual task credentials.

`persistent_core` compares service-ticket digests for restored SOCKS5, Hyraken X and Hyraken Pro using synthetic inputs and independently generated key/certificate fixtures. Cases cover encoded SOCKS authentication, X's CA, client certificate and private key, server trust material, Pro credentials and non-default transport options, stable node IDs/order/labels, and expired stored certificate removal. The storage tests exercise a real interrupted SQLite process with a hot rollback journal, commit failure after a partial edit, a second concurrent owner, schema mismatch, and a changed ciphertext page. Host process-recovery coverage is separate from physical handset durability, Android Keystore and filesystem behavior during power loss.

Design references include the SQLCipher API, SQLite atomic commit behavior and OWASP MASVS storage controls. [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/) · [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html) · [OWASP MASVS-STORAGE](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

| Final host check on Rust 1.100.0 | Observed result |
| --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0, 102 passed, zero failed. Log SHA-256 `c99ea1819b982d7b62e661d477a3d3efd2d9ecbcc42051f80e88f7cafb3a8cdc`. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 0. Log SHA-256 `f9613a2f1b1383fde43379b35136087162edee140c3c5801c4c5d200c507e271`. |
| `cargo fmt --all --check` | Exit 0. |

The tested `Cargo.lock` SHA-256 is `fa6681a8195f2aec474bd99cf4fcbe91cda225caa44ebf2af36eb0211cb5b130`. The first failing test log and explicit column diagnostic log have SHA-256 `b047d1f4c1e7d2df8fe546ba34cbb3ed7b98b77105fe42785ae9092f793a7a16` and `87dac854647bcc511c1fe5029962d374f1b0af5f10e833bb0c9ac198e7fa693d`.

## Hub account and mail port, 0.1.4-LYNX

The client contract was checked against RFC 8252's external browser guidance, RFC 9700's code flow and PKCE guidance and RFC 8628's transaction polling limits. The APP uses a Hub-specific proof and explicit completion. Portal continues to own browser sign-in and consent. The Hub owns Portal client credentials and tokens.

The first pinned `cargo test -p loft-core --test hub --locked` ran three tests against compiled admission shells. It exited 101. The no-candidate test received the shell's `StateUnavailable` and the other tests reached missing discovery behavior. On the first implementation run two tests passed. The reauthorization fixture incorrectly expected the existing account to disappear during browser authorization. The fixture now checks that the previously confirmed account persists until a valid replacement arrives. The resulting suite covers proof binding, explicit pending and completed receipts, matching issuer and browser destination, stale result fencing through candidate changes and logout, opt-in mail access, folder-scoped cursors, attachment byte verification and source session rejection.

`cargo test --manifest-path loft-core-rust/Cargo.toml --workspace --locked --no-fail-fast` passed 108 tests, including six Hub cases. These cases use synthetic receipts and establish core admission, fencing and parsing behavior. The root task report records live Portal and Cloudflare behavior and execution of the Android client.

Pinned `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` both exited 0. The task's isolated x86 native build compiled `libloft_ffi.so` and regenerated Kotlin through UniFFI 0.32.2. The generated Kotlin SHA256 was `6163b4e69d6f0dc92ebd274d820c2abc481e2ef54f8095e4e51ad76d786d17b5`. The generated port exposes `hubBegin`, `hubFinish`, `hubSnapshot`, `hubClear` and `hubAbandon` with immutable records and typed `HubException` failures.

## Offline vault and durable Hub authorization at 0.1.5-LYNX

The first pinned `cargo test -p loft-core --test vault --locked` ran two compiled behavior tests against admission shells and exited 101 with the expected missing save and import behavior. The durable identity test initially received `InvalidResponse` from the existing short-grant client. The encrypted backup transfer test first received `Unavailable` from the sync shell. Each passed after its implementation. During the full run, the reconsent fixture assumed an anonymous request and two 20-billion-second RFC values were transcribed from the wrong rows. The reconsent test now verifies the existing Hub bearer, and the RFC values were checked against Appendix B and Python `hmac`.

Pinned `cargo test --workspace --locked --no-fail-fast` passed 118 tests. New tests cover native TOTP vectors in all three supported algorithms, big-counter time handling, strict URI admission, offline reveal and archival, real SQLCipher migration and reopen, durable identity after process disposal, offline logout, unrelated 401 responses preserving identity, client-to-client encrypted backup transfer, wrong-passphrase rejection, independent edits, merge conflicts, and rejection of a pending sync after logout during detached KDF work. `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` exited 0.

NDK 28.2 `llvm-objdump` reviewed the optimized Rust1.100.0 Android ARM64 and x86_64 `loft_core::vault::generate_code` symbols. The truncation read fixed digest positions and selected with ARM64 `csel` / x86_64 `cmovne`. The decimal path used multiply and shift with public digit-count branches and no divide in the inspected function. This is a compiler-artifact review of the wrapper's truncation and formatting. HMAC and AES-GCM are provided by ring 0.17.14. Argon2id, from RustCrypto argon2 0.5.3, uses 64 MiB, three passes and four lanes with a zeroizing workspace outside the core mutex. Host results do not supply device resource or side-channel measurements.

The actual ARM64 Release Rust input compiled. The task-owned x86 integration build used an earlier sync-lock checkpoint with the same FFI wire. Its generated Kotlin and the final ARM64 Kotlin both had SHA256 `aacb9f2bfcd3085f99aa4bf44ce6a767dbd7000bd238de137450a9e2984bc858`. The root release report associates the final signed APK and deployed Hub with their own checks.

## Application protection and secure notes at 0.1.7-LYNX

SQLCipher schema 3 adds separate protection and notes records through a transactional schema 1 or 2 upgrade. The store retains its existing authenticated page format and secure deletion setting. The notes record is bounded to 480 KiB across a device-local collection and up to four account collections. Notes are limited to 200 total and 25 KiB of UTF-8 per body. A protected page receives at most 20 summaries and at most one requested detail per reply. Deletion clears the active record, and synchronized collections retain only an opaque deletion ID for each deleted note. Flash remapping, historical copies, and Cloudflare retention remain outside the deletion receipt. [SQLite secure delete](https://www.sqlite.org/pragma.html#pragma_secure_delete)

The optional six-digit PIN uses a per-PIN salt, Argon2id with 19 MiB, two passes and one lane, and a constant-time HMAC verifier. Rust reserves each failed-attempt charge in the encrypted store before detached verification. Five unsuccessful attempts start a 30-second backoff, followed by exponential increases up to 30 minutes. The platform clock supplies restart-persistent retry deadlines. The private core issues one scope-bound page lease at a time. PIN and biometric success require the current challenge. Android owns actual biometric authentication. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) · [Android BiometricPrompt](https://developer.android.com/identity/sign-in/biometric-auth)

Sync enrollment requires the negotiated Hub capability and an exact origin, issuer and durable subject. A 32-byte recovery key is generated locally or entered explicitly on another device. Existing device-local notes stay device-local. While paired, new notes enter the current account's encrypted collection. Signing out or changing account hides that collection while preserving its local encrypted state. The wire envelope uses HKDF-SHA256 and AES-256-GCM with a fresh nonce and authenticates account scope and revision. The Worker receives ciphertext only. A conditional GET unchanged receipt avoids collection cloning and local writes. Merge runs outside the state mutex, and apply rechecks account and note generations. Delete IDs dominate conflicting stale copies. A per-note logical version and randomized tie-breaker converge concurrent edits to the same note.

The first focused build reached unresolved exported commands. The later executable regression reproduced two issues: re-discovering the same Hub with the added capability cleared a durable login, and initial enrollment promoted existing local notes into the sync collection. The final suite exercises those repairs, PIN throttling across a real encrypted database reopen, scope fencing for the vault and notes, typo search, archive/delete, stale editing, encrypted exchange between two core instances, offline merge, and deletion propagation.

| Rust 1.100.0 command from the repository root | Result |
| --- | --- |
| `cargo test --manifest-path loft-core-rust/Cargo.toml --workspace --locked --no-fail-fast -j 1` | Exit 0 with 125 passed, zero failed and zero ignored. Log SHA-256 `67c99aa5587932486df944d91b5957bc31581b5de72a4f0359c928817984f97a`. |
| `cargo clippy --manifest-path loft-core-rust/Cargo.toml --workspace --all-targets --locked -j 1 -- -D warnings` | Exit 0. Log SHA-256 `2c0d19fdeb187f3682a9885d2503a35b1c44a3e1acf57f135ed13ed8759a5680`. |
| `cargo fmt --manifest-path loft-core-rust/Cargo.toml --all --check` | Exit 0. |

The workspace lock SHA-256 is `3f4032219e5fbee880e4dcd4ffbd220ec7b99a577e650d8f581537ba172d3e1c`. The capability and guest storage regression logs had SHA-256 `890d0142202e20bef48b86b223597eedbbdbc71a2ef28d6e947b98c08165cba6` and `5590a211f44a7609b81dd8fcd5f8a1b0f3ea99d02f2a830fc5ddddc0a98a47a9`. Device authentication, Fold layout, Android WorkManager delivery, active VPN network routing, and live D1 synchronization require their corresponding platform and deployment receipts.
