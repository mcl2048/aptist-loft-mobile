# LOFT Rust framework · 0.1.3-LYNX

This workspace owns client configuration and business state. Core snapshots use schema 2 and node pages use schema 1. The private Android service opens one persistent `AppCore` on its serial command worker. Android supplies system capabilities and Go supplies the engine adapter. Snapshot reads use published memory state.

`loft-core` contains local validation and bounded state. `loft-storage` implements the core repository port using one SQLCipher connection. `loft-ffi` exports the `AppCore` object and records through UniFFI. `loft-bindgen` is the explicit binding generator. Kotlin bindings use `net.aptist.loft.core.generated` and load `loft_ffi`.

Imports accept the Gateway's `socks5://`/`socks://`, `hyrakenx://` and `hyraken-pro://` formats. They reject malformed encodings, incomplete credentials, duplicate/unknown query parameters, unsupported options and invalid import materials before committing a node. Deduplication compares normalized configuration without its display label. Rust retains decoded secrets in zeroizing buffers and commits each original validated URI into the encrypted node table. Reopen validates stored rows structurally. Import and VPN admission both check certificate validity against the current clock, while expired stored entries remain visible and removable.

Node summaries contain a bounded label, endpoint, protocol and material-presence flag. They omit usernames, passwords, seeds, PEM, keys and original links. Display labels cannot republish the known credentials or a raw link. X's current fixed-target application UDP range is **1–1024 bytes**; Pro's is **0–65,507 bytes**, including empty payloads. SOCKS metadata uses the general UDP ceiling; it does not establish that a particular server supports UDP or encryption.

Server selection stages a strictly parsed HTTPS origin and advances the global configuration generation when the candidate changes. Normalization does not contact the origin or verify TLS, compatibility, identity or enterprise trust. Routing selections remain drafts, and an enabled empty selection fails atomically. The legacy `connect` validates the target and returns `DataPlaneUnavailable`; the trusted service uses the receipt port below. `stop` is idempotent and retains nodes/preferences. Go/Android own actual data-plane resources.

| Resource | Admission limit |
| --- | --- |
| Raw import and cumulative decoded parsing bytes | 512 KiB each |
| Retained node configuration charge | 8 MiB, plus at most 200 nodes |
| Snapshot node rows | First 50; `node_count` reports the full workset |
| Read-only node page rows | At most 50; fixed offsets 0/50/100/150 within the current workset |
| Label | 64 UTF-8 bytes, no display/control characters |
| Server input | 2048 bytes; ASCII DNS/IP authority only |
| Routing input | 100 names, 255 bytes/name, 4096 aggregate bytes |
| X public server/CA material | 64 KiB per field |
| X client certificate/private key | 16 KiB per field |
| Pro public certificate | 64 KiB |
| PEM certificate blocks | At most 8 per field |
| Private start ticket | At most one current ticket; URI is bounded to 512 KiB and consumed once |

The node charge counts owned configuration capacities and conservative record overhead. It is separate from JVM/Go/allocator overhead, kernel queues and measured process PSS. All mutations validate before updating generation; exhausted counters fail without wrapping. Native callers own their input allocations and must bound their command queue. The service must call synchronous imports on its bounded worker, keep large inputs off Binder, and dispose the core when its owner ends.

`nodePage(offset: UInt, expectedGeneration: ULong): NodePage` exposes every retained node through the existing core owner. Its immutable schema-1 record contains `schemaVersion: UInt`, `generation: ULong`, `offset: UInt`, full-workset `nodeCount: UInt`, at most 50 existing redacted `NodeSummary` rows and `nextOffset: UInt?`. Rows retain import order and stable IDs. The empty directory accepts offset zero and returns no rows or continuation; otherwise an offset must be a 50-row page start smaller than `nodeCount`. Following `nextOffset` visits all four pages of a full 200-node workset.

The query checks the caller's global snapshot generation first, returning `StaleGeneration` after any intervening configuration/lifecycle mutation. Invalid offsets return `InvalidNodePage`, appended to the exported error enum. A poisoned owner returns `StateUnavailable`. Reading a page does not reconcile cancellation, publish a snapshot, advance generation or change VPN state. The read holds the normal mutex only while cloning one page; priority Stop retains its non-waiting `try_lock` path. Android owns bounded page IPC and request/binding ordering; the business snapshot uses schema 2 with its first 50 rows and stop/unavailable projections.

Import material checks include strict PEM/DER parsing, validity windows, SAN/SPKI-pin agreement, supplied chain links, X client CA signatures and the client certificate/private-key relationship. They do not implement complete live TLS/PKIX/revocation verification. The actual transport adapter must perform its own full TLS validation and protect/bind actual sockets before it can provide a connection receipt.

The Rust core has no active cloud server profile, authentication, mailbox, software scanner, OS TUN implementation, QR/file import transport or automatic background reconnection. The service adapters implement real VPN/TUN work; their actual transport/device acceptance is separate evidence. No connection, login or safety verdict is synthesized.

The service calls `beginVpn(nodeId, expectedSnapshotGeneration)` after a valid Android permission ticket. Its opaque `VpnStartTicket` freezes node/draft scope, then accepts one `freezeEffectivePackages` and one actual `freezeNetworkScope`. The service obtains bounded `canonicalNetworkPolicy` for Go installation before consuming single-use `takeRawNode`. The canonical credential URI stays service -> Go only, never in a record, Binder reply, UI or log. `markVpnReady` requires the matching attempt/policy/UID scope, consumed configuration, exact effective packages, authenticated/transport/TUN/socket facts, actual DNS/RTC/profile enforcement and platform IPv4/no-bypass/IPv6 confirmations. Only then does Rust publish `Connected`, `appliedRouting` and active privacy protection.

The [network privacy contract](docs/network-privacy-contract.md) adds a Rust-owned DNS/RTC policy draft and independent epoch, one-use actual UID-scope freeze, bounded canonical Go configuration and exact policy/capture/enforcement receipts. Default DNS is explicitly synthetic node-domain/Fake-IP routing, not a verified resolver answer; Hydra is disabled unless explicitly selected. Saved policies do not overwrite an applied attempt. Static capability/configuration flags never establish effective protection, Stop/poison retract it, and actual Go/Android DNS/RTC/UID-scope/device evidence remains separate from Rust reducer tests.

Connection attempt IDs are separate from later configuration generations, so adding guest nodes or staging a Portal server does not replace an existing VPN. A pending/active target cannot be removed; drafts never rewrite confirmed routing. Failed attempts fence readiness. `markVpnBlocked` requires actual original-TUN-held and forwarding-disabled proof and publishes its held scope, including failures before connected readiness. `confirmVpnStopped` clears that scope only after Android closes the original PFD and Go confirms its duplicate/resources were released. Old callbacks are rejected.

Priority `beginVpnStop` sets an atomic cancellation fence and returns without waiting for a held normal Rust mutex. Android cancels Go/FD owners immediately and reconciles a stopped receipt after its start/stop actor quiesces. If preparation was concurrent, it rechecks the captured attempt before confirming; stale receipts never close a newer attempt. Cancellation works at counter exhaustion without admitting a wrapped generation. The infallible query reads immutable published metadata; poison projects `Unavailable` and clears confirmed active/applied state, while pending priority cancellation projects `Stopping`.

Global generation can remain equal during a priority/unavailable projection, particularly at exhaustion. The service's single bounded transport capture sequence is reserved before reading `snapshot()`, so a late earlier `Connected` capture cannot replace a newer `Stopping`/`Unavailable` frame. That sequence is transport ordering, not another business state machine. The consumer regression belongs to Android's boundary tests.

From this directory, using the pinned Rust 1.100.0 toolchain:

```sh
cargo test --workspace --locked --no-fail-fast
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p loft-ffi -p loft-bindgen --locked
target/debug/loft-bindgen generate target/debug/libloft_ffi.so --language kotlin --config bindings/uniffi.toml --out-dir target/generated/kotlin --no-format
```

UniFFI 0.32 uses a global CLI config. `bindings/uniffi.toml` supplies explicit crate roots; `crates/loft-ffi/uniffi.toml` supplies the single Kotlin configuration, including immutable `val` records. Default Cargo metadata discovery is disabled so generation can also run from the repository root with absolute paths. Generated/native artifacts remain build output.

`AppCore.openPersistent(databasePath, key, allowCreate)` opens device-local configuration for the private Android service. The in-memory `AppCore()` supports host callers and tests. `close()`/`destroy()` dispose the native handle and its SQLCipher connection. `stop()` requests VPN cancellation. Numeric fields are `UInt`/`ULong`. Flat `CoreException` subclasses carry empty messages and select localized resources. Rust expected failures carry no attacker-provided text. Poison denies ordinary mutations with `StateUnavailable`, while priority cancellation remains available and queries never recover a possibly partial `Connected` state.

ARM64 Android compilation and 16 KiB ELF alignment are owned by the repository's native build script. Binding generation and native library must use the same UniFFI version. Host tests, generated Kotlin, APK compilation and actual device/72-hour/traffic/battery acceptance are separate evidence; see [validation](docs/validation.md).

