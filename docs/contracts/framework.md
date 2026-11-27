# Framework contract · CoreSnapshot 2 / Android envelope 3

Product `loft`, Android package `net.aptist.loft`, target version `0.1.6-LYNX`. This contract covers the application framework and its VPN resource adapter. Policy JSON and NodePage use schema 1. Their numbers are independent of the snapshot and envelope versions. See the [requirements](../requirements.md) for executed checks and remaining roadmap work.

## Owners and generated boundaries

`loft-core-rust/crates/loft-core` owns validated configuration and business state. `loft-ffi` exports `AppCore` through UniFFI with generated Kotlin in `net.aptist.loft.core.generated` and `libloft_ffi.so`. The private Android `:vpn` owner opens one core and its encrypted local configuration on the serial control worker. Snapshot queries read published state. Kotlin supplies system operations and Go supplies protocol/TUN resources. [Encrypted storage contract](encrypted-storage.md)

Kotlin and native libraries must be generated from the same frozen Rust source and UniFFI version. Bindings are build outputs. The Go `engine` package is generated with the module-locked gomobile/gobind tools and `with_gvisor`; a controller-only build does not contain the VPN stack.

## Local configuration and queries

`importNode`, `removeNode`, `stageServer`, `resetServer`, `setAppRouting` and `setNetworkPrivacyPolicy` return typed failures. The production owner validates and commits changes to encrypted storage before publishing them. `stageServer` normalizes an HTTPS candidate and leaves `serverVerified=false`.

`CoreSnapshot` schema2 is an immutable owned record containing version, at most50 redacted node summaries, full `nodeCount`, server candidate, routing draft, connection state, global generation, attempt ID, active node, confirmed routing and an optional stable VPN failure. It adds a privacy draft/epoch, separate applied policy and actual enforcement state. Summaries omit raw links, usernames, passwords, seeds, PEM and private keys. The snapshot prefix is not the complete directory. [Network privacy](network-privacy.md) defines the matching producer/consumer contract; NodePage remains schema1 and Android publication envelope is3.

`nodePage(offset: UInt, expectedGeneration: ULong)` returns an owned `NodePage` with `schemaVersion`, `generation`, `offset`, full `nodeCount`, up to 50 summaries and optional `nextOffset`. Valid page starts are 0/50/100/150 within the workset; an empty workset permits offset 0. An intervening global generation change returns `StaleGeneration`; malformed offsets return `InvalidNodePage`; a poisoned owner returns `StateUnavailable`. Reading a page neither publishes nor reconciles priority Stop nor advances a generation. The Android page boundary must reject stale binding/request epochs, retain only one page and preserve a stable selected ID plus bounded metadata across pages. Selection is a UI draft; `activeNodeId` remains Rust's confirmed connection.

| Input/resource | Limit and unit |
| --- | --- |
| Raw and cumulative decoded import | 512 KiB each at the Rust parser |
| Retained node workset | 200 records and 8 MiB charged configuration |
| Snapshot/page rows | 50 per response |
| Label | 64 UTF-8 bytes |
| Routing | 100 package names, 255 ASCII bytes/name, 4096 aggregate bytes |
| Server candidate | 2048 input bytes; normalized HTTPS origin only |
| Binder application payload | 60 KiB; 4 KiB reserved beneath the 64 KiB design ceiling |

The existing byte-array import command admits only what fits its 60 KiB envelope. Bounded `ParcelFileDescriptor` import transport and QR remain future work. Import preserves all validated certificate and key material.

## VPN attempt and receipt port

The legacy `connect(nodeId)` validates a target and returns `DataPlaneUnavailable`. Actual service startup calls `beginVpn(nodeId, expectedSnapshotGeneration)` after an OS permission draft bound to that target/generation. The opaque ticket carries attempt/target, frozen routing and privacy draft/epoch, once-only effective-package and actual owner/UID scope freeze, an idempotent immutable canonical policy getter and one-use raw URI. Canonical delivery must precede raw consumption. The URI is consumed only inside `:vpn`, never published over Binder or copied into diagnostics.

Android expands installed shared-UID groups, rejects an enabled empty effective allow-list and calls `Builder.addAllowedApplication` for the actual set. It must reject lockdown/per-app conflicts. A routing edit during a connection stays a draft; it cannot rewrite confirmed `appliedRouting`. This framework does not claim live candidate replacement or automatic TUN rebuilding until that operation has its own tested receipts.

The current Android adapter's expansion and strict UID comparison use the members actually reported by PackageManager. Android11+ discovery is MAIN+LAUNCHER-visible, with no QUERY_ALL_PACKAGES permission; it is not proof that the platform reported every hidden shared-UID member. Freeze the entire reported set without omission, while keeping hidden-package/work-profile/real selected-unselected behavior in the separate device acceptance matrix. Kernel UID routing and a full-device package inventory are different facts.

`markVpnReady` requires a matching current attempt, consumed ticket, exact frozen effective packages and actual UID/profile scope, authenticated transport, ready TUN/protected sockets, matching active privacy epoch/scope/modes/Hydra proof, plus actual IPv4 capture/no-bypass/IPv6 rejection. Only that receipt publishes `Connected`. Importing another node, changing appearance or staging a cloud server does not replace the attempt. Pending/active nodes cannot be removed; old readiness/loss callbacks cannot affect a newer attempt. Saved routing/privacy changes remain separate drafts until an actual replacement attempt applies them.

`markVpnFailed` fences readiness. `markVpnBlocked` additionally requires original-TUN-held and forwarding-disabled facts and records its effective scope. `beginVpnStop` sets priority cancellation outside the ordinary state mutex. `confirmVpnStopped` requires Android's original TUN closure and Go's confirmed duplicate/resource release before clearing the scope and publishing `Disconnected`. A Close call or zero counter alone is not a release receipt. Poison projects `Unavailable` from immutable published metadata; the adapter must abort actual forwarding even if the core cannot accept another mutation.

## Private Android transport

The non-exported controller and the OS `BIND_VPN_SERVICE`-protected VPN entry share the same `:vpn` owner. Binder callers must match the application UID. Commands, snapshots and page replies are bounded binary byte arrays with strict UTF-8, length, schema and trailing-byte checks. Go's separate resource receipt is bounded JSON: require exact names/types, canonical integers and complete consumption, including rejection of trailing raw NUL, duplicate/case-alias/unknown/missing/null fields. A generic JSONTokener end sentinel does not establish consumed input.

The single snapshot publisher reserves its transport sequence before capturing Rust metadata and encoding. A consumer checks binding epoch and sequence as well as business generation, so a late equal-generation `Connected` capture cannot replace a newer `Stopping`/`Unavailable` projection. Sequence exhaustion is explicit. Page responses use a separate query/request fence and cannot overwrite business connection state.

Normal work uses a bounded serial worker. Stop/revoke signals bypass that queue and cancel socket resolution/construction before joining their owners. UI subscriptions follow visibility; unbinding/recreating an Activity does not stop an active VPN. Notification publication and service foreground ownership are ordered with start/stop attempts.

The overview reads app-payload totals through a separate same-UID Binder query on the ordinary worker. Live samples require the current Rust attempt and matching settled Go/TUN/privacy evidence. Final samples require joined Go and original-TUN closure. The wire callback carries a matching attempt ID, two nonnegative byte totals and a final flag. This leaves the strict lifecycle schemas independent of display statistics. TCP counts bytes accepted by the actual peer writer after privacy classification. UDP counts successfully written application datagrams. The counters cover app payload and exclude the dedicated DNS handling path and transport framing. Sampling has no timer.

## Go resource boundary

`NewVPNRuntime(SocketProtector)` is inert. `SocketProtector.protect(fd)` validates the actual socket, binds it to the captured non-VPN physical `Network` and calls `VpnService.protect` before use. `resolveNode` supplies bounded literal IPv4 results for node bootstrap only. Business domains and DNS do not silently fall back to Android physical DNS.

`VPNRuntime` exposes Start, Snapshot, SetStateListener, idle-only SetNetworkPolicy/SetDNSUpstream, bounded Drain, Abort, Stop and Close. A current canonical network policy is installed before Start. Start duplicates the verified TUN descriptor; Android retains ownership of the original. Resource snapshots include `ownership_pending`: construction and cleanup must finish before `resources_released=true`, even when counters are zero. Drain freezes new admission with a bounded deadline; Abort disables forwarding and closes affected protocol work while Android retains the original TUN; Stop closes the Go duplicate and joins workers. Original-TUN closure remains a separate Android receipt. Fixed non-domain DNS quarantine metadata is separately charged/reported and is not an active socket/flow owner.

The real Go constructor may publish Running with authentication/TUN/protection facts while `ownership_pending=true` until its outer Start owner joins. Android must wait for settled ownership without faulting this legal intermediate state. Listener callbacks and direct post-Start snapshots arrive independently: atomically compare/commit one attempt-scoped lifecycle floor so a late startup/pending frame cannot replace settled Ready or joined closure. Actual loss and invalid settled proof still fence admission; Rust remains the only business-state authority. [Producer observation](../validation/go-running-pending-observation.json) and the current source/build/runtime receipts record this boundary.

The stack forwards IPv4, explicitly drops IPv6 in VPN scope and exposes synthetic DNS at `198.18.0.2`. The0.1.2 default is node-domain Fake-IP routing: return a bounded synthetic alias and restore the original FQDN before the selected proxy OPEN. These are routing answers, not validated public resolver answers. Explicit `wire_tcp` uses an approved literal IPv4 resolver over the selected proxy and validates real answers separately; historical failures on that path remain failures without physical fallback. Authentication/literal-IP TLS cannot establish DNS acceptance. Actual query→alias→original-hostname TLS/HTTP200 and bootstrap-only physical resolution are required; neither test substitutes for node-side DNS/Firewall policy receipts.

X preserves fixed-target application UDP 1–1024 bytes. Pro preserves 0–65,507-byte application UDP, including empty packets; 66,023 bytes is the XUDP envelope ceiling. SOCKS5 capability/authentication and TCP/UDP are tested independently; SOCKS5 has no tunnel encryption. Protocol implementations remain source-pinned adapters, including their existing TLS and authenticated cryptography.

## Optional modules and verification boundary

Anonymous startup is local. The Hub uses origin-bound public discovery, explicit activation, user-triggered browser sign-in and scoped, read-only mail. Its private service boundary keeps Portal client secrets and Portal bearers on the server. The persistent native module rail uses icons with localized spoken names and a selected state. Pixel/Samsung Fold, TalkBack, Always-on/Doze, battery and 72-hour acceptance require their own device evidence. [Hub contract](hub.md)

Read `docs/contracts/resources.md` for task/resource ownership and `docs/validation/` plus the task report for executed tests, failed attempts and unverified limits. Compilation, host reducers/packets, Android TUN execution and physical-device acceptance are distinct claims.
