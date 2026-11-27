# LOFT Go VPN and control SDK

Version `0.1.6-LYNX` includes real HyrakenX, Hyraken Pro and SOCKS5 adapters plus the `with_gvisor` Android IPv4 packet stack. Rust owns client business state. The private Android `:vpn` service owns the Go runtime, platform permission, original TUN descriptor and captured underlying Network. Constructing or inspecting either Go runtime performs no network or TUN startup.

The real Java binding package is `net.aptist.loft.engine`:

| API | Contract |
| --- | --- |
| `Engine.newVPNRuntime(SocketProtector)` | Creates one inert owner with mandatory platform callbacks. |
| `Engine.vpnRuntimeInfo()` | Bounded compiled capabilities; active readiness remains false in this description. |
| `VPNRuntime.setNetworkPolicy(String canonicalJSON)` | Idle-only exact schema1, all keys required, max4 KiB; freezes Rust policy epoch/scope/modes before Start, with no I/O. |
| `VPNRuntime.setDNSUpstream(String)` | Legacy idle literal validation only; cannot install or change an authorized policy. |
| `VPNRuntime.start(int fd, String rawNode, String prefix, int mtu)` | Validates private input, duplicates a verified TUN requires an installed canonical policy, and authenticates protected transport before installing the shared privacy packet path. |
| `VPNRuntime.snapshot()` | Credential-free immutable schema-1 JSON with captured Go generation and resource facts. |
| `VPNRuntime.setStateListener(VPNStateListener)` | One coalesced asynchronous listener; the consumer promptly enqueues the captured snapshot. |
| `VPNRuntime.drain(long ms)` | One owned drain waits 1–5,000 ms; caller bound is that wait plus five seconds for cleanup, which remains owned after expiry. |
| `VPNRuntime.abort()` | Shared owned cancellation/completion; caller bound five seconds, retains TUN ownership for Stop. |
| `VPNRuntime.stop()` | Shared owned shutdown; caller bound five seconds and eventual completion remains owned/reconciled after a timeout. |
| `VPNRuntime.close()` | Terminal Stop plus listener-worker termination and join. |

`SocketProtector.protect(int fd)` must call `VpnService.protect` and bind that socket to the captured underlying Network before connect. `resolveNode(String)` uses that Network and returns at most eight literal IPv4 addresses separated by newlines, at most 1,024 bytes, within five seconds. Android uses this callback rather than Go's default resolver. Rust supplies the validated session-local raw URI through its private single-use ticket; it is never included in snapshots or persisted by this SDK.

The platform profile is IPv4 `198.18.0.1/30`, local DNS `198.18.0.2` and MTU1,280. The shared default `node_domain_fake_ip` mode returns synthetic IN-A routing aliases from `198.19.0.0/16` (usable `.0.1` through `.255.254`), restores the original FQDN before actual TCP/UDP OPEN and translates UDP reply addresses. AAAA is explicitly empty for the disabled synthetic family. Unsupported RR/class/DNSSEC DO=1 receives a clear error; EDNS0 DO=0 is supported. Synthetic answers establish neither real resolver addresses nor domain existence.

Explicit `wire_tcp` mode requires a literal IPv4/port and validates actual DNS ID/question/opcode/layout/size before recording a real-wire answer. It uses the selected authenticated client and never falls back physically. The only physical resolver callback is bounded node bootstrap (zero for literal IPv4, one for a domain node); IPv6 node/network data is unsupported. Default DNS and WebRTC policies are mandatory `proxy_only`, with explicit `block` for identified traffic. Unknown encrypted traffic still follows the captured VPN route; this does not hide arbitrary browser-local SDP candidates.

The map is bounded to256 entries/256 KiB. Stable same-domain renewal preserves its address and never shortens the latest advertised deadline. DNS replies atomically acquire a mapping lease before unlocking and retain it through final possible I/O; business copies retain leases until both directions join. The fixed65,534-slot process-owned quarantine table reserves528 KiB, contains only deadlines/slot state and retains no domains, payloads or credentials. Passive allocation recovers slots only after final references and advertised TTL end; exhaustion returns a temporary typed overload/SERVFAIL. Current-map authorization and current proof are required in every epoch. Arbitrary clients ignoring already expired TTLs cannot be distinguished in TCP/IP packets.

Hydra is disabled unless Rust explicitly selects it. The existing X logical-stream and Pro ordinary-TCP shapers are installed before stream/session creation; Pro packet-only XUDP stays unshaped, and enabled Hydra with SOCKS is Unsupported before I/O. Requested/applied scope and actual accepted DATA/PAD counters remain separate. Local nonblocking observations change no wire version, authentication, encryption or pacing.

The snapshot always emits Boolean `ownership_pending`. While it is true, construction/Ready/TUN cleanup still owns resources and zero counters are incomplete facts. `tun_owned` records Go's duplicate only; Android keeps its original descriptor until platform Stop. `resources_released` becomes true only after the actual TUN close, protocol/copy/netstack workers and pending construction/shutdown operations join. A timeout or native close error retains unconfirmed ownership. Unexpected X/Pro peer or TUN reader loss disables forwarding and publishes the captured generation, which cannot reopen or be relabeled into a later Start.

The second 0.1.2 Go source checkpoint follows Root's independently observed X fixture race. Fixture shutdown now completes authenticated Peer.Close and joins its echo workers before closing the UDP transport; ordinary read deadlines are separately tested and cannot stand in for a remote-close receipt. All 431 production Go files and the generated VPNRuntime Java API are unchanged. Fresh full normal/race checks pass114 top-level +145 subtests; the untagged suite passes 86 +140. The original failure, deterministic diagnosis,100 repaired peer-loss repetitions and exact commands are recorded in VERIFICATION.md and .verification/vpn-privacy-peer-loss-freeze-receipt.json. Matching native/APK verification remains Root's release step.

Snapshots always include the25 privacy configuration/enforcement/resource/outcome fields in the root network-privacy contract. `dns_allocator_bytes` is always540672, including idle/closed owners. Stop revokes Ready/enforcement/DNS/RTC/IPv6/Hydra-applied claims before publication and preserves final redacted DNS/bootstrap/shaping totals only after every dynamic producer/worker joins. Those totals remain tied to the old epoch/scope until the next policy or attempt; dynamic map/flow/socket/queued/pending facts are zero. Fixed process metadata remains distinct from released active resources.

| Resource | Admission or deadline |
| --- | --- |
| Pending plus active business/DNS flows | At most 64; byte admission can reject earlier. |
| Physical sockets | X 1; Pro 2 (ordinary plus packet-only XUDP); SOCKS 128 with the shared flow cap. |
| Added mobile memory ledger | 8 MiB total:528 KiB fixed quarantine reservation plus7,847,936 dynamic bytes for mappings/guards/queues/copies. |
| UDP NAT packet queue | 16 slots per association, also subject to the global byte ledger. |
| TCP endpoint buffers | 16 KiB default, 32 KiB maximum per direction. |
| TCP relay copy buffers | 16 KiB per direction; endpoint commitments are reserved before admission. |
| UDP relay reservation | Two64 KiB buffers plus metadata/4 KiB guard; SOCKS reserves a third wire buffer (measured39 admitted UDP associations). |
| Pending TCP forwarder handshakes | 64 at the actual gVisor creator. |
| Node Ready / business open | 15 seconds / 8 seconds; ownership cancellation also joins in-construction work. |
| DNS query / exchange | At most 4 KiB / 8 seconds. |
| Private URI / Go JSON | At most 512 KiB / 64 KiB. |

These are specific owned reservations and queues, not a total Go/Android RSS limit. SOCKS authenticates a real protected UDP_ASSOCIATE during Ready and closes the warm association; subsequent sockets are demand-driven. Its authenticated TUN-ready snapshot can therefore legitimately have `physical_open=0`. SOCKS UDP payload also has to fit its standard address envelope. X fixed-target stream UDP accepts 1–1,024 bytes. Pro UDP/XUDP accepts 0–65,507 bytes; 66,023 bytes is the full XUDP envelope bound.

The preserved local `Runtime` API remains a legacy control boundary. `Engine.newRuntime()`, `Engine.runtimeInfo()` and `Engine.sourceLock()` describe that controller: its `transport_ready=false`, unlinked review flags and typed `loft.engine.data_plane_unavailable` remain accurate for that API. They do not describe `VPNRuntime` capabilities. Its original admission/deadline/drain tests are retained. The legacy [engine/source-lock.json](engine/source-lock.json) identifies 27 reviewed inputs. The real adapter's [third_party/SOURCE-LOCK.json](third_party/SOURCE-LOCK.json) records 440 owned source/module/license/test files, original and owned SHA256 values, and 14 changes/additions in seven explicit patch groups.

The real build uses owned local module replacements. `tools/verify_owned_sources.py` verifies complete owned-byte and patch coverage without reading provenance paths or upstream checkouts. `tools/snapshot_sources.py` refuses to overwrite an existing reviewed snapshot. The Gateway 8.0.36-LYNX source pin is `a984911c8aa0e932c885bb298134031432eb82b7`. Combined Android/Go distribution follows the root GPL-3.0-or-later license and original notices. The independent Rust crates retain their Apache-2.0 metadata.

The lazily loaded Android engine sets process `GOMAXPROCS=2` in its Android-only initializer; `VPNRuntimeInfo` exposes the actual value for JNI verification. Host consumers retain their scheduler policy. The 8 MiB ledger is an explicit reservation/queue limit; no fixed GC soft target or total RSS claim is imposed.

Use pinned Go `1.27.4`, `golang.org/x/mobile v0.0.0-20261117202452-47699113848a`, two build workers, and the root environment script. Host verification commands are:

```bash
source ../scripts/env.sh
python3 tools/verify_owned_sources.py
python3 -m unittest discover -s tools -p 'test_*.py' -v
go test -tags=with_gvisor -p=2 ./... -count=1
go test -race -tags=with_gvisor -p=2 ./... -count=1
go test -p=2 ./... -count=1
go vet -tags=with_gvisor -p=2 ./...
go mod verify
go tool gobind -tags=with_gvisor -lang=java -javapkg=net.aptist.loft -outdir=build/gobind ./engine
```

Use the module-locked generator for a matching AAR; the root pipeline serializes large native/Gradle builds and owns final APK/16 KiB alignment verification:

```bash
LOFT_GOBIND="$(go tool -n gobind)"
export PATH="$(dirname -- "${LOFT_GOBIND}"):${PATH}"
go tool gomobile bind -tags=with_gvisor -target=android/arm64 -androidapi=29 \
  -javapkg=net.aptist.loft \
  -o ../loft-android/app/build/generated/gomobile/loft-engine.aar ./engine
```

The private desktop command bounds an entire file at 1 MiB and at most three matching nodes, rejects empty/unrecognized/oversized input, and emits aliases plus redacted stage classifications. `--mode=protocol` performs the authorized domain HTTPS/DNS diagnostic; `--mode=literal-https` performs the separately authorized host-resolved literal-IP HTTPS transfer, preserving verified SNI/Host, refusing redirects and bounding the body at 4 KiB. Input nodes and receipts are excluded from Git and APK packaging.

[VERIFICATION.md](VERIFICATION.md) records executed host tests, meaningful red/green failures, pinned govulncheck and binding results. ARM64 JNI/TUN/protection, actual Android traffic and DNS, foldable devices, Doze and 72-hour battery acceptance are recorded by the root release independently.

## 0.1.5 transport source refresh

The linked adapter tracks Gateway 8.0.34-LYNX at `a984911c8aa0e932c885bb298134031432eb82b7`. The HyrakenX and QUIC fork upstream trees are byte-identical between the two pins. Hyraken Pro adopts the upstream FIN tail, zero-deadline ownership, stale pooled connection retry and HTTP/2 write deadline changes. The Android adapter retains its protected connection factory, authenticated warmup, explicit resource admission and scoped producer metrics. The legacy Runtime review manifest keeps the historical input it actually reviewed. The real VPNRuntime descriptor reports the linked adapter pin.

## 0.1.6 transport source refresh

Gateway 8.0.36-LYNX brings X authenticated UDP receive buffer reuse and an optional QUIC ECN message path. The mobile adapter supplies the actual UDP socket after Android protection and physical network binding. ECN requires socket option readback and QUIC capability admission. The existing packet path handles platforms and sockets without those options. The release also refreshes the shared Hydra digest with upstream-compatible output. The mobile sender keeps its completion observer, and its existing `SetHydra` call selects upstream's empty-scope behavior. The portable `pkg/hyrakenpro` source tree is byte-identical across 8.0.34 and 8.0.36 and continues to use the mobile authentication and lifecycle patches.
