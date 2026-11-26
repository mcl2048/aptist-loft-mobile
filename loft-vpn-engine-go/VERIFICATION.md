# Go shared privacy source verification · 0.1.2-LYNX · 2026-11-26

The current source adds one shared DNS/WebRTC admission/packet boundary to the real X, Pro and SOCKS VPN adapters. It defaults to node-domain Fake-IP, restores genuine FQDN targets and translates UDP replies. Optional wire_tcp has an explicit literal endpoint and validated wire replies; neither mode falls back to physical business DNS. Hydra remains Disabled unless Rust selects its existing sender hooks. This is verified source/host behavior. Matching native libraries, APK/JNI, Android VPN DNS/UID routing and handset acceptance remain root-owned release steps.

Root's independent normal check invalidated the first 0.1.2 freeze after TestUnexpectedPeerLossRevokesReadinessAndStopsNewBusinessOpens/X failed. Root preserved its exact 497-file source archive, first freeze and original failed log/receipt in tmp/verification/root-0.1.2. The second source checkpoint repairs the demonstrated fixture shutdown race and adds actual shutdown/deadline controls. All 431 inventoried production Go files, source pins and API contract remain byte-identical to the first freeze.

The0.1.1 section below is a preserved historical checkpoint. Its default resolver,42-association capacity and earlier native/source identities do not describe current0.1.2 behavior. Current command/log/exit/hash receipts are under .verification/x-peer-loss-investigation/.

| Actual current check | Result and receipt |
| --- | --- |
| go test -tags=with_gvisor -p=1 ./... -count=1 -json |114 top-level +145 subtests,0 failures; full-normal-final.receipt.json. |
| go test -race -tags=with_gvisor -p=1 ./... -count=1 -json |114 +145,0 failures/races; full-race-final.receipt.json. Both include max-expiry and atomic resolve/lease fixes and the repaired X fixture. |
| go test -p=1 ./... -count=1 -json |86 +140,0 failures; full-no-tag-final.receipt.json. |
| gofmt -l engine internal / go vet -tags=with_gvisor -p=1 ./... |Exit0, empty diagnostics; fmt-final.receipt.json / vet-final.receipt.json. |
| golangci-lint v2.15.0, with_gvisor, concurrency1 |Exit0,0 issues; lint-final.receipt.json. |
| Explicit normal/race checks of linked pinned dependency packages |29 production-linked packages, both exit0; linked-normal-final.receipt.json / linked-race-final.receipt.json. Pro framed-producer regression1 top-level/2 subtests runs in both; the other 28 packages contain no package tests. The main suite exercises real X/Pro/SOCKS behavior. |
| go mod verify / go list -m -json all |All modules verified;58 resolved modules, seven owned local replacements; mod-verify-final.receipt.json / module-graph-final.receipt.json. |
| Owned source verifier / Python source-tool tests |434 files,12 changes/additions in six patch groups; seven behavior tests, exit0; owned-source-final.receipt.json / source-tests-final.receipt.json. No provenance checkout is opened. |
| govulncheck v1.10.0, with_gvisor |Exit0, No vulnerabilities found; govuln-final.receipt.json. |
| Module-locked gobind Java/JNI generation |Exit0; gobind-final.receipt.json. VPNRuntime.setNetworkPolicy(String canonicalJSON) throws Exception verified in actual generated Java; VPNRuntime.java is byte-identical to the first generation. This is API generation, not an AAR/APK claim. |

All Go commands use the root-pinned Go1.27.4 environment, GOTOOLCHAIN=local and process GOMAXPROCS2, with one coordinated Go build worker. The new formal source receipt is .verification/vpn-privacy-peer-loss-freeze-receipt.json. Preserve .verification/vpn-privacy-freeze-receipt.json as the first 0.1.2 checkpoint and .verification/vpn-freeze-receipt.json as0.1.1. Root controls independent review and matching ARM64/isolated x86 native builds.

The X fixture originally canceled its accept loop and closed the shared listener at the same time. Transport destruction could win before deferred Peer.Close; QUIC then used immediate destruction without sending CONNECTION_CLOSE. The client Read returned an ordinary *quic.deadlineError, Timeout=true, and the client watcher had no remote terminal receipt. The former assertion accepted any read error and misinterpreted the one-second deadline as remote closure. The repair joins server Peer.Close and all echo workers while the UDP transport is alive, then closes the listener. The assertion rejects a deadline and independently checks the X connection's remote authenticated terminal error. The existing 300 ms readiness expectation and every production keepalive, timeout and protocol window are unchanged.

Preserved diagnosis includes baseline-repeat.receipt.json (20 ordinary repetitions passed, confirming intermittence), diagnostic-repeat.receipt.json (2 of 30 original-schedule diagnostic iterations reproduced the exact failure), and deterministic-silent-red.receipt.json (all 3 forced transport-first iterations failed on the deadline assertion, with the original canceled-stream teardown symptom). Overlay source hashes and raw logs are retained; no diagnostic hook entered production source. Real socket-disappearance versus explicit Peer.Close controls and an ordinary deadline followed by a successful echo passed 10 repetitions before the repair. The repaired original peer-loss test then passed 100 repetitions across X/ProTCP/ProGRPC (100 top-level +300 subtests), recorded in peer-loss-green-repeat.receipt.json. Full normal/race suites include these controls. Silent UDP disappearance is not an authenticated peer CLOSE; existing protocol liveness detection remains the authority for that path.

The exact cross-language input/output list is API-CONTRACT.json:13 exact policy keys, eight exact Hydra keys,39 required Go snapshot keys plus optional error_code. DNSAllocatorBytes always reports540672; total added memory remains8388608 with7847936 dynamic bytes. Map entries are at most256/256 KiB. Guard state is charged before admission; SOCKS UDP now measurably admits39 associations with its third wire buffer and guard reservation. These bounds do not measure Android PSS or power.

Current actual host packet acceptance covers X/Pro/SOCKS EDNS0 DO=0 UDP and TCP IN-A → same synthetic address/TTL60 → exact original FQDN OPEN → hostname-verified certificate/TLS/HTTP200 → reverse translated UDP → Stop. X preserves1/512/1024; Pro0/1/1232/65507; SOCKS0/1/1232/65491 includes its FQDN wire envelope. Synthetic and validated-wire totals remain separate; literal node bootstrap and business physical resolver totals are0 in these tests. Separate domain-node actual authentication records one physical bootstrap callback.

Relevant failures were preserved before correction:

| RED receipt | Root cause and checked correction |
| --- | --- |
| privacy-red-exact-keys-ttl.log |Case-folded/missing/null JSON and stable TTL address churn; exact required keys/types and retained stable identity. |
| privacy-red-recoverable-pool.log |Cumulative permanent address exhaustion; bounded slot quarantine recovers only after TTL/final leases. Full-pool, refreshed TTL and lease-past-TTL cases execute196k bounded simulated allocations. |
| privacy-red-runtime-api-final.log / privacy-red-actual-fqdn-packet.log |Policy port and installed enforcement absent; stored configuration remains inactive until authenticated selected source and actual packet/filter installation. |
| privacy-red-pro-producer-metrics.log |Caller-side metrics omitted actual completed records; producer full/partial framed AEAD socket checks now count only accepted DATA/PAD boundaries. |
| privacy-red-dns-reply-lease.log |Pending synthetic reply lost its mapping and advertised TTL started before final I/O; atomic lease and conservative last-possible-write quarantine now retain it through completion/retirement. |
| privacy-red-runtime-final-receipts.log |Stop published cached active protection and discarded joined totals; priority cancellation precedes publication and final redacted totals stay in the original scope until the next policy/attempt. |
| privacy-red-ipv6-bootstrap.log |Skipping literal resolution accidentally bypassed IPv6 rejection; literals and resolved node answers require IPv4 before platform networking. |
| privacy-red-packet-denial.log |Closing an admitted blocked UDP flow forgot STUN identity for later empty packets; policy drops retain association classification until its existing idle deadline or Stop. Actual fragmented TCP denies every prohibited byte. |
| privacy-red-late-renewal-runtime.log |Late captured renewal shortened a newer final-write deadline; renewal takes the maximum. AtomicResolveLease pins identity before releasing the map lock. Root separately preserved isolated baseline/patch stdlib evidence. |

Actual packet denial, independent TCP reply probes, malformed/unsupported/DNSSEC input, bounded wire layout/ID/question checks, stable renewal, stale/retired leases, concurrent retirement/advertisement, final Runtime.Stop totals/reset, pending construction/copy/producer joins, peer/TUN loss, and historical mature packet/FIN/empty/max behavior run in the affected suites. Old full-suite failures from literal-node held-resolver fixtures, malformed4096-byte pseudo-DNS and the prior42 capacity were preserved in privacy-normal-integration-1.jsonl and replaced with genuine domain-node/valid bounded EDNS/correct39 fixtures. The first otherwise successful TLS packet test's deferred closeNotify after explicit Stop was an over-strict test cleanup expectation; its failure remains privacy-actual-fqdn-cleanup-failed.log.

An extra broad sweep of every nested HTTP/3 package failed setup because unlinked github.com/quic-go/qpack0.6.0 lacks a main-module go.sum entry. Both privacy-modules-normal-final.log and privacy-modules-race-final.log preserve that attempt. H3/QUBF is outside the linked mobile graph; no dependencies or wire capability were added to hide the gap. Only exact linked-path normal/race checks are claimed.

The usable fake range is198.19.0.1–198.19.255.254, separate from198.18 TUN/DNS controls. All valid advertisement TTLs and active leases remain pinned; current-map authorization/current proof is required across epochs. Stop releases every dynamic owner, keeps only the fixed no-domain/no-payload quarantine table, and retains final requested Hydra settings/totals as inactive scoped history. Arbitrary applications ignoring expired TTLs cannot be identified from TCP/IP alone. Network-path enforcement does not hide arbitrary local SDP candidates or absolutely classify opaque TURN/TLS on unknown443. Hydra shaping is not DNS enforcement or reconnect repair.

Private authorized host DNS/HTTPS probes remain historical evidence, with failed public DNS paths retained. Synthetic aliases never become fabricated real9.9 answers or proof of domain existence/deployment policy. No private task/token/node/URI/key is copied into these source/receipt fixtures. Real UID/IPv4/IPv6 capture/no-bypass is Android/Rust authority; handset/Fold/Doze/PSS/battery/72-hour acceptance is not inferred from host suites.

# Preserved0.1.1 checkpoint

# Go VPN SDK verification · 0.1.1-LYNX · 2026-11-25

The real extension uses pinned X/Pro/SOCKS transports and the actual gVisor IPv4 stack over controlled host packet links. Rust remains business authority and Android owns its original PFD, VpnService protection and captured underlying Network. Host policy callbacks, a controlled packet link and desktop node probes establish their executed layers; they do not establish Android TUN/protection, deployed DNS policy or device/battery acceptance.

All Go commands used Go 1.27.4, GOTOOLCHAIN=local, GOMAXPROCS=2 and GOFLAGS=-p=2 from the root environment. The Android-only engine initializer additionally applies runtime.GOMAXPROCS(2) to the lazily loaded handset process. VPNRuntimeInfo exposes the actual scheduler value; host runtime policy and a total RSS limit are separate. No fixed GC soft memory target was imposed.

Executed final checks:

| Command or boundary | Result |
| --- | --- |
| `go test -race -tags=with_gvisor -p=2 ./... -count=1 -v` | 76 top-level tests and 31 subtests passed; no reported race, exit 0. |
| `go test -tags=with_gvisor -p=2 ./... -count=1` | All test packages passed, exit 0. |
| `go test -p=2 ./... -count=1` | Default build and explicit unavailable boundary passed, exit 0. |
| `go vet -tags=with_gvisor -p=2 ./...` | No diagnostics, exit 0. |
| golangci-lint v2.15.0, with_gvisor, concurrency 2 | 0 issues, exit 0. |
| `go mod verify` | All modules verified, exit 0. |
| `go list -m -json all` | 58 resolved modules; all seven local replacements resolve inside the owned third_party tree. |
| `python3 tools/verify_owned_sources.py` | All 433 owned files and eight modifications/additions verified; five explicit patch groups, no provenance path read. |
| Python source-tool suite | Seven behavioral tests passed: tamper/missing patch/inventory/path/symlink rejection, clean-checkout verification, and snapshot overwrite prevention. |
| `go tool gobind -tags=with_gvisor -lang=java -javapkg=net.aptist.loft ... ./engine` | Final Engine/VPNRuntime/SocketProtector/VPNStateListener Java/JNI API generated, exit 0. |
| govulncheck v1.10.0, `-tags=with_gvisor ./...` | No vulnerabilities found, exit 0; Go 1.27.4, vuln.go.dev DB updated 2026-11-24 15:56 UTC. |

Logs are ignored `.verification/vpn-full-race.log`, `vpn-full-tests-final.log`, `vpn-no-tag-tests.log`, `vpn-vet.log`, `vpn-lint.log`, `vpn-mod-verify.log`, `vpn-module-graph.json`, `vpn-owned-source-lock.log`, `vpn-green-source-tools.log`, `vpn-gobind-final.log` and `vpn-govulncheck-final.log`. The original controller tests remain included. Historical 95.9% coverage below applies to the controller checkpoint, not to the complete VPN extension.

Meaningful failures were reproduced before their fixes:

| Behavioral red evidence | Observed defect and verified correction |
| --- | --- |
| `vpn-red-close-ready.log`, `vpn-red-close-business.log` | Close returned while platform resolution or a SOCKS protected socket open remained owned; cancellation now joins Ready and business construction before seed clearing. |
| `vpn-red-peer-loss.log`, `vpn-red-session-loss.log` | X/Pro/gRPC peer loss retained cached Ready or failed to reach the listener; one captured loss now disables forwarding and prevents same-generation reconnect. |
| `vpn-red-stop-ownership.log` | 64 concurrent Stop callers created 122 extra goroutines; a timed-out Stop never reconciled later completion. One owned completion now joins and publishes actual release. |
| `vpn-red-listener-join.log`, `vpn-red-pending-start.log` | Close confirmed release with a callback in flight; pending Start exposed incomplete zero facts. Terminal listener join and always-emitted Boolean ownership_pending now gate release. |
| `vpn-red-native-close.log`, `vpn-red-startup-cleanup.log` | Native TUN close errors were discarded, including during failed Ready cleanup. The owner remains retained with a redacted unconfirmed error. |
| `vpn-red-preinstall-loss.log` | A peer dying between authentication and installation was accepted as running. Captured startup loss now fences Start itself. |
| `vpn-red-pending-handshakes.log` | Real admission limited 65 SYNs to 64 owners, but Abort blocked on the TCP handshake mutex. Netstack shutdown now interrupts handshakes before flow close. |
| `vpn-red-copy-join.log`, `vpn-red-expiry-claim.log` | A cancellation winner consumed one of two worker results and released bytes early; an expired pending timer could be claimed. Both copy owners join and expired timer claims are rejected atomically. |
| `vpn-packet-udp-ipv6.log` | The first zero-length actual UDP packet was interpreted as stream EOF. The owned NAT copy preserves an empty datagram; Pro IPv4 0/1/1024/1232/65507 round trips and fragmentation/reassembly now pass. |
| `vpn-red-socks-buffer-admission.log`, `vpn-red-dns-wire-budget.log` | SOCKS wire storage and the extra framed DNS query copy were omitted from reservations. The shared byte ledger now includes them before allocation. |
| `vpn-red-abort-deadline.log`, `vpn-red-drain-caller-deadline.log` | Delayed real I/O could outlive the caller without a deadline. Abort is bounded at five seconds; Drain is bounded at its requested wait plus five seconds cleanup. Owned jobs remain and Stop joins them. |
| `vpn-red-probe-input.log`, `vpn-red-probe-mode.log`, `vpn-red-literal-https.log` | Empty input succeeded, whole-file input was silently truncated, wrapped diagnostic causes were lost, and literal mode/verified bounded transfer were missing. The actual command now rejects these failures and keeps diagnostic modes explicit. |

The final real host boundaries cover X mTLS/QUIC, Pro TLS/TCP and custom gRPC, SOCKS username/password and UDP_ASSOCIATE, physical protection callback rejection/admission, X UDP 1–1024 and Pro UDP/XUDP 0–65507, SOCKS envelope-safe payloads, and real blocked-read cancellation. Actual IPv4 packets traverse X, Pro and SOCKS adapters, preserve TCP FIN/late reverse data, keep UDP boundaries and release all owned flows/bytes on Stop. Additional tests exercise IPv6 drop, synthetic UDP DNS carried as proxy TCP framing, successful and expired packet Drain, half-open TCP64, pending Start/Stop/Close, stale generation callbacks, close errors, timeout receipts and late completion.

The resource ledger is specific: 64 business/DNS owners; X 1 / Pro 2 / SOCKS 128 physical socket admissions; TCP default 16 KiB / max 32 KiB per direction plus 16 KiB relay copies; UDP two 64 KiB relay buffers plus metadata, with a third SOCKS wire buffer; NAT queues 16 slots and shared 8 MiB rounded payload/metadata accounting. Byte admission can reduce capacity below 64 (SOCKS UDP reservations admit 42). Ownership_pending is always emitted and makes forwarding disable/resource release unconfirmed until construction joins. Tun_owned refers only to Go's verified duplicate; Android retains its original PFD. Native close errors and caller timeouts never imply full closure.

Private probes used the user-supplied file only as runtime input. Safe alias-only receipts are `node-probe.stdout.json`, `node-dns-diagnostic.stdout.json` and `node-literal-https.stdout.json` in ignored `.verification/`. No private endpoint, URI, seed, certificate/key PEM or task token appears in these reports or source. Both aliases authenticated and transferred verified domain-target HTTPS. Default TCP DNS ended `tcp_read_length:eof`; UDP DNS ended `udp_read:timeout`; one separately requested DoH attempt per node ended `doh_https:rejected`. The first resolver wrapper failure and first default DNS failures were retained rather than replaced by later evidence. Read-only Gateway guard review describes source behavior; deployed policy was not inferred.

The separately authorized literal-only run resolved example.com through an explicitly host-only diagnostic resolver, then preserved verified SNI/Host through the selected proxy to its literal IP. Both aliases completed HTTP 200 bodies of 577 bytes with SHA256 `25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484`; each physical peak was 1 and physical/resolver admissions after Close were 0. TUN and Android protection flags were false; VPN DNS/UDP/DoH flags were false. No DNS/DoH attempts were repeated in this run and no DNS acceptance follows from it. An approved reachable production DNS endpoint remains pending.

A matching transitional ARM64 AAR was built with with_gvisor/API 29, exit 0, containing classes.jar and arm64 libgojni.so (11,083,685 bytes). It preceded the final lifecycle/version/scheduler changes and is compilation-barrier evidence. Root owns the final matching native rebuild, APK/JNI/16 KiB alignment, Android VPN instrumentation, real protection/routing/DNS/UDP, foldable devices, Doze and 72-hour battery evidence. Host packet links are not kernel Android TUN descriptors or device acceptance.

Copied source includes original GPL sing-tun/Ghost notices, X/Pro/historical crypto notices and the referenced ASCON CC0 text, plus QUIC MIT/provenance. Combined Android/Go licensing is compatible with the root GPL-3.0-or-later delivery; independent Rust crates retain Apache-2.0 metadata. The eight explicit mobile changes preserve existing wire/TLS/seed/cryptographic implementations. No independent mobile cryptographic audit is implied. `engine/source-lock.json` is explicitly scoped to the preserved legacy controller's 27 reviewed inputs; current adapter inventory and compiled linkage are `third_party/SOURCE-LOCK.json` and VPNRuntimeInfo.

The historical checkpoint follows only as retained evidence of the original controller work.

# Historical 0.1.0 controller checkpoint · 2026-11-25

Scope: the local gomobile-compatible engine-control package. Tests exercise actual admission accounting, contexts, finite timers, cancellation workers, concurrent owners and lifecycle transitions. Their inputs are synthetic local byte budgets; they provide no Android or upstream protocol execution evidence.

All Go commands used `/home/coder/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin/go`, `GOMAXPROCS=2`, `GOFLAGS=-p=2` and `GOTOOLCHAIN=local`. The pinned toolchain directory was prepended to `PATH` for tools that invoke Go internally.

The tests were written before their implementation. Initial missing APIs produced compiler failures; subsequent behavioral red runs demonstrated these missing effects:

| Red run | Observed failure | Exit |
| --- | --- | --- |
| `red-info.log` | Missing schema/version description | 1 |
| `red-source-lock.log` | Missing reviewed source pin/manifest | 1 |
| `red-admission.log` | 128 concurrent callers admitted; no 64-slot guard, byte guard, terminal close or owned cancellation | 1 |
| `red-owned-cancellation.log` | A real worker stayed uncanceled; a forgotten owner retained its slot past deadline | 1 |
| `red-drain.log` | No drain admission gate, deadline cancellation, signed deadline validation or abort cancellation | 1 |

The full green suite covers 20 top-level tests and 10 subtests, with no failures or skips. The cancellation cases use real contexts and workers, while lifecycle races run simultaneous admission/close and repeated operation close/cancel. Drain completion, timeout, duplicate-drain rejection, Close/Abort/Stop interruption and old-generation callbacks have separate assertions.

| Final command | Observed result |
| --- | --- |
| `go test -p 2 ./... -count=1 -v` | 20 top-level tests + 10 subtests passed, exit 0 |
| `go test -race -p 2 ./... -count=1 -v` | Same suite passed, no reported race, exit 0 |
| `go test -p 2 ./... -count=1 -coverprofile=.verification/coverage.out` | 95.9% statement coverage, exit 0 |
| `go tool cover -func=.verification/coverage.out` | Local package function coverage reported, exit 0 |
| `go vet -p 2 ./...` | No diagnostics, exit 0 |
| `gofmt -l engine` | No unformatted file, exit 0 |
| `golangci-lint run --concurrency=2 ./...` | 0 issues, exit 0 |
| `go mod verify` | All modules verified, exit 0 |
| `go tool gobind -lang=java -javapkg=net.aptist.loft -outdir=.verification/gobind ./engine` | Generated Java/JNI bridge sources successfully, exit 0 |
| `go tool gomobile help bind` | Confirmed Android AAR, architecture and Java package-prefix usage, exit 0 |

Generator output confirmed `net.aptist.loft.engine.Engine`, `Runtime` and `Operation`, including the service-used factory, snapshot, ready flag and close/stop methods. The generated Java API was communicated to the Android owner. No AAR build was run by this subtree owner; the root integrator coordinates its SDK/NDK compilation and app packaging.

Dependency provenance: `golang.org/x/mobile v0.0.0-20261117202452-47699113848a` was resolved through the Go proxy, downloaded and checksum-verified. Its module sum is `h1:jYIfLfiCY1/N6kWqBdUak4c1kMN0vKnoQypLZqbGqv4=` and go.mod sum is `h1:1CQzXnNaNFpaGQOu1QBn5fRZ42ceIiowGw2aQ0I36G4=`. `go mod tidy` emitted one transient HTTP/2 `received DATA after END_STREAM` diagnostic during tool-dependency download and subsequently completed with exit 0; `go mod verify` passed afterwards. The lockfile includes x/mod `v0.43.0`, x/sync `v0.25.0` and x/tools `v0.53.0`.

Lint used the official golangci-lint `v2.15.0` Linux AMD64 binary, built with Go `1.27.0`. The downloaded archive SHA256 was checked against both release metadata and the published checksum manifest: `9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea`. The checksum manifest SHA256 was `364f56cb7ef4555e42bb1754b432b0f40bd914477d962c5888c8a8b5378ce8b6`. The binary and cache remain in the ignored `.verification/` directory.

Source-lock generation checked 27 listed Gateway source files byte-for-byte against `git show 231f14813f2b45cb6f0bde984181c57cba1d02fd:<path>`, then recorded their SHA256 values. The manifest is 8,475 bytes. Source files, private configurations and credentials were not copied or changed. No Gateway/Portal tests, external network sessions or production identity requests were executed.

Local logs and generated artifacts live in ignored `.verification/`; the following SHA256 receipts preserve the observed red/green evidence:

| Log | SHA256 |
| --- | --- |
| `red-info.log` | `9289fc51f54aad1e2e9ae74cb01318e3ae3a1dc65b4433ff4cef49438b6b08e2` |
| `red-source-lock.log` | `d70b5884195cbcc4ad672ae14079a67ce061603dd62d289ead733b35e09d7a8a` |
| `red-admission.log` | `135cdeec1ce7ac2a38f30b90d73838fd3daebf90a4b9becdd1e35141b79251c8` |
| `red-owned-cancellation.log` | `cb5bda9a0d36e0f1e4ceb197249a01a642a80538535eae16c3171d5ee3f89315` |
| `red-drain.log` | `80b7cf9f5877e305081a26f0b86d7fdb7c7c35c7d59687c57a63b47669283cee` |
| `green-info.log` | `856e9fb0ffbe196363db2c626a62e1d9b1da77c6b072f4fb11e55b28276e20dd` |
| `green-admission.log` | `9a0e608685a5b95f6b6dbd0354a5fa32ed61d0141e29722063c77127a9970d48` |
| `green-drain.log` | `4bc5d06b6050c32d1d46c7d2a0e39ec0b729f71b202758917ceb9e4ddf7ab547` |
| `race.log` | `23b3f010e9a415af0daa087b23f0c4b9a1a14fbde348cbb72b2adeb78e623c28` |

At that historical checkpoint, protected protocols, physical-FD admission, TUN/flow conversion and VPN lifecycle were still pending. The 0.1.1 extension above implements and verifies the host boundaries; Android/device prerequisites remain separately scoped. A source pin, a configured pool, control cancellation or a successful binding generator does not establish those properties. ARM64 Android JNI execution, 16 KiB ELF alignment, route/DNS/IPv6/UDP semantics, device memory/FD trends, Doze and 72-hour battery results require separate release/device evidence.
