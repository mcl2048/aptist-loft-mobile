# Resource ownership and acceptance

This is the framework's initial resource contract, derived from the local v3.6 plans. Limits on owned collections do not establish a process PSS ceiling. Protocol buffers, Go/JVM/native allocators, TLS/QUIC/H2, kernel socket queues and the OS remain separately measured costs.

| Work/resource | Owner, trigger and bound | Cancellation/release |
| --- | --- | --- |
| Domain core | One `AppCore` in `:vpn`; the control worker opens the guest store | Dispose after the shared owner has no live work. An Activity recreation preserves the binding |
| Configuration | Rust: 200 nodes/8 MiB retained charge, 512 KiB raw/decoded parser input | Reject atomically and clear temporary owned buffers. Durable configuration stays encrypted across process exits |
| SQLCipher | One connection on the existing serial control worker, 64 MiB maximum database, 2 MiB page cache and bounded restore reads | Transactions precede published mutations. Stop ingress performs priority cancellation independently of disk and Keystore I/O. Final Rust confirmation acquires the state lock |
| UI directory | One node page/50 rows plus bounded selection metadata; APP list page50, current Android11+ launcher-visible discovery | Query/binding epochs reject late results; page changes release rows; PM-reported UID members are frozen exactly, hidden/full-device inventory is not proved |
| Ordinary control | One serial Android worker; 8 queued commands, each at most60 KiB | Queue-full is a typed busy result; Stop/revoke bypass the queue |
| Snapshot delivery | One serialized publisher; at most60 KiB frame, monotonic capture sequence | Visibility unsubscribe and Binder death; explicit sequence exhaustion |
| Node bootstrap resolution | Captured physical Network; one in-flight query, at most8 IPv4 answers/1024 bytes, 5-second deadline | Stop cancels the platform signal; callback executor is bounded and joined |
| TUN | One original Android PFD, one Go-owned duplicate | Failure keeps the original TUN in drop scope; Stop confirms both owners separately |
| Protocol/flow construction | Go leases cover pending, active and retiring resources | Cancel before join; `ownership_pending` prevents early release receipts |
| Physical sockets | X 1; Pro 2 (ordinary 1 plus packet-only 1); SOCKS at most 128 with 64 admitted flows | In-flight and retiring sockets remain charged until closed |
| Business associations | Shared hard admission of64 TCP/UDP associations | Flow copies and protocol owners join before returning leases |
| Added data queues | Shared8 MiB total includes528 KiB/540,672bytes fixed DNS allocator reservation; dynamic session budget is7,847,936bytes, plus finite packet/queue slots | Reserve before allocation, including pending copies; release dynamic owners after final I/O/join |
| Synthetic DNS mappings | At most256 entries/256 KiB inside dynamic budget; stable same-domain TTL renewal retains identity and maximum advertisement deadline | Atomic lookup/lease prevents hostname reuse races; retired/current maps obey TTL/live leases, Stop joins borrowers before clearing dynamic state |
| DNS response I/O | Shared64-operation admission and8-second deadline; prepared A replies own packet buffers plus mapping lease | Final possible write/cleanup extends advertised quarantine; failed/retired reply never reactivates proof or counts as unconfirmed success |
| DNS address quarantine | Process-owned65,534-slot deadline table/cursor/origin, fixed528 KiB reservation; passive allocation only | Preserve valid TTL after dynamic map release, then reclaim; no domain history/timer/periodic restart, process exit releases fixed metadata |
| Drain | Explicit request; maximum5000 ms | Freeze new associations, preserve existing half-close; deadline aborts remaining work |
| Physical transport loss | Captured Go session/generation listener | Revoke readiness and join old generation; never retain cached Ready after loss |
| UI and posture collection | Visibility/window callbacks; no autonomous cloud/scanner/periodic timer | Cancel subscriptions when hidden; no activity retained by native runtime |
| Foreground notification | Ordered service lease; critical state and explicit locale presentation changes only in this framework | Start/stop fence prevents stale update/removal; real permission/channel state is separate from FGS ownership, no new polling |
| Mail notification sink | Compiled boundary, default-denied authority; when enabled by real authority: event2KiB, pending8/32KiB, dedupe128/32KiB | No source/subscription/provider currently exists; scope/permission/expiry changes reset bounded state, event callback never fetches mail |
| Login and mail | Explicit HTTPS work under the existing one-in-flight Hub worker | Scoped deadlines and mail authority checks |
| TOTP and password vault | 200 local entries, at most 30 metadata rows per page, one visible reveal, one camera analysis worker, one explicit sync | The 64 MiB Argon2id allocation belongs to sync. Leaving the screen releases camera and reveal work. D1 holds at most 256 KiB of ciphertext per object |

The transport adapter bounds node Ready to 15 seconds, physical dial/business open/DNS exchange to 8 seconds, and platform node resolution to 5 seconds. Stop bounds its caller wait to 5 seconds and retains an incomplete receipt until late owned cleanup finishes. Abort also has one owned completion job and a 5-second caller bound; Drain bounds its caller to the requested 1–5000 ms wait plus up to 5 seconds cleanup. Ownership remains pending after a timeout until the actual job joins. Android main/Binder Stop ingress must schedule those waits on its reserved cleanup worker after priority cancellation.

The0.1.2 privacy contract separately reports `dns_allocator_bytes` and dynamic `queued_bytes`. An active-resource release receipt can coexist with bounded non-domain address quarantine metadata; it cannot claim whole-process memory is zero. The former cumulative65,534-allocation failure is replaced by TTL/lease-gated passive recovery. Current [full normal/race](../validation/go-0.1.2-checks.json) and [actual Map/Budget RED→GREEN](../validation/dns-advertisement-ttl-review.json) cover exhaustion, renewal, final I/O and dynamic release. These host receipts establish the tested allocation/lifetime behavior, while device PSS/power acceptance remains separate.

`ownership_pending=true` can coexist with a real Running transport while the outer Start owner has not joined. It preserves ownership and delays Ready, without becoming a fault by itself. Direct getters and listener callbacks must share atomic attempt-scoped admission so a late pending snapshot cannot replace settled readiness or release. Caller deadlines do not erase a delayed owner; actual joined facts remain required.

The singleton stores applicationContext; an activeAttempt deliberately retains its VPN Service/protector while real construction/flow/cleanup ownership remains and clears it after join. That bounded ownership is distinct from Activity retention, but neither static-field inspection nor the32 retained lint warnings establish zero leaks or measured PSS. Standard AndroidX startup for Emoji2/lifecycle/profileinstaller remains in the merged APK; current claims of absent background work concern added business polling and unconfigured push SDKs, not every platform initializer.

One final redacted Facts record may survive fully joined Stop until the next policy/attempt. Original epoch/scope and confirmed totals remain, with all active flags false/off and dynamic ownership zero; counter history is not a live proof or a resource owner. No additional timer/task retains or polls it.

TCP forwarding uses two 16 KiB copy buffers and bounded stack buffers (16 KiB default/32 KiB maximum per direction). UDP reserves two 64 KiB buffers plus metadata; SOCKS additionally charges its 64 KiB wire buffer. The byte budget can therefore reject UDP admission before the 64-flow count ceiling; this is an explicit overload result, not an implicit allocation outside the ledger.

The 8-command normal queue is stricter than the design's 32-command ceiling. Its maximum encoded queued bodies fit below the 1 MiB design allowance; active decoded strings and native allocations are additional costs. Larger file imports must use a separately bounded FD path, not a larger Binder transaction.

Go limits apply where resources are created. A protocol option such as `connections=1` does not itself cap pending sockets or packet pools. The source adapter's physical/socket and added-buffer admission must be verified with real construction, loss, overload, Drain/Abort/Stop and close-error tests; consult its source lock and final test receipts. `GOMAXPROCS=2` limits runtime scheduling, not memory. Any `GOMEMLIMIT` value is a GC soft target and must be evaluated with CPU/power rather than reported as total RSS/PSS.

No persistent WakeLock/WifiLock, automatic speed test, cloud polling, mail sync, scanner or forced-GC loop is part of the framework. Existing X/Pro keepalive and timeout behavior is preserved and still has a power cost. Automatic reconnect/candidate replacement, ordinary 60-second notification counters and system-scheduled future background work remain separate verified tasks.

## Device measurements still required

Use the same ARM64 Release APK and reference handset for unconnected, connected idle, four TCP/eight UDP associations, network loss/switch, foreground/background, selected/full routing and Stop. Record both processes' PSS, JVM/native/Go heaps, kernel queues, FD/threads/tasks, CPU/GC and packet wakeups. A software x86 emulator can exercise Android APIs; its host RSS and power cannot establish ARM64 handset budgets.

Freeze numerical steady/peak PSS, idle CPU and incremental battery budgets from measured P0/P1 baselines. Complete 24/48/72-hour checkpoints and at least 8-hour repeated unplugged idle comparisons on Wi-Fi and mobile data, with Always-on/lockdown and Doze scenarios recorded separately. Planned measurements or finite queue tests cannot be marked as executed device acceptance.
