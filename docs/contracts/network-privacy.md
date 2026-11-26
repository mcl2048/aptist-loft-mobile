# Shared VPN network privacy contract

Target: 0.1.2-LYNX. This records the frozen cross-language contract; actual passing source/artifact identities belong in the validation report. The architecture decision is [vpn-network-privacy](../decisions/vpn-network-privacy.md).

## Versions and ownership

Rust owns `NetworkPrivacyPolicy`, its independent nonzero uint64 policy epoch, the draft and applied records, and the effective enforcement state. `CoreSnapshot` is schema2; Android's publication envelope is3; `NodePage` remains schema1. These schemas do not change either protocol's wire version. Producers and consumers reject incompatible schema/length/trailing data rather than assume an old payload contains a policy proof.

Kotlin supplies actual installation/UID and Android TUN facts. Go implements the shared DNS/flow/packet enforcement before the chosen transport adapter. Protocol selection cannot select a less protected path. Future QUBF/Hyraken adapters must enter the same enforcement/ownership boundary.

## Scope and ticket freeze

`freezeEffectivePackages` freezes the complete expanded installed/shared-UID package set once. `freezeNetworkScope(NetworkScopeIdentity)` then freezes the service owner's actual UID plus the complete package/UID pairs once. Pairs are sorted and unique, match the full effective set exactly, obey the 100-package/4096-name-byte limits, and belong to the same Android user/profile as the service owner. Full mode uses an empty pair set plus the actual owner UID; it does not mean an unknown installation scope.

Rust derives a 64-character lowercase SHA256 scope ID from the attempt, selected node, routing mode, owner/pairs, epoch and normalized policy with explicit field boundaries. This is a local correlation identity, not a remote signature or device attestation. Kotlin rechecks the installation/UID facts before Builder, after establishment and before Ready. A mismatch priority-stops that captured attempt.

Only a fully frozen live ticket returns its immutable canonical policy and releases the one-use raw node URI inside `:vpn`. Canonical policy reads are idempotent while the ticket is live; raw-node delivery is single-use and requires prior canonical delivery. Neither the URI nor the full UID mapping is published as a diagnostic. Go's `VPNRuntime.setNetworkPolicy(canonicalJson)` is inert and idle-only; replacing an active policy is rejected. UI policy changes remain separate drafts until a new actual attempt applies them.

## Canonical Go input

JSON schema1 is limited to4096 bytes. All fields, including false/zero Hydra fields and the empty resolver endpoint in synthetic mode, are required by their exact names. Reject duplicate/case-alias/unknown/missing/null fields, wrong types, unsupported protection modes, depth/size excess and trailing values. The policy epoch is an exact nonzero uint64 decimal string, preserving values above2^53. `scope_id` is64 lowercase hex.

```json
{
  "schema_version": 1,
  "policy_epoch": "1",
  "scope_id": "0000000000000000000000000000000000000000000000000000000000000000",
  "dns_mode": "node_domain_fake_ip",
  "dns_leak_policy": "proxy_only",
  "webrtc_policy": "proxy_only",
  "resolver_endpoint": "",
  "dns_map_max_entries": 256,
  "dns_map_max_bytes": 262144,
  "dns_ttl_seconds": 60,
  "dns_max_query_bytes": 4096,
  "dns_max_response_bytes": 65535,
  "hydra": {
    "enabled": false,
    "auto_jitter": false,
    "rotation_seconds": 300,
    "rotation_jitter_percent": 0,
    "chunk_min_percent": 0,
    "burst_min_records": 0,
    "burst_max_records": 0,
    "padding_gap_max_records": 0
  }
}
```

The zero scope above demonstrates shape only; the APP sends Rust's actual derived scope. DNS mode is `node_domain_fake_ip` or `wire_tcp`; leak policies are `proxy_only` or `block`, never allow/off. Synthetic mode has no external resolver endpoint; wire mode needs an explicit validated literal IPv4/port. Hydra defaults Disabled, and has a separate actual installed/scope receipt.

## Actual enforcement proof

Ready requires the consumed current ticket, complete effective package freeze, exact policy epoch/scope/modes and matching applied Hydra scope, plus authenticated selected transport, ready TUN, protected sockets, actual IPv4 capture, no bypass and IPv6 rejection. Go proof is bound to the real ready client/session and cannot be created from a cached controller state. An ownership-pending or inactive proof cannot publish Connected.

The Go constructor may emit a legitimate `running` snapshot while `ownership_pending=true`: authentication/TUN/protection can already be real, but the outer Start owner has not joined. Android waits for settled ownership before publishing Ready; pending alone is not a protocol fault. Callback and direct getters have separate arrival paths, so atomic per-attempt admission must prevent a late pending/startup frame from replacing settled readiness or joined closure. Settled invalid proof and actual loss still revoke admission. Producer evidence is recorded separately in [go-running-pending-observation.json](../validation/go-running-pending-observation.json).

Transport loss, Abort, Stop and retirement revoke the proof before new admission/bytes. Rust removes effective claims immediately on priority Stop/poison, preserving separate actual Blocked or closure facts. A Blocked receipt proves held original TUN and disabled forwarding for its captured scope; Stop separately confirms Android original closure and Go duplicate/resource joins. Zero counters or a requested Close do not prove release.

## DNS, RTC and bounded resources

Synthetic DNS advertises routing aliases, not validated public addresses or domain existence. Restore the original FQDN before mature TCP/UDP OPEN, translate UDP replies, lease mappings through final I/O, reject missing/expired/retired aliases and prevent reassignment during references or advertised TTL. Bound maps to256 entries/256 KiB. Stable-domain TTL renewal retains the current identity before passive eviction. A retired map never authorizes a new-generation flow or reuses its old proof.

The process-owned allocator uses a fixed65,534-slot deadline table, cursor and monotonic origin, reserving528 KiB within the existing8 MiB added-memory total. Dynamic session budget is therefore8 MiB minus528 KiB. Slots remain unavailable while a cached map/borrower owns them; final release preserves the last advertised TTL before passive reclaim. Exhaustion is a typed overload/SERVFAIL and becomes recoverable after the valid deadline/final lease, without a timer, periodic restart, direct fallback or retained domain history. Work per allocation is bounded; ordinary packets do not scan the address table.

`dns_allocator_bytes` reports this fixed reservation separately from dynamic `queued_bytes`. Stop releases and joins all dynamic mappings/flows/sockets, retaining only bounded, non-domain deadline metadata for safe later generations; process exit releases that metadata. `resources_released` is an active ownership receipt, not a claim that static Go metadata or whole-process PSS is zero. TCP/IP packets carry no policy epoch: arbitrary clients continuing to use an expired DNS answer cannot be distinguished forever. The guaranteed non-reassignment boundary is the advertised TTL/live references; every currently admitted flow still requires the current map and proxy proof.

A prepared synthetic A reply owns both its admitted packet buffers and mapping lease until final response I/O completes. Extend the mapping's last advertised TTL through the last possible write/cleanup time, including failed or retired writers that may have accepted partial bytes; this quarantine extension never restores map authorization or proxy proof. Only a confirmed current-scope response counts as synthetic/validated-wire success. Cancellation and response ownership are joined before declaring dynamic release.

The runtime retains one final redacted Facts record only after all session producers/flows/cleanup have joined. It preserves the ended epoch/scope and confirmed synthetic/wire/bootstrap/shaping totals; all Ready/enforcement/DNS/RTC/IPv6/Hydra-applied flags are false, Hydra scope is off, and map/flow/queued/socket/pending ownership is zero. The next idle policy/attempt clears these totals. Android must not turn this closed history into active protection or combine totals across scopes.

Synthetic mode supports IN A, explicit empty IPv6-disabled AAAA, and clear rejection of unsupported RR/DNSSEC input. Wire mode validates actual DNS replies separately. Counters must distinguish synthetic answers from valid wire replies. A failed wire query never falls back to physical DNS; the only physical resolver callback is bounded node bootstrap.

Gateway-derived bounded DNS/STUN/TURN/DTLS classifiers apply to destination admission, fragmented TCP, UDP and replies. `proxy_only` requires the current selected proxy proof; `block` denies identified traffic before violating bytes are forwarded. Unknown encrypted application traffic still uses the captured VPN route; packet filtering does not claim control over browser SDP address enumeration.

DNS and ordinary flows share the existing64-admission/8 MiB/8-second limits. Parser/query/response/probe buffers and pending copies must be charged before allocation, with passive cleanup and no additional background poll. Default Hydra shaping is off; X logical streams and Pro TCP shaping use existing hooks, independent of DNS/RTC or reconnect.

Acceptance includes real VPN DNS→returned alias→original-hostname certificate/TLS/HTTP200, bootstrap-only physical resolution, wire-mode negative evidence, arbitrary-port/fragmented/malformed privacy traffic, ordinary/empty UDP, old epoch/scope, exhaustion/TTL/live leases, denial before bytes, Stop/loss races and resource joins. Host tests, Android API execution and ARM64/Fold/Doze/PSS/battery/72h tests remain distinct.
