# Network privacy contract · 0.1.2-LYNX

Rust owns one session-local `NetworkPrivacyPolicy`, its independent policy epoch, the frozen VPN scope and the confirmed application result. Android supplies actual package/UID and TUN capture facts; Go installs the shared DNS/RTC guard and reports selected-client/resource evidence. Neither adapter owns another business policy state machine. Creating/querying Rust remains local and inert.

The root-approved default is `NodeDomainFakeIp`, DNS/WebRTC `ProxyOnly`, no resolver endpoint, policy epoch 1 and Hydra disabled. Fake-IP is synthetic A-record routing restored to the original FQDN for the mature proxy OPEN path. It is not a real DNS resolver exchange or a Gateway DNS/Firewall deployment receipt. `WireTcp` requires an explicitly configured, normalized literal IPv4:port endpoint; failures never authorize physical DNS fallback. `Block` explicitly refuses applicable DNS or recognized RTC. Browser-local SDP candidates and unknown encrypted application protocols are outside the supported classification claim. The policy protects the captured VPN installation/UID scope; unselected apps and other profiles remain outside it.

## Policy records and validation

`NetworkPrivacyPolicy` has `dns_mode: DnsMode`, `dns_leak_policy: LeakProtectionMode`, `webrtc_policy: LeakProtectionMode`, `resolver_endpoint: String`, `dns_limits: DnsPrivacyLimits` and `hydra: HydraConfig`. DNS modes are `NodeDomainFakeIp/WireTcp`; leak modes are `ProxyOnly/Block`, with no allow/off variant. Fake-IP requires an empty endpoint. Wire endpoints reject hostnames, URL/userinfo syntax, IPv6, unspecified/multicast addresses and invalid ports; validation does no lookup.

| DNS field | Accepted bound | Default |
| --- | --- | --- |
| `map_max_entries` | 1–256 | 256 |
| `map_max_bytes` | 1,024–262,144 bytes and at least 1,024 per permitted entry | 262,144 |
| `ttl_seconds` | 1–60 seconds | 60 |
| `max_query_bytes` | 12–4,096 bytes | 4,096 |
| `max_response_bytes` | 12–65,535 bytes | 65,535 |

Hydra retains the source's eight fields: enabled, auto_jitter, rotation_seconds, rotation_jitter_percent, chunk_min_percent, burst_min_records, burst_max_records and padding_gap_max_records. Rotation zero normalizes to 300; valid rotations are 10–86,400 seconds. Jitter is 0–40%; chunk minimum is zero or 25–50%; burst values are 0–32, with zero interpreted as effective minimum 2 / maximum 32 for ordering validation; padding gap is 0–64. Even disabled configurations are validated. Advanced zeros stay zeros in operator configuration. This is a source profile, not Rust shaping/cryptography or a periodic worker.

`setNetworkPrivacyPolicy(policy, expectedGeneration)` saves a validated draft. An actual normalized change increments both global configuration generation and policy epoch atomically; a no-op increments neither. Stale/invalid/exhausted updates leave all state unchanged. Existing pending/applied tickets retain their old policy/epoch. Applying a changed policy requires the service's explicit Stop/join/new-attempt path. Node/page/profile operations do not independently advance the privacy epoch.

## One-use ticket scope and configuration

After `beginVpn`, Android freezes the effective shared-UID-expanded package set using the existing `freezeEffectivePackages`. It then calls `freezeNetworkScope(NetworkScopeIdentity)` once. The identity contains actual `vpnOwnerUid: UInt` and complete `packageUids: List<EffectivePackageUid(packageName, uid)>`; full tunnel uses empty pairs and the current service owner's installation/profile identity. Selected maps must match the entire frozen package set, contain no duplicate names, fit the 100-row/4,096-name-byte bound, have positive signed-Android-range UIDs and use the owner's Android user/profile range.

Android must revalidate actual owner/shared-UID membership before Builder, after establishment and before Ready. Changes deny/Stop the captured attempt; a ticket cannot be rebound. Rust's lowercase 64-hex SHA256 scope binds framed attempt/node identity, routing mode, actual owner/pairs and the normalized policy/epoch. It is correlation for trusted adapter receipts, not an OS attestation or proof derived merely from package names.

`networkPolicyEpoch()` and `networkPrivacyPolicy()` return frozen metadata. `networkScopeId()` returns the frozen nonsecret identity for later closure/failure receipts. `canonicalNetworkPolicy()` requires a live, identity-frozen ticket and returns deterministic schema-1 JSON of at most 4,096 UTF-8 bytes. It uses the exact Go keys, including an unsigned decimal-string `policy_epoch`, 64-hex `scope_id`, named modes, resolver endpoint, five limits and the Hydra object. Strings are normalized literals/closed enums/hex; no new production JSON dependency or secret-bearing field was added.

Canonical policy delivery precedes one-use `takeRawNode()`. Android installs the canonical policy with idle-only Go `setNetworkPolicy` before Start. Raw URI remains private service → Go; neither policy nor snapshots contain credentials, seed, PEM or private URI. Cancellation invalidates canonical/raw access immediately. Frozen scope metadata remains available for matching blocked/stopped receipts.

## Actual application receipts

`VpnReadyReceipt` retains its original fields and adds `privacy: NetworkPrivacyReceipt` plus `ipv4_capture_confirmed`, `no_bypass_confirmed`, `ipv6_blocked_confirmed`. Original transport/auth/TUN/socket facts must be true, raw configuration must have been consumed and packages must exactly match the frozen scope.

`NetworkPrivacyReceipt` fields are policy_epoch, scope_id, dns_mode, dns_leak_policy, webrtc_policy, policy_installed, enforcement_active, dns_protection_enforced, webrtc_protection_enforced, ipv6_drop_active, ownership_pending, hydra_enabled, hydra_applied and hydra_scope. Epoch/scope/modes must match the ticket; installed/enforcement/DNS/RTC/IPv6 proof must be true; ownership_pending must be false. Platform capture/no-bypass/IPv6 proof must separately match the actual frozen TUN. Capability flags or configured mode strings cannot substitute for these facts.

Disabled Hydra requires off scope and no applied flag. Enabled X requires an actual logical-stream profile receipt; enabled Pro requires TCP-only profile application. Plain SOCKS rejects enabled Hydra before starting. This does not claim every record was shaped, native QUIC datagrams or Pro packet-only/XUDP shaping. Actual record/padding counts remain separate Go resource evidence.

`VpnBlockedReceipt` retains original-TUN-held/drop/package/IPv6 fields and adds policy_epoch, scope_id and the same three platform confirmations. It requires the exact frozen scope and actual original-TUN/drop proof; active Go privacy flags are not required after Abort. Applied metadata then has Hydra off and protection state `Blocked`.

## Snapshot and stale boundaries

`CoreSnapshot` uses payload schema 2 and adds network_privacy_policy, network_privacy_policy_epoch, applied_network_privacy and network_privacy_enforcement. `AppliedNetworkPrivacy` contains policy_epoch, scope_id, the frozen policy and hydra_scope. Saved draft and confirmed applied values remain distinct. `Inactive/Active/Blocked` is Rust-owned: only matching Ready produces Active, only original-TUN-held/drop proof produces Blocked, Stop immediately projects Inactive and poison clears applied privacy and projects Inactive/Unavailable. Actual stopped receipts clear applied metadata; Stop remains available at counter exhaustion.

Android publication envelope 3 is distinct from CoreSnapshot payload schema 2. NodePage retains schema 1, its original fields, 50-row limit, 200-node workset and query fences. Policy edits advance global generation and invalidate stale page requests. Existing publication/binding/query ordering still rejects old frames, including equal-generation priority projections. DNS synthetic/validated-wire/drop counts, RTC classifications, bootstrap/business resolver observations and Hydra activity stay in bounded, scope/epoch-matched Go resource metadata; Rust has no packet-statistics timer or packet copies.

The API and reducer tests prove bounded state/receipt behavior. Go packet enforcement, actual Android captured UID routes, DNS/RTC behavior, APK/native matching and physical-device power/PSS/Fold acceptance require their own evidence. The 0.1.1 artifacts are historical checkpoints and do not implement this contract.
