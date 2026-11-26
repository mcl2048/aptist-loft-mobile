# Trusted VPN service port

Implemented and frozen in 0.1.1-LYNX after root/Android/Go agreement. The 0.1.0 controller foundation remains a separate validation baseline. Generated Kotlin and the matching ARM64 library have been replaced in Android build output.

Rust stages a bounded request and returns immediately. Android grants VPN permission, establishes/holds the original TUN and forwards a duplicated FD plus the private validated URI to NewVPNRuntime(SocketProtector).Start. Go owns actual protocol authentication/data-plane resources. No Go call runs under the Rust state mutex. No URI enters an AIDL response, UI snapshot or ordinary log.

```rust
begin_vpn(node_id: String, expected_snapshot_generation: u64) -> Result<Arc<VpnStartTicket>, CoreError>
mark_vpn_ready(receipt: VpnReadyReceipt) -> Result<(), CoreError>
mark_vpn_failed(attempt_id: u64, reason: VpnFailure) -> Result<(), CoreError>
mark_vpn_blocked(receipt: VpnBlockedReceipt) -> Result<(), CoreError>
begin_vpn_stop() -> Result<u64, CoreError>
confirm_vpn_stopped(receipt: VpnStoppedReceipt) -> Result<(), CoreError>
```

VpnStartTicket is an opaque object, not a secret-bearing generated data class. Metadata getters are attempt_id, node_id, routing_enabled and package_names. The trusted Android adapter resolves/expands installed shared UID groups and calls freeze_effective_packages once with its exact Builder set. It then calls single-use take_raw_node. The URI is rebuilt from validated canonical configuration, omits the display fragment, stays within 512 KiB and is stored in a zeroizing buffer. Cancellation/ready/failure invalidates it; received JVM/Go string copies remain scoped to the operation. Node storage remains session-local.

VpnReadyReceipt fields: attempt_id:u64, transport_ready:bool, authenticated:bool, tun_ready:bool, sockets_protected:bool, applied_package_names:Vec<String>, ipv6_policy:Ipv6Policy. Every readiness fact comes from real Go/Android results. False/incomplete facts, unconsumed configuration, stale/cancelled attempts and routing mismatches are rejected. A controller capability description or source hash cannot supply readiness.

Ipv6Policy initially has only BlockedInVpn. Root policy intercepts DNS at 198.18.0.2 and sends it through node TCP to a configurable explicitly labelled public upstream, initially 1.1.1.1:53, with no fallback. This is configured behavior, not proof of upstream DNS acceptance.

VpnBlockedReceipt fields: attempt_id:u64, tun_held:bool, forwarding_disabled:bool, effective_package_names:Vec<String>, ipv6_policy:Ipv6Policy. It requires actual original Android TUN-held and Go forwarding-disabled/closed-duplicate proof. It can publish its held applied scope before authenticated readiness. Failure never implies the original Android PFD was closed. Ready and blocked receipts require exact equality with the frozen effective package set; empty selected routing never becomes full tunnel.

VpnStoppedReceipt fields: attempt_id:u64, tun_closed:bool, resources_released:bool. Both original Android PFD closure and Go duplicate/resource release are required before Disconnected clears the active node/applied scope. Incomplete closure remains Stopping. Revoke can cancel resources first and then record a trusted Revoked reason without reopening traffic or accepting a late start callback.

CoreSnapshot keeps draft routing_enabled/selected_apps and adds connection_attempt_id:u64, active_node_id:Option<String>, applied_routing:Option<AppliedRouting>, vpn_failure:Option<VpnFailure>. AppliedRouting has enabled, actual package_names and ipv6_policy. States: Disconnected, Connecting, Connected, Stopping, Blocked, Unavailable. Blocked always requires held/drop proof. Poison queries read immutable published metadata, project Unavailable and clear confirmed active/applied claims.

Attempt IDs are independent from later configuration generations. Imports/server staging preserve a frozen guest VPN attempt. Removing a pending/active node or admitting a second connection is rejected. Saved drafts never rewrite confirmed applied routing; apply requires explicit stop/rebuild. Late callbacks check captured attempt and lifecycle phase.

Priority begin_vpn_stop sets an atomic cancellation/admission fence and does not wait for a held normal state mutex. Android cancels Go/PFD owners immediately, joins/quiesces its actor and reconciles a matching stopped receipt. If preparation was concurrent, the service rechecks the captured attempt; stale receipts are rejected. Stop works at counter exhaustion without admitting a wrapped attempt. The consumer reserves one bounded transport capture sequence before snapshot capture so late earlier Connected frames cannot replace newer equal-generation Stopping/Unavailable projections. This is transport ordering only.

Flat errors added: StaleGeneration, ConnectionBusy, NodeInUse, TicketExpired, InvalidEngineReceipt, InvalidRoutingReceipt, EngineStopIncomplete. VpnFailure: EngineStartFailed, EngineUnavailable, Cancelled, Revoked, EngineStopFailed. No expected error carries upstream text or raw credentials. The legacy connect method remains a checked DataPlaneUnavailable boundary; the service uses this explicit receipt port.

TDD covers private URI equivalence, consumption/cancellation, frozen targets/effective routing, readiness gates, rejected stale callbacks, blocked scope, stop/revoke closure, counter exhaustion, poison and priority stop, preserving the earlier parser/budgets. Reducer/FFI tests are separate from Go live-node, Android TUN/protection and device acceptance. No TEST.TXT credentials are copied into Rust fixtures or source.
