#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as loft_ffi;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub mod test_support;

use std::{
    fmt,
    path::Path,
    sync::{
        Arc, Mutex, RwLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use zeroize::Zeroizing;

mod hub;
pub use hub::*;
mod vault;
pub use vault::*;

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum CoreError {
    InputTooLarge,
    InvalidUri,
    UnsupportedProtocol,
    MissingField,
    DuplicateParameter,
    UnknownParameter,
    InvalidEndpoint,
    InvalidCredential,
    InvalidCertificate,
    InvalidOption,
    DuplicateNode,
    NodeCapacityReached,
    NodeNotFound,
    InvalidServerAddress,
    EmptyRoutingSelection,
    InvalidPackageName,
    RoutingSelectionTooLarge,
    GenerationExhausted,
    DataPlaneUnavailable,
    StateUnavailable,
    StaleGeneration,
    ConnectionBusy,
    NodeInUse,
    TicketExpired,
    InvalidEngineReceipt,
    InvalidRoutingReceipt,
    EngineStopIncomplete,
    InvalidNodePage,
    InvalidNetworkPrivacyPolicy,
    InvalidNetworkPrivacyReceipt,
    UnsupportedNetworkPrivacyPolicy,
    StorageUnavailable,
    StorageRecoveryRequired,
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for CoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProtocolKind {
    Socks5,
    HyrakenX,
    HyrakenPro,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Stopping,
    Blocked,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Ipv6Policy {
    BlockedInVpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VpnFailure {
    EngineStartFailed,
    EngineUnavailable,
    Cancelled,
    Revoked,
    EngineStopFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DnsMode {
    NodeDomainFakeIp,
    WireTcp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LeakProtectionMode {
    ProxyOnly,
    Block,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HydraScope {
    Off,
    LogicalStreams,
    TcpOnly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkPrivacyEnforcement {
    Inactive,
    Active,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DnsPrivacyLimits {
    pub map_max_entries: u32,
    pub map_max_bytes: u32,
    pub ttl_seconds: u32,
    pub max_query_bytes: u32,
    pub max_response_bytes: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HydraConfig {
    pub enabled: bool,
    pub auto_jitter: bool,
    pub rotation_seconds: u32,
    pub rotation_jitter_percent: u32,
    pub chunk_min_percent: u32,
    pub burst_min_records: u32,
    pub burst_max_records: u32,
    pub padding_gap_max_records: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkPrivacyPolicy {
    pub dns_mode: DnsMode,
    pub dns_leak_policy: LeakProtectionMode,
    pub webrtc_policy: LeakProtectionMode,
    pub resolver_endpoint: String,
    pub dns_limits: DnsPrivacyLimits,
    pub hydra: HydraConfig,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EffectivePackageUid {
    pub package_name: String,
    pub uid: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkScopeIdentity {
    pub vpn_owner_uid: u32,
    pub package_uids: Vec<EffectivePackageUid>,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppliedNetworkPrivacy {
    pub policy_epoch: u64,
    pub scope_id: String,
    pub policy: NetworkPrivacyPolicy,
    pub hydra_scope: HydraScope,
}
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkPrivacyReceipt {
    pub policy_epoch: u64,
    pub scope_id: String,
    pub dns_mode: DnsMode,
    pub dns_leak_policy: LeakProtectionMode,
    pub webrtc_policy: LeakProtectionMode,
    pub policy_installed: bool,
    pub enforcement_active: bool,
    pub dns_protection_enforced: bool,
    pub webrtc_protection_enforced: bool,
    pub ipv6_drop_active: bool,
    pub ownership_pending: bool,
    pub hydra_enabled: bool,
    pub hydra_applied: bool,
    pub hydra_scope: HydraScope,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppliedRouting {
    pub enabled: bool,
    pub package_names: Vec<String>,
    pub ipv6_policy: Ipv6Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VpnReadyReceipt {
    pub attempt_id: u64,
    pub transport_ready: bool,
    pub authenticated: bool,
    pub tun_ready: bool,
    pub sockets_protected: bool,
    pub applied_package_names: Vec<String>,
    pub ipv6_policy: Ipv6Policy,
    pub privacy: NetworkPrivacyReceipt,
    pub ipv4_capture_confirmed: bool,
    pub no_bypass_confirmed: bool,
    pub ipv6_blocked_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VpnBlockedReceipt {
    pub attempt_id: u64,
    pub tun_held: bool,
    pub forwarding_disabled: bool,
    pub effective_package_names: Vec<String>,
    pub ipv6_policy: Ipv6Policy,
    pub policy_epoch: u64,
    pub scope_id: String,
    pub ipv4_capture_confirmed: bool,
    pub no_bypass_confirmed: bool,
    pub ipv6_blocked_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VpnStoppedReceipt {
    pub attempt_id: u64,
    pub tun_closed: bool,
    pub resources_released: bool,
}

#[derive(uniffi::Object)]
pub struct VpnStartTicket {
    inner: Arc<loft_core::VpnStartTicket>,
}

#[uniffi::export]
impl VpnStartTicket {
    pub fn network_policy_epoch(&self) -> u64 {
        self.inner.network_policy_epoch()
    }
    pub fn network_privacy_policy(&self) -> NetworkPrivacyPolicy {
        self.inner.network_privacy_policy().into()
    }
    pub fn network_scope_id(&self) -> Result<String, CoreError> {
        self.inner.network_scope_id().map_err(CoreError::from)
    }
    pub fn freeze_network_scope(&self, scope: NetworkScopeIdentity) -> Result<(), CoreError> {
        self.inner
            .freeze_network_scope(scope.into())
            .map_err(CoreError::from)
    }
    pub fn canonical_network_policy(&self) -> Result<String, CoreError> {
        self.inner
            .canonical_network_policy()
            .map_err(CoreError::from)
    }
    pub fn attempt_id(&self) -> u64 {
        self.inner.attempt_id()
    }
    pub fn node_id(&self) -> String {
        self.inner.node_id()
    }
    pub fn routing_enabled(&self) -> bool {
        self.inner.routing_enabled()
    }
    pub fn package_names(&self) -> Vec<String> {
        self.inner.package_names()
    }
    pub fn freeze_effective_packages(&self, packages: Vec<String>) -> Result<(), CoreError> {
        self.inner
            .freeze_effective_packages(packages)
            .map_err(CoreError::from)
    }
    pub fn take_raw_node(&self) -> Result<String, CoreError> {
        self.inner.take_raw_node().map_err(CoreError::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NodeSummary {
    pub id: String,
    pub label: String,
    pub protocol: ProtocolKind,
    pub endpoint: String,
    pub udp_min: u32,
    pub udp_max: u32,
    pub credential_material_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NodePage {
    pub schema_version: u32,
    pub generation: u64,
    pub offset: u32,
    pub node_count: u32,
    pub nodes: Vec<NodeSummary>,
    pub next_offset: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreSnapshot {
    pub schema_version: u32,
    pub core_version: String,
    pub nodes: Vec<NodeSummary>,
    pub node_count: u32,
    pub server_address: Option<String>,
    pub server_verified: bool,
    pub routing_enabled: bool,
    pub selected_apps: Vec<String>,
    pub connection_state: ConnectionState,
    pub generation: u64,
    pub connection_attempt_id: u64,
    pub active_node_id: Option<String>,
    pub applied_routing: Option<AppliedRouting>,
    pub vpn_failure: Option<VpnFailure>,
    pub network_privacy_policy: NetworkPrivacyPolicy,
    pub network_privacy_policy_epoch: u64,
    pub applied_network_privacy: Option<AppliedNetworkPrivacy>,
    pub network_privacy_enforcement: NetworkPrivacyEnforcement,
}

#[derive(uniffi::Object)]
pub struct AppCore {
    state: Mutex<loft_core::CoreState>,
    published: RwLock<Arc<loft_core::CoreSnapshot>>,
    stop_signal: Arc<AtomicBool>,
    active_attempt: AtomicU64,
    stop_fence: AtomicU64,
}

#[uniffi::export]
impl AppCore {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let state = loft_core::CoreState::with_stop_signal(stop_signal.clone());
        Self::from_state(state, stop_signal)
    }

    #[uniffi::constructor]
    pub fn open_persistent(
        database_path: String,
        key: Vec<u8>,
        allow_create: bool,
    ) -> Result<Arc<Self>, CoreError> {
        let key = Zeroizing::new(key);
        let stop_signal = Arc::new(AtomicBool::new(false));
        let store =
            loft_storage::SqlCipherStore::open(Path::new(&database_path), &key, allow_create)?;
        drop(key);
        let state = loft_core::CoreState::with_local_storage(stop_signal.clone(), store)?;
        Ok(Self::from_state(state, stop_signal))
    }

    pub fn snapshot(&self) -> CoreSnapshot {
        let published = self
            .published
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let mut snapshot = published.as_ref().clone();
        if self.state.is_poisoned() {
            snapshot.connection_state = loft_core::ConnectionState::Unavailable;
            snapshot.active_node_id = None;
            snapshot.applied_routing = None;
            snapshot.applied_network_privacy = None;
            snapshot.network_privacy_enforcement = loft_core::NetworkPrivacyEnforcement::Inactive;
        } else if self.stop_signal.load(Ordering::Acquire)
            && snapshot.connection_state != loft_core::ConnectionState::Disconnected
        {
            snapshot.connection_state = loft_core::ConnectionState::Stopping;
            snapshot.network_privacy_enforcement = loft_core::NetworkPrivacyEnforcement::Inactive;
        }
        snapshot.into()
    }
    pub fn node_page(&self, offset: u32, expected_generation: u64) -> Result<NodePage, CoreError> {
        let page = {
            // A query must not use with_state: it neither reconciles priority Stop nor publishes.
            let state = self.state.lock().map_err(|_| CoreError::StateUnavailable)?;
            state
                .node_page(offset, expected_generation)
                .map_err(CoreError::from)?
        };
        Ok(page.into())
    }

    pub fn import_node(&self, raw: String) -> Result<NodeSummary, CoreError> {
        let mut raw = Zeroizing::new(raw);
        self.with_state(|state| state.import_node(std::mem::take(&mut *raw)))
            .map(NodeSummary::from)
    }
    pub fn remove_node(&self, id: String) -> Result<(), CoreError> {
        self.with_state(|state| state.remove_node(id))
    }
    pub fn stage_server(&self, raw: String) -> Result<String, CoreError> {
        let mut raw = Zeroizing::new(raw);
        self.with_state(|state| state.stage_server(std::mem::take(&mut *raw)))
    }
    pub fn reset_server(&self) -> Result<(), CoreError> {
        self.with_state(loft_core::CoreState::reset_server)
    }
    pub fn set_app_routing(
        &self,
        enabled: bool,
        package_names: Vec<String>,
    ) -> Result<(), CoreError> {
        self.with_state(|state| state.set_app_routing(enabled, package_names))
    }
    pub fn set_network_privacy_policy(
        &self,
        policy: NetworkPrivacyPolicy,
        expected_generation: u64,
    ) -> Result<(), CoreError> {
        self.with_state(|state| {
            state.set_network_privacy_policy(policy.into(), expected_generation)
        })
    }
    pub fn connect(&self, node_id: String) -> Result<(), CoreError> {
        self.with_state(|state| state.connect(node_id))
    }
    pub fn stop(&self) -> Result<(), CoreError> {
        self.begin_vpn_stop().map(|_| ())
    }

    pub fn begin_vpn(
        &self,
        node_id: String,
        expected_snapshot_generation: u64,
    ) -> Result<Arc<VpnStartTicket>, CoreError> {
        let fence = self.stop_fence.load(Ordering::Acquire);
        self.with_state(|state| {
            if self.stop_signal.load(Ordering::Acquire)
                || self.stop_fence.load(Ordering::Acquire) != fence
            {
                return Err(loft_core::CoreError::ConnectionBusy);
            }
            state.begin_vpn(node_id, expected_snapshot_generation)
        })
        .map(|inner| Arc::new(VpnStartTicket { inner }))
    }
    pub fn mark_vpn_ready(&self, receipt: VpnReadyReceipt) -> Result<(), CoreError> {
        self.with_state(|state| state.mark_vpn_ready(receipt.into()))
    }
    pub fn mark_vpn_failed(&self, attempt_id: u64, reason: VpnFailure) -> Result<(), CoreError> {
        self.with_state(|state| state.mark_vpn_failed(attempt_id, reason.into()))
    }
    pub fn mark_vpn_blocked(&self, receipt: VpnBlockedReceipt) -> Result<(), CoreError> {
        self.with_state(|state| state.mark_vpn_blocked(receipt.into()))
    }
    pub fn begin_vpn_stop(&self) -> Result<u64, CoreError> {
        let _ = self
            .stop_fence
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
        self.stop_signal.store(true, Ordering::Release);
        match self.state.try_lock() {
            Ok(mut state) => {
                let result = state.begin_vpn_stop().map_err(CoreError::from);
                self.publish_snapshot(state.snapshot());
                result
            }
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                // Android immediately cancels Go/FD owners. State reconciliation need not block that path.
                Ok(self.active_attempt.load(Ordering::Acquire))
            }
        }
    }
    pub fn confirm_vpn_stopped(&self, receipt: VpnStoppedReceipt) -> Result<(), CoreError> {
        self.with_state(|state| state.confirm_vpn_stopped(receipt.into()))
    }
}

impl AppCore {
    fn from_state(state: loft_core::CoreState, stop_signal: Arc<AtomicBool>) -> Arc<Self> {
        let published = Arc::new(state.snapshot());
        Arc::new(Self {
            state: Mutex::new(state),
            published: RwLock::new(published),
            stop_signal,
            active_attempt: AtomicU64::new(0),
            stop_fence: AtomicU64::new(0),
        })
    }

    fn with_state<T>(
        &self,
        action: impl FnOnce(&mut loft_core::CoreState) -> Result<T, loft_core::CoreError>,
    ) -> Result<T, CoreError> {
        let mut state = self.state.lock().map_err(|_| CoreError::StateUnavailable)?;
        state.reconcile_priority_stop();
        let result = action(&mut state).map_err(CoreError::from);
        self.publish_snapshot(state.snapshot());
        result
    }

    fn publish_snapshot(&self, snapshot: loft_core::CoreSnapshot) {
        self.active_attempt
            .store(snapshot.connection_attempt_id, Ordering::Release);
        let snapshot = Arc::new(snapshot);
        *self
            .published
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }
}

impl From<loft_core::CoreError> for CoreError {
    fn from(error: loft_core::CoreError) -> Self {
        match error {
            loft_core::CoreError::InputTooLarge => Self::InputTooLarge,
            loft_core::CoreError::InvalidUri => Self::InvalidUri,
            loft_core::CoreError::UnsupportedProtocol => Self::UnsupportedProtocol,
            loft_core::CoreError::MissingField => Self::MissingField,
            loft_core::CoreError::DuplicateParameter => Self::DuplicateParameter,
            loft_core::CoreError::UnknownParameter => Self::UnknownParameter,
            loft_core::CoreError::InvalidEndpoint => Self::InvalidEndpoint,
            loft_core::CoreError::InvalidCredential => Self::InvalidCredential,
            loft_core::CoreError::InvalidCertificate => Self::InvalidCertificate,
            loft_core::CoreError::InvalidOption => Self::InvalidOption,
            loft_core::CoreError::DuplicateNode => Self::DuplicateNode,
            loft_core::CoreError::NodeCapacityReached => Self::NodeCapacityReached,
            loft_core::CoreError::NodeNotFound => Self::NodeNotFound,
            loft_core::CoreError::InvalidServerAddress => Self::InvalidServerAddress,
            loft_core::CoreError::EmptyRoutingSelection => Self::EmptyRoutingSelection,
            loft_core::CoreError::InvalidPackageName => Self::InvalidPackageName,
            loft_core::CoreError::RoutingSelectionTooLarge => Self::RoutingSelectionTooLarge,
            loft_core::CoreError::GenerationExhausted => Self::GenerationExhausted,
            loft_core::CoreError::DataPlaneUnavailable => Self::DataPlaneUnavailable,
            loft_core::CoreError::StateUnavailable => Self::StateUnavailable,
            loft_core::CoreError::StaleGeneration => Self::StaleGeneration,
            loft_core::CoreError::ConnectionBusy => Self::ConnectionBusy,
            loft_core::CoreError::NodeInUse => Self::NodeInUse,
            loft_core::CoreError::TicketExpired => Self::TicketExpired,
            loft_core::CoreError::InvalidEngineReceipt => Self::InvalidEngineReceipt,
            loft_core::CoreError::InvalidRoutingReceipt => Self::InvalidRoutingReceipt,
            loft_core::CoreError::EngineStopIncomplete => Self::EngineStopIncomplete,
            loft_core::CoreError::InvalidNodePage => Self::InvalidNodePage,
            loft_core::CoreError::InvalidNetworkPrivacyPolicy => Self::InvalidNetworkPrivacyPolicy,
            loft_core::CoreError::InvalidNetworkPrivacyReceipt => {
                Self::InvalidNetworkPrivacyReceipt
            }
            loft_core::CoreError::UnsupportedNetworkPrivacyPolicy => {
                Self::UnsupportedNetworkPrivacyPolicy
            }
            loft_core::CoreError::StorageUnavailable => Self::StorageUnavailable,
            loft_core::CoreError::StorageRecoveryRequired => Self::StorageRecoveryRequired,
        }
    }
}

impl From<loft_core::ProtocolKind> for ProtocolKind {
    fn from(protocol: loft_core::ProtocolKind) -> Self {
        match protocol {
            loft_core::ProtocolKind::Socks5 => Self::Socks5,
            loft_core::ProtocolKind::HyrakenX => Self::HyrakenX,
            loft_core::ProtocolKind::HyrakenPro => Self::HyrakenPro,
        }
    }
}

impl From<loft_core::ConnectionState> for ConnectionState {
    fn from(state: loft_core::ConnectionState) -> Self {
        match state {
            loft_core::ConnectionState::Disconnected => Self::Disconnected,
            loft_core::ConnectionState::Connecting => Self::Connecting,
            loft_core::ConnectionState::Connected => Self::Connected,
            loft_core::ConnectionState::Stopping => Self::Stopping,
            loft_core::ConnectionState::Blocked => Self::Blocked,
            loft_core::ConnectionState::Unavailable => Self::Unavailable,
        }
    }
}

impl From<loft_core::NodeSummary> for NodeSummary {
    fn from(node: loft_core::NodeSummary) -> Self {
        Self {
            id: node.id,
            label: node.label,
            protocol: node.protocol.into(),
            endpoint: node.endpoint,
            udp_min: node.udp_min,
            udp_max: node.udp_max,
            credential_material_present: node.credential_material_present,
        }
    }
}

impl From<loft_core::NodePage> for NodePage {
    fn from(page: loft_core::NodePage) -> Self {
        Self {
            schema_version: page.schema_version,
            generation: page.generation,
            offset: page.offset,
            node_count: page.node_count,
            nodes: page.nodes.into_iter().map(NodeSummary::from).collect(),
            next_offset: page.next_offset,
        }
    }
}

impl From<loft_core::CoreSnapshot> for CoreSnapshot {
    fn from(snapshot: loft_core::CoreSnapshot) -> Self {
        Self {
            schema_version: snapshot.schema_version,
            core_version: snapshot.core_version,
            nodes: snapshot.nodes.into_iter().map(NodeSummary::from).collect(),
            node_count: snapshot.node_count,
            server_address: snapshot.server_address,
            server_verified: snapshot.server_verified,
            routing_enabled: snapshot.routing_enabled,
            selected_apps: snapshot.selected_apps,
            connection_state: snapshot.connection_state.into(),
            generation: snapshot.generation,
            connection_attempt_id: snapshot.connection_attempt_id,
            active_node_id: snapshot.active_node_id,
            applied_routing: snapshot.applied_routing.map(AppliedRouting::from),
            vpn_failure: snapshot.vpn_failure.map(VpnFailure::from),
            network_privacy_policy: snapshot.network_privacy_policy.into(),
            network_privacy_policy_epoch: snapshot.network_privacy_policy_epoch,
            applied_network_privacy: snapshot
                .applied_network_privacy
                .map(AppliedNetworkPrivacy::from),
            network_privacy_enforcement: snapshot.network_privacy_enforcement.into(),
        }
    }
}

impl From<loft_core::Ipv6Policy> for Ipv6Policy {
    fn from(value: loft_core::Ipv6Policy) -> Self {
        match value {
            loft_core::Ipv6Policy::BlockedInVpn => Self::BlockedInVpn,
        }
    }
}
impl From<Ipv6Policy> for loft_core::Ipv6Policy {
    fn from(value: Ipv6Policy) -> Self {
        match value {
            Ipv6Policy::BlockedInVpn => Self::BlockedInVpn,
        }
    }
}
impl From<loft_core::VpnFailure> for VpnFailure {
    fn from(value: loft_core::VpnFailure) -> Self {
        match value {
            loft_core::VpnFailure::EngineStartFailed => Self::EngineStartFailed,
            loft_core::VpnFailure::EngineUnavailable => Self::EngineUnavailable,
            loft_core::VpnFailure::Cancelled => Self::Cancelled,
            loft_core::VpnFailure::Revoked => Self::Revoked,
            loft_core::VpnFailure::EngineStopFailed => Self::EngineStopFailed,
        }
    }
}
impl From<VpnFailure> for loft_core::VpnFailure {
    fn from(value: VpnFailure) -> Self {
        match value {
            VpnFailure::EngineStartFailed => Self::EngineStartFailed,
            VpnFailure::EngineUnavailable => Self::EngineUnavailable,
            VpnFailure::Cancelled => Self::Cancelled,
            VpnFailure::Revoked => Self::Revoked,
            VpnFailure::EngineStopFailed => Self::EngineStopFailed,
        }
    }
}
impl From<loft_core::AppliedRouting> for AppliedRouting {
    fn from(value: loft_core::AppliedRouting) -> Self {
        Self {
            enabled: value.enabled,
            package_names: value.package_names,
            ipv6_policy: value.ipv6_policy.into(),
        }
    }
}
impl From<VpnReadyReceipt> for loft_core::VpnReadyReceipt {
    fn from(value: VpnReadyReceipt) -> Self {
        Self {
            attempt_id: value.attempt_id,
            transport_ready: value.transport_ready,
            authenticated: value.authenticated,
            tun_ready: value.tun_ready,
            sockets_protected: value.sockets_protected,
            applied_package_names: value.applied_package_names,
            ipv6_policy: value.ipv6_policy.into(),
            privacy: value.privacy.into(),
            ipv4_capture_confirmed: value.ipv4_capture_confirmed,
            no_bypass_confirmed: value.no_bypass_confirmed,
            ipv6_blocked_confirmed: value.ipv6_blocked_confirmed,
        }
    }
}
impl From<VpnBlockedReceipt> for loft_core::VpnBlockedReceipt {
    fn from(value: VpnBlockedReceipt) -> Self {
        Self {
            attempt_id: value.attempt_id,
            tun_held: value.tun_held,
            forwarding_disabled: value.forwarding_disabled,
            effective_package_names: value.effective_package_names,
            ipv6_policy: value.ipv6_policy.into(),
            policy_epoch: value.policy_epoch,
            scope_id: value.scope_id,
            ipv4_capture_confirmed: value.ipv4_capture_confirmed,
            no_bypass_confirmed: value.no_bypass_confirmed,
            ipv6_blocked_confirmed: value.ipv6_blocked_confirmed,
        }
    }
}
impl From<VpnStoppedReceipt> for loft_core::VpnStoppedReceipt {
    fn from(value: VpnStoppedReceipt) -> Self {
        Self {
            attempt_id: value.attempt_id,
            tun_closed: value.tun_closed,
            resources_released: value.resources_released,
        }
    }
}

macro_rules! privacy_enum_conversion {
    ($name:ident, $($variant:ident),+ $(,)?) => {
        impl From<loft_core::$name> for $name {
            fn from(value: loft_core::$name) -> Self {
                match value { $(loft_core::$name::$variant => Self::$variant),+ }
            }
        }
        impl From<$name> for loft_core::$name {
            fn from(value: $name) -> Self {
                match value { $($name::$variant => Self::$variant),+ }
            }
        }
    };
}
privacy_enum_conversion!(DnsMode, NodeDomainFakeIp, WireTcp);
privacy_enum_conversion!(LeakProtectionMode, ProxyOnly, Block);
privacy_enum_conversion!(HydraScope, Off, LogicalStreams, TcpOnly);
privacy_enum_conversion!(NetworkPrivacyEnforcement, Inactive, Active, Blocked);

impl From<loft_core::DnsPrivacyLimits> for DnsPrivacyLimits {
    fn from(value: loft_core::DnsPrivacyLimits) -> Self {
        Self {
            map_max_entries: value.map_max_entries,
            map_max_bytes: value.map_max_bytes,
            ttl_seconds: value.ttl_seconds,
            max_query_bytes: value.max_query_bytes,
            max_response_bytes: value.max_response_bytes,
        }
    }
}
impl From<DnsPrivacyLimits> for loft_core::DnsPrivacyLimits {
    fn from(value: DnsPrivacyLimits) -> Self {
        Self {
            map_max_entries: value.map_max_entries,
            map_max_bytes: value.map_max_bytes,
            ttl_seconds: value.ttl_seconds,
            max_query_bytes: value.max_query_bytes,
            max_response_bytes: value.max_response_bytes,
        }
    }
}
impl From<loft_core::HydraConfig> for HydraConfig {
    fn from(value: loft_core::HydraConfig) -> Self {
        Self {
            enabled: value.enabled,
            auto_jitter: value.auto_jitter,
            rotation_seconds: value.rotation_seconds,
            rotation_jitter_percent: value.rotation_jitter_percent,
            chunk_min_percent: value.chunk_min_percent,
            burst_min_records: value.burst_min_records,
            burst_max_records: value.burst_max_records,
            padding_gap_max_records: value.padding_gap_max_records,
        }
    }
}
impl From<HydraConfig> for loft_core::HydraConfig {
    fn from(value: HydraConfig) -> Self {
        Self {
            enabled: value.enabled,
            auto_jitter: value.auto_jitter,
            rotation_seconds: value.rotation_seconds,
            rotation_jitter_percent: value.rotation_jitter_percent,
            chunk_min_percent: value.chunk_min_percent,
            burst_min_records: value.burst_min_records,
            burst_max_records: value.burst_max_records,
            padding_gap_max_records: value.padding_gap_max_records,
        }
    }
}
impl From<loft_core::NetworkPrivacyPolicy> for NetworkPrivacyPolicy {
    fn from(value: loft_core::NetworkPrivacyPolicy) -> Self {
        Self {
            dns_mode: value.dns_mode.into(),
            dns_leak_policy: value.dns_leak_policy.into(),
            webrtc_policy: value.webrtc_policy.into(),
            resolver_endpoint: value.resolver_endpoint,
            dns_limits: value.dns_limits.into(),
            hydra: value.hydra.into(),
        }
    }
}
impl From<NetworkPrivacyPolicy> for loft_core::NetworkPrivacyPolicy {
    fn from(value: NetworkPrivacyPolicy) -> Self {
        Self {
            dns_mode: value.dns_mode.into(),
            dns_leak_policy: value.dns_leak_policy.into(),
            webrtc_policy: value.webrtc_policy.into(),
            resolver_endpoint: value.resolver_endpoint,
            dns_limits: value.dns_limits.into(),
            hydra: value.hydra.into(),
        }
    }
}
impl From<EffectivePackageUid> for loft_core::EffectivePackageUid {
    fn from(value: EffectivePackageUid) -> Self {
        Self {
            package_name: value.package_name,
            uid: value.uid,
        }
    }
}
impl From<NetworkScopeIdentity> for loft_core::NetworkScopeIdentity {
    fn from(value: NetworkScopeIdentity) -> Self {
        Self {
            vpn_owner_uid: value.vpn_owner_uid,
            package_uids: value.package_uids.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<loft_core::AppliedNetworkPrivacy> for AppliedNetworkPrivacy {
    fn from(value: loft_core::AppliedNetworkPrivacy) -> Self {
        Self {
            policy_epoch: value.policy_epoch,
            scope_id: value.scope_id,
            policy: value.policy.into(),
            hydra_scope: value.hydra_scope.into(),
        }
    }
}
impl From<NetworkPrivacyReceipt> for loft_core::NetworkPrivacyReceipt {
    fn from(value: NetworkPrivacyReceipt) -> Self {
        Self {
            policy_epoch: value.policy_epoch,
            scope_id: value.scope_id,
            dns_mode: value.dns_mode.into(),
            dns_leak_policy: value.dns_leak_policy.into(),
            webrtc_policy: value.webrtc_policy.into(),
            policy_installed: value.policy_installed,
            enforcement_active: value.enforcement_active,
            dns_protection_enforced: value.dns_protection_enforced,
            webrtc_protection_enforced: value.webrtc_protection_enforced,
            ipv6_drop_active: value.ipv6_drop_active,
            ownership_pending: value.ownership_pending,
            hydra_enabled: value.hydra_enabled,
            hydra_applied: value.hydra_applied,
            hydra_scope: value.hydra_scope.into(),
        }
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;

    #[test]
    fn poisoned_owner_is_unavailable_instead_of_a_confirmed_snapshot() {
        let core = AppCore::new();
        let node = core.import_node("socks5://proxy.example".into()).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        crate::test_support::freeze(&ticket, vec![]);
        ticket.take_raw_node().unwrap();
        core.mark_vpn_ready(VpnReadyReceipt {
            attempt_id: ticket.attempt_id(),
            transport_ready: true,
            authenticated: true,
            tun_ready: true,
            sockets_protected: true,
            applied_package_names: vec![],
            ipv6_policy: Ipv6Policy::BlockedInVpn,
            privacy: crate::test_support::privacy(&ticket),
            ipv4_capture_confirmed: true,
            no_bypass_confirmed: true,
            ipv6_blocked_confirmed: true,
        })
        .unwrap();
        assert_eq!(core.snapshot().connection_state, ConnectionState::Connected);
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Active
        );
        let worker = core.clone();
        let result = std::thread::spawn(move || {
            let _guard = worker.state.lock().unwrap();
            panic!("intentional owner poison for contract test");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(
            core.snapshot().connection_state,
            ConnectionState::Unavailable
        );
        assert_eq!(core.snapshot().active_node_id, None);
        assert_eq!(core.snapshot().applied_routing, None);
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Inactive
        );
        assert_eq!(core.snapshot().applied_network_privacy, None);
        assert_eq!(
            core.node_page(0, core.snapshot().generation),
            Err(CoreError::StateUnavailable)
        );
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        assert_eq!(
            core.snapshot().connection_state,
            ConnectionState::Unavailable
        );
    }

    #[test]
    fn priority_stop_does_not_wait_for_a_held_normal_owner_lock() {
        let core = AppCore::new();
        let node = core.import_node("socks5://proxy.example".into()).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        let _guard = core.state.lock().unwrap();
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
        assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    }

    #[test]
    fn priority_stop_retracts_published_privacy_while_the_normal_mutex_is_held() {
        let core = AppCore::new();
        let node = core.import_node("socks5://proxy.example".into()).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        crate::test_support::freeze(&ticket, vec![]);
        ticket.take_raw_node().unwrap();
        core.mark_vpn_ready(VpnReadyReceipt {
            attempt_id: ticket.attempt_id(),
            transport_ready: true,
            authenticated: true,
            tun_ready: true,
            sockets_protected: true,
            applied_package_names: vec![],
            ipv6_policy: Ipv6Policy::BlockedInVpn,
            privacy: crate::test_support::privacy(&ticket),
            ipv4_capture_confirmed: true,
            no_bypass_confirmed: true,
            ipv6_blocked_confirmed: true,
        })
        .unwrap();
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Active
        );
        let _guard = core.state.lock().unwrap();
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Inactive
        );
        assert_eq!(
            ticket.canonical_network_policy(),
            Err(CoreError::TicketExpired)
        );
    }

    // Catches reusing the mutation helper for a read and reconciling cancellation during a page query.
    #[test]
    fn node_page_does_not_reconcile_a_pending_priority_stop() {
        let core = AppCore::new();
        for index in 0..51 {
            core.import_node(format!("socks5://priority-page-{index}.example"))
                .unwrap();
        }
        let selected = core.snapshot().nodes[0].id.clone();
        let ticket = core
            .begin_vpn(selected, core.snapshot().generation)
            .unwrap();
        let generation = core.snapshot().generation;
        let guard = core.state.lock().unwrap();
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        drop(guard);
        let before = core.snapshot();
        assert_eq!(before.connection_state, ConnectionState::Stopping);
        assert_eq!(before.generation, generation);
        let page = core.node_page(50, generation).unwrap();
        assert_eq!(page.nodes.len(), 1);
        assert_eq!(page.generation, generation);
        assert_eq!(core.snapshot(), before);
        assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    }

    // The same real mutex serializes a queued read; priority Stop must still return immediately.
    #[test]
    fn a_queued_node_page_cannot_delay_priority_stop() {
        let core = AppCore::new();
        for index in 0..51 {
            core.import_node(format!("socks5://queued-page-{index}.example"))
                .unwrap();
        }
        let ticket = core
            .begin_vpn(
                core.snapshot().nodes[0].id.clone(),
                core.snapshot().generation,
            )
            .unwrap();
        let generation = core.snapshot().generation;
        let guard = core.state.lock().unwrap();
        let worker = core.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (page_tx, page_rx) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            page_tx.send(worker.node_page(50, generation)).unwrap();
        });
        entered_rx.recv().unwrap();
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
        drop(guard);
        let page = page_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(page.generation, generation);
        assert_eq!(page.nodes.len(), 1);
        reader.join().unwrap();
    }
}
