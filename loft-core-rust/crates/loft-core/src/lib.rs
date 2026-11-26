#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as loft_core;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub mod test_support;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;
mod certificates;
mod import;
mod origin;
mod privacy;
mod vpn;
pub use import::{MAX_NODE_INPUT_BYTES, MAX_NODE_LABEL_BYTES};
pub use origin::{MAX_SERVER_INPUT_BYTES, normalize_server_origin};
pub use privacy::{
    AppliedNetworkPrivacy, DnsMode, DnsPrivacyLimits, EffectivePackageUid, HydraConfig, HydraScope,
    LeakProtectionMode, NetworkPrivacyEnforcement, NetworkPrivacyPolicy, NetworkPrivacyReceipt,
    NetworkScopeIdentity,
};
pub use vpn::{
    AppliedRouting, Ipv6Policy, VpnBlockedReceipt, VpnFailure, VpnReadyReceipt, VpnStartTicket,
    VpnStoppedReceipt,
};

pub const MAX_NODES: usize = 200;
pub const MAX_SNAPSHOT_NODES: usize = 50;
pub const MAX_RETAINED_NODE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ROUTING_PACKAGES: usize = 100;
pub const MAX_ROUTING_BYTES: usize = 4096;
pub const MAX_PACKAGE_NAME_BYTES: usize = 255;
const MAX_NODE_ID_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for CoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Socks5,
    HyrakenX,
    HyrakenPro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Stopping,
    Blocked,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSummary {
    pub id: String,
    pub label: String,
    pub protocol: ProtocolKind,
    pub endpoint: String,
    pub udp_min: u32,
    pub udp_max: u32,
    pub credential_material_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePage {
    pub schema_version: u32,
    pub generation: u64,
    pub offset: u32,
    pub node_count: u32,
    pub nodes: Vec<NodeSummary>,
    pub next_offset: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

struct NodeEntry {
    summary: NodeSummary,
    config: import::NodeConfig,
    charge: usize,
}

/// A synchronous, session-local owner. It opens no network, file, timer or data-plane runtime.
pub struct CoreState {
    nodes: Vec<NodeEntry>,
    retained_node_bytes: usize,
    next_node_id: u64,
    server_candidate: Option<String>,
    routing_enabled: bool,
    selected_apps: Vec<String>,
    generation: u64,
    vpn: vpn::VpnLifecycle,
    stop_signal: Arc<AtomicBool>,
    network_privacy_policy: NetworkPrivacyPolicy,
    network_privacy_policy_epoch: u64,
}

impl fmt::Debug for CoreState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CoreState")
            .field(&self.snapshot())
            .finish()
    }
}

impl Default for CoreState {
    fn default() -> Self {
        Self::new()
    }
}
impl CoreState {
    pub fn new() -> Self {
        Self::with_stop_signal(Arc::new(AtomicBool::new(false)))
    }

    pub fn with_stop_signal(stop_signal: Arc<AtomicBool>) -> Self {
        Self {
            nodes: Vec::new(),
            retained_node_bytes: 0,
            next_node_id: 1,
            server_candidate: None,
            routing_enabled: false,
            selected_apps: Vec::new(),
            generation: 0,
            vpn: vpn::VpnLifecycle::default(),
            stop_signal,
            network_privacy_policy: NetworkPrivacyPolicy::default(),
            network_privacy_policy_epoch: 1,
        }
    }

    pub fn snapshot(&self) -> CoreSnapshot {
        let connection_state = if self.stop_signal.load(Ordering::Acquire)
            && self.vpn.state != ConnectionState::Disconnected
        {
            ConnectionState::Stopping
        } else {
            self.vpn.state
        };
        CoreSnapshot {
            schema_version: 2,
            core_version: "0.1.2-LYNX".into(),
            nodes: self
                .nodes
                .iter()
                .take(MAX_SNAPSHOT_NODES)
                .map(|node| node.summary.clone())
                .collect(),
            node_count: self.nodes.len() as u32,
            server_address: self.server_candidate.clone(),
            server_verified: false,
            routing_enabled: self.routing_enabled,
            selected_apps: self.selected_apps.clone(),
            connection_state,
            generation: self.generation,
            connection_attempt_id: self.vpn.current_attempt_id,
            active_node_id: if self.vpn.applied.is_some() {
                self.vpn.target.clone()
            } else {
                None
            },
            applied_routing: self.vpn.applied.clone(),
            vpn_failure: self.vpn.failure,
            network_privacy_policy: self.network_privacy_policy.clone(),
            network_privacy_policy_epoch: self.network_privacy_policy_epoch,
            applied_network_privacy: self.vpn.applied_network_privacy.clone(),
            network_privacy_enforcement: match (connection_state, &self.vpn.applied_network_privacy)
            {
                (ConnectionState::Connected, Some(_)) => NetworkPrivacyEnforcement::Active,
                (ConnectionState::Blocked, Some(_)) => NetworkPrivacyEnforcement::Blocked,
                _ => NetworkPrivacyEnforcement::Inactive,
            },
        }
    }

    pub fn set_network_privacy_policy(
        &mut self,
        policy: NetworkPrivacyPolicy,
        expected_generation: u64,
    ) -> Result<(), CoreError> {
        if expected_generation != self.generation {
            return Err(CoreError::StaleGeneration);
        }
        let policy = policy.normalized()?;
        if policy == self.network_privacy_policy {
            return Ok(());
        }
        let generation = self.next_generation()?;
        let epoch = self
            .network_privacy_policy_epoch
            .checked_add(1)
            .ok_or(CoreError::GenerationExhausted)?;
        self.network_privacy_policy = policy;
        self.network_privacy_policy_epoch = epoch;
        self.generation = generation;
        Ok(())
    }

    /// Reads one metadata page at the caller's generation without reconciling or mutating state.
    /// Offsets are fixed page starts; only offset zero is valid for an empty directory.
    pub fn node_page(&self, offset: u32, expected_generation: u64) -> Result<NodePage, CoreError> {
        if expected_generation != self.generation {
            return Err(CoreError::StaleGeneration);
        }
        let start = usize::try_from(offset).map_err(|_| CoreError::InvalidNodePage)?;
        if !start.is_multiple_of(MAX_SNAPSHOT_NODES) || (start != 0 && start >= self.nodes.len()) {
            return Err(CoreError::InvalidNodePage);
        }
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .skip(start)
            .take(MAX_SNAPSHOT_NODES)
            .map(|node| node.summary.clone())
            .collect();
        let end = start + nodes.len();
        Ok(NodePage {
            schema_version: 1,
            generation: self.generation,
            offset,
            node_count: self.nodes.len() as u32,
            nodes,
            next_offset: (end < self.nodes.len()).then_some(end as u32),
        })
    }

    /// Parses and commits one complete configuration. Every failure leaves state and generation unchanged.
    pub fn import_node(&mut self, raw: String) -> Result<NodeSummary, CoreError> {
        let candidate = import::parse_node(raw)?;
        if self
            .nodes
            .iter()
            .any(|node| node.config == candidate.config)
        {
            return Err(CoreError::DuplicateNode);
        }
        let charge = candidate.retained_charge();
        let retained = self
            .retained_node_bytes
            .checked_add(charge)
            .ok_or(CoreError::NodeCapacityReached)?;
        if self.nodes.len() == MAX_NODES || retained > MAX_RETAINED_NODE_BYTES {
            return Err(CoreError::NodeCapacityReached);
        }
        let generation = self.next_generation()?;
        let next_id = self
            .next_node_id
            .checked_add(1)
            .ok_or(CoreError::GenerationExhausted)?;
        let summary = candidate.summary(format!("node-{:016x}", self.next_node_id));
        self.nodes.push(NodeEntry {
            summary: summary.clone(),
            config: candidate.config,
            charge,
        });
        self.retained_node_bytes = retained;
        self.next_node_id = next_id;
        self.generation = generation;
        Ok(summary)
    }

    pub fn remove_node(&mut self, id: String) -> Result<(), CoreError> {
        validate_node_id(&id)?;
        if self.vpn.state != ConnectionState::Disconnected && self.vpn.target.as_ref() == Some(&id)
        {
            return Err(CoreError::NodeInUse);
        }
        let position = self
            .nodes
            .iter()
            .position(|node| node.summary.id == id)
            .ok_or(CoreError::NodeNotFound)?;
        let generation = self.next_generation()?;
        let retained = self
            .retained_node_bytes
            .checked_sub(self.nodes[position].charge)
            .ok_or(CoreError::StateUnavailable)?;
        self.nodes.remove(position);
        self.retained_node_bytes = retained;
        self.generation = generation;
        Ok(())
    }

    /// Stages an origin; compatibility discovery and TLS verification are unavailable in this release.
    pub fn stage_server(&mut self, raw: String) -> Result<String, CoreError> {
        let raw = Zeroizing::new(raw);
        let origin = normalize_server_origin(&raw)?;
        if self.server_candidate.as_ref() == Some(&origin) {
            return Ok(origin);
        }
        let generation = self.next_generation()?;
        self.server_candidate = Some(origin.clone());
        self.generation = generation;
        Ok(origin)
    }

    pub fn reset_server(&mut self) -> Result<(), CoreError> {
        if self.server_candidate.is_none() {
            return Ok(());
        }
        let generation = self.next_generation()?;
        self.server_candidate = None;
        self.generation = generation;
        Ok(())
    }

    /// Stores a validated draft. It does not establish a TUN or apply an Android allowlist.
    pub fn set_app_routing(
        &mut self,
        enabled: bool,
        packages: Vec<String>,
    ) -> Result<(), CoreError> {
        let selected_apps = normalize_packages(packages)?;
        if enabled && selected_apps.is_empty() {
            return Err(CoreError::EmptyRoutingSelection);
        }
        if self.routing_enabled == enabled && self.selected_apps == selected_apps {
            return Ok(());
        }
        let generation = self.next_generation()?;
        self.routing_enabled = enabled;
        self.selected_apps = selected_apps;
        self.generation = generation;
        Ok(())
    }

    pub fn connect(&mut self, id: String) -> Result<(), CoreError> {
        validate_node_id(&id)?;
        if !self.nodes.iter().any(|node| node.summary.id == id) {
            return Err(CoreError::NodeNotFound);
        }
        Err(CoreError::DataPlaneUnavailable)
    }

    /// There are no owned TUNs, connections or background tasks at this framework boundary.
    pub fn stop(&mut self) -> Result<(), CoreError> {
        self.begin_vpn_stop()?;
        Ok(())
    }

    fn next_generation(&self) -> Result<u64, CoreError> {
        self.generation
            .checked_add(1)
            .ok_or(CoreError::GenerationExhausted)
    }
}

fn normalize_packages(packages: Vec<String>) -> Result<Vec<String>, CoreError> {
    if packages.len() > MAX_ROUTING_PACKAGES {
        return Err(CoreError::RoutingSelectionTooLarge);
    }
    let mut bytes = 0usize;
    let mut selected = BTreeSet::new();
    for package in packages {
        validate_package_name(&package)?;
        bytes = bytes
            .checked_add(package.len())
            .ok_or(CoreError::RoutingSelectionTooLarge)?;
        if bytes > MAX_ROUTING_BYTES {
            return Err(CoreError::RoutingSelectionTooLarge);
        }
        selected.insert(package);
    }
    Ok(selected.into_iter().collect())
}

fn validate_node_id(id: &str) -> Result<(), CoreError> {
    if id.len() > MAX_NODE_ID_BYTES {
        return Err(CoreError::InputTooLarge);
    }
    Ok(())
}

fn validate_package_name(package: &str) -> Result<(), CoreError> {
    if package.is_empty() || package.len() > MAX_PACKAGE_NAME_BYTES || !package.is_ascii() {
        return Err(CoreError::InvalidPackageName);
    }
    let mut segment_count = 0;
    for segment in package.split('.') {
        if segment.is_empty()
            || !segment.as_bytes()[0].is_ascii_alphabetic()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(CoreError::InvalidPackageName);
        }
        segment_count += 1;
    }
    if segment_count < 2 {
        return Err(CoreError::InvalidPackageName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_epoch_exhaustion_denies_a_change_without_reusing_scope() {
        let mut core = CoreState::new();
        core.network_privacy_policy_epoch = u64::MAX;
        let before = core.snapshot();
        let policy = NetworkPrivacyPolicy {
            webrtc_policy: LeakProtectionMode::Block,
            ..Default::default()
        };
        assert_eq!(
            core.set_network_privacy_policy(policy, before.generation),
            Err(CoreError::GenerationExhausted)
        );
        assert_eq!(core.snapshot(), before);
    }

    #[test]
    fn privacy_epoch_max_serializes_as_an_exact_unsigned_decimal_string() {
        let mut core = CoreState::new();
        core.network_privacy_policy_epoch = u64::MAX;
        let node = core.import_node("socks5://proxy.example".into()).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        crate::test_support::freeze(&ticket, vec![]);
        let json: serde_json::Value =
            serde_json::from_str(&ticket.canonical_network_policy().unwrap()).unwrap();
        assert_eq!(json["policy_epoch"], "18446744073709551615");
        assert_eq!(ticket.network_policy_epoch(), u64::MAX);
    }

    // Catches generation wraparound admitting a new profile, route or node under a reused generation.
    #[test]
    fn generation_exhaustion_rejects_mutation_without_wrapping() {
        let mut core = CoreState::new();
        core.generation = u64::MAX;
        assert_eq!(
            core.stage_server("cloud.example".into()),
            Err(CoreError::GenerationExhausted)
        );
        assert_eq!(
            core.set_app_routing(true, vec!["net.aptist.loft".into()]),
            Err(CoreError::GenerationExhausted)
        );
        assert_eq!(
            core.import_node("socks5://proxy.example".into()),
            Err(CoreError::GenerationExhausted)
        );
        assert_eq!(core.snapshot().generation, u64::MAX);
        assert_eq!(core.snapshot().node_count, 0);
    }
}
