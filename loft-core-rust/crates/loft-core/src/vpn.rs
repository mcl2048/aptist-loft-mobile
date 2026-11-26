use crate::{
    AppliedNetworkPrivacy, ConnectionState, CoreError, CoreState, HydraScope, NetworkPrivacyPolicy,
    NetworkPrivacyReceipt, NetworkScopeIdentity, ProtocolKind, normalize_packages,
    validate_node_id,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Policy {
    BlockedInVpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnFailure {
    EngineStartFailed,
    EngineUnavailable,
    Cancelled,
    Revoked,
    EngineStopFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRouting {
    pub enabled: bool,
    pub package_names: Vec<String>,
    pub ipv6_policy: Ipv6Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[cfg(test)]
mod lifecycle_counter_tests {
    use super::*;

    #[test]
    fn actual_stop_receipts_are_processed_at_global_counter_exhaustion() {
        let mut core = CoreState::new();
        let id = core
            .import_node("socks5://proxy.example".into())
            .unwrap()
            .id;
        let ticket = core
            .begin_vpn(id.clone(), core.snapshot().generation)
            .unwrap();
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
        core.generation = u64::MAX;
        assert_eq!(core.begin_vpn_stop(), Ok(ticket.attempt_id()));
        core.confirm_vpn_stopped(VpnStoppedReceipt {
            attempt_id: ticket.attempt_id(),
            tun_closed: true,
            resources_released: true,
        })
        .unwrap();
        assert_eq!(core.snapshot().generation, u64::MAX);
        assert_eq!(
            core.snapshot().connection_state,
            ConnectionState::Disconnected
        );
        assert!(matches!(
            core.begin_vpn(id, u64::MAX),
            Err(CoreError::GenerationExhausted)
        ));
    }

    #[test]
    fn exhausted_attempt_counter_never_wraps_into_a_reused_ticket() {
        let mut core = CoreState::new();
        let id = core
            .import_node("socks5://proxy.example".into())
            .unwrap()
            .id;
        core.vpn.next_attempt_id = u64::MAX;
        let before = core.snapshot();
        assert!(matches!(
            core.begin_vpn(id, before.generation),
            Err(CoreError::GenerationExhausted)
        ));
        assert_eq!(core.snapshot(), before);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnStoppedReceipt {
    pub attempt_id: u64,
    pub tun_closed: bool,
    pub resources_released: bool,
}

struct TicketContent {
    uri: Option<Zeroizing<String>>,
    effective_packages: Option<Vec<String>>,
    delivered: bool,
    network_scope: Option<NetworkScopeIdentity>,
    scope_id: Option<String>,
    policy_delivered: bool,
}

/// Native service-only object. No secret-bearing Debug/Serialize representation.
pub struct VpnStartTicket {
    attempt_id: u64,
    node_id: String,
    routing_enabled: bool,
    requested_packages: Vec<String>,
    protocol: ProtocolKind,
    network_privacy_policy: NetworkPrivacyPolicy,
    network_policy_epoch: u64,
    valid: AtomicBool,
    stop_signal: Arc<AtomicBool>,
    content: Mutex<TicketContent>,
}

impl VpnStartTicket {
    pub fn network_policy_epoch(&self) -> u64 {
        self.network_policy_epoch
    }
    pub fn network_privacy_policy(&self) -> NetworkPrivacyPolicy {
        self.network_privacy_policy.clone()
    }
    pub fn network_scope_id(&self) -> Result<String, CoreError> {
        self.content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?
            .scope_id
            .clone()
            .ok_or(CoreError::InvalidNetworkPrivacyReceipt)
    }
    pub fn freeze_network_scope(&self, scope: NetworkScopeIdentity) -> Result<(), CoreError> {
        self.check_valid()?;
        let mut content = self
            .content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?;
        self.check_valid()?;
        if content.network_scope.is_some() || content.delivered {
            return Err(CoreError::TicketExpired);
        }
        let packages = content
            .effective_packages
            .as_ref()
            .ok_or(CoreError::InvalidRoutingReceipt)?;
        let scope = scope.normalized(packages)?;
        let scope_id = scope.digest(
            self.attempt_id,
            &self.node_id,
            self.network_policy_epoch,
            self.routing_enabled,
            &self.network_privacy_policy,
        )?;
        self.check_valid()?;
        content.network_scope = Some(scope);
        content.scope_id = Some(scope_id);
        Ok(())
    }
    pub fn canonical_network_policy(&self) -> Result<String, CoreError> {
        self.check_valid()?;
        let mut content = self
            .content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?;
        self.check_valid()?;
        let scope = content
            .scope_id
            .as_ref()
            .ok_or(CoreError::InvalidNetworkPrivacyReceipt)?;
        let result = self
            .network_privacy_policy
            .canonical_json(self.network_policy_epoch, scope)?;
        self.check_valid()?;
        content.policy_delivered = true;
        Ok(result)
    }
    pub fn attempt_id(&self) -> u64 {
        self.attempt_id
    }
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }
    pub fn routing_enabled(&self) -> bool {
        self.routing_enabled
    }
    pub fn package_names(&self) -> Vec<String> {
        self.requested_packages.clone()
    }

    /// Trusted Android adapter supplies its exact installed/shared-UID-expanded Builder set.
    pub fn freeze_effective_packages(&self, packages: Vec<String>) -> Result<(), CoreError> {
        self.check_valid()?;
        let packages = normalize_packages(packages)?;
        if self.routing_enabled && packages.is_empty() {
            return Err(CoreError::EmptyRoutingSelection);
        }
        if !self.routing_enabled && !packages.is_empty() {
            return Err(CoreError::InvalidRoutingReceipt);
        }
        let mut content = self
            .content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?;
        self.check_valid()?;
        if content.effective_packages.is_some() || content.delivered {
            return Err(CoreError::TicketExpired);
        }
        content.effective_packages = Some(packages);
        Ok(())
    }

    pub fn take_raw_node(&self) -> Result<String, CoreError> {
        self.check_valid()?;
        let mut content = self
            .content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?;
        self.check_valid()?;
        if content.effective_packages.is_none() {
            return Err(CoreError::InvalidRoutingReceipt);
        }
        if content.network_scope.is_none() || !content.policy_delivered {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        let uri = content.uri.take().ok_or(CoreError::TicketExpired)?;
        let mut result = Zeroizing::new(uri.to_string());
        self.check_valid()?;
        content.delivered = true;
        Ok(std::mem::take(&mut *result))
    }

    fn check_valid(&self) -> Result<(), CoreError> {
        if !self.valid.load(Ordering::Acquire) || self.stop_signal.load(Ordering::Acquire) {
            return Err(CoreError::TicketExpired);
        }
        Ok(())
    }

    fn effective_packages(&self) -> Result<Vec<String>, CoreError> {
        self.content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?
            .effective_packages
            .clone()
            .ok_or(CoreError::InvalidRoutingReceipt)
    }

    fn delivered(&self) -> Result<bool, CoreError> {
        Ok(self
            .content
            .lock()
            .map_err(|_| CoreError::StateUnavailable)?
            .delivered)
    }

    fn applied_privacy(
        &self,
        receipt: &NetworkPrivacyReceipt,
    ) -> Result<AppliedNetworkPrivacy, CoreError> {
        if receipt.policy_epoch != self.network_policy_epoch {
            return Err(CoreError::StaleGeneration);
        }
        let policy = &self.network_privacy_policy;
        let scope = self.network_scope_id()?;
        let hydra_scope = if !policy.hydra.enabled {
            HydraScope::Off
        } else {
            match self.protocol {
                ProtocolKind::HyrakenX => HydraScope::LogicalStreams,
                ProtocolKind::HyrakenPro => HydraScope::TcpOnly,
                ProtocolKind::Socks5 => return Err(CoreError::UnsupportedNetworkPrivacyPolicy),
            }
        };
        if receipt.scope_id != scope
            || receipt.dns_mode != policy.dns_mode
            || receipt.dns_leak_policy != policy.dns_leak_policy
            || receipt.webrtc_policy != policy.webrtc_policy
            || !receipt.policy_installed
            || !receipt.enforcement_active
            || !receipt.dns_protection_enforced
            || !receipt.webrtc_protection_enforced
            || !receipt.ipv6_drop_active
            || receipt.ownership_pending
            || receipt.hydra_enabled != policy.hydra.enabled
            || receipt.hydra_applied != policy.hydra.enabled
            || receipt.hydra_scope != hydra_scope
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        Ok(AppliedNetworkPrivacy {
            policy_epoch: self.network_policy_epoch,
            scope_id: scope,
            policy: policy.clone(),
            hydra_scope,
        })
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
        if let Ok(mut content) = self.content.try_lock() {
            content.uri = None;
        }
    }
}

pub(crate) struct VpnLifecycle {
    pub(crate) state: ConnectionState,
    next_attempt_id: u64,
    pub(crate) current_attempt_id: u64,
    pub(crate) target: Option<String>,
    ticket: Option<Arc<VpnStartTicket>>,
    pub(crate) applied: Option<AppliedRouting>,
    pub(crate) failure: Option<VpnFailure>,
    pub(crate) applied_network_privacy: Option<AppliedNetworkPrivacy>,
}

impl Default for VpnLifecycle {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            next_attempt_id: 1,
            current_attempt_id: 0,
            target: None,
            ticket: None,
            applied: None,
            failure: None,
            applied_network_privacy: None,
        }
    }
}

impl CoreState {
    pub fn begin_vpn(
        &mut self,
        node_id: String,
        expected_snapshot_generation: u64,
    ) -> Result<Arc<VpnStartTicket>, CoreError> {
        if expected_snapshot_generation != self.generation {
            return Err(CoreError::StaleGeneration);
        }
        if self.vpn.state != ConnectionState::Disconnected
            || self.stop_signal.load(Ordering::Acquire)
        {
            return Err(CoreError::ConnectionBusy);
        }
        validate_node_id(&node_id)?;
        let node = self
            .nodes
            .iter()
            .find(|node| node.summary.id == node_id)
            .ok_or(CoreError::NodeNotFound)?;
        if self.network_privacy_policy.hydra.enabled
            && node.summary.protocol == ProtocolKind::Socks5
        {
            return Err(CoreError::UnsupportedNetworkPrivacyPolicy);
        }
        let generation = self.next_generation()?;
        let next_attempt = self
            .vpn
            .next_attempt_id
            .checked_add(1)
            .ok_or(CoreError::GenerationExhausted)?;
        let uri = node.config.canonical_uri()?;
        let ticket = Arc::new(VpnStartTicket {
            attempt_id: self.vpn.next_attempt_id,
            node_id: node_id.clone(),
            routing_enabled: self.routing_enabled,
            requested_packages: self.selected_apps.clone(),
            protocol: node.summary.protocol,
            network_privacy_policy: self.network_privacy_policy.clone(),
            network_policy_epoch: self.network_privacy_policy_epoch,
            valid: AtomicBool::new(true),
            stop_signal: self.stop_signal.clone(),
            content: Mutex::new(TicketContent {
                uri: Some(uri),
                effective_packages: None,
                delivered: false,
                network_scope: None,
                scope_id: None,
                policy_delivered: false,
            }),
        });
        self.vpn.current_attempt_id = ticket.attempt_id;
        self.vpn.next_attempt_id = next_attempt;
        self.vpn.target = Some(node_id);
        self.vpn.ticket = Some(ticket.clone());
        self.vpn.applied = None;
        self.vpn.applied_network_privacy = None;
        self.vpn.failure = None;
        self.vpn.state = ConnectionState::Connecting;
        self.generation = generation;
        Ok(ticket)
    }

    pub fn mark_vpn_ready(&mut self, receipt: VpnReadyReceipt) -> Result<(), CoreError> {
        self.check_attempt(receipt.attempt_id)?;
        if self.stop_signal.load(Ordering::Acquire)
            || !matches!(
                self.vpn.state,
                ConnectionState::Connecting | ConnectionState::Connected
            )
        {
            return Err(CoreError::StaleGeneration);
        }
        if !receipt.transport_ready
            || !receipt.authenticated
            || !receipt.tun_ready
            || !receipt.sockets_protected
        {
            return Err(CoreError::InvalidEngineReceipt);
        }
        let ticket = self
            .vpn
            .ticket
            .as_ref()
            .ok_or(CoreError::InvalidEngineReceipt)?;
        if !ticket.delivered()? {
            return Err(CoreError::InvalidEngineReceipt);
        }
        let packages = normalize_packages(receipt.applied_package_names)?;
        if packages != ticket.effective_packages()? {
            return Err(CoreError::InvalidRoutingReceipt);
        }
        if !receipt.ipv4_capture_confirmed
            || !receipt.no_bypass_confirmed
            || !receipt.ipv6_blocked_confirmed
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        let privacy = ticket.applied_privacy(&receipt.privacy)?;
        let applied = AppliedRouting {
            enabled: ticket.routing_enabled,
            package_names: packages,
            ipv6_policy: receipt.ipv6_policy,
        };
        if self.vpn.state == ConnectionState::Connected {
            return if self.vpn.applied.as_ref() == Some(&applied)
                && self.vpn.applied_network_privacy.as_ref() == Some(&privacy)
            {
                Ok(())
            } else {
                Err(CoreError::InvalidRoutingReceipt)
            };
        }
        ticket.invalidate();
        self.vpn.applied = Some(applied);
        self.vpn.applied_network_privacy = Some(privacy);
        self.vpn.state = ConnectionState::Connected;
        self.advance_lifecycle_generation();
        Ok(())
    }

    pub fn mark_vpn_failed(
        &mut self,
        attempt_id: u64,
        reason: VpnFailure,
    ) -> Result<(), CoreError> {
        self.check_attempt(attempt_id)?;
        let priority_reason = matches!(
            reason,
            VpnFailure::Cancelled | VpnFailure::Revoked | VpnFailure::EngineStopFailed
        );
        if self.vpn.state == ConnectionState::Disconnected
            || (self.stop_signal.load(Ordering::Acquire)
                && (self.vpn.state != ConnectionState::Stopping || !priority_reason))
        {
            return Err(CoreError::StaleGeneration);
        }
        if let Some(ticket) = &self.vpn.ticket {
            ticket.invalidate();
        }
        if self.vpn.failure != Some(VpnFailure::Revoked) || reason == VpnFailure::Revoked {
            self.vpn.failure = Some(reason);
        }
        self.vpn.state = ConnectionState::Stopping;
        self.advance_lifecycle_generation();
        Ok(())
    }

    pub fn mark_vpn_blocked(&mut self, receipt: VpnBlockedReceipt) -> Result<(), CoreError> {
        self.check_attempt(receipt.attempt_id)?;
        if self.stop_signal.load(Ordering::Acquire)
            || !matches!(
                self.vpn.state,
                ConnectionState::Stopping | ConnectionState::Blocked
            )
        {
            return Err(CoreError::StaleGeneration);
        }
        if !receipt.tun_held || !receipt.forwarding_disabled {
            return Err(CoreError::InvalidEngineReceipt);
        }
        let ticket = self
            .vpn
            .ticket
            .as_ref()
            .ok_or(CoreError::InvalidEngineReceipt)?;
        let packages = normalize_packages(receipt.effective_package_names)?;
        if packages != ticket.effective_packages()? {
            return Err(CoreError::InvalidRoutingReceipt);
        }
        if receipt.policy_epoch != ticket.network_policy_epoch {
            return Err(CoreError::StaleGeneration);
        }
        let scope = ticket.network_scope_id()?;
        if receipt.scope_id != scope
            || !receipt.ipv4_capture_confirmed
            || !receipt.no_bypass_confirmed
            || !receipt.ipv6_blocked_confirmed
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        self.vpn.applied = Some(AppliedRouting {
            enabled: ticket.routing_enabled,
            package_names: packages,
            ipv6_policy: receipt.ipv6_policy,
        });
        self.vpn.applied_network_privacy = Some(AppliedNetworkPrivacy {
            policy_epoch: ticket.network_policy_epoch,
            scope_id: scope,
            policy: ticket.network_privacy_policy.clone(),
            hydra_scope: HydraScope::Off,
        });
        self.vpn.state = ConnectionState::Blocked;
        self.advance_lifecycle_generation();
        Ok(())
    }

    pub fn begin_vpn_stop(&mut self) -> Result<u64, CoreError> {
        self.stop_signal.store(true, Ordering::Release);
        if self.vpn.state == ConnectionState::Disconnected
            || self.vpn.state == ConnectionState::Stopping
        {
            return Ok(self.vpn.current_attempt_id);
        }
        if let Some(ticket) = &self.vpn.ticket {
            ticket.invalidate();
        }
        self.vpn.state = ConnectionState::Stopping;
        self.advance_lifecycle_generation();
        Ok(self.vpn.current_attempt_id)
    }

    pub fn confirm_vpn_stopped(&mut self, receipt: VpnStoppedReceipt) -> Result<(), CoreError> {
        self.check_attempt(receipt.attempt_id)?;
        if !receipt.tun_closed || !receipt.resources_released {
            return Err(CoreError::EngineStopIncomplete);
        }
        if self.vpn.state == ConnectionState::Disconnected {
            self.stop_signal.store(false, Ordering::Release);
            return Ok(());
        }
        if self.stop_signal.load(Ordering::Acquire) {
            self.reconcile_priority_stop();
        }
        if self.vpn.state != ConnectionState::Stopping {
            return Err(CoreError::InvalidEngineReceipt);
        }
        if let Some(ticket) = &self.vpn.ticket {
            ticket.invalidate();
        }
        self.vpn.ticket = None;
        self.vpn.target = None;
        self.vpn.applied = None;
        self.vpn.applied_network_privacy = None;
        self.vpn.state = ConnectionState::Disconnected;
        self.stop_signal.store(false, Ordering::Release);
        self.advance_lifecycle_generation();
        Ok(())
    }

    pub fn reconcile_priority_stop(&mut self) {
        if self.stop_signal.load(Ordering::Acquire)
            && !matches!(
                self.vpn.state,
                ConnectionState::Disconnected | ConnectionState::Stopping
            )
        {
            if let Some(ticket) = &self.vpn.ticket {
                ticket.invalidate();
            }
            self.vpn.state = ConnectionState::Stopping;
            self.advance_lifecycle_generation();
        }
    }

    fn check_attempt(&self, attempt_id: u64) -> Result<(), CoreError> {
        if attempt_id != self.vpn.current_attempt_id {
            return Err(CoreError::StaleGeneration);
        }
        Ok(())
    }

    fn advance_lifecycle_generation(&mut self) {
        // New admission fails at MAX; cancellation and actual receipts still need processing.
        self.generation = self.generation.saturating_add(1);
    }
}
