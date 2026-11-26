use crate::{CoreError, MAX_ROUTING_BYTES, MAX_ROUTING_PACKAGES, validate_package_name};
use sha2::{Digest, Sha256};
use std::net::SocketAddrV4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    NodeDomainFakeIp,
    WireTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakProtectionMode {
    ProxyOnly,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydraScope {
    Off,
    LogicalStreams,
    TcpOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPrivacyEnforcement {
    Inactive,
    Active,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPrivacyLimits {
    pub map_max_entries: u32,
    pub map_max_bytes: u32,
    pub ttl_seconds: u32,
    pub max_query_bytes: u32,
    pub max_response_bytes: u32,
}
impl Default for DnsPrivacyLimits {
    fn default() -> Self {
        Self {
            map_max_entries: 256,
            map_max_bytes: 262144,
            ttl_seconds: 60,
            max_query_bytes: 4096,
            max_response_bytes: 65535,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
impl Default for HydraConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_jitter: false,
            rotation_seconds: 300,
            rotation_jitter_percent: 0,
            chunk_min_percent: 0,
            burst_min_records: 0,
            burst_max_records: 0,
            padding_gap_max_records: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPrivacyPolicy {
    pub dns_mode: DnsMode,
    pub dns_leak_policy: LeakProtectionMode,
    pub webrtc_policy: LeakProtectionMode,
    pub resolver_endpoint: String,
    pub dns_limits: DnsPrivacyLimits,
    pub hydra: HydraConfig,
}
impl Default for NetworkPrivacyPolicy {
    fn default() -> Self {
        Self {
            dns_mode: DnsMode::NodeDomainFakeIp,
            dns_leak_policy: LeakProtectionMode::ProxyOnly,
            webrtc_policy: LeakProtectionMode::ProxyOnly,
            resolver_endpoint: String::new(),
            dns_limits: DnsPrivacyLimits::default(),
            hydra: HydraConfig::default(),
        }
    }
}
impl NetworkPrivacyPolicy {
    pub fn normalized(mut self) -> Result<Self, CoreError> {
        if self.resolver_endpoint.len() > 64 {
            return Err(CoreError::InvalidNetworkPrivacyPolicy);
        }
        match self.dns_mode {
            DnsMode::NodeDomainFakeIp if !self.resolver_endpoint.is_empty() => {
                return Err(CoreError::InvalidNetworkPrivacyPolicy);
            }
            DnsMode::NodeDomainFakeIp => {}
            DnsMode::WireTcp => {
                let endpoint: SocketAddrV4 = self
                    .resolver_endpoint
                    .parse()
                    .map_err(|_| CoreError::InvalidNetworkPrivacyPolicy)?;
                if endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_multicast()
                {
                    return Err(CoreError::InvalidNetworkPrivacyPolicy);
                }
                self.resolver_endpoint = endpoint.to_string();
            }
        }
        let limits = &self.dns_limits;
        if !(1..=256).contains(&limits.map_max_entries)
            || !(1024..=262144).contains(&limits.map_max_bytes)
            || limits.map_max_bytes < limits.map_max_entries * 1024
            || !(1..=60).contains(&limits.ttl_seconds)
            || !(12..=4096).contains(&limits.max_query_bytes)
            || !(12..=65535).contains(&limits.max_response_bytes)
        {
            return Err(CoreError::InvalidNetworkPrivacyPolicy);
        }
        let hydra = &mut self.hydra;
        if hydra.rotation_seconds == 0 {
            hydra.rotation_seconds = 300;
        }
        let burst_min = if hydra.burst_min_records == 0 {
            2
        } else {
            hydra.burst_min_records
        };
        let burst_max = if hydra.burst_max_records == 0 {
            32
        } else {
            hydra.burst_max_records
        };
        if !(10..=86400).contains(&hydra.rotation_seconds)
            || hydra.rotation_jitter_percent > 40
            || (hydra.chunk_min_percent != 0 && !(25..=50).contains(&hydra.chunk_min_percent))
            || hydra.burst_min_records > 32
            || hydra.burst_max_records > 32
            || burst_min > burst_max
            || hydra.padding_gap_max_records > 64
        {
            return Err(CoreError::InvalidNetworkPrivacyPolicy);
        }
        Ok(self)
    }

    pub(crate) fn canonical_json(&self, epoch: u64, scope: &str) -> Result<String, CoreError> {
        if scope.len() != 64
            || !scope
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        let dns_mode = match self.dns_mode {
            DnsMode::NodeDomainFakeIp => "node_domain_fake_ip",
            DnsMode::WireTcp => "wire_tcp",
        };
        let leak = |mode| match mode {
            LeakProtectionMode::ProxyOnly => "proxy_only",
            LeakProtectionMode::Block => "block",
        };
        // All interpolated strings are closed enum values, normalized literal IPv4/port, or hex.
        let result = format!(
            r#"{{"schema_version":1,"policy_epoch":"{epoch}","scope_id":"{scope}","dns_mode":"{dns_mode}","dns_leak_policy":"{dns_leak}","webrtc_policy":"{rtc}","resolver_endpoint":"{resolver}","dns_map_max_entries":{entries},"dns_map_max_bytes":{bytes},"dns_ttl_seconds":{ttl},"dns_max_query_bytes":{query},"dns_max_response_bytes":{response},"hydra":{{"enabled":{enabled},"auto_jitter":{jitter},"rotation_seconds":{rotation},"rotation_jitter_percent":{rotation_jitter},"chunk_min_percent":{chunk},"burst_min_records":{burst_min},"burst_max_records":{burst_max},"padding_gap_max_records":{padding_gap}}}}}"#,
            dns_leak = leak(self.dns_leak_policy),
            rtc = leak(self.webrtc_policy),
            resolver = self.resolver_endpoint,
            entries = self.dns_limits.map_max_entries,
            bytes = self.dns_limits.map_max_bytes,
            ttl = self.dns_limits.ttl_seconds,
            query = self.dns_limits.max_query_bytes,
            response = self.dns_limits.max_response_bytes,
            enabled = self.hydra.enabled,
            jitter = self.hydra.auto_jitter,
            rotation = self.hydra.rotation_seconds,
            rotation_jitter = self.hydra.rotation_jitter_percent,
            chunk = self.hydra.chunk_min_percent,
            burst_min = self.hydra.burst_min_records,
            burst_max = self.hydra.burst_max_records,
            padding_gap = self.hydra.padding_gap_max_records,
        );
        if result.len() > 4096 {
            return Err(CoreError::InputTooLarge);
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedNetworkPrivacy {
    pub policy_epoch: u64,
    pub scope_id: String,
    pub policy: NetworkPrivacyPolicy,
    pub hydra_scope: HydraScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePackageUid {
    pub package_name: String,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkScopeIdentity {
    pub vpn_owner_uid: u32,
    pub package_uids: Vec<EffectivePackageUid>,
}

impl NetworkScopeIdentity {
    pub(crate) fn normalized(mut self, packages: &[String]) -> Result<Self, CoreError> {
        const UIDS_PER_ANDROID_USER: u32 = 100000;
        if self.vpn_owner_uid == 0
            || self.vpn_owner_uid > i32::MAX as u32
            || self.package_uids.len() > MAX_ROUTING_PACKAGES
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        let mut bytes = 0usize;
        for pair in &self.package_uids {
            validate_package_name(&pair.package_name)
                .map_err(|_| CoreError::InvalidNetworkPrivacyReceipt)?;
            bytes = bytes
                .checked_add(pair.package_name.len())
                .ok_or(CoreError::InvalidNetworkPrivacyReceipt)?;
            if bytes > MAX_ROUTING_BYTES
                || pair.uid == 0
                || pair.uid > i32::MAX as u32
                || pair.uid / UIDS_PER_ANDROID_USER != self.vpn_owner_uid / UIDS_PER_ANDROID_USER
            {
                return Err(CoreError::InvalidNetworkPrivacyReceipt);
            }
        }
        self.package_uids
            .sort_by(|a, b| a.package_name.cmp(&b.package_name));
        if self
            .package_uids
            .windows(2)
            .any(|pair| pair[0].package_name == pair[1].package_name)
            || !self
                .package_uids
                .iter()
                .map(|pair| &pair.package_name)
                .eq(packages.iter())
        {
            return Err(CoreError::InvalidNetworkPrivacyReceipt);
        }
        Ok(self)
    }

    pub(crate) fn digest(
        &self,
        attempt: u64,
        node: &str,
        epoch: u64,
        routing_enabled: bool,
        policy: &NetworkPrivacyPolicy,
    ) -> Result<String, CoreError> {
        let mut hash = Sha256::new();
        hash.update(b"loft.network-privacy.scope.v1\0");
        hash.update(attempt.to_be_bytes());
        hash.update((node.len() as u32).to_be_bytes());
        hash.update(node.as_bytes());
        hash.update([u8::from(routing_enabled)]);
        hash.update(self.vpn_owner_uid.to_be_bytes());
        hash.update((self.package_uids.len() as u32).to_be_bytes());
        for pair in &self.package_uids {
            hash.update((pair.package_name.len() as u32).to_be_bytes());
            hash.update(pair.package_name.as_bytes());
            hash.update(pair.uid.to_be_bytes());
        }
        hash.update(policy.canonical_json(epoch, &"0".repeat(64))?.as_bytes());
        Ok(format!("{:x}", hash.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
