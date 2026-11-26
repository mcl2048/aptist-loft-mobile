use crate::{
    CoreError, CoreState, NetworkPrivacyPolicy, NodeEntry, import, normalize_packages,
    normalize_server_origin,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicBool};

/// Local anonymous preferences. Future account and module data require their own scopes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSettings {
    pub server_candidate: Option<String>,
    pub routing_enabled: bool,
    pub selected_apps: Vec<String>,
    pub network_privacy_policy: NetworkPrivacyPolicy,
    pub network_privacy_policy_epoch: u64,
}

impl Default for LocalSettings {
    fn default() -> Self {
        Self {
            server_candidate: None,
            routing_enabled: false,
            selected_apps: Vec::new(),
            network_privacy_policy: NetworkPrivacyPolicy::default(),
            network_privacy_policy_epoch: 1,
        }
    }
}

pub enum LocalConfigEdit<'a> {
    ImportNode { id: u64, uri: &'a str },
    RemoveNode { id: u64 },
    Settings(&'a LocalSettings),
}

pub struct LoadedLocalConfig {
    pub generation: u64,
    pub next_node_id: u64,
    pub settings: LocalSettings,
}

/// Called only by the single serialized business-state owner. Node rows are visited
/// in ascending numeric ID order and borrowed for the duration of the callback.
pub trait LocalConfigStore: Send {
    fn load_config(&self) -> Result<LoadedLocalConfig, CoreError>;
    fn visit_nodes(
        &self,
        visitor: &mut dyn FnMut(u64, &str) -> Result<(), CoreError>,
    ) -> Result<(), CoreError>;
    fn commit(&mut self, generation: u64, edit: LocalConfigEdit<'_>) -> Result<(), CoreError>;
}

impl CoreState {
    pub fn with_local_storage(
        stop_signal: Arc<AtomicBool>,
        store: impl LocalConfigStore + 'static,
    ) -> Result<Self, CoreError> {
        let config = store.load_config()?;
        let mut state = Self::with_stop_signal(stop_signal);
        config.settings.validate_loaded(config.generation)?;
        if config.next_node_id == 0 || config.next_node_id - 1 > config.generation {
            return Err(CoreError::StorageRecoveryRequired);
        }
        let mut previous_id = 0;
        store.visit_nodes(&mut |id, raw| {
            if id <= previous_id || id >= config.next_node_id {
                return Err(CoreError::StorageRecoveryRequired);
            }
            let candidate =
                import::parse_node(raw, None).map_err(|_| CoreError::StorageRecoveryRequired)?;
            let (charge, retained) = state
                .admit_node(&candidate)
                .map_err(|_| CoreError::StorageRecoveryRequired)?;
            let summary = candidate.summary(format!("node-{id:016x}"));
            state.nodes.push(NodeEntry {
                id,
                summary,
                config: candidate.config,
                charge,
            });
            state.retained_node_bytes = retained;
            previous_id = id;
            Ok(())
        })?;
        state.generation = config.generation;
        state.next_node_id = config.next_node_id;
        state.local = config.settings;
        state.local_store = Some(Box::new(store));
        Ok(state)
    }

    pub(crate) fn require_local_config(&self) -> Result<(), CoreError> {
        if self.local_storage_failed {
            return Err(CoreError::StorageRecoveryRequired);
        }
        Ok(())
    }

    pub(crate) fn commit_local(
        &mut self,
        generation: u64,
        edit: LocalConfigEdit<'_>,
    ) -> Result<(), CoreError> {
        self.require_local_config()?;
        if let Some(store) = &mut self.local_store {
            let result = store.commit(generation, edit);
            if result == Err(CoreError::StorageRecoveryRequired) {
                self.local_storage_failed = true;
            }
            result?;
        }
        Ok(())
    }

    pub(crate) fn commit_local_settings(
        &mut self,
        generation: u64,
        settings: LocalSettings,
    ) -> Result<(), CoreError> {
        self.commit_local(generation, LocalConfigEdit::Settings(&settings))?;
        self.local = settings;
        self.generation = generation;
        Ok(())
    }
}

impl LocalSettings {
    fn validate_loaded(&self, generation: u64) -> Result<(), CoreError> {
        let valid_origin = self.server_candidate.as_ref().is_none_or(|origin| {
            normalize_server_origin(origin).is_ok_and(|normalized| *origin == normalized)
        });
        let valid_apps = normalize_packages(self.selected_apps.clone())
            .is_ok_and(|normalized| self.selected_apps == normalized)
            && (!self.routing_enabled || !self.selected_apps.is_empty());
        let valid_privacy = self.network_privacy_policy_epoch != 0
            && self.network_privacy_policy_epoch - 1 <= generation
            && self
                .network_privacy_policy
                .clone()
                .normalized()
                .is_ok_and(|policy| policy == self.network_privacy_policy);
        if !valid_origin || !valid_apps || !valid_privacy {
            return Err(CoreError::StorageRecoveryRequired);
        }
        Ok(())
    }
}
