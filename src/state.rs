use crate::types::{AppState, DomainState, RenewalHistory};
use anyhow::{Context, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct StateManager {
    path: PathBuf,
    state: AppState,
}

impl StateManager {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            Self::load(&path)?
        } else {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
                }
            }
            AppState::default()
        };
        Ok(Self { path, state })
    }

    fn load(path: &Path) -> Result<AppState> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read state file: {}", path.display()))?;
        let state: AppState = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse state file: {}", path.display()))?;
        Ok(state)
    }

    pub fn save(&mut self) -> Result<()> {
        self.state.updated_at = Utc::now();
        let content = serde_json::to_string_pretty(&self.state)
            .context("Failed to serialize state")?;
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
            }
        }
        std::fs::write(&self.path, content)
            .with_context(|| format!("Failed to write state file: {}", self.path.display()))?;
        Ok(())
    }

    pub fn get_domain_state(&self, domain: &str) -> DomainState {
        self.state
            .domains
            .get(domain)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_domain_state_mut(&mut self, domain: &str) -> &mut DomainState {
        self.state
            .domains
            .entry(domain.to_string())
            .or_insert_with(DomainState::default)
    }

    pub fn update_scan_time(&mut self, domain: &str) {
        let state = self.get_domain_state_mut(domain);
        state.last_scan = Some(Utc::now());
    }

    pub fn update_renew_time(&mut self, domain: &str) {
        let state = self.get_domain_state_mut(domain);
        state.last_renew = Some(Utc::now());
    }

    pub fn update_fingerprint(&mut self, domain: &str, fingerprint: String) {
        let state = self.get_domain_state_mut(domain);
        state.current_fingerprint = Some(fingerprint);
    }

    pub fn update_notification_time(
        &mut self,
        domain: &str,
        level: crate::types::AlertLevel,
    ) {
        let state = self.get_domain_state_mut(domain);
        state
            .last_notifications
            .insert(level, Utc::now());
    }

    pub fn add_renewal_history(
        &mut self,
        domain: &str,
        history: RenewalHistory,
    ) {
        let state = self.get_domain_state_mut(domain);
        state.renewal_history.push(history);
        if state.renewal_history.len() > 5 {
            state.renewal_history = state.renewal_history.split_off(state.renewal_history.len() - 5);
        }
    }

    pub fn should_send_notification(
        &self,
        domain: &str,
        level: &crate::types::AlertLevel,
        debounce_hours: i64,
    ) -> bool {
        let state = self.state.domains.get(domain);
        let Some(state) = state else {
            return true;
        };
        let Some(last_sent) = state.last_notifications.get(level) else {
            return true;
        };
        let now = Utc::now();
        let duration = now.signed_duration_since(*last_sent);
        duration.num_hours() >= debounce_hours
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }
}
