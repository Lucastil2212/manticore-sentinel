use std::time::{Duration, Instant};

use crate::core::command::CommandAction;
use crate::security::auth::{AuthContext, Permission};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemActionPolicy {
    pub action: String,
    pub constraints: SystemActionConstraints,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemActionConstraints {
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    #[serde(default)]
    pub require_capability: Option<String>,
    #[serde(default)]
    pub deny_on_hosts: Vec<String>,
    #[serde(default)]
    pub require_confirmation: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub policy_hash: Option<String>,
}

pub struct ExecutionPolicy {
    auth: AuthContext,
    last_kill_at: Option<Instant>,
    kill_cooldown: Duration,
    hostname: String,
    evrus_policy: Option<SystemActionPolicy>,
    evrus_policy_hash: Option<String>,
}

impl ExecutionPolicy {
    pub fn new(auth: AuthContext, evrus_policy: Option<SystemActionPolicy>) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
        let evrus_policy_hash = evrus_policy
            .as_ref()
            .and_then(|policy| serde_json::to_string(policy).ok())
            .map(|json| sha256_hex(json.as_bytes()));
        Self {
            auth,
            last_kill_at: None,
            kill_cooldown: Duration::from_secs(2),
            hostname,
            evrus_policy,
            evrus_policy_hash,
        }
    }

    pub fn load_evrus_policy() -> Option<SystemActionPolicy> {
        let inline = std::env::var("MANTICORE_EVRUS_POLICY_JSON").ok();
        let file = std::env::var("MANTICORE_EVRUS_POLICY_PATH")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        let raw = inline.or(file)?;
        serde_json::from_str::<SystemActionPolicy>(&raw).ok()
    }

    pub fn evaluate(&self, action: &CommandAction) -> Result<PolicyDecision, String> {
        let permission = match action {
            CommandAction::ShowCpu => Permission::ViewSystemMetrics,
            CommandAction::KillProcess { .. } => Permission::KillProcess,
            CommandAction::ReniceProcess { .. } => Permission::ReniceProcess,
        };
        if !self.auth.allows(permission) {
            return Err(format!(
                "policy denied: role={} mode={} missing permission for {:?}",
                self.auth.role.as_str(),
                self.auth.mode.as_str(),
                permission
            ));
        }
        if let Some(evrus_policy) = &self.evrus_policy {
            self.evaluate_evrus_policy(action, evrus_policy)?;
        }
        match action {
            CommandAction::ShowCpu => Ok(PolicyDecision {
                policy_hash: self.evrus_policy_hash.clone(),
            }),
            CommandAction::KillProcess { .. } | CommandAction::ReniceProcess { .. } => {
                if let CommandAction::KillProcess { .. } = action {
                    if let Some(last) = self.last_kill_at {
                        if last.elapsed() < self.kill_cooldown {
                            return Err("policy denied: kill action in cooldown window".to_string());
                        }
                    }
                }
                Ok(PolicyDecision {
                    policy_hash: self.evrus_policy_hash.clone(),
                })
            }
        }
    }

    pub fn record(&mut self, action: &CommandAction) {
        if matches!(action, CommandAction::KillProcess { .. }) {
            self.last_kill_at = Some(Instant::now());
        }
    }

    pub fn current_policy_hash(&self) -> Option<String> {
        self.evrus_policy_hash.clone()
    }

    fn evaluate_evrus_policy(
        &self,
        action: &CommandAction,
        policy: &SystemActionPolicy,
    ) -> Result<(), String> {
        let action_name = match action {
            CommandAction::ShowCpu => "show_cpu",
            CommandAction::KillProcess { .. } => "kill_process",
            CommandAction::ReniceProcess { .. } => "renice_process",
        };
        if policy.action != action_name && policy.action != "*" {
            return Ok(());
        }
        if !policy.constraints.allowed_roles.is_empty()
            && !policy
                .constraints
                .allowed_roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case(self.auth.role.as_str()))
        {
            return Err("policy denied: EVRUS allowed_roles mismatch".to_string());
        }
        if let Some(required) = &policy.constraints.require_capability {
            let action_capability = match action {
                CommandAction::ShowCpu => "ViewSystemMetrics",
                CommandAction::KillProcess { .. } => "KillProcess",
                CommandAction::ReniceProcess { .. } => "ReniceProcess",
            };
            if !required.eq_ignore_ascii_case(action_capability) {
                return Err(format!(
                    "policy denied: EVRUS require_capability mismatch ({required})"
                ));
            }
        }
        for pattern in &policy.constraints.deny_on_hosts {
            if host_pattern_matches(&self.hostname, pattern) {
                return Err(format!("policy denied: host matched deny pattern {pattern}"));
            }
        }
        if policy.constraints.require_confirmation && matches!(action, CommandAction::ReniceProcess { .. }) {
            return Err("policy denied: EVRUS requires explicit confirmation for renice".to_string());
        }
        Ok(())
    }
}

fn host_pattern_matches(hostname: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return hostname.starts_with(prefix);
    }
    hostname == pattern
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
