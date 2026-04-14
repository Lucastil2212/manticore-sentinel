use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::command::CommandAction;
use crate::core::snapshot::SystemSnapshot;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertPolicy {
    #[serde(default)]
    pub rules: Vec<AlertRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertRule {
    pub id: String,
    pub metric: String,
    pub op: String,
    pub threshold: f64,
    #[serde(default)]
    pub for_cycles: u32,
    pub severity: AlertSeverity,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct AlertMatch {
    pub rule_id: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
}

pub struct ExecutionPolicy {
    auth: AuthContext,
    last_kill_at: Option<Instant>,
    kill_cooldown: Duration,
    hostname: String,
    evrus_policy: Option<SystemActionPolicy>,
    evrus_policy_hash: Option<String>,
    alert_policy: Option<AlertPolicy>,
    alert_rule_streaks: HashMap<String, u32>,
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
            alert_policy: Self::load_alert_policy(),
            alert_rule_streaks: HashMap::new(),
        }
    }

    pub fn load_evrus_policy() -> Option<SystemActionPolicy> {
        let inline = std::env::var("MANTICORE_EVRUS_POLICY_JSON").ok();
        let file = std::env::var("MANTICORE_EVRUS_POLICY_PATH")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        let raw = inline.or(file)?;
        match serde_json::from_str::<SystemActionPolicy>(&raw) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("failed to parse EVRUS policy JSON: {e}");
                None
            }
        }
    }

    pub fn load_alert_policy() -> Option<AlertPolicy> {
        let inline = std::env::var("MANTICORE_ALERT_POLICY_JSON").ok();
        let file = std::env::var("MANTICORE_ALERT_POLICY_PATH")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        let raw = inline.or(file)?;
        match serde_json::from_str::<AlertPolicy>(&raw) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("failed to parse alert policy JSON: {e}");
                None
            }
        }
    }

    pub fn policy_load_warnings() -> Vec<String> {
        let mut warnings = Vec::new();
        if let Ok(raw) = std::env::var("MANTICORE_EVRUS_POLICY_JSON") {
            if serde_json::from_str::<SystemActionPolicy>(&raw).is_err() {
                warnings.push("MANTICORE_EVRUS_POLICY_JSON contains invalid JSON".to_string());
            }
        }
        if let Ok(path) = std::env::var("MANTICORE_EVRUS_POLICY_PATH") {
            match std::fs::read_to_string(&path) {
                Err(_) => warnings.push(format!(
                    "MANTICORE_EVRUS_POLICY_PATH '{}' not readable",
                    path
                )),
                Ok(raw) => {
                    if serde_json::from_str::<SystemActionPolicy>(&raw).is_err() {
                        warnings.push(format!(
                            "MANTICORE_EVRUS_POLICY_PATH '{}' contains invalid JSON",
                            path
                        ));
                    }
                }
            }
        }
        if let Ok(raw) = std::env::var("MANTICORE_ALERT_POLICY_JSON") {
            if serde_json::from_str::<AlertPolicy>(&raw).is_err() {
                warnings.push("MANTICORE_ALERT_POLICY_JSON contains invalid JSON".to_string());
            }
        }
        if let Ok(path) = std::env::var("MANTICORE_ALERT_POLICY_PATH") {
            match std::fs::read_to_string(&path) {
                Err(_) => warnings.push(format!(
                    "MANTICORE_ALERT_POLICY_PATH '{}' not readable",
                    path
                )),
                Ok(raw) => {
                    if serde_json::from_str::<AlertPolicy>(&raw).is_err() {
                        warnings.push(format!(
                            "MANTICORE_ALERT_POLICY_PATH '{}' contains invalid JSON",
                            path
                        ));
                    }
                }
            }
        }
        warnings
    }

    pub fn evaluate(&self, action: &CommandAction) -> Result<PolicyDecision, String> {
        let permission = match action {
            CommandAction::ShowCpu
            | CommandAction::ShowMemory
            | CommandAction::ShowDisk
            | CommandAction::ShowNetwork
            | CommandAction::ShowProcesses { .. }
            | CommandAction::ShowAlerts
            | CommandAction::ShowConfig
            | CommandAction::ShowConnectors
            | CommandAction::ShowAudit { .. }
            | CommandAction::ShowStorage
            | CommandAction::Help { .. } => Permission::ViewSystemMetrics,
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

    pub fn record(&mut self, action: &CommandAction) {
        if matches!(action, CommandAction::KillProcess { .. }) {
            self.last_kill_at = Some(Instant::now());
        }
    }

    pub fn current_policy_hash(&self) -> Option<String> {
        self.evrus_policy_hash.clone()
    }

    pub fn evaluate_snapshot_alerts(&mut self, snapshot: &SystemSnapshot) -> Vec<AlertMatch> {
        let Some(policy) = &self.alert_policy else {
            return Vec::new();
        };
        let mut alerts = Vec::new();
        for rule in &policy.rules {
            let Some(value) = snapshot_metric_value(snapshot, &rule.metric) else {
                continue;
            };
            let matched = compare(rule.op.as_str(), value, rule.threshold);
            let streak_entry = self.alert_rule_streaks.entry(rule.id.clone()).or_insert(0);
            if matched {
                *streak_entry = streak_entry.saturating_add(1);
            } else {
                *streak_entry = 0;
            }
            let needed = rule.for_cycles.max(1);
            if matched && *streak_entry >= needed {
                alerts.push(AlertMatch {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    message: rule.message.clone().unwrap_or_else(|| {
                        format!("{} {} {}", rule.metric, rule.op, rule.threshold)
                    }),
                    value,
                    threshold: rule.threshold,
                });
            }
        }
        alerts
    }

    fn evaluate_evrus_policy(
        &self,
        action: &CommandAction,
        policy: &SystemActionPolicy,
    ) -> Result<(), String> {
        let action_name = match action {
            CommandAction::KillProcess { .. } => "kill_process",
            CommandAction::ReniceProcess { .. } => "renice_process",
            _ => "read_only",
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
                CommandAction::KillProcess { .. } => "KillProcess",
                CommandAction::ReniceProcess { .. } => "ReniceProcess",
                _ => "ViewSystemMetrics",
            };
            if !required.eq_ignore_ascii_case(action_capability) {
                return Err(format!(
                    "policy denied: EVRUS require_capability mismatch ({required})"
                ));
            }
        }
        for pattern in &policy.constraints.deny_on_hosts {
            if host_pattern_matches(&self.hostname, pattern) {
                return Err(format!(
                    "policy denied: host matched deny pattern {pattern}"
                ));
            }
        }
        if policy.constraints.require_confirmation
            && matches!(action, CommandAction::ReniceProcess { .. })
        {
            return Err(
                "policy denied: EVRUS requires explicit confirmation for renice".to_string(),
            );
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

fn snapshot_metric_value(snapshot: &SystemSnapshot, metric: &str) -> Option<f64> {
    match metric {
        "cpu.usage_percent" => Some(snapshot.cpu.usage_percent as f64),
        "memory.used_percent" => {
            if snapshot.memory.total == 0 {
                Some(0.0)
            } else {
                Some((snapshot.memory.used as f64 / snapshot.memory.total as f64) * 100.0)
            }
        }
        "process.count" => Some(snapshot.processes.len() as f64),
        "disk.total_bytes_per_sec" => Some(
            snapshot
                .disks
                .iter()
                .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec))
                .sum::<u64>() as f64,
        ),
        "network.total_bytes_per_sec" => Some(
            snapshot
                .network
                .iter()
                .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec))
                .sum::<u64>() as f64,
        ),
        _ => None,
    }
}

fn compare(op: &str, value: f64, threshold: f64) -> bool {
    match op {
        ">" => value > threshold,
        ">=" => value >= threshold,
        "<" => value < threshold,
        "<=" => value <= threshold,
        "==" => (value - threshold).abs() < f64::EPSILON,
        "!=" => (value - threshold).abs() >= f64::EPSILON,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        cpu::CpuMetrics, disk::DiskMetrics, memory::MemoryMetrics, network::NetworkMetrics,
        process::ProcessMetrics,
    };
    use crate::security::auth::{AuthMode, Role};

    fn snapshot(cpu: f32, mem_used: u64, mem_total: u64, proc_count: usize) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: 1,
            host_id: "test-host".to_string(),
            cpu: CpuMetrics {
                usage_percent: cpu,
                per_core: vec![cpu],
                load_avg: (0.0, 0.0, 0.0),
            },
            memory: MemoryMetrics {
                total: mem_total,
                used: mem_used,
                available: mem_total.saturating_sub(mem_used),
            },
            disks: vec![DiskMetrics {
                device: "sda".to_string(),
                read_bytes_per_sec: 10,
                write_bytes_per_sec: 10,
            }],
            network: vec![NetworkMetrics {
                interface: "eth0".to_string(),
                rx_bytes_per_sec: 10,
                tx_bytes_per_sec: 10,
            }],
            processes: (0..proc_count)
                .map(|i| ProcessMetrics {
                    pid: i as u32 + 1,
                    name: format!("p{i}"),
                    cpu_percent: 0.0,
                    memory_bytes: 0,
                    threads: 1,
                    cmdline: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn alert_policy_matches_threshold_rule() {
        let auth = AuthContext {
            mode: AuthMode::Local,
            role: Role::Admin,
        };
        let mut policy = ExecutionPolicy::new(auth, None);
        policy.alert_policy = Some(AlertPolicy {
            rules: vec![AlertRule {
                id: "cpu-hot".to_string(),
                metric: "cpu.usage_percent".to_string(),
                op: ">=".to_string(),
                threshold: 90.0,
                for_cycles: 1,
                severity: AlertSeverity::Critical,
                message: Some("CPU sustained high utilization".to_string()),
            }],
        });
        let alerts = policy.evaluate_snapshot_alerts(&snapshot(95.0, 200, 1000, 3));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "cpu-hot");
    }

    #[test]
    fn alert_policy_honors_for_cycles_streak() {
        let auth = AuthContext {
            mode: AuthMode::Local,
            role: Role::Admin,
        };
        let mut policy = ExecutionPolicy::new(auth, None);
        policy.alert_policy = Some(AlertPolicy {
            rules: vec![AlertRule {
                id: "mem-warn".to_string(),
                metric: "memory.used_percent".to_string(),
                op: ">".to_string(),
                threshold: 80.0,
                for_cycles: 2,
                severity: AlertSeverity::Warning,
                message: None,
            }],
        });
        let first = policy.evaluate_snapshot_alerts(&snapshot(10.0, 900, 1000, 3));
        let second = policy.evaluate_snapshot_alerts(&snapshot(10.0, 920, 1000, 3));
        assert!(first.is_empty());
        assert_eq!(second.len(), 1);
    }
}
