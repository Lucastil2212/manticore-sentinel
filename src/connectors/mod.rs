pub mod evrus;
pub mod peerweave;

use crate::core::snapshot::SystemSnapshot;
use std::fmt;

/// Runtime status of an ecosystem connector.
#[derive(Debug, Clone)]
pub enum ConnectorStatus {
    /// Connection attempt in progress.
    Connecting,
    /// Connected and receiving data.
    Healthy,
    /// Connected but experiencing issues.
    Degraded(String),
    /// Connection failed or endpoint unreachable.
    Failed(String),
}

impl ConnectorStatus {
    pub fn label(&self) -> &str {
        match self {
            Self::Connecting => "CONNECTING",
            Self::Healthy => "HEALTHY",
            Self::Degraded(_) => "DEGRADED",
            Self::Failed(_) => "FAILED",
        }
    }
}

impl fmt::Display for ConnectorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => write!(f, "CONNECTING"),
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Degraded(d) => write!(f, "DEGRADED: {d}"),
            Self::Failed(d) => write!(f, "FAILED: {d}"),
        }
    }
}

/// Health report returned by a connector's periodic check.
#[derive(Debug, Clone)]
pub struct ConnectorHealth {
    pub name: String,
    pub status: ConnectorStatus,
    pub latency_ms: Option<f64>,
    pub detail: Option<String>,
}

/// Snapshot of data collected from an ecosystem connector.
#[derive(Debug, Clone)]
pub struct ConnectorSnapshot {
    pub name: String,
    pub data: serde_json::Value,
}

/// Trait implemented by all ecosystem connectors (PeerWeave, EVRUS, etc.).
///
/// Connectors are polled by the engine on each refresh cycle.  Failures must
/// never propagate — a connector returns `ConnectorStatus::Failed` instead of
/// panicking or returning an `Err` that would halt collection.
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;
    fn status(&self) -> ConnectorStatus;
    fn health_check(&mut self) -> ConnectorHealth;
    fn collect(&mut self) -> Option<ConnectorSnapshot>;
    fn ingest_system_snapshot(&mut self, _snapshot: &SystemSnapshot) {}
}

/// Aggregated view of all connector states for the dashboard.
#[derive(Debug, Clone, Default)]
pub struct ConnectorSummary {
    pub entries: Vec<ConnectorHealth>,
    pub snapshots: Vec<ConnectorSnapshot>,
}

impl ConnectorSummary {
    pub fn health_for(&self, name: &str) -> Option<&ConnectorHealth> {
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    pub fn snapshot_for(&self, name: &str) -> Option<&ConnectorSnapshot> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.name.eq_ignore_ascii_case(name))
    }
}
