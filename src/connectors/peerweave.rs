use super::{Connector, ConnectorHealth, ConnectorSnapshot, ConnectorStatus};
use crate::core::config::PeerWeaveConfig;
use crate::utils::time::now_unix_secs;

/// PeerWeave ecosystem connector.
///
/// Queries PeerWeave's GraphQL HTTP API for node health, peer count, space
/// state, and graph statistics.  Authentication uses the same CapToken Bearer
/// header that PeerWeave's `capauth.rs` already enforces.
pub struct PeerWeaveConnector {
    config: PeerWeaveConfig,
    status: ConnectorStatus,
    last_snapshot: Option<ConnectorSnapshot>,
}

impl PeerWeaveConnector {
    pub fn new(config: PeerWeaveConfig) -> Self {
        Self {
            config,
            status: ConnectorStatus::Connecting,
            last_snapshot: None,
        }
    }

    fn query_health(&self) -> Result<serde_json::Value, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client init: {e}"))?;

        let query = r#"{"query":"{ node { peerId status uptime peers { count } } spaces { id name syncState } graph { nodeCount edgeCount } }"}"#;

        let mut req = client
            .post(&self.config.graphql_url)
            .header("Content-Type", "application/json")
            .body(query);

        if let Some(token) = &self.config.cap_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req.send().map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        resp.json::<serde_json::Value>()
            .map_err(|e| format!("json parse: {e}"))
    }
}

impl Connector for PeerWeaveConnector {
    fn name(&self) -> &str {
        "PeerWeave"
    }

    fn status(&self) -> ConnectorStatus {
        self.status.clone()
    }

    fn health_check(&mut self) -> ConnectorHealth {
        let start = std::time::Instant::now();
        match self.query_health() {
            Ok(data) => {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                let has_errors = data.get("errors").is_some();
                if has_errors {
                    self.status = ConnectorStatus::Degraded("GraphQL returned errors".into());
                } else {
                    self.status = ConnectorStatus::Healthy;
                }
                self.last_snapshot = Some(ConnectorSnapshot {
                    name: "PeerWeave".into(),
                    timestamp: now_unix_secs(),
                    data,
                });
                ConnectorHealth {
                    name: "PeerWeave".into(),
                    status: self.status.clone(),
                    latency_ms: Some(latency),
                    detail: None,
                }
            }
            Err(e) => {
                self.status = ConnectorStatus::Failed(e.clone());
                self.last_snapshot = None;
                ConnectorHealth {
                    name: "PeerWeave".into(),
                    status: self.status.clone(),
                    latency_ms: None,
                    detail: Some(e),
                }
            }
        }
    }

    fn collect(&mut self) -> Option<ConnectorSnapshot> {
        self.last_snapshot.clone()
    }
}
