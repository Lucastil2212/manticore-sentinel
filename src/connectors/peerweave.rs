use super::{Connector, ConnectorHealth, ConnectorSnapshot, ConnectorStatus};
use crate::core::config::PeerWeaveConfig;
use crate::core::snapshot::SystemSnapshot;
use serde_json::{json, Value};
use std::time::Duration;

/// PeerWeave GraphQL connector.
///
/// The current PeerWeave desktop GraphQL API is a read/query boundary. It
/// exposes graph stats/search/nodes/edges and requires a shared token or
/// CapToken. Telemetry publication is deliberately not attempted until
/// PeerWeave exposes a supported ingestion mutation/API.
pub struct PeerWeaveConnector {
    config: PeerWeaveConfig,
    status: ConnectorStatus,
    last_snapshot: Option<ConnectorSnapshot>,
}

impl PeerWeaveConnector {
    pub fn new(config: PeerWeaveConfig) -> Self {
        Self { config, status: ConnectorStatus::Connecting, last_snapshot: None }
    }

    fn client(&self) -> Result<reqwest::blocking::Client, String> {
        reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_millis(750))
            .timeout(Duration::from_secs(2))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("http client init: {e}"))
    }

    fn query_graph(&self) -> Result<Value, String> {
        let client = self.client()?;
        let body = json!({
            "query": "{ stats { nodeCount edgeCount } allNodes(limit: 8) { id kind label } }"
        });
        let mut req = client
            .post(&self.config.graphql_url)
            .header("Content-Type", "application/json")
            .json(&body);
        if let Some(token) = &self.config.cap_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().map_err(|e| format!("request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let value = resp.json::<Value>().map_err(|e| format!("json parse: {e}"))?;
        if let Some(errors) = value.get("errors") {
            return Err(format!("GraphQL errors: {errors}"));
        }
        Ok(value)
    }
}

impl Connector for PeerWeaveConnector {
    fn name(&self) -> &str { "PeerWeave" }

    fn status(&self) -> ConnectorStatus { self.status.clone() }

    fn health_check(&mut self) -> ConnectorHealth {
        let start = std::time::Instant::now();
        match self.query_graph() {
            Ok(data) => {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                self.status = ConnectorStatus::Healthy;
                self.last_snapshot = Some(ConnectorSnapshot { name: "PeerWeave".into(), data });
                ConnectorHealth {
                    name: "PeerWeave".into(),
                    status: self.status.clone(),
                    latency_ms: Some(latency),
                    detail: if self.config.publish_enabled {
                        Some("publish requested but current PeerWeave GraphQL is read-only; telemetry remains local/search-indexed".into())
                    } else { None },
                }
            }
            Err(e) => {
                self.status = ConnectorStatus::Failed(e.clone());
                self.last_snapshot = None;
                ConnectorHealth { name: "PeerWeave".into(), status: self.status.clone(), latency_ms: None, detail: Some(e) }
            }
        }
    }

    fn collect(&mut self) -> Option<ConnectorSnapshot> { self.last_snapshot.clone() }

    fn ingest_system_snapshot(&mut self, _snapshot: &SystemSnapshot) {
        // Intentionally no-op. The current GraphQL schema has EmptyMutation.
    }
}
