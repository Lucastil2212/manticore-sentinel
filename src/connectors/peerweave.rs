use super::{Connector, ConnectorHealth, ConnectorSnapshot, ConnectorStatus};
use crate::core::config::PeerWeaveConfig;
use crate::core::snapshot::SystemSnapshot;
use crate::utils::time::now_unix_secs;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// PeerWeave ecosystem connector.
///
/// Queries PeerWeave's GraphQL HTTP API for node health, peer count, space
/// state, and graph statistics.  Authentication uses the same CapToken Bearer
/// header that PeerWeave's `capauth.rs` already enforces.
pub struct PeerWeaveConnector {
    config: PeerWeaveConfig,
    status: ConnectorStatus,
    last_snapshot: Option<ConnectorSnapshot>,
    pending_publish: Option<Value>,
    last_publish_at: Option<Instant>,
    host_id: String,
    trust_mode: String,
}

impl PeerWeaveConnector {
    pub fn new(config: PeerWeaveConfig) -> Self {
        Self {
            config,
            status: ConnectorStatus::Connecting,
            last_snapshot: None,
            pending_publish: None,
            last_publish_at: None,
            host_id: std::env::var("HOSTNAME")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "localhost".to_string()),
            trust_mode: std::env::var("MANTICORE_AUTH_MODE")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "local".to_string()),
        }
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client, String> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client init: {e}"))
    }

    fn with_auth(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(token) = &self.config.cap_token {
            req.header("Authorization", format!("Bearer {token}"))
        } else {
            req
        }
    }

    fn query_health(&self) -> Result<serde_json::Value, String> {
        let client = self.build_client()?;

        let query = json!({
            "query": "{ node { peerId status uptime peers { count } } spaces { id name syncState } graph { nodeCount edgeCount } }"
        });

        let req = client
            .post(&self.config.graphql_url)
            .header("Content-Type", "application/json")
            .json(&query);
        let req = self.with_auth(req);
        let resp = req.send().map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        resp.json::<serde_json::Value>()
            .map_err(|e| format!("json parse: {e}"))
    }

    fn should_publish_now(&self) -> bool {
        if !self.config.publish_enabled || self.pending_publish.is_none() {
            return false;
        }
        match self.last_publish_at {
            None => true,
            Some(ts) => ts.elapsed() >= Duration::from_millis(self.config.publish_interval_ms),
        }
    }

    fn publish_snapshot(&mut self) -> Result<(), String> {
        let Some(space_id) = self.config.publish_space_id.as_deref() else {
            return Err(
                "publish enabled but MANTICORE_PEERWEAVE_PUBLISH_SPACE_ID is not set".to_string(),
            );
        };
        let Some(payload) = self.pending_publish.clone() else {
            return Ok(());
        };

        let client = self.build_client()?;
        let body = json!({
            "query": "mutation SentinelIngestSnapshot($spaceId: String!, $host: String!, $snapshot: JSON!) { sentinelIngestSnapshot(spaceId: $spaceId, host: $host, snapshot: $snapshot) { accepted } }",
            "variables": {
                "spaceId": space_id,
                "host": self.host_id,
                "snapshot": payload,
            }
        });
        let req = client
            .post(&self.config.graphql_url)
            .header("Content-Type", "application/json")
            .json(&body);
        let req = self.with_auth(req);
        let resp = req
            .send()
            .map_err(|e| format!("publish request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("publish HTTP {}", resp.status()));
        }
        let value = resp
            .json::<Value>()
            .map_err(|e| format!("publish json parse: {e}"))?;
        if let Some(errors) = value.get("errors") {
            return Err(format!("publish graphql errors: {errors}"));
        }
        self.pending_publish = None;
        self.last_publish_at = Some(Instant::now());
        Ok(())
    }

    fn build_publish_payload(&self, snapshot: &SystemSnapshot) -> Value {
        let disk_read_bps: u64 = snapshot.disks.iter().map(|d| d.read_bytes_per_sec).sum();
        let disk_write_bps: u64 = snapshot.disks.iter().map(|d| d.write_bytes_per_sec).sum();
        let network_rx_bps: u64 = snapshot.network.iter().map(|n| n.rx_bytes_per_sec).sum();
        let network_tx_bps: u64 = snapshot.network.iter().map(|n| n.tx_bytes_per_sec).sum();
        let host_id = if snapshot.host_id.trim().is_empty() {
            self.host_id.clone()
        } else {
            snapshot.host_id.clone()
        };
        let host_key = format!("host:{host_id}");

        json!({
            "timestamp": snapshot.timestamp,
            "host": host_id,
            "trust_mode": self.trust_mode,
            "metrics": {
                "cpu_usage_percent": snapshot.cpu.usage_percent,
                "memory_used_bytes": snapshot.memory.used,
                "memory_total_bytes": snapshot.memory.total,
                "memory_available_bytes": snapshot.memory.available,
                "disk_read_bytes_per_sec": disk_read_bps,
                "disk_write_bytes_per_sec": disk_write_bps,
                "network_rx_bytes_per_sec": network_rx_bps,
                "network_tx_bytes_per_sec": network_tx_bps,
                "process_count": snapshot.processes.len(),
            },
            "triples": [
                [host_key.clone(), String::from("type"), String::from("sentinel:Host")],
                [host_key.clone(), String::from("sentinel:cpuUsage"), snapshot.cpu.usage_percent.to_string()],
                [host_key.clone(), String::from("sentinel:memoryUsedBytes"), snapshot.memory.used.to_string()],
                [host_key.clone(), String::from("sentinel:diskReadBytesPerSec"), disk_read_bps.to_string()],
                [host_key.clone(), String::from("sentinel:networkTxBytesPerSec"), network_tx_bps.to_string()],
                [host_key.clone(), String::from("sentinel:processCount"), snapshot.processes.len().to_string()],
                [host_key.clone(), String::from("sentinel:snapshotTimestamp"), snapshot.timestamp.to_string()],
                [host_key, String::from("sentinel:trustMode"), self.trust_mode.clone()],
            ],
        })
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
                let mut detail: Option<String> = None;
                if self.should_publish_now() {
                    if let Err(e) = self.publish_snapshot() {
                        detail = Some(e);
                    }
                }
                if has_errors {
                    self.status = ConnectorStatus::Degraded("GraphQL returned errors".into());
                } else if let Some(d) = &detail {
                    self.status = ConnectorStatus::Degraded(d.clone());
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
                    detail,
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

    fn ingest_system_snapshot(&mut self, snapshot: &SystemSnapshot) {
        if self.config.publish_enabled {
            self.pending_publish = Some(self.build_publish_payload(snapshot));
        }
    }
}
