use super::{Connector, ConnectorHealth, ConnectorSnapshot, ConnectorStatus};
use crate::core::config::EvrusConfig;
use crate::utils::time::now_unix_secs;

/// EVRUS ecosystem connector.
///
/// Validates operator identity via the EVRUS OIDC bridge and optionally
/// queries Evrmore chain state for audit anchoring status.
pub struct EvrusConnector {
    config: EvrusConfig,
    status: ConnectorStatus,
    oidc_healthy: bool,
}

impl EvrusConnector {
    pub fn new(config: EvrusConfig) -> Self {
        Self {
            config,
            status: ConnectorStatus::Connecting,
            oidc_healthy: false,
        }
    }

    fn probe_oidc(&self) -> Result<serde_json::Value, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client init: {e}"))?;

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.oidc_url.trim_end_matches('/')
        );

        let resp = client
            .get(&discovery_url)
            .send()
            .map_err(|e| format!("OIDC discovery request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("OIDC discovery HTTP {}", resp.status()));
        }

        resp.json::<serde_json::Value>()
            .map_err(|e| format!("OIDC discovery json parse: {e}"))
    }
}

impl Connector for EvrusConnector {
    fn name(&self) -> &str {
        "EVRUS"
    }

    fn status(&self) -> ConnectorStatus {
        self.status.clone()
    }

    fn health_check(&mut self) -> ConnectorHealth {
        let start = std::time::Instant::now();
        match self.probe_oidc() {
            Ok(_discovery) => {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                self.oidc_healthy = true;
                self.status = ConnectorStatus::Healthy;
                ConnectorHealth {
                    name: "EVRUS".into(),
                    status: ConnectorStatus::Healthy,
                    latency_ms: Some(latency),
                    detail: None,
                }
            }
            Err(e) => {
                self.oidc_healthy = false;
                self.status = ConnectorStatus::Failed(e.clone());
                ConnectorHealth {
                    name: "EVRUS".into(),
                    status: self.status.clone(),
                    latency_ms: None,
                    detail: Some(e),
                }
            }
        }
    }

    fn collect(&mut self) -> Option<ConnectorSnapshot> {
        if !self.oidc_healthy {
            return None;
        }
        Some(ConnectorSnapshot {
            name: "EVRUS".into(),
            timestamp: now_unix_secs(),
            data: serde_json::json!({
                "oidc_healthy": true,
                "oidc_url": self.config.oidc_url,
                "anchor_enabled": self.config.anchor_enabled,
                "anchor_interval_secs": self.config.anchor_interval_secs,
                "rpc_configured": self.config.rpc_url.is_some() && self.config.rpc_user.is_some() && self.config.rpc_pass.is_some(),
            }),
        })
    }
}
