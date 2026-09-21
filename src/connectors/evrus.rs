use super::{Connector, ConnectorHealth, ConnectorSnapshot, ConnectorStatus};
use crate::core::config::EvrusConfig;

/// EVRUS ecosystem connector.
///
/// Validates operator identity via the EVRUS OIDC bridge and optionally
/// queries Evrmore chain state for audit anchoring status.
pub struct EvrusConnector {
    config: EvrusConfig,
    status: ConnectorStatus,
    oidc_healthy: bool,
    client: Option<reqwest::blocking::Client>,
}

impl EvrusConnector {
    pub fn new(config: EvrusConfig) -> Self {
        Self {
            config,
            status: ConnectorStatus::Connecting,
            oidc_healthy: false,
            client: None,
        }
    }

    fn client(&mut self) -> Result<&reqwest::blocking::Client, String> {
        if self.client.is_none() {
            let built = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .pool_max_idle_per_host(2)
                .build()
                .map_err(|e| format!("http client init: {e}"))?;
            self.client = Some(built);
        }
        self.client
            .as_ref()
            .ok_or_else(|| "http client missing".to_string())
    }

    fn probe_oidc(&mut self) -> Result<serde_json::Value, String> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.oidc_url.trim_end_matches('/')
        );
        let client = self.client()?.clone();

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
