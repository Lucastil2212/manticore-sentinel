use crate::collectors::{
    cpu::CpuCollector, disk::DiskCollector, memory::MemoryCollector, network::NetworkCollector,
    process::ProcessCollector,
};
use crate::connectors::{Connector, ConnectorSummary};
use crate::core::config::ConnectorConfig;
use crate::core::snapshot::SystemSnapshot;
use crate::utils::time::now_unix_secs;

pub struct SentinelEngine {
    cpu: CpuCollector,
    memory: MemoryCollector,
    process: ProcessCollector,
    disk: DiskCollector,
    network: NetworkCollector,
    ecosystem_connectors: Vec<Box<dyn Connector>>,
    connector_poll_counter: u64,
}

impl SentinelEngine {
    pub fn new() -> Self {
        Self {
            cpu: CpuCollector::new(),
            memory: MemoryCollector::new(),
            process: ProcessCollector::new(),
            disk: DiskCollector::new(),
            network: NetworkCollector::new(),
            ecosystem_connectors: Vec::new(),
            connector_poll_counter: 0,
        }
    }

    /// Initialize ecosystem connectors from runtime configuration.
    /// Called once after config is loaded. Connector failures here are
    /// logged but never prevent Sentinel from starting.
    pub fn init_connectors(&mut self, config: &ConnectorConfig) {
        if let Some(pw) = &config.peerweave {
            let connector = crate::connectors::peerweave::PeerWeaveConnector::new(pw.clone());
            self.ecosystem_connectors.push(Box::new(connector));
            tracing::info!("PeerWeave connector registered");
        }
        if let Some(ev) = &config.evrus {
            let connector = crate::connectors::evrus::EvrusConnector::new(ev.clone());
            self.ecosystem_connectors.push(Box::new(connector));
            tracing::info!("EVRUS connector registered");
        }
    }

    pub async fn collect(&mut self) -> anyhow::Result<SystemSnapshot> {
        let timestamp = now_unix_secs();
        let cpu = self.cpu.collect()?;
        let memory = self.memory.collect()?;
        let processes = self.process.collect()?;
        let disks = self.disk.collect()?;
        let network = self.network.collect()?;

        Ok(SystemSnapshot {
            timestamp,
            cpu,
            memory,
            disks,
            network,
            processes,
        })
    }

    /// Poll all ecosystem connectors and return a health summary.
    /// Called on a slower cadence than system collection (every ~10 core
    /// cycles by default) so connector HTTP calls don't block the UI loop.
    pub fn poll_connectors(&mut self) -> ConnectorSummary {
        self.connector_poll_counter += 1;

        let mut summary = ConnectorSummary::default();
        for conn in &mut self.ecosystem_connectors {
            let health = conn.health_check();
            if let Some(snapshot) = conn.collect() {
                summary.snapshots.push(snapshot);
            }
            if let Some(detail) = &health.detail {
                tracing::warn!(
                    connector = conn.name(),
                    category = "connector",
                    detail = detail.as_str(),
                    "connector health check issue"
                );
            }
            summary.entries.push(health);
        }
        summary
    }

    pub fn connector_summary_passive(&self) -> ConnectorSummary {
        let mut summary = ConnectorSummary::default();
        for conn in &self.ecosystem_connectors {
            summary.entries.push(crate::connectors::ConnectorHealth {
                name: conn.name().to_string(),
                status: conn.status(),
                latency_ms: None,
                detail: None,
            });
        }
        summary
    }

    pub fn has_connectors(&self) -> bool {
        !self.ecosystem_connectors.is_empty()
    }

    pub fn connector_poll_counter(&self) -> u64 {
        self.connector_poll_counter
    }
}
