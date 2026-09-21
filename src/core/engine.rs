use std::thread;

use crate::collectors::{
    cpu::CpuCollector, disk::DiskCollector, memory::MemoryCollector, network::NetworkCollector,
    process::ProcessCollector,
};
use crate::connectors::{Connector, ConnectorSummary};
use crate::core::config::ConnectorConfig;
use crate::core::snapshot::SystemSnapshot;
use crate::utils::time::now_unix_secs;

pub struct SentinelEngine {
    host_collectors: Vec<Box<dyn HostCollector>>,
    primary_host_idx: usize,
    ecosystem_connectors: Vec<Box<dyn Connector>>,
    connector_poll_counter: u64,
}

impl SentinelEngine {
    pub fn new(process_max_entries: usize, process_cmdline_entries: usize) -> Self {
        Self {
            host_collectors: vec![Box::new(LocalHostCollector::new(
                process_max_entries,
                process_cmdline_entries,
            ))],
            primary_host_idx: 0,
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

    pub fn collect_blocking(&mut self) -> anyhow::Result<SystemSnapshot> {
        let snapshots = self.collect_all()?;
        snapshots
            .get(self.primary_host_idx)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no primary host snapshot available"))
    }

    pub fn collect_all(&mut self) -> anyhow::Result<Vec<SystemSnapshot>> {
        let mut out = Vec::new();
        for collector in &mut self.host_collectors {
            out.push(collector.collect()?);
        }
        Ok(out)
    }

    pub fn host_count(&self) -> usize {
        self.host_collectors.len()
    }
}

trait HostCollector: Send + Sync {
    fn collect(&mut self) -> anyhow::Result<SystemSnapshot>;
}

struct LocalHostCollector {
    host_id: String,
    cpu: CpuCollector,
    memory: MemoryCollector,
    process: ProcessCollector,
    disk: DiskCollector,
    network: NetworkCollector,
}

impl LocalHostCollector {
    fn new(process_max_entries: usize, process_cmdline_entries: usize) -> Self {
        let host_id = std::env::var("HOSTNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "localhost".to_string());
        Self {
            host_id,
            cpu: CpuCollector::new(),
            memory: MemoryCollector::new(),
            process: ProcessCollector::new(process_max_entries, process_cmdline_entries),
            disk: DiskCollector::new(),
            network: NetworkCollector::new(),
        }
    }
}

impl HostCollector for LocalHostCollector {
    fn collect(&mut self) -> anyhow::Result<SystemSnapshot> {
        let timestamp = now_unix_secs();
        let cpu = &mut self.cpu;
        let memory = &mut self.memory;
        let process = &mut self.process;
        let disk = &mut self.disk;
        let network = &mut self.network;
        let (cpu, memory, processes, disks, network) = thread::scope(|s| {
            let cpu_h = s.spawn(|| cpu.collect());
            let memory_h = s.spawn(|| memory.collect());
            let process_h = s.spawn(|| process.collect());
            let disk_h = s.spawn(|| disk.collect());
            let network_h = s.spawn(|| network.collect());
            (
                cpu_h.join(),
                memory_h.join(),
                process_h.join(),
                disk_h.join(),
                network_h.join(),
            )
        });
        let cpu = cpu.map_err(|_| anyhow::anyhow!("cpu collector panicked"))??;
        let memory = memory.map_err(|_| anyhow::anyhow!("memory collector panicked"))??;
        let processes = processes.map_err(|_| anyhow::anyhow!("process collector panicked"))??;
        let disks = disks.map_err(|_| anyhow::anyhow!("disk collector panicked"))??;
        let network = network.map_err(|_| anyhow::anyhow!("network collector panicked"))??;

        Ok(SystemSnapshot {
            timestamp,
            host_id: self.host_id.clone(),
            cpu,
            memory,
            disks,
            network,
            processes,
        })
    }
}

impl SentinelEngine {
    pub fn ingest_system_snapshot(&mut self, snapshot: &SystemSnapshot) {
        for conn in &mut self.ecosystem_connectors {
            conn.ingest_system_snapshot(snapshot);
        }
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
}
