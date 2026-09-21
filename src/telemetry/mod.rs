use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::connectors::ConnectorSummary;
use crate::core::config::RuntimeConfig;
use crate::core::engine::SentinelEngine;
use crate::core::snapshot::SystemSnapshot;
use crate::store::{MetricRow, Store, WriteOp};
use crate::utils::time::now_unix_secs;

#[derive(Default)]
struct SharedState {
    seq: u64,
    latest: Option<Arc<SystemSnapshot>>,
    connectors: ConnectorSummary,
    collect_last_ms: f64,
    collect_avg_ms: f64,
    collect_cycles: u64,
    connector_polls: u64,
    errors_total: u64,
    last_error: Option<String>,
    last_error_ts: Option<u64>,
}

#[derive(Clone)]
pub struct TelemetryHandle {
    state: Arc<Mutex<SharedState>>,
    store: Option<Store>,
    has_connectors: bool,
    last_seen_seq: Arc<Mutex<u64>>,
}

pub struct TelemetryTick {
    pub snapshot: Arc<SystemSnapshot>,
    pub collect_last_ms: f64,
    pub collect_avg_ms: f64,
    pub collect_cycles: u64,
    pub connector_polls: u64,
    pub connectors: ConnectorSummary,
    pub last_error: Option<String>,
    pub errors_total: u64,
    pub last_error_ts: Option<u64>,
}

impl TelemetryHandle {
    pub fn spawn(config: &RuntimeConfig) -> anyhow::Result<Self> {
        let store = if config.store.enabled {
            Some(Store::open(&config.store.path)?)
        } else {
            None
        };
        let state = Arc::new(Mutex::new(SharedState::default()));
        let worker_state = Arc::clone(&state);
        let worker_store = store.clone();
        let refresh = Duration::from_millis(config.refresh_ms);
        let connector_interval = config
            .connectors
            .peerweave
            .as_ref()
            .map(|pw| Duration::from_millis(pw.poll_ms))
            .or_else(|| {
                config
                    .connectors
                    .evrus
                    .as_ref()
                    .map(|_| Duration::from_secs(5))
            })
            .unwrap_or(Duration::from_secs(5));
        let mut engine = SentinelEngine::new(
            config.process_max_entries,
            config.process_cmdline_entries,
        );
        engine.init_connectors(&config.connectors);
        let has_connectors = engine.has_connectors();
        tracing::info!(
            hosts = engine.host_count(),
            has_connectors,
            "telemetry worker starting"
        );
        let search_index_processes = config.search.enabled;

        thread::Builder::new()
            .name("sentinel-telemetry".into())
            .spawn(move || {
                run_worker(
                    engine,
                    worker_state,
                    worker_store,
                    refresh,
                    connector_interval,
                    search_index_processes,
                );
            })
            .map_err(|e| anyhow::anyhow!("telemetry thread: {e}"))?;

        Ok(Self {
            state,
            store,
            has_connectors,
            last_seen_seq: Arc::new(Mutex::new(0)),
        })
    }

    pub fn store(&self) -> Option<&Store> {
        self.store.as_ref()
    }

    pub fn has_connectors(&self) -> bool {
        self.has_connectors
    }

    pub fn connectors(&self) -> ConnectorSummary {
        self.state
            .lock()
            .map(|g| g.connectors.clone())
            .unwrap_or_default()
    }

    pub fn latest(&self) -> Option<Arc<SystemSnapshot>> {
        self.state.lock().ok().and_then(|g| g.latest.clone())
    }

    pub fn poll_tick(&self) -> Option<TelemetryTick> {
        let guard = self.state.lock().ok()?;
        let mut seen = self.last_seen_seq.lock().ok()?;
        if guard.seq == *seen {
            return None;
        }
        *seen = guard.seq;
        let snapshot = guard.latest.clone()?;
        Some(TelemetryTick {
            snapshot,
            collect_last_ms: guard.collect_last_ms,
            collect_avg_ms: guard.collect_avg_ms,
            collect_cycles: guard.collect_cycles,
            connector_polls: guard.connector_polls,
            connectors: guard.connectors.clone(),
            last_error: guard.last_error.clone(),
            errors_total: guard.errors_total,
            last_error_ts: guard.last_error_ts,
        })
    }

    pub fn stats_snapshot(&self) -> (f64, f64, u64, u64, u64) {
        self.state
            .lock()
            .map(|g| {
                (
                    g.collect_last_ms,
                    g.collect_avg_ms,
                    g.collect_cycles,
                    g.connector_polls,
                    g.errors_total,
                )
            })
            .unwrap_or((0.0, 0.0, 0, 0, 0))
    }
}

fn run_worker(
    mut engine: SentinelEngine,
    state: Arc<Mutex<SharedState>>,
    store: Option<Store>,
    refresh: Duration,
    connector_interval: Duration,
    index_processes: bool,
) {
    let mut last_connector = Instant::now() - connector_interval;
    loop {
        let started = Instant::now();
        match engine.collect_blocking() {
            Ok(snapshot) => {
                let collect_ms = started.elapsed().as_secs_f64() * 1000.0;
                engine.ingest_system_snapshot(&snapshot);
                if let Some(store) = &store {
                    persist_snapshot(store, &snapshot, collect_ms, None, index_processes);
                }
                if let Ok(mut guard) = state.lock() {
                    guard.seq = guard.seq.saturating_add(1);
                    guard.collect_last_ms = collect_ms;
                    guard.collect_cycles = guard.collect_cycles.saturating_add(1);
                    if guard.collect_cycles == 1 {
                        guard.collect_avg_ms = collect_ms;
                    } else {
                        guard.collect_avg_ms = (guard.collect_avg_ms * 0.9) + (collect_ms * 0.1);
                    }
                    guard.latest = Some(Arc::new(snapshot));
                    guard.last_error = None;
                }
            }
            Err(err) => {
                tracing::error!(category = "collector", message = %err, "snapshot collection failed");
                if let Some(store) = &store {
                    store.write_log("error", "collector", &err.to_string());
                }
                if let Ok(mut guard) = state.lock() {
                    guard.errors_total = guard.errors_total.saturating_add(1);
                    guard.last_error = Some(err.to_string());
                    guard.last_error_ts = Some(now_unix_secs());
                }
            }
        }

        if engine.has_connectors() && last_connector.elapsed() >= connector_interval {
            let conn_started = Instant::now();
            let summary = engine.poll_connectors();
            let connector_ms = conn_started.elapsed().as_secs_f64() * 1000.0;
            if let Some(store) = &store {
                persist_connectors(store, &summary, connector_ms);
            }
            if let Ok(mut guard) = state.lock() {
                guard.connectors = summary;
                guard.connector_polls = guard.connector_polls.saturating_add(1);
            }
            last_connector = Instant::now();
        }

        let elapsed = started.elapsed();
        if elapsed < refresh {
            thread::sleep(refresh - elapsed);
        }
    }
}

fn persist_snapshot(
    store: &Store,
    snapshot: &SystemSnapshot,
    collect_ms: f64,
    connector_ms: Option<f64>,
    index_processes: bool,
) {
    let disk_bps: u64 = snapshot
        .disks
        .iter()
        .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec))
        .sum();
    let net_bps: u64 = snapshot
        .network
        .iter()
        .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec))
        .sum();
    store.write_metric(MetricRow {
        ts: snapshot.timestamp,
        host: snapshot.host_id.clone(),
        cpu: snapshot.cpu.usage_percent,
        mem_used: snapshot.memory.used,
        mem_total: snapshot.memory.total,
        disk_bps,
        net_bps,
        process_count: snapshot.processes.len(),
    });
    store.enqueue(WriteOp::CollectSample {
        ts: snapshot.timestamp,
        collect_ms,
        connector_ms,
    });

    let load = snapshot.cpu.load_avg;
    let body = format!(
        "host {} cpu {:.1}% mem {}/{} load {:.2} {:.2} {:.2} processes {} disk_bps {} net_bps {}",
        snapshot.host_id,
        snapshot.cpu.usage_percent,
        snapshot.memory.used,
        snapshot.memory.total,
        load.0,
        load.1,
        load.2,
        snapshot.processes.len(),
        disk_bps,
        net_bps
    );
    store.write_document(
        "host",
        format!("host:{}", snapshot.host_id),
        body,
        format!("host:{}", snapshot.host_id),
        Some(
            serde_json::json!({
                "cpu": snapshot.cpu.usage_percent,
                "process_count": snapshot.processes.len(),
            })
            .to_string(),
        ),
    );

    if index_processes && snapshot.timestamp % 15 == 0 {
        for proc in snapshot.processes.iter().take(8) {
            let body = format!(
                "pid {} {} cpu {:.1}% rss {} threads {} {}",
                proc.pid,
                proc.name,
                proc.cpu_percent,
                proc.memory_bytes,
                proc.threads,
                proc.cmdline
            );
            store.write_document(
                "process",
                proc.name.clone(),
                body,
                format!("pid:{}", proc.pid),
                None,
            );
        }
        for disk in snapshot.disks.iter().take(4) {
            store.write_document(
                "disk",
                disk.device.clone(),
                format!(
                    "disk {} read {} write {}",
                    disk.device, disk.read_bytes_per_sec, disk.write_bytes_per_sec
                ),
                format!("disk:{}", disk.device),
                None,
            );
        }
        for net in snapshot.network.iter().take(4) {
            store.write_document(
                "network",
                net.interface.clone(),
                format!(
                    "iface {} rx {} tx {}",
                    net.interface, net.rx_bytes_per_sec, net.tx_bytes_per_sec
                ),
                format!("net:{}", net.interface),
                None,
            );
        }
    }
}

fn persist_connectors(store: &Store, summary: &ConnectorSummary, _connector_ms: f64) {
    for health in &summary.entries {
        let body = format!(
            "connector {} status {} latency {:?} {}",
            health.name,
            health.status.label(),
            health.latency_ms,
            health.detail.clone().unwrap_or_default()
        );
        store.write_document(
            "connector",
            health.name.clone(),
            body,
            format!("connector:{}", health.name),
            None,
        );
        store.write_log(
            health.status.label(),
            "connector",
            &format!("{} {}", health.name, health.status),
        );
    }
    for snapshot in &summary.snapshots {
        store.write_document(
            "connector-snapshot",
            snapshot.name.clone(),
            snapshot.data.to_string(),
            format!("connector:{}", snapshot.name),
            Some(snapshot.data.to_string()),
        );
    }
}
