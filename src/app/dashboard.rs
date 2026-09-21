use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use base64::Engine;
use eframe::egui;
use egui::{FontFamily, FontId, RichText, Stroke};
use egui_extras::install_image_loaders;
use tokio::runtime::Runtime;

use crate::connectors::ConnectorSummary;
use crate::core::config::{AuditRetentionConfig, ConfigWarning};
use crate::core::{
    command::{parse_command, CommandAction},
    config::load_runtime_config,
    engine::SentinelEngine,
    history::{
        append_snapshot, count_since, default_snapshot_history_path, read_metric_rows,
        reset as reset_snapshot_history, SnapshotHistoryRetention,
    },
    policy::{AlertMatch, AlertSeverity, ExecutionPolicy},
    snapshot::SystemSnapshot,
};
use crate::models::process::ProcessMetrics;
use crate::security::audit::{
    anchor_audit_if_due, append_event_with_retention, audit_archive_stats, audit_entry_count,
    current_merkle_root, default_audit_path, load_anchor_state, now_ts, read_from_offset,
    read_recent, AnchorConfig, AnchorState, AuditEvent,
};
use crate::security::auth::{AuthContext, AuthGate, AuthMode, TokenLifecycle};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperRuntime};
use crate::utils::time::now_unix_secs;
use tracing::error;

use super::event_stream::EventStreamOutput;
use super::icons;

const ID_COMMAND_INPUT: &str = "command_palette_input";

const SECTION_OVERVIEW: &str = "overview";
const SECTION_DISK_NET: &str = "disk_net";
const SECTION_CONTROL: &str = "control_activity";
const SECTION_PROCESSES: &str = "processes";
const SECTION_AUDIT: &str = "audit";
const SECTION_CONNECTORS: &str = "connectors";
const METRIC_HISTORY_CAP: usize = 360;

#[derive(Clone)]
struct MetricSample {
    ts: u64,
    cpu_pct: f32,
    mem_pct: f32,
    disk_bps: f64,
    net_bps: f64,
    process_count: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeWindow {
    Last5m,
    Last1h,
    Last24h,
}

impl TimeWindow {
    fn seconds(self) -> u64 {
        match self {
            Self::Last5m => 5 * 60,
            Self::Last1h => 60 * 60,
            Self::Last24h => 24 * 60 * 60,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Last5m => "5m",
            Self::Last1h => "1h",
            Self::Last24h => "24h",
        }
    }
}

fn filtered_command_completions(typed: &str) -> Vec<&'static str> {
    let low = typed.trim_start().to_ascii_lowercase();
    if low.is_empty() {
        return crate::core::command::COMMAND_COMPLETIONS.to_vec();
    }
    crate::core::command::COMMAND_COMPLETIONS
        .iter()
        .copied()
        .filter(|c| c.to_ascii_lowercase().starts_with(&low))
        .collect()
}

fn run_scoped_snapshot_history_path(root: &std::path::Path) -> std::path::PathBuf {
    let run_ts = now_unix_secs();
    let base = default_snapshot_history_path(root);
    let parent = base.parent().map(std::path::Path::to_path_buf).unwrap_or_else(|| {
        root.join(".beads").join("state")
    });
    parent.join(format!("snapshots-{run_ts}.jsonl"))
}

pub struct SentinelDashboard {
    engine: SentinelEngine,
    runtime: Runtime,
    latest: Option<SystemSnapshot>,
    last_poll: Instant,
    poll_interval: Duration,
    ui_repaint_interval: Duration,
    last_error: Option<String>,
    command_input: String,
    auth_token_input: String,
    command_feedback: Option<String>,
    helper: HelperRuntime,
    trust_state: &'static str,
    role_label: &'static str,
    auth_mode_label: &'static str,
    audit_feed: Vec<AuditEvent>,
    visuals_applied: bool,
    pending_action: Option<CommandAction>,
    confirm_input: String,
    last_audit_refresh: Instant,
    policy: ExecutionPolicy,
    auth_gate: AuthGate,
    auth_failures: u32,
    auth_locked_until: Option<Instant>,
    show_onboarding: bool,
    show_help_center: bool,
    runtime_diagnostics: String,
    /// Last command feedback string we pushed as an accessibility `ValueChanged` event.
    last_command_feedback_announced: Option<String>,
    /// Executed commands (oldest at front, newest at back), max 50.
    command_history: VecDeque<String>,
    /// When set, `command_input` shows `command_history[len - 1 - k]` (k = newer toward 0).
    history_browse: Option<usize>,
    /// Line being edited before ↑ opened history (restored on ↓ from newest).
    history_draft: String,
    connector_summary: ConnectorSummary,
    last_connector_poll: Instant,
    connector_poll_interval: Duration,
    collapsed_sections: HashSet<&'static str>,
    scroll_to_section: Option<&'static str>,
    token_lifecycle: Option<TokenLifecycle>,
    evrus_jwt: Option<String>,
    anchor_state: AnchorState,
    evrus_anchor_config: Option<AnchorConfig>,
    anchor_interval: Duration,
    last_anchor_poll: Instant,
    last_policy_hash: Option<String>,
    process_sort: ProcessSort,
    audit_filter: String,
    event_stream: Option<EventStreamOutput>,
    event_stream_audit_offset: usize,
    last_event_stream_audit_poll: Instant,
    snapshot_history_enabled: bool,
    snapshot_history_max_entries: usize,
    snapshot_history_max_age_secs: Option<u64>,
    snapshot_history_max_bytes: Option<u64>,
    snapshot_history_slim_records: bool,
    snapshot_history_reset_on_start: bool,
    snapshot_history_path: std::path::PathBuf,
    snapshot_history_recent_hour: usize,
    last_snapshot_history_probe: Instant,
    latest_alerts: Vec<AlertMatch>,
    process_filter: String,
    expanded_process_pid: Option<u32>,
    audit_page: usize,
    audit_page_size: usize,
    expanded_audit_idx: Option<usize>,
    audit_retention: AuditRetentionConfig,
    config_warnings: Vec<ConfigWarning>,
    config_warnings_dismissed: bool,
    show_connector_wizard: bool,
    wizard_step: usize,
    wizard_connector_type: usize,
    wizard_url: String,
    wizard_token: String,
    wizard_space_id: String,
    detailed_mode: bool,
    show_glossary: bool,
    self_collect_last_ms: f64,
    self_collect_avg_ms: f64,
    self_collect_cycles: u64,
    self_connector_polls: u64,
    self_errors_total: u64,
    self_last_error_ts: Option<u64>,
    time_window: TimeWindow,
    metric_history: VecDeque<MetricSample>,
    process_count_history: VecDeque<(u64, usize)>,
    process_churn_history: VecDeque<(u64, usize, usize)>,
    audit_rate_history: VecDeque<(u64, usize, usize)>,
    connector_latency_history: VecDeque<(u64, Option<f64>, Option<f64>)>,
    previous_process_ids: HashSet<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessSort {
    CpuDesc,
    RssDesc,
    PidAsc,
    ThreadsDesc,
}

impl SentinelDashboard {
    fn hydrate_metric_history_from_disk(&mut self) {
        let Ok(rows) = read_metric_rows(&self.snapshot_history_path, METRIC_HISTORY_CAP) else {
            return;
        };
        for (ts, cpu_pct, memory_used, memory_total, process_count) in rows {
            let mem_pct = if memory_total == 0 {
                0.0
            } else {
                (memory_used as f32 / memory_total as f32) * 100.0
            };
            push_history(
                &mut self.metric_history,
                MetricSample {
                    ts,
                    cpu_pct,
                    mem_pct,
                    // Slim durable rows intentionally keep the high-frequency storage footprint small.
                    // Disk/network charts are populated from the live collector after startup.
                    disk_bps: 0.0,
                    net_bps: 0.0,
                    process_count,
                },
                METRIC_HISTORY_CAP,
            );
            push_history(
                &mut self.process_count_history,
                (ts, process_count),
                METRIC_HISTORY_CAP,
            );
        }
    }

    fn render_time_window_selector(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Trend window");
            for window in [TimeWindow::Last5m, TimeWindow::Last1h, TimeWindow::Last24h] {
                ui.selectable_value(&mut self.time_window, window, window.label());
            }
            ui.label(
                RichText::new("Applies to trend and analytics charts in this view.").weak(),
            );
        });
    }

    fn metric_window_samples(&self) -> Vec<&MetricSample> {
        let now = now_unix_secs();
        let min_ts = now.saturating_sub(self.time_window.seconds());
        self.metric_history
            .iter()
            .filter(|sample| sample.ts >= min_ts)
            .collect()
    }

    fn metric_window_samples_owned(&self) -> Vec<MetricSample> {
        self.metric_window_samples().into_iter().cloned().collect()
    }

    fn current_actor(&self) -> String {
        self.evrus_jwt
            .as_deref()
            .and_then(parse_identity_from_jwt)
            .and_then(|identity| identity.did)
            .unwrap_or_else(|| "operator".to_string())
    }

    fn trust_badge_text(&self) -> String {
        let role = self.role_label.to_ascii_uppercase();
        let Some(_health) = self.connector_health_for("EVRUS") else {
            return format!("LOCAL · {role}");
        };
        let did = self
            .evrus_jwt
            .as_deref()
            .and_then(parse_identity_from_jwt)
            .and_then(|identity| identity.did)
            .unwrap_or_else(|| "unknown-did".to_string());
        let anchor_enabled = self
            .connector_summary
            .snapshot_for("EVRUS")
            .and_then(|s| s.data.get("anchor_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if anchor_enabled {
            format!("EVRUS · ANCHORED · {role}")
        } else {
            format!("EVRUS · {did} · {role}")
        }
    }

    pub fn new() -> anyhow::Result<Self> {
        let cfg = load_runtime_config()?;
        let allow_privileged = cfg.privileged;
        let mut capabilities = Vec::new();
        let trust_state = if allow_privileged {
            capabilities.push(Capability::KillProcess);
            capabilities.push(Capability::ReniceProcess);
            "PRIVILEGED"
        } else {
            "UNPRIVILEGED"
        };
        let cwd = std::env::current_dir()?;
        let audit_path = default_audit_path(&cwd);
        let socket_path =
            std::env::temp_dir().join(format!("manticore-sentinel-{}.sock", std::process::id()));
        let helper_mode = cfg.helper_mode.clone();
        let helper = if helper_mode.eq_ignore_ascii_case("subprocess") {
            HelperRuntime::start_subprocess(socket_path, audit_path.clone(), capabilities)?
        } else {
            HelperRuntime::start_embedded(socket_path, audit_path.clone(), capabilities)?
        };
        let auth = AuthContext {
            mode: cfg.auth_mode,
            role: cfg.role,
        };
        let auth_gate = AuthGate::new(auth, cfg.auth_token.clone(), cfg.token_lifecycle);
        let mut runtime_diagnostics = format!(
            "profile={} privileged={} helper_mode={} refresh_ms={} proc_max={} proc_cmdline={} role={} auth_mode={} token_ttl_secs={} peerweave={} evrus={}",
            cfg.profile,
            cfg.privileged,
            cfg.helper_mode,
            cfg.refresh_ms,
            cfg.process_max_entries,
            cfg.process_cmdline_entries,
            cfg.role.as_str(),
            cfg.auth_mode.as_str(),
            cfg.token_lifecycle.map(|t| t.ttl_secs).unwrap_or(0),
            if cfg.connectors.peerweave.is_some() { "on" } else { "off" },
            if cfg.connectors.evrus.is_some() { "on" } else { "off" },
        );
        let token_lifecycle = cfg.token_lifecycle;
        let evrus_jwt = cfg.connectors.evrus.as_ref().and_then(|ev| ev.jwt.clone());
        let evrus_anchor_config = cfg.connectors.evrus.as_ref().and_then(|ev| {
            if !ev.anchor_enabled {
                return None;
            }
            Some(AnchorConfig {
                rpc_url: ev.rpc_url.clone()?,
                rpc_user: ev.rpc_user.clone()?,
                rpc_pass: ev.rpc_pass.clone()?,
            })
        });
        let anchor_interval = cfg
            .connectors
            .evrus
            .as_ref()
            .map(|ev| Duration::from_secs(ev.anchor_interval_secs))
            .unwrap_or(Duration::from_secs(300));
        let anchor_state = load_anchor_state(&audit_path).unwrap_or_default();
        let snapshot_history_path = run_scoped_snapshot_history_path(&cwd);
        if cfg.snapshot_history.enabled && cfg.snapshot_history.reset_on_start {
            reset_snapshot_history(&snapshot_history_path)?;
        }
        if cfg.snapshot_history.enabled {
            if let Some(parent) = snapshot_history_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !snapshot_history_path.exists() {
                std::fs::write(&snapshot_history_path, "")?;
            }
        }

        let mut engine = SentinelEngine::new(cfg.process_max_entries, cfg.process_cmdline_entries);
        engine.init_connectors(&cfg.connectors);
        runtime_diagnostics = format!("{runtime_diagnostics} hosts={}", engine.host_count());
        let connector_poll_interval = cfg
            .connectors
            .peerweave
            .as_ref()
            .map(|pw| Duration::from_millis(pw.poll_ms))
            .unwrap_or(Duration::from_secs(5));

        let policy = ExecutionPolicy::new(auth, ExecutionPolicy::load_evrus_policy());
        let last_policy_hash = policy.current_policy_hash();
        let mut all_warnings = cfg.config_warnings.clone();
        for pw in ExecutionPolicy::policy_load_warnings() {
            all_warnings.push(ConfigWarning {
                area: "Policy",
                message: pw,
            });
        }
        let event_stream = cfg.event_stream.as_ref().and_then(|es| {
            EventStreamOutput::start(
                es.port,
                cfg.auth_mode,
                cfg.auth_token.clone(),
                evrus_jwt.clone(),
            )
            .ok()
        });

        let poll_interval = Duration::from_millis(cfg.refresh_ms);
        let ui_repaint_interval = Duration::from_millis(cfg.refresh_ms.clamp(250, 1500));

        let mut dashboard = Self {
            engine,
            runtime: Runtime::new()?,
            latest: None,
            last_poll: Instant::now() - poll_interval,
            poll_interval,
            ui_repaint_interval,
            last_error: None,
            command_input: String::new(),
            auth_token_input: String::new(),
            command_feedback: None,
            helper,
            trust_state,
            role_label: cfg.role.as_str(),
            auth_mode_label: cfg.auth_mode.as_str(),
            audit_feed: Vec::new(),
            visuals_applied: false,
            pending_action: None,
            confirm_input: String::new(),
            last_audit_refresh: Instant::now() - Duration::from_secs(2),
            policy,
            auth_gate,
            auth_failures: 0,
            auth_locked_until: None,
            show_onboarding: false,
            show_help_center: false,
            runtime_diagnostics,
            last_command_feedback_announced: None,
            command_history: VecDeque::new(),
            history_browse: None,
            history_draft: String::new(),
            connector_summary: ConnectorSummary::default(),
            last_connector_poll: Instant::now() - Duration::from_secs(60),
            connector_poll_interval,
            collapsed_sections: {
                let mut s = HashSet::new();
                s.insert(SECTION_DISK_NET);
                s.insert(SECTION_AUDIT);
                s.insert(SECTION_CONNECTORS);
                s
            },
            scroll_to_section: None,
            token_lifecycle,
            evrus_jwt,
            anchor_state,
            evrus_anchor_config,
            anchor_interval,
            last_anchor_poll: Instant::now() - anchor_interval,
            last_policy_hash,
            process_sort: ProcessSort::CpuDesc,
            audit_filter: String::new(),
            event_stream,
            event_stream_audit_offset: 0,
            last_event_stream_audit_poll: Instant::now() - Duration::from_secs(5),
            snapshot_history_enabled: cfg.snapshot_history.enabled,
            snapshot_history_max_entries: cfg.snapshot_history.max_entries,
            snapshot_history_max_age_secs: cfg.snapshot_history.max_age_secs,
            snapshot_history_max_bytes: cfg.snapshot_history.max_bytes,
            snapshot_history_slim_records: cfg.snapshot_history.slim_records,
            snapshot_history_reset_on_start: cfg.snapshot_history.reset_on_start,
            snapshot_history_path,
            snapshot_history_recent_hour: 0,
            last_snapshot_history_probe: Instant::now() - Duration::from_secs(10),
            latest_alerts: Vec::new(),
            process_filter: String::new(),
            expanded_process_pid: None,
            audit_page: 0,
            audit_page_size: 50,
            expanded_audit_idx: None,
            audit_retention: cfg.audit_retention.clone(),
            config_warnings: all_warnings,
            config_warnings_dismissed: false,
            show_connector_wizard: false,
            wizard_step: 0,
            wizard_connector_type: 0,
            wizard_url: String::new(),
            wizard_token: String::new(),
            wizard_space_id: String::new(),
            detailed_mode: true,
            show_glossary: false,
            self_collect_last_ms: 0.0,
            self_collect_avg_ms: 0.0,
            self_collect_cycles: 0,
            self_connector_polls: 0,
            self_errors_total: 0,
            self_last_error_ts: None,
            time_window: TimeWindow::Last1h,
            metric_history: VecDeque::with_capacity(METRIC_HISTORY_CAP),
            process_count_history: VecDeque::with_capacity(METRIC_HISTORY_CAP),
            process_churn_history: VecDeque::with_capacity(METRIC_HISTORY_CAP),
            audit_rate_history: VecDeque::with_capacity(METRIC_HISTORY_CAP),
            connector_latency_history: VecDeque::with_capacity(METRIC_HISTORY_CAP),
            previous_process_ids: HashSet::new(),
        };
        dashboard.hydrate_metric_history_from_disk();
        Ok(dashboard)
    }

    fn poll(&mut self) {
        if self.last_poll.elapsed() < self.poll_interval {
            return;
        }
        self.last_poll = Instant::now();

        let collect_started = Instant::now();
        match self.runtime.block_on(self.engine.collect()) {
            Ok(snapshot) => {
                self.self_collect_last_ms = collect_started.elapsed().as_secs_f64() * 1000.0;
                self.self_collect_cycles = self.self_collect_cycles.saturating_add(1);
                if self.self_collect_cycles == 1 {
                    self.self_collect_avg_ms = self.self_collect_last_ms;
                } else {
                    self.self_collect_avg_ms =
                        (self.self_collect_avg_ms * 0.9) + (self.self_collect_last_ms * 0.1);
                }
                self.engine.ingest_system_snapshot(&snapshot);
                let mem_pct = if snapshot.memory.total == 0 {
                    0.0
                } else {
                    (snapshot.memory.used as f32 / snapshot.memory.total as f32) * 100.0
                };
                let disk_bps: f64 = snapshot
                    .disks
                    .iter()
                    .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec) as f64)
                    .sum();
                let net_bps: f64 = snapshot
                    .network
                    .iter()
                    .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec) as f64)
                    .sum();
                if self.self_collect_cycles > 1 {
                    push_history(
                        &mut self.metric_history,
                        MetricSample {
                            ts: snapshot.timestamp,
                            cpu_pct: snapshot.cpu.usage_percent,
                            mem_pct,
                            disk_bps,
                            net_bps,
                            process_count: snapshot.processes.len(),
                        },
                        METRIC_HISTORY_CAP,
                    );
                }
                push_history(
                    &mut self.process_count_history,
                    (snapshot.timestamp, snapshot.processes.len()),
                    METRIC_HISTORY_CAP,
                );
                let current_ids: HashSet<u32> = snapshot.processes.iter().map(|p| p.pid).collect();
                if !self.previous_process_ids.is_empty() {
                    let started = current_ids
                        .difference(&self.previous_process_ids)
                        .count();
                    let exited = self
                        .previous_process_ids
                        .difference(&current_ids)
                        .count();
                    push_history(
                        &mut self.process_churn_history,
                        (snapshot.timestamp, started, exited),
                        METRIC_HISTORY_CAP,
                    );
                }
                self.previous_process_ids = current_ids;
                if self.snapshot_history_enabled {
                    if let Err(err) = append_snapshot(
                        &self.snapshot_history_path,
                        &snapshot,
                        SnapshotHistoryRetention {
                            max_entries: self.snapshot_history_max_entries,
                            max_age_secs: self.snapshot_history_max_age_secs,
                            max_bytes: self.snapshot_history_max_bytes,
                            slim_records: self.snapshot_history_slim_records,
                        },
                    ) {
                        self.last_error = Some(format!("snapshot persistence failed: {err}"));
                        self.self_errors_total = self.self_errors_total.saturating_add(1);
                        self.self_last_error_ts = Some(now_unix_secs());
                    }
                }
                self.latest_alerts = self.policy.evaluate_snapshot_alerts(&snapshot);
                if let Some(stream) = &self.event_stream {
                    let payload = serde_json::json!({
                        "timestamp": snapshot.timestamp,
                        "host_id": snapshot.host_id,
                        "cpu_usage_percent": snapshot.cpu.usage_percent,
                        "load_avg": [snapshot.cpu.load_avg.0, snapshot.cpu.load_avg.1, snapshot.cpu.load_avg.2],
                        "memory_used": snapshot.memory.used,
                        "memory_total": snapshot.memory.total,
                        "disk_count": snapshot.disks.len(),
                        "network_count": snapshot.network.len(),
                        "process_count": snapshot.processes.len(),
                    });
                    stream.emit_json("system_snapshot", &payload);
                }
                self.latest = Some(snapshot);
                self.last_error = None;
            }
            Err(err) => {
                self.last_error = Some(err.to_string());
                error!(category = "collector", message = %err, "snapshot collection failed");
                self.self_errors_total = self.self_errors_total.saturating_add(1);
                self.self_last_error_ts = Some(now_unix_secs());
            }
        }

        if self.engine.has_connectors()
            && self.last_connector_poll.elapsed() >= self.connector_poll_interval
        {
            self.connector_summary = self.engine.poll_connectors();
            let now = now_unix_secs();
            let pw = self
                .connector_summary
                .health_for("PeerWeave")
                .and_then(|h| h.latency_ms);
            let evrus = self
                .connector_summary
                .health_for("EVRUS")
                .and_then(|h| h.latency_ms);
            push_history(
                &mut self.connector_latency_history,
                (now, pw, evrus),
                METRIC_HISTORY_CAP,
            );
            self.self_connector_polls = self.self_connector_polls.saturating_add(1);
            self.last_connector_poll = Instant::now();
        }

        if let Some(anchor_cfg) = &self.evrus_anchor_config {
            if self.last_anchor_poll.elapsed() >= self.anchor_interval {
                match anchor_audit_if_due(
                    &self.helper.audit_path,
                    &self.current_actor(),
                    anchor_cfg,
                ) {
                    Ok(Some(state)) => {
                        self.anchor_state = state;
                    }
                    Ok(None) => {
                        if let Ok(state) = load_anchor_state(&self.helper.audit_path) {
                            self.anchor_state = state;
                        }
                    }
                    Err(err) => {
                        self.last_error = Some(format!("audit anchor failed: {err}"));
                        self.self_errors_total = self.self_errors_total.saturating_add(1);
                        self.self_last_error_ts = Some(now_unix_secs());
                    }
                }
                self.last_anchor_poll = Instant::now();
            }
        }

        if self.event_stream.is_some()
            && self.last_event_stream_audit_poll.elapsed() >= Duration::from_secs(1)
        {
            if let Ok((events, next_offset)) =
                read_from_offset(&self.helper.audit_path, self.event_stream_audit_offset)
            {
                if let Some(stream) = &self.event_stream {
                    for event in events {
                        if let Ok(payload) = serde_json::to_value(&event) {
                            stream.emit_json("audit_event", &payload);
                        }
                    }
                }
                self.event_stream_audit_offset = next_offset;
            }
            self.last_event_stream_audit_poll = Instant::now();
        }

        if self.snapshot_history_enabled
            && self.last_snapshot_history_probe.elapsed() >= Duration::from_secs(30)
        {
            let now = now_unix_secs();
            let min_ts = now.saturating_sub(3600);
            match count_since(&self.snapshot_history_path, min_ts) {
                Ok(count) => self.snapshot_history_recent_hour = count,
                Err(err) => {
                    self.last_error = Some(format!("snapshot history query failed: {err}"));
                    self.self_errors_total = self.self_errors_total.saturating_add(1);
                    self.self_last_error_ts = Some(now_unix_secs());
                }
            }
            self.last_snapshot_history_probe = Instant::now();
        }
        let (allow_count, deny_count) = self.audit_feed.iter().fold((0usize, 0usize), |acc, event| {
            if event.result.to_ascii_lowercase().contains("denied") {
                (acc.0, acc.1 + 1)
            } else {
                (acc.0 + 1, acc.1)
            }
        });
        push_history(
            &mut self.audit_rate_history,
            (now_unix_secs(), allow_count, deny_count),
            METRIC_HISTORY_CAP,
        );
    }

    fn verify_auth_submission(&mut self, action: &CommandAction) -> Result<(), String> {
        if let Some(until) = self.auth_locked_until {
            if Instant::now() < until {
                let remaining = until.saturating_duration_since(Instant::now()).as_secs();
                let reason = format!("authentication locked: retry in {}s", remaining.max(1));
                audit_auth_failure(
                    &self.helper,
                    action,
                    &reason,
                    &self.current_actor(),
                    self.last_policy_hash.clone(),
                    &self.audit_retention,
                );
                return Err(reason);
            }
            self.auth_locked_until = None;
        }

        match self
            .auth_gate
            .verify_submission(Some(self.auth_token_input.as_str()))
        {
            Ok(()) => {
                self.auth_failures = 0;
                Ok(())
            }
            Err(err) => {
                self.auth_failures = self.auth_failures.saturating_add(1);
                if self.auth_failures >= 3 {
                    let lock_secs = ((self.auth_failures - 2) * 10).min(60) as u64;
                    self.auth_locked_until = Some(Instant::now() + Duration::from_secs(lock_secs));
                }
                audit_auth_failure(
                    &self.helper,
                    action,
                    &err,
                    &self.current_actor(),
                    self.last_policy_hash.clone(),
                    &self.audit_retention,
                );
                Err(err)
            }
        }
    }

    fn handle_global_shortcuts(&mut self, ctx: &egui::Context) {
        let cmd_focus_id = egui::Id::new(ID_COMMAND_INPUT);

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            if self.show_onboarding {
                self.show_onboarding = false;
            } else if self.show_help_center {
                self.show_help_center = false;
            } else if self.pending_action.is_some() {
                self.pending_action = None;
                self.confirm_input.clear();
                self.command_feedback = Some("Action canceled.".to_string());
            }
        }

        if ctx.input(|i| i.key_pressed(egui::Key::F1)) {
            self.show_help_center = true;
        }
        if ctx.input(|i| i.modifiers.shift && i.key_pressed(egui::Key::Slash)) {
            self.show_help_center = true;
        }

        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::K)) {
            ctx.memory_mut(|m| m.request_focus(cmd_focus_id));
        }
    }

    fn execute_read_only_command(&self, action: &CommandAction) -> Option<String> {
        match action {
            CommandAction::ShowCpu => {
                let snap = self.latest.as_ref()?;
                let mut out = String::new();
                out.push_str(&format!("CPU: {:.2}%\n", snap.cpu.usage_percent));
                out.push_str(&format!(
                    "Load avg: {:.2} {:.2} {:.2}\n",
                    snap.cpu.load_avg.0, snap.cpu.load_avg.1, snap.cpu.load_avg.2
                ));
                if snap.cpu.per_core.is_empty() {
                    out.push_str("Per-core: unavailable");
                } else {
                    out.push_str("Per-core (%): ");
                    for (idx, pct) in snap.cpu.per_core.iter().enumerate() {
                        if idx > 0 {
                            out.push_str("  ");
                        }
                        out.push_str(&format!("{idx}:{pct:.1}"));
                    }
                }
                Some(out)
            }
            CommandAction::ShowMemory => {
                let snap = self.latest.as_ref()?;
                let m = &snap.memory;
                let pct = if m.total > 0 {
                    (m.used as f64 / m.total as f64 * 100.0).round()
                } else {
                    0.0
                };
                Some(format!(
                    "Memory:\n  total:     {}\n  used:      {} ({:.0}%)\n  available: {}",
                    human_bytes(m.total),
                    human_bytes(m.used),
                    pct,
                    human_bytes(m.available)
                ))
            }
            CommandAction::ShowDisk => {
                let snap = self.latest.as_ref()?;
                let mut out = String::from("Disk throughput:\n");
                let mut sorted: Vec<_> = snap.disks.iter().collect();
                sorted.sort_by_key(|d| {
                    std::cmp::Reverse(d.read_bytes_per_sec + d.write_bytes_per_sec)
                });
                for d in &sorted {
                    out.push_str(&format!(
                        "  {} R:{}/s W:{}/s\n",
                        d.device,
                        human_bytes(d.read_bytes_per_sec),
                        human_bytes(d.write_bytes_per_sec)
                    ));
                }
                Some(out)
            }
            CommandAction::ShowNetwork => {
                let snap = self.latest.as_ref()?;
                let mut out = String::from("Network throughput:\n");
                let mut sorted: Vec<_> = snap.network.iter().collect();
                sorted.sort_by_key(|n| std::cmp::Reverse(n.rx_bytes_per_sec + n.tx_bytes_per_sec));
                for n in &sorted {
                    out.push_str(&format!(
                        "  {} RX:{}/s TX:{}/s\n",
                        n.interface,
                        human_bytes(n.rx_bytes_per_sec),
                        human_bytes(n.tx_bytes_per_sec)
                    ));
                }
                Some(out)
            }
            CommandAction::ShowProcesses { sort, limit } => {
                let snap = self.latest.as_ref()?;
                let mut procs: Vec<_> = snap.processes.clone();
                match sort.as_deref() {
                    Some("rss") => procs.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
                    Some("pid") => procs.sort_by(|a, b| a.pid.cmp(&b.pid)),
                    Some("threads") => procs.sort_by(|a, b| b.threads.cmp(&a.threads)),
                    _ => procs.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
                }
                let lim = limit.unwrap_or(20);
                let mut out = format!(
                    "Processes (top {} by {}):\n",
                    lim,
                    sort.as_deref().unwrap_or("cpu")
                );
                out.push_str("  PID      CPU%    RSS          Name\n");
                for p in procs.iter().take(lim) {
                    out.push_str(&format!(
                        "  {:<8} {:<7.2} {:<12} {}\n",
                        p.pid,
                        p.cpu_percent,
                        human_bytes(p.memory_bytes),
                        p.name
                    ));
                }
                Some(out)
            }
            CommandAction::ShowAlerts => {
                if self.latest_alerts.is_empty() {
                    return Some("No active alerts.".to_string());
                }
                let mut out = String::from("Active alerts:\n");
                for a in &self.latest_alerts {
                    out.push_str(&format!(
                        "  [{:?}] {} — {}\n",
                        a.severity, a.rule_id, a.message
                    ));
                }
                Some(out)
            }
            CommandAction::ShowConfig => {
                let mut out = String::from("Effective configuration:\n");
                out.push_str(&format!(
                    "  profile:           {}\n",
                    self.runtime_diagnostics
                ));
                out.push_str(&format!("  auth_mode:         {}\n", self.auth_mode_label));
                out.push_str(&format!("  role:              {}\n", self.role_label));
                out.push_str(&format!("  trust:             {}\n", self.trust_state));
                out.push_str(&format!(
                    "  audit_max_entries: {}\n",
                    self.audit_retention.max_entries
                ));
                out.push_str(&format!(
                    "  audit_archive:     {}\n",
                    self.audit_retention.archive_enabled
                ));
                out.push_str(&format!(
                    "  history_enabled:   {}\n",
                    self.snapshot_history_enabled
                ));
                out.push_str(&format!(
                    "  history_max:       {}\n",
                    self.snapshot_history_max_entries
                ));
                out.push_str(&format!(
                    "  history_reset:     {}\n",
                    self.snapshot_history_reset_on_start
                ));
                out.push_str(&format!(
                    "  history_max_age:   {}\n",
                    self.snapshot_history_max_age_secs
                        .map(|v| format!("{v}s"))
                        .unwrap_or_else(|| "off".to_string())
                ));
                out.push_str(&format!(
                    "  history_max_bytes: {}\n",
                    self.snapshot_history_max_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "off".to_string())
                ));
                out.push_str(&format!(
                    "  history_slim:      {}\n",
                    self.snapshot_history_slim_records
                ));
                out.push_str(&format!(
                    "  sse:               {}\n",
                    if self.event_stream.is_some() {
                        "on"
                    } else {
                        "off"
                    }
                ));
                if !self.config_warnings.is_empty() {
                    out.push_str("\n  Warnings:\n");
                    for w in &self.config_warnings {
                        out.push_str(&format!("    [{}] {}\n", w.area, w.message));
                    }
                }
                Some(out)
            }
            CommandAction::ShowConnectors => {
                let summary = if self.connector_summary.entries.is_empty() {
                    self.engine.connector_summary_passive()
                } else {
                    self.connector_summary.clone()
                };
                if summary.entries.is_empty() {
                    return Some("No connectors configured. Set MANTICORE_PEERWEAVE_ENABLED=true or MANTICORE_EVRUS_ENABLED=true.".to_string());
                }
                let mut out = String::from("Connector status:\n");
                for e in &summary.entries {
                    out.push_str(&format!(
                        "  {} — {:?}{}\n",
                        e.name,
                        e.status,
                        e.detail
                            .as_ref()
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default()
                    ));
                }
                Some(out)
            }
            CommandAction::ShowAudit { last } => {
                let events = read_recent(&self.helper.audit_path, *last).unwrap_or_default();
                if events.is_empty() {
                    return Some("No audit events.".to_string());
                }
                let mut out = format!("Last {} audit events:\n", events.len());
                for e in &events {
                    out.push_str(&format!(
                        "  [{}] {} → {} ({}) by {}\n",
                        e.ts, e.action, e.target, e.result, e.actor
                    ));
                }
                Some(out)
            }
            CommandAction::ShowStorage => {
                let cwd = std::env::current_dir().unwrap_or_default();
                let audit_path = default_audit_path(&cwd);
                let audit_size = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
                let entries = audit_entry_count(&audit_path);
                let snap_size = std::fs::metadata(&self.snapshot_history_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let (arc_count, arc_bytes) = audit_archive_stats(&audit_path);
                let mut out = String::from("Storage health:\n");
                out.push_str(&format!(
                    "  audit events:   {} entries, {}\n",
                    entries,
                    format_bytes(audit_size)
                ));
                out.push_str(&format!(
                    "  audit max:      {}\n",
                    self.audit_retention.max_entries
                ));
                out.push_str(&format!(
                    "  audit archive:  {} files, {}\n",
                    arc_count,
                    format_bytes(arc_bytes)
                ));
                out.push_str(&format!("  snapshots:      {}\n", format_bytes(snap_size)));
                out.push_str(&format!(
                    "  snapshot max:   {}\n",
                    self.snapshot_history_max_entries
                ));
                out.push_str(&format!(
                    "  snapshot max age: {}\n",
                    self.snapshot_history_max_age_secs
                        .map(|v| format!("{v}s"))
                        .unwrap_or_else(|| "off".to_string())
                ));
                out.push_str(&format!(
                    "  snapshot max bytes: {}\n",
                    self.snapshot_history_max_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "off".to_string())
                ));
                Some(out)
            }
            CommandAction::Help { topic } => {
                Some(crate::core::command::help_text(topic.as_deref()))
            }
            _ => None,
        }
    }

    fn run_command_palette_action(&mut self) {
        let trimmed = self.command_input.trim().to_string();
        let (feedback, clear_line) = match parse_command(&trimmed) {
            Ok(action) => {
                if let Some(output) = self.execute_read_only_command(&action) {
                    (output, true)
                } else if let Err(err) = self.verify_auth_submission(&action) {
                    (err, false)
                } else if matches!(action, CommandAction::KillProcess { .. }) {
                    match self.policy.evaluate(&action) {
                        Err(err) => {
                            audit_policy_denial(
                                &self.helper,
                                &action,
                                &err,
                                &self.current_actor(),
                                self.policy.current_policy_hash(),
                                &self.audit_retention,
                            );
                            (err, false)
                        }
                        Ok(decision) => {
                            self.last_policy_hash = decision.policy_hash.clone();
                            self.pending_action = Some(action);
                            (
                                "Confirmation required for destructive action.".to_string(),
                                false,
                            )
                        }
                    }
                } else {
                    match self.policy.evaluate(&action) {
                        Err(err) => {
                            audit_policy_denial(
                                &self.helper,
                                &action,
                                &err,
                                &self.current_actor(),
                                self.policy.current_policy_hash(),
                                &self.audit_retention,
                            );
                            (err, false)
                        }
                        Ok(decision) => {
                            self.last_policy_hash = decision.policy_hash.clone();
                            let output = execute_action(
                                &self.helper,
                                action.clone(),
                                &self.current_actor(),
                                self.last_policy_hash.clone(),
                                &self.audit_retention,
                            );
                            self.policy.record(&action);
                            (output, true)
                        }
                    }
                }
            }
            Err(err) => (format!("Invalid: {err}"), false),
        };

        if clear_line {
            self.record_command_history(&trimmed);
            self.command_input.clear();
            self.history_browse = None;
            self.history_draft.clear();
        }
        self.command_feedback = Some(feedback);
    }

    fn record_command_history(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        if self.command_history.back().map(|s| s.as_str()) == Some(line) {
            return;
        }
        while self.command_history.len() >= 50 {
            self.command_history.pop_front();
        }
        self.command_history.push_back(line.to_string());
    }

    fn history_entry_from_newest(&self, from_newest: usize) -> Option<&String> {
        let len = self.command_history.len();
        let idx = len.checked_sub(1 + from_newest)?;
        self.command_history.get(idx)
    }

    fn shell_history_up(&mut self) {
        let len = self.command_history.len();
        if len == 0 {
            return;
        }
        match self.history_browse {
            None => {
                self.history_draft = self.command_input.clone();
                self.history_browse = Some(0);
                if let Some(e) = self.history_entry_from_newest(0) {
                    self.command_input = e.clone();
                }
            }
            Some(k) if k + 1 < len => {
                self.history_browse = Some(k + 1);
                if let Some(e) = self.history_entry_from_newest(k + 1) {
                    self.command_input = e.clone();
                }
            }
            Some(_) => {}
        }
    }

    fn shell_history_down(&mut self) {
        match self.history_browse {
            None => {}
            Some(0) => {
                self.history_browse = None;
                self.command_input.clone_from(&self.history_draft);
                self.history_draft.clear();
            }
            Some(k) => {
                self.history_browse = Some(k - 1);
                if let Some(e) = self.history_entry_from_newest(k - 1) {
                    self.command_input = e.clone();
                }
            }
        }
    }

    fn shell_tab_complete(&mut self) {
        let comps = filtered_command_completions(&self.command_input);
        if let Some(first) = comps.first() {
            self.command_input = (*first).to_string();
        }
    }

    fn quick_status_chips(&self, ui: &mut egui::Ui) {
        let body = FontId::new(13.5, FontFamily::Proportional);
        match &self.latest {
            Some(s) => {
                let mem_ratio = if s.memory.total == 0 {
                    0.0
                } else {
                    s.memory.used as f32 / s.memory.total as f32
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "CPU {:.1}% · Mem {:.0}% · load {:.2} / {:.2} / {:.2}",
                            s.cpu.usage_percent,
                            mem_ratio * 100.0,
                            s.cpu.load_avg.0,
                            s.cpu.load_avg.1,
                            s.cpu.load_avg.2
                        ))
                        .font(body)
                        .strong(),
                    )
                    .wrap(true),
                )
                .on_hover_text(
                    "Live snapshot: utilization, memory percent of total, and 1/5/15 load.",
                );
            }
            None => {
                ui.label(RichText::new("Collecting…").font(body).weak());
            }
        }
    }

    fn render_command_workbench(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let panel_w = ui.available_width();
        ui.set_min_width(panel_w);

        let shell_inset = egui::Margin::symmetric(10.0, 8.0);
        let shell_fill = egui::Color32::from_rgb(16, 20, 26);
        let shell_stroke = Stroke::new(1.0, egui::Color32::from_rgb(52, 66, 84));
        let mono = FontId::new(14.0, FontFamily::Monospace);
        let mono_hint = FontId::new(11.5, FontFamily::Monospace);
        let prompt_color = egui::Color32::from_rgb(110, 198, 224);

        if self.auth_gate.context().mode == AuthMode::Token {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(20, 24, 30))
                .inner_margin(shell_inset)
                .rounding(egui::Rounding::same(6.0))
                .stroke(shell_stroke)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let lock_remaining = self
                        .auth_locked_until
                        .and_then(|until| until.checked_duration_since(Instant::now()))
                        .map(|d| d.as_secs().max(1));
                    if let Some(remaining) = lock_remaining {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 76, 70),
                            format!(
                                "Auth lockout: {} failures, retry in {}s",
                                self.auth_failures, remaining
                            ),
                        );
                    } else if self.auth_failures > 0 {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 176, 64),
                            format!("Auth failures: {} (lockout after 3)", self.auth_failures),
                        );
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Token").font(mono_hint.clone()));
                        let token_w = ui.available_width().max(120.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.auth_token_input)
                                .font(mono_hint.clone())
                                .password(true)
                                .hint_text("paste auth token…")
                                .desired_width(token_w),
                        );
                    });
                });
            ui.add_space(4.0);
        }

        egui::Frame::none()
            .fill(shell_fill)
            .inner_margin(shell_inset)
            .rounding(egui::Rounding::same(8.0))
            .stroke(shell_stroke)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                let cmd_row_room = ui.available_width();
                let run_reserve = 60.0 + ui.spacing().item_spacing.x * 2.0;
                let prompt_reserve = 90.0;
                let edit_w = (cmd_row_room - run_reserve - prompt_reserve).max(120.0);

                let mut run_clicked = false;
                let mut enter_run = false;
                let response = ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("sentinel")
                            .color(prompt_color)
                            .font(mono.clone()),
                    )
                    .on_hover_text("This session’s operator shell (not a system shell).");
                    ui.label(RichText::new("›").weak().font(mono.clone()));
                    let te = egui::TextEdit::singleline(&mut self.command_input)
                        .id(egui::Id::new(ID_COMMAND_INPUT))
                        .font(mono.clone())
                        .hint_text("type a command... (Tab complete, arrow keys history)")
                        .desired_width(edit_w);
                    let r = ui.add(te);
                    // Single-line TextEdit: Enter must be detected while focused (lost_focus + Enter
                    // often never align in the same frame).
                    enter_run =
                        ui.ctx().input(|i| i.key_pressed(egui::Key::Enter)) && r.has_focus();
                    let run = ui.add_sized(
                        [54.0, 24.0],
                        egui::Button::new(
                            RichText::new("Run")
                                .strong()
                                .font(FontId::new(12.0, FontFamily::Proportional)),
                        )
                        .fill(egui::Color32::from_rgb(52, 98, 128))
                        .stroke(Stroke::new(1.0, egui::Color32::from_rgb(72, 118, 148))),
                    );
                    run_clicked = run.clicked();
                    r
                });

                if response.inner.has_focus() {
                    if ui.ctx().input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                        self.shell_history_up();
                    }
                    if ui.ctx().input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                        self.shell_history_down();
                    }
                    if ui
                        .ctx()
                        .input(|i| i.key_pressed(egui::Key::Tab) && !i.modifiers.shift)
                    {
                        self.shell_tab_complete();
                    }
                }

                if run_clicked || enter_run {
                    self.run_command_palette_action();
                }

                let comps = filtered_command_completions(&self.command_input);
                let show_chips = !comps.is_empty()
                    && !(comps.len() == 1 && comps[0] == self.command_input.trim());
                if show_chips {
                    ui.add_space(3.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        for c in comps {
                            let lbl: &'static str = match c {
                                "renice " => "renice <nice> <pid>",
                                "kill " => "kill <pid>",
                                _ => c,
                            };
                            if ui.small_button(lbl).clicked() {
                                self.command_input = c.to_string();
                            }
                        }
                    });
                }
            });

        if let Some(CommandAction::KillProcess { pid }) = self.pending_action.clone() {
            ui.add_space(4.0);
            let required = format!("KILL {}", pid);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(36, 18, 18))
                .inner_margin(shell_inset)
                .rounding(egui::Rounding::same(8.0))
                .stroke(Stroke::new(1.0, egui::Color32::from_rgb(140, 56, 52)))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        RichText::new(format!("Type \"{required}\" to confirm destructive action"))
                            .color(egui::Color32::from_rgb(255, 190, 175))
                            .font(FontId::new(12.5, FontFamily::Proportional)),
                    );
                    ui.horizontal_wrapped(|ui| {
                        let kill_lbl = ui.label(RichText::new("confirm").font(mono_hint.clone()));
                        let confirm_w =
                            (ui.available_width() - 200.0 - ui.spacing().item_spacing.x * 4.0)
                                .max(100.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.confirm_input)
                                .font(mono.clone())
                                .desired_width(confirm_w)
                                .hint_text(&required),
                        )
                        .labelled_by(kill_lbl.id);
                        let conf = ui
                            .button("Confirm")
                            .on_hover_text("Execute confirmed kill action if policy/auth pass.");
                        conf.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, "Confirm kill")
                        });
                        if conf.clicked() {
                            if self.confirm_input.trim() == required {
                                let action = CommandAction::KillProcess { pid };
                                self.command_feedback =
                                    Some(match self.verify_auth_submission(&action) {
                                        Err(err) => err,
                                        Ok(()) => match self.policy.evaluate(&action) {
                                            Ok(decision) => {
                                                self.last_policy_hash =
                                                    decision.policy_hash.clone();
                                                let output = execute_action(
                                                    &self.helper,
                                                    action.clone(),
                                                    &self.current_actor(),
                                                    self.last_policy_hash.clone(),
                                                    &self.audit_retention,
                                                );
                                                self.policy.record(&action);
                                                self.record_command_history(&format!("kill {pid}"));
                                                self.command_input.clear();
                                                self.history_browse = None;
                                                self.history_draft.clear();
                                                output
                                            }
                                            Err(err) => {
                                                audit_policy_denial(
                                                    &self.helper,
                                                    &action,
                                                    &err,
                                                    &self.current_actor(),
                                                    self.policy.current_policy_hash(),
                                                    &self.audit_retention,
                                                );
                                                err
                                            }
                                        },
                                    });
                                self.pending_action = None;
                                self.confirm_input.clear();
                            } else {
                                self.command_feedback = Some("Confirmation mismatch.".to_string());
                            }
                        }
                        let cancel = ui
                            .button("Cancel")
                            .on_hover_text("Clear pending destructive action (Esc).");
                        cancel.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, "Cancel kill")
                        });
                        if cancel.clicked() {
                            self.pending_action = None;
                            self.confirm_input.clear();
                            self.command_feedback = Some("Action canceled.".to_string());
                        }
                    });
                });
        }

        if let Some(msg) = &self.command_feedback {
            ui.add_space(4.0);
            if self.last_command_feedback_announced.as_ref() != Some(msg) {
                self.last_command_feedback_announced = Some(msg.clone());
                let mut info = egui::WidgetInfo::new(egui::WidgetType::Label);
                info.label = Some(format!("Command result: {msg}"));
                ctx.output_mut(|o| {
                    o.events.push(egui::output::OutputEvent::ValueChanged(info));
                });
            }
            let out_stroke = if msg.starts_with("DENIED")
                || msg.starts_with("Invalid")
                || msg.contains("denied")
            {
                Stroke::new(1.0, egui::Color32::from_rgb(120, 58, 54))
            } else {
                Stroke::new(1.0, egui::Color32::from_rgb(48, 72, 58))
            };
            let out_fill = if msg.starts_with("DENIED")
                || msg.starts_with("Invalid")
                || msg.contains("denied")
            {
                egui::Color32::from_rgb(28, 18, 18)
            } else {
                egui::Color32::from_rgb(18, 26, 22)
            };
            egui::Frame::none()
                .fill(out_fill)
                .inner_margin(shell_inset)
                .rounding(egui::Rounding::same(8.0))
                .stroke(out_stroke)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let out_text = egui::Color32::from_rgb(232, 238, 246);
                    egui::ScrollArea::vertical()
                        .id_source("command_output_scroll")
                        .max_height(220.0)
                        .auto_shrink([true, true])
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(msg.as_str())
                                        .font(mono.clone())
                                        .color(out_text),
                                )
                                .wrap(true),
                            );
                        });
                });
        }

        if !self.command_history.is_empty() {
            ui.add_space(4.0);
            ui.label(
                RichText::new("History")
                    .weak()
                    .font(mono_hint.clone()),
            );
            egui::ScrollArea::vertical()
                .id_source("session_cmd_history_scroll")
                .max_height(120.0)
                .auto_shrink([true, true])
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let entries: Vec<String> = self.command_history.iter().rev().cloned().collect();
                    for line in entries {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(line.as_str())
                                        .font(mono_hint.clone())
                                        .color(egui::Color32::from_rgb(200, 210, 222)),
                                )
                                .wrap(true),
                            );
                            if ui
                                .small_button("Reuse")
                                .on_hover_text("Put this line in the shell (edit, then Enter).")
                                .clicked()
                            {
                                self.command_input = line.clone();
                                self.history_browse = None;
                                self.history_draft.clear();
                                ctx.memory_mut(|m| {
                                    m.request_focus(egui::Id::new(ID_COMMAND_INPUT));
                                });
                            }
                            if ui
                                .small_button("Run")
                                .on_hover_text("Execute this line again.")
                                .clicked()
                            {
                                self.command_input = line;
                                self.history_browse = None;
                                self.history_draft.clear();
                                self.run_command_palette_action();
                            }
                        });
                        ui.add_space(2.0);
                    }
                });
        }

        ui.add_space(8.0);
        let collapsed = egui::CollapsingHeader::new("Advanced Controls").default_open(false);
        let adv = collapsed.show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                icons::paint(ui, "settings", icons::SETTINGS, 14.0);
                ui.label("Power-user diagnostics and runtime metadata");
            });
            ui.add(
                egui::Label::new(format!(
                    "helper_socket={}",
                    self.helper.socket_path.display()
                ))
                .wrap(true),
            );
            ui.add(
                egui::Label::new(format!("audit_path={}", self.helper.audit_path.display()))
                    .wrap(true),
            );
            ui.monospace(format!("auth_failures={}", self.auth_failures));
            ui.monospace(format!(
                "auth_lockout_active={}",
                self.auth_locked_until
                    .map(|t| t > Instant::now())
                    .unwrap_or(false)
            ));
            ui.add(egui::Label::new(format!("runtime={}", self.runtime_diagnostics)).wrap(true));
        });
        adv.header_response.widget_info(|| {
            egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, "Advanced Controls")
        });
    }

    fn render_control_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.set_min_width(ui.available_width());
        self.render_command_workbench(ui, ctx);
    }

    fn render_connector_wizard(&mut self, ui: &mut egui::Ui) {
        const TYPES: &[&str] = &["PeerWeave", "EVRUS", "SSE (Event Stream)"];
        match self.wizard_step {
            0 => {
                ui.heading("Step 1: Choose Connector");
                ui.label("Select which integration to configure:");
                ui.add_space(8.0);
                for (i, name) in TYPES.iter().enumerate() {
                    if ui
                        .selectable_label(self.wizard_connector_type == i, *name)
                        .clicked()
                    {
                        self.wizard_connector_type = i;
                    }
                }
                ui.add_space(12.0);
                if ui.button("Next →").clicked() {
                    self.wizard_step = 1;
                    self.wizard_url = match self.wizard_connector_type {
                        0 => "http://localhost:3200/graphql".to_string(),
                        1 => "http://localhost:8790".to_string(),
                        _ => "9462".to_string(),
                    };
                }
            }
            1 => {
                let name = TYPES[self.wizard_connector_type.min(2)];
                ui.heading(format!("Step 2: Configure {name}"));
                ui.add_space(8.0);
                match self.wizard_connector_type {
                    0 => {
                        ui.label("GraphQL URL:");
                        ui.text_edit_singleline(&mut self.wizard_url);
                        ui.add_space(4.0);
                        ui.label("CapToken (for graph.read):");
                        ui.text_edit_singleline(&mut self.wizard_token);
                        ui.add_space(4.0);
                        ui.label("Publish Space ID (optional):");
                        ui.text_edit_singleline(&mut self.wizard_space_id);
                    }
                    1 => {
                        ui.label("OIDC URL:");
                        ui.text_edit_singleline(&mut self.wizard_url);
                        ui.add_space(4.0);
                        ui.label("JWT Token:");
                        ui.text_edit_singleline(&mut self.wizard_token);
                    }
                    _ => {
                        ui.label("SSE Port:");
                        ui.text_edit_singleline(&mut self.wizard_url);
                    }
                }
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("← Back").clicked() {
                        self.wizard_step = 0;
                    }
                    if ui.button("Generate Config →").clicked() {
                        self.wizard_step = 2;
                    }
                });
            }
            _ => {
                ui.heading("Step 3: Environment Variables");
                ui.label("Add these to your shell or profile .env file:");
                ui.add_space(8.0);
                let env_block = match self.wizard_connector_type {
                    0 => {
                        let mut s = format!(
                            "MANTICORE_PEERWEAVE_ENABLED=true\nMANTICORE_PEERWEAVE_GRAPHQL_URL={}\n",
                            self.wizard_url
                        );
                        if !self.wizard_token.is_empty() {
                            s.push_str(&format!(
                                "MANTICORE_PEERWEAVE_CAP_TOKEN={}\n",
                                self.wizard_token
                            ));
                        }
                        if !self.wizard_space_id.is_empty() {
                            s.push_str(&format!(
                                "MANTICORE_PEERWEAVE_PUBLISH_ENABLED=true\nMANTICORE_PEERWEAVE_PUBLISH_SPACE_ID={}\n",
                                self.wizard_space_id
                            ));
                        }
                        s
                    }
                    1 => {
                        let mut s = format!(
                            "MANTICORE_EVRUS_ENABLED=true\nMANTICORE_EVRUS_OIDC_URL={}\n",
                            self.wizard_url
                        );
                        if !self.wizard_token.is_empty() {
                            s.push_str(&format!("MANTICORE_EVRUS_JWT={}\n", self.wizard_token));
                        }
                        s
                    }
                    _ => {
                        format!(
                            "MANTICORE_EVENT_STREAM_ENABLED=true\nMANTICORE_EVENT_STREAM_PORT={}\n",
                            self.wizard_url
                        )
                    }
                };
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(16, 22, 30))
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .rounding(egui::Rounding::same(4.0))
                    .show(ui, |ui| {
                        ui.monospace(&env_block);
                    });
                ui.add_space(8.0);
                if ui.button("Copy to Clipboard").clicked() {
                    ui.output_mut(|o| o.copied_text = env_block.clone());
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Restart Sentinel after setting these variables for changes to take effect.")
                        .weak()
                        .italics(),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("← Back").clicked() {
                        self.wizard_step = 1;
                    }
                    if ui.button("Done").clicked() {
                        self.show_connector_wizard = false;
                        self.wizard_step = 0;
                    }
                });
            }
        }
    }

    fn render_connector_row(&self, ui: &mut egui::Ui, health: &crate::connectors::ConnectorHealth) {
        let mono_sm = FontId::new(12.0, FontFamily::Monospace);
        let (badge_fg, badge_bg) = match &health.status {
            crate::connectors::ConnectorStatus::Connecting => (
                egui::Color32::from_rgb(130, 205, 235),
                egui::Color32::from_rgb(24, 38, 50),
            ),
            crate::connectors::ConnectorStatus::Healthy => (
                egui::Color32::from_rgb(100, 200, 130),
                egui::Color32::from_rgb(20, 38, 26),
            ),
            crate::connectors::ConnectorStatus::Degraded(_) => (
                egui::Color32::from_rgb(240, 200, 90),
                egui::Color32::from_rgb(48, 42, 26),
            ),
            crate::connectors::ConnectorStatus::Failed(_) => (
                egui::Color32::from_rgb(235, 110, 100),
                egui::Color32::from_rgb(52, 28, 28),
            ),
        };
        let label_text = health.status.label();
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(" {label_text} "))
                    .color(badge_fg)
                    .background_color(badge_bg)
                    .font(mono_sm.clone())
                    .strong(),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(&health.name)
                    .strong()
                    .font(FontId::new(14.0, FontFamily::Proportional)),
            );
            if let Some(ms) = health.latency_ms {
                ui.label(
                    RichText::new(format!("{ms:.0}ms"))
                        .weak()
                        .font(mono_sm.clone()),
                );
            }
            if let Some(detail) = &health.detail {
                ui.label(
                    RichText::new(detail.as_str())
                        .weak()
                        .font(FontId::new(12.5, FontFamily::Proportional)),
                );
            }
        });
        ui.add_space(4.0);
    }

    fn section_header(
        &mut self,
        ui: &mut egui::Ui,
        section_id: &'static str,
        icon_key: &str,
        icon_svg: &'static [u8],
        title: &str,
    ) -> bool {
        let is_collapsed = self.collapsed_sections.contains(section_id);
        let indicator = if is_collapsed { "▸" } else { "▾" };
        let resp = ui.horizontal(|ui| {
            icons::paint(ui, icon_key, icon_svg, 14.0);
            let btn = ui.add(
                egui::Label::new(
                    RichText::new(format!("{indicator} {title}"))
                        .strong()
                        .color(if ui.ui_contains_pointer() {
                            ui.style().visuals.widgets.hovered.fg_stroke.color
                        } else {
                            ui.visuals().text_color()
                        })
                        .font(FontId::new(14.0, FontFamily::Proportional)),
                )
                .sense(egui::Sense::click()),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
            if btn.hovered() {
                ui.painter().rect_stroke(
                    btn.rect.expand2(egui::vec2(4.0, 2.0)),
                    4.0,
                    Stroke::new(1.0, egui::Color32::from_rgb(96, 176, 210)),
                );
            }
            if btn.clicked() {
                if is_collapsed {
                    self.collapsed_sections.remove(section_id);
                } else {
                    self.collapsed_sections.insert(section_id);
                }
            }
        });

        if let Some(target) = self.scroll_to_section {
            if target == section_id {
                resp.response.scroll_to_me(Some(egui::Align::TOP));
                self.scroll_to_section = None;
            }
        }

        !self.collapsed_sections.contains(section_id)
    }

    fn connector_health_for(&self, name: &str) -> Option<crate::connectors::ConnectorHealth> {
        if let Some(health) = self.connector_summary.health_for(name) {
            return Some(health.clone());
        }
        let passive = self.engine.connector_summary_passive();
        passive.health_for(name).cloned()
    }

    fn render_unified_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let window_samples = self.metric_window_samples_owned();
        self.render_overview_quick_tiles(ui);
        self.render_time_window_selector(ui);
        ui.add_space(8.0);

        // --- Overview section (CPU + Memory) ---
        if self.section_header(
            ui,
            SECTION_OVERVIEW,
            "overview-radar",
            icons::RADAR,
            "Overview",
        ) {
            let mode_label = if self.detailed_mode {
                "Detailed"
            } else {
                "Compact"
            };
            ui.label(
                egui::RichText::new(format!("CPU, memory at a glance ({mode_label} mode).")).weak(),
            );
            ui.add_space(4.0);
            if let Some(snapshot) = &self.latest {
                let sample_refs: Vec<&MetricSample> = window_samples.iter().collect();
                render_overview_metrics(ui, snapshot, &sample_refs, self.detailed_mode);
            } else {
                ui.spinner();
                ui.label("Collecting first snapshot...");
            }
        }
        ui.separator();

        // --- Disk & Network throughput (collapsed by default) ---
        if self.section_header(
            ui,
            SECTION_DISK_NET,
            "panel-disk",
            icons::DISK,
            "Disk & Network Throughput",
        ) {
            if let Some(snapshot) = &self.latest {
                let gap = ui.spacing().item_spacing.x;
                let avail = ui.available_width();
                let half = ((avail - gap) * 0.5).max(0.0);
                if half < 200.0 {
                    ui.group(|ui| {
                        ui.set_min_width(ui.available_width());
                        throughput_panel_heading(
                            ui,
                            "panel-disk-inner",
                            icons::DISK,
                            "Disk throughput",
                            "Per-device read/write rates.",
                        );
                        let sample_refs: Vec<&MetricSample> = window_samples.iter().collect();
                        disk_throughput_rows(ui, snapshot, &sample_refs);
                    });
                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.set_min_width(ui.available_width());
                        throughput_panel_heading(
                            ui,
                            "panel-network-inner",
                            icons::NETWORK,
                            "Network throughput",
                            "Per-interface receive/transmit rates.",
                        );
                        let sample_refs: Vec<&MetricSample> = window_samples.iter().collect();
                        network_throughput_rows(ui, snapshot, &sample_refs);
                    });
                } else {
                    ui.horizontal(|ui| {
                        let col_w = ((ui.available_width() - gap) * 0.5).max(1.0);
                        ui.vertical(|ui| {
                            ui.set_width(col_w);
                            ui.group(|ui| {
                                ui.set_min_width(ui.available_width());
                                throughput_panel_heading(
                                    ui,
                                    "panel-disk-inner",
                                    icons::DISK,
                                    "Disk throughput",
                                    "Per-device read/write rates.",
                                );
                                let sample_refs: Vec<&MetricSample> = window_samples.iter().collect();
                                disk_throughput_rows(ui, snapshot, &sample_refs);
                            });
                        });
                        ui.vertical(|ui| {
                            ui.set_width(col_w);
                            ui.group(|ui| {
                                ui.set_min_width(ui.available_width());
                                throughput_panel_heading(
                                    ui,
                                    "panel-network-inner",
                                    icons::NETWORK,
                                    "Network throughput",
                                    "Per-interface receive/transmit rates.",
                                );
                                let sample_refs: Vec<&MetricSample> = window_samples.iter().collect();
                                network_throughput_rows(ui, snapshot, &sample_refs);
                            });
                        });
                    });
                }
            } else {
                ui.spinner();
                ui.label("Collecting first snapshot...");
            }
        }
        ui.separator();

        // --- Control (operator shell) ---
        if self.section_header(
            ui,
            SECTION_CONTROL,
            "section-command",
            icons::COMMAND,
            "Control",
        ) {
            self.render_control_section(ui, ctx);
        }
        ui.separator();

        // --- Processes (full sortable/filterable table) ---
        if self.section_header(
            ui,
            SECTION_PROCESSES,
            "process-view",
            icons::PROCESS,
            "Processes",
        ) {
            self.render_processes_section(ui);
        }
        ui.separator();

        // --- Audit trail ---
        if self.section_header(
            ui,
            SECTION_AUDIT,
            "audit-section",
            icons::AUDIT,
            "Audit Trail",
        ) {
            self.render_audit_section(ui);
        }
        ui.separator();

        // --- Connectors ---
        if self.section_header(
            ui,
            SECTION_CONNECTORS,
            "connectors-network",
            icons::NETWORK,
            "Ecosystem Connectors",
        ) {
            self.render_connectors_section(ui);
        }
    }

    fn render_overview_quick_tiles(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.latest else {
            return;
        };
        let mem_pct = if snapshot.memory.total == 0 {
            0.0
        } else {
            snapshot.memory.used as f32 / snapshot.memory.total as f32 * 100.0
        };
        let total_disk_bw: u64 = snapshot
            .disks
            .iter()
            .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec))
            .sum();
        let total_net_bw: u64 = snapshot
            .network
            .iter()
            .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec))
            .sum();
        let highest = throughput_severity(total_disk_bw.max(total_net_bw));
        let (sev_fg, sev_bg) = severity_pill_colors(highest);

        ui.horizontal_wrapped(|ui| {
            if render_clickable_tile(ui, "CPU", format!("{:.1}%", snapshot.cpu.usage_percent)) {
                self.detailed_mode = true;
                self.collapsed_sections.remove(SECTION_OVERVIEW);
                self.scroll_to_section = Some(SECTION_OVERVIEW);
            }
            if render_clickable_tile(ui, "MEM", format!("{:.0}%", mem_pct)) {
                self.detailed_mode = true;
                self.collapsed_sections.remove(SECTION_OVERVIEW);
                self.scroll_to_section = Some(SECTION_OVERVIEW);
            }
            if render_clickable_tile(ui, "DISK BW", format!("{}/s", human_bytes(total_disk_bw))) {
                self.collapsed_sections.remove(SECTION_DISK_NET);
                self.scroll_to_section = Some(SECTION_DISK_NET);
            }
            if render_clickable_tile(ui, "NET BW", format!("{}/s", human_bytes(total_net_bw))) {
                self.collapsed_sections.remove(SECTION_DISK_NET);
                self.scroll_to_section = Some(SECTION_DISK_NET);
            }
            if self.snapshot_history_enabled {
                render_quick_tile(
                    ui,
                    "HIST 1H",
                    format!("{}", self.snapshot_history_recent_hour),
                );
            }
            if render_clickable_tile(ui, "ALERTS", format!("{}", self.latest_alerts.len())) {
                self.collapsed_sections.remove(SECTION_AUDIT);
                self.scroll_to_section = Some(SECTION_AUDIT);
            }
            ui.label(
                RichText::new(format!(" {} ", highest.label()))
                    .color(sev_fg)
                    .background_color(sev_bg)
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .strong(),
            )
            .on_hover_text("Highest throughput severity across disk/network.");
            if let Some(alert) = self.latest_alerts.first() {
                let tag = match alert.severity {
                    AlertSeverity::Info => "INFO",
                    AlertSeverity::Warning => "WARN",
                    AlertSeverity::Critical => "CRIT",
                };
                let color = match alert.severity {
                    AlertSeverity::Info => egui::Color32::from_rgb(86, 145, 181),
                    AlertSeverity::Warning => egui::Color32::from_rgb(196, 158, 66),
                    AlertSeverity::Critical => egui::Color32::from_rgb(180, 66, 66),
                };
                ui.colored_label(
                    color,
                    format!(
                        "{}: {} ({} {:.2} / {:.2})",
                        tag, alert.rule_id, alert.message, alert.value, alert.threshold
                    ),
                );
            }
            if self.self_collect_cycles < 2 {
                ui.label(
                    RichText::new("Collector warmup: first-sample deltas may read as 0.")
                        .italics()
                        .weak(),
                );
            }
        });
    }

    fn render_processes_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label("Sort");
            ui.selectable_value(&mut self.process_sort, ProcessSort::CpuDesc, "CPU")
                .on_hover_text("Highest CPU first.");
            ui.selectable_value(&mut self.process_sort, ProcessSort::RssDesc, "RSS")
                .on_hover_text("Largest memory footprint first.");
            ui.selectable_value(&mut self.process_sort, ProcessSort::PidAsc, "PID")
                .on_hover_text("PID ascending.");
            ui.selectable_value(&mut self.process_sort, ProcessSort::ThreadsDesc, "Threads")
                .on_hover_text("Most threads first.");
            ui.separator();
            ui.label("Filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.process_filter)
                    .desired_width(180.0)
                    .hint_text("name or PID..."),
            );
        });
        ui.separator();
        let Some(snapshot) = &self.latest else {
            ui.spinner();
            ui.label("Collecting first snapshot...");
            return;
        };
        let mut rows: Vec<ProcessMetrics> = snapshot.processes.clone();
        if !self.process_filter.is_empty() {
            let q = self.process_filter.to_ascii_lowercase();
            rows.retain(|p| {
                p.name.to_ascii_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
                    || p.cmdline.to_ascii_lowercase().contains(&q)
            });
        }
        match self.process_sort {
            ProcessSort::CpuDesc => rows.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
            ProcessSort::RssDesc => rows.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
            ProcessSort::PidAsc => rows.sort_by(|a, b| a.pid.cmp(&b.pid)),
            ProcessSort::ThreadsDesc => rows.sort_by(|a, b| b.threads.cmp(&a.threads)),
        }
        let mut cpu_ranked = rows.clone();
        cpu_ranked.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
        let mut rss_ranked = rows.clone();
        rss_ranked.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
        let top_cpu: Vec<(String, f64)> = cpu_ranked
            .iter()
            .take(8)
            .map(|p| (format!("{} ({})", p.name, p.pid), p.cpu_percent as f64))
            .collect();
        let top_rss: Vec<(String, f64)> = rss_ranked
            .iter()
            .take(8)
            .map(|p| (format!("{} ({})", p.name, p.pid), p.memory_bytes as f64))
            .collect();
        ui.group(|ui| {
            ui.label(RichText::new("Process analytics").strong());
            let gap = ui.spacing().item_spacing.x;
            let avail = ui.available_width();
            let split = (avail - gap) * 0.5;
            if split >= 260.0 {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(split);
                        render_horizontal_bar_chart(
                            ui,
                            "Top CPU processes",
                            &top_cpu,
                            egui::Color32::from_rgb(96, 176, 210),
                            |v| format!("{v:.1}%"),
                        );
                    });
                    ui.vertical(|ui| {
                        ui.set_width(split);
                        render_horizontal_bar_chart(
                            ui,
                            "Top RSS processes",
                            &top_rss,
                            egui::Color32::from_rgb(196, 158, 66),
                            |v| human_bytes(v as u64),
                        );
                    });
                });
            } else {
                render_horizontal_bar_chart(
                    ui,
                    "Top CPU processes",
                    &top_cpu,
                    egui::Color32::from_rgb(96, 176, 210),
                    |v| format!("{v:.1}%"),
                );
                ui.add_space(6.0);
                render_horizontal_bar_chart(
                    ui,
                    "Top RSS processes",
                    &top_rss,
                    egui::Color32::from_rgb(196, 158, 66),
                    |v| human_bytes(v as u64),
                );
            }
            let min_ts = now_unix_secs().saturating_sub(self.time_window.seconds());
            let churn_points: Vec<(u64, f64)> = self
                .process_churn_history
                .iter()
                .filter(|(ts, _, _)| *ts >= min_ts)
                .map(|(ts, started, exited)| (*ts, started.saturating_add(*exited) as f64))
                .collect();
            render_line_chart(
                ui,
                "Process churn rate",
                &churn_points,
                egui::Color32::from_rgb(220, 176, 64),
                110.0,
                |v| format!("{v:.0}/tick"),
            );
            let proc_density: Vec<f64> = rows.iter().map(|p| p.cpu_percent as f64).collect();
            render_distribution_bins(ui, "CPU-share distribution", &proc_density, 8);
        });
        ui.label(
            RichText::new(format!("{} tracked processes shown", rows.len()))
                .weak()
                .font(FontId::new(11.5, FontFamily::Proportional)),
        );
        let expanded = self.expanded_process_pid;
        let mut new_expanded = expanded;
        process_metrics_table_full(
            ui,
            &rows,
            expanded,
            &mut new_expanded,
            "main_process_table_scroll",
        );
        self.expanded_process_pid = new_expanded;
    }

    fn render_audit_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let lbl = ui.label("Filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.audit_filter)
                    .hint_text("action/target/actor/result")
                    .desired_width(280.0),
            )
            .labelled_by(lbl.id)
            .on_hover_text("Filter loaded audit events by text (case-insensitive).");
            ui.separator();
            ui.label("Page size");
            for sz in [25, 50, 100] {
                if ui
                    .selectable_label(self.audit_page_size == sz, sz.to_string())
                    .clicked()
                {
                    self.audit_page_size = sz;
                    self.audit_page = 0;
                }
            }
        });

        let current_merkle = current_merkle_root(&self.helper.audit_path).ok().flatten();
        let anchored_current_window =
            current_merkle.as_deref() == self.anchor_state.last_anchor_merkle_root.as_deref();

        egui::CollapsingHeader::new(RichText::new("Anchor & Merkle status").strong())
            .id_source("audit-anchor-status")
            .default_open(false)
            .show(ui, |ui| {
                ui.label(format!(
                    "Anchored window: {}",
                    if anchored_current_window { "yes" } else { "no" }
                ));
                ui.label(format!(
                    "Last anchor txid: {}",
                    self.anchor_state
                        .last_anchor_txid
                        .as_deref()
                        .unwrap_or("none")
                ));
                ui.label(format!(
                    "Last anchor blockheight: {}",
                    self.anchor_state
                        .last_anchor_blockheight
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ));
                ui.label(format!(
                    "Last anchor timestamp: {}",
                    self.anchor_state
                        .last_anchor_ts
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ));
                if let Some(root) = current_merkle {
                    ui.monospace(format!("Current Merkle root: {root}"));
                }
            });
        ui.separator();

        let fetch_size = (self.audit_page + 1) * self.audit_page_size + self.audit_page_size;
        if self.last_audit_refresh.elapsed() >= Duration::from_secs(2) {
            self.audit_feed = read_recent(&self.helper.audit_path, fetch_size).unwrap_or_default();
            self.last_audit_refresh = Instant::now();
        }
        if self.audit_feed.is_empty() {
            ui.label("No audit events yet.");
            return;
        }
        ui.group(|ui| {
            ui.label(RichText::new("Audit analytics").strong());
            let min_ts = now_unix_secs().saturating_sub(self.time_window.seconds());
            let mut by_action: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            let mut hour_bins = [0usize; 24];
            let mut timeline = Vec::new();
            for event in self.audit_feed.iter().filter(|e| e.ts >= min_ts).take(480) {
                *by_action.entry(event.action.clone()).or_insert(0) += 1;
                let hour = ((event.ts / 3600) % 24) as usize;
                hour_bins[hour] += 1;
                timeline.push((
                    event.ts,
                    if event.result.to_ascii_lowercase().contains("denied") {
                        1.0
                    } else {
                        0.0
                    },
                ));
            }
            let mut bars: Vec<(String, f64)> =
                by_action.iter().map(|(k, v)| (k.clone(), *v as f64)).collect();
            bars.sort_by(|a, b| b.1.total_cmp(&a.1));
            bars.truncate(10);
            render_horizontal_bar_chart(
                ui,
                "Top actions by count",
                &bars,
                egui::Color32::from_rgb(130, 205, 235),
                |v| format!("{v:.0}"),
            );
            let allow_deny_points: Vec<(u64, f64)> = self
                .audit_rate_history
                .iter()
                .filter(|(ts, _, _)| *ts >= now_unix_secs().saturating_sub(self.time_window.seconds()))
                .map(|(ts, allow, deny)| {
                    (
                        *ts,
                        if allow + deny == 0 {
                            0.0
                        } else {
                            (*deny as f64 / (*allow + *deny) as f64) * 100.0
                        },
                    )
                })
                .collect();
            render_line_chart(
                ui,
                "Denied-event ratio trend",
                &allow_deny_points,
                egui::Color32::from_rgb(235, 110, 100),
                100.0,
                |v| format!("{v:.0}%"),
            );
            render_hour_heatmap(ui, "Audit activity heatmap", &hour_bins);
            render_timeline(ui, "Audit timeline", &timeline, 70.0);
        });

        let filter = self.audit_filter.trim().to_ascii_lowercase();
        let filtered: Vec<&AuditEvent> = self
            .audit_feed
            .iter()
            .filter(|event| {
                if filter.is_empty() {
                    return true;
                }
                let haystack = format!(
                    "{} {} {} {} {}",
                    event.action, event.target, event.result, event.actor, event.ts
                )
                .to_ascii_lowercase();
                haystack.contains(&filter)
            })
            .collect();

        let total = filtered.len();
        if total == 0 {
            self.audit_page = 0;
            self.expanded_audit_idx = None;
            ui.label(RichText::new("No audit events match current filters/window.").weak());
            return;
        }
        let total_pages = (total + self.audit_page_size - 1) / self.audit_page_size.max(1);
        self.audit_page = self.audit_page.min(total_pages.saturating_sub(1));
        let start = self.audit_page * self.audit_page_size;
        let end = (start + self.audit_page_size).min(total);

        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.audit_page > 0, egui::Button::new("◀ Prev"))
                .clicked()
            {
                self.audit_page = self.audit_page.saturating_sub(1);
                self.expanded_audit_idx = None;
            }
            ui.label(format!(
                "Page {} of {} ({} events)",
                self.audit_page + 1,
                total_pages.max(1),
                total
            ));
            if ui
                .add_enabled(
                    self.audit_page + 1 < total_pages,
                    egui::Button::new("Next ▶"),
                )
                .clicked()
            {
                self.audit_page += 1;
                self.expanded_audit_idx = None;
            }
        });
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_source("audit_events_scroll_unified")
            .max_height(280.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (view_idx, event) in filtered[start..end].iter().enumerate() {
                    let abs_idx = start + view_idx;
                    let is_expanded = self.expanded_audit_idx == Some(abs_idx);
                    let indicator = if is_expanded { "▾" } else { "▸" };
                    let row_text = format!(
                        "{} [{}] {} → {} ({})",
                        indicator, event.ts, event.action, event.target, event.result
                    );
                    let resp = ui.add(
                        egui::Label::new(
                            RichText::new(row_text)
                                .font(FontId::new(12.0, FontFamily::Monospace))
                                .color(if is_expanded {
                                    egui::Color32::from_rgb(130, 205, 235)
                                } else {
                                    ui.visuals().text_color()
                                }),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        self.expanded_audit_idx = if is_expanded { None } else { Some(abs_idx) };
                    }
                    if is_expanded {
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(16, 22, 30))
                            .inner_margin(egui::Margin::symmetric(12.0, 6.0))
                            .rounding(egui::Rounding::same(4.0))
                            .show(ui, |ui| {
                                ui.monospace(format!("timestamp:  {}", event.ts));
                                ui.monospace(format!("action:     {}", event.action));
                                ui.monospace(format!("target:     {}", event.target));
                                ui.monospace(format!("result:     {}", event.result));
                                ui.monospace(format!("actor:      {}", event.actor));
                                ui.monospace(format!(
                                    "signature:  {}",
                                    event.sig.as_deref().unwrap_or("-")
                                ));
                                ui.monospace(format!(
                                    "policy:     {}",
                                    event.policy_hash.as_deref().unwrap_or("-")
                                ));
                                ui.monospace(format!(
                                    "anchor_tx:  {}",
                                    event.anchor_txid.as_deref().unwrap_or("-")
                                ));
                                ui.monospace(format!(
                                    "anchor_bh:  {}",
                                    event
                                        .anchor_blockheight
                                        .map(|v| v.to_string())
                                        .unwrap_or_else(|| "-".to_string())
                                ));
                                ui.monospace(format!(
                                    "merkle_root: {}",
                                    event.anchor_merkle_root.as_deref().unwrap_or("-")
                                ));
                                if ui.small_button("Copy JSON").clicked() {
                                    if let Ok(json) = serde_json::to_string_pretty(event) {
                                        ui.output_mut(|o| o.copied_text = json);
                                    }
                                }
                            });
                    }
                }
            });
    }

    fn render_connectors_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("PeerWeave and EVRUS integration status.").weak());
            if ui
                .small_button("Setup Wizard")
                .on_hover_text("Open guided connector setup")
                .clicked()
            {
                self.show_connector_wizard = true;
                self.wizard_step = 0;
            }
        });
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(RichText::new("Connector analytics").strong());
            let min_ts = now_unix_secs().saturating_sub(self.time_window.seconds());
            let peer_points: Vec<(u64, f64)> = self
                .connector_latency_history
                .iter()
                .filter(|(ts, _, _)| *ts >= min_ts)
                .filter_map(|(ts, pw, _)| pw.map(|v| (*ts, v)))
                .collect();
            let evrus_points: Vec<(u64, f64)> = self
                .connector_latency_history
                .iter()
                .filter(|(ts, _, _)| *ts >= min_ts)
                .filter_map(|(ts, _, ev)| ev.map(|v| (*ts, v)))
                .collect();
            render_line_chart(
                ui,
                "PeerWeave latency",
                &peer_points,
                egui::Color32::from_rgb(96, 176, 210),
                90.0,
                |v| format!("{v:.0}ms"),
            );
            render_line_chart(
                ui,
                "EVRUS latency",
                &evrus_points,
                egui::Color32::from_rgb(196, 158, 66),
                90.0,
                |v| format!("{v:.0}ms"),
            );
        });

        if self.connector_summary.entries.is_empty() {
            let passive = self.engine.connector_summary_passive();
            if passive.entries.is_empty() {
                ui.label("No connectors configured.");
                ui.monospace(
                    "Set MANTICORE_PEERWEAVE_ENABLED=true or MANTICORE_EVRUS_ENABLED=true to enable integrations.",
                );
            } else {
                for entry in &passive.entries {
                    self.render_connector_row(ui, entry);
                }
            }
        } else {
            for entry in &self.connector_summary.entries {
                self.render_connector_row(ui, entry);
            }
        }

        // PeerWeave detail (nested collapsible)
        if self.connector_health_for("PeerWeave").is_some() {
            egui::CollapsingHeader::new(RichText::new("PeerWeave detail").strong())
                .id_source("peerweave-detail")
                .default_open(false)
                .show(ui, |ui| {
                    if let Some(snapshot) = self.connector_summary.snapshot_for("PeerWeave") {
                        let payload = snapshot.data.get("data").unwrap_or(&snapshot.data);
                        let stats = payload.get("stats").cloned().unwrap_or_default();
                        let graph_nodes = stats.get("nodeCount").and_then(|v| v.as_u64()).unwrap_or(0);
                        let graph_edges = stats.get("edgeCount").and_then(|v| v.as_u64()).unwrap_or(0);
                        ui.label(
                            RichText::new(format!(
                                "Graph nodes: {}  |  Graph edges: {}",
                                graph_nodes, graph_edges
                            ))
                            .strong(),
                        );
                        render_topology_map(ui, 0, graph_nodes, graph_edges);
                        if let Some(nodes) = payload.get("allNodes").and_then(|v| v.as_array()) {
                            ui.label(RichText::new("Recent graph sample").strong());
                            for node in nodes.iter().take(8) {
                                let label = node.get("label").and_then(|v| v.as_str()).unwrap_or("unnamed");
                                let kind = node.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown");
                                ui.label(format!("{label} · {kind}"));
                            }
                        }
                    } else {
                        ui.label("Waiting for PeerWeave GraphQL data...");
                    }
                });
        }

        // EVRUS detail (nested collapsible)
        if self.connector_health_for("EVRUS").is_some() {
            egui::CollapsingHeader::new(RichText::new("EVRUS detail").strong())
                .id_source("evrus-detail")
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(format!("Auth mode: {}", self.auth_mode_label));
                    ui.label(format!("Role: {}", self.role_label));
                    if let Some(lifecycle) = self.token_lifecycle {
                        let now = now_unix_secs();
                        let expiry = lifecycle.issued_at.saturating_add(lifecycle.ttl_secs);
                        let remaining = expiry.saturating_sub(now);
                        ui.label(format!("Token expiry countdown: {}s", remaining));
                    } else {
                        ui.label("Token expiry countdown: n/a");
                    }
                    if let Some(jwt) = self.evrus_jwt.as_deref() {
                        if let Some(identity) = parse_identity_from_jwt(jwt) {
                            ui.label(format!(
                                "Operator DID: {}",
                                identity.did.unwrap_or_else(|| "unknown".into())
                            ));
                            ui.label(format!(
                                "Display name: {}",
                                identity.display_name.unwrap_or_else(|| "unknown".into())
                            ));
                            if let Some(exp) = identity.exp {
                                let remaining = exp.saturating_sub(now_unix_secs());
                                ui.label(format!("JWT exp countdown: {}s", remaining));
                            }
                        } else {
                            ui.label("Operator identity: JWT configured, claims unavailable");
                        }
                    } else {
                        ui.label("Operator identity: no EVRUS JWT configured");
                    }

                    let anchor_enabled = self
                        .connector_summary
                        .snapshot_for("EVRUS")
                        .and_then(|s| s.data.get("anchor_enabled"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let health = self.connector_health_for("EVRUS");
                    ui.label(format!(
                        "Vault connection: {}",
                        if health.as_ref().map_or(false, |h| matches!(
                            h.status,
                            crate::connectors::ConnectorStatus::Healthy
                        )) {
                            "healthy"
                        } else {
                            "degraded"
                        }
                    ));
                    ui.label(format!(
                        "Evrmore chain height: {}",
                        if let Some(height) = self.anchor_state.last_anchor_blockheight {
                            height.to_string()
                        } else if anchor_enabled {
                            "awaiting first anchor".to_string()
                        } else {
                            "anchoring disabled".to_string()
                        }
                    ));
                    ui.label(format!(
                        "Last audit anchor: {}",
                        self.anchor_state
                            .last_anchor_txid
                            .as_deref()
                            .unwrap_or("none")
                    ));
                });
        }

        ui.separator();
        ui.label(RichText::new("Self-health telemetry").strong());
        ui.monospace(format!(
            "collect_last_ms={:.3} collect_avg_ms={:.3} cycles={} connector_polls={}",
            self.self_collect_last_ms,
            self.self_collect_avg_ms,
            self.self_collect_cycles,
            self.self_connector_polls
        ));
        ui.monospace(format!(
            "alerts_active={} errors_total={} last_error_ts={}",
            self.latest_alerts.len(),
            self.self_errors_total,
            self.self_last_error_ts
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));

        ui.separator();
        ui.label(RichText::new("Storage health").strong());
        let cwd = std::env::current_dir().unwrap_or_default();
        let audit_path = default_audit_path(&cwd);
        let snapshot_path = &self.snapshot_history_path;

        let audit_size = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
        let audit_entries = audit_entry_count(&audit_path);
        let snapshot_size = std::fs::metadata(snapshot_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let (archive_count, archive_bytes) = audit_archive_stats(&audit_path);

        ui.monospace(format!(
            "audit: {} entries, {} (max: {}, archive: {})",
            audit_entries,
            format_bytes(audit_size),
            self.audit_retention.max_entries,
            if self.audit_retention.archive_enabled {
                "on"
            } else {
                "off"
            }
        ));
        if archive_count > 0 {
            ui.monospace(format!(
                "audit archives: {} files, {}",
                archive_count,
                format_bytes(archive_bytes)
            ));
        }
        ui.monospace(format!(
            "snapshots: {} (max: {})",
            format_bytes(snapshot_size),
            self.snapshot_history_max_entries
        ));
    }

    fn fill_vertical_remainder(&self, ui: &mut egui::Ui) {
        let h = ui.available_height();
        if h > 1.0 {
            ui.allocate_space(egui::vec2(ui.available_width(), h));
        }
    }
}

impl eframe::App for SentinelDashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.visuals_applied {
            install_image_loaders(ctx);
            apply_security_visuals(ctx);
            self.visuals_applied = true;
        }
        suppress_debug_overlays(ctx);
        self.poll();
        self.handle_global_shortcuts(ctx);
        ctx.request_repaint_after(self.ui_repaint_interval);

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                icons::paint(ui, "mark", icons::MARK, 20.0);
                ui.label(
                    RichText::new("Manticore Sentinel")
                        .strong()
                        .font(FontId::new(16.0, FontFamily::Proportional)),
                );
                ui.separator();
                self.quick_status_chips(ui);
            });
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Mode: OPERATOR  ·  Trust: {}  ·  Auth: {}  ·  Audit: APPEND-ONLY",
                        self.trust_badge_text(),
                        self.auth_mode_label
                    ))
                    .weak()
                    .font(FontId::new(11.5, FontFamily::Proportional)),
                );
            });
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .small_button("Security Guide")
                    .on_hover_text("Security posture and destructive-action guidance")
                    .clicked()
                {
                    self.show_onboarding = true;
                }
                if ui
                    .small_button("Help Center")
                    .on_hover_text("In-app navigation and command help (F1)")
                    .clicked()
                {
                    self.show_help_center = true;
                }
                ui.separator();
                if ui
                    .small_button("Glossary")
                    .on_hover_text("Technical terms glossary")
                    .clicked()
                {
                    self.show_glossary = true;
                }
            });
            ui.add_space(3.0);
        });

        if !self.config_warnings.is_empty() && !self.config_warnings_dismissed {
            egui::TopBottomPanel::top("config_warnings_banner").show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("⚠ Configuration warnings:")
                            .strong()
                            .color(egui::Color32::from_rgb(255, 180, 50)),
                    );
                    for w in &self.config_warnings {
                        ui.label(
                            RichText::new(format!("[{}] {}", w.area, w.message))
                                .color(egui::Color32::from_rgb(255, 200, 100)),
                        );
                    }
                    if ui.small_button("Dismiss").clicked() {
                        self.config_warnings_dismissed = true;
                    }
                });
            });
        }

        if self.show_onboarding {
            egui::Window::new("Operator Security Guide")
                .collapsible(false)
                .resizable(true)
                .default_size(egui::vec2(480.0, 420.0))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_source("onboarding_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label("Navigation");
                            ui.monospace("- One scrollable dashboard: metrics, command palette, processes, audit.");
                            ui.monospace("- Operator shell: Tab complete, ↑↓ history, Enter run, Ctrl/⌘+K focus.");
                            ui.monospace("- Top bar shows live CPU/Mem/load plus trust and auth posture.");
                            ui.separator();
                            ui.label("Trust Modes");
                            ui.monospace("- UNPRIVILEGED: read-only posture, privileged actions denied.");
                            ui.monospace("- PRIVILEGED: capability-gated kill/renice via helper boundary.");
                            ui.separator();
                            ui.label("Destructive Action Flow");
                            ui.monospace("1) Parse and validate command.");
                            ui.monospace("2) Enforce policy checks (privilege + cooldown).");
                            ui.monospace("3) Require typed confirmation for kill actions.");
                            ui.monospace("4) Execute via helper socket, not shell.");
                            ui.separator();
                            ui.label("Audit Semantics");
                            ui.monospace("- Every helper action is written to append-only JSONL.");
                            ui.monospace("- Event fields include action, target, result, actor, timestamp.");
                            ui.separator();
                            let ack = ui.button("Acknowledge");
                            ack.widget_info(|| {
                                egui::WidgetInfo::labeled(egui::WidgetType::Button, "Acknowledge security guide")
                            });
                            if ack.clicked() {
                                self.show_onboarding = false;
                            }
                        });
                });
        }
        if self.show_help_center {
            egui::Window::new("Help Center")
                .collapsible(true)
                .resizable(true)
                .default_size(egui::vec2(560.0, 460.0))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_source("help_center_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.heading("Quick Start");
                            ui.monospace("1) One unified scrollable view with collapsible sections.");
                            ui.monospace("2) Click quick tiles (CPU/MEM/DISK/NET/ALERTS) to jump to detail.");
                            ui.monospace("3) Click section headers to expand/collapse.");
                            ui.monospace("4) Operator shell (Ctrl/⌘+K): Tab, history, Enter — no raw shell.");
                            ui.monospace("5) Processes, Audit, and Connectors are below the main overview.");
                            ui.separator();
                            ui.heading("Command Examples");
                            ui.monospace("show cpu");
                            ui.monospace("renice 5 1234");
                            ui.monospace("kill 1234  (requires confirmation and policy permission)");
                            ui.separator();
                            ui.heading("Safety Model");
                            ui.monospace("- Policy gate checks role permissions before execution.");
                            ui.monospace("- Token mode requires valid token, expiry window, and lockout rules.");
                            ui.monospace("- Destructive actions are routed through helper boundary.");
                            ui.monospace("- All accepts/denials are append-only audited.");
                            ui.separator();
                            ui.heading("Troubleshooting");
                            ui.monospace("- DENIED policy: adjust role/mode or command type.");
                            ui.monospace("- Auth failed: verify token and lockout countdown.");
                            ui.monospace("- Collector error: verify runtime permissions/profile.");
                            ui.separator();
                            ui.heading("Keyboard");
                            ui.monospace("F1 or ? — open this Help Center");
                            ui.monospace("Ctrl/⌘+K — focus shell input");
                            ui.monospace("Tab — complete first matching command · ↑↓ — history · Enter — run");
                            ui.monospace("Esc — close Help/Guide or cancel pending kill");
                            let close = ui
                                .button("Close Help")
                                .on_hover_text("Close help window (Esc).");
                            close.widget_info(|| {
                                egui::WidgetInfo::labeled(egui::WidgetType::Button, "Close help")
                            });
                            if close.clicked() {
                                self.show_help_center = false;
                            }
                        });
                });
        }

        if self.show_glossary {
            egui::Window::new("Glossary of Technical Terms")
                .collapsible(true)
                .resizable(true)
                .default_size(egui::vec2(520.0, 480.0))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_source("glossary_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for (term, def) in GLOSSARY_ENTRIES {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(*term)
                                            .strong()
                                            .color(egui::Color32::from_rgb(130, 205, 235)),
                                    );
                                    ui.label(*def);
                                });
                                ui.add_space(2.0);
                            }
                            ui.separator();
                            if ui.button("Close").clicked() {
                                self.show_glossary = false;
                            }
                        });
                });
        }

        if self.show_connector_wizard {
            egui::Window::new("Connector Setup Wizard")
                .collapsible(false)
                .resizable(true)
                .default_size(egui::vec2(520.0, 420.0))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_source("wizard_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            self.render_connector_wizard(ui);
                        });
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            let central_fill_h = ui.available_height().max(1.0);
            let central_fill_w = ui.available_width().max(1.0);
            egui::ScrollArea::vertical()
                .id_source("central_main_scroll")
                .max_height(central_fill_h)
                .max_width(central_fill_w)
                .auto_shrink([false, false])
                .min_scrolled_height(central_fill_h)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());

                    if let Some(err) = &self.last_error {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("Collector error: {err}"))
                                    .color(egui::Color32::from_rgb(220, 76, 70)),
                            )
                            .wrap(true),
                        );
                        ui.separator();
                    }

                    self.render_unified_view(ui, ctx);
                    self.fill_vertical_remainder(ui);
                });
        });
    }
}

fn disk_throughput_rows(ui: &mut egui::Ui, snapshot: &SystemSnapshot, samples: &[&MetricSample]) {
    if snapshot.disks.is_empty() {
        ui.label(
            egui::RichText::new("No disk devices in this snapshot.")
                .weak()
                .italics(),
        );
        return;
    }
    let mut rows: Vec<_> = snapshot.disks.iter().collect();
    rows.sort_by_key(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec));
    rows.reverse();
    let total_rw: u64 = rows
        .iter()
        .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec))
        .sum();
    ui.label(
        egui::RichText::new(format!(
            "All devices by R+W throughput ({} combined) — {} devices.",
            human_bytes(total_rw),
            rows.len()
        ))
        .weak()
        .font(FontId::new(12.0, FontFamily::Proportional)),
    );
    ui.add_space(4.0);
    let disk_points: Vec<(u64, f64)> = samples.iter().map(|s| (s.ts, s.disk_bps)).collect();
    render_line_chart(
        ui,
        "Disk throughput trend",
        &disk_points,
        egui::Color32::from_rgb(130, 205, 235),
        90.0,
        |v| format!("{}/s", human_bytes(v as u64)),
    );
    let disk_totals: Vec<(String, f64)> = rows
        .iter()
        .map(|d| {
            (
                d.device.clone(),
                d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec) as f64,
            )
        })
        .collect();
    render_horizontal_bar_chart(
        ui,
        "Disk throughput bars",
        &disk_totals,
        egui::Color32::from_rgb(86, 145, 181),
        |v| format!("{}/s", human_bytes(v as u64)),
    );
    for disk in &rows {
        let total = disk
            .read_bytes_per_sec
            .saturating_add(disk.write_bytes_per_sec);
        let sev = throughput_severity(total);
        let (sev_color, _) = severity_pill_colors(sev);
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "{} R:{} W:{}",
                disk.device,
                human_bytes(disk.read_bytes_per_sec),
                human_bytes(disk.write_bytes_per_sec)
            ))
            .color(sev_color),
        )
        .id_source(format!("disk-{}", disk.device))
        .default_open(false)
        .show(ui, |ui| {
            ui.monospace(format!("device: {}", disk.device));
            ui.monospace(format!("read:  {}/s", human_bytes(disk.read_bytes_per_sec)));
            ui.monospace(format!(
                "write: {}/s",
                human_bytes(disk.write_bytes_per_sec)
            ));
            ui.monospace(format!("total: {}/s", human_bytes(total)));
        });
    }
}

fn network_throughput_rows(ui: &mut egui::Ui, snapshot: &SystemSnapshot, samples: &[&MetricSample]) {
    if snapshot.network.is_empty() {
        ui.label(
            egui::RichText::new("No network interfaces in this snapshot.")
                .weak()
                .italics(),
        );
        return;
    }
    let mut rows: Vec<_> = snapshot.network.iter().collect();
    rows.sort_by_key(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec));
    rows.reverse();
    let total_io: u64 = rows
        .iter()
        .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec))
        .sum();
    ui.label(
        egui::RichText::new(format!(
            "All interfaces by RX+TX ({} combined) — {} interfaces.",
            human_bytes(total_io),
            rows.len()
        ))
        .weak()
        .font(FontId::new(12.0, FontFamily::Proportional)),
    );
    ui.add_space(4.0);
    let net_points: Vec<(u64, f64)> = samples.iter().map(|s| (s.ts, s.net_bps)).collect();
    render_line_chart(
        ui,
        "Network throughput trend",
        &net_points,
        egui::Color32::from_rgb(220, 176, 64),
        90.0,
        |v| format!("{}/s", human_bytes(v as u64)),
    );
    let net_totals: Vec<(String, f64)> = rows
        .iter()
        .map(|n| {
            (
                n.interface.clone(),
                n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec) as f64,
            )
        })
        .collect();
    render_horizontal_bar_chart(
        ui,
        "Network throughput bars",
        &net_totals,
        egui::Color32::from_rgb(196, 158, 66),
        |v| format!("{}/s", human_bytes(v as u64)),
    );
    for net in &rows {
        let total = net.rx_bytes_per_sec.saturating_add(net.tx_bytes_per_sec);
        let sev = throughput_severity(total);
        let (sev_color, _) = severity_pill_colors(sev);
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "{} RX:{} TX:{}",
                net.interface,
                human_bytes(net.rx_bytes_per_sec),
                human_bytes(net.tx_bytes_per_sec)
            ))
            .color(sev_color),
        )
        .id_source(format!("net-{}", net.interface))
        .default_open(false)
        .show(ui, |ui| {
            ui.monospace(format!("interface: {}", net.interface));
            ui.monospace(format!("rx: {}/s", human_bytes(net.rx_bytes_per_sec)));
            ui.monospace(format!("tx: {}/s", human_bytes(net.tx_bytes_per_sec)));
            ui.monospace(format!("total: {}/s", human_bytes(total)));
        });
    }
}

/// Full-width process table: fixed numeric columns, name column absorbs remaining width.
fn process_metrics_table_full(
    ui: &mut egui::Ui,
    processes: &[ProcessMetrics],
    expanded_pid: Option<u32>,
    new_expanded: &mut Option<u32>,
    scroll_id: &'static str,
) {
    const BASE_PID_W: f32 = 80.0;
    const BASE_CPU_W: f32 = 74.0;
    const BASE_RSS_W: f32 = 100.0;
    const BASE_THR_W: f32 = 70.0;

    let full = ui.available_width();
    ui.set_min_width(full);
    let sp = ui.spacing().item_spacing.x;
    let base_fixed = BASE_PID_W + BASE_CPU_W + BASE_RSS_W + BASE_THR_W + sp * 4.0;
    let min_name = 96.0;
    let total_needed = base_fixed + min_name;
    let scale = if full < total_needed {
        (full / total_needed).clamp(0.7, 1.0)
    } else {
        1.0
    };
    let pid_w = BASE_PID_W * scale;
    let cpu_w = BASE_CPU_W * scale;
    let rss_w = BASE_RSS_W * scale;
    let thr_w = BASE_THR_W * scale;
    let fixed = pid_w + cpu_w + rss_w + thr_w + sp * 4.0;
    let name_w = (full - fixed).max(min_name * scale);

    ui.horizontal(|ui| {
        ui.add_sized(
            [pid_w, 20.0],
            egui::Label::new(egui::RichText::new("PID").strong()),
        )
        .on_hover_text("Process ID");
        ui.add_sized(
            [name_w, 20.0],
            egui::Label::new(egui::RichText::new("Name").strong()).wrap(true),
        )
        .on_hover_text("Executable or command name — click row for details");
        ui.add_sized(
            [cpu_w, 20.0],
            egui::Label::new(egui::RichText::new("CPU %").strong()),
        )
        .on_hover_text("Process share of total host CPU time since previous sample.");
        ui.add_sized(
            [rss_w, 20.0],
            egui::Label::new(egui::RichText::new("RSS").strong()),
        )
        .on_hover_text("Resident set size (physical memory)");
        ui.add_sized(
            [thr_w, 20.0],
            egui::Label::new(egui::RichText::new("Threads").strong()),
        )
        .on_hover_text("Thread count");
    });
    ui.separator();

    const PROCESS_TABLE_VIEWPORT_H: f32 = 640.0;
    egui::ScrollArea::vertical()
        .id_source(scroll_id)
        .max_height(PROCESS_TABLE_VIEWPORT_H)
        .min_scrolled_height(PROCESS_TABLE_VIEWPORT_H)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for process in processes {
                let is_expanded = expanded_pid == Some(process.pid);
                let row_resp = ui
                    .horizontal_top(|ui| {
                        ui.add_sized(
                            [pid_w, 20.0],
                            egui::Label::new(process.pid.to_string()).wrap(false),
                        );
                        ui.vertical(|ui| {
                            ui.set_width(name_w);
                            let indicator = if is_expanded { "▾ " } else { "▸ " };
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!("{}{}", indicator, process.name))
                                        .color(if is_expanded {
                                            egui::Color32::from_rgb(130, 205, 235)
                                        } else {
                                            ui.visuals().text_color()
                                        }),
                                )
                                .wrap(true)
                                .sense(egui::Sense::click()),
                            );
                        });
                        ui.add_sized(
                            [cpu_w, 20.0],
                            egui::Label::new(format!("{:.2}", process.cpu_percent)),
                        );
                        ui.add_sized(
                            [rss_w, 20.0],
                            egui::Label::new(human_bytes(process.memory_bytes)).wrap(false),
                        );
                        ui.add_sized([thr_w, 20.0], egui::Label::new(process.threads.to_string()));
                    })
                    .response;

                let row_click = row_resp
                    .interact(egui::Sense::click())
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if row_click.clicked() {
                    *new_expanded = if is_expanded { None } else { Some(process.pid) };
                }

                if is_expanded {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(16, 22, 30))
                        .inner_margin(egui::Margin::symmetric(12.0, 6.0))
                        .rounding(egui::Rounding::same(4.0))
                        .show(ui, |ui| {
                            ui.monospace(format!("cmdline: {}", process.cmdline));
                            ui.monospace(format!(
                                "pid: {}  threads: {}  rss: {}  cpu: {:.2}%",
                                process.pid,
                                process.threads,
                                human_bytes(process.memory_bytes),
                                process.cpu_percent
                            ));
                        });
                }
                ui.add_space(2.0);
            }
        });
}

fn cpu_util_fill(pct: f32) -> egui::Color32 {
    let t = (pct / 100.0).clamp(0.0, 1.0);
    let a = egui::Color32::from_rgb(62, 118, 148);
    let b = egui::Color32::from_rgb(220, 176, 64);
    let c = egui::Color32::from_rgb(208, 72, 64);
    let (c1, c2, u) = if t < 0.5 {
        (a, b, t * 2.0)
    } else {
        (b, c, (t - 0.5) * 2.0)
    };
    egui::Color32::from_rgb(
        (c1.r() as f32 + (c2.r() as f32 - c1.r() as f32) * u).round() as u8,
        (c1.g() as f32 + (c2.g() as f32 - c1.g() as f32) * u).round() as u8,
        (c1.b() as f32 + (c2.b() as f32 - c1.b() as f32) * u).round() as u8,
    )
}

fn render_per_core_cpu(ui: &mut egui::Ui, per_core: &[f32]) {
    if per_core.is_empty() {
        return;
    }
    const MAX: usize = 32;
    let n_show = per_core.len().min(MAX);
    let gap = ui.spacing().item_spacing.x;
    let row_w = ui.available_width();
    let show_plus = per_core.len() > MAX;
    let plus_reserve = if show_plus { 76.0 } else { 0.0 };
    let gaps = (n_show as f32 - 1.0).max(0.0) * gap;
    let bar_w = ((row_w - plus_reserve - gaps) / n_show as f32).clamp(24.0, 52.0);

    ui.add_space(8.0);
    ui.label(
        RichText::new("Per-core utilization")
            .strong()
            .font(FontId::new(13.0, FontFamily::Proportional)),
    )
    .on_hover_text("Each bar is one logical CPU since the previous sample (up to 32 shown). Hover for exact percent.");
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        for (i, pct) in per_core.iter().enumerate().take(MAX) {
            let f = (*pct / 100.0).clamp(0.0, 1.0);
            let fill = cpu_util_fill(*pct);
            let label = if *pct >= 10.0 {
                format!("{:.0}%", pct)
            } else {
                format!("{:.1}%", pct)
            };
            let r = ui.add(
                egui::ProgressBar::new(f)
                    .desired_width(bar_w)
                    .desired_height(24.0)
                    .rounding(3.0)
                    .fill(fill)
                    .text(label),
            );
            let r = r.on_hover_text(format!("Logical CPU {i}: {pct:.1}%"));
            r.widget_info(|| {
                let mut w = egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator);
                w.label = Some(format!("Logical CPU {i} {pct:.1} percent"));
                w.value = Some(*pct as f64);
                w
            });
        }
        if show_plus {
            ui.label(
                RichText::new(format!("+{} cores", per_core.len() - MAX))
                    .weak()
                    .font(FontId::new(12.0, FontFamily::Proportional)),
            )
            .on_hover_text("Additional cores omitted; aggregate CPU above reflects all cores.");
        }
    });
}

fn cpu_overview_extras(ui: &mut egui::Ui, cpu: &crate::models::cpu::CpuMetrics) {
    ui.add_space(6.0);
    let pc = &cpu.per_core;
    if pc.is_empty() {
        ui.label(
            RichText::new("Per-core breakdown not available this tick.")
                .weak()
                .italics()
                .font(FontId::new(12.5, FontFamily::Proportional)),
        );
        return;
    }
    let n = pc.len();
    let mx = pc.iter().cloned().fold(0_f32, f32::max);
    let mn = pc.iter().cloned().fold(100_f32, f32::min);
    let sum: f32 = pc.iter().sum();
    let avg = sum / n as f32;
    ui.label(
        RichText::new(format!(
            "{n} logical CPUs · core avg {:.1}% · coolest {:.1}% · hottest {:.1}%",
            avg, mn, mx
        ))
        .weak()
        .font(FontId::new(12.5, FontFamily::Proportional)),
    )
    .on_hover_text(
        "Instantaneous per-core utilization since the last sample; aggregate can differ slightly.",
    );
}

fn memory_overview_extras(ui: &mut egui::Ui, m: &crate::models::memory::MemoryMetrics) {
    ui.add_space(6.0);
    if m.total == 0 {
        return;
    }
    let avail_pct = (m.available as f32 / m.total as f32) * 100.0;
    let used_pct = (m.used as f32 / m.total as f32) * 100.0;
    ui.label(
        RichText::new(format!(
            "{} available ({:.0}% of total) · {} in use ({:.0}%)",
            human_bytes(m.available),
            avail_pct,
            human_bytes(m.used),
            used_pct
        ))
        .weak()
        .font(FontId::new(12.5, FontFamily::Proportional)),
    )
    .on_hover_text("From /proc/meminfo: MemAvailable is memory for new work without pushing swap.");
    let note = if avail_pct < 10.0 {
        "Very low MemAvailable — risk of swap thrash or OOM under load."
    } else if avail_pct < 20.0 {
        "Limited headroom for bursty workloads."
    } else {
        "Comfortable headroom for new allocations."
    };
    ui.label(
        RichText::new(note)
            .weak()
            .italics()
            .font(FontId::new(12.0, FontFamily::Proportional)),
    );
}

fn throughput_panel_heading(
    ui: &mut egui::Ui,
    icon_key: &str,
    icon_bytes: &'static [u8],
    title: &str,
    tip: &str,
) {
    ui.horizontal_top(|ui| {
        icons::paint(ui, icon_key, icon_bytes, 18.0);
        ui.add(
            egui::Label::new(
                RichText::new(title)
                    .strong()
                    .font(FontId::new(14.0, FontFamily::Proportional)),
            )
            .wrap(true),
        )
        .on_hover_text(tip);
    });
    ui.add_space(6.0);
}

fn render_overview_metrics(
    ui: &mut egui::Ui,
    snapshot: &SystemSnapshot,
    samples: &[&MetricSample],
    detailed_mode: bool,
) {
    const MIN_CPU_MEM_COL: f32 = 168.0;

    let gap = ui.spacing().item_spacing.x;
    let avail_row = ui.available_width();
    let half_cpu_mem = ((avail_row - gap) * 0.5).max(0.0);
    let stack_cpu_mem = half_cpu_mem < MIN_CPU_MEM_COL;

    if detailed_mode {
        let total_disk_bw: u64 = snapshot
            .disks
            .iter()
            .map(|d| d.read_bytes_per_sec.saturating_add(d.write_bytes_per_sec))
            .sum();
        let total_net_bw: u64 = snapshot
            .network
            .iter()
            .map(|n| n.rx_bytes_per_sec.saturating_add(n.tx_bytes_per_sec))
            .sum();
        let top_proc = snapshot
            .processes
            .iter()
            .max_by(|a, b| a.cpu_percent.total_cmp(&b.cpu_percent));
        let hottest_core = snapshot
            .cpu
            .per_core
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.total_cmp(b));
        ui.group(|ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Host: {}  ·  ts: {}  ·  tracked processes: {}  ·  disks: {}  ·  nets: {}",
                        snapshot.host_id,
                        snapshot.timestamp,
                        snapshot.processes.len(),
                        snapshot.disks.len(),
                        snapshot.network.len()
                    ))
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .weak(),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Disk BW: {}/s  ·  Net BW: {}/s",
                        human_bytes(total_disk_bw),
                        human_bytes(total_net_bw)
                    ))
                    .font(FontId::new(12.0, FontFamily::Monospace)),
                );
                if let Some((idx, pct)) = hottest_core {
                    ui.label(
                        RichText::new(format!("Hottest core: CPU{idx} {pct:.1}%"))
                            .font(FontId::new(12.0, FontFamily::Monospace)),
                    );
                }
                if let Some(proc) = top_proc {
                    ui.label(
                        RichText::new(format!(
                            "Top process: {} ({:.1}%, {})",
                            proc.name,
                            proc.cpu_percent,
                            human_bytes(proc.memory_bytes)
                        ))
                        .font(FontId::new(12.0, FontFamily::Monospace)),
                    );
                }
            });
        });
        ui.add_space(6.0);
        let cpu_points: Vec<(u64, f64)> = samples
            .iter()
            .map(|s| (s.ts, s.cpu_pct as f64))
            .collect();
        let mem_points: Vec<(u64, f64)> = samples
            .iter()
            .map(|s| (s.ts, s.mem_pct as f64))
            .collect();
        render_line_chart(
            ui,
            "CPU trend",
            &cpu_points,
            egui::Color32::from_rgb(96, 176, 210),
            85.0,
            |v| format!("{v:.1}%"),
        );
        render_line_chart(
            ui,
            "Memory trend",
            &mem_points,
            egui::Color32::from_rgb(196, 158, 66),
            85.0,
            |v| format!("{v:.1}%"),
        );
        let process_points: Vec<(u64, f64)> = samples
            .iter()
            .map(|s| (s.ts, s.process_count as f64))
            .collect();
        render_line_chart(
            ui,
            "Tracked process count trend",
            &process_points,
            egui::Color32::from_rgb(130, 205, 235),
            70.0,
            |v| format!("{v:.0}"),
        );
        let cpu_roll = rolling_stats(&cpu_points);
        ui.label(
            RichText::new(format!(
                "CPU window stats: avg {:.1}% · p95 {:.1}% · max {:.1}%",
                cpu_roll.0, cpu_roll.1, cpu_roll.2
            ))
            .weak(),
        );
    }

    if stack_cpu_mem {
        ui.vertical(|ui| {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                icons::paint(ui, "cpu-panel", icons::CPU, 16.0);
                ui.label(RichText::new("CPU").font(FontId::new(13.0, FontFamily::Proportional)))
                    .on_hover_text("Current aggregate processor utilization and load.");
                ui.add_space(2.0);
                ui.label(
                    RichText::new(format!("{:.2}%", snapshot.cpu.usage_percent))
                        .strong()
                        .font(FontId::new(22.0, FontFamily::Proportional)),
                );
                ui.label(format!(
                    "load {:.2} {:.2} {:.2}",
                    snapshot.cpu.load_avg.0, snapshot.cpu.load_avg.1, snapshot.cpu.load_avg.2
                ))
                .on_hover_text("Load averages for 1, 5, and 15 minute windows.");
                render_per_core_cpu(ui, &snapshot.cpu.per_core);
                cpu_overview_extras(ui, &snapshot.cpu);
            });
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                icons::paint(ui, "memory", icons::MEMORY, 16.0);
                ui.label(RichText::new("Memory").font(FontId::new(13.0, FontFamily::Proportional)))
                    .on_hover_text("Memory available for new programs (approx.) versus total RAM.");
                ui.add_space(2.0);
                ui.label(
                    RichText::new(format!(
                        "{} used · {} total",
                        human_bytes(snapshot.memory.used),
                        human_bytes(snapshot.memory.total)
                    ))
                    .strong()
                    .font(FontId::new(17.0, FontFamily::Proportional)),
                );
                let mem_ratio = if snapshot.memory.total == 0 {
                    0.0
                } else {
                    snapshot.memory.used as f32 / snapshot.memory.total as f32
                };
                let mem_pct = (mem_ratio * 100.0).round() as i32;
                let bar_w = ui.available_width().max(80.0);
                let pb = ui.add(
                    egui::ProgressBar::new(mem_ratio)
                        .show_percentage()
                        .desired_width(bar_w)
                        .desired_height(18.0)
                        .rounding(4.0)
                        .fill(cpu_util_fill(mem_pct as f32)),
                );
                pb.widget_info(|| {
                    let mut info = egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator);
                    info.label = Some(format!("Memory usage {mem_pct} percent"));
                    info
                });
                memory_overview_extras(ui, &snapshot.memory);
                render_memory_pie(ui, &snapshot.memory);
            });
        });
    } else {
        ui.horizontal(|ui| {
            let col_w = ((ui.available_width() - gap) * 0.5).max(1.0);
            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    icons::paint(ui, "cpu-panel", icons::CPU, 16.0);
                    ui.label(
                        RichText::new("CPU").font(FontId::new(13.0, FontFamily::Proportional)),
                    )
                    .on_hover_text("Current aggregate processor utilization and load.");
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("{:.2}%", snapshot.cpu.usage_percent))
                            .strong()
                            .font(FontId::new(22.0, FontFamily::Proportional)),
                    );
                    ui.label(format!(
                        "load {:.2} {:.2} {:.2}",
                        snapshot.cpu.load_avg.0, snapshot.cpu.load_avg.1, snapshot.cpu.load_avg.2
                    ))
                    .on_hover_text("Load averages for 1, 5, and 15 minute windows.");
                    render_per_core_cpu(ui, &snapshot.cpu.per_core);
                    cpu_overview_extras(ui, &snapshot.cpu);
                });
            });
            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    icons::paint(ui, "memory", icons::MEMORY, 16.0);
                    ui.label(
                        RichText::new("Memory").font(FontId::new(13.0, FontFamily::Proportional)),
                    )
                    .on_hover_text("Memory available for new programs (approx.) versus total RAM.");
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!(
                            "{} used · {} total",
                            human_bytes(snapshot.memory.used),
                            human_bytes(snapshot.memory.total)
                        ))
                        .strong()
                        .font(FontId::new(17.0, FontFamily::Proportional)),
                    );
                    let mem_ratio = if snapshot.memory.total == 0 {
                        0.0
                    } else {
                        snapshot.memory.used as f32 / snapshot.memory.total as f32
                    };
                    let mem_pct = (mem_ratio * 100.0).round() as i32;
                    let bar_w = ui.available_width().max(80.0);
                    let pb = ui.add(
                        egui::ProgressBar::new(mem_ratio)
                            .show_percentage()
                            .desired_width(bar_w)
                            .desired_height(18.0)
                            .rounding(4.0)
                            .fill(cpu_util_fill(mem_pct as f32)),
                    );
                    pb.widget_info(|| {
                        let mut info = egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator);
                        info.label = Some(format!("Memory usage {mem_pct} percent"));
                        info
                    });
                    memory_overview_extras(ui, &snapshot.memory);
                    render_memory_pie(ui, &snapshot.memory);
                });
            });
        });
    }
}

fn audit_auth_failure(
    helper: &HelperRuntime,
    action: &CommandAction,
    reason: &str,
    actor: &str,
    policy_hash: Option<String>,
    retention: &AuditRetentionConfig,
) {
    let (action_name, target) = match action {
        CommandAction::KillProcess { pid } => ("kill_process", format!("pid:{pid}")),
        CommandAction::ReniceProcess { pid, .. } => ("renice_process", format!("pid:{pid}")),
        _ => ("read_only", "system".to_string()),
    };
    let event = AuditEvent {
        ts: now_ts(),
        action: action_name.to_string(),
        target,
        result: format!("denied: auth_gate: {reason}"),
        actor: actor.to_string(),
        sig: None,
        policy_hash,
        anchor_txid: None,
        anchor_blockheight: None,
        anchor_merkle_root: None,
    };
    let _ = append_event_with_retention(
        &helper.audit_path,
        &event,
        retention.max_entries,
        retention.archive_enabled,
    );
}

fn audit_policy_denial(
    helper: &HelperRuntime,
    action: &CommandAction,
    reason: &str,
    actor: &str,
    policy_hash: Option<String>,
    retention: &AuditRetentionConfig,
) {
    let (action_name, target) = match action {
        CommandAction::KillProcess { pid } => ("kill_process", format!("pid:{pid}")),
        CommandAction::ReniceProcess { pid, .. } => ("renice_process", format!("pid:{pid}")),
        _ => ("read_only", "system".to_string()),
    };
    let event = AuditEvent {
        ts: now_ts(),
        action: action_name.to_string(),
        target,
        result: format!("denied: policy_gate: {reason}"),
        actor: actor.to_string(),
        sig: None,
        policy_hash,
        anchor_txid: None,
        anchor_blockheight: None,
        anchor_merkle_root: None,
    };
    let _ = append_event_with_retention(
        &helper.audit_path,
        &event,
        retention.max_entries,
        retention.archive_enabled,
    );
}

fn execute_action(
    helper: &HelperRuntime,
    action: CommandAction,
    actor: &str,
    policy_hash: Option<String>,
    retention: &AuditRetentionConfig,
) -> String {
    match action {
        CommandAction::ShowCpu => {
            let event = AuditEvent {
                ts: now_ts(),
                action: "show_cpu".to_string(),
                target: "system".to_string(),
                result: "ok: local read action".to_string(),
                actor: actor.to_string(),
                sig: None,
                policy_hash,
                anchor_txid: None,
                anchor_blockheight: None,
                anchor_merkle_root: None,
            };
            let _ = append_event_with_retention(
                &helper.audit_path,
                &event,
                retention.max_entries,
                retention.archive_enabled,
            );
            "Accepted: ShowCpu (local read-only action)".to_string()
        }
        CommandAction::KillProcess { pid } => {
            let req = HelperRequest {
                action: "kill_process".to_string(),
                pid,
                nice: None,
            };
            match send_request(&helper.socket_path, &req) {
                Ok(resp) => format!(
                    "{}: {}",
                    if resp.ok { "OK" } else { "DENIED" },
                    resp.message
                ),
                Err(err) => format!("Helper error: {err}"),
            }
        }
        CommandAction::ReniceProcess { pid, nice } => {
            let req = HelperRequest {
                action: "renice_process".to_string(),
                pid,
                nice: Some(nice),
            };
            match send_request(&helper.socket_path, &req) {
                Ok(resp) => format!(
                    "{}: {}",
                    if resp.ok { "OK" } else { "DENIED" },
                    resp.message
                ),
                Err(err) => format!("Helper error: {err}"),
            }
        }
        _ => "Read-only command handled inline.".to_string(),
    }
}

struct EvrusIdentity {
    did: Option<String>,
    display_name: Option<String>,
    exp: Option<u64>,
}

fn parse_identity_from_jwt(jwt: &str) -> Option<EvrusIdentity> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let did = claims
        .get("did")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| {
            claims
                .get("sub")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        });
    let display_name = claims
        .get("name")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| {
            claims
                .get("preferred_username")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        });
    let exp = claims.get("exp").and_then(|v| v.as_u64());
    Some(EvrusIdentity {
        did,
        display_name,
        exp,
    })
}

fn push_history<T>(buf: &mut VecDeque<T>, value: T, cap: usize) {
    if buf.len() >= cap {
        let _ = buf.pop_front();
    }
    buf.push_back(value);
}

fn render_line_chart<F: Fn(f64) -> String>(
    ui: &mut egui::Ui,
    title: &str,
    points: &[(u64, f64)],
    color: egui::Color32,
    height: f32,
    value_fmt: F,
) {
    ui.label(RichText::new(title).strong());
    if points.len() < 2 {
        ui.label(RichText::new("Waiting for more samples...").weak());
        return;
    }
    let width = ui.available_width().max(140.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let min_x = points.iter().map(|p| p.0).min().unwrap_or(0) as f64;
    let max_x = points.iter().map(|p| p.0).max().unwrap_or(1).max(min_x as u64 + 1) as f64;
    let min_y = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
    let raw_max_y = points
        .iter()
        .map(|p| p.1)
        .fold(f64::NEG_INFINITY, f64::max);
    let mut max_y = raw_max_y.max(min_y + 1e-6);
    let mut min_plot_y = min_y;
    let span = (max_y - min_plot_y).abs();
    if span < 0.25 {
        // Make low-variance series more legible instead of visually flat.
        let pad = 0.125_f64.max(max_y.abs() * 0.01);
        min_plot_y -= pad;
        max_y += pad;
    }
    let to_screen = |x: u64, y: f64| {
        let tx = if (max_x - min_x).abs() < f64::EPSILON {
            0.0_f64
        } else {
            ((x as f64 - min_x) / (max_x - min_x)).clamp(0.0, 1.0)
        };
        let ty = ((y - min_plot_y) / (max_y - min_plot_y)).clamp(0.0, 1.0);
        egui::pos2(
            rect.left() + (tx as f32) * rect.width(),
            rect.bottom() - (ty as f32) * rect.height(),
        )
    };
    ui.painter().rect_stroke(
        rect,
        4.0,
        Stroke::new(1.0, egui::Color32::from_rgb(46, 64, 80)),
    );
    for frac in [0.25_f32, 0.5_f32, 0.75_f32] {
        let y = egui::lerp(rect.top()..=rect.bottom(), frac);
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(1.0, egui::Color32::from_rgb(30, 44, 58)),
        );
    }
    for line in points.windows(2) {
        let p0 = to_screen(line[0].0, line[0].1);
        let p1 = to_screen(line[1].0, line[1].1);
        ui.painter().line_segment([p0, p1], Stroke::new(2.0, color));
    }
    let stride = (points.len() / 40).max(1);
    for (idx, (x, y)) in points.iter().enumerate() {
        if idx % stride == 0 || idx + 1 == points.len() {
            ui.painter()
                .circle_filled(to_screen(*x, *y), 2.4, color.gamma_multiply(0.9));
        }
    }
    let delta = points.last().map(|v| v.1).unwrap_or(0.0) - points.first().map(|v| v.1).unwrap_or(0.0);
    ui.label(
        RichText::new(format!(
            "min {} · max {} · delta {}",
            value_fmt(min_y),
            value_fmt(raw_max_y),
            value_fmt(delta)
        ))
        .weak(),
    );
    if response.hovered() {
        if let Some(last) = points.last() {
            response.on_hover_text(format!("latest {}", value_fmt(last.1)));
        }
    }
}

fn render_horizontal_bar_chart<F: Fn(f64) -> String>(
    ui: &mut egui::Ui,
    title: &str,
    items: &[(String, f64)],
    fill: egui::Color32,
    value_fmt: F,
) {
    if items.is_empty() {
        return;
    }
    ui.vertical(|ui| {
        ui.label(RichText::new(title).strong());
        let max_val = items
            .iter()
            .map(|(_, v)| *v)
            .fold(0.0_f64, f64::max)
            .max(1.0);
        let row_width = ui.available_width().max(160.0);
        let label_width = (row_width * 0.42).clamp(80.0, 260.0);
        let bar_width = (row_width - label_width - 10.0).max(60.0);
        for (label, value) in items.iter().take(8) {
            let ratio = (*value / max_val) as f32;
            ui.horizontal(|ui| {
                ui.add_sized(
                    [label_width, 18.0],
                    egui::Label::new(RichText::new(label).small()).truncate(true),
                )
                .on_hover_text(label);
                let pb = egui::ProgressBar::new(ratio)
                    .desired_width(bar_width)
                    .desired_height(14.0)
                    .fill(fill)
                    .text(value_fmt(*value));
                ui.add(pb);
            });
        }
    });
}

fn render_distribution_bins(ui: &mut egui::Ui, title: &str, values: &[f64], bins: usize) {
    if values.is_empty() || bins == 0 {
        return;
    }
    ui.label(RichText::new(title).strong());
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(min + 1e-6);
    let step = (max - min) / bins as f64;
    let mut counts = vec![0usize; bins];
    for value in values {
        let idx = (((*value - min) / step).floor() as usize).min(bins - 1);
        counts[idx] += 1;
    }
    let bars: Vec<(String, f64)> = counts
        .iter()
        .enumerate()
        .map(|(i, c)| (format!("{i}"), *c as f64))
        .collect();
    render_horizontal_bar_chart(
        ui,
        "Histogram bins",
        &bars,
        egui::Color32::from_rgb(130, 205, 235),
        |v| format!("{v:.0}"),
    );
}

fn render_hour_heatmap(ui: &mut egui::Ui, title: &str, bins: &[usize; 24]) {
    ui.label(RichText::new(title).strong());
    let max_v = bins.iter().copied().max().unwrap_or(1).max(1) as f32;
    ui.horizontal_wrapped(|ui| {
        for (hour, value) in bins.iter().enumerate() {
            let intensity = (*value as f32 / max_v).clamp(0.0, 1.0);
            let color = egui::Color32::from_rgb(
                (30.0 + intensity * 120.0) as u8,
                (45.0 + intensity * 140.0) as u8,
                (60.0 + intensity * 150.0) as u8,
            );
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 2.0, color);
            if resp.hovered() {
                resp.on_hover_text(format!("hour {:02}: {} events", hour, value));
            }
        }
    });
}

fn render_timeline(ui: &mut egui::Ui, title: &str, points: &[(u64, f64)], height: f32) {
    ui.label(RichText::new(title).strong());
    if points.is_empty() {
        return;
    }
    let width = ui.available_width().max(120.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let min_ts = points.iter().map(|p| p.0).min().unwrap_or(0);
    let max_ts = points
        .iter()
        .map(|p| p.0)
        .max()
        .unwrap_or(min_ts.saturating_add(1))
        .max(min_ts.saturating_add(1));
    let span = (max_ts - min_ts).max(1) as f32;
    ui.painter().rect_stroke(
        rect,
        4.0,
        Stroke::new(1.0, egui::Color32::from_rgb(46, 64, 80)),
    );
    for (ts, mark) in points.iter().take(160) {
        let t = ts.saturating_sub(min_ts) as f32 / span;
        let x = rect.left() + t * rect.width();
        let color = if *mark > 0.5 {
            egui::Color32::from_rgb(225, 90, 90)
        } else {
            egui::Color32::from_rgb(96, 176, 210)
        };
        ui.painter().line_segment(
            [egui::pos2(x, rect.top() + 4.0), egui::pos2(x, rect.bottom() - 4.0)],
            Stroke::new(1.0, color),
        );
    }
}

fn render_topology_map(ui: &mut egui::Ui, peers: u64, nodes: u64, edges: u64) {
    ui.label(RichText::new("Topology map").strong());
    let width = ui.available_width().max(200.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 120.0), egui::Sense::hover());
    let center = egui::pos2(rect.center().x, rect.center().y);
    ui.painter().circle_filled(center, 14.0, egui::Color32::from_rgb(96, 176, 210));
    let n = peers.clamp(1, 10) as usize;
    for idx in 0..n {
        let angle = (idx as f32 / n as f32) * std::f32::consts::TAU;
        let p = egui::pos2(center.x + angle.cos() * 40.0, center.y + angle.sin() * 34.0);
        ui.painter().line_segment([center, p], Stroke::new(1.0, egui::Color32::from_rgb(130, 205, 235)));
        ui.painter().circle_filled(p, 6.0, egui::Color32::from_rgb(196, 158, 66));
    }
    ui.label(RichText::new(format!("peers={peers} nodes={nodes} edges={edges}")).weak());
}

fn render_memory_pie(ui: &mut egui::Ui, m: &crate::models::memory::MemoryMetrics) {
    if m.total == 0 {
        return;
    }
    ui.label(RichText::new("Memory composition").strong());
    let used = m.used.min(m.total);
    let available = m.available.min(m.total.saturating_sub(used));
    let other = m.total.saturating_sub(used).saturating_sub(available);
    let segments = [
        ("used", used, egui::Color32::from_rgb(220, 116, 78)),
        ("available", available, egui::Color32::from_rgb(96, 176, 210)),
        ("other", other, egui::Color32::from_rgb(120, 140, 165)),
    ];
    let (rect, _) = ui.allocate_exact_size(egui::vec2(140.0, 140.0), egui::Sense::hover());
    let center = rect.center();
    let radius = 50.0;
    let mut start = 0.0_f32;
    for (name, value, color) in segments {
        let frac = value as f32 / m.total as f32;
        let sweep = frac * std::f32::consts::TAU;
        let end = start + sweep;
        let mut points = vec![center];
        let steps = 24usize.max((sweep.abs() * 24.0) as usize);
        for i in 0..=steps {
            let a = start + (end - start) * (i as f32 / steps as f32);
            points.push(egui::pos2(center.x + radius * a.cos(), center.y + radius * a.sin()));
        }
        ui.painter().add(egui::Shape::convex_polygon(points, color, Stroke::NONE));
        ui.label(RichText::new(format!("{name}: {}", human_bytes(value))).small());
        start = end;
    }
}

fn rolling_stats(points: &[(u64, f64)]) -> (f64, f64, f64) {
    if points.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mut values: Vec<f64> = points.iter().map(|(_, v)| *v).collect();
    values.sort_by(|a, b| a.total_cmp(b));
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let idx = ((values.len() as f64) * 0.95).floor() as usize;
    let p95 = values[idx.min(values.len() - 1)];
    let max = *values.last().unwrap_or(&0.0);
    (avg, p95, max)
}

fn human_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.2} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Suppress all egui debug/diagnostic overlays every frame.
/// In debug builds egui defaults `warn_on_id_clash = true` which paints red
/// "First use of widget ID …" rectangles whenever two widgets share an ID.
/// The style-level debug flags are a separate layer on top.
fn suppress_debug_overlays(ctx: &egui::Context) {
    ctx.options_mut(|opt| opt.warn_on_id_clash = false);
    ctx.style_mut(|style| {
        style.debug.debug_on_hover = false;
        style.debug.debug_on_hover_with_all_modifiers = false;
        style.debug.show_expand_width = false;
        style.debug.show_expand_height = false;
        style.debug.show_resize = false;
        style.debug.show_interactive_widgets = false;
        style.debug.show_widget_hits = false;
    });
}

fn apply_security_visuals(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(egui::Color32::from_rgb(214, 222, 230));
    visuals.panel_fill = egui::Color32::from_rgb(13, 18, 24);
    visuals.window_fill = egui::Color32::from_rgb(13, 18, 24);
    visuals.extreme_bg_color = egui::Color32::from_rgb(7, 11, 16);
    visuals.faint_bg_color = egui::Color32::from_rgb(22, 29, 38);
    visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(170, 182, 194);
    visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(198, 206, 214);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(44, 84, 103);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(31, 56, 70);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(19, 33, 44);
    visuals.hyperlink_color = egui::Color32::from_rgb(96, 176, 210);
    visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 62, 78));
    ctx.set_visuals(visuals);

    ctx.style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(6.0, 5.0);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(10.0);
        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::new(13.5, FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        );
    });
}

#[derive(Clone, Copy)]
enum ThroughputSeverity {
    Nominal,
    Elevated,
    Critical,
}

impl ThroughputSeverity {
    fn label(self) -> &'static str {
        match self {
            ThroughputSeverity::Nominal => "NOMINAL",
            ThroughputSeverity::Elevated => "ELEVATED",
            ThroughputSeverity::Critical => "CRITICAL",
        }
    }
}

fn throughput_severity(bytes_per_sec: u64) -> ThroughputSeverity {
    if bytes_per_sec >= 100 * 1024 * 1024 {
        ThroughputSeverity::Critical
    } else if bytes_per_sec >= 20 * 1024 * 1024 {
        ThroughputSeverity::Elevated
    } else {
        ThroughputSeverity::Nominal
    }
}

fn severity_pill_colors(severity: ThroughputSeverity) -> (egui::Color32, egui::Color32) {
    match severity {
        ThroughputSeverity::Nominal => (
            egui::Color32::from_rgb(130, 205, 235),
            egui::Color32::from_rgb(24, 38, 50),
        ),
        ThroughputSeverity::Elevated => (
            egui::Color32::from_rgb(240, 200, 90),
            egui::Color32::from_rgb(48, 42, 26),
        ),
        ThroughputSeverity::Critical => (
            egui::Color32::from_rgb(235, 110, 100),
            egui::Color32::from_rgb(52, 28, 28),
        ),
    }
}

#[allow(dead_code)]
fn throughput_detail_row(ui: &mut egui::Ui, severity: ThroughputSeverity, detail: String) {
    let (fg, bg) = severity_pill_colors(severity);
    let badge = severity.label();
    let hover = format!("Severity {badge} — {detail}");
    ui.add_space(3.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!(" {badge} "))
                .color(fg)
                .background_color(bg)
                .font(FontId::new(11.5, FontFamily::Monospace))
                .strong(),
        )
        .on_hover_text(&hover);
        ui.add_space(8.0);
        ui.add(
            egui::Label::new(
                RichText::new(detail).font(FontId::new(13.0, FontFamily::Proportional)),
            )
            .wrap(true),
        )
        .on_hover_text(hover);
    });
}

fn render_quick_tile(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(20, 28, 36))
        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
        .rounding(egui::Rounding::same(6.0))
        .stroke(Stroke::new(1.0, egui::Color32::from_rgb(42, 58, 74)))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(label)
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .weak(),
                );
                ui.label(
                    RichText::new(value)
                        .font(FontId::new(15.0, FontFamily::Proportional))
                        .strong(),
                );
            });
        });
}

fn render_clickable_tile(ui: &mut egui::Ui, label: &str, value: String) -> bool {
    let resp = egui::Frame::none()
        .fill(egui::Color32::from_rgb(20, 28, 36))
        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
        .rounding(egui::Rounding::same(6.0))
        .stroke(Stroke::new(1.0, egui::Color32::from_rgb(42, 58, 74)))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(label)
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .weak(),
                );
                ui.label(
                    RichText::new(value)
                        .font(FontId::new(15.0, FontFamily::Proportional))
                        .strong(),
                );
            });
        });
    let click = resp
        .response
        .interact(egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if click.hovered() {
        ui.painter().rect_stroke(
            click.rect,
            6.0,
            Stroke::new(1.0, egui::Color32::from_rgb(96, 176, 210)),
        );
    }
    click.clicked()
}

const GLOSSARY_ENTRIES: &[(&str, &str)] = &[
    ("CapToken", "Capability-based access token used by PeerWeave for fine-grained graph permissions."),
    ("Merkle Root", "A single hash that cryptographically summarizes all audit events. Any change to any event changes the root."),
    ("Ed25519", "A digital signature algorithm used to sign audit events, ensuring they haven't been tampered with."),
    ("OP_RETURN", "A Bitcoin/Evrmore transaction output used to embed data (like a Merkle root) on the blockchain."),
    ("OIDC", "OpenID Connect — an identity protocol. EVRUS uses it to issue JWTs for operator identity."),
    ("JWT", "JSON Web Token — a compact, signed token containing identity claims (DID, role, expiry)."),
    ("RBAC", "Role-Based Access Control — permissions granted based on role (viewer/operator/admin)."),
    ("UDS", "Unix Domain Socket — local inter-process communication channel between core and helper."),
    ("SSE", "Server-Sent Events — a protocol for streaming real-time telemetry from Sentinel over HTTP."),
    ("JSONL", "JSON Lines — one JSON object per line. Used for audit events and snapshot history files."),
    ("Anchor", "The act of writing a Merkle root to the Evrmore blockchain for tamper-evidence."),
    ("DID", "Decentralized Identifier — a globally unique identity string from EVRUS."),
    ("Connector", "An optional integration module (PeerWeave, EVRUS) that extends Sentinel's capabilities."),
    ("Policy Gate", "Runtime check that evaluates role permissions and EVRUS policies before allowing actions."),
    ("Auth Gate", "Authentication check that verifies token validity before command execution."),
    ("Cooldown", "A minimum time interval between consecutive destructive actions (e.g., kill commands)."),
    ("Profile", "A preset configuration (default/dev/secure/ecosystem) loaded from config/profiles/*.env."),
    ("Helper", "A privilege-separated process that executes destructive actions (kill/renice) on behalf of the UI."),
    ("Snapshot", "A point-in-time capture of all system metrics (CPU, memory, disk, network, processes)."),
];

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
