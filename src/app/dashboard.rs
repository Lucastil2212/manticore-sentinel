use std::collections::VecDeque;
use std::time::{Duration, Instant};

use base64::Engine;
use eframe::egui;
use egui::{FontFamily, FontId, RichText, Stroke};
use egui_extras::install_image_loaders;
use tokio::runtime::Runtime;

use crate::connectors::ConnectorSummary;
use crate::core::{
    command::{parse_command, CommandAction},
    config::load_runtime_config,
    engine::SentinelEngine,
    history::{append_snapshot, default_snapshot_history_path, read_since},
    policy::ExecutionPolicy,
    snapshot::SystemSnapshot,
};
use crate::models::process::ProcessMetrics;
use crate::security::audit::{
    anchor_audit_if_due, append_event, current_merkle_root, default_audit_path, load_anchor_state,
    now_ts, read_from_offset, read_recent, AnchorConfig, AnchorState, AuditEvent,
};
use crate::security::auth::{AuthContext, AuthGate, AuthMode, TokenLifecycle};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperRuntime};
use crate::utils::time::now_unix_secs;
use tracing::error;

use super::event_stream::EventStreamOutput;
use super::icons;

const ID_COMMAND_INPUT: &str = "command_palette_input";

#[derive(Clone, Copy, PartialEq, Eq)]
enum DashboardView {
    System,
    Processes,
    Network,
    PeerWeave,
    Evrus,
    Audit,
    Connectors,
}

impl DashboardView {
    fn all() -> [DashboardView; 7] {
        [
            DashboardView::System,
            DashboardView::Processes,
            DashboardView::Network,
            DashboardView::PeerWeave,
            DashboardView::Evrus,
            DashboardView::Audit,
            DashboardView::Connectors,
        ]
    }

    fn label(self) -> &'static str {
        match self {
            DashboardView::System => "System",
            DashboardView::Processes => "Processes",
            DashboardView::Network => "Network",
            DashboardView::PeerWeave => "PeerWeave",
            DashboardView::Evrus => "EVRUS",
            DashboardView::Audit => "Audit",
            DashboardView::Connectors => "Connectors",
        }
    }

    fn help(self) -> &'static str {
        match self {
            DashboardView::System => "Overview + control shell + activity feed.",
            DashboardView::Processes => "Dedicated process inspection with sortable table.",
            DashboardView::Network => "Focused interface and throughput analysis.",
            DashboardView::PeerWeave => "PeerWeave connector health and graph context.",
            DashboardView::Evrus => "EVRUS identity, auth, and anchoring posture.",
            DashboardView::Audit => "Chronological audit trail with filtering and anchor metadata.",
            DashboardView::Connectors => "Integration health matrix for all connectors.",
        }
    }
}

fn filtered_command_completions(typed: &str) -> Vec<&'static str> {
    const ALL: &[&str] = &["show cpu", "renice ", "kill "];
    let low = typed.trim_start().to_ascii_lowercase();
    if low.is_empty() {
        return ALL.to_vec();
    }
    ALL.iter()
        .copied()
        .filter(|c| c.to_ascii_lowercase().starts_with(&low))
        .collect()
}

pub struct SentinelDashboard {
    engine: SentinelEngine,
    runtime: Runtime,
    latest: Option<SystemSnapshot>,
    last_poll: Instant,
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
    active_view: DashboardView,
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
    snapshot_history_path: std::path::PathBuf,
    snapshot_history_recent_hour: usize,
    last_snapshot_history_probe: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessSort {
    CpuDesc,
    RssDesc,
    PidAsc,
    ThreadsDesc,
}

impl SentinelDashboard {
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
        let runtime_diagnostics = format!(
            "profile={} privileged={} helper_mode={} refresh_ms={} role={} auth_mode={} token_ttl_secs={} peerweave={} evrus={}",
            cfg.profile,
            cfg.privileged,
            cfg.helper_mode,
            cfg.refresh_ms,
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
        let snapshot_history_path = default_snapshot_history_path(&cwd);

        let mut engine = SentinelEngine::new();
        engine.init_connectors(&cfg.connectors);
        let connector_poll_interval = cfg
            .connectors
            .peerweave
            .as_ref()
            .map(|pw| Duration::from_millis(pw.poll_ms))
            .unwrap_or(Duration::from_secs(5));

        let policy = ExecutionPolicy::new(auth, ExecutionPolicy::load_evrus_policy());
        let last_policy_hash = policy.current_policy_hash();
        let event_stream = cfg.event_stream.as_ref().and_then(|es| {
            EventStreamOutput::start(
                es.port,
                cfg.auth_mode,
                cfg.auth_token.clone(),
                evrus_jwt.clone(),
            )
            .ok()
        });

        Ok(Self {
            engine,
            runtime: Runtime::new()?,
            latest: None,
            last_poll: Instant::now() - Duration::from_millis(500),
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
            show_onboarding: true,
            show_help_center: false,
            runtime_diagnostics,
            last_command_feedback_announced: None,
            command_history: VecDeque::new(),
            history_browse: None,
            history_draft: String::new(),
            connector_summary: ConnectorSummary::default(),
            last_connector_poll: Instant::now() - Duration::from_secs(60),
            connector_poll_interval,
            active_view: DashboardView::System,
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
            snapshot_history_path,
            snapshot_history_recent_hour: 0,
            last_snapshot_history_probe: Instant::now() - Duration::from_secs(10),
        })
    }

    fn poll(&mut self) {
        if self.last_poll.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.last_poll = Instant::now();

        match self.runtime.block_on(self.engine.collect()) {
            Ok(snapshot) => {
                self.engine.ingest_system_snapshot(&snapshot);
                if self.snapshot_history_enabled {
                    if let Err(err) = append_snapshot(
                        &self.snapshot_history_path,
                        &snapshot,
                        self.snapshot_history_max_entries,
                    ) {
                        self.last_error = Some(format!("snapshot persistence failed: {err}"));
                    }
                }
                if let Some(stream) = &self.event_stream {
                    let payload = serde_json::json!({
                        "timestamp": snapshot.timestamp,
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
            }
        }

        if self.engine.has_connectors()
            && self.last_connector_poll.elapsed() >= self.connector_poll_interval
        {
            self.connector_summary = self.engine.poll_connectors();
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
            && self.last_snapshot_history_probe.elapsed() >= Duration::from_secs(10)
        {
            let now = now_unix_secs();
            let min_ts = now.saturating_sub(3600);
            match read_since(&self.snapshot_history_path, min_ts) {
                Ok(rows) => self.snapshot_history_recent_hour = rows.len(),
                Err(err) => {
                    self.last_error = Some(format!("snapshot history query failed: {err}"));
                }
            }
            self.last_snapshot_history_probe = Instant::now();
        }
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

        let alt = ctx.input(|i| i.modifiers.alt);
        if alt && ctx.input(|i| i.key_pressed(egui::Key::Num1)) {
            self.active_view = DashboardView::System;
        } else if alt && ctx.input(|i| i.key_pressed(egui::Key::Num2)) {
            self.active_view = DashboardView::Processes;
        } else if alt && ctx.input(|i| i.key_pressed(egui::Key::Num3)) {
            self.active_view = DashboardView::Network;
        } else if alt && ctx.input(|i| i.key_pressed(egui::Key::Num4)) {
            self.active_view = DashboardView::Audit;
        } else if alt && ctx.input(|i| i.key_pressed(egui::Key::Num5)) {
            self.active_view = DashboardView::Connectors;
        }
    }

    fn run_command_palette_action(&mut self) {
        let trimmed = self.command_input.trim().to_string();
        let (feedback, clear_line) = match parse_command(&trimmed) {
            Ok(action) => {
                if let Err(err) = self.verify_auth_submission(&action) {
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
        let body = FontId::new(15.0, FontFamily::Proportional);
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

        let shell_inset = egui::Margin::symmetric(12.0, 10.0);
        let shell_fill = egui::Color32::from_rgb(16, 20, 26);
        let shell_stroke = Stroke::new(1.0, egui::Color32::from_rgb(52, 66, 84));
        let mono = FontId::new(16.0, FontFamily::Monospace);
        let mono_hint = FontId::new(12.0, FontFamily::Monospace);
        let prompt_color = egui::Color32::from_rgb(110, 198, 224);

        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "command", icons::COMMAND, 15.0);
            ui.label(
                RichText::new("Operator shell")
                    .strong()
                    .font(FontId::new(14.5, FontFamily::Proportional)),
            );
        });
        ui.label(
            RichText::new("Structured commands only — no pipes, redirects, or subshells.")
                .weak()
                .font(FontId::new(12.5, FontFamily::Proportional)),
        );
        ui.add_space(6.0);

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
                                "Auth lockout active: {} failures, retry in {}s",
                                self.auth_failures, remaining
                            ),
                        );
                    } else if self.auth_failures > 0 {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 176, 64),
                            format!(
                                "Auth failures: {} (lockout after 3 consecutive failures)",
                                self.auth_failures
                            ),
                        );
                    } else {
                        ui.colored_label(
                            egui::Color32::from_rgb(96, 176, 210),
                            "Auth status: ready",
                        );
                    }
                    ui.add_space(4.0);
                    let tok_lbl = ui
                        .label(RichText::new("Token").font(mono_hint.clone()))
                        .on_hover_text("Required in token mode. Input is masked.");
                    let token_w = ui.available_width().max(120.0);
                    let te = egui::TextEdit::singleline(&mut self.auth_token_input)
                        .font(mono_hint.clone())
                        .password(true)
                        .hint_text("paste token")
                        .desired_width(token_w);
                    ui.add(te).labelled_by(tok_lbl.id);
                });
            ui.add_space(8.0);
        }

        egui::Frame::none()
            .fill(shell_fill)
            .inner_margin(shell_inset)
            .rounding(egui::Rounding::same(8.0))
            .stroke(shell_stroke)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    RichText::new("Tab complete · ↑ / ↓ history · Enter run · ⌘K focus")
                        .weak()
                        .font(mono_hint.clone()),
                )
                .on_hover_text("Same spirit as a modern terminal: keyboard-first, no raw shell.");
                ui.add_space(6.0);

                let cmd_row_room = ui.available_width();
                let run_reserve = 76.0 + ui.spacing().item_spacing.x * 2.0;
                let prompt_reserve = 108.0;
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
                        .hint_text("show cpu")
                        .desired_width(edit_w);
                    let r = ui.add(te).on_hover_text(
                        "Enter runs the line. Tab fills the first matching built-in.",
                    );
                    // Single-line TextEdit: Enter must be detected while focused (lost_focus + Enter
                    // often never align in the same frame).
                    enter_run =
                        ui.ctx().input(|i| i.key_pressed(egui::Key::Enter)) && r.has_focus();
                    let run = ui
                        .add_sized(
                            [68.0, 30.0],
                            egui::Button::new(
                                RichText::new("Run")
                                    .strong()
                                    .font(FontId::new(13.5, FontFamily::Proportional)),
                            )
                            .fill(egui::Color32::from_rgb(52, 98, 128))
                            .stroke(Stroke::new(1.0, egui::Color32::from_rgb(72, 118, 148))),
                        )
                        .on_hover_text("Run the current line (same as Enter).");
                    run.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, "Run command")
                    });
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

                ui.add_space(8.0);
                ui.label(
                    RichText::new("Quick actions")
                        .weak()
                        .font(mono_hint.clone()),
                );
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if ui
                        .button(RichText::new("show cpu").font(mono_hint.clone()))
                        .on_hover_text("Run read-only CPU snapshot (most common).")
                        .clicked()
                    {
                        self.command_input = "show cpu".to_string();
                        self.run_command_palette_action();
                    }
                    if ui
                        .button(RichText::new("renice …").font(mono_hint.clone()))
                        .on_hover_text("Insert template: renice <nice> <pid>  (nice −20…19).")
                        .clicked()
                    {
                        self.command_input = "renice 0 ".to_string();
                        ctx.memory_mut(|m| {
                            m.request_focus(egui::Id::new(ID_COMMAND_INPUT));
                        });
                    }
                    if self.trust_state == "PRIVILEGED" {
                        if ui
                            .button(RichText::new("kill …").font(mono_hint.clone()))
                            .on_hover_text("Insert template: kill <pid>  (requires typed confirm).")
                            .clicked()
                        {
                            self.command_input = "kill ".to_string();
                            ctx.memory_mut(|m| {
                                m.request_focus(egui::Id::new(ID_COMMAND_INPUT));
                            });
                        }
                    } else {
                        ui.add_enabled(
                            false,
                            egui::Button::new(RichText::new("kill …").font(mono_hint.clone())),
                        )
                        .on_hover_text("Privileged mode only (kill is capability-gated).");
                    }
                });

                let comps = filtered_command_completions(&self.command_input);
                let show_chips = !comps.is_empty()
                    && !(comps.len() == 1 && comps[0] == self.command_input.trim());
                if show_chips {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Suggestions").weak().font(mono_hint.clone()));
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        for c in comps {
                            let lbl: &'static str = match c {
                                "renice " => "renice <nice> <pid>",
                                "kill " => "kill <pid>",
                                _ => c,
                            };
                            if ui
                                .small_button(lbl)
                                .on_hover_text(format!("Insert `{c}`"))
                                .clicked()
                            {
                                self.command_input = c.to_string();
                            }
                        }
                    });
                }
            });

        if let Some(CommandAction::KillProcess { pid }) = self.pending_action.clone() {
            ui.add_space(8.0);
            let required = format!("KILL {}", pid);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(36, 18, 18))
                .inner_margin(shell_inset)
                .rounding(egui::Rounding::same(8.0))
                .stroke(Stroke::new(1.0, egui::Color32::from_rgb(140, 56, 52)))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        RichText::new(format!("Destructive action — type `{required}` to confirm"))
                            .color(egui::Color32::from_rgb(255, 190, 175))
                            .font(FontId::new(13.0, FontFamily::Proportional)),
                    );
                    ui.add_space(6.0);
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
            ui.add_space(8.0);
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
                    ui.label(RichText::new("Output").weak().font(mono_hint.clone()));
                    ui.add_space(4.0);
                    let out_text = egui::Color32::from_rgb(232, 238, 246);
                    let status = ui
                        .add(
                            egui::Label::new(
                                RichText::new(msg.as_str())
                                    .font(mono.clone())
                                    .color(out_text),
                            )
                            .wrap(true)
                            .sense(egui::Sense::hover()),
                        )
                        .on_hover_text(
                            "Latest command outcome; assistive tech is notified when this text changes.",
                        );
                    status.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Label, format!("Command result: {msg}"))
                    });
                });
        }

        if !self.command_history.is_empty() {
            ui.add_space(8.0);
            ui.label(
                RichText::new("Session history (newest first)")
                    .weak()
                    .font(mono_hint.clone()),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .id_source("session_cmd_history_scroll")
                .max_height(140.0)
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
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "section-command", icons::COMMAND, 18.0);
            ui.heading("Control");
        });
        ui.label(egui::RichText::new("Operator shell, auth, and block-style output.").weak());
        ui.add_space(8.0);
        self.render_command_workbench(ui, ctx);
    }

    fn render_activity_section(&mut self, ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "section-activity", icons::AUDIT, 18.0);
            ui.heading("Activity");
        });
        ui.label(egui::RichText::new("Top processes and append-only audit trail.").weak());
        ui.add_space(8.0);
        self.render_activity_panels(ui, snapshot);
    }

    fn render_activity_panels(&mut self, ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "command-process", icons::PROCESS, 14.0);
            ui.heading("Top Processes (CPU)")
                .on_hover_text("Highest CPU consumers in current snapshot.");
        });
        if snapshot.processes.is_empty() {
            ui.label(
                egui::RichText::new("No process list in this snapshot.")
                    .weak()
                    .italics(),
            );
        } else {
            process_metrics_table(ui, &snapshot.processes);
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "audit", icons::AUDIT, 14.0);
            ui.heading("Recent Audit Events")
                .on_hover_text("Append-only trail for helper and auth-gate outcomes.");
        });
        if self.last_audit_refresh.elapsed() >= Duration::from_secs(1) {
            self.audit_feed = read_recent(&self.helper.audit_path, 12).unwrap_or_default();
            self.last_audit_refresh = Instant::now();
        }
        if self.audit_feed.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No audit events recorded yet. Helper actions and auth denials appear here.",
                )
                .weak()
                .italics(),
            );
        } else {
            for event in &self.audit_feed {
                let line = format!(
                    "[{}] action={} target={} result={}",
                    event.ts, event.action, event.target, event.result
                );
                ui.add(egui::Label::new(egui::RichText::new(line).monospace()).wrap(true));
            }
        }
    }

    fn render_connectors_panel(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "connectors-network", icons::NETWORK, 18.0);
            ui.heading("Ecosystem Connectors");
        });
        ui.label(egui::RichText::new("PeerWeave and EVRUS integration status.").weak());
        ui.add_space(8.0);

        if self.connector_summary.entries.is_empty() {
            let passive = self.engine.connector_summary_passive();
            if passive.entries.is_empty() {
                ui.label("No connectors configured.");
                ui.monospace(
                    "Set MANTICORE_PEERWEAVE_ENABLED=true or MANTICORE_EVRUS_ENABLED=true to enable integrations.",
                );
                return;
            }
            for entry in &passive.entries {
                self.render_connector_row(ui, entry);
            }
        } else {
            for entry in &self.connector_summary.entries {
                self.render_connector_row(ui, entry);
            }
        }
    }

    fn render_connector_row(&self, ui: &mut egui::Ui, health: &crate::connectors::ConnectorHealth) {
        let mono_sm = FontId::new(12.0, FontFamily::Monospace);
        let (badge_fg, badge_bg) = match &health.status {
            crate::connectors::ConnectorStatus::Disabled => (
                egui::Color32::from_rgb(130, 140, 150),
                egui::Color32::from_rgb(30, 34, 40),
            ),
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

    fn render_navigation_tabs(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Views (Alt+1..5 quick switch)")
                .weak()
                .font(FontId::new(12.0, FontFamily::Proportional)),
        );
        ui.horizontal_wrapped(|ui| {
            for view in DashboardView::all() {
                let selected = self.active_view == view;
                let tab = ui
                    .selectable_label(selected, view.label())
                    .on_hover_text(view.help());
                tab.widget_info(|| {
                    egui::WidgetInfo::labeled(
                        egui::WidgetType::SelectableLabel,
                        format!("Open {} view", view.label()),
                    )
                });
                if tab.clicked() {
                    self.active_view = view;
                }
            }
        });
    }

    fn connector_health_for(&self, name: &str) -> Option<crate::connectors::ConnectorHealth> {
        if let Some(health) = self.connector_summary.health_for(name) {
            return Some(health.clone());
        }
        let passive = self.engine.connector_summary_passive();
        passive.health_for(name).cloned()
    }

    fn render_peerweave_view(&self, ui: &mut egui::Ui) {
        ui.heading("PeerWeave");
        let Some(health) = self.connector_health_for("PeerWeave") else {
            ui.label("PeerWeave connector is disabled.");
            ui.monospace("Enable with MANTICORE_PEERWEAVE_ENABLED=true");
            return;
        };
        self.render_connector_row(ui, &health);

        let Some(snapshot) = self.connector_summary.snapshot_for("PeerWeave") else {
            ui.label("Waiting for PeerWeave snapshot data...");
            return;
        };

        let payload = snapshot.data.get("data").unwrap_or(&snapshot.data);
        let node = payload.get("node").cloned().unwrap_or_default();
        let graph = payload.get("graph").cloned().unwrap_or_default();
        ui.separator();
        ui.label(
            RichText::new(format!(
                "Node: {}  |  Status: {}  |  Uptime: {}s",
                node.get("peerId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                node.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                node.get("uptime").and_then(|v| v.as_u64()).unwrap_or(0)
            ))
            .strong(),
        );
        ui.label(format!(
            "Peers: {}  |  Graph nodes: {}  |  Graph edges: {}",
            node.get("peers")
                .and_then(|p| p.get("count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            graph.get("nodeCount").and_then(|v| v.as_u64()).unwrap_or(0),
            graph.get("edgeCount").and_then(|v| v.as_u64()).unwrap_or(0)
        ));

        ui.add_space(8.0);
        ui.label(RichText::new("Spaces").strong());
        if let Some(spaces) = payload.get("spaces").and_then(|v| v.as_array()) {
            if spaces.is_empty() {
                ui.label("No spaces returned.");
            } else {
                for space in spaces.iter().take(16) {
                    let name = space
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed");
                    let sync = space
                        .get("syncState")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let ops = space.get("opsCount").and_then(|v| v.as_u64()).unwrap_or(0);
                    ui.label(format!("{name} · sync={sync} · ops={ops}"));
                }
            }
        } else {
            ui.label("No spaces payload available.");
        }
    }

    fn render_evrus_view(&self, ui: &mut egui::Ui) {
        ui.heading("EVRUS");
        let Some(health) = self.connector_health_for("EVRUS") else {
            ui.label("EVRUS connector is disabled.");
            ui.monospace("Enable with MANTICORE_EVRUS_ENABLED=true");
            return;
        };
        self.render_connector_row(ui, &health);

        ui.separator();
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
        ui.label(format!(
            "Vault connection: {}",
            if matches!(health.status, crate::connectors::ConnectorStatus::Healthy) {
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
        ui.label("Policy summary: local execution policy active; EVRUS policy bridge pending");
    }

    fn render_audit_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Audit");
        ui.horizontal(|ui| {
            let lbl = ui.label("Filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.audit_filter)
                    .hint_text("action/target/actor/result")
                    .desired_width(280.0),
            )
            .labelled_by(lbl.id)
            .on_hover_text("Filter current audit window by text (case-insensitive).");
        });
        let current_merkle = current_merkle_root(&self.helper.audit_path).ok().flatten();
        let anchored_current_window =
            current_merkle.as_deref() == self.anchor_state.last_anchor_merkle_root.as_deref();
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
        ui.separator();
        if self.last_audit_refresh.elapsed() >= Duration::from_secs(1) {
            self.audit_feed = read_recent(&self.helper.audit_path, 32).unwrap_or_default();
            self.last_audit_refresh = Instant::now();
        }
        if self.audit_feed.is_empty() {
            ui.label("No audit events yet.");
            return;
        }
        let filter = self.audit_filter.trim().to_ascii_lowercase();
        for event in &self.audit_feed {
            if !filter.is_empty() {
                let haystack = format!(
                    "{} {} {} {} {}",
                    event.action, event.target, event.result, event.actor, event.ts
                )
                .to_ascii_lowercase();
                if !haystack.contains(&filter) {
                    continue;
                }
            }
            ui.monospace(format!(
                "[{}] action={} target={} result={} actor={} policy={} txid={} bh={}",
                event.ts,
                event.action,
                event.target,
                event.result,
                event.actor,
                event.policy_hash.as_deref().unwrap_or("-"),
                event.anchor_txid.as_deref().unwrap_or("-"),
                event
                    .anchor_blockheight
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ));
        }
    }

    fn render_processes_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "process-view", icons::PROCESS, 18.0);
            ui.heading("Processes");
        });
        ui.label(
            egui::RichText::new("Sortable process inspection by CPU, RSS, PID, and thread count.")
                .weak(),
        );
        ui.add_space(8.0);
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
        });
        ui.separator();
        let Some(snapshot) = &self.latest else {
            ui.spinner();
            ui.label("Collecting first snapshot...");
            return;
        };
        let mut rows: Vec<ProcessMetrics> = snapshot.processes.clone();
        match self.process_sort {
            ProcessSort::CpuDesc => rows.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
            ProcessSort::RssDesc => rows.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
            ProcessSort::PidAsc => rows.sort_by(|a, b| a.pid.cmp(&b.pid)),
            ProcessSort::ThreadsDesc => rows.sort_by(|a, b| b.threads.cmp(&a.threads)),
        }
        process_metrics_table(ui, &rows);
    }

    fn render_network_view(&self, ui: &mut egui::Ui) {
        ui.heading("Network & Throughput");
        let Some(snapshot) = &self.latest else {
            ui.spinner();
            ui.label("Collecting first snapshot...");
            return;
        };
        ui.group(|ui| {
            ui.label(RichText::new("Interfaces").strong());
            network_throughput_rows(ui, snapshot);
        });
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(RichText::new("Disk throughput").strong());
            disk_throughput_rows(ui, snapshot);
        });
    }

    fn render_system_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, central_fill_w: f32) {
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "overview-radar", icons::RADAR, 18.0);
            ui.heading("Overview");
        });
        ui.label(egui::RichText::new("CPU, memory, disk, and network at a glance.").weak());
        ui.add_space(8.0);
        self.render_overview_quick_tiles(ui);
        ui.add_space(8.0);
        if let Some(snapshot) = &self.latest {
            render_overview_metrics(ui, snapshot);
        } else {
            ui.spinner();
            ui.label("Collecting first snapshot...");
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        const CONTROL_ACTIVITY_SPLIT_PX: f32 = 1060.0;
        if central_fill_w >= CONTROL_ACTIVITY_SPLIT_PX {
            ui.horizontal_top(|ui| {
                let gap = ui.spacing().item_spacing.x;
                let tw = ui.available_width();
                let w_control = tw * 0.44;
                let w_activity = (tw - w_control - gap).max(220.0);
                ui.vertical(|ui| {
                    ui.set_min_width(w_control);
                    ui.set_max_width(w_control);
                    self.render_control_section(ui, ctx);
                });
                ui.vertical(|ui| {
                    ui.set_min_width(w_activity);
                    ui.set_max_width(w_activity);
                    if let Some(snapshot) = self.latest.clone() {
                        self.render_activity_section(ui, &snapshot);
                    } else {
                        ui.spinner();
                        ui.label("Collecting first snapshot...");
                    }
                });
            });
        } else {
            self.render_control_section(ui, ctx);
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(12.0);
            if let Some(snapshot) = self.latest.clone() {
                self.render_activity_section(ui, &snapshot);
            } else {
                ui.spinner();
                ui.label("Collecting first snapshot...");
            }
        }
    }

    fn render_overview_quick_tiles(&self, ui: &mut egui::Ui) {
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
            render_quick_tile(ui, "CPU", format!("{:.1}%", snapshot.cpu.usage_percent));
            render_quick_tile(ui, "MEM", format!("{:.0}%", mem_pct));
            render_quick_tile(ui, "DISK BW", human_bytes(total_disk_bw));
            render_quick_tile(ui, "NET BW", human_bytes(total_net_bw));
            if self.snapshot_history_enabled {
                render_quick_tile(
                    ui,
                    "HIST 1H",
                    format!("{}", self.snapshot_history_recent_hour),
                );
            }
            ui.label(
                RichText::new(format!(" {} ", highest.label()))
                    .color(sev_fg)
                    .background_color(sev_bg)
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .strong(),
            )
            .on_hover_text("Highest throughput severity across disk/network.");
        });
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
        self.poll();
        self.handle_global_shortcuts(ctx);
        ctx.request_repaint_after(Duration::from_millis(120));

        let screen = ctx.screen_rect();
        let top_scroll_cap = (screen.height() * 0.42).clamp(72.0, 320.0);

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_source("top_bar_vscroll")
                .max_height(top_scroll_cap)
                .auto_shrink([true, true])
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            icons::paint(ui, "mark", icons::MARK, 24.0);
                            ui.label(
                                RichText::new("Manticore Sentinel")
                                    .strong()
                                    .font(FontId::new(18.0, FontFamily::Proportional)),
                            );
                            ui.separator();
                            self.quick_status_chips(ui);
                        });
                        ui.add_space(6.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "Mode: OPERATOR  ·  Trust: {}  ·  Auth: {}  ·  Audit: APPEND-ONLY",
                                    self.trust_badge_text(),
                                    self.auth_mode_label
                                ))
                                .font(FontId::new(13.5, FontFamily::Proportional)),
                            )
                            .wrap(true),
                        );
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            icons::paint(ui, "security-guide-icon", icons::SHIELD, 14.0);
                            let guide = ui
                                .button("Security Guide")
                                .on_hover_text("Open security posture and destructive-action guidance.");
                            guide.widget_info(|| {
                                egui::WidgetInfo::labeled(egui::WidgetType::Button, "Security Guide")
                            });
                            if guide.clicked() {
                                self.show_onboarding = true;
                            }
                            icons::paint(ui, "help-center-icon", icons::HELP, 14.0);
                            let help = ui
                                .button("Help Center")
                                .on_hover_text("Open full in-app navigation and command help (F1).");
                            help.widget_info(|| {
                                egui::WidgetInfo::labeled(egui::WidgetType::Button, "Help Center")
                            });
                            if help.clicked() {
                                self.show_help_center = true;
                            }
                        });
                    });
                });
            ui.add_space(4.0);
        });

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
                            ui.monospace("1) Scroll the main area for metrics, command palette, processes, and audit.");
                            ui.monospace("2) Top bar shows live CPU/Mem/load chips plus Trust/Role/Auth.");
                            ui.monospace("3) Metrics: CPU (aggregate + per-core bars), memory, disk/network.");
                            ui.monospace("4) Operator shell (Ctrl/⌘+K): Tab, history, Enter — no raw shell.");
                            ui.monospace("5) Top processes and Recent Audit Events below.");
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

                    self.render_navigation_tabs(ui);
                    ui.separator();
                    ui.add_space(8.0);
                    match self.active_view {
                        DashboardView::System => self.render_system_view(ui, ctx, central_fill_w),
                        DashboardView::Processes => self.render_processes_view(ui),
                        DashboardView::Network => self.render_network_view(ui),
                        DashboardView::PeerWeave => self.render_peerweave_view(ui),
                        DashboardView::Evrus => self.render_evrus_view(ui),
                        DashboardView::Audit => self.render_audit_view(ui),
                        DashboardView::Connectors => self.render_connectors_panel(ui),
                    }

                    self.fill_vertical_remainder(ui);
                });
        });
    }
}

fn disk_throughput_rows(ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
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
            "Top devices by R+W throughput ({} combined) — showing up to 10.",
            human_bytes(total_rw)
        ))
        .weak()
        .font(FontId::new(12.0, FontFamily::Proportional)),
    );
    ui.add_space(4.0);
    for disk in rows.iter().take(10) {
        let total = disk
            .read_bytes_per_sec
            .saturating_add(disk.write_bytes_per_sec);
        let sev = throughput_severity(total);
        throughput_detail_row(
            ui,
            sev,
            format!(
                "{} R:{} W:{}",
                disk.device,
                human_bytes(disk.read_bytes_per_sec),
                human_bytes(disk.write_bytes_per_sec)
            ),
        );
    }
}

fn network_throughput_rows(ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
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
            "Top interfaces by RX+TX ({} combined) — showing up to 10.",
            human_bytes(total_io)
        ))
        .weak()
        .font(FontId::new(12.0, FontFamily::Proportional)),
    );
    ui.add_space(4.0);
    for net in rows.iter().take(10) {
        let total = net.rx_bytes_per_sec.saturating_add(net.tx_bytes_per_sec);
        let sev = throughput_severity(total);
        throughput_detail_row(
            ui,
            sev,
            format!(
                "{} RX:{} TX:{}",
                net.interface,
                human_bytes(net.rx_bytes_per_sec),
                human_bytes(net.tx_bytes_per_sec)
            ),
        );
    }
}

/// Full-width process table: fixed numeric columns, name column absorbs remaining width.
fn process_metrics_table(ui: &mut egui::Ui, processes: &[ProcessMetrics]) {
    const PID_W: f32 = 80.0;
    const CPU_W: f32 = 74.0;
    const RSS_W: f32 = 100.0;
    const THR_W: f32 = 70.0;

    let full = ui.available_width();
    ui.set_min_width(full);
    let sp = ui.spacing().item_spacing.x;
    let fixed = PID_W + CPU_W + RSS_W + THR_W + sp * 4.0;
    let name_w = (full - fixed).max(96.0);

    ui.horizontal(|ui| {
        ui.add_sized(
            [PID_W, 20.0],
            egui::Label::new(egui::RichText::new("PID").strong()),
        )
        .on_hover_text("Process ID");
        ui.add_sized(
            [name_w, 20.0],
            egui::Label::new(egui::RichText::new("Name").strong()).wrap(true),
        )
        .on_hover_text("Executable or command name");
        ui.add_sized(
            [CPU_W, 20.0],
            egui::Label::new(egui::RichText::new("CPU %").strong()),
        )
        .on_hover_text("CPU time as percent of one core");
        ui.add_sized(
            [RSS_W, 20.0],
            egui::Label::new(egui::RichText::new("RSS").strong()),
        )
        .on_hover_text("Resident set size (physical memory)");
        ui.add_sized(
            [THR_W, 20.0],
            egui::Label::new(egui::RichText::new("Threads").strong()),
        )
        .on_hover_text("Thread count");
    });
    ui.separator();

    for process in processes.iter().take(20) {
        ui.horizontal_top(|ui| {
            ui.add_sized(
                [PID_W, 20.0],
                egui::Label::new(process.pid.to_string()).wrap(false),
            );
            ui.vertical(|ui| {
                ui.set_width(name_w);
                ui.add(egui::Label::new(egui::RichText::new(process.name.as_str())).wrap(true));
            });
            ui.add_sized(
                [CPU_W, 20.0],
                egui::Label::new(format!("{:.2}", process.cpu_percent)),
            );
            ui.add_sized(
                [RSS_W, 20.0],
                egui::Label::new(human_bytes(process.memory_bytes)).wrap(false),
            );
            ui.add_sized([THR_W, 20.0], egui::Label::new(process.threads.to_string()));
        });
        ui.add_space(4.0);
    }
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

fn render_overview_metrics(ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
    // Minimum half-width before stacking pairs vertically (avoids horizontal clip).
    const MIN_CPU_MEM_COL: f32 = 168.0;
    const MIN_DISK_NET_COL: f32 = 200.0;

    let gap = ui.spacing().item_spacing.x;
    let avail_row = ui.available_width();
    let half_cpu_mem = ((avail_row - gap) * 0.5).max(0.0);
    let stack_cpu_mem = half_cpu_mem < MIN_CPU_MEM_COL;

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
                });
            });
        });
    }
    ui.add_space(8.0);

    let avail_disk = ui.available_width();
    let half_disk_net = ((avail_disk - gap) * 0.5).max(0.0);
    let stack_disk_net = half_disk_net < MIN_DISK_NET_COL;

    if stack_disk_net {
        ui.vertical(|ui| {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                throughput_panel_heading(
                    ui,
                    "panel-disk",
                    icons::DISK,
                    "Disk throughput",
                    "Per-device read/write rates with severity bands.",
                );
                disk_throughput_rows(ui, snapshot);
            });
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                throughput_panel_heading(
                    ui,
                    "panel-network",
                    icons::NETWORK,
                    "Network throughput",
                    "Per-interface receive/transmit rates and severity.",
                );
                network_throughput_rows(ui, snapshot);
            });
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
                        "panel-disk",
                        icons::DISK,
                        "Disk throughput",
                        "Per-device read/write rates with severity bands.",
                    );
                    disk_throughput_rows(ui, snapshot);
                });
            });
            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    throughput_panel_heading(
                        ui,
                        "panel-network",
                        icons::NETWORK,
                        "Network throughput",
                        "Per-interface receive/transmit rates and severity.",
                    );
                    network_throughput_rows(ui, snapshot);
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
) {
    let (action_name, target) = match action {
        CommandAction::ShowCpu => ("show_cpu", "system".to_string()),
        CommandAction::KillProcess { pid } => ("kill_process", format!("pid:{pid}")),
        CommandAction::ReniceProcess { pid, .. } => ("renice_process", format!("pid:{pid}")),
    };
    let _ = append_event(
        &helper.audit_path,
        &AuditEvent {
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
        },
    );
}

fn audit_policy_denial(
    helper: &HelperRuntime,
    action: &CommandAction,
    reason: &str,
    actor: &str,
    policy_hash: Option<String>,
) {
    let (action_name, target) = match action {
        CommandAction::ShowCpu => ("show_cpu", "system".to_string()),
        CommandAction::KillProcess { pid } => ("kill_process", format!("pid:{pid}")),
        CommandAction::ReniceProcess { pid, .. } => ("renice_process", format!("pid:{pid}")),
    };
    let _ = append_event(
        &helper.audit_path,
        &AuditEvent {
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
        },
    );
}

fn execute_action(
    helper: &HelperRuntime,
    action: CommandAction,
    actor: &str,
    policy_hash: Option<String>,
) -> String {
    match action {
        CommandAction::ShowCpu => {
            let _ = append_event(
                &helper.audit_path,
                &AuditEvent {
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
                },
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
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.window_margin = egui::Margin::same(12.0);
        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::new(14.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            FontId::new(12.5, FontFamily::Proportional),
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
