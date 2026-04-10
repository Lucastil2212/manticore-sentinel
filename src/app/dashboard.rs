use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;

use crate::core::{
    command::{parse_command, CommandAction},
    config::load_runtime_config,
    engine::SentinelEngine,
    error::classify_action_error,
    policy::ExecutionPolicy,
    snapshot::SystemSnapshot,
};
use crate::security::audit::{append_event, default_audit_path, now_ts, read_recent, AuditEvent};
use crate::security::auth::{AuthContext, AuthGate, AuthMode};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperRuntime};
use tracing::{error, info, warn};

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
}

impl SentinelDashboard {
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
        let socket_path = std::env::temp_dir().join(format!("manticore-sentinel-{}.sock", std::process::id()));
        let helper_mode = cfg.helper_mode.clone();
        let helper = if helper_mode.eq_ignore_ascii_case("subprocess") {
            HelperRuntime::start_subprocess(socket_path, audit_path, capabilities)?
        } else {
            HelperRuntime::start_embedded(socket_path, audit_path, capabilities)?
        };
        let auth = AuthContext {
            mode: cfg.auth_mode,
            role: cfg.role,
        };
        let auth_gate = AuthGate::new(auth, cfg.auth_token.clone(), cfg.token_lifecycle);
        let runtime_diagnostics = format!(
            "profile={} privileged={} helper_mode={} refresh_ms={} role={} auth_mode={} token_ttl_secs={}",
            cfg.profile,
            cfg.privileged,
            cfg.helper_mode,
            cfg.refresh_ms,
            cfg.role.as_str(),
            cfg.auth_mode.as_str(),
            cfg.token_lifecycle.map(|t| t.ttl_secs).unwrap_or(0)
        );

        Ok(Self {
            engine: SentinelEngine::new(),
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
            policy: ExecutionPolicy::new(auth),
            auth_gate,
            auth_failures: 0,
            auth_locked_until: None,
            show_onboarding: true,
            show_help_center: false,
            runtime_diagnostics,
        })
    }

    fn poll(&mut self) {
        if self.last_poll.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.last_poll = Instant::now();

        match self.runtime.block_on(self.engine.collect()) {
            Ok(snapshot) => {
                self.latest = Some(snapshot);
                self.last_error = None;
            }
            Err(err) => {
                self.last_error = Some(err.to_string());
                error!(category = "collector", message = %err, "snapshot collection failed");
            }
        }
    }

    fn verify_auth_submission(&mut self, action: &CommandAction) -> Result<(), String> {
        if let Some(until) = self.auth_locked_until {
            if Instant::now() < until {
                let remaining = until.saturating_duration_since(Instant::now()).as_secs();
                let reason = format!("authentication locked: retry in {}s", remaining.max(1));
                audit_auth_failure(&self.helper, action, &reason);
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
                audit_auth_failure(&self.helper, action, &err);
                Err(err)
            }
        }
    }
}

impl eframe::App for SentinelDashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.visuals_applied {
            apply_security_visuals(ctx);
            self.visuals_applied = true;
        }
        self.poll();
        ctx.request_repaint_after(Duration::from_millis(120));

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Manticore Sentinel");
                ui.separator();
                ui.label("Mode: OPERATOR");
                ui.separator();
                ui.label(format!("Trust: {}", self.trust_state));
                ui.separator();
                ui.label(format!("Role: {}", self.role_label));
                ui.separator();
                ui.label(format!("Auth: {}", self.auth_mode_label));
                ui.separator();
                ui.label("Audit: APPEND-ONLY");
                ui.separator();
                ui.label(format!("Diag: {}", self.runtime_diagnostics));
                ui.separator();
                if ui
                    .button("Security Guide")
                    .on_hover_text("Open security posture and destructive-action guidance.")
                    .clicked()
                {
                    self.show_onboarding = true;
                }
                if ui
                    .button("Help Center")
                    .on_hover_text("Open full in-app navigation and command help.")
                    .clicked()
                {
                    self.show_help_center = true;
                }
            });
        });

        if self.show_onboarding {
            egui::Window::new("Operator Security Guide")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
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
                    if ui.button("Acknowledge").clicked() {
                        self.show_onboarding = false;
                    }
                });
        }
        if self.show_help_center {
            egui::Window::new("Help Center")
                .collapsible(true)
                .resizable(true)
                .default_size(egui::vec2(560.0, 460.0))
                .show(ctx, |ui| {
                    ui.heading("Quick Start");
                    ui.monospace("1) Check top bar for Trust, Role, and Auth mode.");
                    ui.monospace("2) Watch CPU/Memory cards for live system health.");
                    ui.monospace("3) Review Disk/Network throughput severity badges.");
                    ui.monospace("4) Use Command Palette for safe actions.");
                    ui.monospace("5) Read Recent Audit Events to verify outcomes.");
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
                    if ui.button("Close Help").on_hover_text("Close help window.").clicked() {
                        self.show_help_center = false;
                    }
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.group(|ui| {
                ui.label("Command Palette (capability-gated)")
                    .on_hover_text("Enter approved commands only. Parsing blocks shell operators.");
                ui.label("Allowed: show cpu | renice <nice> <pid> | kill <pid>")
                    .on_hover_text("Kill actions require typed confirmation and policy authorization.");
                if self.auth_gate.context().mode == AuthMode::Token {
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
                    ui.horizontal(|ui| {
                        ui.label("Auth Token")
                            .on_hover_text("Required in token mode. Input is masked.");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.auth_token_input)
                                .password(true)
                                .hint_text("required in token auth mode"),
                        );
                    });
                }
                ui.horizontal(|ui| {
                    let response = ui.text_edit_singleline(&mut self.command_input);
                    let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    response.on_hover_text("Type one command at a time.");
                    if ui
                        .button("Execute")
                        .on_hover_text("Validate, authorize, and execute command.")
                        .clicked()
                        || enter
                    {
                        self.command_feedback = Some(match parse_command(&self.command_input) {
                            Ok(action) => {
                                if let Err(err) = self.verify_auth_submission(&action) {
                                    err
                                } else if matches!(action, CommandAction::KillProcess { .. }) {
                                    if let Err(err) = self.policy.evaluate(&action) {
                                        err
                                    } else {
                                        self.pending_action = Some(action);
                                        "Confirmation required for destructive action.".to_string()
                                    }
                                } else {
                                    match self.policy.evaluate(&action) {
                                        Ok(()) => {
                                            let output = execute_action(&self.helper, action.clone());
                                            self.policy.record(&action);
                                            output
                                        }
                                        Err(err) => err,
                                    }
                                }
                            }
                            Err(err) => format!("Invalid: {err}"),
                        });
                    }
                });
                if let Some(CommandAction::KillProcess { pid }) = self.pending_action.clone() {
                    let required = format!("KILL {}", pid);
                    ui.colored_label(
                        egui::Color32::from_rgb(208, 72, 64),
                        format!("Type `{required}` to confirm kill request"),
                    );
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.confirm_input);
                        if ui
                            .button("Confirm")
                            .on_hover_text("Execute confirmed kill action if policy/auth pass.")
                            .clicked()
                        {
                            if self.confirm_input.trim() == required {
                                let action = CommandAction::KillProcess { pid };
                                self.command_feedback = Some(match self.verify_auth_submission(&action) {
                                    Err(err) => err,
                                    Ok(()) => match self.policy.evaluate(&action) {
                                        Ok(()) => {
                                            let output = execute_action(&self.helper, action.clone());
                                            self.policy.record(&action);
                                            output
                                        }
                                        Err(err) => err,
                                    },
                                });
                                self.pending_action = None;
                                self.confirm_input.clear();
                            } else {
                                self.command_feedback = Some("Confirmation mismatch.".to_string());
                            }
                        }
                        if ui
                            .button("Cancel")
                            .on_hover_text("Clear pending destructive action.")
                            .clicked()
                        {
                            self.pending_action = None;
                            self.confirm_input.clear();
                            self.command_feedback = Some("Action canceled.".to_string());
                        }
                    });
                }
                if let Some(msg) = &self.command_feedback {
                    let cat = classify_action_error(msg);
                    if msg.starts_with("DENIED") || msg.starts_with("Invalid") || msg.contains("denied") {
                        warn!(category = cat.as_str(), message = %msg, "command feedback");
                    } else {
                        info!(category = cat.as_str(), message = %msg, "command feedback");
                    }
                    ui.monospace(msg);
                }
            });
            ui.separator();

            if let Some(err) = &self.last_error {
                ui.colored_label(egui::Color32::from_rgb(220, 76, 70), format!("Collector error: {err}"));
                ui.separator();
            }

            match &self.latest {
                Some(snapshot) => {
                    ui.horizontal(|ui| {
                        ui.group(|ui| {
                            ui.label("CPU")
                                .on_hover_text("Current aggregate processor utilization and load.");
                            ui.heading(format!("{:.2}%", snapshot.cpu.usage_percent));
                            ui.label(format!(
                                "load {:.2} {:.2} {:.2}",
                                snapshot.cpu.load_avg.0, snapshot.cpu.load_avg.1, snapshot.cpu.load_avg.2
                            ))
                            .on_hover_text("Load averages for 1, 5, and 15 minute windows.");
                        });

                        ui.group(|ui| {
                            ui.label("Memory")
                                .on_hover_text("Resident memory usage versus total detected memory.");
                            ui.heading(format!(
                                "{} / {}",
                                human_bytes(snapshot.memory.used),
                                human_bytes(snapshot.memory.total)
                            ));
                            let mem_ratio = if snapshot.memory.total == 0 {
                                0.0
                            } else {
                                snapshot.memory.used as f32 / snapshot.memory.total as f32
                            };
                            ui.add(egui::ProgressBar::new(mem_ratio).show_percentage());
                        });
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.group(|ui| {
                            ui.label("Disk Throughput")
                                .on_hover_text("Per-device read/write rates with severity bands.");
                            for disk in snapshot.disks.iter().take(6) {
                                let total = disk
                                    .read_bytes_per_sec
                                    .saturating_add(disk.write_bytes_per_sec);
                                let sev = throughput_severity(total);
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        severity_color(sev),
                                        format!("[{}]", sev.label()),
                                    );
                                    ui.monospace(format!(
                                        "{} R:{} W:{}",
                                        disk.device,
                                        human_bytes(disk.read_bytes_per_sec),
                                        human_bytes(disk.write_bytes_per_sec)
                                    ));
                                });
                            }
                        });
                        ui.group(|ui| {
                            ui.label("Network Throughput")
                                .on_hover_text("Per-interface receive/transmit rates and severity.");
                            for net in snapshot.network.iter().take(6) {
                                let total = net
                                    .rx_bytes_per_sec
                                    .saturating_add(net.tx_bytes_per_sec);
                                let sev = throughput_severity(total);
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        severity_color(sev),
                                        format!("[{}]", sev.label()),
                                    );
                                    ui.monospace(format!(
                                        "{} RX:{} TX:{}",
                                        net.interface,
                                        human_bytes(net.rx_bytes_per_sec),
                                        human_bytes(net.tx_bytes_per_sec)
                                    ));
                                });
                            }
                        });
                    });

                    ui.separator();
                    ui.heading("Top Processes (CPU)")
                        .on_hover_text("Highest CPU consumers in current snapshot.");
                    egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        egui::Grid::new("proc_grid").striped(true).show(ui, |ui| {
                            ui.strong("PID");
                            ui.strong("Name");
                            ui.strong("CPU %");
                            ui.strong("RSS");
                            ui.strong("Threads");
                            ui.end_row();

                            for process in snapshot.processes.iter().take(20) {
                                ui.label(process.pid.to_string());
                                ui.label(&process.name);
                                ui.label(format!("{:.2}", process.cpu_percent));
                                ui.label(human_bytes(process.memory_bytes));
                                ui.label(process.threads.to_string());
                                ui.end_row();
                            }
                        });
                    });
                    ui.separator();
                    ui.heading("Recent Audit Events")
                        .on_hover_text("Append-only trail for helper and auth-gate outcomes.");
                    if self.last_audit_refresh.elapsed() >= Duration::from_secs(1) {
                        self.audit_feed = read_recent(&self.helper.audit_path, 12).unwrap_or_default();
                        self.last_audit_refresh = Instant::now();
                    }
                    egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                        for event in &self.audit_feed {
                            ui.monospace(format!(
                                "[{}] action={} target={} result={}",
                                event.ts, event.action, event.target, event.result
                            ));
                        }
                    });
                }
                None => {
                    ui.label("Collecting first snapshot...");
                }
            }
        });
    }
}

fn audit_auth_failure(helper: &HelperRuntime, action: &CommandAction, reason: &str) {
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
            actor: "operator".to_string(),
        },
    );
}

fn execute_action(helper: &HelperRuntime, action: CommandAction) -> String {
    match action {
        CommandAction::ShowCpu => {
            let _ = append_event(
                &helper.audit_path,
                &AuditEvent {
                    ts: now_ts(),
                    action: "show_cpu".to_string(),
                    target: "system".to_string(),
                    result: "ok: local read action".to_string(),
                    actor: "operator".to_string(),
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
                Ok(resp) => format!("{}: {}", if resp.ok { "OK" } else { "DENIED" }, resp.message),
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
                Ok(resp) => format!("{}: {}", if resp.ok { "OK" } else { "DENIED" }, resp.message),
                Err(err) => format!("Helper error: {err}"),
            }
        }
    }
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
    visuals.override_text_color = Some(egui::Color32::from_rgb(208, 216, 222));
    visuals.panel_fill = egui::Color32::from_rgb(13, 18, 24);
    visuals.window_fill = egui::Color32::from_rgb(13, 18, 24);
    visuals.extreme_bg_color = egui::Color32::from_rgb(7, 11, 16);
    visuals.faint_bg_color = egui::Color32::from_rgb(20, 27, 35);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(44, 84, 103);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(31, 56, 70);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(19, 33, 44);
    visuals.hyperlink_color = egui::Color32::from_rgb(96, 176, 210);
    ctx.set_visuals(visuals);
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

fn severity_color(severity: ThroughputSeverity) -> egui::Color32 {
    match severity {
        ThroughputSeverity::Nominal => egui::Color32::from_rgb(96, 176, 210),
        ThroughputSeverity::Elevated => egui::Color32::from_rgb(220, 176, 64),
        ThroughputSeverity::Critical => egui::Color32::from_rgb(208, 72, 64),
    }
}
