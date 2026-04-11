use std::time::{Duration, Instant};

use eframe::egui;
use egui::{FontFamily, FontId, RichText};
use egui_extras::install_image_loaders;
use tokio::runtime::Runtime;

use crate::core::{
    command::{parse_command, CommandAction},
    config::load_runtime_config,
    engine::SentinelEngine,
    error::classify_action_error,
    policy::ExecutionPolicy,
    snapshot::SystemSnapshot,
};
use crate::models::process::ProcessMetrics;
use crate::security::audit::{append_event, default_audit_path, now_ts, read_recent, AuditEvent};
use crate::security::auth::{AuthContext, AuthGate, AuthMode};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperRuntime};
use tracing::{error, info, warn};

use super::icons;

const ID_COMMAND_INPUT: &str = "command_palette_input";

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
            last_command_feedback_announced: None,
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

    fn run_command_palette_action(&mut self) {
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
                .on_hover_text("Live snapshot: utilization, memory percent of total, and 1/5/15 load.");
            }
            None => {
                ui.label(RichText::new("Collecting…").font(body).weak());
            }
        }
    }

    fn render_command_workbench(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.group(|ui| {
            let panel_w = ui.available_width();
            ui.set_min_width(panel_w);
            ui.horizontal_wrapped(|ui| {
                icons::paint(ui, "command", icons::COMMAND, 15.0);
                ui.label("Command Palette (capability-gated)")
                    .on_hover_text("Enter approved commands only. Parsing blocks shell operators.");
            });
            ui.add(
                egui::Label::new("Allowed: show cpu | renice <nice> <pid> | kill <pid>")
                    .wrap(true),
            )
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
                ui.vertical(|ui| {
                    let tok_lbl = ui
                        .label("Auth Token")
                        .on_hover_text("Required in token mode. Input is masked.");
                    let token_w = ui.available_width().max(120.0);
                    let te = egui::TextEdit::singleline(&mut self.auth_token_input)
                        .password(true)
                        .hint_text("required in token auth mode")
                        .desired_width(token_w);
                    ui.add(te).labelled_by(tok_lbl.id);
                });
            }
            let cmd_row_room = panel_w;
            if cmd_row_room >= 520.0 {
                ui.horizontal(|ui| {
                    let cmd_lbl = ui
                        .label("Command")
                        .on_hover_text("Single-line operator command; press Enter or Execute.");
                    let btn_reserve = 96.0 + ui.spacing().item_spacing.x * 2.0;
                    let edit_w = (ui.available_width() - btn_reserve).max(160.0);
                    let response = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.command_input)
                                .id(egui::Id::new(ID_COMMAND_INPUT))
                                .desired_width(edit_w)
                                .hint_text("e.g. show cpu"),
                        )
                        .labelled_by(cmd_lbl.id);
                    let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    response.on_hover_text("Type one command at a time.");
                    let exec = ui
                        .button("Execute")
                        .on_hover_text("Validate, authorize, and execute command.");
                    exec.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, "Execute command"));
                    if exec.clicked() || enter {
                        self.run_command_palette_action();
                    }
                });
            } else {
                ui.vertical(|ui| {
                    let cmd_lbl = ui
                        .label("Command")
                        .on_hover_text("Single-line operator command; press Enter or Execute.");
                    let edit_w = ui.available_width().max(120.0);
                    let response = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.command_input)
                                .id(egui::Id::new(ID_COMMAND_INPUT))
                                .desired_width(edit_w)
                                .hint_text("e.g. show cpu"),
                        )
                        .labelled_by(cmd_lbl.id);
                    let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    response.on_hover_text("Type one command at a time.");
                    ui.horizontal(|ui| {
                        let exec = ui
                            .button("Execute")
                            .on_hover_text("Validate, authorize, and execute command.");
                        exec.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, "Execute command")
                        });
                        if exec.clicked() || enter {
                            self.run_command_palette_action();
                        }
                    });
                });
            }
            if let Some(CommandAction::KillProcess { pid }) = self.pending_action.clone() {
                let required = format!("KILL {}", pid);
                ui.colored_label(
                    egui::Color32::from_rgb(208, 72, 64),
                    format!("Type `{required}` to confirm kill request"),
                );
                ui.horizontal_wrapped(|ui| {
                    let kill_lbl = ui.label("Kill confirmation");
                    let confirm_w =
                        (ui.available_width() - 200.0 - ui.spacing().item_spacing.x * 4.0).max(100.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.confirm_input)
                            .desired_width(confirm_w)
                            .hint_text(&required),
                    )
                    .labelled_by(kill_lbl.id);
                    let conf = ui
                        .button("Confirm")
                        .on_hover_text("Execute confirmed kill action if policy/auth pass.");
                    conf.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, "Confirm kill"));
                    if conf.clicked() {
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
                    let cancel = ui
                        .button("Cancel")
                        .on_hover_text("Clear pending destructive action (Esc).");
                    cancel.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, "Cancel kill"));
                    if cancel.clicked() {
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
                if self.last_command_feedback_announced.as_ref() != Some(msg) {
                    self.last_command_feedback_announced = Some(msg.clone());
                    let mut info = egui::WidgetInfo::new(egui::WidgetType::Label);
                    info.label = Some(format!("Command result: {msg}"));
                    ctx.output_mut(|o| {
                        o.events
                            .push(egui::output::OutputEvent::ValueChanged(info));
                    });
                }
                let status = ui
                    .add(
                        egui::Label::new(egui::RichText::new(msg).monospace())
                            .wrap(true)
                            .sense(egui::Sense::hover()),
                    )
                    .on_hover_text(
                        "Latest command outcome; assistive tech is notified when this text changes.",
                    );
                status.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Label, format!("Command result: {msg}"))
                });
            }
            let collapsed = egui::CollapsingHeader::new("Advanced Controls").default_open(false);
            let adv = collapsed.show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    icons::paint(ui, "settings", icons::SETTINGS, 14.0);
                    ui.label("Power-user diagnostics and runtime metadata");
                });
                ui.add(
                    egui::Label::new(format!("helper_socket={}", self.helper.socket_path.display()))
                        .wrap(true),
                );
                ui.add(
                    egui::Label::new(format!("audit_path={}", self.helper.audit_path.display()))
                        .wrap(true),
                );
                ui.monospace(format!("auth_failures={}", self.auth_failures));
                ui.monospace(format!(
                    "auth_lockout_active={}",
                    self.auth_locked_until.map(|t| t > Instant::now()).unwrap_or(false)
                ));
                ui.add(
                    egui::Label::new(format!("runtime={}", self.runtime_diagnostics)).wrap(true),
                );
            });
            adv.header_response
                .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, "Advanced Controls"));
        });
    }

    fn render_control_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "section-command", icons::COMMAND, 18.0);
            ui.heading("Control");
        });
        ui.label(
            egui::RichText::new("Command palette, auth, and execution feedback.").weak(),
        );
        ui.add_space(8.0);
        self.render_command_workbench(ui, ctx);
    }

    fn render_activity_section(&mut self, ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "section-activity", icons::AUDIT, 18.0);
            ui.heading("Activity");
        });
        ui.label(
            egui::RichText::new("Top processes and append-only audit trail.").weak(),
        );
        ui.add_space(8.0);
        self.render_activity_panels(ui, snapshot);
    }

    fn render_activity_panels(&mut self, ui: &mut egui::Ui, snapshot: &SystemSnapshot) {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            icons::paint(ui, "command-process", icons::COMMAND, 14.0);
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
                egui::RichText::new("No audit events recorded yet. Helper actions and auth denials appear here.")
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
                                    "Mode: OPERATOR  ·  Trust: {}  ·  Role: {}  ·  Auth: {}  ·  Audit: APPEND-ONLY",
                                    self.trust_state, self.role_label, self.auth_mode_label
                                ))
                                .font(FontId::new(13.5, FontFamily::Proportional)),
                            )
                            .wrap(true),
                        );
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            let guide = ui
                                .button("Security Guide")
                                .on_hover_text("Open security posture and destructive-action guidance.");
                            guide.widget_info(|| {
                                egui::WidgetInfo::labeled(egui::WidgetType::Button, "Security Guide")
                            });
                            if guide.clicked() {
                                self.show_onboarding = true;
                            }
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
                        ui.add_space(4.0);
                        let diag = ui
                            .add(
                                egui::Label::new(
                                    RichText::new(format!("Diag: {}", self.runtime_diagnostics))
                                        .font(FontId::new(11.5, FontFamily::Monospace))
                                        .color(egui::Color32::from_rgb(158, 168, 180)),
                                )
                                .wrap(true),
                            )
                            .on_hover_text("Runtime configuration string for support and troubleshooting.");
                        diag.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Label, "Runtime diagnostics")
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
                            ui.monospace("- Ctrl/⌘+K focuses the command field.");
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
                            ui.monospace("4) Command Palette (Ctrl/⌘+K) for safe actions.");
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
                            ui.monospace("Ctrl/⌘+K — focus command field");
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

                    ui.horizontal_wrapped(|ui| {
                        icons::paint(ui, "overview-radar", icons::RADAR, 18.0);
                        ui.heading("Overview");
                    });
                    ui.label(
                        egui::RichText::new("CPU, memory, disk, and network at a glance.")
                            .weak(),
                    );
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
    for disk in snapshot.disks.iter().take(6) {
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
    for net in snapshot.network.iter().take(6) {
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
                ui.add(
                    egui::Label::new(egui::RichText::new(process.name.as_str()))
                        .wrap(true),
                );
            });
            ui.add_sized(
                [CPU_W, 20.0],
                egui::Label::new(format!("{:.2}", process.cpu_percent)),
            );
            ui.add_sized(
                [RSS_W, 20.0],
                egui::Label::new(human_bytes(process.memory_bytes)).wrap(false),
            );
            ui.add_sized(
                [THR_W, 20.0],
                egui::Label::new(process.threads.to_string()),
            );
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

fn throughput_panel_heading(ui: &mut egui::Ui, icon_key: &str, icon_bytes: &'static [u8], title: &str, tip: &str) {
    ui.horizontal_top(|ui| {
        icons::paint(ui, icon_key, icon_bytes, 18.0);
        ui.add(
            egui::Label::new(RichText::new(title).strong().font(FontId::new(14.0, FontFamily::Proportional)))
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
            });
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                icons::paint(ui, "shield", icons::SHIELD, 16.0);
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
                    let mut info =
                        egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator);
                    info.label = Some(format!("Memory usage {mem_pct} percent"));
                    info
                });
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
                });
            });
            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    icons::paint(ui, "shield", icons::SHIELD, 16.0);
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
                        let mut info =
                            egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator);
                        info.label = Some(format!("Memory usage {mem_pct} percent"));
                        info
                    });
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
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::new(12.5, FontFamily::Proportional));
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
