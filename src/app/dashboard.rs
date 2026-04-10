use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;

use crate::core::{
    command::{parse_command, CommandAction},
    engine::SentinelEngine,
    policy::ExecutionPolicy,
    snapshot::SystemSnapshot,
};
use crate::security::audit::{append_event, default_audit_path, now_ts, read_recent, AuditEvent};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperRuntime};

pub struct SentinelDashboard {
    engine: SentinelEngine,
    runtime: Runtime,
    latest: Option<SystemSnapshot>,
    last_poll: Instant,
    last_error: Option<String>,
    command_input: String,
    command_feedback: Option<String>,
    helper: HelperRuntime,
    trust_state: &'static str,
    audit_feed: Vec<AuditEvent>,
    visuals_applied: bool,
    pending_action: Option<CommandAction>,
    confirm_input: String,
    last_audit_refresh: Instant,
    policy: ExecutionPolicy,
    show_onboarding: bool,
}

impl SentinelDashboard {
    pub fn new() -> anyhow::Result<Self> {
        let allow_privileged = std::env::var("MANTICORE_PRIVILEGED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
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
        let helper_mode = std::env::var("MANTICORE_HELPER_MODE").unwrap_or_else(|_| "embedded".to_string());
        let helper = if helper_mode.eq_ignore_ascii_case("subprocess") {
            HelperRuntime::start_subprocess(socket_path, audit_path, capabilities)?
        } else {
            HelperRuntime::start_embedded(socket_path, audit_path, capabilities)?
        };

        Ok(Self {
            engine: SentinelEngine::new(),
            runtime: Runtime::new()?,
            latest: None,
            last_poll: Instant::now() - Duration::from_millis(500),
            last_error: None,
            command_input: String::new(),
            command_feedback: None,
            helper,
            trust_state,
            audit_feed: Vec::new(),
            visuals_applied: false,
            pending_action: None,
            confirm_input: String::new(),
            last_audit_refresh: Instant::now() - Duration::from_secs(2),
            policy: ExecutionPolicy::new(allow_privileged),
            show_onboarding: true,
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
                ui.label("Audit: APPEND-ONLY");
                ui.separator();
                if ui.button("Security Guide").clicked() {
                    self.show_onboarding = true;
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

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.group(|ui| {
                ui.label("Command Palette (capability-gated)");
                ui.horizontal(|ui| {
                    let response = ui.text_edit_singleline(&mut self.command_input);
                    let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Execute").clicked() || enter {
                        self.command_feedback = Some(match parse_command(&self.command_input) {
                            Ok(action) => {
                                if matches!(action, CommandAction::KillProcess { .. }) {
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
                        if ui.button("Confirm").clicked() {
                            if self.confirm_input.trim() == required {
                                let action = CommandAction::KillProcess { pid };
                                self.command_feedback = Some(match self.policy.evaluate(&action) {
                                    Ok(()) => {
                                        let output = execute_action(&self.helper, action.clone());
                                        self.policy.record(&action);
                                        output
                                    }
                                    Err(err) => err,
                                });
                                self.pending_action = None;
                                self.confirm_input.clear();
                            } else {
                                self.command_feedback = Some("Confirmation mismatch.".to_string());
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_action = None;
                            self.confirm_input.clear();
                            self.command_feedback = Some("Action canceled.".to_string());
                        }
                    });
                }
                if let Some(msg) = &self.command_feedback {
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
                            ui.label("CPU");
                            ui.heading(format!("{:.2}%", snapshot.cpu.usage_percent));
                            ui.label(format!(
                                "load {:.2} {:.2} {:.2}",
                                snapshot.cpu.load_avg.0, snapshot.cpu.load_avg.1, snapshot.cpu.load_avg.2
                            ));
                        });

                        ui.group(|ui| {
                            ui.label("Memory");
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
                            ui.label("Disk Throughput");
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
                            ui.label("Network Throughput");
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
                    ui.heading("Top Processes (CPU)");
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
                    ui.heading("Recent Audit Events");
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
