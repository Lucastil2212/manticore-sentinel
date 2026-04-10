use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;

use crate::core::{
    command::{parse_command, CommandAction},
    engine::SentinelEngine,
    snapshot::SystemSnapshot,
};
use crate::security::audit::{append_event, default_audit_path, now_ts, read_recent, AuditEvent};
use crate::security::helper::{send_request, Capability, HelperRequest, HelperServer};

pub struct SentinelDashboard {
    engine: SentinelEngine,
    runtime: Runtime,
    latest: Option<SystemSnapshot>,
    last_poll: Instant,
    last_error: Option<String>,
    command_input: String,
    command_feedback: Option<String>,
    helper_server: HelperServer,
    trust_state: &'static str,
    audit_feed: Vec<AuditEvent>,
    visuals_applied: bool,
    pending_action: Option<CommandAction>,
    confirm_input: String,
    last_audit_refresh: Instant,
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
        let helper_server = HelperServer::spawn(socket_path, audit_path, capabilities)?;

        Ok(Self {
            engine: SentinelEngine::new(),
            runtime: Runtime::new()?,
            latest: None,
            last_poll: Instant::now() - Duration::from_millis(500),
            last_error: None,
            command_input: String::new(),
            command_feedback: None,
            helper_server,
            trust_state,
            audit_feed: Vec::new(),
            visuals_applied: false,
            pending_action: None,
            confirm_input: String::new(),
            last_audit_refresh: Instant::now() - Duration::from_secs(2),
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
            });
        });

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
                                    self.pending_action = Some(action);
                                    "Confirmation required for destructive action.".to_string()
                                } else {
                                    execute_action(&self.helper_server, action)
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
                                self.command_feedback =
                                    Some(execute_action(&self.helper_server, CommandAction::KillProcess { pid }));
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
                        self.audit_feed = read_recent(&self.helper_server.audit_path, 12).unwrap_or_default();
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

fn execute_action(helper_server: &HelperServer, action: CommandAction) -> String {
    match action {
        CommandAction::ShowCpu => {
            let _ = append_event(
                &helper_server.audit_path,
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
            match send_request(&helper_server.socket_path, &req) {
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
            match send_request(&helper_server.socket_path, &req) {
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
