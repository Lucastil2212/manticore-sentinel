use std::time::{Duration, Instant};

use crate::core::command::CommandAction;

pub struct ExecutionPolicy {
    privileged_mode: bool,
    last_kill_at: Option<Instant>,
    kill_cooldown: Duration,
}

impl ExecutionPolicy {
    pub fn new(privileged_mode: bool) -> Self {
        Self {
            privileged_mode,
            last_kill_at: None,
            kill_cooldown: Duration::from_secs(2),
        }
    }

    pub fn evaluate(&self, action: &CommandAction) -> Result<(), String> {
        match action {
            CommandAction::ShowCpu => Ok(()),
            CommandAction::KillProcess { .. } | CommandAction::ReniceProcess { .. } => {
                if !self.privileged_mode {
                    return Err("policy denied: privileged mode required".to_string());
                }
                if let CommandAction::KillProcess { .. } = action {
                    if let Some(last) = self.last_kill_at {
                        if last.elapsed() < self.kill_cooldown {
                            return Err("policy denied: kill action in cooldown window".to_string());
                        }
                    }
                }
                Ok(())
            }
        }
    }

    pub fn record(&mut self, action: &CommandAction) {
        if matches!(action, CommandAction::KillProcess { .. }) {
            self.last_kill_at = Some(Instant::now());
        }
    }
}
