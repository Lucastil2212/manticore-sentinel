use std::time::{Duration, Instant};

use crate::core::command::CommandAction;
use crate::security::auth::{AuthContext, Permission};

pub struct ExecutionPolicy {
    auth: AuthContext,
    last_kill_at: Option<Instant>,
    kill_cooldown: Duration,
}

impl ExecutionPolicy {
    pub fn new(auth: AuthContext) -> Self {
        Self {
            auth,
            last_kill_at: None,
            kill_cooldown: Duration::from_secs(2),
        }
    }

    pub fn evaluate(&self, action: &CommandAction) -> Result<(), String> {
        let permission = match action {
            CommandAction::ShowCpu => Permission::ViewSystemMetrics,
            CommandAction::KillProcess { .. } => Permission::KillProcess,
            CommandAction::ReniceProcess { .. } => Permission::ReniceProcess,
        };
        if !self.auth.allows(permission) {
            return Err(format!(
                "policy denied: role={} mode={} missing permission for {:?}",
                self.auth.role.as_str(),
                self.auth.mode.as_str(),
                permission
            ));
        }
        match action {
            CommandAction::ShowCpu => Ok(()),
            CommandAction::KillProcess { .. } | CommandAction::ReniceProcess { .. } => {
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
