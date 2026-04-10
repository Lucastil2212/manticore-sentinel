#[derive(Debug, Clone)]
pub enum CommandAction {
    ShowCpu,
    KillProcess { pid: u32 },
    ReniceProcess { pid: u32, nice: i32 },
}

pub fn parse_command(input: &str) -> Result<CommandAction, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("empty command".to_string());
    }
    if raw.len() > 128 {
        return Err("command too long".to_string());
    }
    if raw.contains('|') || raw.contains(';') || raw.contains('&') || raw.contains('>') || raw.contains('<') {
        return Err("shell operators are not allowed".to_string());
    }

    let tokens: Vec<&str> = raw.split_whitespace().collect();
    match tokens.as_slice() {
        ["show", "cpu"] => Ok(CommandAction::ShowCpu),
        ["kill", pid] => {
            let pid = pid.parse::<u32>().map_err(|_| "invalid pid".to_string())?;
            if pid == 0 {
                return Err("pid must be > 0".to_string());
            }
            Ok(CommandAction::KillProcess { pid })
        }
        ["renice", nice, pid] => {
            let nice = nice.parse::<i32>().map_err(|_| "invalid nice value".to_string())?;
            let pid = pid.parse::<u32>().map_err(|_| "invalid pid".to_string())?;
            if pid == 0 {
                return Err("pid must be > 0".to_string());
            }
            if !(-20..=19).contains(&nice) {
                return Err("nice must be between -20 and 19".to_string());
            }
            Ok(CommandAction::ReniceProcess { pid, nice })
        }
        _ => Err("unknown command. allowed: show cpu | kill <pid> | renice <nice> <pid>".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_command, CommandAction};

    #[test]
    fn parses_show_cpu() {
        let action = parse_command("show cpu").expect("should parse");
        assert!(matches!(action, CommandAction::ShowCpu));
    }

    #[test]
    fn rejects_shell_operators() {
        let err = parse_command("show cpu | cat").expect_err("should reject");
        assert!(err.contains("shell operators"));
    }

    #[test]
    fn rejects_zero_pid_kill() {
        let err = parse_command("kill 0").expect_err("should reject");
        assert!(err.contains("pid must be > 0"));
    }

    #[test]
    fn parses_renice_command() {
        let action = parse_command("renice 10 123").expect("should parse");
        match action {
            CommandAction::ReniceProcess { pid, nice } => {
                assert_eq!(pid, 123);
                assert_eq!(nice, 10);
            }
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn rejects_too_long_command() {
        let input = "x".repeat(200);
        let err = parse_command(&input).expect_err("should reject");
        assert!(err.contains("too long"));
    }
}
