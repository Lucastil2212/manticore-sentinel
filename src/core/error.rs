#[derive(Debug, Clone, Copy)]
pub enum ErrorCategory {
    Collector,
    Helper,
    Policy,
    Config,
    Runtime,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Collector => "collector",
            ErrorCategory::Helper => "helper",
            ErrorCategory::Policy => "policy",
            ErrorCategory::Config => "config",
            ErrorCategory::Runtime => "runtime",
        }
    }
}

pub fn classify_action_error(message: &str) -> ErrorCategory {
    if message.contains("policy denied") {
        ErrorCategory::Policy
    } else if message.contains("Helper error") || message.contains("helper") {
        ErrorCategory::Helper
    } else if message.contains("Collector error") {
        ErrorCategory::Collector
    } else if message.contains("profile") || message.contains("config") {
        ErrorCategory::Config
    } else {
        ErrorCategory::Runtime
    }
}
