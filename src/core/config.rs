#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub profile: String,
    pub privileged: bool,
    pub helper_mode: String,
    pub refresh_ms: u64,
}

pub fn load_runtime_config() -> anyhow::Result<RuntimeConfig> {
    let profile = std::env::var("MANTICORE_PROFILE").unwrap_or_else(|_| "default".to_string());
    let privileged = parse_bool_env("MANTICORE_PRIVILEGED", false)?;
    let helper_mode = std::env::var("MANTICORE_HELPER_MODE").unwrap_or_else(|_| "embedded".to_string());
    if helper_mode != "embedded" && helper_mode != "subprocess" {
        return Err(anyhow::anyhow!(
            "invalid MANTICORE_HELPER_MODE '{}', expected embedded|subprocess",
            helper_mode
        ));
    }

    let refresh_ms = std::env::var("MANTICORE_REFRESH_MS")
        .ok()
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("MANTICORE_REFRESH_MS must be an integer"))?
        .unwrap_or(500);
    if !(100..=5000).contains(&refresh_ms) {
        return Err(anyhow::anyhow!(
            "MANTICORE_REFRESH_MS out of range (100..=5000): {}",
            refresh_ms
        ));
    }

    Ok(RuntimeConfig {
        profile,
        privileged,
        helper_mode,
        refresh_ms,
    })
}

fn parse_bool_env(key: &str, default: bool) -> anyhow::Result<bool> {
    let Some(raw) = std::env::var(key).ok() else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow::anyhow!("{key} must be a boolean-like value")),
    }
}
