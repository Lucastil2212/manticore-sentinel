use crate::security::auth::{AuthMode, Role, TokenLifecycle};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub profile: String,
    pub privileged: bool,
    pub helper_mode: String,
    pub refresh_ms: u64,
    pub auth_mode: AuthMode,
    pub role: Role,
    pub auth_token: Option<String>,
    pub token_lifecycle: Option<TokenLifecycle>,
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
    let auth_mode_raw = std::env::var("MANTICORE_AUTH_MODE").unwrap_or_else(|_| "local".to_string());
    let auth_mode = AuthMode::from_env(&auth_mode_raw).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid MANTICORE_AUTH_MODE '{}', expected local|token",
            auth_mode_raw
        )
    })?;
    let role_raw = std::env::var("MANTICORE_ROLE").unwrap_or_else(|_| {
        if privileged {
            "admin".to_string()
        } else {
            "viewer".to_string()
        }
    });
    let role = Role::from_env(&role_raw).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid MANTICORE_ROLE '{}', expected viewer|operator|admin",
            role_raw
        )
    })?;
    let auth_token = std::env::var("MANTICORE_AUTH_TOKEN").ok().map(|v| v.trim().to_string());
    if auth_mode == AuthMode::Token {
        let Some(token) = auth_token.as_ref() else {
            return Err(anyhow::anyhow!(
                "MANTICORE_AUTH_TOKEN is required when MANTICORE_AUTH_MODE=token"
            ));
        };
        if token.len() < 12 {
            return Err(anyhow::anyhow!(
                "MANTICORE_AUTH_TOKEN must be at least 12 characters"
            ));
        }
    }
    let token_lifecycle = if auth_mode == AuthMode::Token {
        let issued_at = parse_u64_env("MANTICORE_AUTH_TOKEN_ISSUED_AT")?;
        let ttl_secs = parse_u64_env("MANTICORE_AUTH_TOKEN_TTL_SECS")?;
        if !(60..=604800).contains(&ttl_secs) {
            return Err(anyhow::anyhow!(
                "MANTICORE_AUTH_TOKEN_TTL_SECS out of range (60..=604800): {}",
                ttl_secs
            ));
        }
        let grace_secs = std::env::var("MANTICORE_AUTH_TOKEN_GRACE_SECS")
            .ok()
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|_| anyhow::anyhow!("MANTICORE_AUTH_TOKEN_GRACE_SECS must be an integer"))?
            .unwrap_or(30);
        if grace_secs > 600 {
            return Err(anyhow::anyhow!(
                "MANTICORE_AUTH_TOKEN_GRACE_SECS out of range (0..=600): {}",
                grace_secs
            ));
        }
        Some(TokenLifecycle {
            issued_at,
            ttl_secs,
            grace_secs,
        })
    } else {
        None
    };

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
        auth_mode,
        role,
        auth_token,
        token_lifecycle,
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

fn parse_u64_env(key: &str) -> anyhow::Result<u64> {
    let raw = std::env::var(key).map_err(|_| anyhow::anyhow!("{key} is required"))?;
    raw.parse::<u64>()
        .map_err(|_| anyhow::anyhow!("{key} must be an integer"))
}
