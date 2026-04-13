use crate::security::auth::{AuthMode, Role, TokenLifecycle};

#[derive(Debug, Clone)]
pub struct PeerWeaveConfig {
    pub graphql_url: String,
    pub cap_token: Option<String>,
    pub poll_ms: u64,
}

#[derive(Debug, Clone)]
pub struct EvrusConfig {
    pub oidc_url: String,
    pub jwt: Option<String>,
    pub anchor_enabled: bool,
    pub anchor_interval_secs: u64,
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectorConfig {
    pub peerweave: Option<PeerWeaveConfig>,
    pub evrus: Option<EvrusConfig>,
}

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
    pub connectors: ConnectorConfig,
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
            "invalid MANTICORE_AUTH_MODE '{}', expected local|token|evrus",
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

    let connectors = load_connector_config();
    if auth_mode == AuthMode::Evrus {
        let evrus = connectors
            .evrus
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MANTICORE_AUTH_MODE=evrus requires EVRUS connector enabled"))?;
        if evrus.jwt.as_deref().unwrap_or("").trim().is_empty() {
            return Err(anyhow::anyhow!(
                "MANTICORE_AUTH_MODE=evrus requires MANTICORE_EVRUS_JWT"
            ));
        }
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
        connectors,
    })
}

fn load_connector_config() -> ConnectorConfig {
    let peerweave = if parse_bool_env("MANTICORE_PEERWEAVE_ENABLED", false).unwrap_or(false) {
        let graphql_url = std::env::var("MANTICORE_PEERWEAVE_GRAPHQL_URL")
            .unwrap_or_else(|_| "http://localhost:3200/graphql".to_string());
        let cap_token = std::env::var("MANTICORE_PEERWEAVE_CAP_TOKEN").ok();
        let poll_ms = std::env::var("MANTICORE_PEERWEAVE_POLL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5000)
            .clamp(1000, 30000);
        tracing::info!(
            graphql_url = %graphql_url,
            poll_ms = poll_ms,
            "PeerWeave connector enabled"
        );
        Some(PeerWeaveConfig {
            graphql_url,
            cap_token,
            poll_ms,
        })
    } else {
        None
    };

    let evrus = if parse_bool_env("MANTICORE_EVRUS_ENABLED", false).unwrap_or(false) {
        let oidc_url = std::env::var("MANTICORE_EVRUS_OIDC_URL")
            .unwrap_or_else(|_| "http://localhost:8790".to_string());
        let jwt = std::env::var("MANTICORE_EVRUS_JWT").ok();
        let anchor_enabled =
            parse_bool_env("MANTICORE_EVRUS_ANCHOR_ENABLED", false).unwrap_or(false);
        let anchor_interval_secs = std::env::var("MANTICORE_EVRUS_ANCHOR_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300)
            .clamp(30, 86_400);
        let rpc_url = std::env::var("MANTICORE_EVRUS_RPC_URL").ok();
        let rpc_user = std::env::var("MANTICORE_EVRUS_RPC_USER").ok();
        let rpc_pass = std::env::var("MANTICORE_EVRUS_RPC_PASS").ok();
        tracing::info!(
            oidc_url = %oidc_url,
            anchor_enabled = anchor_enabled,
            anchor_interval_secs = anchor_interval_secs,
            "EVRUS connector enabled"
        );
        Some(EvrusConfig {
            oidc_url,
            jwt,
            anchor_enabled,
            anchor_interval_secs,
            rpc_url,
            rpc_user,
            rpc_pass,
        })
    } else {
        None
    };

    ConnectorConfig { peerweave, evrus }
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
