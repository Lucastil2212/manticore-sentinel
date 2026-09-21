use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMode {
    Local,
    Token,
    Evrus,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Local => "local",
            AuthMode::Token => "token",
            AuthMode::Evrus => "evrus",
        }
    }

    pub fn from_env(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "local" => Some(AuthMode::Local),
            "token" => Some(AuthMode::Token),
            "evrus" => Some(AuthMode::Evrus),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn from_env(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ViewSystemMetrics,
    KillProcess,
    ReniceProcess,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthContext {
    pub mode: AuthMode,
    pub role: Role,
}

impl AuthContext {
    pub fn allows(self, permission: Permission) -> bool {
        if self.mode == AuthMode::Token && self.role == Role::Admin {
            return false;
        }
        match self.role {
            Role::Viewer => matches!(permission, Permission::ViewSystemMetrics),
            Role::Operator => {
                matches!(
                    permission,
                    Permission::ViewSystemMetrics | Permission::ReniceProcess
                )
            }
            Role::Admin => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthGate {
    context: AuthContext,
    token_secret: Option<String>,
    token_lifecycle: Option<TokenLifecycle>,
}

#[derive(Debug, Clone, Copy)]
pub struct TokenLifecycle {
    pub issued_at: u64,
    pub ttl_secs: u64,
    pub grace_secs: u64,
}

impl AuthGate {
    pub fn new(
        context: AuthContext,
        token_secret: Option<String>,
        token_lifecycle: Option<TokenLifecycle>,
    ) -> Self {
        Self {
            context,
            token_secret,
            token_lifecycle,
        }
    }

    pub fn context(&self) -> AuthContext {
        self.context
    }

    pub fn verify_submission(&self, submitted_token: Option<&str>) -> Result<(), String> {
        if self.context.mode != AuthMode::Token {
            return Ok(());
        }
        let Some(secret) = self.token_secret.as_ref() else {
            return Err("authentication failed: token mode is missing server token".to_string());
        };
        let Some(submitted) = submitted_token else {
            return Err("authentication failed: token required".to_string());
        };
        if submitted.trim().is_empty() {
            return Err("authentication failed: token required".to_string());
        }
        if submitted.trim() != secret {
            return Err("authentication failed: invalid token".to_string());
        }
        if let Some(lifecycle) = self.token_lifecycle {
            let now = now_ts();
            if now < lifecycle.issued_at {
                return Err("authentication failed: token issue time is in the future".to_string());
            }
            let age_secs = now.saturating_sub(lifecycle.issued_at);
            let max_age = lifecycle.ttl_secs.saturating_add(lifecycle.grace_secs);
            if age_secs > max_age {
                return Err("authentication failed: token expired".to_string());
            }
        }
        Ok(())
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extracts the token from `Authorization: Bearer …` (scheme is case-insensitive).
pub fn extract_bearer(authorization_header: &str) -> Option<&str> {
    let header = authorization_header.trim();
    let value = if let Some(rest) = header.strip_prefix("Bearer ") {
        rest
    } else if header.len() >= 7 && header[..7].eq_ignore_ascii_case("bearer ") {
        &header[7..]
    } else {
        return None;
    };
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Returns true only when a non-empty expected secret matches the Bearer token.
/// Empty expected secrets never authenticate (fail closed).
pub fn bearer_equals(authorization_header: Option<&str>, expected: Option<&str>) -> bool {
    let Some(expected) = expected.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(header) = authorization_header else {
        return false;
    };
    extract_bearer(header) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::{
        bearer_equals, extract_bearer, AuthContext, AuthGate, AuthMode, Permission, Role,
        TokenLifecycle,
    };

    #[test]
    fn viewer_is_read_only() {
        let ctx = AuthContext {
            mode: AuthMode::Local,
            role: Role::Viewer,
        };
        assert!(ctx.allows(Permission::ViewSystemMetrics));
        assert!(!ctx.allows(Permission::KillProcess));
        assert!(!ctx.allows(Permission::ReniceProcess));
    }

    #[test]
    fn operator_can_renice_but_not_kill() {
        let ctx = AuthContext {
            mode: AuthMode::Local,
            role: Role::Operator,
        };
        assert!(ctx.allows(Permission::ViewSystemMetrics));
        assert!(ctx.allows(Permission::ReniceProcess));
        assert!(!ctx.allows(Permission::KillProcess));
    }

    #[test]
    fn token_mode_never_allows_admin_destructive_actions() {
        let ctx = AuthContext {
            mode: AuthMode::Token,
            role: Role::Admin,
        };
        assert!(!ctx.allows(Permission::KillProcess));
        assert!(!ctx.allows(Permission::ReniceProcess));
    }

    #[test]
    fn token_gate_requires_matching_token() {
        let gate = AuthGate::new(
            AuthContext {
                mode: AuthMode::Token,
                role: Role::Operator,
            },
            Some("sentinel-secret".to_string()),
            None,
        );
        let err = gate
            .verify_submission(Some("wrong-secret"))
            .expect_err("mismatch should fail");
        assert!(err.contains("invalid token"));
        gate.verify_submission(Some("sentinel-secret"))
            .expect("matching token should pass");
    }

    #[test]
    fn token_gate_rejects_expired_token() {
        let gate = AuthGate::new(
            AuthContext {
                mode: AuthMode::Token,
                role: Role::Operator,
            },
            Some("sentinel-secret".to_string()),
            Some(TokenLifecycle {
                issued_at: 1,
                ttl_secs: 1,
                grace_secs: 0,
            }),
        );
        let err = gate
            .verify_submission(Some("sentinel-secret"))
            .expect_err("expired token should fail");
        assert!(err.contains("expired"));
    }

    #[test]
    fn extract_bearer_is_case_insensitive() {
        assert_eq!(extract_bearer("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("BEARER abc"), Some("abc"));
        assert_eq!(extract_bearer("Basic abc"), None);
        assert_eq!(extract_bearer("Bearer "), None);
    }

    #[test]
    fn bearer_equals_fails_closed_on_empty_secret() {
        assert!(!bearer_equals(Some("Bearer secret"), None));
        assert!(!bearer_equals(Some("Bearer secret"), Some("")));
        assert!(!bearer_equals(None, Some("secret")));
        assert!(!bearer_equals(Some("Bearer other"), Some("secret")));
        assert!(bearer_equals(Some("Bearer secret"), Some("secret")));
    }
}
