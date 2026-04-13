use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub action: String,
    pub target: String,
    pub result: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

pub fn default_audit_path(root: &Path) -> PathBuf {
    root.join(".beads").join("audit").join("events.jsonl")
}

pub fn append_event(path: &Path, event: &AuditEvent) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let signing_key = load_signing_key(path)?;
    let mut signed_event = event.clone();
    if signed_event.sig.is_none() {
        signed_event.sig = Some(sign_event(&signed_event, &signing_key)?);
    }
    let line = serde_json::to_string(&signed_event)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn signing_key_path(audit_path: &Path) -> PathBuf {
    audit_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("signing.ed25519")
}

fn load_signing_key(audit_path: &Path) -> anyhow::Result<SigningKey> {
    if let Ok(raw) = std::env::var("MANTICORE_EVRUS_SIGNING_KEY") {
        return decode_signing_key(raw.trim());
    }
    let path = signing_key_path(audit_path);
    if let Ok(raw) = fs::read_to_string(&path) {
        return decode_signing_key(raw.trim());
    }
    let key = SigningKey::generate(&mut OsRng);
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    fs::write(&path, format!("{encoded}\n"))?;
    Ok(key)
}

fn decode_signing_key(encoded: &str) -> anyhow::Result<SigningKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid signing key encoding: {e}"))?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn canonical_event_payload(event: &AuditEvent) -> String {
    let mut map = Map::new();
    map.insert("action".to_string(), Value::String(event.action.clone()));
    map.insert("actor".to_string(), Value::String(event.actor.clone()));
    map.insert("result".to_string(), Value::String(event.result.clone()));
    map.insert("target".to_string(), Value::String(event.target.clone()));
    map.insert(
        "ts".to_string(),
        Value::Number(serde_json::Number::from(event.ts)),
    );
    Value::Object(map).to_string()
}

fn sign_event(event: &AuditEvent, signing_key: &SigningKey) -> anyhow::Result<String> {
    let payload = canonical_event_payload(event);
    let signature: Signature = signing_key.sign(payload.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

pub fn read_recent(path: &Path, limit: usize) -> anyhow::Result<Vec<AuditEvent>> {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let mut events = Vec::new();
    for line in raw.lines().rev().take(limit) {
        if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
            events.push(ev);
        }
    }
    Ok(events)
}

pub fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{append_event, read_recent, AuditEvent};

    fn temp_audit_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("manticore-audit-test-{}-{}.jsonl", std::process::id(), name));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn append_and_read_recent_events() {
        let path = temp_audit_file("append-read");

        let e1 = AuditEvent {
            ts: 1,
            action: "show_cpu".to_string(),
            target: "system".to_string(),
            result: "ok".to_string(),
            actor: "tester".to_string(),
            sig: None,
        };
        let e2 = AuditEvent {
            ts: 2,
            action: "kill_process".to_string(),
            target: "pid:123".to_string(),
            result: "denied".to_string(),
            actor: "tester".to_string(),
            sig: None,
        };

        append_event(&path, &e1).expect("append first");
        append_event(&path, &e2).expect("append second");

        let recent = read_recent(&path, 2).expect("read recent");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].ts, 2);
        assert_eq!(recent[1].ts, 1);
        assert!(recent[0].sig.is_some());
        assert!(recent[1].sig.is_some());

        let _ = fs::remove_file(path);
    }
}
