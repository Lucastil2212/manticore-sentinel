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
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub action: String,
    pub target: String,
    pub result: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_blockheight: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_merkle_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnchorState {
    pub last_anchor_ts: Option<u64>,
    pub last_anchor_txid: Option<String>,
    pub last_anchor_blockheight: Option<u64>,
    pub last_anchor_merkle_root: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnchorConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
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
    if let Some(policy_hash) = &event.policy_hash {
        map.insert(
            "policy_hash".to_string(),
            Value::String(policy_hash.clone()),
        );
    }
    if let Some(anchor_txid) = &event.anchor_txid {
        map.insert(
            "anchor_txid".to_string(),
            Value::String(anchor_txid.clone()),
        );
    }
    if let Some(anchor_blockheight) = event.anchor_blockheight {
        map.insert(
            "anchor_blockheight".to_string(),
            Value::Number(serde_json::Number::from(anchor_blockheight)),
        );
    }
    if let Some(anchor_merkle_root) = &event.anchor_merkle_root {
        map.insert(
            "anchor_merkle_root".to_string(),
            Value::String(anchor_merkle_root.clone()),
        );
    }
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

pub fn read_from_offset(path: &Path, offset: usize) -> anyhow::Result<(Vec<AuditEvent>, usize)> {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = raw.lines().collect();
    let mut events = Vec::new();
    for line in lines.iter().skip(offset) {
        if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
            events.push(ev);
        }
    }
    Ok((events, lines.len()))
}

pub fn current_merkle_root(path: &Path) -> anyhow::Result<Option<String>> {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for line in raw.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let canonical = canonicalize_json(&value);
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        leaves.push(hasher.finalize().into());
    }
    if leaves.is_empty() {
        return Ok(None);
    }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
            i += 2;
        }
        level = next;
    }
    Ok(Some(hex_bytes(level[0])))
}

pub fn load_anchor_state(audit_path: &Path) -> anyhow::Result<AnchorState> {
    let path = anchor_state_path(audit_path);
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(AnchorState::default()),
    };
    Ok(serde_json::from_str::<AnchorState>(&raw).unwrap_or_default())
}

pub fn anchor_audit_if_due(
    audit_path: &Path,
    actor: &str,
    config: &AnchorConfig,
) -> anyhow::Result<Option<AnchorState>> {
    let Some(merkle_root) = current_merkle_root(audit_path)? else {
        return Ok(None);
    };
    let mut state = load_anchor_state(audit_path)?;
    if state.last_anchor_merkle_root.as_deref() == Some(merkle_root.as_str()) {
        return Ok(None);
    }

    let txid = submit_op_return_anchor(config, &merkle_root)?;
    let blockheight = query_block_height(config).ok();
    let ts = now_ts();

    let event = AuditEvent {
        ts,
        action: "audit_anchor".to_string(),
        target: "audit_window".to_string(),
        result: "ok: anchored".to_string(),
        actor: actor.to_string(),
        sig: None,
        policy_hash: None,
        anchor_txid: Some(txid.clone()),
        anchor_blockheight: blockheight,
        anchor_merkle_root: Some(merkle_root.clone()),
    };
    append_event(audit_path, &event)?;

    state.last_anchor_ts = Some(ts);
    state.last_anchor_txid = Some(txid);
    state.last_anchor_blockheight = blockheight;
    state.last_anchor_merkle_root = Some(merkle_root);
    store_anchor_state(audit_path, &state)?;
    Ok(Some(state))
}

fn anchor_state_path(audit_path: &Path) -> PathBuf {
    audit_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("anchor_state.json")
}

fn store_anchor_state(audit_path: &Path, state: &AnchorState) -> anyhow::Result<()> {
    let path = anchor_state_path(audit_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

fn canonicalize_json(value: &Value) -> String {
    fn normalize(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    if let Some(inner) = map.get(&k) {
                        out.insert(k, normalize(inner));
                    }
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(normalize).collect()),
            _ => v.clone(),
        }
    }
    normalize(value).to_string()
}

fn hex_bytes(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn submit_op_return_anchor(config: &AnchorConfig, merkle_root: &str) -> anyhow::Result<String> {
    let marker = format!("sentinel:{merkle_root}");
    let hex_data = marker
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let outputs = serde_json::json!({
        "data": hex_data
    });
    let raw_tx = rpc_call(
        config,
        "createrawtransaction",
        serde_json::json!([[], outputs]),
    )?
    .as_str()
    .ok_or_else(|| anyhow::anyhow!("createrawtransaction response missing hex"))?
    .to_string();
    let funded = rpc_call(config, "fundrawtransaction", serde_json::json!([raw_tx]))?;
    let funded_hex = funded
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("fundrawtransaction response missing hex"))?
        .to_string();
    let signed = rpc_call(
        config,
        "signrawtransactionwithwallet",
        serde_json::json!([funded_hex]),
    )?;
    let signed_hex = signed
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("signrawtransactionwithwallet response missing hex"))?
        .to_string();
    let txid = rpc_call(
        config,
        "sendrawtransaction",
        serde_json::json!([signed_hex]),
    )?
    .as_str()
    .ok_or_else(|| anyhow::anyhow!("sendrawtransaction response missing txid"))?
    .to_string();
    Ok(txid)
}

fn query_block_height(config: &AnchorConfig) -> anyhow::Result<u64> {
    rpc_call(config, "getblockcount", serde_json::json!([]))?
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("getblockcount returned non-numeric result"))
}

fn rpc_call(config: &AnchorConfig, method: &str, params: Value) -> anyhow::Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "sentinel-anchor",
        "method": method,
        "params": params
    });
    let response = client
        .post(&config.rpc_url)
        .basic_auth(&config.rpc_user, Some(&config.rpc_pass))
        .json(&body)
        .send()?;
    let status = response.status();
    let value: Value = response.json()?;
    if !status.is_success() {
        return Err(anyhow::anyhow!("rpc {method} failed: HTTP {status}"));
    }
    if !value.get("error").unwrap_or(&Value::Null).is_null() {
        return Err(anyhow::anyhow!("rpc {method} error: {}", value["error"]));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
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
        p.push(format!(
            "manticore-audit-test-{}-{}.jsonl",
            std::process::id(),
            name
        ));
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
            policy_hash: None,
            anchor_txid: None,
            anchor_blockheight: None,
            anchor_merkle_root: None,
        };
        let e2 = AuditEvent {
            ts: 2,
            action: "kill_process".to_string(),
            target: "pid:123".to_string(),
            result: "denied".to_string(),
            actor: "tester".to_string(),
            sig: None,
            policy_hash: None,
            anchor_txid: None,
            anchor_blockheight: None,
            anchor_merkle_root: None,
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
