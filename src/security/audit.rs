use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub action: String,
    pub target: String,
    pub result: String,
    pub actor: String,
}

pub fn default_audit_path(root: &Path) -> PathBuf {
    root.join(".beads").join("audit").join("events.jsonl")
}

pub fn append_event(path: &Path, event: &AuditEvent) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(event)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
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
        };
        let e2 = AuditEvent {
            ts: 2,
            action: "kill_process".to_string(),
            target: "pid:123".to_string(),
            result: "denied".to_string(),
            actor: "tester".to_string(),
        };

        append_event(&path, &e1).expect("append first");
        append_event(&path, &e2).expect("append second");

        let recent = read_recent(&path, 2).expect("read recent");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].ts, 2);
        assert_eq!(recent[1].ts, 1);

        let _ = fs::remove_file(path);
    }
}
