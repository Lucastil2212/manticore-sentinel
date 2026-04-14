use crate::core::snapshot::SystemSnapshot;
use anyhow::Context;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct SnapshotHistoryRetention {
    pub max_entries: usize,
    pub max_age_secs: Option<u64>,
    pub max_bytes: Option<u64>,
    pub slim_records: bool,
}

pub fn default_snapshot_history_path(root: &Path) -> PathBuf {
    root.join(".beads").join("state").join("snapshots.jsonl")
}

pub fn append_snapshot(
    path: &Path,
    snapshot: &SystemSnapshot,
    retention: SnapshotHistoryRetention,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    let line = if retention.slim_records {
        serde_json::to_string(&SnapshotHistoryRecord::from_snapshot(snapshot))
            .context("serialize snapshot history record")?
    } else {
        serde_json::to_string(snapshot).context("serialize snapshot")?
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(f, "{line}").with_context(|| format!("append {}", path.display()))?;
    compact(path, retention, snapshot.timestamp)?;
    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotHistoryRecord {
    timestamp: u64,
    host_id: String,
    cpu_usage_percent: f32,
    memory_used: u64,
    memory_total: u64,
    process_count: usize,
}

impl SnapshotHistoryRecord {
    fn from_snapshot(snapshot: &SystemSnapshot) -> Self {
        Self {
            timestamp: snapshot.timestamp,
            host_id: snapshot.host_id.clone(),
            cpu_usage_percent: snapshot.cpu.usage_percent,
            memory_used: snapshot.memory.used,
            memory_total: snapshot.memory.total,
            process_count: snapshot.processes.len(),
        }
    }
}

#[allow(dead_code)]
pub fn read_since(path: &Path, min_timestamp: u64) -> anyhow::Result<Vec<SystemSnapshot>> {
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let snapshot: SystemSnapshot =
            serde_json::from_str(line).context("parse snapshot history line")?;
        if snapshot.timestamp >= min_timestamp {
            out.push(snapshot);
        }
    }
    Ok(out)
}

pub fn count_since(path: &Path, min_timestamp: u64) -> anyhow::Result<usize> {
    let file = match File::open(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };

    #[derive(serde::Deserialize)]
    struct SnapshotTimestampOnly {
        timestamp: u64,
    }

    let mut count = 0usize;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let row: SnapshotTimestampOnly =
            serde_json::from_str(&line).context("parse snapshot history timestamp")?;
        if row.timestamp >= min_timestamp {
            count += 1;
        }
    }

    Ok(count)
}

pub fn reset(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    fs::write(path, "").with_context(|| format!("truncate {}", path.display()))
}

fn compact(path: &Path, retention: SnapshotHistoryRetention, now_ts: u64) -> anyhow::Result<()> {
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let original_bytes = raw.len() as u64;

    let mut lines: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();

    if let Some(max_age_secs) = retention.max_age_secs {
        #[derive(serde::Deserialize)]
        struct SnapshotTimestampOnly {
            timestamp: u64,
        }
        let min_ts = now_ts.saturating_sub(max_age_secs);
        lines.retain(|line| {
            serde_json::from_str::<SnapshotTimestampOnly>(line)
                .map(|row| row.timestamp >= min_ts)
                .unwrap_or(false)
        });
    }

    if retention.max_entries > 0 && lines.len() > retention.max_entries {
        let keep_from = lines.len() - retention.max_entries;
        lines = lines.split_off(keep_from);
    }

    if let Some(max_bytes) = retention.max_bytes {
        let mut kept: Vec<&str> = Vec::new();
        let mut total = 0u64;
        for line in lines.iter().rev() {
            let line_bytes = (line.len() + 1) as u64;
            if !kept.is_empty() && total.saturating_add(line_bytes) > max_bytes {
                break;
            }
            kept.push(*line);
            total = total.saturating_add(line_bytes);
        }
        kept.reverse();
        lines = kept;
    }

    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    let next_bytes = content.len() as u64;
    if next_bytes == original_bytes && content == raw {
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("rewrite {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        cpu::CpuMetrics, disk::DiskMetrics, memory::MemoryMetrics, network::NetworkMetrics,
        process::ProcessMetrics,
    };

    fn sample_snapshot(timestamp: u64) -> SystemSnapshot {
        SystemSnapshot {
            timestamp,
            host_id: "local-test".to_string(),
            cpu: CpuMetrics {
                usage_percent: 12.5,
                per_core: vec![10.0, 15.0],
                load_avg: (0.4, 0.5, 0.6),
            },
            memory: MemoryMetrics {
                total: 1024,
                used: 512,
                available: 512,
            },
            disks: vec![DiskMetrics {
                device: "sda".to_string(),
                read_bytes_per_sec: 100,
                write_bytes_per_sec: 50,
            }],
            network: vec![NetworkMetrics {
                interface: "eth0".to_string(),
                rx_bytes_per_sec: 200,
                tx_bytes_per_sec: 120,
            }],
            processes: vec![ProcessMetrics {
                pid: 1,
                name: "init".to_string(),
                cpu_percent: 0.1,
                memory_bytes: 4096,
                threads: 1,
                cmdline: "/sbin/init".to_string(),
            }],
        }
    }

    #[test]
    fn append_and_read_since_with_retention() {
        let root = std::env::temp_dir().join(format!(
            "manticore-history-test-{}-{}",
            std::process::id(),
            crate::utils::time::now_unix_secs()
        ));
        let path = default_snapshot_history_path(&root);

        let retention = SnapshotHistoryRetention {
            max_entries: 2,
            max_age_secs: None,
            max_bytes: None,
            slim_records: false,
        };
        append_snapshot(&path, &sample_snapshot(100), retention).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), retention).expect("append 2");
        append_snapshot(&path, &sample_snapshot(300), retention).expect("append 3");

        let all = read_since(&path, 0).expect("read all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].timestamp, 200);
        assert_eq!(all[1].timestamp, 300);

        let recent = read_since(&path, 250).expect("read recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].timestamp, 300);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn count_since_reads_only_timestamps() {
        let root = std::env::temp_dir().join(format!(
            "manticore-history-count-test-{}-{}",
            std::process::id(),
            crate::utils::time::now_unix_secs()
        ));
        let path = default_snapshot_history_path(&root);

        let retention = SnapshotHistoryRetention {
            max_entries: 10,
            max_age_secs: None,
            max_bytes: None,
            slim_records: false,
        };
        append_snapshot(&path, &sample_snapshot(100), retention).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), retention).expect("append 2");
        append_snapshot(&path, &sample_snapshot(300), retention).expect("append 3");

        let recent = count_since(&path, 150).expect("count recent");
        assert_eq!(recent, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_applies_max_age_window() {
        let root = std::env::temp_dir().join(format!(
            "manticore-history-age-test-{}-{}",
            std::process::id(),
            crate::utils::time::now_unix_secs()
        ));
        let path = default_snapshot_history_path(&root);
        let retention = SnapshotHistoryRetention {
            max_entries: 10,
            max_age_secs: Some(100),
            max_bytes: None,
            slim_records: false,
        };

        append_snapshot(&path, &sample_snapshot(100), retention).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), retention).expect("append 2");
        append_snapshot(&path, &sample_snapshot(300), retention).expect("append 3");

        let all = read_since(&path, 0).expect("read all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].timestamp, 200);
        assert_eq!(all[1].timestamp, 300);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_applies_max_bytes_window() {
        let root = std::env::temp_dir().join(format!(
            "manticore-history-bytes-test-{}-{}",
            std::process::id(),
            crate::utils::time::now_unix_secs()
        ));
        let path = default_snapshot_history_path(&root);
        let base = sample_snapshot(100);
        let line_len = serde_json::to_string(&base).expect("serialize").len() as u64 + 1;
        let retention = SnapshotHistoryRetention {
            max_entries: 10,
            max_age_secs: None,
            max_bytes: Some(line_len + 10),
            slim_records: false,
        };

        append_snapshot(&path, &sample_snapshot(100), retention).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), retention).expect("append 2");
        append_snapshot(&path, &sample_snapshot(300), retention).expect("append 3");

        let all = read_since(&path, 0).expect("read all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].timestamp, 300);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_slim_records_are_countable() {
        let root = std::env::temp_dir().join(format!(
            "manticore-history-slim-test-{}-{}",
            std::process::id(),
            crate::utils::time::now_unix_secs()
        ));
        let path = default_snapshot_history_path(&root);
        let retention = SnapshotHistoryRetention {
            max_entries: 10,
            max_age_secs: None,
            max_bytes: None,
            slim_records: true,
        };

        append_snapshot(&path, &sample_snapshot(100), retention).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), retention).expect("append 2");

        let recent = count_since(&path, 150).expect("count recent");
        assert_eq!(recent, 1);

        let _ = std::fs::remove_file(&path);
    }
}
