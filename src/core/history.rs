use crate::core::snapshot::SystemSnapshot;
use anyhow::Context;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn default_snapshot_history_path(root: &Path) -> PathBuf {
    root.join(".beads").join("state").join("snapshots.jsonl")
}

pub fn append_snapshot(
    path: &Path,
    snapshot: &SystemSnapshot,
    max_entries: usize,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    let line = serde_json::to_string(snapshot).context("serialize snapshot")?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(f, "{line}").with_context(|| format!("append {}", path.display()))?;
    enforce_max_entries(path, max_entries)?;
    Ok(())
}

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

fn enforce_max_entries(path: &Path, max_entries: usize) -> anyhow::Result<()> {
    if max_entries == 0 {
        return Ok(());
    }
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let mut lines: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    if lines.len() <= max_entries {
        return Ok(());
    }
    let keep_from = lines.len() - max_entries;
    lines = lines.split_off(keep_from);
    let mut content = lines.join("\n");
    content.push('\n');
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

        append_snapshot(&path, &sample_snapshot(100), 2).expect("append 1");
        append_snapshot(&path, &sample_snapshot(200), 2).expect("append 2");
        append_snapshot(&path, &sample_snapshot(300), 2).expect("append 3");

        let all = read_since(&path, 0).expect("read all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].timestamp, 200);
        assert_eq!(all[1].timestamp, 300);

        let recent = read_since(&path, 250).expect("read recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].timestamp, 300);

        let _ = std::fs::remove_file(&path);
    }
}
