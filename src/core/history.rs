use crate::core::snapshot::SystemSnapshot;
use anyhow::Context;
use rusqlite::{params, Connection, OpenFlags};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct SnapshotHistoryRetention {
    pub max_entries: usize,
    pub max_age_secs: Option<u64>,
    pub max_bytes: Option<u64>,
    pub slim_records: bool,
}

pub fn default_snapshot_history_path(root: &Path) -> PathBuf {
    root.join(".beads").join("state").join("snapshots.sqlite3")
}

fn open(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            host_id TEXT NOT NULL,
            cpu_usage_percent REAL NOT NULL,
            memory_used INTEGER NOT NULL,
            memory_total INTEGER NOT NULL,
            process_count INTEGER NOT NULL,
            payload TEXT
        );
        CREATE INDEX IF NOT EXISTS snapshots_timestamp_idx ON snapshots(timestamp DESC);",
    )?;
    Ok(conn)
}

pub fn append_snapshot(
    path: &Path,
    snapshot: &SystemSnapshot,
    retention: SnapshotHistoryRetention,
) -> anyhow::Result<()> {
    let mut conn = open(path)?;
    let tx = conn.transaction()?;
    let payload = if retention.slim_records {
        None
    } else {
        Some(serde_json::to_string(snapshot).context("serialize snapshot")?)
    };
    tx.execute(
        "INSERT INTO snapshots(timestamp,host_id,cpu_usage_percent,memory_used,memory_total,process_count,payload)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            snapshot.timestamp as i64,
            snapshot.host_id,
            snapshot.cpu.usage_percent,
            snapshot.memory.used as i64,
            snapshot.memory.total as i64,
            snapshot.processes.len() as i64,
            payload
        ],
    )?;
    apply_retention(&tx, retention, snapshot.timestamp)?;
    tx.commit()?;
    Ok(())
}

fn apply_retention(
    conn: &Connection,
    retention: SnapshotHistoryRetention,
    now_ts: u64,
) -> anyhow::Result<()> {
    if let Some(max_age) = retention.max_age_secs {
        let min_ts = now_ts.saturating_sub(max_age);
        conn.execute("DELETE FROM snapshots WHERE timestamp < ?1", [min_ts as i64])?;
    }
    if retention.max_entries > 0 {
        conn.execute(
            "DELETE FROM snapshots WHERE id NOT IN (
               SELECT id FROM snapshots ORDER BY id DESC LIMIT ?1
             )",
            [retention.max_entries as i64],
        )?;
    }
    // max_bytes is enforced approximately without rewriting the database on every sample.
    // When the file crosses the cap, discard the oldest quarter, then let WAL checkpointing
    // reclaim pages asynchronously. This keeps the hot path bounded.
    if let Some(max_bytes) = retention.max_bytes {
        let bytes = conn
            .query_row("PRAGMA page_count", [], |r| r.get::<_, u64>(0))
            .unwrap_or(0)
            .saturating_mul(
                conn.query_row("PRAGMA page_size", [], |r| r.get::<_, u64>(0))
                    .unwrap_or(4096),
            );
        if bytes > max_bytes {
            let count = conn
                .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get::<_, u64>(0))
                .unwrap_or(0);
            let trim = (count / 4).max(1);
            conn.execute(
                "DELETE FROM snapshots WHERE id IN (SELECT id FROM snapshots ORDER BY id ASC LIMIT ?1)",
                [trim as i64],
            )?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn read_since(path: &Path, min_timestamp: u64) -> anyhow::Result<Vec<SystemSnapshot>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        "SELECT payload FROM snapshots WHERE timestamp >= ?1 AND payload IS NOT NULL ORDER BY timestamp ASC, id ASC",
    )?;
    let rows = stmt.query_map([min_timestamp as i64], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for raw in rows {
        let raw = raw?;
        out.push(serde_json::from_str(&raw).context("parse snapshot payload")?);
    }
    Ok(out)
}

pub fn count_since(path: &Path, min_timestamp: u64) -> anyhow::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let conn = open(path)?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM snapshots WHERE timestamp >= ?1",
        [min_timestamp as i64],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as usize)
}

pub fn read_metric_rows(
    path: &Path,
    limit: usize,
) -> anyhow::Result<Vec<(u64, f32, u64, u64, usize)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        "SELECT timestamp,cpu_usage_percent,memory_used,memory_total,process_count
         FROM snapshots ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |row| {
        Ok((
            row.get::<_, i64>(0)?.max(0) as u64,
            row.get::<_, f64>(1)? as f32,
            row.get::<_, i64>(2)?.max(0) as u64,
            row.get::<_, i64>(3)?.max(0) as u64,
            row.get::<_, i64>(4)?.max(0) as usize,
        ))
    })?;
    let mut out: Vec<_> = rows.collect::<Result<_, _>>()?;
    out.reverse();
    Ok(out)
}

pub fn reset(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        let _ = open(path)?;
        return Ok(());
    }
    let conn = open(path)?;
    conn.execute("DELETE FROM snapshots", [])?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
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
            cpu: CpuMetrics { usage_percent: 12.5, per_core: vec![10.0, 15.0], load_avg: (0.4, 0.5, 0.6) },
            memory: MemoryMetrics { total: 1024, used: 512, available: 512 },
            disks: vec![DiskMetrics { device: "sda".to_string(), read_bytes_per_sec: 100, write_bytes_per_sec: 50 }],
            network: vec![NetworkMetrics { interface: "eth0".to_string(), rx_bytes_per_sec: 200, tx_bytes_per_sec: 120 }],
            processes: vec![ProcessMetrics { pid: 1, name: "init".to_string(), cpu_percent: 0.1, memory_bytes: 4096, threads: 1, cmdline: "/sbin/init".to_string() }],
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("manticore-{name}-{}-{}.sqlite3", std::process::id(), crate::utils::time::now_unix_secs()))
    }

    #[test]
    fn retention_keeps_latest_rows() {
        let path = temp_path("history-retention");
        let retention = SnapshotHistoryRetention { max_entries: 2, max_age_secs: None, max_bytes: None, slim_records: false };
        append_snapshot(&path, &sample_snapshot(100), retention).unwrap();
        append_snapshot(&path, &sample_snapshot(200), retention).unwrap();
        append_snapshot(&path, &sample_snapshot(300), retention).unwrap();
        let rows = read_since(&path, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, 200);
        assert_eq!(count_since(&path, 250).unwrap(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn slim_rows_are_queryable_without_payload_cost() {
        let path = temp_path("history-slim");
        let retention = SnapshotHistoryRetention { max_entries: 10, max_age_secs: None, max_bytes: None, slim_records: true };
        append_snapshot(&path, &sample_snapshot(100), retention).unwrap();
        append_snapshot(&path, &sample_snapshot(200), retention).unwrap();
        assert_eq!(count_since(&path, 150).unwrap(), 1);
        assert_eq!(read_since(&path, 0).unwrap().len(), 0);
        assert_eq!(read_metric_rows(&path, 10).unwrap().len(), 2);
        let _ = fs::remove_file(path);
    }
}
