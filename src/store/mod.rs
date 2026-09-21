use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use rusqlite::{params, Connection};

use crate::search::{embed_text, pack_embedding, EMBED_DIM};
use crate::utils::time::now_unix_secs;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metrics (
    ts INTEGER NOT NULL,
    host TEXT NOT NULL,
    cpu REAL NOT NULL,
    mem_used INTEGER NOT NULL,
    mem_total INTEGER NOT NULL,
    disk_bps INTEGER NOT NULL,
    net_bps INTEGER NOT NULL,
    process_count INTEGER NOT NULL,
    PRIMARY KEY (ts, host)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    ts INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    source TEXT NOT NULL,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_kind_ts ON documents(kind, ts);
CREATE INDEX IF NOT EXISTS idx_documents_ts ON documents(ts);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    title, body, kind, source,
    content='documents',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, title, body, kind, source)
    VALUES (new.id, new.title, new.body, new.kind, new.source);
END;
CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, body, kind, source)
    VALUES ('delete', old.id, old.title, old.body, old.kind, old.source);
END;
CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, body, kind, source)
    VALUES ('delete', old.id, old.title, old.body, old.kind, old.source);
    INSERT INTO documents_fts(rowid, title, body, kind, source)
    VALUES (new.id, new.title, new.body, new.kind, new.source);
END;

CREATE TABLE IF NOT EXISTS embeddings (
    doc_id INTEGER PRIMARY KEY,
    dim INTEGER NOT NULL,
    vec BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    level TEXT NOT NULL,
    target TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);

CREATE TABLE IF NOT EXISTS collect_samples (
    ts INTEGER PRIMARY KEY,
    collect_ms REAL NOT NULL,
    connector_ms REAL
);
"#;

#[derive(Debug, Clone)]
pub struct MetricRow {
    pub ts: u64,
    pub host: String,
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_bps: u64,
    pub net_bps: u64,
    pub process_count: usize,
}

#[derive(Debug, Clone)]
pub struct DocumentRow {
    pub id: i64,
    pub kind: String,
    pub ts: u64,
    pub title: String,
    pub body: String,
    pub source: String,
    pub payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogRow {
    pub ts: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StoreStats {
    pub path: PathBuf,
    pub bytes: u64,
    pub metrics: u64,
    pub documents: u64,
    pub logs: u64,
    pub embeddings: u64,
}

#[derive(Debug)]
pub enum WriteOp {
    Metric(MetricRow),
    Document {
        kind: String,
        ts: u64,
        title: String,
        body: String,
        source: String,
        payload: Option<String>,
    },
    Log(LogRow),
    CollectSample {
        ts: u64,
        collect_ms: f64,
        connector_ms: Option<f64>,
    },
    Prune {
        keep_metrics: usize,
        keep_docs: usize,
        keep_logs: usize,
        min_ts: Option<u64>,
    },
    Sync(mpsc::Sender<()>),
}

#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    tx: SyncSender<WriteOp>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = open_writer(&path)?;
        conn.execute_batch(SCHEMA)?;
        drop(conn);

        let (tx, rx) = mpsc::sync_channel(4096);
        let writer_path = path.clone();
        thread::Builder::new()
            .name("sentinel-store".into())
            .spawn(move || writer_loop(writer_path, rx))
            .map_err(|e| anyhow::anyhow!("store writer thread: {e}"))?;

        Ok(Self { path, tx })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn enqueue(&self, op: WriteOp) {
        let _ = self.tx.try_send(op);
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(WriteOp::Sync(tx))
            .map_err(|_| anyhow::anyhow!("store writer disconnected"))?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("store flush timed out"))?;
        Ok(())
    }

    pub fn write_metric(&self, row: MetricRow) {
        self.enqueue(WriteOp::Metric(row));
    }

    pub fn write_document(
        &self,
        kind: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        source: impl Into<String>,
        payload: Option<String>,
    ) {
        self.enqueue(WriteOp::Document {
            kind: kind.into(),
            ts: now_unix_secs(),
            title: title.into(),
            body: body.into(),
            source: source.into(),
            payload,
        });
    }

    pub fn write_log(&self, level: &str, target: &str, message: &str) {
        self.enqueue(WriteOp::Log(LogRow {
            ts: now_unix_secs(),
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
        }));
    }

    pub fn reader(&self) -> anyhow::Result<Connection> {
        open_reader(&self.path)
    }

    pub fn stats(&self) -> anyhow::Result<StoreStats> {
        let conn = self.reader()?;
        let bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let metrics = count_table(&conn, "metrics")?;
        let documents = count_table(&conn, "documents")?;
        let logs = count_table(&conn, "logs")?;
        let embeddings = count_table(&conn, "embeddings")?;
        Ok(StoreStats {
            path: self.path.clone(),
            bytes,
            metrics,
            documents,
            logs,
            embeddings,
        })
    }

    pub fn recent_metrics(&self, limit: usize) -> anyhow::Result<Vec<MetricRow>> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare(
            "SELECT ts, host, cpu, mem_used, mem_total, disk_bps, net_bps, process_count
             FROM metrics ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(MetricRow {
                ts: row.get::<_, i64>(0)? as u64,
                host: row.get(1)?,
                cpu: row.get::<_, f64>(2)? as f32,
                mem_used: row.get::<_, i64>(3)? as u64,
                mem_total: row.get::<_, i64>(4)? as u64,
                disk_bps: row.get::<_, i64>(5)? as u64,
                net_bps: row.get::<_, i64>(6)? as u64,
                process_count: row.get::<_, i64>(7)? as usize,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out.reverse();
        Ok(out)
    }

    pub fn metric_count_since(&self, min_ts: u64) -> anyhow::Result<usize> {
        let conn = self.reader()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM metrics WHERE ts >= ?1",
            [min_ts as i64],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn recent_logs(&self, limit: usize) -> anyhow::Result<Vec<LogRow>> {
        let conn = self.reader()?;
        let mut stmt =
            conn.prepare("SELECT ts, level, target, message FROM logs ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(LogRow {
                ts: row.get::<_, i64>(0)? as u64,
                level: row.get(1)?,
                target: row.get(2)?,
                message: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out.reverse();
        Ok(out)
    }

    pub fn log_hour_bins(&self) -> anyhow::Result<[usize; 24]> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare("SELECT ts FROM logs")?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        let mut bins = [0usize; 24];
        for row in rows {
            let ts = row? as u64;
            let hour = ((ts % 86_400) / 3600) as usize;
            if hour < 24 {
                bins[hour] += 1;
            }
        }
        Ok(bins)
    }

    pub fn collect_samples(&self, limit: usize) -> anyhow::Result<Vec<(u64, f64, Option<f64>)>> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare(
            "SELECT ts, collect_ms, connector_ms FROM collect_samples ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, f64>(1)?,
                row.get::<_, Option<f64>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out.reverse();
        Ok(out)
    }

    pub fn fts_search(&self, match_query: &str, limit: usize) -> anyhow::Result<Vec<(DocumentRow, f32)>> {
        if match_query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.reader()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.kind, d.ts, d.title, d.body, d.source, d.payload,
                    bm25(documents_fts) AS rank
             FROM documents_fts
             JOIN documents d ON d.id = documents_fts.rowid
             WHERE documents_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![match_query, limit as i64], |row| {
            Ok((
                DocumentRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    ts: row.get::<_, i64>(2)? as u64,
                    title: row.get(3)?,
                    body: row.get(4)?,
                    source: row.get(5)?,
                    payload: row.get(6)?,
                },
                row.get::<_, f64>(7)? as f32,
            ))
        });
        let rows = match rows {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for row in rows {
            if let Ok(v) = row {
                out.push(v);
            }
        }
        Ok(out)
    }

    pub fn recent_documents(&self, limit: usize) -> anyhow::Result<Vec<DocumentRow>> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, ts, title, body, source, payload
             FROM documents ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(DocumentRow {
                id: row.get(0)?,
                kind: row.get(1)?,
                ts: row.get::<_, i64>(2)? as u64,
                title: row.get(3)?,
                body: row.get(4)?,
                source: row.get(5)?,
                payload: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn load_embeddings(&self, limit: usize) -> anyhow::Result<Vec<(DocumentRow, Vec<f32>)>> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.kind, d.ts, d.title, d.body, d.source, d.payload, e.vec
             FROM embeddings e
             JOIN documents d ON d.id = e.doc_id
             ORDER BY d.ts DESC, d.id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            let blob: Vec<u8> = row.get(7)?;
            Ok((
                DocumentRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    ts: row.get::<_, i64>(2)? as u64,
                    title: row.get(3)?,
                    body: row.get(4)?,
                    source: row.get(5)?,
                    payload: row.get(6)?,
                },
                unpack_embedding(&blob),
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn kind_counts(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.reader()?;
        let mut stmt = conn.prepare("SELECT kind, COUNT(*) FROM documents GROUP BY kind ORDER BY COUNT(*) DESC")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

fn open_writer(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(500))?;
    Ok(conn)
}

fn open_reader(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(250))?;
    conn.pragma_update(None, "query_only", true)?;
    Ok(conn)
}

fn count_table(conn: &Connection, table: &str) -> anyhow::Result<u64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(count as u64)
}

fn writer_loop(path: PathBuf, rx: Receiver<WriteOp>) {
    let conn = match open_writer(&path) {
        Ok(v) => v,
        Err(err) => {
            tracing::error!(error = %err, "store writer failed to open sqlite");
            return;
        }
    };
    let _ = conn.execute_batch("BEGIN");
    let mut pending = 0usize;
    let mut since_prune = 0usize;
    loop {
        match rx.recv_timeout(Duration::from_millis(40)) {
            Ok(op) => {
                let is_sync = matches!(op, WriteOp::Sync(_));
                if let Err(err) = apply_op(&conn, op) {
                    tracing::warn!(error = %err, "store write failed");
                } else if !is_sync {
                    pending += 1;
                    since_prune += 1;
                }
                if pending >= 24 {
                    let _ = conn.execute_batch("COMMIT; BEGIN");
                    pending = 0;
                }
                if since_prune >= 256 {
                    let _ = apply_op(
                        &conn,
                        WriteOp::Prune {
                            keep_metrics: 50_000,
                            keep_docs: 20_000,
                            keep_logs: 20_000,
                            min_ts: Some(now_unix_secs().saturating_sub(7 * 86_400)),
                        },
                    );
                    since_prune = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if pending > 0 {
                    let _ = conn.execute_batch("COMMIT; BEGIN");
                    pending = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = conn.execute_batch("COMMIT");
                break;
            }
        }
    }
}

fn apply_op(conn: &Connection, op: WriteOp) -> anyhow::Result<()> {
    match op {
        WriteOp::Metric(row) => {
            conn.execute(
                "INSERT OR REPLACE INTO metrics
                 (ts, host, cpu, mem_used, mem_total, disk_bps, net_bps, process_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    row.ts as i64,
                    row.host,
                    row.cpu as f64,
                    row.mem_used as i64,
                    row.mem_total as i64,
                    row.disk_bps as i64,
                    row.net_bps as i64,
                    row.process_count as i64
                ],
            )?;
        }
        WriteOp::Document {
            kind,
            ts,
            title,
            body,
            source,
            payload,
        } => {
            let text = format!("{title} {body} {kind} {source}");
            conn.execute(
                "INSERT INTO documents (kind, ts, title, body, source, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![kind, ts as i64, title, body, source, payload],
            )?;
            let id = conn.last_insert_rowid();
            let vec = pack_embedding(&embed_text(&text));
            conn.execute(
                "INSERT OR REPLACE INTO embeddings (doc_id, dim, vec) VALUES (?1, ?2, ?3)",
                params![id, EMBED_DIM as i64, vec],
            )?;
        }
        WriteOp::Log(row) => {
            conn.execute(
                "INSERT INTO logs (ts, level, target, message) VALUES (?1, ?2, ?3, ?4)",
                params![row.ts as i64, row.level, row.target, row.message],
            )?;
        }
        WriteOp::CollectSample {
            ts,
            collect_ms,
            connector_ms,
        } => {
            conn.execute(
                "INSERT OR REPLACE INTO collect_samples (ts, collect_ms, connector_ms)
                 VALUES (?1, ?2, ?3)",
                params![ts as i64, collect_ms, connector_ms],
            )?;
        }
        WriteOp::Prune {
            keep_metrics,
            keep_docs,
            keep_logs,
            min_ts,
        } => {
            if let Some(min_ts) = min_ts {
                let _ = conn.execute("DELETE FROM metrics WHERE ts < ?1", [min_ts as i64]);
                let _ = conn.execute("DELETE FROM logs WHERE ts < ?1", [min_ts as i64]);
                let _ = conn.execute("DELETE FROM documents WHERE ts < ?1", [min_ts as i64]);
            }
            let _ = conn.execute(
                "DELETE FROM metrics WHERE ts NOT IN (SELECT ts FROM metrics ORDER BY ts DESC LIMIT ?1)",
                [keep_metrics as i64],
            );
            let _ = conn.execute(
                "DELETE FROM documents WHERE id NOT IN (SELECT id FROM documents ORDER BY ts DESC, id DESC LIMIT ?1)",
                [keep_docs as i64],
            );
            let _ = conn.execute(
                "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?1)",
                [keep_logs as i64],
            );
            let _ = conn.execute(
                "DELETE FROM embeddings WHERE doc_id NOT IN (SELECT id FROM documents)",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM collect_samples WHERE ts NOT IN (SELECT ts FROM collect_samples ORDER BY ts DESC LIMIT 4000)",
                [],
            );
        }
        WriteOp::Sync(done) => {
            let _ = conn.execute_batch("COMMIT; BEGIN");
            let _ = done.send(());
        }
    }
    Ok(())
}

fn unpack_embedding(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Store {
        let path = std::env::temp_dir().join(format!(
            "manticore-store-{}-{}.sqlite",
            std::process::id(),
            now_unix_secs()
        ));
        Store::open(path).expect("open store")
    }

    #[test]
    fn writes_metrics_and_documents() {
        let store = test_store();
        store.write_metric(MetricRow {
            ts: 100,
            host: "local".into(),
            cpu: 12.5,
            mem_used: 512,
            mem_total: 1024,
            disk_bps: 10,
            net_bps: 20,
            process_count: 3,
        });
        store.write_document(
            "process",
            "sshd",
            "pid 22 cpu 1.2 sshd -D",
            "host:local",
            None,
        );
        store.flush().expect("flush");
        let metrics = store.recent_metrics(10).expect("metrics");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cpu, 12.5);
        let docs = store.recent_documents(10).expect("docs");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "sshd");
        let _ = std::fs::remove_file(store.path());
    }
}
