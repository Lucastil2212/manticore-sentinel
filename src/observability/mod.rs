use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use serde_json::{json, Value};

use crate::core::config::RuntimeConfig;
use crate::search::{discover, hybrid_search, SearchMode};
use crate::security::auth::{bearer_equals, AuthMode};
use crate::telemetry::TelemetryHandle;
use crate::utils::time::now_unix_secs;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Clone)]
pub struct ListenConfig {
    pub bind: String,
    pub port: u16,
    pub auth_mode: AuthMode,
    pub token_secret: Option<String>,
    pub evrus_jwt: Option<String>,
}

impl ListenConfig {
    pub fn from_runtime(cfg: &RuntimeConfig) -> Self {
        Self {
            bind: cfg.observability.http_bind.clone(),
            port: cfg.observability.http_port,
            auth_mode: cfg.auth_mode,
            token_secret: cfg.auth_token.clone(),
            evrus_jwt: cfg.connectors.evrus.as_ref().and_then(|ev| ev.jwt.clone()),
        }
    }
}

#[derive(Clone)]
pub struct ObservabilityServer {
    telemetry: TelemetryHandle,
    auth_mode: AuthMode,
    token_secret: Option<String>,
    evrus_jwt: Option<String>,
}

impl ObservabilityServer {
    pub fn spawn(listen: ListenConfig, telemetry: TelemetryHandle) -> anyhow::Result<()> {
        let listener = TcpListener::bind((listen.bind.as_str(), listen.port))?;
        listener.set_nonblocking(false)?;
        tracing::info!(
            bind = %listen.bind,
            port = listen.port,
            auth_mode = listen.auth_mode.as_str(),
            "observability HTTP listening"
        );
        let server = Self {
            telemetry,
            auth_mode: listen.auth_mode,
            token_secret: listen.token_secret,
            evrus_jwt: listen.evrus_jwt,
        };
        thread::Builder::new()
            .name("sentinel-observe".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if let Ok(stream) = stream {
                        let server = server.clone();
                        thread::spawn(move || {
                            if let Err(err) = server.handle(stream) {
                                tracing::debug!(error = %err, "observability request failed");
                            }
                        });
                    }
                }
            })?;
        Ok(())
    }

    fn authorized(&self, req: &str) -> bool {
        match self.auth_mode {
            AuthMode::Local => true,
            AuthMode::Token => bearer_equals(
                request_header(req, "authorization"),
                self.token_secret.as_deref(),
            ),
            AuthMode::Evrus => bearer_equals(
                request_header(req, "authorization"),
                self.evrus_jwt.as_deref(),
            ),
        }
    }

    fn handle(&self, mut stream: TcpStream) -> anyhow::Result<()> {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        let req = String::from_utf8_lossy(&buf[..n]);
        let first = req.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let path = parts.next().unwrap_or("/");
        if method != "GET" {
            return write_response(&mut stream, 405, "text/plain", b"method not allowed");
        }
        let (route, query) = split_query(path);
        if route != "/health" && !self.authorized(&req) {
            return write_response(&mut stream, 401, "text/plain", b"unauthorized");
        }
        match route {
            "/" | "/index.html" => write_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
            ),
            "/health" => write_json(&mut stream, self.health()),
            "/metrics" => {
                let body = self.prometheus();
                write_response(
                    &mut stream,
                    200,
                    "text/plain; version=0.0.4",
                    body.as_bytes(),
                )
            }
            "/api/search" => {
                let q = query_param(&query, "q").unwrap_or_default();
                let mode = SearchMode::from_env(query_param(&query, "mode").unwrap_or("hybrid"));
                let limit = query_param(&query, "limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(12)
                    .clamp(1, 50);
                write_json(&mut stream, self.search(&q, mode, limit))
            }
            "/api/discover" => write_json(
                &mut stream,
                self.discover(query_param(&query, "q").unwrap_or("")),
            ),
            "/api/metrics/series" => {
                let limit = query_param(&query, "limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(180)
                    .clamp(8, 2000);
                write_json(&mut stream, self.series(limit))
            }
            "/api/logs" => {
                let limit = query_param(&query, "limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(40)
                    .clamp(1, 500);
                write_json(&mut stream, self.logs(limit))
            }
            "/api/connectors" => write_json(&mut stream, self.connectors()),
            _ => write_response(&mut stream, 404, "text/plain", b"not found"),
        }
    }

    fn health(&self) -> Value {
        let (last, avg, cycles, polls, errors) = self.telemetry.stats_snapshot();
        let mut stats = json!({
            "ok": true,
            "ts": now_unix_secs(),
            "collect_last_ms": last,
            "collect_avg_ms": avg,
            "cycles": cycles,
            "connector_polls": polls,
            "errors_total": errors,
            "has_connectors": self.telemetry.has_connectors(),
        });
        if let Some(store) = self.telemetry.store() {
            if let Ok(s) = store.stats() {
                stats["metrics"] = json!(s.metrics);
                stats["documents"] = json!(s.documents);
                stats["logs"] = json!(s.logs);
                stats["embeddings"] = json!(s.embeddings);
                stats["store_bytes"] = json!(s.bytes);
            }
        }
        stats["detail"] = json!(format!(
            "cycles={} collect_avg_ms={:.2} errors={}",
            cycles, avg, errors
        ));
        stats
    }

    fn prometheus(&self) -> String {
        let (last, avg, cycles, polls, errors) = self.telemetry.stats_snapshot();
        let mut out = format!(
            "# TYPE sentinel_collect_last_ms gauge\nsentinel_collect_last_ms {last}\n\
             # TYPE sentinel_collect_avg_ms gauge\nsentinel_collect_avg_ms {avg}\n\
             # TYPE sentinel_collect_cycles counter\nsentinel_collect_cycles {cycles}\n\
             # TYPE sentinel_connector_polls counter\nsentinel_connector_polls {polls}\n\
             # TYPE sentinel_errors_total counter\nsentinel_errors_total {errors}\n"
        );
        if let Some(snap) = self.telemetry.latest() {
            out.push_str(&format!(
                "sentinel_cpu_percent {}\nsentinel_memory_used_bytes {}\nsentinel_process_count {}\n",
                snap.cpu.usage_percent,
                snap.memory.used,
                snap.processes.len()
            ));
        }
        out
    }

    fn search(&self, q: &str, mode: SearchMode, limit: usize) -> Value {
        let Some(store) = self.telemetry.store() else {
            return json!({ "hits": [], "error": "store disabled" });
        };
        match hybrid_search(store, q, mode, limit) {
            Ok(hits) => json!({
                "mode": mode.as_str(),
                "query": q,
                "hits": hits.iter().map(|h| json!({
                    "id": h.id,
                    "kind": h.kind,
                    "ts": h.ts,
                    "title": h.title,
                    "body": h.body,
                    "source": h.source,
                    "fts_rank": h.fts_rank,
                    "vector_score": h.vector_score,
                    "fused_score": h.fused_score,
                })).collect::<Vec<_>>(),
            }),
            Err(err) => json!({ "hits": [], "error": err.to_string() }),
        }
    }

    fn discover(&self, q: &str) -> Value {
        let Some(store) = self.telemetry.store() else {
            return json!({ "trending": [], "recent": [], "log_hour_bins": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] });
        };
        let report = discover(store, q, 12).ok();
        let bins = store.log_hour_bins().unwrap_or([0; 24]);
        json!({
            "trending": report.as_ref().map(|r| r.trending.iter().map(|(k,c)| json!({"kind":k,"count":c})).collect::<Vec<_>>()).unwrap_or_default(),
            "recent": report.as_ref().map(|r| r.recent.iter().map(|h| json!({"title":h.title,"kind":h.kind,"score":h.fused_score})).collect::<Vec<_>>()).unwrap_or_default(),
            "related": report.as_ref().map(|r| r.related.iter().map(|h| json!({"title":h.title,"kind":h.kind,"score":h.fused_score})).collect::<Vec<_>>()).unwrap_or_default(),
            "log_hour_bins": bins,
        })
    }

    fn series(&self, limit: usize) -> Value {
        let Some(store) = self.telemetry.store() else {
            return json!({ "cpu": [], "mem": [], "disk": [], "net": [], "collect_ms": [] });
        };
        let metrics = store.recent_metrics(limit).unwrap_or_default();
        let collect = store.collect_samples(limit).unwrap_or_default();
        json!({
            "cpu": metrics.iter().map(|m| json!({"ts": m.ts, "value": m.cpu})).collect::<Vec<_>>(),
            "mem": metrics.iter().map(|m| {
                let pct = if m.mem_total == 0 { 0.0 } else { m.mem_used as f64 / m.mem_total as f64 * 100.0 };
                json!({"ts": m.ts, "value": pct})
            }).collect::<Vec<_>>(),
            "disk": metrics.iter().map(|m| json!({"ts": m.ts, "value": m.disk_bps})).collect::<Vec<_>>(),
            "net": metrics.iter().map(|m| json!({"ts": m.ts, "value": m.net_bps})).collect::<Vec<_>>(),
            "collect_ms": collect.iter().map(|(ts, ms, _)| json!({"ts": ts, "value": ms})).collect::<Vec<_>>(),
        })
    }

    fn logs(&self, limit: usize) -> Value {
        let Some(store) = self.telemetry.store() else {
            return json!({ "entries": [] });
        };
        let entries = store.recent_logs(limit).unwrap_or_default();
        json!({
            "entries": entries.iter().map(|l| json!({
                "ts": l.ts,
                "level": l.level,
                "target": l.target,
                "message": l.message,
            })).collect::<Vec<_>>(),
        })
    }

    fn connectors(&self) -> Value {
        let summary = self.telemetry.connectors();
        json!({
            "entries": summary.entries.iter().map(|e| json!({
                "name": e.name,
                "status": e.status.label(),
                "latency_ms": e.latency_ms,
                "detail": e.detail,
            })).collect::<Vec<_>>(),
        })
    }
}

fn split_query(path: &str) -> (&str, &str) {
    match path.split_once('?') {
        Some((route, query)) => (route, query),
        None => (path, ""),
    }
}

fn request_header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    for line in req.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }
    None
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(v)
        } else {
            None
        }
    })
}

fn write_json(stream: &mut TcpStream, value: Value) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&value)?;
    write_response(stream, 200, "application/json", &body)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let www_authenticate = if status == 401 {
        "WWW-Authenticate: Bearer realm=\"sentinel\"\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n{www_authenticate}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::request_header;

    #[test]
    fn request_header_reads_authorization() {
        let req =
            "GET /api/search HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n";
        assert_eq!(request_header(req, "authorization"), Some("Bearer secret"));
        assert_eq!(request_header(req, "host"), Some("127.0.0.1"));
        assert_eq!(request_header(req, "missing"), None);
    }
}
