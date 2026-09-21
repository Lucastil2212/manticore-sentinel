mod app;
mod collectors;
mod connectors;
mod core;
mod models;
mod observability;
mod search;
mod security;
mod store;
mod telemetry;
mod utils;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    if let Some(profile) = profile_arg(&args) {
        load_profile_env(&profile)?;
        tracing::info!(profile = %profile, "runtime profile loaded");
    }
    let mut config = core::config::load_runtime_config()?;
    tracing::info!(
        profile = %config.profile,
        privileged = config.privileged,
        helper_mode = %config.helper_mode,
        refresh_ms = config.refresh_ms,
        process_max_entries = config.process_max_entries,
        process_cmdline_entries = config.process_cmdline_entries,
        store = %config.store.path.display(),
        search = config.search.enabled,
        obs_http = config.observability.http_enabled,
        log_json = config.observability.log_json,
        "startup diagnostics"
    );
    if args.iter().any(|arg| arg == "--helper-daemon") {
        tracing::info!("starting helper daemon mode");
        return security::helper::run_helper_daemon_from_env();
    }
    if args.iter().any(|arg| arg == "--healthcheck") {
        return run_healthcheck(config.observability.http_port);
    }
    if args.iter().any(|arg| arg == "--benchmark") {
        tracing::info!("starting benchmark mode");
        return run_benchmark_mode(&config);
    }
    if args.iter().any(|arg| arg == "--headless") {
        config.observability.http_enabled = true;
        tracing::info!("starting headless telemetry mode");
        return run_headless(config);
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([360.0, 260.0]),
        ..Default::default()
    };
    let app = app::dashboard::SentinelDashboard::new()?;

    eframe::run_native(
        "Manticore Sentinel",
        options,
        Box::new(move |_cc| Box::new(app)),
    )
    .map_err(|e| anyhow::anyhow!("eframe failed: {e}"))?;

    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json = std::env::var("MANTICORE_LOG_JSON")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if json {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }
}

fn profile_arg(args: &[String]) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == "--profile")
        .map(|w| w[1].clone())
}

fn load_profile_env(profile: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let path = cwd
        .join("config")
        .join("profiles")
        .join(format!("{profile}.env"));
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read profile {}: {}", path.display(), e))?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // SAFETY: called before any threads are spawned (early main, single-threaded).
            unsafe { std::env::set_var(k.trim(), v.trim()) };
        }
    }
    tracing::debug!(profile = %profile, path = %path.display(), "profile environment applied");
    Ok(())
}

fn run_headless(config: core::config::RuntimeConfig) -> anyhow::Result<()> {
    let telemetry = telemetry::TelemetryHandle::spawn(&config)?;
    if config.observability.http_enabled {
        observability::ObservabilityServer::spawn(config.observability.http_port, telemetry.clone())?;
        tracing::info!(
            port = config.observability.http_port,
            "observability UI at / and /api/search"
        );
    }
    if let Some(es) = config.event_stream.as_ref() {
        match app::event_stream::EventStreamOutput::start(
            es.port,
            config.auth_mode,
            config.auth_token.clone(),
            config.connectors.evrus.as_ref().and_then(|ev| ev.jwt.clone()),
        ) {
            Ok(stream) => {
                tracing::info!(port = es.port, "event stream listening");
                loop {
                    if let Some(tick) = telemetry.poll_tick() {
                        let payload = serde_json::json!({
                            "timestamp": tick.snapshot.timestamp,
                            "host_id": tick.snapshot.host_id,
                            "cpu_usage_percent": tick.snapshot.cpu.usage_percent,
                            "memory_used": tick.snapshot.memory.used,
                            "memory_total": tick.snapshot.memory.total,
                            "process_count": tick.snapshot.processes.len(),
                            "collect_ms": tick.collect_last_ms,
                        });
                        stream.emit_json("system_snapshot", &payload);
                    }
                    std::thread::sleep(Duration::from_millis(config.refresh_ms.max(200)));
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "event stream failed to bind; continuing without SSE");
            }
        }
    }
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let (last, avg, cycles, polls, errors) = telemetry.stats_snapshot();
        tracing::info!(
            collect_last_ms = last,
            collect_avg_ms = avg,
            cycles,
            connector_polls = polls,
            errors_total = errors,
            "headless heartbeat"
        );
    }
}

fn run_healthcheck(port: u16) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| anyhow::anyhow!("healthcheck connect {port}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    if buf.contains("\"ok\":true") || buf.contains("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(anyhow::anyhow!("healthcheck failed: {buf}"))
    }
}

fn run_benchmark_mode(config: &core::config::RuntimeConfig) -> anyhow::Result<()> {
    use std::time::Instant;

    let mut engine = core::engine::SentinelEngine::new(
        config.process_max_entries,
        config.process_cmdline_entries,
    );
    engine.init_connectors(&config.connectors);
    let iterations = 40u32;

    let startup_begin = Instant::now();
    let _first = engine.collect_blocking()?;
    let startup_ms = startup_begin.elapsed().as_secs_f64() * 1000.0;

    let mut total_ms = 0.0f64;
    for _ in 0..iterations {
        let step = Instant::now();
        let _ = engine.collect_blocking()?;
        if engine.has_connectors() {
            let _ = engine.poll_connectors();
        }
        total_ms += step.elapsed().as_secs_f64() * 1000.0;
    }
    let avg_ms = total_ms / iterations as f64;
    let hz = if avg_ms > 0.0 { 1000.0 / avg_ms } else { 0.0 };

    println!("benchmark.startup_ms={:.3}", startup_ms);
    println!("benchmark.collect_avg_ms={:.3}", avg_ms);
    println!("benchmark.collect_hz={:.3}", hz);
    println!("benchmark.iterations={}", iterations);

    Ok(())
}
