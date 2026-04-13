mod app;
mod collectors;
mod connectors;
mod core;
mod models;
mod security;
mod utils;

fn main() -> anyhow::Result<()> {
    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    if let Some(profile) = profile_arg(&args) {
        load_profile_env(&profile)?;
        tracing::info!(profile = %profile, "runtime profile loaded");
    }
    let config = core::config::load_runtime_config()?;
    tracing::info!(
        profile = %config.profile,
        privileged = config.privileged,
        helper_mode = %config.helper_mode,
        refresh_ms = config.refresh_ms,
        "startup diagnostics"
    );
    if args.iter().any(|arg| arg == "--helper-daemon") {
        tracing::info!("starting helper daemon mode");
        return security::helper::run_helper_daemon_from_env();
    }
    if args.iter().any(|arg| arg == "--benchmark") {
        tracing::info!("starting benchmark mode");
        return run_benchmark_mode();
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
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn profile_arg(args: &[String]) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == "--profile")
        .map(|w| w[1].clone())
}

fn load_profile_env(profile: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let path = cwd.join("config").join("profiles").join(format!("{profile}.env"));
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read profile {}: {}", path.display(), e))?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            std::env::set_var(k.trim(), v.trim());
        }
    }
    tracing::debug!(profile = %profile, path = %path.display(), "profile environment applied");
    Ok(())
}

fn run_benchmark_mode() -> anyhow::Result<()> {
    use std::time::Instant;

    let mut engine = core::engine::SentinelEngine::new();
    let runtime = tokio::runtime::Runtime::new()?;
    let iterations = 40u32;

    let startup_begin = Instant::now();
    let _first = runtime.block_on(engine.collect())?;
    let startup_ms = startup_begin.elapsed().as_secs_f64() * 1000.0;

    let mut total_ms = 0.0f64;
    for _ in 0..iterations {
        let step = Instant::now();
        let _ = runtime.block_on(engine.collect())?;
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
