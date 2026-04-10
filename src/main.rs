mod app;
mod collectors;
mod core;
mod models;
mod security;
mod utils;

fn main() -> anyhow::Result<()> {
    let options = eframe::NativeOptions::default();
    let app = app::dashboard::SentinelDashboard::new()?;

    eframe::run_native(
        "Manticore Sentinel",
        options,
        Box::new(move |_cc| Box::new(app)),
    )
    .map_err(|e| anyhow::anyhow!("eframe failed: {e}"))?;

    Ok(())
}
