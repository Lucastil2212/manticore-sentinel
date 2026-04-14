//! Embedded SVG assets for the operator UI (single source of truth for `include_bytes!` paths).

use eframe::egui;

pub const MARK: &[u8] = include_bytes!("../../assets/icons/manticore-mark.svg");
#[allow(dead_code)]
pub const SHIELD: &[u8] = include_bytes!("../../assets/icons/icon-shield.svg");
pub const RADAR: &[u8] = include_bytes!("../../assets/icons/icon-radar.svg");
pub const CPU: &[u8] = include_bytes!("../../assets/icons/icon-cpu.svg");
pub const MEMORY: &[u8] = include_bytes!("../../assets/icons/icon-memory.svg");
pub const DISK: &[u8] = include_bytes!("../../assets/icons/icon-disk.svg");
pub const NETWORK: &[u8] = include_bytes!("../../assets/icons/icon-network.svg");
pub const PROCESS: &[u8] = include_bytes!("../../assets/icons/icon-process.svg");
pub const COMMAND: &[u8] = include_bytes!("../../assets/icons/icon-command.svg");
pub const AUDIT: &[u8] = include_bytes!("../../assets/icons/icon-audit.svg");
pub const SETTINGS: &[u8] = include_bytes!("../../assets/icons/icon-settings.svg");
#[allow(dead_code)]
pub const HELP: &[u8] = include_bytes!("../../assets/icons/icon-help.svg");

/// Rasterize an embedded SVG at a square size. `uri_suffix` must be unique per asset for egui's image cache.
pub fn paint(ui: &mut egui::Ui, uri_suffix: &str, bytes: &'static [u8], size: f32) {
    let image = egui::Image::from_bytes(format!("bytes://{uri_suffix}.svg"), bytes)
        .fit_to_exact_size(egui::vec2(size, size));
    // Reserve a unique slot in the current UI so each icon draw gets a distinct widget identity.
    // This avoids ID-clash warnings when the same icon URI is rendered in multiple places.
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    image.paint_at(ui, rect);
}
