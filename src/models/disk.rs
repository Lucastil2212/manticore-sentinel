#[derive(Debug, Clone)]
pub struct DiskMetrics {
    pub device: String,
    pub read_bytes_per_sec: u64,
    pub write_bytes_per_sec: u64,
}
