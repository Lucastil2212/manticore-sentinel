#[derive(Debug, Clone)]
pub struct MemoryMetrics {
    pub total: u64,
    pub used: u64,
    pub available: u64,
}
