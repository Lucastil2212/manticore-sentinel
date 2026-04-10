#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    pub interface: String,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}
