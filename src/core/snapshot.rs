use crate::models::{
    cpu::CpuMetrics, disk::DiskMetrics, memory::MemoryMetrics, network::NetworkMetrics,
    process::ProcessMetrics,
};

#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub timestamp: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disks: Vec<DiskMetrics>,
    pub network: Vec<NetworkMetrics>,
    pub processes: Vec<ProcessMetrics>,
}
