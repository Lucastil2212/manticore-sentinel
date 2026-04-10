use crate::collectors::{
    cpu::CpuCollector, disk::DiskCollector, memory::MemoryCollector, network::NetworkCollector,
    process::ProcessCollector,
};
use crate::core::snapshot::SystemSnapshot;
use crate::utils::time::now_unix_secs;

pub struct SentinelEngine {
    cpu: CpuCollector,
    memory: MemoryCollector,
    process: ProcessCollector,
    disk: DiskCollector,
    network: NetworkCollector,
}

impl SentinelEngine {
    pub fn new() -> Self {
        Self {
            cpu: CpuCollector::new(),
            memory: MemoryCollector::new(),
            process: ProcessCollector::new(),
            disk: DiskCollector::new(),
            network: NetworkCollector::new(),
        }
    }

    pub async fn collect(&mut self) -> anyhow::Result<SystemSnapshot> {
        let timestamp = now_unix_secs();
        let cpu = self.cpu.collect()?;
        let memory = self.memory.collect()?;
        let processes = self.process.collect()?;
        let disks = self.disk.collect()?;
        let network = self.network.collect()?;

        Ok(SystemSnapshot {
            timestamp,
            cpu,
            memory,
            disks,
            network,
            processes,
        })
    }
}
