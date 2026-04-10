use procfs::Meminfo;
use procfs::prelude::Current;

use crate::models::memory::MemoryMetrics;

pub struct MemoryCollector;

impl MemoryCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self) -> anyhow::Result<MemoryMetrics> {
        let mem = Meminfo::current()?;
        let total_bytes = mem.mem_total.saturating_mul(1024);
        let available_kib = mem.mem_available.unwrap_or(mem.mem_free);
        let available_bytes = available_kib.saturating_mul(1024);
        let used_bytes = total_bytes.saturating_sub(available_bytes);

        Ok(MemoryMetrics {
            total: total_bytes,
            used: used_bytes,
            available: available_bytes,
        })
    }
}
