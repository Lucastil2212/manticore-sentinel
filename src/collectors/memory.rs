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
        // procfs Meminfo sizes are already converted to bytes (see Meminfo docs).
        let total_bytes = mem.mem_total;
        let available_bytes = mem.mem_available.unwrap_or(mem.mem_free);
        let used_bytes = total_bytes.saturating_sub(available_bytes);

        Ok(MemoryMetrics {
            total: total_bytes,
            used: used_bytes,
            available: available_bytes,
        })
    }
}
