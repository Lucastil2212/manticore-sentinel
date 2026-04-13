use std::collections::HashMap;

use procfs::{
    prelude::CurrentSI,
    process::{all_processes, Process},
    CpuTime, KernelStats,
};

use crate::models::process::ProcessMetrics;

pub struct ProcessCollector {
    previous_proc_ticks: HashMap<u32, u64>,
    previous_total_ticks: Option<u64>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            previous_proc_ticks: HashMap::new(),
            previous_total_ticks: None,
        }
    }

    pub fn collect(&mut self) -> anyhow::Result<Vec<ProcessMetrics>> {
        let kernel = KernelStats::current()?;
        let total_ticks_now = cpu_total_ticks(&kernel.total);
        let delta_total = self
            .previous_total_ticks
            .map(|prev| total_ticks_now.saturating_sub(prev))
            .unwrap_or(0);

        let mut next_proc_ticks: HashMap<u32, u64> = HashMap::new();
        let mut out = Vec::new();

        for item in all_processes()? {
            let process = match item {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let Ok((metrics, ticks)) = self.collect_one(&process, delta_total) {
                next_proc_ticks.insert(metrics.pid, ticks);
                out.push(metrics);
            }
        }

        out.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        self.previous_proc_ticks = next_proc_ticks;
        self.previous_total_ticks = Some(total_ticks_now);
        Ok(out)
    }

    fn collect_one(
        &self,
        process: &Process,
        delta_total: u64,
    ) -> anyhow::Result<(ProcessMetrics, u64)> {
        let stat = process.stat()?;
        let pid = stat.pid as u32;
        let total_proc_ticks = stat.utime.saturating_add(stat.stime);
        let previous_ticks = self
            .previous_proc_ticks
            .get(&pid)
            .copied()
            .unwrap_or(total_proc_ticks);
        let delta_proc = total_proc_ticks.saturating_sub(previous_ticks);

        let cpu_percent = if delta_total == 0 {
            0.0
        } else {
            (delta_proc as f32 / delta_total as f32) * 100.0
        };

        let status = process.status()?;
        let memory_bytes = status.vmrss.unwrap_or(0).saturating_mul(1024);
        let cmdline = process
            .cmdline()
            .map(|argv| argv.join(" "))
            .unwrap_or_default();

        Ok((
            ProcessMetrics {
                pid,
                name: stat.comm,
                cpu_percent,
                memory_bytes,
                threads: status.threads as u32,
                cmdline,
            },
            total_proc_ticks,
        ))
    }
}

fn cpu_total_ticks(cpu: &CpuTime) -> u64 {
    cpu.user
        .saturating_add(cpu.nice)
        .saturating_add(cpu.system)
        .saturating_add(cpu.idle)
        .saturating_add(cpu.iowait.unwrap_or(0))
        .saturating_add(cpu.irq.unwrap_or(0))
        .saturating_add(cpu.softirq.unwrap_or(0))
        .saturating_add(cpu.steal.unwrap_or(0))
        .saturating_add(cpu.guest.unwrap_or(0))
        .saturating_add(cpu.guest_nice.unwrap_or(0))
}
