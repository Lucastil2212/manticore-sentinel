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
    max_entries: usize,
    cmdline_entries: usize,
}

impl ProcessCollector {
    pub fn new(max_entries: usize, cmdline_entries: usize) -> Self {
        Self {
            previous_proc_ticks: HashMap::new(),
            previous_total_ticks: None,
            max_entries,
            cmdline_entries,
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

        if out.len() > self.max_entries {
            out.truncate(self.max_entries);
        }
        for metrics in out.iter_mut().take(self.cmdline_entries) {
            metrics.cmdline = Process::new(metrics.pid as i32)
                .ok()
                .and_then(|p| p.cmdline().ok())
                .map(|argv| argv.join(" "))
                .map(sanitize_text)
                .unwrap_or_default();
        }

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
        Ok((
            ProcessMetrics {
                pid,
                name: sanitize_text(stat.comm),
                cpu_percent,
                memory_bytes,
                threads: status.threads as u32,
                cmdline: String::new(),
            },
            total_proc_ticks,
        ))
    }
}

fn sanitize_text(input: String) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect()
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
