use procfs::{
    prelude::{Current, CurrentSI},
    CpuTime, KernelStats, LoadAverage,
};

use crate::models::cpu::CpuMetrics;

pub struct CpuCollector {
    previous: Option<KernelStats>,
}

impl CpuCollector {
    pub fn new() -> Self {
        Self { previous: None }
    }

    pub fn collect(&mut self) -> anyhow::Result<CpuMetrics> {
        let current = KernelStats::current()?;

        let usage_percent = if let Some(prev) = &self.previous {
            let prev_total = cpu_total_ticks(&prev.total);
            let curr_total = cpu_total_ticks(&current.total);
            let prev_idle = prev.total.idle;
            let curr_idle = current.total.idle;

            let delta_total = curr_total.saturating_sub(prev_total);
            let delta_idle = curr_idle.saturating_sub(prev_idle);

            if delta_total == 0 {
                0.0
            } else {
                (1.0 - (delta_idle as f32 / delta_total as f32)) * 100.0
            }
        } else {
            0.0
        };

        let per_core = if let Some(prev) = &self.previous {
            let n = current.cpu_time.len().min(prev.cpu_time.len());
            (0..n)
                .map(|i| {
                    let p = &prev.cpu_time[i];
                    let c = &current.cpu_time[i];
                    let prev_total = cpu_total_ticks(p);
                    let curr_total = cpu_total_ticks(c);
                    let delta_total = curr_total.saturating_sub(prev_total);
                    let delta_idle = c.idle.saturating_sub(p.idle);
                    if delta_total == 0 {
                        0.0
                    } else {
                        let pct = (1.0 - (delta_idle as f32 / delta_total as f32)) * 100.0;
                        pct.clamp(0.0, 100.0)
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        self.previous = Some(current);

        let load = LoadAverage::current().unwrap_or(procfs::LoadAverage {
            one: 0.0,
            five: 0.0,
            fifteen: 0.0,
            cur: 0,
            max: 0,
            latest_pid: 0,
        });

        Ok(CpuMetrics {
            usage_percent,
            per_core,
            load_avg: (load.one as f32, load.five as f32, load.fifteen as f32),
        })
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
