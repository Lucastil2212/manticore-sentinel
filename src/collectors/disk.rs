use std::{collections::HashMap, time::Instant};

use procfs::diskstats;

use crate::models::disk::DiskMetrics;

pub struct DiskCollector {
    previous: HashMap<String, (u64, u64)>,
    previous_at: Option<Instant>,
}

impl DiskCollector {
    pub fn new() -> Self {
        Self {
            previous: HashMap::new(),
            previous_at: None,
        }
    }

    pub fn collect(&mut self) -> anyhow::Result<Vec<DiskMetrics>> {
        let now = Instant::now();
        let elapsed = self
            .previous_at
            .map(|prev| now.duration_since(prev).as_secs_f64())
            .unwrap_or(0.0);

        let stats = diskstats()?;
        let mut next: HashMap<String, (u64, u64)> = HashMap::new();
        let mut out = Vec::new();

        for stat in stats {
            let key = stat.name;
            let read_bytes = stat.sectors_read.saturating_mul(512);
            let write_bytes = stat.sectors_written.saturating_mul(512);

            let (read_bps, write_bps) = if elapsed > 0.0 {
                let prev = self.previous.get(&key).copied().unwrap_or((read_bytes, write_bytes));
                let d_read = read_bytes.saturating_sub(prev.0);
                let d_write = write_bytes.saturating_sub(prev.1);
                (
                    (d_read as f64 / elapsed).max(0.0) as u64,
                    (d_write as f64 / elapsed).max(0.0) as u64,
                )
            } else {
                (0, 0)
            };

            next.insert(key.clone(), (read_bytes, write_bytes));
            out.push(DiskMetrics {
                device: key,
                read_bytes_per_sec: read_bps,
                write_bytes_per_sec: write_bps,
            });
        }

        out.sort_by(|a, b| {
            let a_total = a.read_bytes_per_sec.saturating_add(a.write_bytes_per_sec);
            let b_total = b.read_bytes_per_sec.saturating_add(b.write_bytes_per_sec);
            b_total.cmp(&a_total)
        });

        self.previous = next;
        self.previous_at = Some(now);
        Ok(out)
    }
}
