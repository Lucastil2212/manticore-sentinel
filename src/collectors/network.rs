use std::{collections::HashMap, fs, path::Path, time::Instant};

use crate::models::network::NetworkMetrics;

pub struct NetworkCollector {
    previous: HashMap<String, (u64, u64)>,
    previous_at: Option<Instant>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            previous: HashMap::new(),
            previous_at: None,
        }
    }

    pub fn collect(&mut self) -> anyhow::Result<Vec<NetworkMetrics>> {
        let now = Instant::now();
        let elapsed = self
            .previous_at
            .map(|prev| now.duration_since(prev).as_secs_f64())
            .unwrap_or(0.0);

        let net_path = Path::new("/sys/class/net");
        let mut next: HashMap<String, (u64, u64)> = HashMap::new();
        let mut out = Vec::new();

        for entry in fs::read_dir(net_path)? {
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let iface = entry.file_name().to_string_lossy().to_string();
            let stats_path = entry.path().join("statistics");
            let rx_now = read_u64(stats_path.join("rx_bytes")).unwrap_or(0);
            let tx_now = read_u64(stats_path.join("tx_bytes")).unwrap_or(0);

            let (rx_bps, tx_bps) = if elapsed > 0.0 {
                let prev = self
                    .previous
                    .get(&iface)
                    .copied()
                    .unwrap_or((rx_now, tx_now));
                let d_rx = rx_now.saturating_sub(prev.0);
                let d_tx = tx_now.saturating_sub(prev.1);
                (
                    (d_rx as f64 / elapsed).max(0.0) as u64,
                    (d_tx as f64 / elapsed).max(0.0) as u64,
                )
            } else {
                (0, 0)
            };

            next.insert(iface.clone(), (rx_now, tx_now));
            out.push(NetworkMetrics {
                interface: iface,
                rx_bytes_per_sec: rx_bps,
                tx_bytes_per_sec: tx_bps,
            });
        }

        out.sort_by(|a, b| {
            let a_total = a.rx_bytes_per_sec.saturating_add(a.tx_bytes_per_sec);
            let b_total = b.rx_bytes_per_sec.saturating_add(b.tx_bytes_per_sec);
            b_total.cmp(&a_total)
        });

        self.previous = next;
        self.previous_at = Some(now);
        Ok(out)
    }
}

fn read_u64(path: impl AsRef<Path>) -> anyhow::Result<u64> {
    let raw = fs::read_to_string(path)?;
    let value = raw.trim().parse::<u64>()?;
    Ok(value)
}
