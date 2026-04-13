use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f32,
    pub per_core: Vec<f32>,
    pub load_avg: (f32, f32, f32),
}
