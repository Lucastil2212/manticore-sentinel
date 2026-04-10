#[derive(Debug, Clone)]
pub struct ProcessMetrics {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub threads: u32,
    pub cmdline: String,
}
