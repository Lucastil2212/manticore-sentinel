# Performance Baseline

This baseline was captured using the built-in benchmark mode:

`cargo run -- --benchmark`

## Results (local machine)

- `benchmark.startup_ms=53.054`
- `benchmark.collect_avg_ms=46.029`
- `benchmark.collect_hz=21.725`
- `benchmark.iterations=40`

## Interpretation

- Startup latency is currently under 100ms target.
- Collector cadence is around 46ms per full snapshot cycle in this environment.
- Effective throughput is ~21.7 collections per second.

## Notes

- These figures are environment-dependent and include current collector set.
- Re-run after major collector or UI pipeline changes and append new measurements.
