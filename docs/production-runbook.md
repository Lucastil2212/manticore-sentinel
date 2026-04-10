# Production Deployment Runbook

## 1) Host Preparation

- Install Rust toolchain and build dependencies.
- Ensure target host has access to `/proc` and `/sys` in read-only context for telemetry.
- Create dedicated operator account for running the app.

## 2) Build and Validate

From repository root:

```bash
cargo check
cargo test
cargo run -- --benchmark
```

## 3) Secure Defaults

- Prefer profile: `secure`
  - `MANTICORE_PRIVILEGED=true`
  - `MANTICORE_HELPER_MODE=subprocess`
- Start command:
  - `cargo run -- --profile secure`
- Ensure helper socket permissions remain owner-only (`0600`).

## 4) Health Checks

- Startup diagnostics visible in logs.
- Benchmark command returns metrics without errors.
- Command palette accepts `show cpu` and denies privileged actions when expected.
- Audit stream updates for action attempts.

## 5) Backup and Recovery

- Create backup before release switch:
  - `./scripts/backup-state.sh`
- Restore if rollback is required:
  - `./scripts/restore-state.sh <archive>`

## 6) Rollback Procedure

1. Stop running process.
2. Restore last known-good state archive.
3. Re-deploy prior tagged binary/build.
4. Re-run health checks and benchmark mode.

## 7) Post-Deploy Verification

- Check quality workflows passed in CI.
- Confirm packaging scaffolds generated successfully.
- Validate trust mode, diagnostics string, and audit panel in UI.
