# Backup and Recovery Workflow

## Backup

Create a state backup archive:

`./scripts/backup-state.sh`

Optional output directory:

`./scripts/backup-state.sh /path/to/backups`

Included artifacts:

- `.beads/config.yaml`
- `.beads/metadata.json`
- `.beads/audit/`
- `config/profiles/`
- key security/performance docs

## Restore

Restore from archive:

`./scripts/restore-state.sh /path/to/manticore-state-YYYYMMDD-HHMMSS.tar.gz`

## Safety Guidance

- Restore only when the app is stopped.
- Preserve a copy of the current `.beads/audit/events.jsonl` before overwrite.
- After restore, run:
  - `cargo check`
  - `cargo test`
  - `cargo run -- --benchmark`
