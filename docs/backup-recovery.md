# Backup and Recovery Workflow

## Backup

```bash
./scripts/backup-state.sh
./scripts/backup-state.sh /path/to/backups
```

Included when present:

- `.beads/config.yaml`, `.beads/metadata.json`
- `.beads/audit/` (events, merkle state, signing key)
- `.beads/state/sentinel.sqlite` (+ WAL/SHM)
- `config/profiles/` except `*.local.env`
- Security docs (`SECURITY.md`, threat model, checklist, performance baseline)

Archives can contain host process names, audit actions, and the audit signing
key. Store them with the same care as secrets. Default output is `backups/`
(gitignored).

Also back up `MANTICORE_STORE_PATH` if you relocated SQLite outside
`.beads/state/`.

## Restore

```bash
./scripts/restore-state.sh /path/to/manticore-state-YYYYMMDD-HHMMSS.tar.gz
```

## Safety guidance

- Restore only when the app (and Compose) are stopped.
- Copy the current `.beads/audit/events.jsonl` and `signing.ed25519` aside before overwrite.
- After restore, run `cargo test` and `cargo run -- --benchmark` (or equivalent against the shipped binary).
- Rotate `MANTICORE_AUTH_TOKEN` / JWTs if the archive or host may have been exposed.
