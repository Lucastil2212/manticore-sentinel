# Pre-v1 Hardening and RC Gate

Use this gate before creating a `v1.0.0-rc` tag.

## Required Checks

- [ ] CI quality gates workflow passes.
- [ ] CI packaging workflow passes.
- [ ] `cargo check`
- [ ] `cargo test`
- [ ] `cargo run -- --benchmark`

## Security and Controls

- [ ] Threat model reviewed (`docs/security-threat-model.md`).
- [ ] Security checklist fully checked (`docs/security-checklist.md`).
- [ ] Startup diagnostics validated in CLI and UI.
- [ ] Helper subprocess mode healthcheck verified.
- [ ] Policy denial and cooldown behavior manually exercised.

## Operational Readiness

- [ ] Backup archive generated using `scripts/backup-state.sh`.
- [ ] Restore drill performed with `scripts/restore-state.sh`.
- [ ] Production runbook reviewed (`docs/production-runbook.md`).
- [ ] Runtime profile docs reviewed (`docs/runtime-profiles.md`).

## Packaging Readiness

- [ ] AppImage scaffold generation completed.
- [ ] Flatpak manifest build command executed successfully.
- [ ] Release notes include packaging caveats and secure defaults.

## Signoff

- Engineering lead:
- Security reviewer:
- Operations reviewer:
- Release date target:
