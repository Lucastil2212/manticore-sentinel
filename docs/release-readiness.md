# Release Readiness and Versioning Flow

## Versioning Policy

- Use semantic versioning: `MAJOR.MINOR.PATCH`.
- Increment:
  - `PATCH` for bug fixes and internal hardening.
  - `MINOR` for new backward-compatible features.
  - `MAJOR` for breaking behavior or API changes.

## Release Gates

All gates must pass before tagging:

- [ ] `cargo check`
- [ ] `cargo test`
- [ ] `cargo run -- --benchmark`
- [ ] security checklist complete (`docs/security-checklist.md`)
- [ ] threat model reviewed (`docs/security-threat-model.md`)
- [ ] packaging scaffolds validated (AppImage + Flatpak docs followed)

## Changelog Process

- Keep a running changelog section per release candidate.
- Include:
  - security-impacting changes
  - policy/control changes
  - helper boundary updates
  - packaging/release infrastructure updates

## Release Candidate Workflow

1. Ensure working tree is clean.
2. Run validation commands.
3. Update version in project metadata.
4. Update changelog/release notes.
5. Create annotated git tag (e.g. `v0.2.0`).
6. Build artifacts from tagged commit.
7. Publish release notes with security and performance sections.

## Suggested Validation Command Block

```bash
cargo check
cargo test
cargo run -- --benchmark
```
