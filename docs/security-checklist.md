# Security Checklist

Use this checklist before tagging a release candidate.

## Build and Test

- [ ] `cargo check`
- [ ] `cargo test`
- [ ] `cargo run -- --benchmark`

## Parser and Policy Controls

- [ ] Parser rejects shell operators (`|`, `;`, `&`, `>`, `<`).
- [ ] Parser enforces max command length.
- [ ] Parser rejects invalid PID and nice ranges.
- [ ] Policy blocks privileged actions in unprivileged mode.
- [ ] Policy kill cooldown is active and tested.

## Helper Boundary

- [ ] Helper startup contract validated (healthcheck).
- [ ] Helper socket permissions set to `0600`.
- [ ] Capability denial path returns clear errors.
- [ ] Protected PID actions are denied.

## Audit and UX

- [ ] Append-only audit path exists and receives entries.
- [ ] Dashboard displays recent audit events.
- [ ] Security onboarding guide is visible and accurate.
- [ ] Destructive action typed confirmation works as expected.

## Release Hygiene

- [ ] Threat model document reviewed (`docs/security-threat-model.md`).
- [ ] Performance baseline updated (`docs/performance-baseline.md`).
- [ ] Changelog/release notes include security-impacting changes.
