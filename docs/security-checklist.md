# Security Checklist

Use this checklist before tagging a release candidate or publishing a public commit that touches listeners, auth, or profiles.

## Build and test

- [ ] `cargo check --all-targets`
- [ ] `cargo test --all-targets`
- [ ] `cargo run -- --benchmark`
- [ ] `./scripts/vuln-scan.sh` when `cargo-audit` is installed

## Parser and policy

- [ ] Parser rejects shell operators (`|`, `;`, `&`, `>`, `<`).
- [ ] Parser enforces max command length.
- [ ] Parser rejects invalid PID and nice ranges.
- [ ] Policy blocks privileged actions in unprivileged mode.
- [ ] Policy kill cooldown is active and tested.
- [ ] `token` mode still denies admin kill/renice.

## Helper boundary

- [ ] Helper startup contract validated (healthcheck).
- [ ] Helper socket permissions set to `0600`.
- [ ] Capability denial path returns clear errors.
- [ ] Protected PID actions are denied.

## HTTP and Compose

- [ ] Observability default bind is `127.0.0.1`.
- [ ] Event stream binds `127.0.0.1`.
- [ ] `token` / `evrus` require Bearer; empty secrets fail closed; `GET /health` remains unauthenticated.
- [ ] Responses do not send `Access-Control-Allow-Origin: *`.
- [ ] `docker-compose.yml` publishes `127.0.0.1:<port>:<port>` only.
- [ ] Dockerfile in-container `0.0.0.0` bind is documented as container-local.

## Secrets hygiene

- [ ] No tokens, JWTs, RPC passwords, or `.env` files in git (`git ls-files` review).
- [ ] Example profiles have comments only — no placeholder secrets.
- [ ] `.gitignore` covers `.env`, `*.local.env`, sqlite, and keys.

## Audit and UX

- [ ] Append-only audit path exists and receives entries.
- [ ] Events include Ed25519 signatures when the signing key is present.
- [ ] Dashboard displays recent audit events.
- [ ] Destructive action typed confirmation works as expected.

## Release hygiene

- [ ] [security-threat-model.md](security-threat-model.md) still matches the code.
- [ ] [SECURITY.md](../SECURITY.md) reporting URL is correct.
- [ ] Performance baseline updated if collectors changed ([performance-baseline.md](performance-baseline.md)).
- [ ] Changelog/release notes include security-impacting changes.
