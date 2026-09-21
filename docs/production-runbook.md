# Production Deployment Runbook

Sentinel is a **single-host operator console**. It is not a public web application.
Production here means a dedicated Linux workstation or server you control, with
HTTP remaining on loopback unless you have a separate, reviewed exposure design.

## 1) Host preparation

- Dedicated OS account for the process. Do not run as root.
- Read access to `/proc` and `/sys` for telemetry.
- Disk encryption and restricted permissions on:
  - `.beads/audit/` (events + `signing.ed25519`)
  - SQLite path (`MANTICORE_STORE_PATH`)
- Rust toolchain (or a signed binary you built in CI) and build dependencies.

## 2) Build and validate

```bash
cargo check --all-targets
cargo test --all-targets
cargo run -- --benchmark
./scripts/vuln-scan.sh   # requires cargo-audit
```

Confirm CI quality-gates and vulnerability-scan workflows on the commit you ship.

## 3) Secure defaults

Prefer the `secure` profile **plus exported secrets** (nothing committed):

```bash
export MANTICORE_AUTH_TOKEN="$(openssl rand -hex 16)"
export MANTICORE_AUTH_TOKEN_ISSUED_AT="$(date +%s)"
export MANTICORE_AUTH_TOKEN_TTL_SECS=86400
cargo run --release -- --profile secure
```

- `MANTICORE_HELPER_MODE=subprocess`
- `MANTICORE_PRIVILEGED=true` only if kill/renice are required
- `MANTICORE_OBS_HTTP_BIND=127.0.0.1` (default)
- Leave Compose lab stubs off production hosts, or point connectors at real PeerWeave/EVRUS with TLS and real tokens

Optional workstation overlay: `config/profiles/secure.local.env` (gitignored).

## 4) Health checks

- Startup log shows profile, privileged flag, `obs_bind`, and helper mode.
- `show cpu` works; privileged actions deny when the role/mode says they should.
- Audit stream updates for attempts.
- If observability is enabled: `curl -sS http://127.0.0.1:9463/health` succeeds; `/api/search` requires Bearer in token mode.

## 5) Backup and recovery

```bash
./scripts/backup-state.sh
./scripts/restore-state.sh <archive>
```

Archives include audit data and the SQLite file when present. They may contain
host process names. Store them like secrets. See [backup-recovery.md](backup-recovery.md).

## 6) Rollback

1. Stop the process (and Compose if used).
2. Restore the last known-good state archive.
3. Redeploy the prior tagged binary.
4. Re-run health checks and `--benchmark`.
5. Rotate `MANTICORE_AUTH_TOKEN` / JWTs if the old process may have leaked them.

## 7) Post-deploy verification

- Quality and vuln-scan workflows passed for the shipped SHA.
- Helper socket is `0600`.
- No listeners on `0.0.0.0` on the host (`ss -lnt` / `ss -lntup`).
- Trust mode, diagnostics, and audit panel match the intended role.
