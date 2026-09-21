# Security Policy

Manticore Sentinel can control processes on the host it runs on. Treat it as a privileged operator tool.

## Supported versions

Security fixes are accepted against the default branch (`main`). Older tagged releases are not maintained unless an advisory says otherwise.

## Reporting a vulnerability

**Do not file a public GitHub issue for a security defect.**

Use GitHub's private reporting flow:

https://github.com/Lucastil2212/manticore-sentinel/security/advisories/new

Include:

- Sentinel version or commit SHA
- Host OS and how you started the process (`--profile`, Compose, headless)
- Impact (info disclosure, privilege, audit bypass)
- A minimal description of the behavior — **not** a ready-to-run exploit

You should receive an acknowledgement when the report is seen. Please give a reasonable window before any public discussion.

## What this project is not

- Not a multi-tenant SaaS control plane
- Not safe to publish HTTP ports on an untrusted network
- Not a substitute for host hardening, disk encryption, or OS MAC (SELinux/AppArmor)

## Secure defaults (current `main`)

- Observability HTTP binds `127.0.0.1` unless `MANTICORE_OBS_HTTP_BIND` is set
- Event stream (SSE) binds `127.0.0.1`
- `token` and `evrus` modes require a non-empty `Authorization: Bearer` secret on HTTP APIs (except `GET /health`) and on the event stream
- Empty tokens fail closed
- Compose publishes `127.0.0.1:<port>:<port>` only
- Example profiles contain **no** placeholder secrets
- Audit events are Ed25519-signed JSONL under `.beads/audit/`

Inside Docker the process may bind `0.0.0.0` *in the container namespace* so other Compose services can reach it. The host mapping must stay on loopback.

## Operator responsibilities

1. Never commit `.env`, `*.local.env`, JWTs, CapTokens, RPC passwords, or helper signing keys.
2. Do not run `--profile secure` or privileged mode on a shared host without a unique token and a dedicated OS account.
3. Do not change Compose publishes from `127.0.0.1` to `0.0.0.0` without putting authentication in front of every listener.
4. Keep the helper socket owner-only (`0600`). Do not relocate it to a shared directory.
5. Restrict filesystem access to `.beads/audit/` (including `signing.ed25519`) and the SQLite store path.
6. Run `cargo audit` / `./scripts/vuln-scan.sh` before production builds.

## Threat model

See [docs/security-threat-model.md](docs/security-threat-model.md) and [docs/security-checklist.md](docs/security-checklist.md).
