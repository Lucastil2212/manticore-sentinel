# Manticore Sentinel

[![quality-gates](https://github.com/Lucastil2212/manticore-sentinel/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/Lucastil2212/manticore-sentinel/actions/workflows/quality-gates.yml)

Linux operator console for live host telemetry, capability-gated process actions, and an append-only audit trail. Sentinel is a standalone Rust + egui desktop application. Optional HTTP connectors talk to PeerWeave and EVRUS over GraphQL, OIDC, and JSON-RPC — never by sharing libraries.

**This is a privileged host tool, not a public internet service.** Default HTTP listeners bind loopback. Compose publishes ports on `127.0.0.1` only. See [SECURITY.md](SECURITY.md).

## Features

- Live CPU, memory, disk, network, and process snapshot from `/proc` and `/sys`
- Allowlisted command palette (no shell). Kill/renice go through a Unix-socket helper
- RBAC: `local | token | evrus` × `viewer | operator | admin`
- Append-only JSONL audit with Ed25519 signatures
- SQLite WAL store with hybrid FTS5 / hashed-vector / RRF search
- Optional loopback observability HTTP (`/health`, `/metrics`, search and logs APIs)
- Optional Docker Compose lab stack (each service is profile-gated)

## Requirements

- Linux (full functionality: Unix-domain helper, `/proc` collectors)
- Rust stable toolchain (edition 2021)
- Optional: Docker Engine with Compose v2

## Quick start

```bash
git clone https://github.com/Lucastil2212/manticore-sentinel.git
cd manticore-sentinel
cargo run --release
```

Load an example profile (see [`config/profiles/README.md`](config/profiles/README.md)):

```bash
cargo run --release -- --profile dev
```

Token mode does not ship a secret. Generate one, then start:

```bash
export MANTICORE_AUTH_TOKEN="$(openssl rand -hex 16)"
export MANTICORE_AUTH_TOKEN_ISSUED_AT="$(date +%s)"
cargo run --release -- --profile secure
```

## Security model (short)

| Surface | Default |
|---------|---------|
| Collectors | Unprivileged reads of `/proc` and `/sys` |
| Kill / renice | Helper over a `0600` Unix socket; denied unless privileged + role allows it |
| Observability HTTP | Off unless enabled; bind `127.0.0.1:9463`; `token`/`evrus` require `Authorization: Bearer` except `GET /health` |
| Event stream (SSE) | `127.0.0.1:9462`; same Bearer rules |
| Compose ports | Published as `127.0.0.1:<port>:<port>` |
| Secrets | Not in git. Use environment variables or gitignored `*.local.env` overlays |

Do not bind `0.0.0.0` on an untrusted network. Do not commit tokens, JWTs, RPC passwords, or `.env` files.

Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Command palette

| Command | Purpose |
|---------|---------|
| `show cpu` | Read-only acknowledgment (audited) |
| `search nginx` | Hybrid FTS / vector search |
| `renice <nice> <pid>` | Nice adjustment via helper |
| `kill <pid>` | Termination via helper; typed confirmation |

Shell metacharacters (`|`, `;`, `&`, `>`, `<`) are rejected.

## CLI

| Flag | Purpose |
|------|---------|
| `--profile <name>` | Load `config/profiles/<name>.env`, then optional `<name>.local.env` |
| `--headless` | Collectors + store + observability HTTP (no GUI) |
| `--healthcheck` | Probe `GET /health` on loopback (Docker) |
| `--benchmark` | Headless collection timings |
| `--helper-daemon` | Internal helper subprocess entry |

## Docker Compose (lab)

Stand-ins are for local evaluation. They are not production PeerWeave or EVRUS.

```bash
cp .env.example .env   # optional overrides; never commit .env
docker compose --profile stack up -d
```

Then on this host only:

- Observability UI: `http://127.0.0.1:9463/`
- Search: `http://127.0.0.1:9463/api/search?q=nginx&mode=hybrid`
- PeerWeave GraphQL stand-in: `http://127.0.0.1:3200/`
- EVRUS OIDC stand-in: `http://127.0.0.1:8790/.well-known/openid-configuration`

Details: [docs/docker-compose.md](docs/docker-compose.md).

## Documentation

Index: [docs/README.md](docs/README.md).

| Document | Topic |
|----------|--------|
| [docs/configuration.md](docs/configuration.md) | Environment variables |
| [docs/auth-rbac-model.md](docs/auth-rbac-model.md) | Auth modes, roles, lockout |
| [docs/security-threat-model.md](docs/security-threat-model.md) | Assets, boundaries, residual risk |
| [docs/production-runbook.md](docs/production-runbook.md) | Operator deploy checklist |
| [docs/manticore-ecosystem-integration.md](docs/manticore-ecosystem-integration.md) | Protocol-only PeerWeave / EVRUS contract |

## Development

```bash
cargo test
cargo run -- --benchmark
```

Layout: `src/app` (egui), `src/collectors`, `src/security` (audit, auth, helper), `src/store`, `src/search`, `src/observability`, `src/connectors` (HTTP clients only).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not open public issues that include secrets, host dumps, or exploit details.

## License

Copyright © 2026 Manticore Technology. Source is available for evaluation under the terms in [LICENSE](LICENSE). Production use and redistribution require a separate written license.
