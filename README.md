# Manticore Sentinel

Desktop operator console for live system telemetry and capability-gated actions. Built for [Manticore Technology](https://manticore.technology) security operations: clear defaults for new users, progressive disclosure for advanced operators, and an audit trail for sensitive actions.

## For users

### What you get

- **Live snapshot**: CPU, memory, disk and network throughput, and top processes.
- **Command palette**: Approved commands only (no shell injection). Destructive actions require confirmation and policy checks.
- **Security posture**: Trust mode (privileged vs unprivileged helper), role-based permissions, optional token auth, and append-only audit events.
- **In-app help**: **Help Center** and **Security Guide** windows plus hover tooltips on major controls.

### Requirements

- **Rust** toolchain (see [Developers](#developers) for versions).
- **Linux** recommended for full functionality (helper uses Unix domain sockets and process signals).

### Run the application

From the repository root:

```bash
cargo run --release
```

Optional: load a predefined environment profile (see `config/profiles/`):

```bash
cargo run --release -- --profile dev
```

```bash
cargo run --release -- --profile secure
```

Profiles set variables such as `MANTICORE_PRIVILEGED`, `MANTICORE_HELPER_MODE`, and auth settings. Edit the `.env` files before production use—especially tokens.

### Command palette (quick reference)

| Command | Purpose |
|--------|---------|
| `show cpu` | Read-only acknowledgment (audited). |
| `renice <nice> <pid>` | Adjust process nice value via helper (requires permission + privileged helper when applicable). |
| `kill <pid>` | Request termination via helper; requires typed confirmation and policy permission. |

Shell metacharacters (`|`, `;`, `&`, `>`, `<`) are rejected.

### Important environment variables

| Variable | Meaning |
|----------|---------|
| `MANTICORE_PROFILE` | Logical profile name (default `default`). |
| `MANTICORE_PRIVILEGED` | When true, helper may expose kill/renice capabilities. |
| `MANTICORE_HELPER_MODE` | `embedded` or `subprocess` helper execution. |
| `MANTICORE_REFRESH_MS` | Snapshot refresh interval in ms (100–5000). |
| `MANTICORE_AUTH_MODE` | `local` or `token`. |
| `MANTICORE_ROLE` | `viewer`, `operator`, or `admin`. |
| `MANTICORE_AUTH_TOKEN` | Required in token mode (minimum length enforced). |
| `MANTICORE_AUTH_TOKEN_ISSUED_AT` | Unix seconds (token mode). |
| `MANTICORE_AUTH_TOKEN_TTL_SECS` | Token lifetime (token mode). |
| `MANTICORE_AUTH_TOKEN_GRACE_SECS` | Optional grace window (token mode). |
| `MANTICORE_STORE_ENABLED` | SQLite WAL store (default true). |
| `MANTICORE_SEARCH_ENABLED` | Hybrid FTS/vector indexing (default true). |
| `MANTICORE_OBS_HTTP_ENABLED` | Observability HTTP API (default false; on with `--headless`). |
| `MANTICORE_OBS_HTTP_PORT` | Observability port (default 9463). |
| `MANTICORE_LOG_JSON` | JSON tracing output. |

Full auth and RBAC semantics are documented in `docs/auth-rbac-model.md`.

### Advanced controls in the UI

Expand **Advanced Controls** (collapsed by default) to see helper socket path, audit log path, auth failure counters, lockout state, and raw runtime diagnostic string. Prefer the main view for day-to-day monitoring.

### Logging

Structured logging uses `tracing`. For example:

```bash
RUST_LOG=debug cargo run --release
```

### Other modes (CLI)

| Flag | Purpose |
|------|---------|
| `--helper-daemon` | Internal: helper subprocess entry (set by the app, not typical for end users). |
| `--benchmark` | Headless collection benchmark; prints timings to stdout. |
| `--headless` | Collectors + SQLite store + hybrid search + observability HTTP (no GUI). |
| `--healthcheck` | Probe `GET /health` on the observability port (used by Docker). |

### Docker Compose (optional services)

Each service is profile-gated and starts independently. Connectors degrade if a peer is missing.

```bash
docker compose --profile stack up -d          # sentinel + PeerWeave stub + EVRUS OIDC stub
docker compose --profile sentinel up -d       # telemetry/search only
docker compose --profile peerweave --profile evrus up -d
```

- Sentinel observability UI: `http://127.0.0.1:9463/`
- Search API: `http://127.0.0.1:9463/api/search?q=nginx&mode=hybrid`
- PeerWeave GraphQL stand-in: `http://127.0.0.1:3200/`
- EVRUS OIDC stand-in: `http://127.0.0.1:8790/.well-known/openid-configuration`

Replace the stand-ins with live `peer-weave` / `evrus-v0` processes by pointing `MANTICORE_PEERWEAVE_GRAPHQL_URL` and `MANTICORE_EVRUS_OIDC_URL` at them.

### Hybrid search

Host, process, connector, and log documents land in a SQLite WAL store (FTS5 + 64-d hashed n-gram vectors, fused with reciprocal rank). In the GUI use **Search & Discovery**; from the palette: `search nginx` or `search --mode vector high cpu`.

---

## For developers

### Prerequisites

- **Rust** with `cargo` (edition 2021; use a current stable toolchain).
- **Linux** dev environment for running helper and integration-style tests that touch processes/sockets.

### Clone and build

```bash
git clone <repository-url>
cd manticore-sentinel
cargo build --release
```

### Test

```bash
cargo test
```

Some tests spawn short-lived processes or use temporary Unix sockets; they expect a normal Linux user session.

### Run (debug, faster iteration)

```bash
cargo run
```

### Project layout (high level)

| Path | Role |
|------|------|
| `src/main.rs` | Entry: profiles, config load, benchmark/helper modes, GUI bootstrap. |
| `src/app/dashboard.rs` | Primary egui UI: telemetry, commands, help, icons, advanced section. |
| `src/core/` | Engine, snapshot, policy, commands, config, errors. |
| `src/security/` | Audit trail, auth/RBAC gate, privileged helper (UDS). |
| `src/collectors/` | Data collectors (CPU, memory, disk, network, processes). |
| `src/store/` | SQLite WAL metrics/documents/logs (FTS5 + embeddings). |
| `src/search/` | Hybrid FTS / vector / semantic discovery. |
| `src/telemetry/` | Background collector so the UI thread never blocks on `/proc` or HTTP. |
| `src/observability/` | Optional HTTP API, Prometheus text, and analysis dashboard. |
| `src/models/` | Metric structs shared by collectors and UI. |
| `assets/icons/` | Custom SVG icons embedded at compile time for the operator UI. |
| `config/profiles/` | Example `*.env` profiles for local vs secure-style runs. |
| `docs/` | Deeper operational and security documentation. |

### Configuration loading

`core::config::load_runtime_config()` reads environment variables and validates ranges (e.g. refresh interval, token mode requirements). The GUI dashboard uses the same loader for consistency with CLI startup logging.

### UI assets (SVG)

Icons are included with `include_bytes!` from `assets/icons/`. `egui_extras` registers image loaders once when visuals initialize. New icons should be small, single-purpose SVGs; keep stroke/fill colors aligned with the existing tactical palette if you extend the set.

### Issue tracking (Beads)

This repository may use **Beads** (`.beads/`) for in-repo issues. Typical workflow:

```bash
bd list
bd show <issue-id>
bd create "Title"
bd update <issue-id> --claim
```

### Documentation index

- `docs/auth-rbac-model.md` — Authentication modes, roles, permissions, token lifecycle, lockout, audit behavior.
- Other `docs/*.md` files — Packaging, runbooks, certification gates, etc., as present in your checkout.

### Security notes for contributors

- Do not bypass the command parser for operator input.
- Keep destructive actions on the helper boundary; avoid `Command::shell` or stringly shell execution.
- Preserve append-only audit semantics for security-relevant outcomes.
- When changing auth or policy, update `docs/auth-rbac-model.md` and add or adjust tests in `src/security/`.

---

## License and branding

Manticore Sentinel is part of the Manticore Technology product line. Use and distribution terms follow the license file in this repository if one is present; otherwise clarify with the repository owner.
